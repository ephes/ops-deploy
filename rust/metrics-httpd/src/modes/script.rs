//! Mode `script` (PLAN.md 4.4, `metrics_endpoint`, `metrics_httpd.py.j2`
//! l.30–52): runs a metrics script per request and serves its stdout.
//!
//! After the gate (HTML 404, `htpasswd -vb` password rules): the script runs
//! without a shell and without arguments, with the inherited environment and
//! working directory, in its own process group. Exit 0 → 200 with stdout
//! (Python's universal-newline translation applied, no JSON validation);
//! exit ≠ 0 → 502 `send_error` with the stripped stderr or "Metrics script
//! failed" (D-3: in the body, not the reason phrase); timeout → 504
//! "Metrics script timeout", and the whole process group is killed (D-8).
//! A script that cannot be started gets 502 where Python drops the
//! connection (D-2); stdout above [`MAX_STDOUT_BYTES`] gets 502 (D-12).

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use clap::Args;
use hyper::StatusCode;
use rustix::fs::{Access, access};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::auth::PasswordSource;
use crate::clock::SharedClock;
use crate::modes::{
    AuthArgs, Gate, ListenArgs, Mode, NotFound, PathMatch, Problems, parse_seconds,
};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// D-12: stdout above this answers 502 (Python: unbounded).
pub const MAX_STDOUT_BYTES: usize = 64 * 1024 * 1024;
/// stderr kept for the 502 message; the rest is read and discarded.
pub const KEPT_STDERR_BYTES: usize = 64 * 1024;
/// D-3: the stderr text in the 502 body is cut to this many bytes.
pub const MAX_MESSAGE_BYTES: usize = 1024;

/// `send_error(502, ...)` without stderr text (`metrics_httpd.py.j2` l.43).
pub const FAILED_MESSAGE: &str = "Metrics script failed";
/// D-2: the 502 when the script cannot be started (Python drops the
/// connection).
pub const CANNOT_RUN_MESSAGE: &str = "Cannot run metrics script";
/// D-12: the 502 when stdout exceeds [`MAX_STDOUT_BYTES`].
pub const TOO_LARGE_MESSAGE: &str = "Metrics script output too large";
/// `send_error(504, "Metrics script timeout")` (l.39).
pub const TIMEOUT_MESSAGE: &str = "Metrics script timeout";

#[derive(Args, Debug, Clone)]
pub struct ScriptArgs {
    #[command(flatten)]
    pub listen: ListenArgs,
    #[command(flatten)]
    pub auth: AuthArgs,
    /// The metrics script (run without a shell and without arguments).
    #[arg(long, value_name = "X")]
    pub script: PathBuf,
    /// Seconds before the script is killed and the request answered 504.
    #[arg(long, value_name = "SECS", value_parser = parse_seconds)]
    pub script_timeout: Duration,
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

impl Mode for ScriptArgs {
    type Service = Script;
    const NAME: &'static str = "script";

    fn addr(&self) -> SocketAddr {
        self.listen.addr()
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        let entries = problems.htpasswd(&self.auth.htpasswd_file);
        match std::fs::metadata(&self.script) {
            Ok(metadata) if metadata.is_file() => {
                if access(&self.script, Access::EXEC_OK).is_err() {
                    problems.push(format!(
                        "script {} is not executable",
                        self.script.display()
                    ));
                }
            }
            Ok(_) => problems.push(format!("script {} is not a file", self.script.display())),
            Err(error) => problems.push(format!("script {}: {error}", self.script.display())),
        }
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} script {} timeout {:?} htpasswd {} (bcrypt entries: {entries}) realm {}",
            self.addr(),
            self.auth.path,
            self.script.display(),
            self.script_timeout,
            self.auth.htpasswd_file.display(),
            self.auth.realm,
        ))
    }

    fn server_config(&self, clock: SharedClock) -> ServerConfig {
        ServerConfig {
            request_timeout: self.auth.request_timeout,
            access_log: AccessLog::Stderr,
            server_header: server::server_header(&self.auth.server_name),
            clock,
        }
    }

    fn service(&self, _clock: SharedClock) -> Script {
        Script {
            gate: Gate {
                // `htpasswd -vb`: the password in argv (D-6 keeps its rules).
                password_source: PasswordSource::Argv,
                ..Gate::new(&self.auth, PathMatch::Exact, NotFound::Html)
            },
            script: self.script.clone(),
            script_timeout: self.script_timeout,
        }
    }
}

/// The script endpoint.
pub struct Script {
    pub gate: Gate,
    pub script: PathBuf,
    pub script_timeout: Duration,
}

impl Service for Script {
    async fn call(&self, request: Request) -> HttpResponse {
        if let Some(response) = self.gate.check(&request).await {
            return response;
        }
        let outcome = run(&self.script, self.script_timeout).await;
        respond(&self.script, self.script_timeout, outcome)
    }
}

/// How one run of the script ended.
#[derive(Debug)]
pub enum Outcome {
    /// The script exited and both pipes reached EOF.
    Exited {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// The timeout elapsed; the process group was killed (D-8).
    TimedOut,
    /// stdout exceeded [`MAX_STDOUT_BYTES`]; the process group was killed.
    TooLarge,
    /// The script could not be started, or reading its pipes or waiting for
    /// it failed (Python: an uncaught `OSError`, no response; D-2).
    Failed(io::Error),
}

/// Kills the script's process group (SIGKILL) unless disarmed: on timeout,
/// on oversized output and when the request is abandoned (the future is
/// dropped at shutdown).
struct GroupGuard(Option<Pid>);

impl GroupGuard {
    fn kill(&mut self) {
        if let Some(group) = self.0.take() {
            // ESRCH: the group is already gone.
            let _ = kill_process_group(group, Signal::KILL);
        }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

enum Failure {
    TooLarge,
    Io(io::Error),
}

/// Runs `script` as `subprocess.run([script], capture_output=True,
/// timeout=...)` does, except that a timeout kills the whole process group
/// (D-8) instead of only the direct child.
pub async fn run(script: &Path, timeout: Duration) -> Outcome {
    let mut command = tokio::process::Command::new(script);
    command
        // systemd gives the unit /dev/null; Python's child inherits it.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Outcome::Failed(error),
    };
    // `process_group(0)`: the group id is the child's pid. Never 0 or 1
    // (`kill(-1)` would signal every process).
    let mut group = GroupGuard(
        child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 1)
            .and_then(Pid::from_raw),
    );
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        reap(&mut child, &mut group).await;
        return Outcome::Failed(io::Error::other("the script's pipes are missing"));
    };
    let finished = {
        let work = async {
            tokio::try_join!(read_stdout(stdout), read_stderr(stderr), async {
                child.wait().await.map_err(Failure::Io)
            },)
        };
        tokio::time::timeout(timeout, work).await
    };
    match finished {
        Ok(Ok((stdout, stderr, status))) => {
            // Exited and both pipes closed: what is left in the group (a
            // detached background job) is left alone, as by Python.
            group.0 = None;
            Outcome::Exited {
                status,
                stdout,
                stderr,
            }
        }
        Ok(Err(failure)) => {
            reap(&mut child, &mut group).await;
            match failure {
                Failure::TooLarge => Outcome::TooLarge,
                Failure::Io(error) => Outcome::Failed(error),
            }
        }
        Err(_elapsed) => {
            reap(&mut child, &mut group).await;
            Outcome::TimedOut
        }
    }
}

/// Kills the process group and the child itself (in case it left the
/// group) and waits for the child.
async fn reap(child: &mut tokio::process::Child, group: &mut GroupGuard) {
    group.kill();
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn read_stdout(stdout: impl AsyncRead + Unpin) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_STDOUT_BYTES).unwrap_or(u64::MAX);
    stdout
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .map_err(Failure::Io)?;
    if bytes.len() > MAX_STDOUT_BYTES {
        return Err(Failure::TooLarge);
    }
    Ok(bytes)
}

/// Keeps the first [`KEPT_STDERR_BYTES`] and drains the rest, so a chatty
/// script never blocks on a full pipe.
async fn read_stderr(mut stderr: impl AsyncRead + Unpin) -> Result<Vec<u8>, Failure> {
    let mut kept = Vec::new();
    let limit = u64::try_from(KEPT_STDERR_BYTES).unwrap_or(u64::MAX);
    (&mut stderr)
        .take(limit)
        .read_to_end(&mut kept)
        .await
        .map_err(Failure::Io)?;
    tokio::io::copy(&mut stderr, &mut tokio::io::sink())
        .await
        .map_err(Failure::Io)?;
    Ok(kept)
}

/// The answer to an [`Outcome`], with one error line per 5xx cause (D-9).
pub fn respond(script: &Path, timeout: Duration, outcome: Outcome) -> HttpResponse {
    let script = script.display();
    match outcome {
        Outcome::Exited { status, stdout, .. } if status.success() => {
            // `completed.stdout.encode()`: the text-mode output with
            // universal newlines; bytes that are not UTF-8 pass through (D-2).
            server::json_response(StatusCode::OK, translate_newlines(&stdout))
        }
        Outcome::Exited { status, stderr, .. } => {
            let message = stderr_message(&stderr);
            let message = message.as_deref().unwrap_or(FAILED_MESSAGE);
            server::log_line(&format!(
                "metrics-httpd script: {script} failed ({status}): {message}"
            ));
            bad_gateway(message)
        }
        Outcome::TimedOut => {
            server::log_line(&format!(
                "metrics-httpd script: {script} timed out after {timeout:?}; its process group was killed"
            ));
            server::send_error(
                StatusCode::GATEWAY_TIMEOUT,
                TIMEOUT_MESSAGE,
                "The gateway server did not receive a timely response",
            )
        }
        Outcome::TooLarge => {
            server::log_line(&format!(
                "metrics-httpd script: {script} wrote more than {MAX_STDOUT_BYTES} bytes to stdout; its process group was killed"
            ));
            bad_gateway(TOO_LARGE_MESSAGE)
        }
        Outcome::Failed(error) => {
            server::log_line(&format!(
                "metrics-httpd script: cannot run {script}: {error}"
            ));
            bad_gateway(CANNOT_RUN_MESSAGE)
        }
    }
}

fn bad_gateway(message: &str) -> HttpResponse {
    server::send_error(
        StatusCode::BAD_GATEWAY,
        message,
        "Invalid responses from another server/proxy",
    )
}

/// Python's text-mode `_translate_newlines`: `\r\n` and lone `\r` → `\n`.
pub fn translate_newlines(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().copied().peekable();
    while let Some(byte) = iter.next() {
        if byte == b'\r' {
            if iter.peek() == Some(&b'\n') {
                iter.next();
            }
            out.push(b'\n');
        } else {
            out.push(byte);
        }
    }
    out
}

/// `completed.stderr.strip()` as the 502 message (`None` when empty), cut
/// to [`MAX_MESSAGE_BYTES`] with control characters replaced by spaces
/// (D-3); bytes that are not UTF-8 are replaced (D-2: Python crashes).
pub fn stderr_message(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&translate_newlines(stderr)).into_owned();
    let stripped = text.trim_matches(python_space);
    if stripped.is_empty() {
        return None;
    }
    let mut end = stripped.len().min(MAX_MESSAGE_BYTES);
    while !stripped.is_char_boundary(end) {
        end -= 1;
    }
    Some(
        stripped[..end]
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect(),
    )
}

/// Python's `str.isspace()`: Unicode White_Space plus the information
/// separators U+001C–U+001F.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newlines_are_translated_as_python_text_mode() {
        assert_eq!(translate_newlines(b"a\r\nb\rc\n\r"), b"a\nb\nc\n\n");
        assert_eq!(translate_newlines(b"\r\r\n"), b"\n\n");
        assert_eq!(translate_newlines(b"\xff\r\n"), b"\xff\n");
        assert_eq!(translate_newlines(b""), b"");
    }

    #[test]
    fn stderr_message_follows_python_strip_and_d3() {
        assert_eq!(stderr_message(b""), None);
        assert_eq!(stderr_message(b" \t\n\x0b\x0c\r\x1c\x1d\x1e\x1f"), None);
        assert_eq!(stderr_message("\u{a0}\u{3000}\n".as_bytes()), None);
        assert_eq!(stderr_message(b"\n  boom \n").as_deref(), Some("boom"));
        assert_eq!(
            stderr_message(b"line1\nline2\tx\r\n").as_deref(),
            Some("line1 line2 x")
        );
        assert_eq!(stderr_message(b"bad \xff").as_deref(), Some("bad \u{fffd}"));
        let long = "é".repeat(600);
        let message = stderr_message(long.as_bytes()).unwrap();
        assert_eq!(message.len(), MAX_MESSAGE_BYTES);
        assert!(long.starts_with(&message));
        let odd = format!("x{long}");
        let message = stderr_message(odd.as_bytes()).unwrap();
        assert_eq!(message.len(), MAX_MESSAGE_BYTES - 1);
    }
}
