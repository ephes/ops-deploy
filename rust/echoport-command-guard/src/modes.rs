//! The modes that read `SSH_ORIGINAL_COMMAND` (PLAN.md 3.1, 3.6;
//! `guard.py:681-717`): forced-command mode, `--decide` and `--shadow`.
//! `main.rs` holds the argv grammar and calls these with the real host
//! ([`Host`]); the process tests call them with a stub `check()` and their
//! own search path and logger.

use std::any::Any;
use std::cell::RefCell;
use std::ffi::{CString, OsStr};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::ExitCode;

use nix::sys::stat::{Mode, umask};
use serde_json::{Value, json};

use crate::PROGRAM;
use crate::decision::{Decision, Refused};
use crate::env::GuardEnv;
use crate::exec;
use crate::mutate;
use crate::policy::{Policy, load_policy};
use crate::redirect;
use crate::repr::py_repr_bytes;
use crate::syslog::{Ident, Logger, Priority, truncate};

/// `check(command, policy)` with its host lookups.
pub type Checker = fn(&[u8], &Policy, &dyn GuardEnv) -> Result<Decision, Refused>;

/// What the modes act on.
pub struct Host<'a> {
    /// The lookups of `check()` and the redirect owner check.
    pub env: &'a dyn GuardEnv,
    pub log: &'a dyn Logger,
    /// [`crate::rules::check`]; a stub in the process tests.
    pub check: Checker,
    /// `PATH` for the exec: [`exec::SAFE_PATH`]; a test directory in the
    /// process tests.
    pub search_path: &'a str,
}

thread_local! {
    static PANIC_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A panic hook that prints nothing (stderr belongs to the SSH client) and
/// keeps the panic's text and location for the log line.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        PANIC_TEXT.with(|text| *text.borrow_mut() = Some(info.to_string().replace('\n', " ")));
    }));
}

/// Runs `f`; a panic becomes `Err(<text>)`.
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|payload| {
        PANIC_TEXT
            .with(|text| text.borrow_mut().take())
            .unwrap_or_else(|| payload_text(payload.as_ref()))
    })
}

fn payload_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        format!("panicked: {text}")
    } else if let Some(text) = payload.downcast_ref::<String>() {
        format!("panicked: {text}")
    } else {
        "panicked".to_owned()
    }
}

/// `SSH_ORIGINAL_COMMAND` as bytes (Python decodes them with
/// `surrogateescape`; the prefilter and the log lines handle the bytes).
fn original_command() -> Option<Vec<u8>> {
    std::env::var_os("SSH_ORIGINAL_COMMAND").map(|command| command.as_bytes().to_vec())
}

/// `os.environ.get("SSH_CLIENT", "-").split(" ")[0]`.
fn client() -> String {
    match std::env::var_os("SSH_CLIENT") {
        Some(value) => {
            let bytes = value.as_bytes();
            let first = bytes.split(|b| *b == b' ').next().unwrap_or_default();
            String::from_utf8_lossy(first).into_owned()
        }
        None => "-".to_owned(),
    }
}

/// A guard line (`_log`, `guard.py:654-659`): cut after 1000 characters.
fn log(host: &Host<'_>, priority: Priority, message: &str) {
    host.log.log(Ident::Guard, priority, truncate(message));
}

fn refuse(host: &Host<'_>, client: &str, reason: &str, command: &[u8]) -> ExitCode {
    log(
        host,
        Priority::Warning,
        &format!(
            "refused from {client}: {reason}: {}",
            py_repr_bytes(command)
        ),
    );
    eprintln!("{PROGRAM}: command not allowed");
    ExitCode::FAILURE
}

/// Forced-command mode (`<prog> <policy>`, PLAN.md 3.1): refuse, make an
/// allowed mutation itself (exit 0, H1), or exec the allowed command.
/// Returns only when nothing was executed: 0 for a mutation made, 1 for a
/// refusal, 127 when the exec failed.
pub fn forced_command(host: &Host<'_>, policy_path: &OsStr) -> ExitCode {
    let client = client();
    // 1. Interactive sessions, before the policy is read.
    let Some(command) = original_command() else {
        log(
            host,
            Priority::Warning,
            &format!("refused interactive session from {client}"),
        );
        eprintln!("{PROGRAM}: interactive sessions are not allowed");
        return ExitCode::FAILURE;
    };
    // 2. The policy.
    let policy = match guarded(|| load_policy(Path::new(policy_path))) {
        Ok(Ok(policy)) => policy,
        failed => {
            let kind = match failed {
                Ok(Err(error)) => error.kind.python_name(),
                _ => "OSError",
            };
            log(
                host,
                Priority::Err,
                &format!(
                    "policy error ({kind}): refusing {}",
                    py_repr_bytes(&command)
                ),
            );
            eprintln!("{PROGRAM}: policy error");
            return ExitCode::FAILURE;
        }
    };
    // 3. check(), the umask, the redirects.
    let decision = match guarded(|| (host.check)(&command, &policy, host.env)) {
        Ok(Ok(decision)) => decision,
        Ok(Err(refused)) => return refuse(host, &client, refused.reason(), &command),
        Err(panic) => {
            return refuse(host, &client, &format!("internal error: {panic}"), &command);
        }
    };
    if let Some(mutation) = &decision.mutation {
        // Made here, on file descriptors; nothing is executed (H1). `chmod`,
        // `mv` and `rm` as the root's owner, `chown` as root.
        let made = guarded(|| {
            if let Some(user) = &mutation.user {
                mutate::become_user(user, host.env)?;
            }
            mutate::perform(mutation, host.env, &mut |_, _| {})
        });
        match made {
            Ok(Ok(())) => {}
            Ok(Err(refused)) => return refuse(host, &client, refused.reason(), &command),
            Err(panic) => {
                return refuse(host, &client, &format!("internal error: {panic}"), &command);
            }
        }
        log(
            host,
            Priority::Info,
            &format!("allowed from {client}: {}", py_repr_bytes(&command)),
        );
        return ExitCode::SUCCESS;
    }
    let argv = match exec::c_argv(&decision.argv) {
        Ok(argv) if !argv.is_empty() => argv,
        _ => return refuse(host, &client, "internal error: unusable argv", &command),
    };
    match decision.umask {
        None => {}
        // `umask 077 && ...`, the only umask a decision carries.
        Some(0o077) => {
            umask(Mode::S_IRWXG | Mode::S_IRWXO);
        }
        Some(_) => return refuse(host, &client, "internal error: unexpected umask", &command),
    }
    if let Err(error) = redirect::apply(&decision, host.env) {
        return refuse(host, &client, &error.to_string(), &command);
    }
    // 4. Log, then exec.
    log(
        host,
        Priority::Info,
        &format!("allowed from {client}: {}", py_repr_bytes(&command)),
    );
    let errno = match exec::exec_command(&argv, host.search_path) {
        Err(errno) => errno,
        Ok(never) => match never {},
    };
    let program = decision
        .argv
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    eprintln!("{PROGRAM}: cannot run {program}: {}", exec::strerror(errno));
    ExitCode::from(127)
}

/// The decision for `SSH_ORIGINAL_COMMAND` as JSON (`--decide`, the shadow
/// record), and whether it allows the command. It never opens a redirect,
/// changes the umask, logs or execs. Verdicts:
///
/// - `allowed`, with `argv`, `umask`, `stdin`, `stdout` (the fixtures'
///   form);
/// - `refused`, with `reason`;
/// - `interactive` (`SSH_ORIGINAL_COMMAND` unset);
/// - `policy-error`, with `error_type` (Python's name) and `message`;
/// - `panic`, with `reason` (never for a correct guard).
pub fn decision_record(host: &Host<'_>, policy_path: &OsStr) -> (Value, bool) {
    let record = guarded(|| {
        let Some(command) = original_command() else {
            return (json!({"verdict": "interactive"}), false);
        };
        let policy = match load_policy(Path::new(policy_path)) {
            Ok(policy) => policy,
            Err(error) => {
                return (
                    json!({"verdict": "policy-error", "error_type": error.kind.python_name(),
                           "message": error.message}),
                    false,
                );
            }
        };
        match (host.check)(&command, &policy, host.env) {
            Ok(decision) => (decision.to_json(), true),
            Err(refused) => (
                json!({"verdict": "refused", "reason": refused.reason()}),
                false,
            ),
        }
    });
    record.unwrap_or_else(|panic| (json!({"verdict": "panic", "reason": panic}), false))
}

/// `--decide <policy>`: the decision as one JSON line on `out`. Exit 0 when
/// the command is allowed, 1 otherwise.
pub fn decide(host: &Host<'_>, policy_path: &OsStr, out: &mut dyn Write) -> ExitCode {
    let (record, allowed) = decision_record(host, policy_path);
    if let Err(error) = writeln!(out, "{record}").and_then(|()| out.flush()) {
        eprintln!("{PROGRAM}: cannot write the decision: {error}");
        return ExitCode::FAILURE;
    }
    if allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The tail of `--shadow`: the Python guard's forced command.
pub struct PythonGuard<'a> {
    pub python: &'a OsStr,
    pub guard: &'a OsStr,
    pub policy: &'a OsStr,
}

impl PythonGuard<'_> {
    /// `<python> -I <guard> <policy>`: both programs absolute.
    pub fn is_valid(&self) -> bool {
        self.python.as_bytes().starts_with(b"/") && self.guard.as_bytes().starts_with(b"/")
    }
}

/// `--shadow <policy> <python> -I <guard> <policy>` (PLAN.md 3.6): log the
/// Rust decision under `echoport-remote-command-guard-shadow`, then always
/// exec the Python guard with the environment unchanged; the PID stays, so
/// the two log lines pair up by `_PID`. Returns only if that exec fails
/// (127).
pub fn shadow(host: &Host<'_>, python_guard: &PythonGuard<'_>) -> ExitCode {
    let (record, _) = decision_record(host, python_guard.policy);
    let _ = guarded(|| {
        host.log
            .log(Ident::Shadow, Priority::Info, &record.to_string())
    });
    let argv: Result<Vec<CString>, _> = [
        python_guard.python,
        OsStr::new("-I"),
        python_guard.guard,
        python_guard.policy,
    ]
    .iter()
    .map(|arg| CString::new(arg.as_bytes()))
    .collect();
    let errno = match argv {
        Ok(argv) => exec::execv_program(python_guard.python, &argv),
        Err(_) => nix::errno::Errno::EINVAL,
    };
    eprintln!(
        "{PROGRAM}: cannot run {}: {}",
        python_guard.python.to_string_lossy(),
        exec::strerror(errno)
    );
    ExitCode::from(127)
}
