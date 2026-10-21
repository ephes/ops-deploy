//! Process-level tests of the built binary (PLAN.md 4.8, 4.9, 8.4): exit
//! codes, `--check-config`, the startup and access log lines, timeouts and
//! the connection limit (D-1), SIGTERM/SIGINT, no credentials in any output.

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::{exchange, fixtures, raw_request, read_response};

const BINARY: &str = env!("CARGO_BIN_EXE_metrics-httpd");
/// The commit `build.rs` embedded into this build of the package.
const COMMIT: &str = env!("METRICS_HTTPD_GIT_COMMIT");

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(BINARY)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

fn is_commit(value: &str) -> bool {
    value == "unknown"
        || (7..=40).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn htpasswd() -> String {
    fixtures().join("htpasswd").display().to_string()
}

/// json-file flags with every required option, for `dir`.
fn json_file_args(dir: &Path, htpasswd: &str) -> Vec<String> {
    [
        "json-file",
        "--bind",
        "127.0.0.1",
        "--port",
        "0",
        "--path",
        "/.well-known/backup",
        "--json-path",
        &dir.join("backup.json").display().to_string(),
        "--htpasswd-file",
        htpasswd,
        "--realm",
        "backup-metrics",
        "--server-name",
        "backup-metrics-httpd/0.1",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn version_names_crate_version_and_commit() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let line = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        line,
        format!("metrics-httpd {} ({COMMIT})\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(is_commit(COMMIT), "{COMMIT:?}");
}

#[test]
fn usage_errors_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let good = json_file_args(dir.path(), &htpasswd());
    let with = |flag: &str, value: &str| {
        let mut args = good.clone();
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = value.to_owned();
        args
    };
    let cases: Vec<Vec<String>> = vec![
        vec![],
        vec!["--bogus".into()],
        vec!["--version".into(), "--version".into()],
        vec!["version".into()],
        vec!["json-file".into()],
        vec!["--version".into(), "json-file".into()],
        with("--bind", "localhost"),
        with("--port", "65536"),
        with("--path", "relative"),
        with("--realm", "a\"b"),
        [good.clone(), vec!["--request-timeout".into(), "0".into()]].concat(),
        [good.clone(), vec!["--meta".into(), "append".into()]].concat(),
        [good.clone(), vec!["--path-match".into(), "prefix".into()]].concat(),
        vec!["logyard-health".into(), "--bind".into(), "127.0.0.1".into()],
    ];
    for args in cases {
        let output = run(&strs(&args));
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let help = String::from_utf8(help.stdout).unwrap();
    for mode in [
        "json-file",
        "script",
        "apt-state",
        "logyard-health",
        "static",
    ] {
        assert!(help.contains(mode), "{help}");
    }
}

/// `--check-config`: exit 0 with one summary line, or 2; never a hash, and
/// it does not bind (the port may be taken).
#[test]
fn check_config_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    // Only $2y$/$2a$ entries pass (D-6); the fixture file also has $2b$.
    let bcrypt_only = dir.path().join("htpasswd");
    let user_line = std::fs::read_to_string(fixtures().join("htpasswd"))
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("user:") || line.starts_with("bob:"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&bcrypt_only, format!("# test\n{user_line}\n")).unwrap();
    let mut good = json_file_args(dir.path(), &bcrypt_only.display().to_string());
    good[4] = port.clone();
    good.push("--check-config".into());
    let output = run(&strs(&good));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("metrics-httpd json-file configuration ok: "),
        "{stdout}"
    );
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("bcrypt entries: 2"), "{stdout}");
    assert!(!stdout.contains("$04$"), "{stdout}");

    let empty = dir.path().join("empty-htpasswd");
    std::fs::write(&empty, "# only a comment\n\n").unwrap();
    let missing_dir = dir.path().join("nope").join("x");
    for (htpasswd, json_dir) in [
        (fixtures().join("htpasswd"), dir.path().to_owned()),
        (fixtures().join("htpasswd-mixed"), dir.path().to_owned()),
        (fixtures().join("htpasswd-invalid"), dir.path().to_owned()),
        (dir.path().join("missing"), dir.path().to_owned()),
        (empty.clone(), dir.path().to_owned()),
        (bcrypt_only.clone(), missing_dir.clone()),
    ] {
        let mut args = json_file_args(&json_dir, &htpasswd.display().to_string());
        args.push("--check-config".into());
        let output = run(&strs(&args));
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        for secret in ["$04$", "$apr1$", "{SHA}", "7jKANZTa5kFfs"] {
            assert!(!stderr.contains(secret), "{stderr}");
        }
    }

    // apt-state shares the htpasswd and file checks.
    let mut apt: Vec<String> = json_file_args(dir.path(), &bcrypt_only.display().to_string());
    apt[0] = "apt-state".into();
    apt.extend(
        [
            "--freshness-max-age",
            "1209600",
            "--state-max-age",
            "1296000",
            "--check-config",
        ]
        .map(str::to_owned),
    );
    assert_eq!(run(&strs(&apt)).status.code(), Some(0));

    // script: the script must be an executable file.
    let script = dir.path().join("metrics.sh");
    std::fs::write(&script, "#!/bin/sh\necho '{}'\n").unwrap();
    let script_args = |path: &Path| {
        let mut args = vec![
            "script",
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--path",
            "/.well-known/health",
            "--script-timeout",
            "10",
            "--realm",
            "metrics",
            "--server-name",
            "metrics-httpd/0.1",
            "--check-config",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        args.extend(["--script".to_owned(), path.display().to_string()]);
        args.extend([
            "--htpasswd-file".to_owned(),
            bcrypt_only.display().to_string(),
        ]);
        args
    };
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(run(&strs(&script_args(&script))).status.code(), Some(2));
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run(&strs(&script_args(&script))).status.code(), Some(0));
    assert_eq!(run(&strs(&script_args(dir.path()))).status.code(), Some(2));

    // static: the root must be a directory.
    let root = dir.path().display().to_string();
    let static_args = [
        "static",
        "--bind",
        "127.0.0.1",
        "--port",
        "0",
        "--root",
        &root,
        "--check-config",
    ];
    assert_eq!(run(&static_args).status.code(), Some(0));
    let file = script.display().to_string();
    let static_file = [
        "static",
        "--bind",
        "127.0.0.1",
        "--port",
        "0",
        "--root",
        &file,
        "--check-config",
    ];
    assert_eq!(run(&static_file).status.code(), Some(2));

    // logyard-health: the environment, and only http:// Loki URLs (D-13).
    let check = ["logyard-health", "--check-config"];
    assert_eq!(run_env(&check, &[]).status.code(), Some(0));
    for env in [
        [("LOGYARD_LOKI_URL", "https://loki.example:3100")],
        [("LOGYARD_HEALTH_PORT", "nine")],
        [("LOGYARD_WARNING_WINDOW_SECONDS", "1.5")],
    ] {
        assert_eq!(run_env(&check, &env).status.code(), Some(2), "{env:?}");
    }
    drop(taken);
}

/// A running endpoint whose stderr lines are collected.
struct Server {
    child: Child,
    addr: SocketAddr,
    lines: mpsc::Receiver<String>,
    collected: Vec<String>,
}

impl Server {
    fn start(args: &[String], env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(BINARY)
            .args(args)
            .env_clear()
            .envs(env.iter().copied())
            .env("TZ", "UTC")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (sender, lines) = mpsc::channel();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let startup = lines.recv_timeout(Duration::from_secs(10)).unwrap();
        let prefix = format!("metrics-httpd {} ({COMMIT}) ", env!("CARGO_PKG_VERSION"));
        assert!(startup.starts_with(&prefix), "{startup}");
        let addr = startup.rsplit(' ').next().unwrap().parse().unwrap();
        Self {
            child,
            addr,
            lines,
            collected: vec![startup],
        }
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([format!("-{name}"), self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Waits for the exit (at most `limit`) and returns the code and all
    /// stderr lines.
    fn wait(mut self, limit: Duration) -> (Option<i32>, Vec<String>) {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(200)) {
                    self.collected.push(line);
                }
                return (status.code(), self.collected);
            }
            assert!(Instant::now() < deadline, "the process did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(self) -> Vec<String> {
        self.signal("TERM");
        let (code, lines) = self.wait(Duration::from_secs(10));
        assert_eq!(code, Some(0), "{lines:?}");
        lines
    }
}

fn get(addr: SocketAddr, target: &str, headers: &[(&str, &str)]) -> support::Exchange {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    exchange(
        addr,
        &raw_request("GET", target, "HTTP/1.1", &headers),
        false,
    )
}

#[test]
fn access_log_matches_the_python_lines_and_hides_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let variants: Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("http_common.json")).unwrap(),
    )
    .unwrap();
    let backup = &variants.as_array().unwrap()[0];
    assert_eq!(backup["variant"], "backup");
    let server = Server::start(&json_file_args(dir.path(), &htpasswd()), &[]);
    let mut expected = Vec::new();
    for case in backup["cases"].as_array().unwrap() {
        let headers: Vec<(String, String)> = case["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    pair[1].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let method = case["method"].as_str().unwrap();
        let request = raw_request(
            method,
            case["target"].as_str().unwrap(),
            case["version"].as_str().unwrap(),
            &headers,
        );
        let response = exchange(server.addr, &request, method == "HEAD");
        // D-7: the Server header names the variant and the Rust binary.
        assert_eq!(
            response.header("Server"),
            Some(
                format!(
                    "backup-metrics-httpd/0.1 metrics-httpd/{}",
                    env!("CARGO_PKG_VERSION")
                )
                .as_str()
            )
        );
        assert!(response.header("Date").is_some());
        // D-14: hyper drops a fragment, so the line differs there.
        expected.push(
            case.get("d")
                .is_none()
                .then(|| case["access_log"].as_str().unwrap().to_owned()),
        );
    }
    // A wrong password must not show up anywhere.
    let token = "dXNlcjpkby1ub3QtbG9nLW1l"; // user:do-not-log-me
    get(
        server.addr,
        "/.well-known/backup",
        &[("Authorization", &format!("Basic {token}"))],
    );
    let lines = server.stop();
    let access: Vec<String> = lines[1..]
        .iter()
        .map(|line| {
            let (client, rest) = line.split_once(" - - [").unwrap();
            assert_eq!(client, "127.0.0.1");
            let (time, rest) = rest.split_once("] ").unwrap();
            // `%02d/%3s/%04d %02d:%02d:%02d` (log_date_time_string).
            assert_eq!(time.len(), 20, "{line}");
            rest.to_owned()
        })
        .collect();
    assert_eq!(access.len(), expected.len() + 1, "{access:?}");
    for (actual, expected) in access.iter().zip(&expected) {
        if let Some(expected) = expected {
            assert_eq!(actual, expected);
        }
    }
    for line in &lines {
        assert!(
            !line.contains(token) && !line.contains("do-not-log-me"),
            "{line}"
        );
    }
}

#[test]
fn sigint_and_sigterm_exit_0_and_idle_keep_alive_does_not_block() {
    let dir = tempfile::tempdir().unwrap();
    for signal in ["TERM", "INT"] {
        let server = Server::start(&json_file_args(dir.path(), &htpasswd()), &[]);
        // An idle keep-alive connection after one exchange.
        let mut stream = TcpStream::connect(server.addr).unwrap();
        stream
            .write_all(&raw_request("GET", "/.well-known/backup", "HTTP/1.1", &[]))
            .unwrap();
        assert_eq!(read_response(&mut stream, false).status, 401);
        let start = Instant::now();
        server.signal(signal);
        let (code, _) = server.wait(Duration::from_secs(10));
        assert_eq!(code, Some(0));
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "{:?}",
            start.elapsed()
        );
    }
}

/// PLAN.md 4.8: in-flight requests get 5 s after SIGTERM, then the process
/// exits even while a bcrypt check still runs on the blocking pool.
#[test]
fn sigterm_does_not_wait_for_a_running_bcrypt_check() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixtures().join("htpasswd")).unwrap();
    let hash = fixture
        .lines()
        .find_map(|line| line.strip_prefix("user:"))
        .unwrap();
    // The same salt and digest at cost 20: verifying takes minutes.
    let slow = dir.path().join("htpasswd");
    std::fs::write(&slow, format!("slow:$2y$20${}\n", &hash[7..])).unwrap();
    let server = Server::start(
        &json_file_args(dir.path(), &slow.display().to_string()),
        &[],
    );
    let addr = server.addr;
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        let header = "Authorization: Basic c2xvdzpwYXNzd29yZA==\r\n"; // slow:password
        let request = format!("GET /.well-known/backup HTTP/1.1\r\nHost: x\r\n{header}\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
    });
    std::thread::sleep(Duration::from_millis(300));
    let start = Instant::now();
    server.signal("TERM");
    let (code, lines) = server.wait(Duration::from_secs(15));
    assert_eq!(code, Some(0), "{lines:?}");
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
    client.join().unwrap();
}

#[test]
fn bind_failure_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut args = json_file_args(dir.path(), &htpasswd());
    args[4] = taken.local_addr().unwrap().port().to_string();
    let output = run(&strs(&args));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot listen")
    );
}

/// D-1: the header-read timeout closes a silent connection, the same
/// timeout closes an idle keep-alive connection.
#[test]
fn request_timeout_closes_silent_and_idle_connections() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = json_file_args(dir.path(), &htpasswd());
    args.extend(["--request-timeout".to_owned(), "0.3".to_owned()]);
    let server = Server::start(&args, &[]);
    let closed_within = |stream: &mut TcpStream| {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 64];
        let read = stream.read(&mut buf).unwrap_or(0);
        (read, start.elapsed())
    };
    let mut silent = TcpStream::connect(server.addr).unwrap();
    let (read, elapsed) = closed_within(&mut silent);
    assert!(
        read == 0 && elapsed < Duration::from_secs(3),
        "{read} {elapsed:?}"
    );

    let mut idle = TcpStream::connect(server.addr).unwrap();
    idle.write_all(&raw_request("GET", "/.well-known/backup", "HTTP/1.1", &[]))
        .unwrap();
    assert_eq!(read_response(&mut idle, false).status, 401);
    let (read, elapsed) = closed_within(&mut idle);
    assert!(
        read == 0 && elapsed < Duration::from_secs(3),
        "{read} {elapsed:?}"
    );
    server.stop();
}

/// D-1: at most 64 connections are served; the next waits in the accept
/// queue until one closes.
#[test]
fn connection_limit_is_64() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = json_file_args(dir.path(), &htpasswd());
    args.extend(["--request-timeout".to_owned(), "30".to_owned()]);
    let server = Server::start(&args, &[]);
    let mut idle: Vec<TcpStream> = (0..64)
        .map(|_| {
            let mut stream = TcpStream::connect(server.addr).unwrap();
            // A started request keeps the connection busy.
            stream
                .write_all(b"GET /.well-known/backup HTTP/1.1\r\n")
                .unwrap();
            stream
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let mut waiting = TcpStream::connect(server.addr).unwrap();
    waiting
        .write_all(&raw_request("GET", "/.well-known/backup", "HTTP/1.1", &[]))
        .unwrap();
    waiting
        .set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    let mut buf = [0u8; 16];
    assert!(
        waiting.read(&mut buf).is_err(),
        "the 65th connection was served"
    );
    idle.truncate(60);
    waiting
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(read_response(&mut waiting, false).status, 401);
    drop(idle);
    server.stop();
}

#[test]
fn ipv6_bind_works_in_every_mode() {
    if TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipped: no IPv6 loopback");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut args = json_file_args(dir.path(), &htpasswd());
    args[2] = "::1".into();
    let server = Server::start(&args, &[]);
    assert!(server.addr.is_ipv6());
    assert_eq!(get(server.addr, "/.well-known/backup", &[]).status, 401);
    let lines = server.stop();
    assert!(lines[1].starts_with("::1 - - ["), "{lines:?}");
}

/// PLAN.md 4.6: logyard-health writes nothing per request.
#[test]
fn logyard_health_is_silent_per_request() {
    let server = Server::start(
        &["logyard-health".to_owned()],
        &[
            ("LOGYARD_HEALTH_PORT", "0"),
            ("LOGYARD_HEALTH_PATH", "/.well-known/logyard"),
        ],
    );
    let response = get(server.addr, "/elsewhere", &[]);
    assert_eq!(response.status, 404);
    assert_eq!(response.body, b"{\"error\":\"not_found\"}");
    assert_eq!(response.header("Content-Type"), Some("application/json"));
    let lines = server.stop();
    assert_eq!(lines.len(), 1, "{lines:?}");
}

/// The stubs of S1 answer the gate per PLAN.md 4.1 in every mode.
#[test]
fn every_mode_answers_the_gate() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("metrics.sh");
    let mut modes: Vec<Vec<String>> = Vec::new();
    modes.push(json_file_args(dir.path(), &htpasswd()));
    let mut apt = json_file_args(dir.path(), &htpasswd());
    apt[0] = "apt-state".into();
    apt.extend(["--freshness-max-age", "1", "--state-max-age", "1"].map(str::to_owned));
    modes.push(apt);
    let mut script_mode = json_file_args(dir.path(), &htpasswd());
    script_mode[0] = "script".into();
    let json_index = script_mode.iter().position(|a| a == "--json-path").unwrap();
    script_mode[json_index] = "--script".into();
    script_mode[json_index + 1] = script.display().to_string();
    script_mode.extend(["--script-timeout", "5"].map(str::to_owned));
    modes.push(script_mode);
    for args in modes {
        let server = Server::start(&args, &[]);
        assert_eq!(
            get(server.addr, "/.well-known/backup", &[]).status,
            401,
            "{args:?}"
        );
        assert_eq!(get(server.addr, "/other", &[]).status, 404, "{args:?}");
        let post = exchange(
            server.addr,
            &raw_request("POST", "/.well-known/backup", "HTTP/1.1", &[]),
            false,
        );
        assert_eq!(post.status, 501, "{args:?}");
        server.stop();
    }
    let root = dir.path().display().to_string();
    let server = Server::start(
        &[
            "static",
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--root",
            &root,
        ]
        .map(str::to_owned),
        &[],
    );
    let put = exchange(
        server.addr,
        &raw_request(
            "PUT",
            "/",
            "HTTP/1.1",
            &[("Content-Length".into(), "0".into())],
        ),
        false,
    );
    assert_eq!(put.status, 501);
    server.stop();
}
