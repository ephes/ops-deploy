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

    // logyard-health: the environment, only http:// Loki URLs (D-13) and a
    // units list without rejected entries (S2d).
    let check = ["logyard-health", "--check-config"];
    assert_eq!(run_env(&check, &[]).status.code(), Some(0));
    // [{"id": "vector", "unit": "vector.service"}]
    let good_units = "W3siaWQiOiAidmVjdG9yIiwgInVuaXQiOiAidmVjdG9yLnNlcnZpY2UifV0="; // pragma: allowlist secret
    let output = run_env(&check, &[("LOGYARD_HEALTH_UNITS_B64", good_units)]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let summary = String::from_utf8(output.stdout).unwrap();
    assert!(summary.trim_end().ends_with(" units 1"), "{summary}");
    for env in [
        [("LOGYARD_LOKI_URL", "https://loki.example:3100")],
        [("LOGYARD_HEALTH_PORT", "nine")],
        [("LOGYARD_WARNING_WINDOW_SECONDS", "1.5")],
        [("LOGYARD_HEALTH_UNITS_B64", "not base64!")],
        // [{"id": "a.b", "unit": "x.service"}]
        [(
            "LOGYARD_HEALTH_UNITS_B64",
            "W3siaWQiOiAiYS5iIiwgInVuaXQiOiAieC5zZXJ2aWNlIn1d",
        )],
    ] {
        let output = run_env(&check, &env);
        assert_eq!(output.status.code(), Some(2), "{env:?}");
        assert!(output.stdout.is_empty(), "{env:?}: {output:?}");
    }
    let output = run_env(
        &check,
        &[(
            "LOGYARD_HEALTH_UNITS_B64",
            "W3siaWQiOiAiYS5iIiwgInVuaXQiOiAieC5zZXJ2aWNlIn1d",
        )],
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "metrics-httpd logyard-health: LOGYARD_HEALTH_UNITS_B64: entry rejected \
         (id_contains_dot) unit \"x.service\" id \"a.b\"\n"
    );
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

/// PLAN.md 4.6: logyard-health writes nothing per request, also when Loki
/// is down and a unit entry is rejected.
#[test]
fn logyard_health_is_silent_per_request() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let loki = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let server = Server::start(
        &["logyard-health".to_owned()],
        &[
            ("LOGYARD_HEALTH_PORT", "0"),
            ("LOGYARD_HEALTH_PATH", "/.well-known/logyard"),
            ("LOGYARD_LOKI_URL", &loki),
            ("LOGYARD_REQUEST_TIMEOUT_SECONDS", "2"),
            // [5]: one rejected entry, so no systemctl call.
            ("LOGYARD_HEALTH_UNITS_B64", "WzVd"),
        ],
    );
    let response = get(server.addr, "/elsewhere", &[]);
    assert_eq!(response.status, 404);
    assert_eq!(response.body, b"{\"error\":\"not_found\"}");
    assert_eq!(response.header("Content-Type"), Some("application/json"));
    let response = get(server.addr, "/.well-known/logyard", &[]);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("Content-Type"), Some("application/json"));
    let payload: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(payload["status"], "critical", "{payload}");
    assert_eq!(payload["loki"]["ready"], false, "{payload}");
    assert_eq!(payload["loki"]["ready_status"], Value::Null, "{payload}");
    assert!(payload["ingest"]["error"].is_string(), "{payload}");
    assert_eq!(payload["units"], serde_json::json!({}));
    assert_eq!(
        payload["units_rejected"],
        serde_json::json!([{"reason": "not_an_object"}])
    );
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

/// script flags with every required option.
fn script_args(script: &Path, timeout: &str) -> Vec<String> {
    [
        "script",
        "--bind",
        "127.0.0.1",
        "--port",
        "0",
        "--path",
        "/.well-known/health",
        "--script",
        &script.display().to_string(),
        "--script-timeout",
        timeout,
        "--htpasswd-file",
        &htpasswd(),
        "--realm",
        "metrics",
        "--server-name",
        "metrics-httpd/0.1",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn write_script(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

const USER_SECRET: &str = "Basic dXNlcjpzZWNyZXQ="; // user:secret (fixtures/htpasswd)

/// D-9: one error line per 5xx cause next to the access line; a 200 logs
/// only the access line.
#[test]
fn script_mode_logs_one_error_line_per_5xx() {
    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("ok.sh");
    let failing = dir.path().join("failing.sh");
    write_script(&ok, "#!/bin/sh\necho '{\"ok\": true}'\n");
    write_script(&failing, "#!/bin/sh\necho 'disk <full>' >&2\nexit 3\n");
    let server = Server::start(&script_args(&ok, "5"), &[]);
    let response = get(
        server.addr,
        "/.well-known/health",
        &[("Authorization", USER_SECRET)],
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"ok\": true}\n");
    assert_eq!(response.header("Content-Type"), Some("application/json"));
    let lines = server.stop();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[1].ends_with("\"GET /.well-known/health HTTP/1.1\" 200 -"));

    let server = Server::start(&script_args(&failing, "5"), &[]);
    let response = get(
        server.addr,
        "/.well-known/health",
        &[("Authorization", USER_SECRET)],
    );
    assert_eq!(response.status, 502);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("<p>Message: disk &lt;full&gt;.</p>")
    );
    let lines = server.stop();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(
        lines[1],
        format!(
            "metrics-httpd script: {} failed (exit status: 3): disk <full>",
            failing.display()
        )
    );
    assert!(lines[2].ends_with("\"GET /.well-known/health HTTP/1.1\" 502 -"));
    for line in &lines {
        assert!(!line.contains("secret") && !line.contains("dXNlcjpzZWNyZXQ="));
    }
}

/// D-8 at shutdown: SIGTERM while a script runs exits 0 after the grace
/// period and kills the script's process group.
#[test]
fn sigterm_kills_a_running_script_group() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("slow.sh");
    let pid_file = dir.path().join("slow.pid");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nsleep 60 &\necho $! > '{}'\nwait\n",
            pid_file.display()
        ),
    );
    let path = std::env::var("PATH").unwrap_or_default();
    let server = Server::start(&script_args(&script, "60"), &[("PATH", &path)]);
    let addr = server.addr;
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(&raw_request(
                "GET",
                "/.well-known/health",
                "HTTP/1.1",
                &[("Authorization".into(), USER_SECRET.into())],
            ))
            .unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the script did not start");
        std::thread::sleep(Duration::from_millis(20));
    };
    server.signal("TERM");
    let (code, lines) = server.wait(Duration::from_secs(15));
    assert_eq!(code, Some(0), "{lines:?}");
    client.join().unwrap();
    let pid = rustix::process::Pid::from_raw(pid).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let gone = rustix::process::test_kill_process(pid).is_err()
            || std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero())).is_ok_and(
                |stat| {
                    stat.rsplit_once(')')
                        .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
                },
            );
        if gone {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the script's sleep survived SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// apt-state (PLAN.md 4.5, D-9): the reboot flag and `uname` are read per
/// request, and every 5xx answer gets one error line next to the access
/// line, without credentials.
#[test]
fn apt_state_reads_flag_and_uname_per_request_and_logs_5xx_causes() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let flag = dir.path().join("reboot-required");
    let mut args = json_file_args(dir.path(), &htpasswd());
    args[0] = "apt-state".into();
    let json_index = args.iter().position(|a| a == "--json-path").unwrap();
    args[json_index + 1] = state.display().to_string();
    args.extend(
        [
            "--freshness-max-age",
            "1209600",
            "--state-max-age",
            "1296000",
            "--reboot-flag",
            &flag.display().to_string(),
        ]
        .map(str::to_owned),
    );
    let server = Server::start(&args, &[]);
    let auth = [("Authorization", "Basic dXNlcjpzZWNyZXQ=")]; // user:secret
    let body =
        |response: &support::Exchange| -> Value { serde_json::from_slice(&response.body).unwrap() };

    let missing = get(server.addr, "/.well-known/backup", &auth);
    assert_eq!(missing.status, 503);
    assert_eq!(body(&missing)["error_type"], "state_file_missing");

    let release = Command::new("uname").arg("-r").output().unwrap();
    let release = String::from_utf8(release.stdout).unwrap().trim().to_owned();
    std::fs::write(
        &state,
        serde_json::json!({
            "last_status": "success",
            "reboot_required_details": {"reasons": ["stale_kernel"], "running_kernel": release},
        })
        .to_string(),
    )
    .unwrap();
    let stale = body(&get(server.addr, "/.well-known/backup", &auth));
    assert_eq!(
        stale["reboot_required_details"]["reasons"],
        serde_json::json!(["stale_kernel"])
    );
    std::fs::write(&flag, "*** System restart required ***\n").unwrap();
    let both = body(&get(server.addr, "/.well-known/backup", &auth));
    assert_eq!(
        both["reboot_required_details"]["reasons"],
        serde_json::json!(["reboot_required_flag", "stale_kernel"])
    );
    assert_eq!(both["summary"]["reboot_required"], true);

    std::fs::write(&state, "[1]").unwrap();
    let list = get(server.addr, "/.well-known/backup", &auth);
    assert_eq!(list.status, 502);
    assert_eq!(body(&list)["error_type"], "invalid_json");

    let lines = server.stop();
    let errors: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with("metrics-httpd apt-state: "))
        .collect();
    assert_eq!(errors.len(), 2, "{lines:?}");
    assert!(errors[0].starts_with("metrics-httpd apt-state: 503 state_file_missing: "));
    assert!(errors[1].starts_with("metrics-httpd apt-state: 502 invalid_json: "));
    for line in &lines {
        assert!(!line.contains("dXNlcjpzZWNyZXQ="), "{line}");
    }
}

/// json-file through the binary (PLAN.md 4.2): the document with its meta
/// block, and D-9: one line with the cause on stderr per 5xx answer, never
/// a credential or the document.
#[test]
fn json_file_serves_the_document_and_logs_5xx_causes() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("backup.json");
    let server = Server::start(&json_file_args(dir.path(), &htpasswd()), &[]);
    let auth = [("Authorization", "Basic dXNlcjpzZWNyZXQ=")]; // user:secret
    let missing = get(server.addr, "/.well-known/backup", &auth);
    assert_eq!(missing.status, 503);
    std::fs::write(&json, "{\"z\": 1, \"secret-content\": ").unwrap();
    let invalid = get(server.addr, "/.well-known/backup", &auth);
    assert_eq!(invalid.status, 502);
    std::fs::write(&json, "{\"z\": 1.2345678987654321e999}").unwrap();
    let overflow = get(server.addr, "/.well-known/backup", &auth);
    assert_eq!(overflow.status, 502);
    std::fs::write(&json, "{\"z\": 1, \"a\": [2.50]}").unwrap();
    let ok = get(server.addr, "/.well-known/backup", &auth);
    assert_eq!(ok.status, 200);
    assert_eq!(ok.header("Content-Type"), Some("application/json"));
    let body: Value = serde_json::from_slice(&ok.body).unwrap();
    assert_eq!(body["a"], serde_json::json!([2.5]));
    let served = body["meta"]["served_at_epoch"].as_i64().unwrap();
    let generated = body["meta"]["generated_at_epoch"].as_i64().unwrap();
    assert_eq!(
        body["meta"]["age_seconds"].as_i64(),
        Some(served - generated)
    );
    assert!(
        ok.body
            .starts_with(b"{\"a\": [2.5], \"meta\": {\"age_seconds\": ")
    );
    let lines = server.stop();
    let causes: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with("metrics-httpd: json-file "))
        .collect();
    assert_eq!(causes.len(), 3, "{lines:?}");
    let path = json.display().to_string();
    assert!(
        causes[0].starts_with(&format!(
            "metrics-httpd: json-file {path}: 503 metrics_file_missing: "
        )),
        "{}",
        causes[0]
    );
    assert!(
        causes[1].starts_with(&format!(
            "metrics-httpd: json-file {path}: 502 invalid_json: "
        )),
        "{}",
        causes[1]
    );
    let access = lines
        .iter()
        .filter(|line| line.contains("\"GET /.well-known/backup HTTP/1.1\""))
        .count();
    assert!(
        causes[2].starts_with(&format!(
            "metrics-httpd: json-file {path}: 502 invalid_json: "
        )),
        "{}",
        causes[2]
    );
    assert_eq!(access, 4, "{lines:?}");
    for line in &lines {
        assert!(
            !line.contains("dXNlcjpzZWNyZXQ")
                && !line.contains("secret-content")
                && !line.contains("2345678987654321"),
            "{line}"
        );
    }
}

/// PLAN.md 4.7, D-9: the static mode logs Python's access line
/// (`<client> - "<request line>" <status> -`) to stdout, the lines of
/// `static.json`; stderr has the startup line only.
#[test]
fn static_mode_logs_access_lines_to_stdout() {
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("static.json")).unwrap())
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "index\n").unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let mut child = Command::new(BINARY)
        .args(["static", "--bind", "127.0.0.1", "--port", "0", "--root"])
        .arg(dir.path())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut startup = String::new();
    stderr.read_line(&mut startup).unwrap();
    let addr: SocketAddr = startup
        .trim_end()
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut expected = Vec::new();
    for id in [
        "root",
        "index-head",
        "missing",
        "dir-redirect",
        "put",
        "lowercase-get",
    ] {
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == id)
            .unwrap();
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
        let response = exchange(addr, &request, method == "HEAD");
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            response.header("Server"),
            Some(format!("SimpleHTTP/0.6 metrics-httpd/{}", env!("CARGO_PKG_VERSION")).as_str()),
            "{id}"
        );
        expected.push(format!(
            "127.0.0.1 - {}",
            case["access_log"].as_str().unwrap()
        ));
    }
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_eq!(out.lines().collect::<Vec<_>>(), expected);
    assert_eq!(rest, "", "stderr after the startup line");
}
