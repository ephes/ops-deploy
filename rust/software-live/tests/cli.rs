//! The command line of `software-live` against the Python program's exit
//! codes (`fixtures/cli.json`, PLAN.md 3.1): every case runs the real
//! binary with the argv the Python program got, in a directory with the
//! same files.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    files: BTreeMap<String, String>,
    binary_files: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    argv: Vec<String>,
    exit: i32,
    #[serde(default)]
    stderr: Option<String>,
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_software-live")
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn write_files(dir: &Path, fixtures: &Fixtures) {
    for (name, text) in &fixtures.files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    for (name, hex) in &fixtures.binary_files {
        std::fs::write(dir.join(name), decode_hex(hex)).unwrap();
    }
}

#[test]
fn exit_codes_match_python() {
    let fixtures: Fixtures = serde_json::from_str(include_str!("../fixtures/cli.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), &fixtures);
    let dir_text = dir.path().to_str().unwrap();
    assert!(fixtures.cases.len() >= 30);
    for case in &fixtures.cases {
        let argv: Vec<String> = case
            .argv
            .iter()
            .map(|arg| arg.replace("{dir}", dir_text))
            .collect();
        let output = Command::new(binary())
            .args(&argv)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(case.exit),
            "{}: {output:?}",
            case.id
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        if let Some(expected) = &case.stderr {
            assert_eq!(&stderr, expected, "{}", case.id);
        }
        let help = case
            .argv
            .iter()
            .any(|a| a.starts_with("-h") || a.starts_with("--he"));
        if case.exit == 0 && !help {
            assert!(
                output.stdout.is_empty(),
                "{}: validate prints nothing",
                case.id
            );
            assert!(stderr.is_empty(), "{}", case.id);
        }
        if case.exit == 1 {
            // One line, never a traceback (PLAN.md 3.8, 4.2 item 7).
            assert_eq!(stderr.lines().count(), 1, "{}: {stderr}", case.id);
        }
    }
}

#[test]
fn version_names_the_crate_version_and_the_commit() {
    let output = Command::new(binary()).arg("--version").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let rest = text
        .strip_prefix(concat!("software-live ", env!("CARGO_PKG_VERSION"), " ("))
        .unwrap_or_else(|| panic!("{text:?}"));
    let commit = rest.strip_suffix(")\n").unwrap();
    assert!(
        commit == "unknown"
            || ((7..=40).contains(&commit.len())
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "{commit:?}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn the_error_line_never_quotes_a_policy_value() {
    let secret = "do-not-print-me";
    let policy = format!(r#"{{"host": "h", "traefik": {{"expected": true, "unit": "{secret}"}}}}"#);
    let output = Command::new(binary())
        .args(["validate", "--config-json", &policy])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("ValueError: invalid Traefik policy"),
        "{stderr}"
    );
    assert!(!stderr.contains(secret), "{stderr}");
}

/// `collect --report-usage` (PLAN.md 3.1): one usage line on stderr after
/// the run, also after a failed one; other modes ignore the flag. (A
/// successful `collect` is not run here: it would read this host and ask
/// GitHub and endoflife.date; `collect::tests` run it in recorded worlds.)
#[test]
fn report_usage_adds_one_line_to_collect() {
    let usage = regex::Regex::new(
        r"^software-live: usage wall_s=\d+\.\d{3} cpu_s=\d+\.\d{3} maxrss_kib=\d+ self_cpu_s=\d+\.\d{3} self_maxrss_kib=\d+ children_cpu_s=\d+\.\d{3} children_maxrss_kib=\d+$",
    )
    .unwrap();
    for flag in ["--report-usage", "--rep"] {
        let output = Command::new(binary())
            .args(["collect", flag, "--config-json", r#"{"host": ""}"#])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{flag}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        let lines: Vec<_> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{stderr}");
        assert!(lines[0].starts_with("software-live: invalid policy: ValueError"));
        assert!(usage.is_match(lines[1]), "{stderr}");
    }
    let output = Command::new(binary())
        .args([
            "validate",
            "--report-usage",
            "--config-json",
            r#"{"host": ""}"#,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8(output.stderr).unwrap().lines().count(), 1);
    // A flag, not an option with a value; a usage error as in argparse.
    for argv in [
        &["collect", "--report-usage=yes"][..],
        &["collect", "--group", "--report-usage"],
    ] {
        let output = Command::new(binary()).args(argv).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{argv:?}");
    }
}

/// A free port on 127.0.0.1 (released again; the race with another
/// process taking it in between is accepted).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http_get(port: u16, authorization: Option<&str>) -> (u16, String) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut request = "GET /.well-known/software-live HTTP/1.1\r\nHost: x\r\n".to_owned();
    if let Some(value) = authorization {
        request.push_str(&format!("Authorization: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response.split_once("\r\n\r\n").unwrap().1.to_owned();
    (status, body)
}

#[test]
fn serve_answers_on_its_bind_address_and_logs_nothing() {
    #[derive(Deserialize)]
    struct Htpasswd {
        files: BTreeMap<String, String>,
    }
    let htpasswd: Htpasswd =
        serde_json::from_str(include_str!("../fixtures/htpasswd.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("htpasswd"), &htpasswd.files["main"]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let state = serde_json::json!({
        "schema_version": 2, "host": "example", "generated_at_epoch": now - 30.0,
        "summary": {"observation_ok": true, "os_ok": true, "postgresql_ok": true,
                    "traefik_ok": true, "security_updates_ok": true, "apt_indexes_fresh": true},
    });
    std::fs::write(dir.path().join("state.json"), state.to_string()).unwrap();
    let port = free_port();
    let config = serde_json::json!({
        "auth_user": "nyxmon", "bind": "127.0.0.1", "port": port,
        "htpasswd": dir.path().join("htpasswd"), "path": "/.well-known/software-live",
        "state": dir.path().join("state.json"),
    });
    let config_path = dir.path().join("endpoint.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let started = std::time::Instant::now();
    let mut child = Command::new(binary())
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "not listening"
        );
        assert!(child.try_wait().unwrap().is_none(), "serve exited");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let (status, body) = http_get(port, None);
    assert_eq!(status, 401);
    assert_eq!(body, r#"{"error":"unauthorized"}"#);
    // "nyxmon:correct horse battery staple"
    let good = "Basic bnl4bW9uOmNvcnJlY3QgaG9yc2UgYmF0dGVyeSBzdGFwbGU=";
    let (status, body) = http_get(port, Some(good));
    assert_eq!(status, 200);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(data["summary"]["fresh"], true);
    assert_eq!(data["host"], "example");
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stdout.is_empty());
    assert!(
        output.stderr.is_empty(),
        "no request logging: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn serve_exits_1_when_the_port_is_taken() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let config = format!(
        r#"{{"auth_user": "u", "bind": "127.0.0.1", "port": {port}, "htpasswd": "h",
            "path": "/", "state": "s"}}"#
    );
    let output = Command::new(binary())
        .args(["serve", "--config-json", &config])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("software-live: "), "{stderr}");
}
