//! Replays `fixtures/apt_state.json` (`fixtures/generate.py`, PLAN.md 4.5,
//! 8.2): the rendered os_apt_maintenance script's `reboot_state()` against
//! [`apt_state::reboot_state`], and its handler's answers for every state
//! file case against the Rust apt-state mode over real sockets, with the
//! same frozen clock, kernel release and reboot flag.

mod support;

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use clap::Parser;
use metrics_httpd::cli::{Cli, Command};
use metrics_httpd::clock::{FixedClock, SharedClock};
use metrics_httpd::modes::Mode;
use metrics_httpd::modes::apt_state::{self, AptStateArgs, KernelRelease};
use metrics_httpd::server;
use serde_json::{Map, Value};
use support::{exchange, fixtures, raw_request};

fn load() -> Value {
    let text = std::fs::read_to_string(fixtures().join("apt_state.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// The fixture's JSON value as the Rust side parses it (Python-compatible
/// number lexemes).
fn py_value(value: &Value) -> Value {
    metrics_httpd::pyjson::parse(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn reboot_state_matches_python() {
    let fixture = load();
    let cases = fixture["reboot_state"].as_array().unwrap();
    assert!(cases.len() > 30);
    for case in cases {
        let id = text(&case["id"]);
        let Value::Object(state) = py_value(&case["state"]) else {
            panic!("{id}: state is not an object");
        };
        let actual = apt_state::reboot_state(
            &state,
            case["flag_present"].as_bool().unwrap(),
            text(&case["running_release"]),
        );
        match &case["python"] {
            Value::String(error) if error == "TypeError" => {
                assert!(actual.is_err(), "{id}: Python raises TypeError");
            }
            expected => {
                let actual = actual.unwrap_or_else(|error| panic!("{id}: {error}"));
                assert_eq!(Value::Object(actual), py_value(expected), "{id}");
            }
        }
    }
}

/// A `state_latin1` text as its bytes (one byte per code point < 256).
fn latin1(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap())
        .collect()
}

/// Writes the case's state file as the generator did.
fn write_state(path: &Path, case: &Value) {
    match case.get("state_kind").and_then(Value::as_str) {
        Some("missing") => return,
        Some("directory") => {
            std::fs::create_dir(path).unwrap();
            return;
        }
        Some("broken-symlink") => {
            std::os::unix::fs::symlink(path.with_file_name("absent.json"), path).unwrap();
            return;
        }
        Some("unreadable") => std::fs::write(path, "{}").unwrap(),
        Some(other) => panic!("unknown state kind {other}"),
        None => match case.get("state_latin1") {
            Some(data) => std::fs::write(path, latin1(text(data))).unwrap(),
            None => std::fs::write(path, text(&case["state_text"])).unwrap(),
        },
    }
    let mtime = case["mtime_epoch"].as_u64().unwrap();
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(mtime))
        .unwrap();
    if case.get("state_kind").and_then(Value::as_str) == Some("unreadable") {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
}

/// Starts the apt-state mode of the fixture's argv in process, with the
/// case's frozen clock and kernel release.
async fn start(
    args: &AptStateArgs,
    served_at_epoch: i64,
    release: &str,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let clock: SharedClock = Arc::new(FixedClock::at_epoch(served_at_epoch));
    let listener = server::bind(args.addr()).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut service = args.service(clock.clone());
    service.kernel_release = KernelRelease::Fixed(release.to_owned());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server::run(
        listener,
        args.server_config(clock),
        Arc::new(service),
        async {
            let _ = stopped.await;
        },
    ));
    (addr, stop)
}

fn parse_args(argv: &[Value], dir: &Path) -> AptStateArgs {
    let mut args = vec!["metrics-httpd".to_owned()];
    args.extend(argv.iter().map(|arg| match text(arg) {
        "{htpasswd}" => fixtures().join("htpasswd").display().to_string(),
        "{json}" => dir.join("state.json").display().to_string(),
        "{reboot_flag}" => dir.join("reboot-required").display().to_string(),
        other => other.to_owned(),
    }));
    args.extend(["--bind", "127.0.0.1", "--port", "0"].map(str::to_owned));
    match Cli::try_parse_from(args).unwrap().mode.unwrap() {
        Command::AptState(args) => args,
        other => panic!("not apt-state: {other:?}"),
    }
}

fn error_body(body: &str) -> Map<String, Value> {
    match serde_json::from_str(body).unwrap() {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

#[tokio::test]
async fn apt_state_answers_match_the_python_script() {
    let fixture = load();
    let served = fixture["served_at_epoch"].as_i64().unwrap();
    let argv = fixture["http"]["argv"].as_array().unwrap();
    let cases = fixture["http"]["cases"].as_array().unwrap();
    assert!(cases.len() > 40);
    let ok = format!(
        "Basic {}",
        base64_user_secret() // user:secret of fixtures/htpasswd
    );
    let headers = vec![("Authorization".to_owned(), ok)];
    let request = raw_request(
        "GET",
        "/.well-known/os-apt-maintenance",
        "HTTP/1.1",
        &headers,
    );
    let mut compared = 0;
    for case in cases {
        let id = text(&case["id"]);
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        write_state(&state, case);
        if case.get("state_kind").and_then(Value::as_str) == Some("unreadable")
            && std::fs::read(&state).is_ok()
        {
            // Root reads a mode-0 file; the case needs an unprivileged user.
            continue;
        }
        if case["flag_present"].as_bool().unwrap() {
            std::fs::write(
                dir.path().join("reboot-required"),
                "*** System restart required ***\n",
            )
            .unwrap();
        }
        let args = parse_args(argv, dir.path());
        let (addr, stop) = start(&args, served, text(&case["running_release"])).await;
        let request = request.clone();
        let response = tokio::task::spawn_blocking(move || exchange(addr, &request, false))
            .await
            .unwrap();
        let _ = stop.send(());
        let body = String::from_utf8(response.body.clone()).unwrap();
        assert_eq!(
            response.header("Content-Type"),
            Some("application/json"),
            "{id}"
        );
        assert_eq!(
            response.header("Content-Length"),
            Some(body.len().to_string().as_str()),
            "{id}"
        );
        match text(&case["compare"]) {
            "bytes" => {
                assert_eq!(
                    u64::from(response.status),
                    case["status"].as_u64().unwrap(),
                    "{id}"
                );
                assert_eq!(body, text(&case["body"]), "{id}");
                assert_eq!(
                    response.header("Content-Length"),
                    case["response_headers"]["Content-Length"].as_str(),
                    "{id}"
                );
            }
            "error_type_only" => {
                // D-3: the text after the fixed prefix may differ.
                assert_eq!(
                    u64::from(response.status),
                    case["status"].as_u64().unwrap(),
                    "{id}"
                );
                let expected = error_body(text(&case["body"]));
                let actual = error_body(&body);
                assert_eq!(
                    actual.keys().collect::<Vec<_>>(),
                    ["error", "error_type", "message"],
                    "{id}"
                );
                assert_eq!(actual["error"], Value::Bool(true), "{id}");
                assert_eq!(actual["error_type"], expected["error_type"], "{id}");
                assert!(
                    text(&actual["message"]).starts_with(text(&case["message_prefix"])),
                    "{id}: {body}"
                );
            }
            "rust_only" => {
                // A named allowed difference: Python crashes (D-2) or
                // accepts what Rust refuses (D-4, D-5).
                let d = text(&case["d"]);
                assert!(["D-2", "D-4", "D-5"].contains(&d), "{id}: {d}");
                assert_eq!(
                    u64::from(response.status),
                    case["rust_status"].as_u64().unwrap(),
                    "{id}"
                );
                let actual = error_body(&body);
                assert_eq!(actual["error"], Value::Bool(true), "{id}");
                assert_eq!(actual["error_type"], case["rust_error_type"], "{id}");
            }
            other => panic!("{id}: unknown compare mode {other}"),
        }
        compared += 1;
    }
    assert!(compared >= cases.len() - 1);
}

/// `base64("user:secret")`, the committed fixtures/htpasswd test entry.
fn base64_user_secret() -> &'static str {
    "dXNlcjpzZWNyZXQ="
}
