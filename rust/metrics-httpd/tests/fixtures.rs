//! Replays the Python-generated fixtures (`fixtures/generate.py`, PLAN.md
//! 8.2) against the Rust modules: the JSON formatter and value semantics
//! (D-4, D-5), the meta helpers, the auth decisions (D-2, D-6), the
//! 501/404/401 gate of every mode over real sockets (PLAN.md 4.1) and the
//! script mode past the gate (PLAN.md 4.4, D-2, D-3, D-8, D-12).

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use metrics_httpd::auth::{self, PasswordSource};
use metrics_httpd::cli::{Cli, Command};
use metrics_httpd::clock::{FixedClock, SharedClock};
use metrics_httpd::meta;
use metrics_httpd::modes::Mode;
use metrics_httpd::modes::logyard_health::LogyardConfig;
use metrics_httpd::pyjson::{self, PyInt};
use metrics_httpd::server;
use serde_json::Value;
use support::{exchange, fixtures, raw_request};

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(fixtures().join(name)).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
fn float_repr_matches_cpython() {
    let mut count = 0;
    let mut parts: Vec<PathBuf> = std::fs::read_dir(fixtures().join("float_repr"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    parts.sort();
    assert!(!parts.is_empty());
    for part in parts {
        let content = std::fs::read_to_string(&part).unwrap();
        for line in content.lines().filter(|line| !line.starts_with('#')) {
            let x: f64 = line.parse().unwrap();
            assert_eq!(pyjson::float_repr(x), line, "{}", part.display());
            count += 1;
        }
    }
    // PLAN.md D-5: at least 100,000 random bit patterns plus the extra cases.
    assert!(count > 150_000, "{count}");
}

#[test]
fn json_round_trip_matches_python_dumps() {
    let fixture = load("pyjson.json");
    let cases = fixture["dumps"].as_array().unwrap();
    assert!(cases.len() > 2_000);
    for case in cases {
        let id = text(&case["id"]);
        let input = match case.get("input") {
            Some(input) => text(input).as_bytes().to_vec(),
            None => hex(text(&case["input_hex"])),
        };
        let parsed = pyjson::parse(&input);
        match text(&case["rust"]) {
            "same" => {
                let value = parsed.unwrap_or_else(|error| panic!("{id}: {error}"));
                let output = String::from_utf8(pyjson::dumps(&value)).unwrap();
                assert_eq!(output, text(&case["python"]), "{id}");
            }
            "invalid" => {
                assert!(parsed.is_err(), "{id}: Rust must refuse it");
                if case.get("python").is_some() {
                    // Python accepts: a named allowed difference.
                    assert!(case.get("d").is_some(), "{id}");
                }
            }
            other => panic!("{id}: unknown expectation {other}"),
        }
    }
}

#[test]
fn value_semantics_match_python() {
    let fixture = load("pyjson.json");
    for case in fixture["values"].as_array().unwrap() {
        let input = text(&case["input"]);
        let value = pyjson::parse(input.as_bytes()).unwrap();
        assert_eq!(
            pyjson::truthy(&value),
            case["truthy"].as_bool().unwrap(),
            "{input}"
        );
        assert_eq!(
            pyjson::is_py_int(&value),
            case["is_int"].as_bool().unwrap(),
            "{input}"
        );
        match (&case["int"], pyjson::py_int(&value)) {
            (Value::Null, None) => {}
            (Value::String(expected), Some(PyInt::Value(actual))) => {
                assert_eq!(&actual.to_string(), expected, "{input}");
            }
            (Value::String(expected), Some(PyInt::OutOfRange)) => {
                assert!(expected.parse::<i128>().is_err(), "{input}");
            }
            (expected, actual) => panic!("{input}: {expected:?} vs {actual:?}"),
        }
        let contains = pyjson::contains_str(&value, "stale_kernel");
        match &case["contains_stale_kernel"] {
            Value::Bool(expected) => assert_eq!(contains, Ok(*expected), "{input}"),
            Value::String(error) if error == "TypeError" => assert!(contains.is_err(), "{input}"),
            other => panic!("{input}: {other:?}"),
        }
    }
}

#[test]
fn meta_helpers_match_python() {
    let fixture = load("meta.json");
    for case in fixture["iso_utc"].as_array().unwrap() {
        let epoch = case["epoch"].as_i64().unwrap();
        assert_eq!(
            meta::iso_utc(epoch).as_deref(),
            case["python"].as_str(),
            "{epoch}"
        );
    }
    for case in fixture["mtime_epoch"].as_array().unwrap() {
        let (sec, nsec) = (
            case["sec"].as_i64().unwrap(),
            case["nsec"].as_i64().unwrap(),
        );
        assert_eq!(
            meta::float_mtime_epoch(sec, nsec),
            case["python"].as_i64().unwrap(),
            "{sec}.{nsec:09}"
        );
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn latin1(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap())
        .collect()
}

#[test]
fn auth_decisions_match_htpasswd() {
    let dir = tempfile::tempdir().unwrap();
    let unreadable = dir.path().join("htpasswd-unreadable");
    std::fs::copy(fixtures().join("htpasswd"), &unreadable).unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable_works = std::fs::read(&unreadable).is_err(); // false as root
    let files: HashMap<&str, PathBuf> = HashMap::from([
        ("htpasswd", fixtures().join("htpasswd")),
        ("htpasswd-mixed", fixtures().join("htpasswd-mixed")),
        ("htpasswd-invalid", fixtures().join("htpasswd-invalid")),
        ("missing", dir.path().join("missing")),
        ("unreadable", unreadable),
    ]);
    let cases = load("auth.json");
    let cases = cases.as_array().unwrap();
    assert!(cases.len() > 60);
    for case in cases {
        let id = text(&case["id"]);
        let file = text(&case["file"]);
        if file == "unreadable" && !unreadable_works {
            continue;
        }
        let header = case["header"].as_str().map(latin1);
        // D-6: the strict base64 rule is Python's strict_mode decoder.
        if let Some(strict) = case["strict_base64"].as_bool() {
            let token = auth::basic_token(header.as_deref().unwrap()).unwrap();
            assert_eq!(auth::decode_base64(token).is_some(), strict, "{id}");
        }
        for (source, key) in [(PasswordSource::Stdin, "vi"), (PasswordSource::Argv, "vb")] {
            let decision = auth::parse_basic(header.as_deref()).is_some_and(|credentials| {
                std::fs::read(&files[file])
                    .is_ok_and(|contents| auth::verify(&contents, &credentials, source))
            });
            let expected = text(&case["rust"][key]) == "ok";
            assert_eq!(decision, expected, "{id} ({key})");
            if text(&case["python"][key]) != text(&case["rust"][key]) {
                assert!(
                    case["d"][key].is_string(),
                    "{id} ({key}): difference without a D item"
                );
                // An allowed difference never widens access.
                assert!(!decision, "{id} ({key})");
            }
        }
    }
}

/// Starts a mode in process on an ephemeral loopback port.
async fn start<M: Mode>(mode: M) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let clock: SharedClock = Arc::new(FixedClock::at_epoch(1_792_576_800));
    let listener = server::bind(mode.addr()).unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let service = Arc::new(mode.service(clock.clone()));
    let config = mode.server_config(clock);
    tokio::spawn(server::run(listener, config, service, async {
        let _ = stopped.await;
    }));
    (addr, stop)
}

async fn start_variant(
    argv: &[String],
    env: &HashMap<String, String>,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    if argv[0] == "logyard-health" {
        let mut env = env.clone();
        env.insert("LOGYARD_HEALTH_PORT".to_owned(), "0".to_owned());
        return start(LogyardConfig::from_env(|name| env.get(name).cloned()).unwrap()).await;
    }
    let mut args = vec!["metrics-httpd".to_owned()];
    args.extend(argv.iter().cloned());
    args.extend(["--bind", "127.0.0.1", "--port", "0"].map(str::to_owned));
    match Cli::try_parse_from(args).unwrap().mode.unwrap() {
        Command::JsonFile(mode) => start(mode).await,
        Command::Script(mode) => start(mode).await,
        Command::AptState(mode) => start(mode).await,
        Command::Static(mode) => start(mode).await,
        Command::LogyardHealth(_) => unreachable!(),
    }
}

/// The argv of a variant with the fixture placeholders filled in.
pub fn variant_argv(variant: &Value, dir: &Path) -> Vec<String> {
    variant["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|arg| match text(arg) {
            "{htpasswd}" => fixtures().join("htpasswd").display().to_string(),
            "{json}" => dir.join("missing.json").display().to_string(),
            "{script}" => dir.join("script.sh").display().to_string(),
            other => other.to_owned(),
        })
        .collect()
}

/// CPython 3.14 added a `<style>` block to `send_error`'s page; the hosts
/// (3.12, 3.13) and Rust do not have it (D-3 allows the difference).
fn without_style(body: &str) -> String {
    match (body.find("        <style"), body.find("</style>\n")) {
        (Some(start), Some(end)) => {
            format!("{}{}", &body[..start], &body[end + "</style>\n".len()..])
        }
        _ => body.to_owned(),
    }
}

#[tokio::test]
async fn gate_answers_match_the_python_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let variants = load("http_common.json");
    for variant in variants.as_array().unwrap() {
        let name = text(&variant["variant"]);
        let argv = variant_argv(variant, dir.path());
        let env: HashMap<String, String> = variant
            .get("env")
            .and_then(Value::as_object)
            .map(|env| {
                env.iter()
                    .map(|(k, v)| (k.clone(), text(v).to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let (addr, stop) = start_variant(&argv, &env).await;
        for case in variant["cases"].as_array().unwrap() {
            let id = format!("{name}/{}", text(&case["id"]));
            let method = text(&case["method"]).to_owned();
            let headers: Vec<(String, String)> = case["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (text(&pair[0]).to_owned(), text(&pair[1]).to_owned()))
                .collect();
            let request = raw_request(
                &method,
                text(&case["target"]),
                text(&case["version"]),
                &headers,
            );
            let head = method == "HEAD";
            let response = tokio::task::spawn_blocking(move || exchange(addr, &request, head))
                .await
                .unwrap();
            if let Some(status) = case.get("rust_status") {
                // A named allowed difference (D-14): only the status is pinned.
                assert!(case["d"].is_string(), "{id}");
                assert_eq!(u64::from(response.status), status.as_u64().unwrap(), "{id}");
                continue;
            }
            assert_eq!(
                u64::from(response.status),
                case["status"].as_u64().unwrap(),
                "{id}"
            );
            let expected = &case["response_headers"];
            let body = String::from_utf8(response.body.clone()).unwrap();
            let compare = text(&case["compare"]);
            for name in [
                "Content-Type",
                "WWW-Authenticate",
                "Connection",
                "Content-Length",
            ] {
                if name == "Content-Length" && compare != "bytes" {
                    continue;
                }
                assert_eq!(
                    response.header(name),
                    expected[name].as_str(),
                    "{id}: {name}"
                );
            }
            match compare {
                "bytes" => assert_eq!(body, text(&case["body"]), "{id}"),
                "html" => assert_eq!(body, without_style(text(&case["body"])), "{id}"),
                "logyard-404" => {
                    // D-7: Rust adds Content-Length (Python's HTTP/1.0 404 has none).
                    assert_eq!(body, text(&case["body"]), "{id}");
                    let length = response
                        .header("Content-Length")
                        .map(|v| v.parse::<usize>().unwrap());
                    assert_eq!(length, (!head).then_some(body.len()).or(length), "{id}");
                }
                other => panic!("{id}: unknown compare mode {other}"),
            }
        }
        let _ = stop.send(());
    }
}

/// Script cases spawn processes; they run one test at a time, so a script
/// written by one test is never open for writing while another test's
/// server forks (`ETXTBSY` on Linux).
static SCRIPT_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The script-mode argv of `script.json` for one script and timeout.
fn script_argv(fixture: &Value, script: &Path, timeout: &str) -> Vec<String> {
    fixture["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|arg| match text(arg) {
            "{htpasswd}" => fixtures().join("htpasswd").display().to_string(),
            "{script}" => script.display().to_string(),
            "{timeout}" => timeout.to_owned(),
            other => other.to_owned(),
        })
        .collect()
}

/// The authenticated request every `script.json` case sends.
fn script_request(fixture: &Value) -> Vec<u8> {
    let request = &fixture["request"];
    let headers: Vec<(String, String)> = request["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (text(&pair[0]).to_owned(), text(&pair[1]).to_owned()))
        .collect();
    raw_request(
        text(&request["method"]),
        text(&request["target"]),
        text(&request["version"]),
        &headers,
    )
}

fn write_script(path: &Path, content: &str, mode: u32) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The `send_error` page line that carries the message.
fn message_line(message: &str) -> String {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<p>Message: {escaped}.</p>")
}

async fn script_exchange(argv: &[String], request: Vec<u8>) -> support::Exchange {
    let (addr, stop) = start_variant(argv, &HashMap::new()).await;
    let response = tokio::task::spawn_blocking(move || exchange(addr, &request, false))
        .await
        .unwrap();
    let _ = stop.send(());
    response
}

#[tokio::test]
async fn script_mode_matches_metrics_httpd_py() {
    let _serial = SCRIPT_TESTS.lock().await;
    let fixture = load("script.json");
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    let dir = tempfile::tempdir().unwrap();
    // Every script is written before any server forks.
    for case in cases {
        if let Some(script) = case["script"].as_str() {
            let mode = u32::from_str_radix(text(&case["mode"]), 8).unwrap();
            write_script(
                &dir.path().join(format!("{}.sh", text(&case["id"]))),
                script,
                mode,
            );
        }
    }
    for case in cases {
        let id = text(&case["id"]);
        let script = dir.path().join(format!("{id}.sh"));
        let argv = script_argv(&fixture, &script, text(&case["timeout"]));
        let response = script_exchange(&argv, script_request(&fixture)).await;
        let compare = text(&case["compare"]);
        if matches!(compare, "status" | "no-response") {
            // Python drops the connection or the plan allows a difference:
            // the Rust expectation is written next to the case.
            assert!(case["d"].is_string(), "{id}");
            assert_eq!(
                u64::from(response.status),
                case["rust_status"].as_u64().unwrap(),
                "{id}"
            );
            if let Some(message) = case.get("rust_message") {
                assert_eq!(
                    response.header("Content-Type"),
                    Some("text/html;charset=utf-8"),
                    "{id}"
                );
                assert_eq!(response.header("Connection"), Some("close"), "{id}");
                let body = String::from_utf8(response.body.clone()).unwrap();
                assert!(body.contains(&message_line(text(message))), "{id}: {body}");
            }
            if let Some(hex) = case.get("rust_body_hex") {
                assert_eq!(
                    response.header("Content-Type"),
                    Some("application/json"),
                    "{id}"
                );
                assert_eq!(response.body, hex_bytes(text(hex)), "{id}");
            }
            continue;
        }
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{id}"
        );
        let expected = &case["response_headers"];
        for name in [
            "Content-Type",
            "WWW-Authenticate",
            "Connection",
            "Content-Length",
        ] {
            if name == "Content-Length" && compare != "bytes" {
                continue;
            }
            assert_eq!(
                response.header(name),
                expected[name].as_str(),
                "{id}: {name}"
            );
        }
        let body = String::from_utf8(response.body.clone()).unwrap();
        match compare {
            "bytes" => assert_eq!(body, text(&case["body"]), "{id}"),
            "html" => assert_eq!(body, without_style(text(&case["body"])), "{id}"),
            other => panic!("{id}: unknown compare mode {other}"),
        }
    }
}

/// Whether `pid` is gone (or a zombie nobody reaped yet).
fn process_gone(pid: i32) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return true;
    };
    if rustix::process::test_kill_process(pid).is_err() {
        return true;
    }
    std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero()))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .map(|(_, rest)| rest.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

/// D-8: a timeout kills the script's whole process group, so a grandchild
/// holding the stdout pipe neither delays the 504 (Python waits for it)
/// nor survives.
#[tokio::test]
async fn script_timeout_kills_the_process_group() {
    let _serial = SCRIPT_TESTS.lock().await;
    let fixture = load("script.json");
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("grandchild.sh");
    let pid_file = dir.path().join("grandchild.pid");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nsleep 30 &\necho $! > '{}'\nwait\n",
            pid_file.display()
        ),
        0o755,
    );
    let argv = script_argv(&fixture, &script, "0.5");
    let started = std::time::Instant::now();
    let response = script_exchange(&argv, script_request(&fixture)).await;
    assert_eq!(response.status, 504);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let body = String::from_utf8(response.body).unwrap();
    assert!(
        body.contains(&message_line("Metrics script timeout")),
        "{body}"
    );
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !process_gone(pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "the grandchild {pid} survived the timeout"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// D-12: stdout above 64 MiB answers 502 and the script is killed.
#[tokio::test]
async fn script_stdout_above_64_mib_is_refused() {
    let _serial = SCRIPT_TESTS.lock().await;
    let fixture = load("script.json");
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("large.sh");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nhead -c {} /dev/zero\nsleep 30\n",
            metrics_httpd::modes::script::MAX_STDOUT_BYTES + 1
        ),
        0o755,
    );
    let argv = script_argv(&fixture, &script, "60");
    let started = std::time::Instant::now();
    let response = script_exchange(&argv, script_request(&fixture)).await;
    assert_eq!(response.status, 502);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    let body = String::from_utf8(response.body).unwrap();
    assert!(
        body.contains(&message_line(
            metrics_httpd::modes::script::TOO_LARGE_MESSAGE
        )),
        "{body}"
    );
}

/// The json-file variants in fixture order (PLAN.md 4.3).
const JSON_FILE_VARIANTS: [&str; 8] = [
    "backup",
    "storage",
    "thermal",
    "tailscale",
    "dns",
    "openclaw",
    "ddns",
    "torrent-vpn",
];

/// Puts a `json_file.json` state at `dir/data/metrics.json` (the
/// variant's `--json-path`), as `generate.py` `prepare_state` does.
fn prepare_json_state(dir: &Path, state: &Value) {
    let data = dir.join("data");
    match std::fs::symlink_metadata(&data) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&data).unwrap(),
        Ok(_) => std::fs::remove_file(&data).unwrap(),
        Err(_) => {}
    }
    let target = data.join("metrics.json");
    let kind = text(&state["kind"]);
    if kind == "parent-is-file" {
        std::fs::write(&data, "not a directory\n").unwrap();
        return;
    }
    std::fs::create_dir(&data).unwrap();
    match kind {
        "absent" => return,
        "directory" => {
            std::fs::create_dir(&target).unwrap();
            return;
        }
        "broken-symlink" => {
            std::os::unix::fs::symlink("nowhere.json", &target).unwrap();
            return;
        }
        _ => {}
    }
    let content = match state.get("hex") {
        Some(value) => hex(text(value)),
        None => text(&state["text"]).as_bytes().to_vec(),
    };
    let written = if kind == "symlink" {
        data.join("target.json")
    } else {
        target.clone()
    };
    std::fs::write(&written, content).unwrap();
    let mtime_ns = state["mtime_ns"].as_u64().unwrap();
    std::fs::File::options()
        .write(true)
        .open(&written)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(mtime_ns))
        .unwrap();
    if kind == "symlink" {
        std::os::unix::fs::symlink("target.json", &target).unwrap();
    }
    if kind == "unreadable" {
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
}

/// PLAN.md 4.2, 4.3: every json-file variant answers each file state as its
/// Python script does (`fixtures/json_file.json`), except the named
/// differences (D-2 crash paths answered, D-3 texts, D-4 refusals, D-5).
#[tokio::test]
async fn json_file_variants_match_the_python_scripts() {
    let fixture = load("json_file.json");
    // The replay's clock (`start`) is the generator's frozen clock.
    assert_eq!(fixture["clock_epoch"].as_i64(), Some(1_792_576_800));
    let states = fixture["states"].as_object().unwrap();
    let variants = fixture["variants"].as_array().unwrap();
    let names: Vec<&str> = variants.iter().map(|v| text(&v["variant"])).collect();
    assert_eq!(names, JSON_FILE_VARIANTS);
    let probe = tempfile::tempdir().unwrap();
    let probe_file = probe.path().join("probe");
    std::fs::write(&probe_file, "x").unwrap();
    std::fs::set_permissions(&probe_file, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable_works = std::fs::read(&probe_file).is_err(); // false as root
    let mut checked = 0;
    for variant in variants {
        let name = text(&variant["variant"]);
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("data").join("metrics.json");
        let argv: Vec<String> = variant["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| match text(arg) {
                "{htpasswd}" => fixtures().join("htpasswd").display().to_string(),
                "{json}" => json_path.display().to_string(),
                other => other.to_owned(),
            })
            .collect();
        let (addr, stop) = start_variant(&argv, &HashMap::new()).await;
        let server = format!(
            "{} metrics-httpd/{}",
            text(&variant["server_version"]),
            env!("CARGO_PKG_VERSION")
        );
        for case in variant["cases"].as_array().unwrap() {
            let id = format!("{name}/{}", text(&case["id"]));
            let state = &states[text(&case["state"])];
            if text(&state["kind"]) == "unreadable" && !unreadable_works {
                continue;
            }
            prepare_json_state(dir.path(), state);
            let method = text(&case["method"]).to_owned();
            let headers: Vec<(String, String)> = case["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (text(&pair[0]).to_owned(), text(&pair[1]).to_owned()))
                .collect();
            let request = raw_request(
                &method,
                text(&case["target"]),
                text(&case["version"]),
                &headers,
            );
            let response = tokio::task::spawn_blocking(move || exchange(addr, &request, false))
                .await
                .unwrap();
            checked += 1;
            // D-7: the Server header names the variant and the Rust binary.
            assert_eq!(response.header("Server"), Some(server.as_str()), "{id}");
            if let Some(status) = case.get("rust_status") {
                // A named allowed difference: Rust's status and error_type.
                assert!(case["d"].is_string(), "{id}");
                assert_eq!(u64::from(response.status), status.as_u64().unwrap(), "{id}");
                let body: Value = serde_json::from_slice(&response.body).unwrap();
                assert_eq!(body["error"], Value::Bool(true), "{id}");
                assert_eq!(body["error_type"], case["rust_error_type"], "{id}");
                assert_eq!(response.header("Content-Type"), Some("application/json"));
                continue;
            }
            assert_eq!(
                u64::from(response.status),
                case["status"].as_u64().unwrap(),
                "{id}"
            );
            let expected = &case["response_headers"];
            let compare = text(&case["compare"]);
            for header in [
                "Content-Type",
                "WWW-Authenticate",
                "Connection",
                "Content-Length",
            ] {
                if header == "Content-Length" && compare != "bytes" {
                    continue;
                }
                assert_eq!(
                    response.header(header),
                    expected[header].as_str(),
                    "{id}: {header}"
                );
            }
            let body = String::from_utf8(response.body.clone()).unwrap();
            match compare {
                "bytes" => assert_eq!(body, text(&case["body"]), "{id}"),
                "html" => assert_eq!(body, without_style(text(&case["body"])), "{id}"),
                "error_type" => {
                    // D-3: the parser's or OS's text after the fixed prefix may differ.
                    let body: Value = serde_json::from_str(&body).unwrap();
                    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
                    assert_eq!(keys, ["error", "error_type", "message"], "{id}");
                    assert_eq!(body["error"], Value::Bool(true), "{id}");
                    assert_eq!(body["error_type"], case["error_type"], "{id}");
                    let message = text(&body["message"]);
                    assert!(
                        message.starts_with(text(&case["message_prefix"])),
                        "{id}: {message}"
                    );
                }
                other => panic!("{id}: unknown compare mode {other}"),
            }
        }
        let _ = stop.send(());
    }
    assert!(checked >= 8 * 40, "{checked}");
}
