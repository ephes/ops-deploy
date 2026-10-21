//! Replays the Python-generated fixtures (`fixtures/generate.py`, PLAN.md
//! 8.2) against the Rust modules: the JSON formatter and value semantics
//! (D-4, D-5), the meta helpers, the auth decisions (D-2, D-6) and the
//! 501/404/401 gate of every mode over real sockets (PLAN.md 4.1).

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
