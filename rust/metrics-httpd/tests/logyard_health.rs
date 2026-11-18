//! Replays `fixtures/logyard_health.json` (`fixtures/generate.py`, PLAN.md
//! 4.6, 8.2) against the logyard-health mode: the rendered
//! `logyard_health_httpd.py`'s `_load_units()`, `b64decode(validate=True)`
//! and `_query_count()` body handling, and its handler's payloads with a fake
//! Loki (the same canned answer bytes) and the committed fake `systemctl`
//! (`fixtures/fake-bin/systemctl`), with the same frozen clock, over real
//! sockets.

mod support;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use metrics_httpd::auth;
use metrics_httpd::clock::{FixedClock, SharedClock};
use metrics_httpd::modes::Mode;
use metrics_httpd::modes::logyard_health::{self, LogyardConfig};
use metrics_httpd::pyjson;
use metrics_httpd::server;
use serde_json::{Map, Value};
use support::{exchange, fixtures, raw_request};

/// Stands for an exception text in a recorded body (`generate.py`).
const TEXT_MARKER: &str = "<text: D-3>";

fn load() -> Value {
    let text = std::fs::read_to_string(fixtures().join("logyard_health.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The `LOGYARD_HEALTH_UNITS_B64` value of a case: as recorded, or the
/// standard base64 of the recorded decoded text (canonical inputs are stored
/// decoded to keep long base64 strings out of the repository).
fn unit_list_input(case: &Value) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    if let Some(input) = case.get("input") {
        text(input).to_owned()
    } else if let Some(decoded) = case.get("input_decoded") {
        engine.encode(text(decoded))
    } else {
        engine.encode(unhex(text(&case["input_decoded_hex"])))
    }
}

#[test]
fn unit_lists_match_python() {
    let fixture = load();
    let cases = fixture["unit_lists"].as_array().unwrap();
    assert!(cases.len() > 25);
    for case in cases {
        let id = text(&case["id"]);
        let actual = logyard_health::load_units(&unit_list_input(case));
        if let Some(d) = case.get("d") {
            // Python accepts (D-4) or crashes at import (D-2); Rust rejects
            // the whole list.
            assert!(["D-2", "D-4"].contains(&text(d)), "{id}");
            assert!(actual.units.is_empty(), "{id}");
            assert_eq!(actual.rejected.len(), 1, "{id}");
            assert_eq!(actual.rejected[0]["reason"], case["rust_rejected"], "{id}");
            assert!(actual.rejected[0].contains_key("detail"), "{id}");
            continue;
        }
        let expected: Vec<(String, String)> = case["units"]
            .as_array()
            .unwrap()
            .iter()
            .map(|unit| (text(&unit["id"]).to_owned(), text(&unit["unit"]).to_owned()))
            .collect();
        let units: Vec<(String, String)> = actual
            .units
            .iter()
            .map(|unit| (unit.id.clone(), unit.unit.clone()))
            .collect();
        assert_eq!(units, expected, "{id}");
        let expected = case["rejected"].as_array().unwrap();
        assert_eq!(actual.rejected.len(), expected.len(), "{id}");
        for (actual, expected) in actual.rejected.iter().zip(expected) {
            let expected = expected.as_object().unwrap();
            assert_eq!(
                actual.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>(),
                "{id}"
            );
            for (key, value) in expected {
                if key == "detail" {
                    // D-3: the exception text may differ.
                    assert!(!text(&actual[key]).is_empty(), "{id}");
                } else {
                    assert_eq!(&actual[key], value, "{id}");
                }
            }
        }
    }
}

#[test]
fn units_base64_matches_python_b64decode_validate() {
    let fixture = load();
    let cases = fixture["base64"].as_array().unwrap();
    assert!(cases.len() >= 400);
    for case in cases {
        let input = text(&case["input"]);
        let actual = auth::decode_base64(input.as_bytes()).map(|bytes| hex(&bytes));
        assert_eq!(actual.as_deref(), case["decoded_hex"].as_str(), "{input:?}");
    }
}

#[test]
fn query_counts_match_python() {
    let fixture = load();
    let cases = fixture["counts"].as_array().unwrap();
    assert!(cases.len() > 60);
    for case in cases {
        let id = text(&case["id"]);
        let body = match case.get("body") {
            Some(body) => text(body).as_bytes().to_vec(),
            None => unhex(text(&case["body_hex"])),
        };
        let actual = pyjson::parse(&body)
            .map_err(|error| error.to_string())
            .and_then(|body| logyard_health::count_from_body(&body))
            .map(pyjson::float_repr);
        let python_repr = |repr: &str| match repr {
            "nan" => "NaN".to_owned(),
            "inf" => "Infinity".to_owned(),
            "-inf" => "-Infinity".to_owned(),
            other => other.to_owned(),
        };
        match (case.get("d").map(text), case.get("rust").map(text)) {
            (Some(d), Some("error")) => {
                assert_eq!(d, "D-4", "{id}");
                assert!(actual.is_err(), "{id}: {actual:?}");
            }
            (Some(d), Some(rust)) => {
                assert_eq!(d, "D-13", "{id}");
                assert_eq!(actual.as_deref(), Ok(rust), "{id}");
            }
            (d, None) => match case.get("python") {
                Some(repr) => {
                    assert_eq!(d, None, "{id}");
                    assert_eq!(actual, Ok(python_repr(text(repr))), "{id}");
                }
                None => {
                    // Caught (the ingest error) or a crash (D-2): Rust
                    // reports both as the ingest error.
                    let caught = case["python_caught"].as_bool().unwrap();
                    assert_eq!(d, (!caught).then_some("D-2"), "{id}");
                    assert!(actual.is_err(), "{id}: {actual:?}");
                }
            },
            other => panic!("{id}: {other:?}"),
        }
    }
}

/// The bytes of a fake Loki answer, as `generate.py`'s `loki_response`.
fn loki_response(spec: &Map<String, Value>) -> Vec<u8> {
    let body = match spec.get("body_hex") {
        Some(body) => unhex(text(body)),
        None => spec
            .get("body")
            .map_or_else(Vec::new, |body| text(body).as_bytes().to_vec()),
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        spec.get("status").and_then(Value::as_u64).unwrap_or(200),
        spec.get("reason").and_then(Value::as_str).unwrap_or("OK")
    );
    for header in spec
        .get("headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        head.push_str(&format!("{}: {}\r\n", text(&header[0]), text(&header[1])));
    }
    let data = if spec.get("chunked") == Some(&Value::Bool(true)) {
        head.push_str("Transfer-Encoding: chunked\r\n");
        let mut data = Vec::new();
        for chunk in body.chunks(7) {
            data.extend(format!("{:x}\r\n", chunk.len()).bytes());
            data.extend(chunk);
            data.extend(b"\r\n");
        }
        data.extend(b"0\r\n\r\n");
        data
    } else {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        body
    };
    head.push_str("Connection: close\r\n\r\n");
    let mut out: Vec<u8> = head.chars().map(|c| u8::try_from(c).unwrap()).collect();
    out.extend(data);
    out
}

#[derive(Default)]
struct LokiState {
    specs: Map<String, Value>,
    requests: Vec<Value>,
    queries: usize,
}

/// The fake Loki of `generate.py`: canned answers by role (`ready`,
/// `ready_target`, then `warning` and `critical` for the first and second
/// query), recording each request's path and decoded `query`.
struct FakeLoki {
    url: String,
    state: Arc<Mutex<LokiState>>,
}

impl FakeLoki {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(LokiState::default()));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = shared.clone();
                std::thread::spawn(move || answer(stream, &state));
            }
        });
        Self { url, state }
    }

    fn reset(&self, specs: &Map<String, Value>) {
        let mut state = self.state.lock().unwrap();
        state.specs = specs.clone();
        state.requests.clear();
        state.queries = 0;
    }

    fn requests(&self) -> Vec<Value> {
        self.state.lock().unwrap().requests.clone()
    }
}

fn answer(mut stream: TcpStream, state: &Mutex<LokiState>) {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let target = loop {
        let Ok(read) = stream.read(&mut chunk) else {
            return;
        };
        if read == 0 {
            return;
        }
        data.extend_from_slice(&chunk[..read]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(_)) = request.parse(&data) {
            break request.path.unwrap().to_owned();
        }
    };
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let query = form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "query")
        .map(|(_, value)| value.into_owned());
    let spec = {
        let mut state = state.lock().unwrap();
        let role = match path {
            "/loki/api/v1/query" => {
                state.queries += 1;
                ["warning", "critical", "extra"][(state.queries - 1).min(2)]
            }
            "/ready" => "ready",
            "/ready-target" => "ready_target",
            _ => "unknown",
        };
        state
            .requests
            .push(Value::Array(vec![path.into(), query.into()]));
        state.specs.get(role).cloned()
    };
    let spec = spec
        .and_then(|spec| spec.as_object().cloned())
        .unwrap_or_else(|| {
            serde_json::json!({"status": 404, "reason": "Not Found", "body": "404 page not found\n"})
                .as_object()
                .unwrap()
                .clone()
        });
    if let Some(delay) = spec.get("delay").and_then(Value::as_f64) {
        std::thread::sleep(Duration::from_secs_f64(delay));
    }
    if spec.get("close") == Some(&Value::Bool(true)) {
        return;
    }
    let _ = stream.write_all(&loki_response(&spec));
}

/// A URL whose port nothing listens on.
fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

/// Sets the JSON value at a dotted `path` (unit ids contain no dot).
fn at<'a>(value: &'a mut Value, path: &str) -> &'a mut Value {
    path.split('.').fold(value, |node, key| match node {
        Value::Array(items) => &mut items[key.parse::<usize>().unwrap()],
        Value::Object(map) => map.get_mut(key).unwrap(),
        other => panic!("{path}: not a container: {other}"),
    })
}

async fn start(
    config: &LogyardConfig,
    epoch: f64,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let clock: SharedClock = Arc::new(FixedClock(UNIX_EPOCH + Duration::from_secs_f64(epoch)));
    let listener = server::bind(config.addr()).unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server::run(
        listener,
        config.server_config(clock.clone()),
        Arc::new(config.service(clock)),
        async {
            let _ = stopped.await;
        },
    ));
    (addr, stop)
}

#[tokio::test]
async fn payloads_match_the_python_script() {
    let fixture = load();
    let epoch = fixture["http"]["generated_at_epoch"].as_f64().unwrap();
    let cases = fixture["http"]["cases"].as_array().unwrap();
    assert!(cases.len() > 40);
    let loki = FakeLoki::start();
    let fake_systemctl = fixtures().join("fake-bin").join("systemctl");
    let dir = tempfile::tempdir().unwrap();
    for case in cases {
        let id = text(&case["id"]);
        let closed = closed_port_url();
        let mut env: HashMap<String, String> = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| {
                let value = text(value)
                    .replace("{loki}", &loki.url)
                    .replace("{closed}", &closed);
                (name.clone(), value)
            })
            .collect();
        if let Some(units) = case.get("units_json") {
            env.insert(
                "LOGYARD_HEALTH_UNITS_B64".to_owned(),
                base64::engine::general_purpose::STANDARD.encode(text(units)),
            );
        }
        let mut config = LogyardConfig::from_env(|name| env.get(name).cloned()).unwrap();
        config.systemctl = match text(&case["systemctl"]) {
            "fake" => fake_systemctl.clone(),
            "missing" => dir.path().join("systemctl"),
            other => panic!("{id}: systemctl {other}"),
        };
        assert_eq!(config.path, text(&case["path"]), "{id}");
        loki.reset(case["loki"].as_object().unwrap());
        let (addr, stop) = start(&config, epoch).await;
        let request = raw_request("GET", text(&case["path"]), "HTTP/1.1", &[]);
        let response = tokio::task::spawn_blocking(move || exchange(addr, &request, false))
            .await
            .unwrap();
        let _ = stop.send(());

        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{id}"
        );
        assert_eq!(
            response.header("Content-Type"),
            case["content_type"].as_str(),
            "{id}"
        );
        assert_eq!(
            response.header("Content-Length"),
            Some(response.body.len().to_string().as_str()),
            "{id}"
        );
        let body = String::from_utf8(response.body.clone()).unwrap();
        let texts = case["texts"].as_array().unwrap();
        if texts.is_empty() {
            assert_eq!(body, text(&case["body"]), "{id}");
        } else {
            // D-3: exception texts are compared by presence; everything
            // else of the payload is equal.
            let mut actual: Value = serde_json::from_str(&body).unwrap();
            for path in texts {
                let field = at(&mut actual, text(path));
                assert!(
                    field.as_str().is_some_and(|text| !text.is_empty()),
                    "{id}: {path}: {field}"
                );
                *field = Value::String(TEXT_MARKER.to_owned());
            }
            let expected: Value = serde_json::from_str(text(&case["body"])).unwrap();
            assert_eq!(actual, expected, "{id}: {body}");
        }
        assert_eq!(
            loki.requests(),
            case["requests"].as_array().unwrap().clone(),
            "{id}"
        );
    }
}

#[test]
fn every_difference_is_named() {
    let fixture = load();
    for case in fixture["http"]["cases"].as_array().unwrap() {
        let id = text(&case["id"]);
        match case.get("python").map(text) {
            Some("crash") => assert_eq!(case["d"], "D-2", "{id}"),
            Some("redirect followed") => assert_eq!(case["d"], "D-13", "{id}"),
            Some(other) => panic!("{id}: {other}"),
            None => assert!(case.get("d").is_none(), "{id}"),
        }
    }
}

/// D-12: a Loki answer above 64 MiB is not read to the end; it takes the
/// caught-error path (Python reads any size).
#[tokio::test]
async fn loki_answers_over_64_mib_take_the_error_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut head = [0u8; 4096];
                let _ = stream.read(&mut head);
                let length = logyard_health::MAX_LOKI_BODY_BYTES + 1;
                let _ = stream.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n").as_bytes(),
                );
                let chunk = vec![b' '; 1 << 20];
                let mut sent = 0;
                while sent < length {
                    let size = chunk.len().min(length - sent);
                    if stream.write_all(&chunk[..size]).is_err() {
                        return;
                    }
                    sent += size;
                }
            });
        }
    });
    let env: HashMap<&str, String> = [
        ("LOGYARD_HEALTH_PORT", "0".to_owned()),
        ("LOGYARD_LOKI_URL", url),
    ]
    .into();
    let config = LogyardConfig::from_env(|name| env.get(name).cloned()).unwrap();
    let (addr, stop) = start(&config, 1_792_576_800.0).await;
    let request = raw_request("GET", "/.well-known/logyard", "HTTP/1.1", &[]);
    let response = tokio::task::spawn_blocking(move || exchange(addr, &request, false))
        .await
        .unwrap();
    let _ = stop.send(());
    assert_eq!(response.status, 200);
    let payload: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(payload["status"], "critical", "{payload}");
    assert_eq!(payload["loki"]["ready"], false, "{payload}");
    assert_eq!(payload["loki"]["ready_status"], Value::Null, "{payload}");
    for text in [&payload["loki"]["ready_body"], &payload["ingest"]["error"]] {
        assert!(
            text.as_str().unwrap().contains("length limit exceeded"),
            "{payload}"
        );
    }
}
