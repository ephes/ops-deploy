//! `serve` (PLAN.md 3.1, 3.4): the software-live handler behind the
//! [`crate::endpoint`] boundary, and the endpoint configuration
//! (`software_live.py:713-761, 909-918`).
//!
//! Order of the checks, as `Handler.do_GET`: any method but `GET` is 501
//! (`BaseHTTPRequestHandler` has no `do_<METHOD>`); a request-target other
//! than the configured path, also with a query string, is 404
//! `{"error": "not_found"}` — before authentication; failed authentication
//! is 401 `{"error": "unauthorized"}` with `WWW-Authenticate: Basic
//! realm="software-live"`; then the state file is read again for every
//! request and passed through `with_freshness`, any failure being 503
//! `{"error": "missing_or_invalid_observation"}`. A stale report is a 200
//! with `summary.fresh: false`.

use std::convert::Infallible;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;

use hyper::header;
use hyper::{Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::endpoint::{self, BasicAuth, Handler, HtpasswdFile, Reply, Request, Verifier};
use crate::error::PyError;
use crate::probe::{HostSystem, System};
use crate::pyjson::{self, is_int_token, token_f64, type_name};
use crate::report::with_freshness;
use crate::traefik::Pid;

/// The realm of the 401 challenge.
pub const REALM: &str = "software-live";

/// `endpoint.json` (written by the role: `auth_user, bind, htpasswd, path,
/// port, state`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointConfig {
    pub bind: Ipv4Addr,
    pub port: u16,
    pub path: String,
    pub auth_user: String,
    pub htpasswd: PathBuf,
    pub state: PathBuf,
}

impl EndpointConfig {
    /// The checks of `software_live.py:909-916` in their order:
    /// `ip_address(config["bind"])`, the loopback/Tailscale check,
    /// `int(config["port"])` and the port range of `bind()`. Then, unlike
    /// Python, which reads them only per request, `path`, `auth_user`,
    /// `htpasswd` and `state` must be strings (PLAN.md 4.2 item 14).
    pub fn from_value(config: &Value) -> Result<Self, PyError> {
        let Value::Object(map) = config else {
            return Err(PyError::type_error(format!(
                "'{}' object is not subscriptable",
                type_name(config)
            )));
        };
        let host = bind_host(item(map, "bind")?)?;
        let port = port(item(map, "port")?)?;
        // `bind((host, port))`: the host's type first, then the port range.
        let bind =
            host.ok_or_else(|| PyError::type_error("str, bytes or bytearray expected, not int"))?;
        let port =
            port.ok_or_else(|| PyError::new("OverflowError", "bind(): port must be 0-65535."))?;
        let text = |key: &str| match item(map, key)? {
            Value::String(text) => Ok(text.clone()),
            other => Err(PyError::type_error(format!(
                "endpoint {key} must be a string, not {}",
                type_name(other)
            ))),
        };
        Ok(Self {
            bind,
            port,
            path: text("path")?,
            auth_user: text("auth_user")?,
            htpasswd: PathBuf::from(text("htpasswd")?),
            state: PathBuf::from(text("state")?),
        })
    }
}

fn item<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value, PyError> {
    map.get(key).ok_or_else(|| PyError::key(key))
}

/// `ip_address(value)` plus the check. `None`: an integer that Python reads
/// as an allowed IPv4 address; it passes the check, and `bind()`, which
/// takes only a string host, refuses it later (`TypeError`).
fn bind_host(value: &Value) -> Result<Option<Ipv4Addr>, PyError> {
    let not_allowed = || PyError::value("endpoint must bind IPv4 loopback or Tailscale");
    match value {
        Value::String(text) => endpoint::check_bind(text).map(Some),
        Value::Number(number) if is_int_token(number.as_str()) => {
            // Below 2**32 an IPv4 address, else IPv6 (or invalid).
            let allowed = number
                .as_str()
                .parse::<u32>()
                .is_ok_and(|bits| endpoint::bind_allowed(Ipv4Addr::from(bits)));
            if allowed {
                Ok(None)
            } else {
                Err(not_allowed())
            }
        }
        // `ip_address(True)` is 0.0.0.1, `False` 0.0.0.0: not allowed.
        Value::Bool(_) => Err(not_allowed()),
        other => Err(PyError::value(format!(
            "{} does not appear to be an IPv4 or IPv6 address",
            type_name(other)
        ))),
    }
}

/// `int(config["port"])`; `None` for a number outside `bind()`'s range
/// 0-65535, which only `bind()` refuses.
fn port(value: &Value) -> Result<Option<u16>, PyError> {
    let integer: String = match value {
        Value::Bool(flag) => u8::from(*flag).to_string(),
        Value::Number(number) => {
            let token = number.as_str();
            if is_int_token(token) {
                pyjson::canonical_int(token).to_owned()
            } else {
                // `int(float)` truncates toward zero; `1e400` reads as an
                // infinity (JSON has no NaN, PLAN.md 4.2 item 4).
                let float = token_f64(token);
                if !float.is_finite() {
                    return Err(PyError::new(
                        "OverflowError",
                        "cannot convert float infinity to integer",
                    ));
                }
                let truncated = float.trunc();
                return Ok((0.0..=65535.0)
                    .contains(&truncated)
                    .then_some(truncated as u16));
            }
        }
        Value::String(text) => Pid::parse(text)?.as_str().to_owned(),
        other => {
            return Err(PyError::type_error(format!(
                "int() argument must be a string, a bytes-like object or a real number, not '{}'",
                type_name(other)
            )));
        }
    };
    Ok(integer.parse::<u16>().ok())
}

/// The software-live handler.
pub struct SoftwareLive<V, C> {
    pub path: String,
    pub auth: BasicAuth<V>,
    pub state: PathBuf,
    /// `time.time()` at the request.
    pub clock: C,
}

impl SoftwareLive<HtpasswdFile, fn() -> f64> {
    pub fn new(config: &EndpointConfig) -> Self {
        Self {
            path: config.path.clone(),
            auth: BasicAuth {
                user: config.auth_user.clone(),
                verifier: HtpasswdFile(config.htpasswd.clone()),
            },
            state: config.state.clone(),
            clock: host_time,
        }
    }
}

fn host_time() -> f64 {
    HostSystem.now()
}

fn error(status: StatusCode, text: &str) -> Reply {
    Reply::new(status, json!({ "error": text }))
}

impl<V: Verifier, C: Fn() -> f64> SoftwareLive<V, C> {
    /// `with_freshness(json.loads(Path(state).read_text()))`. The text is
    /// strict UTF-8 (the hosts' locale); `read_text`'s newline translation
    /// changes nothing JSON can contain, as a raw CR or LF inside a string
    /// is invalid either way.
    fn observation(&self) -> Result<Value, PyError> {
        let bytes = std::fs::read(&self.state).map_err(|error| PyError::os(&error))?;
        let text = String::from_utf8(bytes)
            .map_err(|error| PyError::new("UnicodeDecodeError", error.to_string()))?;
        with_freshness(pyjson::loads(&text)?, (self.clock)())
    }
}

impl<V: Verifier + Send + Sync, C: Fn() -> f64 + Send + Sync> Handler for SoftwareLive<V, C> {
    fn handle(&self, request: &Request<'_>) -> Reply {
        if request.method != Method::GET {
            return error(StatusCode::NOT_IMPLEMENTED, "unsupported_method");
        }
        if request.path != self.path {
            return error(StatusCode::NOT_FOUND, "not_found");
        }
        if !self.auth.check(request.header(header::AUTHORIZATION)) {
            let mut reply = error(StatusCode::UNAUTHORIZED, "unauthorized");
            reply.realm = Some(REALM);
            return reply;
        }
        match self.observation() {
            Ok(data) => Reply::new(StatusCode::OK, data),
            Err(_) => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "missing_or_invalid_observation",
            ),
        }
    }
}

/// `serve`: listen on `bind:port` and serve forever. Returns only on a
/// bind or runtime error.
pub fn run(config: &EndpointConfig) -> Result<Infallible, PyError> {
    let listener =
        TcpListener::bind((config.bind, config.port)).map_err(|error| PyError::os(&error))?;
    endpoint::serve(
        listener,
        SoftwareLive::new(config),
        std::future::pending::<()>(),
    )
    .map_err(|error| PyError::os(&error))?;
    Err(PyError::new("RuntimeError", "the server stopped"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::json_eq;
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Deserialize)]
    struct Fixtures {
        constants: Constants,
        config: Vec<ConfigCase>,
        requests: Vec<RequestCase>,
    }

    #[derive(Deserialize)]
    struct Constants {
        path: String,
        user: String,
        password: String,
        realm: String,
    }

    #[derive(Deserialize)]
    struct PyErrorSpec {
        class: String,
        message: Option<String>,
    }

    #[derive(Deserialize)]
    struct ConfigCase {
        id: String,
        config: String,
        address: Option<(String, u16)>,
        error: Option<PyErrorSpec>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Deserialize)]
    struct RequestCase {
        id: String,
        request_hex: String,
        now: f64,
        #[serde(default)]
        state: Option<String>,
        #[serde(default)]
        state_hex: Option<String>,
        python: PythonAnswer,
        #[serde(default)]
        p3: Option<String>,
        #[serde(default)]
        rust_status: Option<u16>,
    }

    #[derive(Deserialize)]
    struct PythonAnswer {
        /// `None`: Python closed the connection without an answer.
        status: Option<u16>,
        body: Option<Value>,
        challenge: Option<String>,
        htpasswd: Option<(String, String)>,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/serve.json")).unwrap()
    }

    /// The password table the Python fixture run used in place of `htpasswd`,
    /// recording every check.
    #[derive(Clone, Default)]
    struct Table {
        accepted: Vec<(String, String)>,
        calls: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl Verifier for Table {
        fn verify(&self, user: &str, password: &str, _deadline: std::time::Instant) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push((user.to_owned(), password.to_owned()));
            self.accepted
                .iter()
                .any(|(u, p)| u == user && p == password)
        }
    }

    /// A server on 127.0.0.1 in its own thread, stopped on drop.
    struct Running {
        address: SocketAddr,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Running {
        fn start<H: Handler + Send + 'static>(handler: H) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let thread = std::thread::spawn(move || {
                endpoint::serve(listener, handler, async {
                    let _ = stopped.await;
                })
                .unwrap();
            });
            Self {
                address,
                stop: Some(stop),
                thread: Some(thread),
            }
        }

        fn send(&self, raw: &[u8]) -> Answer {
            let mut stream = TcpStream::connect(self.address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            stream.write_all(raw).unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            Answer::parse(&bytes)
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    /// A response as the client reads it.
    #[derive(Debug)]
    struct Answer {
        status: u16,
        headers: BTreeMap<String, Vec<String>>,
        body: Vec<u8>,
    }

    impl Answer {
        fn parse(bytes: &[u8]) -> Self {
            let end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap_or_else(|| panic!("no response head: {bytes:?}"));
            let head = std::str::from_utf8(&bytes[..end]).unwrap();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap();
            assert!(status_line.starts_with("HTTP/1."), "{status_line}");
            let status = status_line[9..12].parse().unwrap();
            let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for line in lines {
                let (name, value) = line.split_once(':').unwrap();
                headers
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(value.trim().to_owned());
            }
            Self {
                status,
                headers,
                body: bytes[end + 4..].to_vec(),
            }
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).map(|values| {
                assert_eq!(values.len(), 1, "{name}");
                values[0].as_str()
            })
        }

        fn json(&self) -> Value {
            pyjson::loads(std::str::from_utf8(&self.body).unwrap()).unwrap()
        }

        /// The headers of PLAN.md 3.4 and 4.2 item 2 on every JSON answer.
        fn assert_contract(&self, id: &str, head_request: bool) {
            assert_eq!(
                self.header("content-type"),
                Some("application/json"),
                "{id}"
            );
            assert_eq!(self.header("cache-control"), Some("no-store"), "{id}");
            assert_eq!(self.header("connection"), Some("close"), "{id}");
            assert!(self.header("date").is_some(), "{id}");
            assert!(!self.headers.contains_key("server"), "{id}: no banner");
            if !head_request {
                assert!(self.body.is_ascii(), "{id}");
                assert_eq!(
                    self.header("content-length"),
                    Some(self.body.len().to_string().as_str()),
                    "{id}"
                );
            }
            assert_eq!(
                self.header("www-authenticate").is_some(),
                self.status == 401,
                "{id}"
            );
        }
    }

    fn clock_at(now: &Arc<Mutex<f64>>) -> impl Fn() -> f64 + Send + 'static {
        let now = now.clone();
        move || *now.lock().unwrap()
    }

    #[test]
    fn configuration_matches_python() {
        let cases = fixtures().config;
        assert!(cases.len() >= 70);
        for case in cases {
            let id = &case.id;
            let config = pyjson::loads(&case.config).unwrap_or_else(|e| panic!("{id}: {e}"));
            let result = EndpointConfig::from_value(&config);
            if let Some(tag) = &case.p3 {
                // Python accepts these at startup (PLAN.md 4.2 items 11, 14).
                assert!(case.address.is_some(), "{id}");
                let error = result.unwrap_err();
                let expected = if tag == "unicode-digits" {
                    &["ValueError"][..]
                } else {
                    &["KeyError", "TypeError"][..]
                };
                assert!(expected.contains(&error.class), "{id}: {error}");
                continue;
            }
            match (&case.address, &case.error) {
                (Some((host, port)), None) => {
                    let endpoint = result.unwrap_or_else(|e| panic!("{id}: {e}"));
                    assert_eq!(&endpoint.bind.to_string(), host, "{id}");
                    assert_eq!(endpoint.port, *port, "{id}");
                }
                (None, Some(expected)) => {
                    let error = result.unwrap_err();
                    assert_eq!(error.class, expected.class, "{id}: {error}");
                    if let Some(message) = &expected.message {
                        assert_eq!(&error.message, message, "{id}");
                    }
                }
                _ => panic!("{id}: an address or an error"),
            }
        }
    }

    #[test]
    fn requests_match_python() {
        let fixtures = fixtures();
        let constants = &fixtures.constants;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let now = Arc::new(Mutex::new(0.0));
        let table = Table {
            accepted: vec![(constants.user.clone(), constants.password.clone())],
            ..Table::default()
        };
        let calls = table.calls.clone();
        let server = Running::start(SoftwareLive {
            path: constants.path.clone(),
            auth: BasicAuth {
                user: constants.user.clone(),
                verifier: table,
            },
            state: state.clone(),
            clock: clock_at(&now),
        });
        assert!(fixtures.requests.len() >= 90);
        let mut divergences = 0;
        for case in &fixtures.requests {
            let id = &case.id;
            *now.lock().unwrap() = case.now;
            calls.lock().unwrap().clear();
            let _ = std::fs::remove_file(&state);
            if let Some(text) = &case.state {
                std::fs::write(&state, text).unwrap();
            } else if let Some(hex) = &case.state_hex {
                std::fs::write(&state, hex::decode(hex).unwrap()).unwrap();
            }
            let raw = hex::decode(&case.request_hex).unwrap();
            let answer = server.send(&raw);
            let python = &case.python;
            if case.p3.is_some() {
                // PLAN.md 4.2 items 2 and 4.
                divergences += 1;
                assert_ne!(python.status, case.rust_status, "{id}");
                assert_eq!(Some(answer.status), case.rust_status, "{id}");
                continue;
            }
            assert_eq!(Some(answer.status), python.status, "{id}");
            answer.assert_contract(id, raw.starts_with(b"HEAD "));
            assert_eq!(
                answer.header("www-authenticate"),
                python.challenge.as_deref(),
                "{id}"
            );
            let call = calls.lock().unwrap().first().cloned();
            assert_eq!(call, python.htpasswd, "{id}");
            assert!(calls.lock().unwrap().len() <= 1, "{id}");
            match (&python.body, answer.status) {
                (Some(expected), _) => {
                    let actual = answer.json();
                    assert!(json_eq(&actual, expected), "{id}: {actual} != {expected}");
                }
                // Python's 501 is an HTML page (PLAN.md 4.2 item 2).
                (None, 501) => {
                    if !raw.starts_with(b"HEAD ") {
                        assert_eq!(
                            answer.json(),
                            json!({"error": "unsupported_method"}),
                            "{id}"
                        );
                    }
                }
                (None, status) => panic!("{id}: no Python body for {status}"),
            }
        }
        assert!(divergences >= 4);
        assert_eq!(constants.realm, REALM);
    }

    fn htpasswd_fixture(dir: &std::path::Path) -> PathBuf {
        #[derive(Deserialize)]
        struct Htpasswd {
            files: BTreeMap<String, String>,
        }
        let fixture: Htpasswd =
            serde_json::from_str(include_str!("../fixtures/htpasswd.json")).unwrap();
        let path = dir.join("htpasswd");
        std::fs::write(&path, &fixture.files["main"]).unwrap();
        path
    }

    fn get(path: &str, credentials: Option<&str>) -> Vec<u8> {
        use base64::Engine as _;
        let mut raw = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        if let Some(credentials) = credentials {
            let token = base64::engine::general_purpose::STANDARD.encode(credentials);
            raw.push_str(&format!("Authorization: Basic {token}\r\n"));
        }
        raw.push_str("\r\n");
        raw.into_bytes()
    }

    #[test]
    fn the_role_written_htpasswd_file_is_verified_with_bcrypt() {
        let constants = fixtures().constants;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        std::fs::write(
            &state,
            r#"{"schema_version": 2, "generated_at_epoch": 1, "summary": {"observation_ok": true,
               "os_ok": true, "postgresql_ok": true, "traefik_ok": true,
               "security_updates_ok": true, "apt_indexes_fresh": true}}"#,
        )
        .unwrap();
        let config = EndpointConfig {
            bind: Ipv4Addr::LOCALHOST,
            port: 0,
            path: constants.path.clone(),
            auth_user: constants.user.clone(),
            htpasswd: htpasswd_fixture(dir.path()),
            state,
        };
        let server = Running::start(SoftwareLive::new(&config));
        let good = format!("{}:{}", constants.user, constants.password);
        let answer = server.send(&get(&constants.path, Some(&good)));
        assert_eq!(answer.status, 200);
        let body = answer.json();
        // The Python test's state: one second after the epoch is stale.
        assert_eq!(body["summary"]["fresh"], false);
        assert_eq!(body["meta"]["max_age_seconds"], 1800);
        let wrong = format!("{}:wrong", constants.user);
        assert_eq!(server.send(&get(&constants.path, Some(&wrong))).status, 401);
        // htpasswd's own rules, e.g. a NUL ends the password it checks.
        let nul = format!("{good}\0ignored");
        assert_eq!(server.send(&get(&constants.path, Some(&nul))).status, 200);
        // An entry of another user never authenticates the configured one.
        assert_eq!(
            server
                .send(&get(&constants.path, Some("md5:md5-password")))
                .status,
            401
        );
        assert_eq!(server.send(&get(&constants.path, None)).status, 401);
        std::fs::write(&config.state, "{broken").unwrap();
        assert_eq!(server.send(&get(&constants.path, Some(&good))).status, 503);
        // A changed password file applies to the next request.
        std::fs::write(&config.htpasswd, "").unwrap();
        assert_eq!(server.send(&get(&constants.path, Some(&good))).status, 401);
    }

    struct Fixed;

    impl Handler for Fixed {
        fn handle(&self, _request: &Request<'_>) -> Reply {
            Reply::new(StatusCode::OK, json!({"ok": true}))
        }
    }

    #[test]
    fn idle_connections_are_closed_after_the_budget_and_never_block_others() {
        let server = Running::start(Fixed);
        // A full set of idle clients, as a slow or hostile peer would hold.
        let idle: Vec<TcpStream> = (0..endpoint::MAX_CONNECTIONS)
            .map(|_| TcpStream::connect(server.address).unwrap())
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        // Above the limit a request waits in the listen queue until a slot
        // frees, at the latest when the idle connections run out of budget.
        let started = Instant::now();
        let answer = server.send(&get("/", None));
        let waited = started.elapsed();
        assert_eq!(answer.status, 200);
        assert!(waited >= Duration::from_secs(4), "{waited:?}");
        assert!(waited < Duration::from_secs(10), "{waited:?}");
        for mut stream in idle {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut rest = Vec::new();
            // Closed by the server without a response.
            assert_eq!(stream.read_to_end(&mut rest).unwrap(), 0);
        }
        // Below the limit an idle client does not delay anyone.
        let _slow = TcpStream::connect(server.address).unwrap();
        let started = Instant::now();
        assert_eq!(server.send(&get("/", None)).status, 200);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_partial_request_is_closed_after_the_budget() {
        let server = Running::start(Fixed);
        let mut stream = TcpStream::connect(server.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let started = Instant::now();
        // A request head that never ends, one byte at a time.
        for byte in b"GET / HTTP/1.1\r\nX: " {
            stream.write_all(&[*byte]).unwrap();
        }
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(4), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    }

    /// A verifier that takes its time, as `htpasswd` on a slow host.
    struct Slow(Duration);

    impl Verifier for Slow {
        fn verify(&self, _user: &str, _password: &str, _deadline: std::time::Instant) -> bool {
            std::thread::sleep(self.0);
            true
        }
    }

    #[test]
    fn a_slow_password_check_never_holds_up_other_connections() {
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(Running::start(SoftwareLive {
            path: "/p".into(),
            auth: BasicAuth {
                user: "u".into(),
                verifier: Slow(Duration::from_secs(3)),
            },
            state: dir.path().join("missing"),
            clock: || 0.0,
        }));
        let slow = {
            let server = server.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                let answer = server.send(&get("/p", Some("u:x")));
                (answer.status, started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        assert_eq!(server.send(&get("/other", None)).status, 404);
        assert_eq!(server.send(&get("/p", None)).status, 401);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        let (status, took) = slow.join().unwrap();
        assert_eq!(status, 503, "authenticated, no state file");
        assert!(took >= Duration::from_secs(3), "{took:?}");
    }

    #[test]
    fn the_password_check_gives_up_after_its_budget() {
        // Many entries of the user, each verified in turn (htpasswd checks
        // every one): far more work than the budget allows.
        let dir = tempfile::tempdir().unwrap();
        let hash = bcrypt::hash_with_salt("pw", 12, [3; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoY);
        let htpasswd = dir.path().join("htpasswd");
        std::fs::write(&htpasswd, format!("u:{hash}\n").repeat(400)).unwrap();
        let config = EndpointConfig {
            bind: Ipv4Addr::LOCALHOST,
            port: 0,
            path: "/p".into(),
            auth_user: "u".into(),
            htpasswd,
            state: dir.path().join("missing"),
        };
        let server = Running::start(SoftwareLive::new(&config));
        let started = Instant::now();
        let answer = server.send(&get("/p", Some("u:pw")));
        let took = started.elapsed();
        assert_eq!(answer.status, 401, "as Python's htpasswd timeout");
        assert!(took >= endpoint::VERIFY_BUDGET, "{took:?}");
        assert!(took < endpoint::CONNECTION_LIMIT, "{took:?}");
    }

    #[test]
    fn malformed_and_oversized_requests_get_hyper_errors() {
        let server = Running::start(Fixed);
        assert_eq!(server.send(b"NOT HTTP\r\n\r\n").status, 400);
        // A head beyond the read buffer is refused (431) and the connection
        // closed; the client may see the reset of its unread rest instead.
        let huge = format!(
            "GET / HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(2 * endpoint::MAX_HEAD_BYTES)
        );
        let mut stream = TcpStream::connect(server.address).unwrap();
        let _ = stream.write_all(huge.as_bytes());
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        if !bytes.is_empty() {
            assert_eq!(Answer::parse(&bytes).status, 431);
        }
        // A request body is never read, and the connection still closes.
        let answer = server.send(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc");
        assert_eq!(answer.status, 200);
    }

    #[test]
    fn run_reports_a_bind_failure() {
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let config = EndpointConfig {
            bind: Ipv4Addr::LOCALHOST,
            port,
            path: "/".into(),
            auth_user: "u".into(),
            htpasswd: "/nonexistent".into(),
            state: "/nonexistent".into(),
        };
        let error = run(&config).unwrap_err();
        assert!(
            ["OSError", "FileExistsError"].contains(&error.class),
            "{error}"
        );
    }
}
