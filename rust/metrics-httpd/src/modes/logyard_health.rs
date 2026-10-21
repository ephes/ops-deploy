//! Mode `logyard-health` (PLAN.md 4.6): Loki readiness, ingest freshness
//! and unit states, configured from the `LOGYARD_*` environment the unit
//! already sets; no auth and no per-request log.
//!
//! The port of `roles/logyard_deploy/templates/logyard_health_httpd.py.j2`:
//! the environment as the module reads it at import time (l.19–28), the
//! unit list parsed once at startup (`_load_units`, l.33–85), and per
//! request the payload of `_build_payload` (l.177–232): `GET /ready` and two
//! `count_over_time` queries against Loki, then `systemctl show` per unit,
//! one after the other as in Python. Where the Python handler raises an
//! exception it does not catch and drops the connection, Rust takes the
//! caught-error path of the same `try` block instead (D-2).

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use clap::Args;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::{Method, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::{Map, Value};

use crate::auth;
use crate::clock::{SharedClock, epoch_seconds};
use crate::meta::iso_utc;
use crate::modes::{Mode, Problems};
use crate::pyjson;
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// D-1: header-read and keep-alive timeout (Python: none).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `BaseHTTPRequestHandler.server_version` (D-7 adds `metrics-httpd/<v>`).
pub const SERVER_NAME: &str = "BaseHTTP/0.6";
/// D-12: the largest Loki response body read (Python: unbounded).
pub const MAX_LOKI_BODY_BYTES: usize = 64 * 1024 * 1024;
/// `SYSTEMCTL_PROPERTIES` (l.30).
pub const SYSTEMCTL_PROPERTIES: [&str; 4] = ["LoadState", "ActiveState", "SubState", "Result"];

#[derive(Args, Debug, Clone)]
pub struct LogyardHealthArgs {
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

/// One accepted entry of `LOGYARD_HEALTH_UNITS_B64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitEntry {
    /// The payload key (`$.units.<id>`).
    pub id: String,
    /// The systemd unit passed to `systemctl show`.
    pub unit: String,
}

/// `_load_units()`: the accepted entries and the rejected ones, as the
/// payload shows them under `units_rejected`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Units {
    pub units: Vec<UnitEntry>,
    pub rejected: Vec<Map<String, Value>>,
}

/// The module-level settings of `logyard_health_httpd.py.j2` l.19–28.
#[derive(Debug, Clone, PartialEq)]
pub struct LogyardConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub path: String,
    /// `LOGYARD_LOKI_URL` with trailing `/` removed.
    pub loki_url: String,
    pub selector: String,
    pub warning_window_seconds: i64,
    pub critical_window_seconds: i64,
    pub request_timeout: Duration,
    pub systemctl_timeout: Duration,
    /// `LOGYARD_HEALTH_UNITS_B64`, parsed once as Python does at import.
    pub units: Units,
    /// The program run as `systemctl show …`, searched on `PATH` as Python's
    /// `subprocess.run(["systemctl", …])` does (the tests point it at a
    /// fake).
    pub systemctl: PathBuf,
}

impl LogyardConfig {
    /// Reads the environment through `var`; every invalid value is a
    /// problem (exit 2), as Python's module-level `int()`/`float()` abort
    /// the start. A rejected unit entry is not: Python serves it under
    /// `units_rejected`, and `--check-config` reports it.
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> Result<Self, Problems> {
        let mut problems = Problems::default();
        let text = |name: &str, default: &str| var(name).unwrap_or_else(|| default.to_owned());

        let bind_text = text("LOGYARD_HEALTH_BIND", "127.0.0.1");
        let bind = bind_text.parse().unwrap_or_else(|_| {
            problems.push(format!(
                "LOGYARD_HEALTH_BIND {bind_text:?} is not an IP address"
            ));
            IpAddr::from([127, 0, 0, 1])
        });
        let port_text = text("LOGYARD_HEALTH_PORT", "9105");
        let port = py_int(&port_text)
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or_else(|| {
                problems.push(format!("LOGYARD_HEALTH_PORT {port_text:?} is not a port"));
                0
            });
        let path = text("LOGYARD_HEALTH_PATH", "/.well-known/logyard");
        let loki_url = text("LOGYARD_LOKI_URL", "http://127.0.0.1:3101")
            .trim_end_matches('/')
            .to_owned();
        let selector = text(
            "LOGYARD_HEALTH_SELECTOR",
            "{host=\"macmini\",source_type=\"journald\"}",
        );
        let mut int = |name: &str, default: &str| {
            let value = text(name, default);
            py_int(&value).unwrap_or_else(|| {
                problems.push(format!("{name} {value:?} is not an integer"));
                0
            })
        };
        let warning_window_seconds = int("LOGYARD_WARNING_WINDOW_SECONDS", "900");
        let critical_window_seconds = int("LOGYARD_CRITICAL_WINDOW_SECONDS", "3600");
        let mut seconds = |name: &str, default: &str| {
            let value = text(name, default);
            py_positive_seconds(&value).unwrap_or_else(|| {
                problems.push(format!(
                    "{name} {value:?} is not a positive number of seconds"
                ));
                Duration::from_secs(1)
            })
        };
        let request_timeout = seconds("LOGYARD_REQUEST_TIMEOUT_SECONDS", "10");
        let systemctl_timeout = seconds("LOGYARD_HEALTH_SYSTEMCTL_TIMEOUT_SECONDS", "5");
        let units = load_units(&text("LOGYARD_HEALTH_UNITS_B64", ""));
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(Self {
            bind,
            port,
            path,
            loki_url,
            selector,
            warning_window_seconds,
            critical_window_seconds,
            request_timeout,
            systemctl_timeout,
            units,
            systemctl: PathBuf::from("systemctl"),
        })
    }
}

/// Python's `str.strip()`: every character `str.isspace()` accepts (the
/// Unicode white space plus the separators U+001C–U+001F).
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// The white space `int()`/`float()` ignore around a number: ASCII
/// `" \t\n\v\f\r"` and every non-ASCII `str.isspace()` character (Python
/// maps those to a space first); unlike `str.strip()`, not U+001C–U+001F.
fn py_number_strip(text: &str) -> &str {
    text.trim_matches(char::is_whitespace)
}

/// Digits with single `_` between them, as `int()`/`float()` accept.
fn without_underscores(digits: &str) -> Option<String> {
    if digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut chars = digits.chars().peekable();
    let mut out = String::with_capacity(digits.len());
    let mut previous_digit = false;
    while let Some(c) = chars.next() {
        if c == '_' {
            let next_digit = chars.peek().is_some_and(char::is_ascii_digit);
            if !(previous_digit && next_digit) {
                return None;
            }
        } else {
            out.push(c);
        }
        previous_digit = c.is_ascii_digit();
    }
    Some(out)
}

/// Python's `int(text)` for base-10 ASCII input.
pub fn py_int(text: &str) -> Option<i64> {
    let text = py_number_strip(text);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = without_underscores(digits)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: i64 = digits.parse().ok()?;
    Some(if negative { -value } else { value })
}

/// Python's `float(text)` for a `str`: surrounding white space, a sign,
/// `_` between digits, `inf`/`infinity`/`nan` in any case; an overflowing
/// literal is `±inf`. Digits outside ASCII (which Python also accepts) are
/// refused (PLAN.md D-13).
pub fn py_float(text: &str) -> Option<f64> {
    let text = without_underscores(py_number_strip(text))?;
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(&text);
    let lower = unsigned.to_ascii_lowercase();
    let special = matches!(lower.as_str(), "inf" | "infinity" | "nan");
    // Rust's grammar is Python's apart from the spellings checked here: a
    // decimal literal has only ASCII digits, `.`, `e`/`E` and exponent signs.
    if !special
        && !unsigned
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    text.parse().ok()
}

/// Python's `float(text)`, accepted only as a finite positive timeout.
pub fn py_positive_seconds(text: &str) -> Option<Duration> {
    let text = without_underscores(py_number_strip(text))?;
    let seconds: f64 = text.parse().ok()?;
    (seconds.is_finite() && seconds > 0.0 && seconds <= 86_400.0)
        .then(|| Duration::from_secs_f64(seconds))
}

/// A rejected entry of `_load_units`.
fn rejected(fields: &[(&str, &str)]) -> Map<String, Value> {
    fields
        .iter()
        .map(|(key, value)| ((*key).to_owned(), Value::String((*value).to_owned())))
        .collect()
}

/// `_load_units()` (l.33–85): strict base64 (`b64decode(validate=True)`),
/// UTF-8, JSON (with the D-4 refusals of [`pyjson::parse`]), a list of
/// `{"id", "unit"}` objects with non-empty string values, dot-free and
/// unique ids. Rejected entries carry the fields Python gives them; the
/// `detail` texts may differ (D-3).
pub fn load_units(units_b64: &str) -> Units {
    let mut out = Units::default();
    if units_b64.is_empty() {
        return out;
    }
    let raw = match auth::decode_base64(units_b64.as_bytes()) {
        None => {
            out.rejected.push(rejected(&[
                ("reason", "invalid_base64"),
                (
                    "detail",
                    "not strict base64 (standard alphabet, canonical padding)",
                ),
            ]));
            return out;
        }
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => {
                out.rejected.push(rejected(&[
                    ("reason", "invalid_base64"),
                    ("detail", &format!("decoded data is not UTF-8: {error}")),
                ]));
                return out;
            }
        },
    };
    let parsed = match pyjson::parse(raw.as_bytes()) {
        Ok(parsed) => parsed,
        Err(error) => {
            out.rejected.push(rejected(&[
                ("reason", "invalid_json"),
                ("detail", &error.to_string()),
            ]));
            return out;
        }
    };
    let Value::Array(entries) = parsed else {
        out.rejected.push(rejected(&[("reason", "not_a_list")]));
        return out;
    };
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let Value::Object(entry) = entry else {
            out.rejected.push(rejected(&[("reason", "not_an_object")]));
            continue;
        };
        let unit = match entry.get("unit") {
            Some(Value::String(unit)) if !unit.is_empty() => unit.clone(),
            _ => {
                out.rejected.push(rejected(&[("reason", "missing_unit")]));
                continue;
            }
        };
        let id = match entry.get("id") {
            Some(Value::String(id)) if !id.is_empty() => id.clone(),
            _ => {
                out.rejected
                    .push(rejected(&[("unit", &unit), ("reason", "missing_id")]));
                continue;
            }
        };
        if id.contains('.') {
            out.rejected.push(rejected(&[
                ("unit", &unit),
                ("id", &id),
                ("reason", "id_contains_dot"),
            ]));
            continue;
        }
        if !seen.insert(id.clone()) {
            out.rejected.push(rejected(&[
                ("unit", &unit),
                ("id", &id),
                ("reason", "duplicate_id"),
            ]));
            continue;
        }
        out.units.push(UnitEntry { id, unit });
    }
    out
}

impl Mode for LogyardConfig {
    type Service = LogyardHealth;
    const NAME: &'static str = "logyard-health";

    fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind, self.port)
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        // D-13: no TLS client.
        if !self.loki_url.starts_with("http://") {
            problems.push(format!(
                "LOGYARD_LOKI_URL {:?} is not an http:// URL",
                self.loki_url
            ));
        } else if format!("{}/ready", self.loki_url).parse::<Uri>().is_err() {
            problems.push(format!(
                "LOGYARD_LOKI_URL {:?} is not a valid URL",
                self.loki_url
            ));
        }
        // Python serves these under `units_rejected` and monitors the rest;
        // a role must not switch to Rust with such a list.
        for entry in &self.units.rejected {
            let field = |key: &str| entry.get(key).and_then(Value::as_str);
            let mut line = format!(
                "LOGYARD_HEALTH_UNITS_B64: entry rejected ({})",
                field("reason").unwrap_or("?")
            );
            for key in ["unit", "id", "detail"] {
                if let Some(value) = field(key) {
                    line.push_str(&format!(" {key} {value:?}"));
                }
            }
            problems.push(line);
        }
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} loki {} warning-window {}s critical-window {}s units {}",
            self.addr(),
            self.path,
            self.loki_url,
            self.warning_window_seconds,
            self.critical_window_seconds,
            self.units.units.len(),
        ))
    }

    fn server_config(&self, clock: SharedClock) -> ServerConfig {
        ServerConfig {
            request_timeout: REQUEST_TIMEOUT,
            access_log: AccessLog::Silent,
            server_header: server::server_header(SERVER_NAME),
            clock,
        }
    }

    fn service(&self, clock: SharedClock) -> LogyardHealth {
        LogyardHealth::new(self.clone(), clock)
    }
}

/// The logyard-health endpoint.
pub struct LogyardHealth {
    pub config: LogyardConfig,
    pub clock: SharedClock,
    client: Client<HttpConnector, Empty<Bytes>>,
}

impl LogyardHealth {
    pub fn new(config: LogyardConfig, clock: SharedClock) -> Self {
        // Python's `urlopen` opens a connection per request and closes it;
        // no idle connections are kept (and none can go stale).
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(HttpConnector::new());
        Self {
            config,
            clock,
            client,
        }
    }

    /// `urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS)` and `response.read()`:
    /// the status and body of a 2xx answer, else the text of the exception
    /// Python's `except` turns into a payload field. Redirects are not
    /// followed (D-13); the timeout covers the whole exchange.
    async fn fetch(&self, url: &str) -> Result<(u16, Bytes), String> {
        let uri: Uri = url
            .parse()
            .map_err(|error| format!("<urlopen error {error}>"))?;
        let exchange = async {
            let response = self.client.get(uri).await.map_err(client_error)?;
            let status = response.status();
            if !status.is_success() {
                let reason = response
                    .extensions()
                    .get::<hyper::ext::ReasonPhrase>()
                    .map(|reason| latin1(reason.as_bytes()))
                    .unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_owned());
                return Err(http_error(status, &reason));
            }
            let body = Limited::new(response.into_body(), MAX_LOKI_BODY_BYTES)
                .collect()
                .await
                .map_err(|error| format!("cannot read the response: {error}"))?
                .to_bytes();
            Ok((status.as_u16(), body))
        };
        tokio::time::timeout(self.config.request_timeout, exchange)
            .await
            .unwrap_or_else(|_| Err("timed out".to_owned()))
    }

    /// The `loki` block (l.184–192, 203–207).
    async fn loki_ready(&self) -> Map<String, Value> {
        let answer = self
            .fetch(&format!("{}/ready", self.config.loki_url))
            .await
            .and_then(|(status, body)| match String::from_utf8(body.to_vec()) {
                Ok(text) => Ok((status, py_strip(&text).to_owned())),
                // D-2: Python's `decode` raises outside the caught types.
                Err(error) => Err(format!("the response is not UTF-8: {error}")),
            });
        let (ready, status, body) = match answer {
            Ok((status, body)) => (
                status == 200 && body.to_lowercase() == "ready",
                Value::from(status),
                body,
            ),
            Err(error) => (false, Value::Null, error),
        };
        let mut loki = Map::new();
        loki.insert("ready".to_owned(), Value::Bool(ready));
        loki.insert("ready_status".to_owned(), status);
        loki.insert("ready_body".to_owned(), Value::String(body));
        loki
    }

    /// `_query_count(window_seconds)` (l.164–174).
    async fn query_count(&self, window_seconds: i64) -> Result<f64, String> {
        let expr = format!(
            "sum(count_over_time({}[{window_seconds}s]))",
            self.config.selector
        );
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("query", &expr)
            .finish();
        let (_, body) = self
            .fetch(&format!(
                "{}/loki/api/v1/query?{query}",
                self.config.loki_url
            ))
            .await?;
        let body = pyjson::parse(&body).map_err(|error| error.to_string())?;
        count_from_body(&body)
    }

    /// `_unit_status(unit)` (l.113–156).
    async fn unit_status(&self, unit: &str) -> Value {
        let mut args: Vec<&str> = vec!["show"];
        for property in SYSTEMCTL_PROPERTIES {
            args.extend(["-p", property]);
        }
        // Terminator before the unit name: valid units may start with "-".
        args.extend(["--", unit]);
        let program = &self.config.systemctl;
        let child = tokio::process::Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Dropping the wait at the timeout kills the child, as
            // `subprocess.run(timeout=…)` does.
            .kill_on_drop(true)
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                return unit_unknown(unit, &os_error(&error, &program.to_string_lossy()));
            }
        };
        let output =
            match tokio::time::timeout(self.config.systemctl_timeout, child.wait_with_output())
                .await
            {
                Ok(Ok(output)) => output,
                Ok(Err(error)) => return unit_unknown(unit, &os_error(&error, "")),
                Err(_) => {
                    let mut argv = vec![program.to_string_lossy().into_owned()];
                    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
                    return unit_unknown(
                        unit,
                        &format!(
                            "Command '{}' timed out after {} seconds",
                            py_list_repr(&argv),
                            pyjson::float_repr(self.config.systemctl_timeout.as_secs_f64())
                        ),
                    );
                }
            };
        // `text=True`: strict UTF-8 (D-2: Python raises outside the caught
        // types) and universal newlines.
        let (Ok(stdout), Ok(stderr)) = (
            String::from_utf8(output.stdout),
            String::from_utf8(output.stderr),
        ) else {
            return unit_unknown(unit, "systemctl output is not valid UTF-8");
        };
        let (stdout, stderr) = (universal_newlines(&stdout), universal_newlines(&stderr));
        if !output.status.success() {
            let code = output
                .status
                .code()
                .or_else(|| output.status.signal().map(|signal| -signal))
                .unwrap_or(-1);
            let detail = Some(py_strip(&stderr))
                .filter(|text| !text.is_empty())
                .or_else(|| Some(py_strip(&stdout)).filter(|text| !text.is_empty()))
                .map_or_else(|| format!("systemctl show failed ({code})"), str::to_owned);
            return unit_unknown(unit, &detail);
        }
        let mut data: BTreeMap<&str, &str> = BTreeMap::new();
        for line in py_splitlines(&stdout) {
            if let Some((key, value)) = line.split_once('=') {
                data.insert(key, value);
            }
        }
        let load_state = data.get("LoadState").copied().unwrap_or("");
        let optional = |key: &str| {
            data.get(key)
                .map_or(Value::Null, |value| Value::String((*value).to_owned()))
        };
        let mut status = Map::new();
        status.insert("unit".to_owned(), Value::String(unit.to_owned()));
        status.insert(
            "exists".to_owned(),
            Value::Bool(!matches!(load_state, "" | "not-found")),
        );
        status.insert(
            "load_state".to_owned(),
            Value::String(load_state.to_owned()),
        );
        status.insert("active_state".to_owned(), optional("ActiveState"));
        status.insert("sub_state".to_owned(), optional("SubState"));
        status.insert("result".to_owned(), optional("Result"));
        status.insert("error".to_owned(), Value::Null);
        Value::Object(status)
    }

    /// `_build_payload()` (l.177–232) serialised as `json.dumps(payload,
    /// sort_keys=True)`.
    pub async fn payload(&self) -> Vec<u8> {
        let generated_at = iso_utc(epoch_seconds(self.clock.now())).unwrap_or_default();
        let loki = self.loki_ready().await;
        let ready = loki.get("ready") == Some(&Value::Bool(true));

        let mut warning_entries = 0.0;
        let mut critical_entries = 0.0;
        let mut ingest_error = None;
        match self.query_count(self.config.warning_window_seconds).await {
            Ok(count) => {
                warning_entries = count;
                match self.query_count(self.config.critical_window_seconds).await {
                    Ok(count) => critical_entries = count,
                    Err(error) => ingest_error = Some(error),
                }
            }
            Err(error) => ingest_error = Some(error),
        }

        let mut ingest = BTreeMap::new();
        ingest.insert(
            "warning_window_seconds",
            Out::Json(self.config.warning_window_seconds.into()),
        );
        ingest.insert(
            "critical_window_seconds",
            Out::Json(self.config.critical_window_seconds.into()),
        );
        ingest.insert("warning_window_entries", Out::Float(warning_entries));
        ingest.insert("critical_window_entries", Out::Float(critical_entries));
        ingest.insert(
            "warning_fresh",
            Out::Json(Value::Bool(warning_entries > 0.0)),
        );
        ingest.insert(
            "critical_fresh",
            Out::Json(Value::Bool(critical_entries > 0.0)),
        );
        if let Some(error) = &ingest_error {
            ingest.insert("error", Out::Json(Value::String(error.clone())));
        }

        let mut units = Map::new();
        for entry in &self.config.units.units {
            units.insert(entry.id.clone(), self.unit_status(&entry.unit).await);
        }

        // NaN compares false both ways, as in Python.
        let status = if !ready || ingest_error.is_some() || critical_entries <= 0.0 {
            "critical"
        } else if warning_entries <= 0.0 {
            "warning"
        } else {
            "ok"
        };

        let mut payload = BTreeMap::new();
        payload.insert("generated_at", Out::Json(Value::String(generated_at)));
        payload.insert("status", Out::Json(Value::String(status.to_owned())));
        payload.insert(
            "selector",
            Out::Json(Value::String(self.config.selector.clone())),
        );
        payload.insert("loki", Out::Json(Value::Object(loki)));
        payload.insert("ingest", Out::Object(ingest));
        payload.insert("units", Out::Json(Value::Object(units)));
        if !self.config.units.rejected.is_empty() {
            payload.insert(
                "units_rejected",
                Out::Json(Value::Array(
                    self.config
                        .units
                        .rejected
                        .iter()
                        .cloned()
                        .map(Value::Object)
                        .collect(),
                )),
            );
        }
        let mut out = Vec::with_capacity(1024);
        Out::Object(payload).write(&mut out);
        out
    }
}

impl Service for LogyardHealth {
    async fn call(&self, request: Request) -> HttpResponse {
        if request.method != Method::GET {
            return server::not_implemented(&request.method);
        }
        if request.python_path() != self.config.path {
            return server::json_response(
                StatusCode::NOT_FOUND,
                b"{\"error\":\"not_found\"}".to_vec(),
            );
        }
        server::json_response(StatusCode::OK, self.payload().await)
    }
}

/// A payload value: JSON, or a Python `float` (the entry counts, which may
/// be `NaN` or `±Infinity`, written as `json.dumps` writes them).
enum Out {
    Json(Value),
    Float(f64),
    Object(BTreeMap<&'static str, Out>),
}

impl Out {
    /// `json.dumps(…, sort_keys=True)`: keys in code point order (the map's
    /// order), Python's separators, `float.__repr__`.
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Json(value) => out.extend(pyjson::dumps(value)),
            Self::Float(value) => out.extend(pyjson::float_repr(*value).bytes()),
            Self::Object(map) => {
                out.push(b'{');
                for (index, (key, value)) in map.iter().enumerate() {
                    if index > 0 {
                        out.extend(b", ");
                    }
                    out.extend(pyjson::dumps(&Value::String((*key).to_owned())));
                    out.extend(b": ");
                    value.write(out);
                }
                out.push(b'}');
            }
        }
    }
}

/// `_unit_unknown(unit, error)` (l.95–110).
fn unit_unknown(unit: &str, error: &str) -> Value {
    let mut status = Map::new();
    status.insert("unit".to_owned(), Value::String(unit.to_owned()));
    for key in [
        "exists",
        "load_state",
        "active_state",
        "sub_state",
        "result",
    ] {
        status.insert(key.to_owned(), Value::Null);
    }
    status.insert("error".to_owned(), Value::String(error.to_owned()));
    Value::Object(status)
}

/// The body handling of `_query_count` after `json.loads` (l.168–174), with
/// Python's indexing and `float()` semantics: `body.get("data", {})
/// .get("result", [])`, falsy → 0.0, `float(result[0]["value"][1])` with
/// `KeyError`/`IndexError`/`TypeError`/`ValueError` → 0.0. `Err` is the
/// text of an exception Python does not catch there (`AttributeError` of a
/// non-object body or `data`, `OverflowError` of a huge int); Python then
/// drops the connection, Rust reports it as the ingest error (D-2).
pub fn count_from_body(body: &Value) -> Result<f64, String> {
    let Value::Object(body) = body else {
        return Err(no_get(body));
    };
    let result = match body.get("data") {
        None => return Ok(0.0),
        Some(Value::Object(data)) => match data.get("result") {
            None => return Ok(0.0),
            Some(result) => result,
        },
        Some(other) => return Err(no_get(other)),
    };
    if !pyjson::truthy(result) {
        return Ok(0.0);
    }
    // `result[0]`: only a list yields an element that can be indexed by
    // "value" (a str element is a 1-character str → TypeError; a dict has
    // no int key → KeyError; other types → TypeError).
    let Value::Array(result) = result else {
        return Ok(0.0);
    };
    let Some(Value::Object(first)) = result.first() else {
        return Ok(0.0);
    };
    let sample = match first.get("value") {
        Some(Value::Array(value)) => match value.get(1) {
            Some(sample) => sample.clone(),
            None => return Ok(0.0),
        },
        // `"12"[1]` is the str "2".
        Some(Value::String(value)) => match value.chars().nth(1) {
            Some(c) => Value::String(c.to_string()),
            None => return Ok(0.0),
        },
        _ => return Ok(0.0),
    };
    match sample {
        Value::String(text) => Ok(py_float(&text).unwrap_or(0.0)),
        Value::Bool(flag) => Ok(if flag { 1.0 } else { 0.0 }),
        Value::Number(number) => {
            let lexeme = number.as_str();
            let value: f64 = lexeme.parse().map_err(|_| format!("bad number {lexeme}"))?;
            if pyjson::is_int_lexeme(lexeme) {
                // `float(int)`: correctly rounded, `-0` is the int 0.
                if value.is_infinite() {
                    return Err("int too large to convert to float".to_owned());
                }
                Ok(if value == 0.0 { 0.0 } else { value })
            } else {
                Ok(value)
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => Ok(0.0),
    }
}

/// The `AttributeError` text of `<value>.get` on a non-dict.
fn no_get(value: &Value) -> String {
    let type_name = match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if pyjson::is_int_lexeme(number.as_str()) => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    };
    format!("'{type_name}' object has no attribute 'get'")
}

/// `str(HTTPError)`: `HTTP Error <code>: <reason>`.
fn http_error(status: StatusCode, reason: &str) -> String {
    format!("HTTP Error {}: {}", status.as_u16(), py_strip(reason))
}

/// Bytes of a status line as `http.client` decodes them (ISO-8859-1).
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| char::from(byte)).collect()
}

/// `str(URLError(OSError))` of a failed connection, else the error chain.
fn client_error(error: hyper_util::client::legacy::Error) -> String {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(current) = source {
        if let Some(io_error) = current.downcast_ref::<io::Error>() {
            return format!("<urlopen error {}>", os_error(io_error, ""));
        }
        source = current.source();
    }
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(current) = source {
        text.push_str(&format!(": {current}"));
        source = current.source();
    }
    text
}

/// `str(OSError)`: `[Errno <n>] <strerror>[: '<filename>']`.
fn os_error(error: &io::Error, filename: &str) -> String {
    let Some(code) = error.raw_os_error() else {
        return error.to_string();
    };
    let text = error.to_string();
    let suffix = format!(" (os error {code})");
    let message = text.strip_suffix(&suffix).unwrap_or(&text);
    if filename.is_empty() {
        format!("[Errno {code}] {message}")
    } else {
        format!("[Errno {code}] {message}: {}", py_str_repr(filename))
    }
}

/// `repr()` of a Python `str` (the quote choice and the common escapes).
fn py_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if u32::from(c) < 0x20 || (0x7f..0xa0).contains(&u32::from(c)) => {
                out.push_str(&format!("\\x{:02x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr()` of a list of `str` (`subprocess.TimeoutExpired`'s command).
fn py_list_repr(items: &[String]) -> String {
    let items: Vec<String> = items.iter().map(|item| py_str_repr(item)).collect();
    format!("[{}]", items.join(", "))
}

/// Text mode's universal newlines: `\r\n` and `\r` become `\n`.
fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `str.splitlines()`: the line boundaries Python recognises.
fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if boundary {
            lines.push(&text[start..index]);
            let mut end = index + c.len_utf8();
            if c == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Result<LogyardConfig, Problems> {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        LogyardConfig::from_env(|name| env.get(name).cloned())
    }

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    #[test]
    fn defaults_match_the_python_module() {
        let config = config(&[]).unwrap();
        assert_eq!(config.addr(), "127.0.0.1:9105".parse().unwrap());
        assert_eq!(config.path, "/.well-known/logyard");
        assert_eq!(config.loki_url, "http://127.0.0.1:3101");
        assert_eq!(
            config.selector,
            "{host=\"macmini\",source_type=\"journald\"}"
        );
        assert_eq!(config.warning_window_seconds, 900);
        assert_eq!(config.critical_window_seconds, 3600);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.systemctl_timeout, Duration::from_secs(5));
        assert_eq!(config.units, Units::default());
        assert_eq!(config.systemctl, PathBuf::from("systemctl"));
        assert!(config.check_config().is_ok());
    }

    #[test]
    fn environment_values_parse_as_python() {
        let config = config(&[
            ("LOGYARD_LOKI_URL", "http://loki:3100//"),
            ("LOGYARD_HEALTH_PORT", " 9_105 "),
            ("LOGYARD_WARNING_WINDOW_SECONDS", "+0900"),
            ("LOGYARD_REQUEST_TIMEOUT_SECONDS", "2.5"),
            ("LOGYARD_HEALTH_BIND", "::1"),
        ])
        .unwrap();
        assert_eq!(config.loki_url, "http://loki:3100");
        assert_eq!(config.port, 9105);
        assert_eq!(config.warning_window_seconds, 900);
        assert_eq!(config.request_timeout, Duration::from_millis(2500));
        assert_eq!(config.addr(), "[::1]:9105".parse().unwrap());
        assert_eq!(py_int("-5"), Some(-5));
        assert_eq!(py_int("\u{a0}5\x0b"), Some(5));
        for bad in [
            "", "9__0", "_9", "9_", "1.0", "0x10", "1e3", "\x1c5", "5\x1f",
        ] {
            assert_eq!(py_int(bad), None, "{bad}");
        }
    }

    #[test]
    fn invalid_environment_is_a_config_error() {
        for pair in [
            ("LOGYARD_HEALTH_PORT", "65536"),
            ("LOGYARD_HEALTH_PORT", "x"),
            ("LOGYARD_WARNING_WINDOW_SECONDS", "15m"),
            ("LOGYARD_CRITICAL_WINDOW_SECONDS", ""),
            ("LOGYARD_REQUEST_TIMEOUT_SECONDS", "nan"),
            ("LOGYARD_HEALTH_SYSTEMCTL_TIMEOUT_SECONDS", "0"),
            ("LOGYARD_HEALTH_BIND", "localhost"),
        ] {
            assert!(config(&[pair]).is_err(), "{pair:?}");
        }
        let https = config(&[("LOGYARD_LOKI_URL", "https://loki")]).unwrap();
        assert!(https.check_config().is_err(), "D-13");
        let bad = config(&[("LOGYARD_LOKI_URL", "http://bad host:3100")]).unwrap();
        assert!(bad.check_config().is_err());
    }

    #[test]
    fn rejected_units_fail_check_config_but_not_the_start() {
        let list = r#"[{"id": "vector", "unit": "vector.service"},
                       {"id": "a.b", "unit": "x.service"}, 5]"#;
        let config = config(&[("LOGYARD_HEALTH_UNITS_B64", &b64(list))]).unwrap();
        assert_eq!(
            config.units.units,
            [UnitEntry {
                id: "vector".to_owned(),
                unit: "vector.service".to_owned()
            }]
        );
        assert_eq!(config.units.rejected.len(), 2);
        let problems = config.check_config().unwrap_err().0;
        assert_eq!(
            problems,
            [
                "LOGYARD_HEALTH_UNITS_B64: entry rejected (id_contains_dot) unit \"x.service\" id \"a.b\"",
                "LOGYARD_HEALTH_UNITS_B64: entry rejected (not_an_object)",
            ]
        );
        let good = config_with_units(r#"[{"id": "vector", "unit": "vector.service"}]"#);
        assert!(good.check_config().unwrap().ends_with("units 1"));
        let bad = config_with_units("{");
        assert_eq!(bad.units.rejected[0]["reason"], "invalid_json");
        assert!(bad.check_config().is_err());
    }

    fn config_with_units(list: &str) -> LogyardConfig {
        config(&[("LOGYARD_HEALTH_UNITS_B64", &b64(list))]).unwrap()
    }

    #[test]
    fn load_units_follows_python() {
        assert_eq!(load_units(""), Units::default());
        let units = load_units("not base64!");
        assert_eq!(units.rejected[0]["reason"], "invalid_base64");
        let units = load_units(&base64::engine::general_purpose::STANDARD.encode(b"\xff"));
        assert_eq!(units.rejected[0]["reason"], "invalid_base64");
        assert_eq!(
            load_units(&b64("{}")).rejected,
            [rejected(&[("reason", "not_a_list")])]
        );
        let units = load_units(&b64(
            r#"[{"unit": ""}, {"unit": true}, {"unit": "u"}, {"unit": "u", "id": 1},
                {"unit": "-.mount", "id": "root"}, {"unit": "v", "id": "root"}]"#,
        ));
        assert_eq!(
            units.units,
            [UnitEntry {
                id: "root".to_owned(),
                unit: "-.mount".to_owned()
            }]
        );
        assert_eq!(
            units.rejected,
            [
                rejected(&[("reason", "missing_unit")]),
                rejected(&[("reason", "missing_unit")]),
                rejected(&[("unit", "u"), ("reason", "missing_id")]),
                rejected(&[("unit", "u"), ("reason", "missing_id")]),
                rejected(&[("unit", "v"), ("id", "root"), ("reason", "duplicate_id")]),
            ]
        );
    }

    #[test]
    fn python_float_spellings() {
        for (text, expected) in [
            ("42", 42.0),
            (" 4_2\n", 42.0),
            ("1e3", 1000.0),
            ("-0", -0.0),
            (".5", 0.5),
            ("5.", 5.0),
            ("1E+3", 1000.0),
        ] {
            assert_eq!(py_float(text), Some(expected), "{text}");
        }
        assert!(py_float("nan").unwrap().is_nan());
        assert!(py_float("-NaN").unwrap().is_nan());
        assert_eq!(py_float("+Infinity"), Some(f64::INFINITY));
        assert_eq!(py_float("-inf"), Some(f64::NEG_INFINITY));
        assert_eq!(py_float("1e500"), Some(f64::INFINITY));
        for bad in [
            "", " ", "4__2", "_4", "0x10", "1,0", "inf_", "in f", "١٢", "1e", "\x1c7",
        ] {
            assert_eq!(py_float(bad), None, "{bad}");
        }
    }

    #[test]
    fn counts_follow_python_indexing() {
        let count = |text: &str| count_from_body(&pyjson::parse(text.as_bytes()).unwrap());
        assert_eq!(
            count(r#"{"data": {"result": [{"value": [1, "12"]}]}}"#),
            Ok(12.0)
        );
        assert_eq!(count(r#"{"data": {"result": [{"value": "12"}]}}"#), Ok(2.0));
        assert_eq!(
            count(r#"{"data": {"result": [{"value": [1, -0]}]}}"#),
            Ok(0.0)
        );
        assert_eq!(
            count(r#"{"data": {"result": [{"value": [1, true]}]}}"#),
            Ok(1.0)
        );
        assert_eq!(count(r#"{"data": {"result": "abc"}}"#), Ok(0.0));
        assert_eq!(count(r#"{"status": "success"}"#), Ok(0.0));
        assert_eq!(
            count("[]"),
            Err("'list' object has no attribute 'get'".to_owned())
        );
        assert_eq!(
            count(r#"{"data": null}"#),
            Err("'NoneType' object has no attribute 'get'".to_owned())
        );
        let huge = format!(
            r#"{{"data": {{"result": [{{"value": [1, 1{}]}}]}}}}"#,
            "0".repeat(400)
        );
        assert!(count(&huge).is_err());
    }

    #[test]
    fn python_texts() {
        assert_eq!(
            http_error(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"),
            "HTTP Error 503: Service Unavailable"
        );
        assert_eq!(
            py_list_repr(&["systemctl".to_owned(), "it's".to_owned()]),
            "['systemctl', \"it's\"]"
        );
        assert_eq!(py_str_repr("a\0b"), "'a\\x00b'");
        let error = io::Error::from_raw_os_error(2);
        assert_eq!(
            os_error(&error, "systemctl"),
            format!(
                "[Errno 2] {}: 'systemctl'",
                error.to_string().strip_suffix(" (os error 2)").unwrap()
            )
        );
        assert_eq!(
            py_splitlines("a\r\nb\rc\x0bd\u{2028}e\n"),
            ["a", "b", "c", "d", "e"]
        );
        assert_eq!(py_splitlines(""), Vec::<&str>::new());
        assert_eq!(universal_newlines("a\r\nb\rc"), "a\nb\nc");
        assert_eq!(py_strip("\x1c ready \u{a0}\n"), "ready");
    }

    #[test]
    fn float_payload_values_are_written_as_python() {
        let mut map = BTreeMap::new();
        map.insert("b", Out::Float(f64::NAN));
        map.insert("a", Out::Float(12.0));
        map.insert("c", Out::Float(f64::NEG_INFINITY));
        map.insert("é", Out::Json(Value::Null));
        let mut out = Vec::new();
        Out::Object(map).write(&mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"a\": 12.0, \"b\": NaN, \"c\": -Infinity, \"\\u00e9\": null}"
        );
    }
}
