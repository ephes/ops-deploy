//! Mode `logyard-health` (PLAN.md 4.6): Loki readiness, ingest freshness
//! and unit states, configured from the `LOGYARD_*` environment the unit
//! already sets; no auth and no per-request log.
//!
//! S1: the environment (as the Python module reads it at import time),
//! `--check-config`, the 501/404 answers; the payload, the unit list and
//! the Loki client arrive with S2d.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use clap::Args;
use hyper::{Method, StatusCode};

use crate::clock::SharedClock;
use crate::modes::{Mode, Problems, not_yet_implemented};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// D-1: header-read and keep-alive timeout (Python: none).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `BaseHTTPRequestHandler.server_version` (D-7 adds `metrics-httpd/<v>`).
pub const SERVER_NAME: &str = "BaseHTTP/0.6";

#[derive(Args, Debug, Clone)]
pub struct LogyardHealthArgs {
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
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
    /// `LOGYARD_HEALTH_UNITS_B64`, parsed in S2d.
    pub units_b64: String,
}

impl LogyardConfig {
    /// Reads the environment through `var`; every invalid value is a
    /// problem (exit 2), as Python's module-level `int()`/`float()` abort
    /// the start.
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
        let units_b64 = text("LOGYARD_HEALTH_UNITS_B64", "");
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
            units_b64,
        })
    }
}

/// The characters Python's `str.strip()` removes (ASCII subset; the
/// environment of the unit is ASCII).
fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
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
    let text = py_strip(text);
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

/// Python's `float(text)`, accepted only as a finite positive timeout.
pub fn py_positive_seconds(text: &str) -> Option<Duration> {
    let text = without_underscores(py_strip(text))?;
    let seconds: f64 = text.parse().ok()?;
    (seconds.is_finite() && seconds > 0.0 && seconds <= 86_400.0)
        .then(|| Duration::from_secs_f64(seconds))
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
        }
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} loki {} warning-window {}s critical-window {}s",
            self.addr(),
            self.path,
            self.loki_url,
            self.warning_window_seconds,
            self.critical_window_seconds,
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
        LogyardHealth {
            config: self.clone(),
            clock,
        }
    }
}

/// The logyard-health endpoint.
pub struct LogyardHealth {
    pub config: LogyardConfig,
    pub clock: SharedClock,
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
        not_yet_implemented(<LogyardConfig as Mode>::NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Result<LogyardConfig, Problems> {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        LogyardConfig::from_env(|name| env.get(name).cloned())
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
        for bad in ["", "9__0", "_9", "9_", "1.0", "0x10", "1e3"] {
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
    }
}
