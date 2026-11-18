//! The endpoint families of PLAN.md 3 and 4.9, their shared flags and the
//! request gate of PLAN.md 4.1 (method, path, auth).
//!
//! S1 provides the command line, `--check-config` and the gate of every
//! mode; a request that passes the gate gets a 500 `internal_error` until
//! the mode's slice (S2a–S2e) implements its body.

pub mod apt_state;
pub mod json_file;
pub mod logyard_health;
pub mod script;
pub mod static_site;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, ValueEnum};
use hyper::header::AUTHORIZATION;
use hyper::{Method, StatusCode};

use crate::auth::{self, PasswordSource};
use crate::clock::SharedClock;
use crate::server::{self, HttpResponse, Request, ServerConfig, Service};

/// A mode's validated configuration: what `main` needs to check or run it.
pub trait Mode {
    type Service: Service;
    /// The subcommand name.
    const NAME: &'static str;
    fn addr(&self) -> SocketAddr;
    /// `--check-config`: everything the process would need, without
    /// binding. `Ok` is the one-line summary (never a hash or password).
    fn check_config(&self) -> Result<String, Problems>;
    fn server_config(&self, clock: SharedClock) -> ServerConfig;
    fn service(&self, clock: SharedClock) -> Self::Service;
}

/// `--bind`/`--port` (PLAN.md 4.1.7). The bind address is an IP literal,
/// as in every role (`tailscale_ip`, LAN or loopback addresses).
#[derive(Args, Debug, Clone)]
pub struct ListenArgs {
    /// Address to listen on (IPv4 or IPv6 literal).
    #[arg(long, value_name = "ADDR")]
    pub bind: IpAddr,
    /// TCP port (0: any free port, for tests).
    #[arg(long, value_name = "N")]
    pub port: u16,
}

impl ListenArgs {
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind, self.port)
    }
}

/// The flags of every authenticated mode (json-file, script, apt-state).
#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// The only path served (the raw request-target must equal it).
    #[arg(long, value_name = "P", value_parser = parse_path)]
    pub path: String,
    /// htpasswd file with bcrypt entries, read on every request.
    #[arg(long, value_name = "H")]
    pub htpasswd_file: PathBuf,
    /// Basic auth realm of the 401 answer.
    #[arg(long, value_name = "R", value_parser = parse_header_text)]
    pub realm: String,
    /// The Python script's `server_version`, sent as `Server: <S> metrics-httpd/<version>`.
    #[arg(long, value_name = "S", value_parser = parse_header_text)]
    pub server_name: String,
    /// Header-read and keep-alive idle timeout in seconds.
    #[arg(long, value_name = "SECS", default_value = "10", value_parser = parse_seconds)]
    pub request_timeout: Duration,
}

/// `--path-match` (PLAN.md 4.1.2).
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMatch {
    /// `self.path != cfg["path"]` (raw target, query included).
    Exact,
    /// `urlsplit(self.path).path` (tailscale): query and fragment ignored.
    PathOnly,
}

/// How a wrong path is answered (PLAN.md 4.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotFound {
    /// `_send_json_error(404, "not_found", "Endpoint not found")`.
    Json,
    /// metrics_endpoint: `send_error(404, "Not found")`.
    Html,
}

/// The checks every authenticated mode makes before its own work, in
/// Python's order: method (dispatch), path, auth.
#[derive(Debug, Clone)]
pub struct Gate {
    pub path: String,
    pub path_match: PathMatch,
    pub not_found: NotFound,
    pub htpasswd_file: PathBuf,
    pub realm: String,
    pub password_source: PasswordSource,
}

impl Gate {
    /// The gate of a json-file or apt-state variant (`htpasswd -vi`).
    pub fn new(args: &AuthArgs, path_match: PathMatch, not_found: NotFound) -> Self {
        Self {
            path: args.path.clone(),
            path_match,
            not_found,
            htpasswd_file: args.htpasswd_file.clone(),
            realm: args.realm.clone(),
            password_source: PasswordSource::Stdin,
        }
    }

    /// `Some(response)` when the request ends here (501, 404 or 401).
    pub async fn check(&self, request: &Request) -> Option<HttpResponse> {
        if request.method != Method::GET {
            return Some(server::not_implemented(&request.method));
        }
        let path = match self.path_match {
            PathMatch::Exact => request.python_path(),
            PathMatch::PathOnly => request.path_only(),
        };
        if path != self.path {
            return Some(match self.not_found {
                NotFound::Json => {
                    server::json_error(StatusCode::NOT_FOUND, "not_found", "Endpoint not found")
                }
                NotFound::Html => server::not_found_html(),
            });
        }
        let header = request
            .headers
            .get(AUTHORIZATION)
            .map(|value| value.as_bytes());
        if !auth::authorize(header, &self.htpasswd_file, self.password_source).await {
            return Some(server::unauthorized(&self.realm));
        }
        None
    }
}

/// The answer of a mode whose slice has not landed yet.
pub fn not_yet_implemented(mode: &str) -> HttpResponse {
    server::json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("the {mode} mode is not implemented in this build"),
    )
}

/// Collects the problems `--check-config` reports.
#[derive(Debug, Default)]
pub struct Problems(pub Vec<String>);

impl Problems {
    pub fn push(&mut self, problem: impl Into<String>) {
        self.0.push(problem.into());
    }

    /// `--check-config` of an htpasswd file; returns the entry count.
    pub fn htpasswd(&mut self, path: &Path) -> usize {
        auth::check_file(path).unwrap_or_else(|problem| {
            self.push(format!("htpasswd file {problem}"));
            0
        })
    }

    /// The directory a JSON file is written into exists.
    pub fn parent_dir(&mut self, what: &str, path: &Path) {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.is_dir() {
            self.push(format!(
                "{what} {}: directory {} does not exist",
                path.display(),
                parent.display()
            ));
        }
    }
}

/// `--path`: an absolute path without control characters.
fn parse_path(value: &str) -> Result<String, String> {
    if !value.starts_with('/') {
        return Err("must start with '/'".to_owned());
    }
    if value.chars().any(|c| c.is_control() || c == ' ') {
        return Err("must not contain spaces or control characters".to_owned());
    }
    Ok(value.to_owned())
}

/// `--realm`, `--server-name`: printable ASCII without `"` and `\`, so they
/// fit a header value (`Basic realm="<realm>"`) unquoted.
pub fn parse_header_text(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("must not be empty".to_owned());
    }
    if !value
        .chars()
        .all(|c| (' '..='~').contains(&c) && c != '"' && c != '\\')
    {
        return Err("must be printable ASCII without '\"' and '\\'".to_owned());
    }
    Ok(value.to_owned())
}

/// A positive number of seconds, fractions allowed (`10`, `0.5`).
pub fn parse_seconds(value: &str) -> Result<Duration, String> {
    let seconds: f64 = value
        .trim()
        .parse()
        .map_err(|_| format!("not a number of seconds: {value:?}"))?;
    if !(seconds.is_finite() && seconds > 0.0 && seconds <= 86_400.0) {
        return Err(format!(
            "must be more than 0 and at most 86400 seconds: {value:?}"
        ));
    }
    Ok(Duration::from_secs_f64(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_value_rules() {
        assert!(parse_path("/.well-known/backup").is_ok());
        assert!(parse_path("well-known").is_err());
        assert!(parse_path("/a b").is_err());
        assert!(parse_header_text("backup-metrics").is_ok());
        assert!(parse_header_text("a\"b").is_err());
        assert!(parse_header_text("").is_err());
        assert_eq!(parse_seconds("10").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_seconds("0.25").unwrap(), Duration::from_millis(250));
        for bad in ["0", "-1", "nan", "inf", "x", "86401"] {
            assert!(parse_seconds(bad).is_err(), "{bad}");
        }
    }
}
