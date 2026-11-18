//! Mode `static` (PLAN.md 4.7, `static_site_deploy`): a read-only static
//! site behind Traefik, the port of `static-site-httpd.py.j2`
//! (`SimpleHTTPRequestHandler` with `directory=<site root>`).
//!
//! The files come from `tower-http`'s `ServeDir` (D-11): path sanitising,
//! `index.html` for a directory, `Content-Type` from `mime_guess`,
//! `Last-Modified`, `If-Modified-Since` → 304 and `Range` → 206. Around it,
//! this module keeps Python's answers where they are cheap to keep:
//!
//! - GET and HEAD only; every other method gets Python's 501 page;
//! - a leading run of `/` is collapsed as Python does (gh-87389), so
//!   `//dir` never redirects to the protocol-relative `//dir/`;
//! - a target that is not origin-form (absolute form, `*`) is 404: Python
//!   looks for a file named after the whole target;
//! - `If-Match` and `If-Unmodified-Since` are ignored and an
//!   `If-None-Match` disables both it and `If-Modified-Since`, as in
//!   Python (which evaluates only `If-Modified-Since`); no `ETag` is sent;
//! - a directory without trailing `/` gets Python's 301 (`ServeDir`: 307)
//!   with Python's `Location` and `Content-Length: 0`;
//! - a missing or unreadable file is Python's 404 page "File not found";
//! - every answer carries the four headers of the template's
//!   `end_headers` override.
//!
//! The remaining differences are D-11 (and D-3 for the 404 page text of a
//! directory without index); `TESTMAP.md` lists the cases that pin them.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use clap::Args;
use http_body_util::{BodyExt, Empty};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, StatusCode, Uri};
use tower_http::services::ServeDir;

use crate::clock::SharedClock;
use crate::modes::{ListenArgs, Mode, Problems};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// `StaticHandler.timeout = 10`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `SimpleHTTPRequestHandler.server_version` (D-7 adds `metrics-httpd/<v>`).
pub const SERVER_NAME: &str = "SimpleHTTP/0.6";

/// The headers `StaticHandler.end_headers` adds to every response.
pub const SITE_HEADERS: [(HeaderName, &str); 4] = [
    (header::CACHE_CONTROL, "no-cache"),
    (header::REFERRER_POLICY, "no-referrer"),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::X_FRAME_OPTIONS, "SAMEORIGIN"),
];

#[derive(Args, Debug, Clone)]
pub struct StaticArgs {
    #[command(flatten)]
    pub listen: ListenArgs,
    /// The site root directory.
    #[arg(long, value_name = "DIR")]
    pub root: PathBuf,
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

impl Mode for StaticArgs {
    type Service = StaticSite;
    const NAME: &'static str = "static";

    fn addr(&self) -> SocketAddr {
        self.listen.addr()
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        if !self.root.is_dir() {
            problems.push(format!(
                "site root {} is not a directory",
                self.root.display()
            ));
        }
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!("bind {} root {}", self.addr(), self.root.display()))
    }

    fn server_config(&self, clock: SharedClock) -> ServerConfig {
        ServerConfig {
            request_timeout: REQUEST_TIMEOUT,
            access_log: AccessLog::Stdout,
            server_header: server::server_header(SERVER_NAME),
            clock,
        }
    }

    fn service(&self, _clock: SharedClock) -> StaticSite {
        StaticSite::new(self.root.clone())
    }
}

/// The static site endpoint.
pub struct StaticSite {
    files: ServeDir,
}

impl StaticSite {
    /// Serves the files under `root`. Like Python's handler, the root is
    /// not checked at startup: a missing root answers 404.
    pub fn new(root: PathBuf) -> Self {
        Self {
            files: ServeDir::new(root)
                .append_index_html_on_directories(true)
                .redirect_to_trailing_slash(true)
                // Python ignores `Range`; of the ranges ServeDir serves, a
                // multi-range request gets the whole file, as from Python.
                .ignore_multi_range_requests(true),
        }
    }

    async fn serve(&self, request: &Request) -> HttpResponse {
        // `BaseHTTPRequestHandler.parse_request` collapses a leading run of
        // `/` (gh-87389); `translate_path` drops query and fragment.
        let target = server::python_path(&request.target);
        if !target.starts_with('/') {
            return file_not_found();
        }
        let Ok(uri) = target.parse::<Uri>() else {
            return file_not_found();
        };
        let mut headers = request.headers.clone();
        // Python evaluates `If-Modified-Since` only, and not when an
        // `If-None-Match` is present.
        headers.remove(header::IF_MATCH);
        headers.remove(header::IF_UNMODIFIED_SINCE);
        if headers.remove(header::IF_NONE_MATCH).is_some() {
            headers.remove(header::IF_MODIFIED_SINCE);
        }
        let mut file_request = hyper::Request::new(Empty::<Bytes>::new());
        *file_request.method_mut() = request.method.clone();
        *file_request.uri_mut() = uri;
        *file_request.headers_mut() = headers;
        match self.files.clone().try_call(file_request).await {
            Ok(response) => match response.status() {
                StatusCode::TEMPORARY_REDIRECT => moved_permanently(&target),
                StatusCode::NOT_FOUND => file_not_found(),
                status => {
                    let mut response = response.map(BodyExt::boxed_unsync);
                    let headers = response.headers_mut();
                    headers.remove(header::ETAG);
                    if status == StatusCode::NOT_MODIFIED {
                        // Python's 304 is `send_response(304)` and the
                        // `end_headers` additions only.
                        headers.remove(header::LAST_MODIFIED);
                    }
                    response
                }
            },
            Err(error) => {
                if !is_not_found(&error) {
                    // Python answers every `OSError` of `open()` with 404.
                    server::log_line(&format!(
                        "metrics-httpd static: cannot open {target:?}: {error}"
                    ));
                }
                file_not_found()
            }
        }
    }
}

impl Service for StaticSite {
    async fn call(&self, request: Request) -> HttpResponse {
        let mut response = if request.method == Method::GET || request.method == Method::HEAD {
            self.serve(&request).await
        } else {
            server::not_implemented(&request.method)
        };
        let headers = response.headers_mut();
        for (name, value) in SITE_HEADERS {
            headers.insert(name, HeaderValue::from_static(value));
        }
        response
    }
}

/// The errors `ServeDir`'s own `call` turns into 404.
fn is_not_found(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::NotADirectory
    )
}

/// `send_error(HTTPStatus.NOT_FOUND, "File not found")`.
fn file_not_found() -> HttpResponse {
    server::send_error(
        StatusCode::NOT_FOUND,
        "File not found",
        "Nothing matches the given URI",
    )
}

/// `send_head`'s redirect of a directory without trailing `/`: 301,
/// `Location` = the request's path + `/` and its query (`urlunsplit`
/// leaves out an empty query), `Content-Length: 0`.
fn moved_permanently(target: &str) -> HttpResponse {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let location = if query.is_empty() {
        format!("{path}/")
    } else {
        format!("{path}/?{query}")
    };
    let mut response = HttpResponse::new(server::full_body(Bytes::new()));
    *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
    // Explicit, so a HEAD answer carries it too.
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    // The target came from hyper's request line: valid header text.
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_location_follows_urlunsplit() {
        let location = |target: &str| {
            moved_permanently(target)
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(location("/sub"), "/sub/");
        assert_eq!(location("/sub?x=1"), "/sub/?x=1");
        assert_eq!(location("/sub?"), "/sub/");
        assert_eq!(location("/a%20b?q=a?b"), "/a%20b/?q=a?b");
        assert_eq!(
            moved_permanently("/sub").status(),
            StatusCode::MOVED_PERMANENTLY
        );
    }

    #[test]
    fn missing_files_are_not_found() {
        assert!(is_not_found(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(is_not_found(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(is_not_found(&io::Error::from_raw_os_error(20)));
        assert!(!is_not_found(&io::Error::other("EIO")));
    }
}
