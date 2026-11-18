//! The HTTP/1.1 server core shared by every mode (PLAN.md 4.1, 4.8, D-1,
//! D-7, D-9, D-10): bind (IPv4 and IPv6, `SO_REUSEADDR`), header-read and
//! keep-alive timeouts, at most [`MAX_CONNECTIONS`] connections, graceful
//! SIGTERM/SIGINT, the access log, and the 501/404/401 responses of
//! Python's `BaseHTTPRequestHandler`.

use std::convert::Infallible;
use std::future::Future;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Local};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Response, StatusCode, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Semaphore;

use crate::clock::SharedClock;
use crate::pyjson;

/// D-1: connections served at once; more wait in the accept queue.
pub const MAX_CONNECTIONS: usize = 64;
/// PLAN.md 4.8: in-flight requests get this long after SIGTERM.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const LISTEN_BACKLOG: u32 = 128;

/// The body of every response: a buffered body (every mode's answers) or
/// a file streamed in chunks (`static`, `tower-http`'s `ServeDir`).
pub type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

/// The response type of every handler.
pub type HttpResponse = Response<ResponseBody>;

/// A buffered response body.
pub fn full_body(body: impl Into<Bytes>) -> ResponseBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// What a handler sees of a request (the body is never read).
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    /// The request-target as received (`/path?query`, or the absolute form).
    pub target: String,
    pub version: Version,
    pub headers: HeaderMap,
    pub peer: SocketAddr,
}

impl Request {
    /// Python's `self.path`: the request-target, with a leading run of `/`
    /// collapsed to one (`BaseHTTPRequestHandler.parse_request`, CPython
    /// ≥ 3.11, gh-87389).
    pub fn python_path(&self) -> String {
        python_path(&self.target)
    }

    /// `urlsplit(self.path).path`: the path without query and fragment
    /// (tailscale's path-only match).
    pub fn path_only(&self) -> String {
        path_only(&self.target)
    }

    /// The request line as Python logs it (`"GET /path HTTP/1.1"`).
    pub fn request_line(&self) -> String {
        format!("{} {} {:?}", self.method, self.target, self.version)
    }
}

/// [`Request::python_path`] of a request-target.
pub fn python_path(target: &str) -> String {
    if target.starts_with("//") {
        format!("/{}", target.trim_start_matches('/'))
    } else {
        target.to_owned()
    }
}

/// [`Request::path_only`] of a request-target.
pub fn path_only(target: &str) -> String {
    let path = python_path(target);
    let mut rest = path.as_str();
    // urlsplit: a scheme (`letter (letter|digit|+|-|.)* ":"`), then an
    // authority after `//`.
    if let Some((scheme, after)) = rest.split_once(':')
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        rest = after;
    }
    if let Some(after) = rest.strip_prefix("//") {
        rest = after
            .find(['/', '?', '#'])
            .map_or("", |index| &after[index..]);
    }
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// A mode's request handler.
pub trait Service: Send + Sync + 'static {
    fn call(&self, request: Request) -> impl Future<Output = HttpResponse> + Send;
}

/// Where the access line of each request goes (PLAN.md 4.1.6, 4.6, 4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLog {
    /// `<client> - - [<local time>] "<request line>" <status> -` on stderr.
    Stderr,
    /// `<client> - "<request line>" <status> -` on stdout (static).
    Stdout,
    /// logyard-health: nothing per request (Logyard ingests the journal).
    Silent,
}

/// Per-process server settings.
#[derive(Clone)]
pub struct ServerConfig {
    /// D-1: header-read timeout and keep-alive idle timeout.
    pub request_timeout: Duration,
    pub access_log: AccessLog,
    /// D-7: `Server: <server-name> metrics-httpd/<version>`.
    pub server_header: HeaderValue,
    pub clock: SharedClock,
}

/// The `Server` header value of D-7.
pub fn server_header(server_name: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{server_name} metrics-httpd/{}",
        env!("CARGO_PKG_VERSION")
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("metrics-httpd"))
}

/// Binds a listening socket with `SO_REUSEADDR` (Python's
/// `allow_reuse_address`), IPv4 or IPv6 by the address (D-10).
pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = match addr.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Serves `service` on `listener` until `shutdown` resolves, then stops
/// accepting and gives open connections [`SHUTDOWN_GRACE`] to finish.
pub async fn run<S: Service>(
    listener: TcpListener,
    config: ServerConfig,
    service: Arc<S>,
    shutdown: impl Future<Output = ()>,
) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let graceful = GracefulShutdown::new();
    let config = Arc::new(config);
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(config.request_timeout)
        .keep_alive(true)
        .title_case_headers(true);
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            permit = limit.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // EMFILE and friends: back off instead of spinning.
                    log_line(&format!("metrics-httpd: accept failed: {error}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let config = config.clone();
        let service = service.clone();
        let handler = hyper::service::service_fn(move |request: hyper::Request<_>| {
            let config = config.clone();
            let service = service.clone();
            async move { Ok::<_, Infallible>(handle(&config, service.as_ref(), request, peer).await) }
        });
        let connection = builder.serve_connection(TokioIo::new(stream), handler);
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            // Client errors and timeouts close the connection; nothing to report.
            let _ = connection.await;
            drop(permit);
        });
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(SHUTDOWN_GRACE) => {}
    }
}

async fn handle<S: Service, B>(
    config: &ServerConfig,
    service: &S,
    request: hyper::Request<B>,
    peer: SocketAddr,
) -> HttpResponse {
    let (parts, _body) = request.into_parts();
    let request = Request {
        method: parts.method,
        target: parts.uri.to_string(),
        version: parts.version,
        headers: parts.headers,
        peer,
    };
    let line = (config.access_log != AccessLog::Silent).then(|| request.request_line());
    let mut response = service.call(request).await;
    response
        .headers_mut()
        .entry(header::SERVER)
        .or_insert_with(|| config.server_header.clone());
    if let Some(line) = line {
        let client = peer.ip();
        let status = response.status().as_u16();
        match config.access_log {
            AccessLog::Stderr => {
                let time: DateTime<Local> = config.clock.now().into();
                log_line(&access_line(client, &time, &line, status));
            }
            AccessLog::Stdout => {
                let mut out = io::stdout().lock();
                let _ = writeln!(out, "{client} - \"{}\" {status} -", escape_control(&line));
                let _ = out.flush();
            }
            AccessLog::Silent => {}
        }
    }
    response
}

/// One access line of PLAN.md 4.1.6.
pub fn access_line(
    client: IpAddr,
    time: &DateTime<Local>,
    request_line: &str,
    status: u16,
) -> String {
    format!(
        "{client} - - [{}] \"{}\" {status} -",
        time.format("%d/%b/%Y %H:%M:%S"),
        escape_control(request_line)
    )
}

/// Control characters as `\xNN`, so a request cannot forge log lines.
fn escape_control(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            out.push_str(&format!("\\x{:02x}", u32::from(ch)));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Writes one line to stderr (the journal), ignoring a closed stderr.
pub fn log_line(line: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{line}");
}

fn response(status: StatusCode, content_type: Option<&'static str>, body: Vec<u8>) -> HttpResponse {
    let mut response = Response::new(full_body(body));
    *response.status_mut() = status;
    if let Some(content_type) = content_type {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    response
}

/// `_send_json_error`: `{"error": true, "error_type": …, "message": …}`.
pub fn json_error(status: StatusCode, error_type: &str, message: &str) -> HttpResponse {
    let body = serde_json::json!({
        "error": true,
        "error_type": error_type,
        "message": message,
    });
    json_response(status, pyjson::dumps(&body))
}

/// A JSON body with `Content-Type: application/json`.
pub fn json_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    response(status, Some("application/json"), body)
}

/// The 401 of PLAN.md 4.1.3: `WWW-Authenticate: Basic realm="<realm>"`,
/// `Content-Length: 0`, keep-alive.
pub fn unauthorized(realm: &str) -> HttpResponse {
    let mut response = response(StatusCode::UNAUTHORIZED, None, Vec::new());
    if let Ok(value) = HeaderValue::from_str(&format!("Basic realm=\"{realm}\"")) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// `BaseHTTPRequestHandler.send_error`: Python's HTML error page and
/// `Connection: close`.
pub fn send_error(status: StatusCode, message: &str, explain: &str) -> HttpResponse {
    let code = status.as_u16();
    let body = format!(
        "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        \
         <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        \
         <p>Error code: {code}</p>\n        <p>Message: {}.</p>\n        \
         <p>Error code explanation: {code} - {explain}.</p>\n    </body>\n</html>\n",
        html_escape(message)
    );
    let mut response = response(status, Some("text/html;charset=utf-8"), body.into_bytes());
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// The 501 Python's dispatcher sends for a method without a `do_<METHOD>`.
pub fn not_implemented(method: &Method) -> HttpResponse {
    send_error(
        StatusCode::NOT_IMPLEMENTED,
        &format!("Unsupported method ({})", py_repr(method.as_str())),
        "Server does not support this operation",
    )
}

/// `send_error(404, "Not found")` (metrics_endpoint).
pub fn not_found_html() -> HttpResponse {
    send_error(
        StatusCode::NOT_FOUND,
        "Not found",
        "Nothing matches the given URI",
    )
}

/// `html.escape(text, quote=False)`.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `repr()` of a str of printable ASCII (an HTTP method token).
fn py_repr(text: &str) -> String {
    if text.contains('\'') && !text.contains('"') {
        format!("\"{text}\"")
    } else {
        format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

/// Resolves when SIGTERM or SIGINT arrives.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        // Without signal handlers the default action (termination) applies.
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn python_path_rules() {
        assert_eq!(python_path("/a//b"), "/a//b");
        assert_eq!(python_path("//a"), "/a");
        assert_eq!(python_path("///a?x"), "/a?x");
        assert_eq!(path_only("/a?b#c"), "/a");
        assert_eq!(path_only("/a#c?d"), "/a");
        assert_eq!(
            path_only("//.well-known/tailscale?x"),
            "/.well-known/tailscale"
        );
        assert_eq!(
            path_only("http://host:9107/.well-known/tailscale?q"),
            "/.well-known/tailscale"
        );
        assert_eq!(path_only("http://host"), "");
        assert_eq!(path_only("/a:b/c"), "/a:b/c");
        assert_eq!(path_only("*"), "*");
    }

    #[test]
    fn access_line_format() {
        let time = Local.with_ymd_and_hms(2026, 10, 1, 9, 5, 7).unwrap();
        assert_eq!(
            access_line("127.0.0.1".parse().unwrap(), &time, "GET /x HTTP/1.1", 401),
            "127.0.0.1 - - [01/Oct/2026 09:05:07] \"GET /x HTTP/1.1\" 401 -"
        );
        assert_eq!(
            access_line(
                "::1".parse().unwrap(),
                &time,
                "GET /\u{1b}[1m HTTP/1.1",
                404
            ),
            "::1 - - [01/Oct/2026 09:05:07] \"GET /\\x1b[1m HTTP/1.1\" 404 -"
        );
    }

    #[test]
    fn python_reprs() {
        assert_eq!(py_repr("POST"), "'POST'");
        assert_eq!(py_repr("A'B"), "\"A'B\"");
        assert_eq!(html_escape("a&<b>"), "a&amp;&lt;b&gt;");
    }
}
