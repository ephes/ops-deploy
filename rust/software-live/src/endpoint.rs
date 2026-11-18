//! The `Endpoint` boundary of PLAN.md 5.4: what an authenticated JSON
//! endpoint of the fleet needs regardless of what it serves — the bind
//! check, Basic authentication against the role's htpasswd file, and the
//! HTTP/1.1 server (hyper 1 on a current-thread tokio runtime). The
//! software-live handler (`serve.rs`) decides the order of the checks, the
//! bodies and the observation; this module knows nothing of it, so moving it
//! into a shared crate later is mechanical.
//!
//! Server behaviour (PLAN.md 3.4, 4.2 item 2): one request per connection
//! (`Connection: close`); the request head must arrive within
//! [`HEAD_TIMEOUT`] of the accept (Python sets a 5-second socket timeout per
//! read or write); the handler runs on tokio's blocking pool, so a slow
//! password check never holds up another connection, and the password check
//! gives up after [`VERIFY_BUDGET`] (Python's `htpasswd` timeout; the request
//! is then a 401); no connection lives longer than [`CONNECTION_LIMIT`]. At
//! most [`MAX_CONNECTIONS`] connections are served at a time (Python serves
//! one at a time), request heads up to [`MAX_HEAD_BYTES`] and [`MAX_HEADERS`]
//! header lines; every response is JSON with `Content-Type`,
//! `Content-Length` and `Cache-Control: no-store`. Malformed requests get
//! hyper's 400 (431 for an oversized head or too many headers). The
//! request-target is taken from the request line as sent, as Python's
//! `self.path` is (hyper's `Uri` drops a `#fragment`). Nothing is logged: no
//! request line, path, header or credential ever reaches the journal.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error::PyError;
use crate::htpasswd;
use crate::pyjson;

/// The request head must have arrived this long after the accept.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// A password check stops after this long and fails (Python runs
/// `htpasswd` with `timeout=5`).
pub const VERIFY_BUDGET: Duration = Duration::from_secs(5);
/// No connection lives longer than this from the accept: the head, the
/// handler with its password check and the response together.
pub const CONNECTION_LIMIT: Duration = Duration::from_secs(15);
/// Connections served at once; more wait in the listen queue.
pub const MAX_CONNECTIONS: usize = 16;
/// The largest request head (request line plus headers): a longer one is
/// a 431, whatever its lines (PLAN.md 4.2 item 2). hyper's own limit,
/// `max_buf_size`, is only checked after a read that left the head
/// incomplete, and a read may fill more than it, so [`RecordingStream`]
/// hands hyper no more than this many bytes before the head is parsed.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// The most header lines a request may have: Python's `http.client` refuses
/// a head of more than 100 lines counting the empty one that ends it
/// (431 "Too many headers"); hyper's default is 100.
pub const MAX_HEADERS: usize = 99;
/// `len(header) > 4096` is refused before decoding (`software_live.py:727`).
pub const MAX_AUTHORIZATION_BYTES: usize = 4096;

/// `ipaddress.ip_address(bind)` and the check of `software_live.py:911-915`:
/// IPv4 loopback (`127.0.0.0/8`) or Tailscale's `100.64.0.0/10`. The parser
/// is Rust's, which takes exactly Python's dotted quads (four decimal
/// octets, no leading zeros, ASCII digits, nothing around them).
pub fn check_bind(text: &str) -> Result<Ipv4Addr, PyError> {
    let not_allowed = || PyError::value("endpoint must bind IPv4 loopback or Tailscale");
    match text.parse::<Ipv4Addr>() {
        Ok(address) if bind_allowed(address) => Ok(address),
        Ok(_) => Err(not_allowed()),
        // A valid IPv6 address (with or without a scope) is version 6.
        Err(_) if is_ipv6(text) => Err(not_allowed()),
        Err(_) => Err(PyError::value(
            "bind does not appear to be an IPv4 or IPv6 address",
        )),
    }
}

/// `address.is_loopback or address in ip_network("100.64.0.0/10")`.
pub fn bind_allowed(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_loopback() || (first == 100 && (64..128).contains(&second))
}

fn is_ipv6(text: &str) -> bool {
    let address = text.split_once('%').map_or(text, |(address, _)| address);
    address.parse::<Ipv6Addr>().is_ok()
}

/// Checks a user name and password, e.g. against an htpasswd file; a check
/// that is still running at `deadline` fails.
pub trait Verifier {
    fn verify(&self, user: &str, password: &str, deadline: Instant) -> bool;
}

/// `htpasswd -vi <file> <user>` with the password on stdin
/// ([`crate::htpasswd`]); the file is read on every check, so a changed
/// password applies without a restart, as with the Python endpoint.
#[derive(Clone, Debug)]
pub struct HtpasswdFile(pub PathBuf);

impl Verifier for HtpasswdFile {
    fn verify(&self, user: &str, password: &str, deadline: Instant) -> bool {
        std::fs::read(&self.0).is_ok_and(|contents| {
            htpasswd::verify(&contents, user.as_bytes(), password.as_bytes(), deadline)
        })
    }
}

/// `b64decode(…, validate=True)`: the standard alphabet only, canonical
/// padding; non-zero trailing bits are accepted, as `binascii` does.
const STRICT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Basic authentication as `software_live.py:724-739` does it: the header
/// starts with `Basic ` and has at most 4096 bytes; the rest is strict
/// base64 of UTF-8 `user:password` (split at the first `:`); the user must
/// be the configured one and the password must not contain `\n`; then the
/// verifier decides within [`VERIFY_BUDGET`].
pub struct BasicAuth<V> {
    pub user: String,
    pub verifier: V,
}

impl<V: Verifier> BasicAuth<V> {
    /// Whether the `Authorization` header value (absent: `""`) passes.
    pub fn check(&self, header: Option<&[u8]>) -> bool {
        let header = header.unwrap_or_default();
        let Some(token) = header.strip_prefix(b"Basic ") else {
            return false;
        };
        if header.len() > MAX_AUTHORIZATION_BYTES {
            return false;
        }
        let Ok(decoded) = STRICT_BASE64.decode(token) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((user, password)) = decoded.split_once(':') else {
            return false;
        };
        if user != self.user || password.contains('\n') {
            return false;
        }
        self.verifier
            .verify(user, password, Instant::now() + VERIFY_BUDGET)
    }
}

/// What a handler sees of a request; the body is never read.
pub struct Request<'a> {
    pub method: &'a Method,
    /// Python's `self.path`: the request-target as received, with a leading
    /// run of `/` collapsed to one (`parse_request`, Python 3.11 and later).
    pub path: &'a str,
    pub headers: &'a HeaderMap,
}

impl Request<'_> {
    /// The first value of a header, as Python's `headers.get(name)`.
    pub fn header(&self, name: header::HeaderName) -> Option<&[u8]> {
        self.headers.get(name).map(HeaderValue::as_bytes)
    }
}

/// The request-target of the request line at the start of `head`, decoded
/// as ISO-8859-1 like Python's request line. Empty lines before it are
/// skipped, as hyper skips them; hyper accepts only single spaces between
/// the parts of a request line it parses.
pub fn request_target(head: &[u8]) -> Option<String> {
    let start = head
        .iter()
        .position(|&byte| byte != b'\r' && byte != b'\n')?;
    let line = &head[start..];
    let line = &line[..line.iter().position(|&byte| byte == b'\n')?];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let target = line.split(|&byte| byte == b' ').nth(1)?;
    Some(target.iter().map(|&byte| char::from(byte)).collect())
}

/// [`Request::path`] of a request-target.
pub fn python_path(target: &str) -> String {
    if target.starts_with("//") {
        format!("/{}", target.trim_start_matches('/'))
    } else {
        target.to_owned()
    }
}

/// A JSON answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
    /// `WWW-Authenticate: Basic realm="<realm>"`.
    pub realm: Option<&'static str>,
}

impl Reply {
    pub fn new(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            body,
            realm: None,
        }
    }
}

/// The endpoint's request handler. It runs on tokio's blocking pool, one
/// call per request.
pub trait Handler: Send + Sync {
    fn handle(&self, request: &Request<'_>) -> Reply;
}

/// The HTTP response of a reply: the body as compact, sorted, ASCII-only
/// JSON (PLAN.md 4.2 item 3).
pub fn response(reply: &Reply) -> Response<Full<Bytes>> {
    let body = pyjson::dumps_compact(&reply.body);
    let mut response = Response::new(Full::new(Bytes::from(body.clone())));
    *response.status_mut() = reply.status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    if let Some(realm) = reply.realm
        && let Ok(value) = HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
    {
        headers.insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// Serves `handler` on `listener` until `shutdown` resolves (the binary
/// passes a future that never does). Runs a current-thread tokio runtime on
/// the calling thread; handlers run on its blocking pool.
pub fn serve<H: Handler + 'static>(
    listener: std::net::TcpListener,
    handler: H,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .max_blocking_threads(MAX_CONNECTIONS)
        .build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, accept_loop(listener, Arc::new(handler), shutdown))
}

async fn accept_loop<H: Handler + 'static>(
    listener: std::net::TcpListener,
    handler: Arc<H>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let open = Rc::new(Cell::new(0usize));
    let slot_freed = Rc::new(tokio::sync::Notify::new());
    tokio::pin!(shutdown);
    loop {
        while open.get() >= MAX_CONNECTIONS {
            tokio::select! {
                () = slot_freed.notified() => {}
                () = &mut shutdown => return Ok(()),
            }
        }
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => stream,
                Err(_) => {
                    // EMFILE and friends: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => return Ok(()),
        };
        open.set(open.get() + 1);
        let (handler, open, slot_freed) = (handler.clone(), open.clone(), slot_freed.clone());
        tokio::task::spawn_local(async move {
            // Errors and timeouts close the connection; nothing is reported
            // (no request logging).
            let _ = tokio::time::timeout(CONNECTION_LIMIT, connection(stream, handler)).await;
            open.set(open.get() - 1);
            slot_freed.notify_one();
        });
    }
}

/// A connection's stream that keeps a copy of the first bytes read, up to
/// the end of the request line (hyper's parsed `Uri` drops a `#fragment`,
/// Python's `self.path` keeps it), and hands hyper at most
/// [`MAX_HEAD_BYTES`] until the head is parsed: hyper refuses a head that
/// fills its read buffer of that size with 431, so a longer head is always
/// a 431 and never depends on how the bytes arrive.
struct RecordingStream {
    stream: TcpStream,
    head: Rc<RefCell<Vec<u8>>>,
    /// Set by the service once hyper has parsed the head.
    parsed: Rc<Cell<bool>>,
    delivered: usize,
    scratch: Vec<u8>,
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.parsed.get() {
            this.scratch = Vec::new();
            return Pin::new(&mut this.stream).poll_read(cx, buf);
        }
        let room = MAX_HEAD_BYTES
            .saturating_sub(this.delivered)
            .min(buf.remaining());
        if room == 0 {
            // Only after hyper consumed empty lines before the request line
            // and still has no complete head: close without an answer.
            return Poll::Ready(Err(io::Error::other("request head too large")));
        }
        this.scratch.resize(room, 0);
        let mut limited = ReadBuf::new(&mut this.scratch);
        let poll = Pin::new(&mut this.stream).poll_read(cx, &mut limited);
        if let Poll::Ready(Ok(())) = poll {
            let new = limited.filled();
            this.delivered += new.len();
            let mut head = this.head.borrow_mut();
            if request_target(&head).is_none() && head.len() < MAX_HEAD_BYTES {
                let room = MAX_HEAD_BYTES - head.len();
                head.extend_from_slice(&new[..new.len().min(room)]);
            }
            buf.put_slice(new);
        }
        poll
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

async fn connection<H: Handler + 'static>(stream: TcpStream, handler: Arc<H>) {
    let head = Rc::new(RefCell::new(Vec::new()));
    let recorded = head.clone();
    let parsed = Rc::new(Cell::new(false));
    let head_parsed = parsed.clone();
    let service = hyper::service::service_fn(move |request: hyper::Request<_>| {
        head_parsed.set(true);
        let (parts, _body) = request.into_parts();
        // hyper accepted the head, so the request line is complete; without
        // one, no path can match.
        let path = request_target(&recorded.borrow())
            .map(|target| python_path(&target))
            .unwrap_or_default();
        let handler = handler.clone();
        async move {
            let reply = tokio::task::spawn_blocking(move || {
                handler.handle(&Request {
                    method: &parts.method,
                    path: &path,
                    headers: &parts.headers,
                })
            })
            .await
            // A panicking handler closes the connection without an answer,
            // as an exception in Python's handler does.
            .map_err(io::Error::other)?;
            Ok::<_, io::Error>(response(&reply))
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD_TIMEOUT)
        .keep_alive(false)
        .title_case_headers(true)
        .max_buf_size(MAX_HEAD_BYTES)
        .max_headers(MAX_HEADERS)
        .serve_connection(
            TokioIo::new(RecordingStream {
                stream,
                head,
                parsed,
                delivered: 0,
                scratch: Vec::new(),
            }),
            service,
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_follows_python() {
        for ok in [
            "127.0.0.1",
            "127.255.255.255",
            "127.0.0.0",
            "100.64.0.0",
            "100.100.1.2",
            "100.127.255.255",
        ] {
            assert_eq!(check_bind(ok).unwrap().to_string(), ok);
        }
        for refused in [
            "0.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "10.0.0.1",
            "::1",
        ] {
            assert_eq!(
                check_bind(refused).unwrap_err().message,
                "endpoint must bind IPv4 loopback or Tailscale",
                "{refused}"
            );
        }
        for invalid in ["127.0.0.01", "127.1", " 127.0.0.1", "127.0.0.1/8", "", "x"] {
            assert_eq!(check_bind(invalid).unwrap_err().class, "ValueError");
        }
    }

    struct Table(Vec<(&'static str, &'static str)>);

    impl Verifier for Table {
        fn verify(&self, user: &str, password: &str, _deadline: Instant) -> bool {
            self.0.contains(&(user, password))
        }
    }

    fn basic(text: &[u8]) -> Vec<u8> {
        [
            b"Basic ".as_slice(),
            base64::engine::general_purpose::STANDARD
                .encode(text)
                .as_bytes(),
        ]
        .concat()
    }

    #[test]
    fn basic_auth_follows_python() {
        let auth = BasicAuth {
            user: "u".into(),
            verifier: Table(vec![("u", "p:w"), ("u", ""), ("u", "p\r")]),
        };
        assert!(auth.check(Some(&basic(b"u:p:w"))));
        assert!(auth.check(Some(&basic(b"u:"))));
        assert!(auth.check(Some(&basic(b"u:p\r"))));
        assert!(!auth.check(Some(&basic(b"u:p\n"))));
        assert!(!auth.check(Some(&basic(b"v:p:w"))));
        assert!(!auth.check(Some(&basic(b"u"))));
        assert!(!auth.check(Some(&basic(b"u:\xff"))));
        assert!(!auth.check(None));
        assert!(!auth.check(Some(b"Basic")));
        assert!(!auth.check(Some(b"basic dTpw")));
        assert!(!auth.check(Some(b"Basic  dTpw")));
        assert!(!auth.check(Some(b"Basic dTpw ")));
        // "u:p:w" with non-zero trailing bits in the last character.
        assert!(auth.check(Some(b"Basic dTpwOnd=")));
        assert!(auth.check(Some(b"Basic dTpwOnc=")));
        assert!(!auth.check(Some(b"Basic dTpwOnc")));
        assert!(!auth.check(Some(b"Basic dTpwOnc==")));
        // The length limit counts the whole header.
        let long = basic(&[b"u:".as_slice(), &[b'x'; 3062]].concat());
        assert_eq!(long.len(), 4094);
        let longer = basic(&[b"u:".as_slice(), &[b'x'; 3065]].concat());
        assert_eq!(longer.len(), 4098);
        let calls = std::cell::RefCell::new(Vec::new());
        struct Recorder<'a>(&'a std::cell::RefCell<Vec<usize>>);
        impl Verifier for Recorder<'_> {
            fn verify(&self, _user: &str, password: &str, _deadline: Instant) -> bool {
                self.0.borrow_mut().push(password.len());
                false
            }
        }
        let recording = BasicAuth {
            user: "u".into(),
            verifier: Recorder(&calls),
        };
        assert!(!recording.check(Some(&long)));
        assert!(!recording.check(Some(&longer)));
        assert_eq!(*calls.borrow(), [3062]);
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    #[test]
    fn htpasswd_file_is_read_on_every_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("htpasswd");
        let verifier = HtpasswdFile(path.clone());
        assert!(!verifier.verify("u", "secret", far()), "missing file");
        let hash = bcrypt::hash_with_salt("secret", 4, [7; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoY);
        std::fs::write(&path, format!("u:{hash}\n")).unwrap();
        assert!(verifier.verify("u", "secret", far()));
        assert!(!verifier.verify("u", "other", far()));
        std::fs::write(&path, "u:$apr1$x$y\n").unwrap();
        assert!(!verifier.verify("u", "secret", far()));
    }

    #[test]
    fn the_request_target_is_read_from_the_request_line() {
        let target = |head: &[u8]| request_target(head);
        assert_eq!(
            target(b"GET /a#b HTTP/1.1\r\nHost: x\r\n\r\n").as_deref(),
            Some("/a#b")
        );
        assert_eq!(
            target(b"\r\n\r\nGET /a HTTP/1.1\r\n").as_deref(),
            Some("/a")
        );
        assert_eq!(target(b"GET /a HTTP/1.1\n").as_deref(), Some("/a"));
        assert_eq!(
            target(b"GET /\xe9 HTTP/1.1\r\n").as_deref(),
            Some("/\u{e9}")
        );
        assert_eq!(target(b"GET /a HTTP/1.1"), None, "incomplete");
        assert_eq!(target(b""), None);
    }

    #[test]
    fn leading_slashes_collapse_as_in_python() {
        assert_eq!(python_path("//a//b"), "/a//b");
        assert_eq!(python_path("///"), "/");
        assert_eq!(python_path("/a"), "/a");
        assert_eq!(python_path("*"), "*");
        assert_eq!(python_path("http://h/a"), "http://h/a");
    }

    #[test]
    fn responses_are_json_with_the_contract_headers() {
        let mut reply = Reply::new(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "unauthorized", "a": "é"}),
        );
        reply.realm = Some("software-live");
        let response = response(&reply);
        assert_eq!(response.status(), 401);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::CONNECTION], "close");
        assert_eq!(
            headers[header::WWW_AUTHENTICATE],
            "Basic realm=\"software-live\""
        );
        let body = br#"{"a":"\u00e9","error":"unauthorized"}"#;
        assert_eq!(headers[header::CONTENT_LENGTH], body.len().to_string());
        assert!(!headers.contains_key(header::SERVER));
    }
}
