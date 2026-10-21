//! The upstream HTTPS request of `upstream` and `lifecycle_upstream`
//! (`software_live.py:149-239`, PLAN.md 3.3 "Upstream lookups and caches"):
//! `urllib.request.urlopen(request, timeout=10)` followed by
//! `response.read(1024 * 1024)`.
//!
//! - ureq 3 over rustls with the ring provider, synchronous (the collector
//!   has no async runtime).
//! - Trust: the system store only (`rustls-native-certs`: `SSL_CERT_FILE` /
//!   `SSL_CERT_DIR`, else the distribution bundle under `/etc/ssl`), as
//!   Python's `urllib` with OpenSSL's default paths. No bundled roots, so
//!   the fleet's CA-trust changes apply to both implementations alike.
//! - No proxy (PLAN.md 4.1; ureq would read `*_proxy` from the environment
//!   by default), no compression, up to 10 redirects as `urllib`.
//! - The body is read up to the limit and then cut, as `read(n)` does: a
//!   longer body is not an error here, its JSON is just incomplete.
//! - Errors carry a Python class name (PLAN.md 4.2 item 5): an HTTP status
//!   of 400 or more and too many redirects `HTTPError`, any timeout
//!   `TimeoutError`, every other failure before the response head
//!   (resolution, connection, TLS, protocol) `URLError`, any other failure
//!   while reading the body `OSError`. The message is ureq's and is never
//!   reported (the observation reports only the class).

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};

use crate::error::PyError;

/// `timeout=10` of both `urlopen` calls.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// `response.read(1024 * 1024)`.
pub const BODY_LIMIT: u64 = 1024 * 1024;
/// `urllib` follows at most this many redirects (`HTTPRedirectHandler.max_redirections`).
pub const MAX_REDIRECTS: u32 = 10;

/// One GET request.
#[derive(Clone, Copy, Debug)]
pub struct HttpRequest<'a> {
    pub url: &'a str,
    /// Header names and values, in this order.
    pub headers: &'a [(&'a str, &'a str)],
    /// Applied to each phase: resolution, connection with the TLS
    /// handshake, sending the request, the response head and the body
    /// (`urllib`'s timeout applies to each blocking socket operation).
    pub timeout: Duration,
    /// The body is cut after this many bytes.
    pub limit: u64,
}

/// An HTTPS client with a fixed set of trust roots.
#[derive(Debug)]
pub struct HttpClient {
    agent: Agent,
}

impl HttpClient {
    /// A client that trusts exactly `roots`.
    pub fn with_roots(roots: Vec<CertificateDer<'static>>) -> Self {
        let roots: Vec<Certificate<'static>> = roots
            .iter()
            .map(|der| Certificate::from_der(der.as_ref()).to_owned())
            .collect();
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::Specific(Arc::new(roots)))
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let config = Agent::config_builder()
            .tls_config(tls)
            .proxy(None)
            .http_status_as_error(true)
            .max_redirects(MAX_REDIRECTS)
            .build();
        Self {
            agent: Agent::new_with_config(config),
        }
    }

    /// A client that trusts the system store. Fails (`URLError`, as
    /// Python's certificate verification would) when the store has no
    /// usable certificate.
    pub fn system() -> Result<Self, PyError> {
        let loaded = rustls_native_certs::load_native_certs();
        if loaded.certs.is_empty() {
            let detail = loaded
                .errors
                .first()
                .map_or_else(|| "no certificates".to_owned(), ToString::to_string);
            return Err(PyError::new(
                "URLError",
                format!("no system trust roots: {detail}"),
            ));
        }
        Ok(Self::with_roots(loaded.certs))
    }

    /// GET `request.url` and return at most `request.limit` bytes of the
    /// body.
    pub fn get(&self, request: &HttpRequest<'_>) -> Result<Vec<u8>, PyError> {
        let timeout = Some(request.timeout);
        let mut builder = self
            .agent
            .get(request.url)
            .config()
            .timeout_resolve(timeout)
            .timeout_connect(timeout)
            .timeout_send_request(timeout)
            .timeout_recv_response(timeout)
            .timeout_recv_body(timeout)
            .build();
        for (name, value) in request.headers {
            builder = builder.header(*name, *value);
        }
        let response = builder.call().map_err(|error| request_error(&error))?;
        let mut body = Vec::new();
        response
            .into_body()
            .into_reader()
            .take(request.limit)
            .read_to_end(&mut body)
            .map_err(|error| body_error(ureq::Error::from(error)))?;
        Ok(body)
    }
}

fn is_timeout(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Timeout(_) => true,
        ureq::Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        _ => false,
    }
}

/// The class of a failure before the response head was read.
fn request_error(error: &ureq::Error) -> PyError {
    let class = match error {
        _ if is_timeout(error) => "TimeoutError",
        ureq::Error::StatusCode(_) | ureq::Error::TooManyRedirects => "HTTPError",
        _ => "URLError",
    };
    PyError::new(class, error.to_string())
}

/// The class of a failure while reading the body.
fn body_error(error: ureq::Error) -> PyError {
    if is_timeout(&error) {
        return PyError::new("TimeoutError", error.to_string());
    }
    match error {
        ureq::Error::Io(io) => PyError::os(&io),
        other => PyError::new("OSError", other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::https::{Reply, TestServer};

    fn request(url: &str) -> HttpRequest<'_> {
        HttpRequest {
            url,
            headers: &[
                ("User-Agent", "ops-library-software-live/1"),
                ("Accept", "application/vnd.github+json"),
            ],
            timeout: Duration::from_secs(5),
            limit: BODY_LIMIT,
        }
    }

    #[test]
    fn a_trusted_server_answers_with_the_requested_headers() {
        let server = TestServer::start(vec![Reply::ok(b"{\"tag_name\":\"v3.7.12\"}")]);
        let client = HttpClient::with_roots(vec![server.root()]);
        let body = client.get(&request(&server.url("/repos/x"))).unwrap();
        assert_eq!(body, b"{\"tag_name\":\"v3.7.12\"}");
        let seen = server.requests();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].starts_with("GET /repos/x HTTP/1.1\r\n"),
            "{}",
            seen[0]
        );
        let lower = seen[0].to_ascii_lowercase();
        assert!(
            lower.contains("\r\nuser-agent: ops-library-software-live/1\r\n"),
            "{lower}"
        );
        assert!(
            lower.contains("\r\naccept: application/vnd.github+json\r\n"),
            "{lower}"
        );
        // No compression is offered: the body limit counts plain bytes.
        assert!(!lower.contains("accept-encoding: gzip"), "{lower}");
    }

    #[test]
    fn status_errors_are_http_errors() {
        for status in [404, 500, 503] {
            let server = TestServer::start(vec![Reply::status(status)]);
            let client = HttpClient::with_roots(vec![server.root()]);
            let error = client.get(&request(&server.url("/"))).unwrap_err();
            assert_eq!(error.class, "HTTPError", "{status}: {error}");
        }
    }

    #[test]
    fn redirects_are_followed() {
        let server = TestServer::start(vec![Reply::redirect("/final"), Reply::ok(b"[1]")]);
        let client = HttpClient::with_roots(vec![server.root()]);
        assert_eq!(client.get(&request(&server.url("/start"))).unwrap(), b"[1]");
        let seen = server.requests();
        assert!(seen[1].starts_with("GET /final "), "{}", seen[1]);
    }

    #[test]
    fn a_long_body_is_cut_at_the_limit() {
        let mut long = b"[\"".to_vec();
        long.extend(std::iter::repeat_n(b'a', 2 * BODY_LIMIT as usize));
        long.extend(b"\"]");
        let server = TestServer::start(vec![Reply::ok(&long)]);
        let client = HttpClient::with_roots(vec![server.root()]);
        let body = client.get(&request(&server.url("/"))).unwrap();
        assert_eq!(body.len() as u64, BODY_LIMIT);
        assert_eq!(&body[..], &long[..BODY_LIMIT as usize]);
    }

    #[test]
    fn an_untrusted_certificate_is_refused() {
        let server = TestServer::start(vec![Reply::ok(b"[]")]);
        // Another server's root does not vouch for this one.
        let other = TestServer::start(vec![]);
        let client = HttpClient::with_roots(vec![other.root()]);
        let error = client.get(&request(&server.url("/"))).unwrap_err();
        assert_eq!(error.class, "URLError", "{error}");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn the_system_store_does_not_trust_a_self_signed_test_server() {
        let server = TestServer::start(vec![Reply::ok(b"[]")]);
        let client = HttpClient::system().expect("the test host has a system trust store");
        let error = client.get(&request(&server.url("/"))).unwrap_err();
        assert_eq!(error.class, "URLError", "{error}");
    }

    #[test]
    fn a_refused_connection_is_a_url_error() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let client = HttpClient::with_roots(Vec::new());
        let url = format!("https://127.0.0.1:{port}/");
        assert_eq!(client.get(&request(&url)).unwrap_err().class, "URLError");
    }

    #[test]
    fn a_silent_server_times_out() {
        // Accepts the connection but never answers the TLS handshake.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}/", listener.local_addr().unwrap());
        let client = HttpClient::with_roots(Vec::new());
        let started = std::time::Instant::now();
        let mut slow = request(&url);
        slow.timeout = Duration::from_millis(300);
        assert_eq!(client.get(&slow).unwrap_err().class, "TimeoutError");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
    }

    #[test]
    fn proxy_variables_are_ignored() {
        // The agent is built with `proxy(None)`; a proxy from the
        // environment would make this request fail.
        let client = HttpClient::with_roots(Vec::new());
        assert!(client.agent.config().proxy().is_none());
    }
}
