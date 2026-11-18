//! Helpers shared by the fixture tests (`fixtures/*.json`, written by
//! `fixtures/generate.py` from the Python oracle).

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::error::PyError;
use crate::probe::fake::{FakeSystem, World};
use crate::probe::{FileStat, Identity};
use crate::report::{ERROR_LIMIT, Observation};

/// A Python exception as a fixture records it: the class always; the
/// message only where the Python code raises it itself (`own`), since the
/// interpreter's texts differ between Python versions and are not part of
/// the contract (PLAN.md 4.2 item 5).
#[derive(Clone, Debug, Deserialize)]
pub struct ErrorSpec {
    pub class: String,
    #[serde(default)]
    pub message: Option<String>,
}

impl ErrorSpec {
    pub fn assert_matches(&self, error: &PyError, id: &str) {
        assert_eq!(error.class, self.class, "{id}: {error}");
        if let Some(message) = &self.message {
            assert_eq!(&error.message, message, "{id}");
        }
    }
}

/// `#[serde(default, deserialize_with = "present")]`: a field that is
/// present is `Some`, also when it is `null` (a result of `None`).
pub fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// JSON equality where numbers compare by value: integers by their
/// canonical text, other numbers as `f64` (Python and Rust may spell the
/// same float differently, PLAN.md 4.2 item 3).
pub fn json_eq(left: &Value, right: &Value) -> bool {
    use crate::pyjson::{canonical_int, is_int_token, token_f64};
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            let (a, b) = (a.as_str(), b.as_str());
            match (is_int_token(a), is_int_token(b)) {
                (true, true) => canonical_int(a) == canonical_int(b),
                (false, false) => token_f64(a).to_bits() == token_f64(b).to_bits(),
                _ => false,
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| json_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((ka, va), (kb, vb))| ka == kb && json_eq(va, vb))
        }
        _ => left == right,
    }
}

/// A local HTTPS server for the upstream tests: a self-signed certificate
/// for `127.0.0.1` (trusted only by a client built with [`TestServer::root`]),
/// one canned reply per connection, every request head recorded.
pub mod https {
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    /// One answer: status line, extra headers and body.
    #[derive(Clone, Debug)]
    pub struct Reply {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
        /// Instead of the above: these bytes as they are, one part at a
        /// time with `pause` between them, then the connection is closed.
        pub raw: Option<(Vec<Vec<u8>>, std::time::Duration)>,
    }

    impl Reply {
        pub fn ok(body: &[u8]) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body: body.to_vec(),
                raw: None,
            }
        }

        pub fn status(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: b"{\"message\": \"error\"}".to_vec(),
                raw: None,
            }
        }

        pub fn redirect(location: &str) -> Self {
            Self {
                status: 302,
                headers: vec![("Location".into(), location.into())],
                body: Vec::new(),
                raw: None,
            }
        }

        /// A raw response written in parts, `pause` apart.
        pub fn raw(parts: &[&[u8]], pause: std::time::Duration) -> Self {
            Self {
                raw: Some((parts.iter().map(|part| part.to_vec()).collect(), pause)),
                ..Self::ok(b"")
            }
        }
    }

    pub struct TestServer {
        port: u16,
        root: CertificateDer<'static>,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl TestServer {
        /// Serve `replies` in order, one per connection (then 500s).
        pub fn start(replies: Vec<Reply>) -> Self {
            let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
                .expect("a test certificate");
            let root = certified.cert.der().clone();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.signing_key.serialize_der(),
            ));
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![root.clone()], key)
            .expect("a server certificate");
            let config = Arc::new(config);
            let listener = TcpListener::bind("127.0.0.1:0").expect("a local port");
            let port = listener.local_addr().expect("a local address").port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&requests);
            let mut replies: VecDeque<Reply> = replies.into();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let reply = replies.pop_front().unwrap_or_else(|| Reply::status(500));
                    serve(&config, stream, &reply, &seen);
                }
            });
            Self {
                port,
                root,
                requests,
            }
        }

        pub fn url(&self, path: &str) -> String {
            format!("https://127.0.0.1:{}{path}", self.port)
        }

        pub fn root(&self) -> CertificateDer<'static> {
            self.root.clone()
        }

        /// The request heads received so far.
        pub fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("not poisoned").clone()
        }
    }

    fn serve(
        config: &Arc<ServerConfig>,
        stream: TcpStream,
        reply: &Reply,
        seen: &Mutex<Vec<String>>,
    ) {
        let Ok(connection) = ServerConnection::new(Arc::clone(config)) else {
            return;
        };
        let mut tls = StreamOwned::new(connection, stream);
        let mut head = Vec::new();
        let mut buffer = [0u8; 4096];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&buffer[..n]),
            }
        }
        seen.lock()
            .expect("not poisoned")
            .push(String::from_utf8_lossy(&head).into_owned());
        if let Some((parts, pause)) = &reply.raw {
            for (index, part) in parts.iter().enumerate() {
                if index > 0 {
                    thread::sleep(*pause);
                }
                if tls.write_all(part).and_then(|()| tls.flush()).is_err() {
                    return;
                }
            }
            tls.conn.send_close_notify();
            let _ = tls.flush();
            return;
        }
        let mut out = format!(
            "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
            reply.status,
            reply.body.len()
        )
        .into_bytes();
        for (name, value) in &reply.headers {
            out.extend(format!("{name}: {value}\r\n").into_bytes());
        }
        out.extend(b"\r\n");
        out.extend(&reply.body);
        let _ = tls.write_all(&out);
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
}

/// A step's outcome against the fixture: its JSON result or its exception.
pub fn assert_outcome(
    actual: Result<Value, PyError>,
    result: Option<&Value>,
    error: Option<&ErrorSpec>,
    id: &str,
) {
    match (result, error) {
        (Some(expected), None) => {
            let actual = actual.unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!(json_eq(&actual, expected), "{id}: {actual} != {expected}");
        }
        (None, Some(expected)) => match actual {
            Ok(value) => panic!("{id}: expected {expected:?}, got {value}"),
            Err(error) => expected.assert_matches(&error, id),
        },
        _ => panic!("{id}: fixture needs a result or an error"),
    }
}

/// An observation against the fixture: every field but `error` equal, and
/// `error` of the recorded class, with the recorded text where the message
/// is part of the contract (PLAN.md 4.2 item 5).
pub fn assert_observation(
    actual: &Observation,
    result: &Value,
    error: Option<&ErrorSpec>,
    id: &str,
) {
    let mut fields = actual.as_map().clone();
    let text = fields.remove("error");
    let fields = Value::Object(fields);
    assert!(json_eq(&fields, result), "{id}: {fields} != {result}");
    match (error, text) {
        (None, None) => {}
        (Some(expected), Some(Value::String(text))) => {
            let prefix = format!("{}: ", expected.class);
            assert!(
                text.starts_with(&prefix),
                "{id}: {text:?} is not a {}",
                expected.class
            );
            if let Some(message) = &expected.message {
                let full: String = format!("{prefix}{message}")
                    .chars()
                    .take(ERROR_LIMIT)
                    .collect();
                assert_eq!(text, full, "{id}");
            }
        }
        (expected, text) => panic!("{id}: error {text:?}, expected {expected:?}"),
    }
}

/// The world was asked exactly what Python asked, in the same order, and
/// every expected command ran.
pub fn assert_calls(fake: &FakeSystem, expected: &[String], id: &str) {
    assert_eq!(&*fake.calls.borrow(), expected, "{id}: calls");
    assert_eq!(fake.pending_commands(), 0, "{id}: commands never run");
}

/// Python's calls without the `sha256 <fd>` of a running image that was
/// opened with the identity the installed file had when it was hashed:
/// Rust gives that image the installed file's digest instead of reading
/// it again (PLAN.md 4.2 item 15). The identities come from the world:
/// the `n`-th `open` of a path takes the `n`-th answer (the last one
/// repeats), and the first `fstat` answer of an open is the identity
/// `binary_info` checks before hashing.
pub fn without_reused_hashes(python: &[String], world: &World, binary_path: &str) -> Vec<String> {
    let mut opened: HashMap<&str, usize> = HashMap::new();
    let mut descriptors: HashMap<String, (&str, Option<Identity>)> = HashMap::new();
    let mut installed = None;
    let mut expected = Vec::new();
    for call in python {
        if let Some(path) = call.strip_prefix("open ")
            && let Some(answers) = world.open.get(path)
        {
            let count = opened.entry(path).or_default();
            let answer = &answers[(*count).min(answers.len() - 1)];
            *count += 1;
            if let Ok(spec) = answer.get() {
                let identity = spec
                    .fstat
                    .first()
                    .and_then(|stat| stat.get().ok())
                    .map(|stat| FileStat::from(stat).identity());
                descriptors.insert(spec.fd.to_string(), (path, identity));
            }
        } else if let Some(fd) = call.strip_prefix("sha256 ") {
            let (path, identity) = descriptors[fd];
            if path == binary_path {
                installed = identity;
            } else if identity.is_some() && identity == installed {
                continue;
            }
        }
        expected.push(call.clone());
    }
    expected
}
