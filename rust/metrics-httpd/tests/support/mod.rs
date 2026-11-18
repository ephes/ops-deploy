//! Shared helpers of the integration tests: a raw HTTP/1.1 exchange (the
//! fixtures record the exact request bytes Python saw) and fixture paths.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

/// The crate's `fixtures/` directory.
pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// A parsed response.
#[derive(Debug)]
pub struct Exchange {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Exchange {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Sends `request` and reads one response (by `Content-Length`, else to
/// EOF; no body for HEAD).
pub fn exchange(addr: SocketAddr, request: &[u8], head: bool) -> Exchange {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request).unwrap();
    read_response(&mut stream, head)
}

/// Reads one response from `stream`.
pub fn read_response(stream: &mut TcpStream, head: bool) -> Exchange {
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        if let httparse::Status::Complete(length) = response.parse(&data).unwrap() {
            let status = response.code.unwrap();
            let headers: Vec<(String, String)> = response
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_owned(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            let mut body = data[length..].to_vec();
            let content_length = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.parse::<usize>().unwrap());
            if !head {
                match content_length {
                    Some(n) => {
                        while body.len() < n {
                            let read = stream.read(&mut chunk).unwrap();
                            assert!(read > 0, "EOF inside the body");
                            body.extend_from_slice(&chunk[..read]);
                        }
                        body.truncate(n);
                    }
                    None => {
                        stream.read_to_end(&mut body).unwrap();
                    }
                }
            } else {
                body.clear();
            }
            return Exchange {
                status,
                headers,
                body,
            };
        }
        let read = stream.read(&mut chunk).unwrap();
        assert!(
            read > 0,
            "EOF before the response head: {:?}",
            String::from_utf8_lossy(&data)
        );
        data.extend_from_slice(&chunk[..read]);
    }
}

/// The raw request of an `http_common.json` case.
pub fn raw_request(
    method: &str,
    target: &str,
    version: &str,
    headers: &[(String, String)],
) -> Vec<u8> {
    let mut text = format!("{method} {target} {version}\r\nHost: 127.0.0.1\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    // The fixture strings are latin-1 (Python's header decoding).
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap())
        .collect()
}
