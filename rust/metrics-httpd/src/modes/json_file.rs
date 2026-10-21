//! Mode `json-file` (PLAN.md 4.2, variants of 4.3): serves a JSON file
//! written by a root timer, with the `meta` block of [`crate::meta`].
//!
//! One implementation for the eight Python variants (backup, storage,
//! thermal, tailscale, dns, openclaw, ddns, torrent-vpn); their differences
//! are flags: `--realm`, `--server-name`, `--path-match`, `--meta`,
//! `--missing-message`, `--request-timeout` (PLAN.md 4.3, 7.3).
//!
//! Python (`backup_metrics_httpd.py.j2` `do_GET`, l.49–101), after the gate
//! of PLAN.md 4.1:
//!
//! ```python
//! if not os.path.isfile(json_path): -> 503 metrics_file_missing <variant text>
//! stat, now, json.load(...)   # JSONDecodeError -> 502 invalid_json, OSError -> 503 read_error
//! data["meta"] = {...}        # dns: merged into an existing meta object
//! -> 200 json.dumps(data, sort_keys=True)
//! ```
//!
//! Where Python's handler raises and drops the connection (a top-level value
//! that is not an object, a file that is not UTF-8, an int longer than 4300
//! digits, an mtime outside the years 1–9999), Rust answers (D-2, D-5); JSON
//! that Python accepts but Rust refuses (`NaN`, `Infinity`, overflowing
//! floats, lone surrogates, nesting deeper than 127) is a 502 (D-4). Every
//! 5xx answer also writes one line with its cause to stderr (D-9).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use hyper::StatusCode;

use crate::clock::SharedClock;
use crate::meta::{self, Document, FileError, MetaMode};
use crate::modes::{AuthArgs, Gate, ListenArgs, Mode, NotFound, PathMatch, Problems};
use crate::pyjson;
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// The backup variant's missing-file message (the default).
pub const DEFAULT_MISSING_MESSAGE: &str = "Metrics file not found - timer may not have run yet";

/// `--meta` (PLAN.md 4.2 step 4).
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaArg {
    Replace,
    Merge,
}

impl From<MetaArg> for MetaMode {
    fn from(value: MetaArg) -> Self {
        match value {
            MetaArg::Replace => Self::Replace,
            MetaArg::Merge => Self::Merge,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct JsonFileArgs {
    #[command(flatten)]
    pub listen: ListenArgs,
    #[command(flatten)]
    pub auth: AuthArgs,
    /// The JSON file to serve.
    #[arg(long, value_name = "F")]
    pub json_path: PathBuf,
    /// replace: `meta` is replaced; merge (dns): the keys are set into an existing `meta` object.
    #[arg(long, value_enum, default_value = "replace")]
    pub meta: MetaArg,
    /// exact: the raw request-target must equal --path; path-only (tailscale): query and fragment ignored.
    #[arg(long, value_enum, default_value = "exact")]
    pub path_match: PathMatch,
    /// `message` of the 503 `metrics_file_missing` answer.
    #[arg(long, value_name = "TEXT", default_value = DEFAULT_MISSING_MESSAGE)]
    pub missing_message: String,
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

impl Mode for JsonFileArgs {
    type Service = JsonFile;
    const NAME: &'static str = "json-file";

    fn addr(&self) -> SocketAddr {
        self.listen.addr()
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        let entries = problems.htpasswd(&self.auth.htpasswd_file);
        problems.parent_dir("json file", &self.json_path);
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} json {} htpasswd {} (bcrypt entries: {entries}) realm {} meta {:?} path-match {:?}",
            self.addr(),
            self.auth.path,
            self.json_path.display(),
            self.auth.htpasswd_file.display(),
            self.auth.realm,
            self.meta,
            self.path_match,
        ))
    }

    fn server_config(&self, clock: SharedClock) -> ServerConfig {
        ServerConfig {
            request_timeout: self.auth.request_timeout,
            access_log: AccessLog::Stderr,
            server_header: server::server_header(&self.auth.server_name),
            clock,
        }
    }

    fn service(&self, clock: SharedClock) -> JsonFile {
        JsonFile {
            gate: Gate::new(&self.auth, self.path_match, NotFound::Json),
            json_path: self.json_path.clone(),
            meta: self.meta.into(),
            missing_message: self.missing_message.clone(),
            clock,
        }
    }
}

/// The json-file endpoint.
pub struct JsonFile {
    pub gate: Gate,
    pub json_path: PathBuf,
    pub meta: MetaMode,
    pub missing_message: String,
    pub clock: SharedClock,
}

impl Service for JsonFile {
    async fn call(&self, request: Request) -> HttpResponse {
        if let Some(response) = self.gate.check(&request).await {
            return response;
        }
        match meta::read_document(self.json_path.clone(), self.clock.clone()).await {
            Ok(document) => self.serve(document),
            Err(FileError::Missing) => self.fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "metrics_file_missing",
                &self.missing_message,
                "not a regular file (missing, a directory, a broken symlink or not accessible)",
            ),
            Err(FileError::Read(error)) => {
                let cause = error.to_string();
                self.fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "read_error",
                    &format!("Cannot read metrics file: {cause}"),
                    &cause,
                )
            }
            Err(FileError::Invalid(cause)) => self.fail(
                StatusCode::BAD_GATEWAY,
                "invalid_json",
                &format!("Invalid JSON in metrics file: {cause}"),
                &cause,
            ),
        }
    }
}

impl JsonFile {
    /// PLAN.md 4.2 steps 4–5: the `meta` block, then the sorted document.
    fn serve(&self, mut document: Document) -> HttpResponse {
        let Some(fields) = meta::meta_fields(&document) else {
            // Python's `datetime.fromtimestamp` raises outside the years
            // 1–9999 and the handler drops the connection (D-2).
            let cause = format!(
                "modification time {} is outside the years 1-9999",
                document.generated_at_epoch
            );
            return self.fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("Cannot serve metrics file: {cause}"),
                &cause,
            );
        };
        meta::apply_meta(&mut document.data, fields, self.meta);
        server::json_response(StatusCode::OK, pyjson::dumps(&document.data))
    }

    /// A JSON error answer plus its cause on stderr (D-9).
    fn fail(
        &self,
        status: StatusCode,
        error_type: &str,
        message: &str,
        cause: &str,
    ) -> HttpResponse {
        server::log_line(&format!(
            "metrics-httpd: {} {}: {} {error_type}: {cause}",
            <JsonFileArgs as Mode>::NAME,
            self.json_path.display(),
            status.as_u16(),
        ));
        server::json_error(status, error_type, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PasswordSource;
    use crate::clock::FixedClock;
    use http_body_util::BodyExt;
    use hyper::header::{AUTHORIZATION, HeaderMap, HeaderValue};
    use hyper::{Method, Version};
    use serde_json::Value;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: i64 = 1_792_576_800;

    fn endpoint(json_path: PathBuf, meta: MetaMode) -> JsonFile {
        let htpasswd = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/htpasswd");
        JsonFile {
            gate: Gate {
                path: "/.well-known/backup".to_owned(),
                path_match: PathMatch::Exact,
                not_found: NotFound::Json,
                htpasswd_file: htpasswd,
                realm: "backup-metrics".to_owned(),
                password_source: PasswordSource::Stdin,
            },
            json_path,
            meta,
            missing_message: DEFAULT_MISSING_MESSAGE.to_owned(),
            clock: Arc::new(FixedClock::at_epoch(NOW)),
        }
    }

    async fn get(endpoint: &JsonFile) -> (StatusCode, Value) {
        let mut headers = HeaderMap::new();
        // user:secret, the test-only entry of fixtures/htpasswd.
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpzZWNyZXQ="),
        );
        let request = Request {
            method: Method::GET,
            target: "/.well-known/backup".to_owned(),
            version: Version::HTTP_11,
            headers,
            peer: "127.0.0.1:1".parse().unwrap(),
        };
        let response = endpoint.call(request).await;
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn set_mtime(path: &Path, epoch: u64) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(UNIX_EPOCH + Duration::from_secs(epoch))
            .unwrap();
    }

    #[tokio::test]
    async fn serves_the_document_with_meta() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        std::fs::write(&path, r#"{"meta": {"keep": 1}, "b": [1.50], "a": "é"}"#).unwrap();
        set_mtime(&path, 1_792_576_700);
        let (status, body) = get(&endpoint(path.clone(), MetaMode::Replace)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({
                "a": "é",
                "b": [1.5],
                "meta": {
                    "generated_at": "2026-10-21T09:58:20+00:00",
                    "generated_at_epoch": 1_792_576_700,
                    "served_at_epoch": NOW,
                    "age_seconds": 100,
                },
            })
        );
        let (_, merged) = get(&endpoint(path, MetaMode::Merge)).await;
        assert_eq!(merged["meta"]["keep"], 1);
        assert_eq!(merged["meta"]["age_seconds"], 100);
    }

    /// D-12: a file over 64 MiB is not read into memory (502).
    #[tokio::test]
    async fn files_over_the_size_limit_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(meta::MAX_DOCUMENT_BYTES + 1).unwrap();
        let (status, body) = get(&endpoint(path, MetaMode::Replace)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error_type"], "invalid_json");
        let message = body["message"].as_str().unwrap();
        assert!(
            message.starts_with("Invalid JSON in metrics file: "),
            "{message}"
        );
    }

    /// D-2: Python's `fromtimestamp` raises for an mtime past the year 9999
    /// and drops the connection; Rust answers 500 `internal_error`. (Built
    /// directly: ext4 cannot store such an mtime.)
    #[tokio::test]
    async fn mtime_outside_python_datetime_is_an_internal_error() {
        let endpoint = endpoint(PathBuf::from("/nonexistent"), MetaMode::Replace);
        let document = Document {
            data: serde_json::Map::new(),
            generated_at_epoch: 253_402_300_800,
            served_at_epoch: NOW,
        };
        let response = endpoint.serve(document);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_type"], "internal_error");
    }
}
