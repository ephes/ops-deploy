//! Mode `json-file` (PLAN.md 4.2, variants of 4.3): serves a JSON file
//! written by a root timer, with the `meta` block of [`crate::meta`].
//!
//! S1: command line, `--check-config` and the gate; the file handling
//! arrives with S2a.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

use crate::clock::SharedClock;
use crate::meta::MetaMode;
use crate::modes::{
    AuthArgs, Gate, ListenArgs, Mode, NotFound, PathMatch, Problems, not_yet_implemented,
};
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
        not_yet_implemented(<JsonFileArgs as Mode>::NAME)
    }
}
