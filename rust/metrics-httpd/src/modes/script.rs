//! Mode `script` (PLAN.md 4.4, `metrics_endpoint`): runs a metrics script
//! per request and serves its stdout.
//!
//! S1: command line, `--check-config` and the gate (404 as Python's HTML
//! `send_error`); running the script arrives with S2b.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use rustix::fs::{Access, access};

use crate::auth::PasswordSource;
use crate::clock::SharedClock;
use crate::modes::{
    AuthArgs, Gate, ListenArgs, Mode, NotFound, PathMatch, Problems, not_yet_implemented,
    parse_seconds,
};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

#[derive(Args, Debug, Clone)]
pub struct ScriptArgs {
    #[command(flatten)]
    pub listen: ListenArgs,
    #[command(flatten)]
    pub auth: AuthArgs,
    /// The metrics script (run without a shell and without arguments).
    #[arg(long, value_name = "X")]
    pub script: PathBuf,
    /// Seconds before the script is killed and the request answered 504.
    #[arg(long, value_name = "SECS", value_parser = parse_seconds)]
    pub script_timeout: Duration,
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

impl Mode for ScriptArgs {
    type Service = Script;
    const NAME: &'static str = "script";

    fn addr(&self) -> SocketAddr {
        self.listen.addr()
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        let entries = problems.htpasswd(&self.auth.htpasswd_file);
        match std::fs::metadata(&self.script) {
            Ok(metadata) if metadata.is_file() => {
                if access(&self.script, Access::EXEC_OK).is_err() {
                    problems.push(format!(
                        "script {} is not executable",
                        self.script.display()
                    ));
                }
            }
            Ok(_) => problems.push(format!("script {} is not a file", self.script.display())),
            Err(error) => problems.push(format!("script {}: {error}", self.script.display())),
        }
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} script {} timeout {:?} htpasswd {} (bcrypt entries: {entries}) realm {}",
            self.addr(),
            self.auth.path,
            self.script.display(),
            self.script_timeout,
            self.auth.htpasswd_file.display(),
            self.auth.realm,
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

    fn service(&self, _clock: SharedClock) -> Script {
        Script {
            gate: Gate {
                // `htpasswd -vb`: the password in argv (D-6 keeps its rules).
                password_source: PasswordSource::Argv,
                ..Gate::new(&self.auth, PathMatch::Exact, NotFound::Html)
            },
            script: self.script.clone(),
            script_timeout: self.script_timeout,
        }
    }
}

/// The script endpoint.
pub struct Script {
    pub gate: Gate,
    pub script: PathBuf,
    pub script_timeout: Duration,
}

impl Service for Script {
    async fn call(&self, request: Request) -> HttpResponse {
        if let Some(response) = self.gate.check(&request).await {
            return response;
        }
        not_yet_implemented(<ScriptArgs as Mode>::NAME)
    }
}
