//! Mode `apt-state` (PLAN.md 4.5, `os_apt_maintenance`): serves the apt
//! maintenance state file with the computed `summary` and reboot state.
//!
//! S1: command line, `--check-config` and the gate; the state logic
//! arrives with S2c.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

use crate::clock::SharedClock;
use crate::modes::{
    AuthArgs, Gate, ListenArgs, Mode, NotFound, PathMatch, Problems, not_yet_implemented,
};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// `os.path.exists("/var/run/reboot-required")` in Python.
pub const DEFAULT_REBOOT_FLAG: &str = "/var/run/reboot-required";

#[derive(Args, Debug, Clone)]
pub struct AptStateArgs {
    #[command(flatten)]
    pub listen: ListenArgs,
    #[command(flatten)]
    pub auth: AuthArgs,
    /// The state file written by os-apt-maintenance.
    #[arg(long, value_name = "F")]
    pub json_path: PathBuf,
    /// FRESHNESS_MAX_AGE_SECONDS: the last success must be at most this old.
    #[arg(long, value_name = "SECS", allow_negative_numbers = true)]
    pub freshness_max_age: i64,
    /// STATE_MAX_AGE_SECONDS: the state file must be at most this old.
    #[arg(long, value_name = "SECS", allow_negative_numbers = true)]
    pub state_max_age: i64,
    /// The flag file whose existence means a reboot is required.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_REBOOT_FLAG)]
    pub reboot_flag: PathBuf,
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

impl Mode for AptStateArgs {
    type Service = AptState;
    const NAME: &'static str = "apt-state";

    fn addr(&self) -> SocketAddr {
        self.listen.addr()
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        let entries = problems.htpasswd(&self.auth.htpasswd_file);
        problems.parent_dir("state file", &self.json_path);
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} state {} freshness-max-age {} state-max-age {} reboot-flag {} htpasswd {} (bcrypt entries: {entries}) realm {}",
            self.addr(),
            self.auth.path,
            self.json_path.display(),
            self.freshness_max_age,
            self.state_max_age,
            self.reboot_flag.display(),
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

    fn service(&self, clock: SharedClock) -> AptState {
        AptState {
            gate: Gate::new(&self.auth, PathMatch::Exact, NotFound::Json),
            json_path: self.json_path.clone(),
            freshness_max_age: self.freshness_max_age,
            state_max_age: self.state_max_age,
            reboot_flag: self.reboot_flag.clone(),
            clock,
        }
    }
}

/// The apt-state endpoint.
pub struct AptState {
    pub gate: Gate,
    pub json_path: PathBuf,
    pub freshness_max_age: i64,
    pub state_max_age: i64,
    pub reboot_flag: PathBuf,
    pub clock: SharedClock,
}

impl Service for AptState {
    async fn call(&self, request: Request) -> HttpResponse {
        if let Some(response) = self.gate.check(&request).await {
            return response;
        }
        not_yet_implemented(<AptStateArgs as Mode>::NAME)
    }
}
