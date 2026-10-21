//! Mode `static` (PLAN.md 4.7, `static_site_deploy`): a read-only static
//! site behind Traefik.
//!
//! S1: command line, `--check-config` and the 501 for methods other than
//! GET and HEAD; file serving (`tower-http`) arrives with S2e.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use hyper::Method;

use crate::clock::SharedClock;
use crate::modes::{ListenArgs, Mode, Problems, not_yet_implemented};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// `StaticHandler.timeout = 10`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `SimpleHTTPRequestHandler.server_version` (D-7 adds `metrics-httpd/<v>`).
pub const SERVER_NAME: &str = "SimpleHTTP/0.6";

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
        StaticSite {
            root: self.root.clone(),
        }
    }
}

/// The static site endpoint.
pub struct StaticSite {
    pub root: PathBuf,
}

impl Service for StaticSite {
    async fn call(&self, request: Request) -> HttpResponse {
        if request.method != Method::GET && request.method != Method::HEAD {
            return server::not_implemented(&request.method);
        }
        not_yet_implemented(<StaticArgs as Mode>::NAME)
    }
}
