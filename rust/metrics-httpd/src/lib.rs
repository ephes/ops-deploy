//! metrics-httpd library: the server core, auth, Python-compatible JSON and
//! the modes (`rust/metrics-httpd/PLAN.md` section 6). The binary
//! (`src/main.rs`) is the command line around it; the integration tests
//! replay the fixtures against these modules in process.

pub mod auth;
pub mod cli;
pub mod clock;
pub mod meta;
pub mod modes;
pub mod pyjson;
pub mod server;

/// The crate version, as `--version` prints it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The commit `build.rs` embedded.
pub const COMMIT: &str = env!("METRICS_HTTPD_GIT_COMMIT");
