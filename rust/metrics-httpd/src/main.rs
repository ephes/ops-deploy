//! metrics-httpd: small authenticated HTTP endpoints for homelab metrics, the
//! Rust port of the Python endpoint daemons (`rust/metrics-httpd/PLAN.md`).
//!
//! Foundation skeleton (PLAN-foundation.md slice F1): only `--version`, which
//! prints `metrics-httpd <version> (<commit>)`. The modes of PLAN.md 4.9
//! arrive with slice S1. Any other command line is a usage error and exits 2
//! (PLAN.md 4.8).

use std::io::Write;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("METRICS_HTTPD_GIT_COMMIT");

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--version" => {
            // A closed or full stdout is a runtime error (exit 1), not a panic.
            match writeln!(
                std::io::stdout().lock(),
                "metrics-httpd {VERSION} ({COMMIT})"
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("metrics-httpd: cannot write the version: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage: metrics-httpd --version");
            ExitCode::from(2)
        }
    }
}
