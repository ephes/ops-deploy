//! metrics-httpd: small authenticated HTTP endpoints for homelab metrics, the
//! Rust port of the Python endpoint daemons (`rust/metrics-httpd/PLAN.md`).
//!
//! One binary, one subcommand per endpoint family (PLAN.md 3, 4.9); each
//! systemd unit runs one process. Exit codes (PLAN.md 4.8): 0 after
//! SIGTERM/SIGINT, `--version` and a passing `--check-config`; 2 for usage
//! and configuration errors; 1 for runtime errors such as a failed bind.

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser as _;

use metrics_httpd::cli::{Cli, Command};
use metrics_httpd::clock::{SharedClock, SystemClock};
use metrics_httpd::modes::logyard_health::LogyardConfig;
use metrics_httpd::modes::{Mode, Problems};
use metrics_httpd::server;
use metrics_httpd::{COMMIT, VERSION};

/// PLAN.md 6, 9: the runtime thread plus at most four blocking threads.
const MAX_BLOCKING_THREADS: usize = 4;
/// After the server's own grace period, how long blocking tasks may still
/// run before the process exits anyway.
const BLOCKING_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // Help goes to stdout with 0, usage errors to stderr with 2.
            let _ = error.print();
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2));
        }
    };
    if cli.version {
        // A closed or full stdout is a runtime error (exit 1), not a panic.
        return match writeln!(
            std::io::stdout().lock(),
            "metrics-httpd {VERSION} ({COMMIT})"
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("metrics-httpd: cannot write the version: {error}");
                ExitCode::FAILURE
            }
        };
    }
    match cli.mode {
        None => {
            eprintln!(
                "metrics-httpd: a mode is required (json-file, script, apt-state, logyard-health, static) or --version; see --help"
            );
            ExitCode::from(2)
        }
        Some(Command::JsonFile(args)) => launch(args.check_config, Ok(args)),
        Some(Command::Script(args)) => launch(args.check_config, Ok(args)),
        Some(Command::AptState(args)) => launch(args.check_config, Ok(args)),
        Some(Command::Static(args)) => launch(args.check_config, Ok(args)),
        Some(Command::LogyardHealth(args)) => launch(
            args.check_config,
            LogyardConfig::from_env(|name| {
                std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
            }),
        ),
    }
}

fn report(mode: &str, problems: &Problems) -> ExitCode {
    for problem in &problems.0 {
        eprintln!("metrics-httpd {mode}: {problem}");
    }
    ExitCode::from(2)
}

/// Checks or runs a mode.
fn launch<M: Mode>(check_config: bool, config: Result<M, Problems>) -> ExitCode {
    let config = match config {
        Ok(config) => config,
        Err(problems) => return report(M::NAME, &problems),
    };
    if check_config {
        return match config.check_config() {
            Ok(summary) => {
                println!("metrics-httpd {} configuration ok: {summary}", M::NAME);
                ExitCode::SUCCESS
            }
            Err(problems) => report(M::NAME, &problems),
        };
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("metrics-httpd: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(serve(config));
    // Blocking work still running after the grace period (a bcrypt check of
    // an expensive hash, a slow file read) must not hold the exit: dropping
    // the runtime would wait for it.
    runtime.shutdown_timeout(BLOCKING_SHUTDOWN_GRACE);
    code
}

async fn serve<M: Mode>(config: M) -> ExitCode {
    let clock: SharedClock = Arc::new(SystemClock);
    let addr = config.addr();
    let listener = match server::bind(addr) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "metrics-httpd {}: cannot listen on {addr}: {error}",
                M::NAME
            );
            return ExitCode::FAILURE;
        }
    };
    let local = listener.local_addr().unwrap_or(addr);
    server::log_line(&format!(
        "metrics-httpd {VERSION} ({COMMIT}) {} listening on {local}",
        M::NAME
    ));
    let service = Arc::new(config.service(clock.clone()));
    server::run(
        listener,
        config.server_config(clock),
        service,
        server::shutdown_signal(),
    )
    .await;
    ExitCode::SUCCESS
}
