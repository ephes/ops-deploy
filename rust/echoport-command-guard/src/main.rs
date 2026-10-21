//! `echoport-command-guard`: the argv grammar and the modes (PLAN.md 3.1,
//! 3.6; `guard.py:673-717`).
//!
//! S1 implements `--version` and `--check-policy`. Forced-command mode
//! (`<prog> <policy>`) is S4; until then it refuses every command and never
//! executes anything. `--decide` and `--shadow` are S4 as well and are a
//! usage error until then. The guard never writes to stdout except in
//! `--version` (and `--decide`), and never reads stdin.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use echoport_command_guard::PROGRAM;
use echoport_command_guard::policy::load_policy;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("ECHOPORT_COMMAND_GUARD_GIT_COMMIT");

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    match args.as_slice() {
        [_, flag] if flag == "--version" => version(),
        [_, flag, policy] if flag == "--check-policy" => check_policy(Path::new(policy)),
        [_, _policy] => {
            // Forced-command mode (PLAN.md 3.1) arrives with S4; refuse.
            eprintln!("{PROGRAM}: command not allowed");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("{PROGRAM}: usage: {PROGRAM} <policy.json> | --check-policy <policy.json>");
            ExitCode::from(2)
        }
    }
}

/// `--version`: `echoport-command-guard <version> (<commit>)`, exit 0.
fn version() -> ExitCode {
    // A closed or full stdout is a runtime error (exit 1), not a panic.
    match writeln!(
        std::io::stdout().lock(),
        "echoport-command-guard {VERSION} ({COMMIT})"
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{PROGRAM}: cannot write the version: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `--check-policy <file>` (`guard.py:674-680`): exit 0 for a valid policy,
/// else the detail on stderr and exit 1.
fn check_policy(path: &Path) -> ExitCode {
    match load_policy(path) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{PROGRAM}: invalid policy: {error}");
            ExitCode::FAILURE
        }
    }
}
