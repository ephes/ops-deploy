//! `echoport-command-guard`: the argv grammar and the modes (PLAN.md 3.1,
//! 3.6; `guard.py:673-717`).
//!
//! - `<prog> --check-policy <policy>`: validate a policy file.
//! - `<prog> <policy>`: forced-command mode (`modes::forced_command`).
//! - Additions a client cannot reach (sshd's `command=` fixes the argv):
//!   `--version`, `--decide <policy>` and
//!   `--shadow <policy> <python> -I <guard> <policy>`.
//! - Anything else: the Python guard's usage error, exit 2.
//!
//! The guard never reads stdin and writes to stdout only in `--version` and
//! `--decide`.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use echoport_command_guard::PROGRAM;
use echoport_command_guard::env::RealEnv;
use echoport_command_guard::exec::SAFE_PATH;
use echoport_command_guard::modes::{self, Host, PythonGuard};
use echoport_command_guard::policy::load_policy;
use echoport_command_guard::rules::check;
use echoport_command_guard::syslog::SysLog;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("ECHOPORT_COMMAND_GUARD_GIT_COMMIT");

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    // The host as the binary sees it (S2): geteuid, NSS users, lstat and
    // `realpath` as `pyrealpath` (PLAN.md 3.3.6-3.3.8).
    let env = RealEnv;
    let host = Host {
        env: &env,
        log: &SysLog,
        check,
        search_path: SAFE_PATH,
    };
    match args.as_slice() {
        [_, flag] if flag == "--version" => version(),
        [_, flag, policy] if flag == "--check-policy" => check_policy(Path::new(policy)),
        [_, flag, policy] if flag == "--decide" => {
            modes::install_panic_hook();
            modes::decide(&host, policy, &mut std::io::stdout().lock())
        }
        [_, flag, policy, python, isolated, guard, policy_again]
            if flag == "--shadow" && isolated == "-I" && policy == policy_again =>
        {
            let python_guard = PythonGuard {
                python,
                guard,
                policy,
            };
            if !python_guard.is_valid() {
                return shadow_usage();
            }
            modes::install_panic_hook();
            modes::shadow(&host, &python_guard)
        }
        [_, flag, ..] if flag == "--shadow" => shadow_usage(),
        [_, policy] => {
            modes::install_panic_hook();
            modes::forced_command(&host, policy)
        }
        _ => {
            eprintln!("{PROGRAM}: usage: {PROGRAM} <policy.json> | --check-policy <policy.json>");
            ExitCode::from(2)
        }
    }
}

/// A `--shadow` argv that is not exactly the Python guard's forced command
/// for the same policy: exit 2, nothing is executed.
fn shadow_usage() -> ExitCode {
    eprintln!(
        "{PROGRAM}: usage: {PROGRAM} --shadow <policy.json> </abs/python> -I </abs/guard> <policy.json>"
    );
    ExitCode::from(2)
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
