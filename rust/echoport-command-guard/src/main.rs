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
use echoport_command_guard::env::{FileStat, GuardEnv, OsError};
use echoport_command_guard::exec::SAFE_PATH;
use echoport_command_guard::modes::{self, Host, PythonGuard};
use echoport_command_guard::policy::load_policy;
use echoport_command_guard::rules::check;
use echoport_command_guard::syslog::SysLog;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("ECHOPORT_COMMAND_GUARD_GIT_COMMIT");

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let env = HostEnv;
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

/// The host as the binary sees it. The euid and the NSS user lookups
/// (`getpwnam_r`, as Python's `pwd.getpwnam`) are real. `lstat` and
/// `realpath` are S2's (`env::RealEnv` with `pyrealpath.rs`); until that
/// lands they fail, so every path check refuses (`... not checkable`) and
/// nothing is accepted on a path the guard has not looked at.
struct HostEnv;

impl HostEnv {
    fn not_yet() -> OsError {
        OsError {
            errno: "ENOSYS".into(),
            strerror: "Function not implemented".into(),
        }
    }
}

impl GuardEnv for HostEnv {
    fn euid(&self) -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn uid_of(&self, name: &str) -> Option<u32> {
        match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => Some(user.uid.as_raw()),
            Ok(None) | Err(_) => None,
        }
    }

    fn lstat(&self, _path: &str) -> Result<Option<FileStat>, OsError> {
        Err(Self::not_yet())
    }

    fn realpath(&self, _path: &str) -> Result<String, OsError> {
        Err(Self::not_yet())
    }
}
