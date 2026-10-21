//! The Rust-only invariants of an accepted decision (PLAN.md 7.3), shared by
//! the decision property tests (`tests/decisions.rs`) and the fuzz targets
//! (`fuzz/fuzz_targets/*.rs` include this file by path). They hold for every
//! decision `check()` can return, whatever Python would decide:
//!
//! - `argv[0]` is one of the tools the guard executes;
//! - a `sudo` decision starts `sudo -n -u postgres --`;
//! - a `runuser` decision is `runuser -u <user> -- ...` with a safe user name
//!   that is not `root`, and every upload (`scp -t`, an rsync receiver) and
//!   every `mkdir` runs under it;
//! - every path the decision names (an argv token that starts with `/`, the
//!   value of `--file=`, the target of `.backup`, the redirects) is a safe
//!   path (`_SAFE_PATH_RE`, no empty, `.` or `..` component);
//! - the umask is none or `0o077`, and a redirect's name is a single safe name.

use echoport_command_guard::decision::Decision;
use echoport_command_guard::policy::{is_safe_name, is_safe_path};

/// The programs an accepted decision may execute (`guard.py:489-617`).
pub const EXECUTED: [&str; 19] = [
    "sudo",
    "runuser",
    "systemctl",
    "scp",
    "rsync",
    "rm",
    "mktemp",
    "cat",
    "sha256sum",
    "du",
    "sh",
    "readlink",
    "test",
    "mv",
    "mkdir",
    "chmod",
    "chown",
    "curl",
    "tar",
];

/// `Ok(())`, or the first invariant `decision` breaks.
pub fn decision_invariants(decision: &Decision) -> Result<(), String> {
    let argv = &decision.argv;
    let Some(program) = argv.first() else {
        return Err("empty argv".into());
    };
    if !EXECUTED.contains(&program.as_str()) {
        return Err(format!("argv[0] {program:?} is not a guard tool"));
    }
    let inner: &[String] = match program.as_str() {
        "sudo" => {
            if argv.len() < 6 || argv[1..5] != ["-n", "-u", "postgres", "--"] {
                return Err(format!("sudo decision {argv:?}"));
            }
            &argv[5..]
        }
        "runuser" => {
            if argv.len() < 5 || argv[1] != "-u" || argv[3] != "--" {
                return Err(format!("runuser decision {argv:?}"));
            }
            if argv[2] == "root" || !is_safe_name(&argv[2]) {
                return Err(format!("runuser as {:?}", argv[2]));
            }
            &argv[4..]
        }
        _ => argv,
    };
    let Some(tool) = inner.first() else {
        return Err(format!("nothing to run in {argv:?}"));
    };
    let upload = (tool == "scp" && inner.get(1).is_some_and(|a| a == "-t"))
        || (tool == "rsync" && inner.get(2).is_some_and(|a| a != "--sender"))
        || tool == "mkdir";
    if upload && program != "runuser" {
        return Err(format!("upload or mkdir not under runuser: {argv:?}"));
    }
    for token in argv {
        let path = if token.starts_with('/') {
            Some(token.as_str())
        } else if let Some(value) = token.strip_prefix("--file=") {
            Some(value)
        } else {
            token
                .strip_prefix(".backup ")
                .map(|quoted| quoted.trim_matches('\''))
        };
        if let Some(path) = path
            && !is_safe_path(path)
        {
            return Err(format!("unsafe path {path:?} in {argv:?}"));
        }
    }
    if !matches!(decision.umask, None | Some(0o077)) {
        return Err(format!("umask {:?}", decision.umask));
    }
    for redirect in [&decision.stdin, &decision.stdout].into_iter().flatten() {
        if !is_safe_path(&redirect.directory) || !is_safe_name(&redirect.name) {
            return Err(format!("redirect {redirect:?}"));
        }
    }
    Ok(())
}
