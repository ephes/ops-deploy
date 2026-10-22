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
//! - the umask is none or `0o077`, and a redirect's name is a single safe name;
//! - a mutation (H1) has an empty argv and nothing else: `chmod` with one
//!   safe path and mode `0o600`/`0o700`, `chown` with one safe path and a
//!   `<user>:<group>` owner that is not `root`'s (`private` only without
//!   `recursive`), `mv` with two safe paths, `rm` with two safe paths ending
//!   in `-wal`/`-shm`; a path never ends in `/`; `chmod`, `mv` and `rm` run
//!   as a safe user that is not `root`, `chown` as root (no `user`).

use echoport_command_guard::decision::{Decision, Mutation};
use echoport_command_guard::policy::{is_safe_name, is_safe_path};

/// The programs an accepted decision may execute (`guard.py:489-617`).
/// `mv`, `chmod` and `chown` are not among them: the guard makes those
/// changes itself (H1), as it does `rm -f` of SQLite side files.
pub const EXECUTED: [&str; 16] = [
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
    "mkdir",
    "curl",
    "tar",
];

/// The invariants of a change the guard makes itself.
fn mutation_invariants(decision: &Decision, mutation: &Mutation) -> Result<(), String> {
    if !decision.argv.is_empty()
        || decision.umask.is_some()
        || decision.stdin.is_some()
        || decision.stdout.is_some()
    {
        return Err(format!("mutation with more: {decision:?}"));
    }
    let paths = &mutation.paths;
    if paths
        .iter()
        .any(|path| !is_safe_path(path) || path.ends_with('/'))
    {
        return Err(format!("unsafe mutation path in {mutation:?}"));
    }
    let as_user = mutation
        .user
        .as_deref()
        .is_some_and(|user| user != "root" && is_safe_name(user));
    if as_user == (mutation.op == "chown") || (mutation.op == "chown" && mutation.user.is_some()) {
        return Err(format!("mutation user in {mutation:?}"));
    }
    let only_paths = mutation.mode.is_none()
        && mutation.owner.is_none()
        && !mutation.recursive
        && !mutation.private;
    let ok = match mutation.op.as_str() {
        "chmod" => {
            paths.len() == 1
                && matches!(mutation.mode, Some(0o600 | 0o700))
                && mutation.owner.is_none()
                && !mutation.recursive
                && !mutation.private
                && !mutation.replace
        }
        "chown" => {
            paths.len() == 1
                && mutation.mode.is_none()
                && !mutation.replace
                && !(mutation.private && mutation.recursive)
                && mutation.owner.as_deref().is_some_and(|owner| {
                    owner.split_once(':').is_some_and(|(user, group)| {
                        user != "root" && is_safe_name(user) && is_safe_name(group)
                    })
                })
        }
        "mv" => paths.len() == 2 && only_paths,
        "rm" => {
            paths.len() == 2
                && only_paths
                && !mutation.replace
                && paths[0].ends_with("-wal")
                && paths[1].ends_with("-shm")
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("mutation {mutation:?}"))
    }
}

/// `Ok(())`, or the first invariant `decision` breaks.
pub fn decision_invariants(decision: &Decision) -> Result<(), String> {
    if let Some(mutation) = &decision.mutation {
        return mutation_invariants(decision, mutation);
    }
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
