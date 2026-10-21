//! `check()` (PLAN.md 3.4; `guard.py:452-619`): what to execute for an
//! allowed command, or why it is refused.
//!
//! Ported so far (S1): the pre-checks and the prefilter, the two raw shapes
//! (detected, their checks are S3b), the tokeniser, the trailing `< file` of
//! `runuser`, and the tool dispatcher. Every tool branch is still a stub that
//! refuses ([`Refused::not_ported`]); S3a and S3b port them in
//! `postgres.rs`, `sqlite.rs`, `transfer.rs` and `files.rs`, in the order of
//! `guard.py`, so that the refusal reasons match (PLAN.md 4.4).

use crate::decision::{Decision, Refused};
use crate::env::GuardEnv;
use crate::policy::Policy;
use crate::prefilter;
use crate::repr::py_repr;
use crate::tokens;

/// The tools `check()` has a branch for (`guard.py:489-617`).
pub const TOOLS: [&str; 18] = [
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
];

/// `check(command, policy, realpath, lstat)` for the bytes of
/// `SSH_ORIGINAL_COMMAND`.
pub fn check(command: &[u8], policy: &Policy, env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let command = prefilter::command_text(command)?;

    if tokens::tar_shape(command).is_some() {
        // `guard.py:457-469`, S3b.
        return Err(Refused::not_ported("command not allowed: 'tar'"));
    }
    if tokens::cat_to_file_shape(command).is_some() {
        // `guard.py:471-476`, S3b.
        return Err(Refused::not_ported("command not allowed: 'cat'"));
    }

    let mut args = tokens::split(command)
        .map_err(|error| Refused::new(format!("unparsable command: {error}")))?;
    if args.is_empty() {
        return Err(Refused::new("empty command"));
    }
    let mut stdin_path = None;
    if args.len() >= 3 && args[args.len() - 2] == "<" {
        stdin_path = args.pop();
        args.pop();
    }
    let Some(tool) = args.first() else {
        return Err(Refused::new("empty command"));
    };
    if stdin_path.is_some() && tool != "runuser" {
        return Err(Refused::new("input redirection not allowed here"));
    }
    dispatch(tool, &args, stdin_path.as_deref(), policy, env)
}

/// The branches of `check()` by tool (`guard.py:489-619`).
fn dispatch(
    tool: &str,
    _args: &[String],
    _stdin_path: Option<&str>,
    _policy: &Policy,
    _env: &dyn GuardEnv,
) -> Result<Decision, Refused> {
    let reason = format!("command not allowed: {}", py_repr(tool));
    if TOOLS.contains(&tool) {
        Err(Refused::not_ported(reason))
    } else {
        Err(Refused::new(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::VirtualEnv;

    fn refusal(command: &str) -> Refused {
        check(
            command.as_bytes(),
            &Policy::default(),
            &VirtualEnv::default(),
        )
        .unwrap_err()
    }

    #[test]
    fn unknown_tools_are_refused_with_pythons_reason() {
        let refused = refusal("id");
        assert_eq!(refused.reason(), "command not allowed: 'id'");
        assert!(!refused.is_not_ported());
        assert_eq!(refusal("'' x").reason(), "command not allowed: ''");
        assert_eq!(
            refusal("\"it's\"").reason(),
            "command not allowed: \"it's\""
        );
    }

    #[test]
    fn every_known_tool_is_still_refused() {
        for tool in TOOLS {
            let refused = refusal(&format!("{tool} x y z"));
            assert!(refused.is_not_ported(), "{tool}");
        }
        assert!(refusal("umask 077 && tar -C /a -czf /b -- c").is_not_ported());
        assert!(refusal("umask 077 && cat > /a/b").is_not_ported());
    }

    #[test]
    fn tokeniser_stage_reasons() {
        assert_eq!(
            refusal("cat 'x").reason(),
            "unparsable command: No closing quotation"
        );
        assert_eq!(refusal("  \t ").reason(), "empty command");
        assert_eq!(
            refusal("cat < /etc/passwd").reason(),
            "input redirection not allowed here"
        );
        assert!(refusal("runuser -u postgres -- pg_restore < /tmp/x").is_not_ported());
        // `<` must be the second-to-last token of at least three.
        assert_eq!(refusal("< x").reason(), "command not allowed: '<'");
    }
}
