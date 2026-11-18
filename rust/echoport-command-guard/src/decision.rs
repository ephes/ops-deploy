//! The outcome of `check()`: a [`Decision`] for an allowed command, or
//! [`Refused`] (PLAN.md 3.4; `guard.py:75-77, 176-195`).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A file the guard opens itself and hands the command as stdin or stdout
/// (`guard.py:176-187`; opened by `redirect.rs`, S4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Redirect {
    /// Opened without following symlinks; must belong to the guard's own user
    /// or one of `owners`, with no group or other access.
    pub directory: String,
    /// Opened inside `directory` without following symlinks; a plain file.
    pub name: String,
    pub owners: Vec<String>,
}

/// A change the guard makes itself instead of running a tool (the Python
/// guard's `Mutation`; made by [`crate::mutate::perform`]): `chmod` (`mode`),
/// `chown` (`owner`, `recursive`; `private`: the path must still be a
/// directory of the guard's own user with no group or other access), `mv`
/// (`paths` is source and target; `replace`: the target may exist) or `rm`
/// (`-f`: missing paths are fine). Every path is walked from `/` without
/// following symlinks (PLAN.md 4.5, H1). `user`: the forced-command flow
/// drops to this user (the root's owner) before the change, so `chmod`, `mv`
/// and `rm` only do what that user could do itself; `chown` keeps root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub op: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub replace: bool,
    #[serde(default)]
    pub user: Option<String>,
}

impl Mutation {
    /// `Mutation(op, paths)`.
    pub fn new(op: &str, paths: &[&str]) -> Self {
        Self {
            op: op.to_owned(),
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            ..Self::default()
        }
    }
}

/// What to execute for an allowed command (`guard.py:190-195`), or the
/// change the guard makes itself (`mutation`, with an empty `argv`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub argv: Vec<String>,
    /// `None` or `0o077`.
    pub umask: Option<u32>,
    pub stdin: Option<Redirect>,
    /// Created exclusively, mode `0600`.
    pub stdout: Option<Redirect>,
    /// Made by the guard on file descriptors; nothing is executed.
    pub mutation: Option<Mutation>,
}

impl Decision {
    /// `Decision(argv=argv)`: run `argv` with the inherited umask and no
    /// redirects.
    pub fn run(argv: Vec<String>) -> Self {
        Self {
            argv,
            umask: None,
            stdin: None,
            stdout: None,
            mutation: None,
        }
    }

    /// `Decision(argv=[], mutation=mutation)`: the guard makes the change
    /// itself and runs nothing.
    pub fn mutate(mutation: Mutation) -> Self {
        Self {
            mutation: Some(mutation),
            ..Self::run(Vec::new())
        }
    }

    /// The decision in the fixtures' `expected` form (PLAN.md 7.2), which is
    /// also what `--decide` prints (S4).
    pub fn to_json(&self) -> Value {
        json!({
            "verdict": "allowed",
            "argv": self.argv,
            "umask": self.umask,
            "stdin": self.stdin,
            "stdout": self.stdout,
            "mutation": self.mutation,
        })
    }
}

/// The command is not on the allowlist; `reason` goes into the log line
/// `refused from <client>: <reason>: <repr(command)>` (PLAN.md 3.1, 4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    reason: String,
}

impl Refused {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Refused {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_has_the_fixture_shape() {
        let decision = Decision {
            argv: vec!["cat".into()],
            umask: Some(0o077),
            stdin: None,
            stdout: Some(Redirect {
                directory: "/var/tmp/x.abcdef".into(),
                name: "db.dump".into(),
                owners: vec![],
            }),
            mutation: None,
        };
        assert_eq!(
            decision.to_json(),
            json!({"verdict": "allowed", "argv": ["cat"], "umask": 63, "stdin": null,
                   "stdout": {"directory": "/var/tmp/x.abcdef", "name": "db.dump", "owners": []},
                   "mutation": null})
        );
        let chown = Decision::mutate(Mutation {
            owner: Some("marina:marina".into()),
            recursive: true,
            ..Mutation::new("chown", &["/home/marina/site/media"])
        });
        assert_eq!(
            chown.to_json(),
            json!({"verdict": "allowed", "argv": [], "umask": null, "stdin": null, "stdout": null,
                   "mutation": {"op": "chown", "paths": ["/home/marina/site/media"], "mode": null,
                                "owner": "marina:marina", "recursive": true, "private": false,
                                "replace": false, "user": null}})
        );
    }
}
