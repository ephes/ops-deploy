//! The outcome of `check()`: a [`Decision`] for an allowed command, or
//! [`Refused`] (PLAN.md 3.4; `guard.py:75-77, 176-195`).

use serde::Serialize;
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

/// What to execute for an allowed command (`guard.py:190-195`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub argv: Vec<String>,
    /// `None` or `0o077`.
    pub umask: Option<u32>,
    pub stdin: Option<Redirect>,
    /// Created exclusively, mode `0600`.
    pub stdout: Option<Redirect>,
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
        };
        assert_eq!(
            decision.to_json(),
            json!({"verdict": "allowed", "argv": ["cat"], "umask": 63, "stdin": null,
                   "stdout": {"directory": "/var/tmp/x.abcdef", "name": "db.dump", "owners": []}})
        );
    }
}
