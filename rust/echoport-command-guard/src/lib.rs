//! The Rust port of the Echoport remote command guard (`PLAN.md`): the
//! forced-command allowlist sshd runs for the Echoport remote runners' key.
//!
//! The library holds everything that decides; `main.rs` holds the argv
//! grammar and the modes. The Python guard
//! (`roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py`,
//! cited as `guard.py:<line>`) is the oracle: `fixtures/` holds its decisions.

// PLAN.md 5.3: no unwrap/expect on input-derived data outside tests.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod decision;
pub mod env;
pub mod exec;
pub mod modes;
pub mod policy;
pub mod prefilter;
pub mod pyrealpath;
pub mod redirect;
pub mod repr;
pub mod rules;
pub mod syslog;
pub mod tokens;

/// The name in every message and log line, whatever the binary is called
/// (PLAN.md 3.1).
pub const PROGRAM: &str = "echoport-remote-command-guard";

/// `MAX_COMMAND_LENGTH` (`guard.py:34`), in characters.
pub const MAX_COMMAND_LENGTH: usize = 4096;
