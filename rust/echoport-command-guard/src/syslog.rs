//! The guard's log lines (PLAN.md 3.6; `guard.py:654-659`).
//!
//! CPython's `syslog` module calls libc `openlog(ident, LOG_PID, LOG_AUTH)`
//! and then `syslog(priority, "%s", message)`. [`SysLog`] makes the same two
//! libc calls through `nix::syslog`, a thin wrapper of exactly these
//! functions (glibc, `/dev/log`, journald), so the identifier, the PID and
//! the facility come out as Python's. Errors while logging are ignored, as
//! in Python.
//!
//! The modes write through the [`Logger`] trait, so the process tests can
//! read what the guard logged without a syslog daemon.

use nix::syslog::Severity;

/// `message[:1000]` (`guard.py:657`): the guard's own lines are cut after
/// 1000 characters. The shadow record is not cut (it must stay valid JSON).
pub const MAX_MESSAGE_CHARS: usize = 1000;

/// The syslog identifier of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ident {
    /// `echoport-remote-command-guard`, the Python guard's identifier.
    Guard,
    /// `echoport-remote-command-guard-shadow`: the Rust decision in
    /// `--shadow` mode (PLAN.md 3.6).
    Shadow,
}

impl Ident {
    pub fn name(self) -> &'static str {
        match self {
            Ident::Guard => "echoport-remote-command-guard",
            Ident::Shadow => "echoport-remote-command-guard-shadow",
        }
    }

    #[cfg(target_os = "linux")]
    fn c_name(self) -> &'static std::ffi::CStr {
        match self {
            Ident::Guard => c"echoport-remote-command-guard",
            Ident::Shadow => c"echoport-remote-command-guard-shadow",
        }
    }
}

/// The priorities the guard logs at (`guard.py:686-711`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// An allowed command.
    Info,
    /// A refusal or an interactive session.
    Warning,
    /// A policy error.
    Err,
}

impl Priority {
    /// The syslog severity (no facility bits).
    pub fn severity(self) -> Severity {
        match self {
            Priority::Info => Severity::LOG_INFO,
            Priority::Warning => Severity::LOG_WARNING,
            Priority::Err => Severity::LOG_ERR,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Priority::Info => "info",
            Priority::Warning => "warning",
            Priority::Err => "err",
        }
    }
}

/// Where the modes send their log lines.
pub trait Logger {
    fn log(&self, ident: Ident, priority: Priority, message: &str);
}

/// libc syslog, as CPython's `syslog` module uses it.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysLog;

impl Logger for SysLog {
    #[cfg(target_os = "linux")]
    fn log(&self, ident: Ident, priority: Priority, message: &str) {
        use nix::syslog::{Facility, LogFlags};
        // `syslog.openlog(PROGRAM, syslog.LOG_PID, syslog.LOG_AUTH)` before
        // every line, as `_log` does. The priority carries no facility, so
        // the one from `openlog` (LOG_AUTH) applies.
        let opened =
            nix::syslog::openlog(Some(ident.c_name()), LogFlags::LOG_PID, Facility::LOG_AUTH);
        if opened.is_ok() {
            // A message with a NUL byte cannot be passed to libc; the guard's
            // messages never have one (`repr` escapes it).
            let _ = nix::syslog::syslog(priority.severity(), message);
        }
    }

    /// The guard runs on Linux only. Elsewhere (macOS development) nothing
    /// is logged: nix's `openlog` there hands libc a pointer to a temporary
    /// copy of the identifier, which libc keeps.
    #[cfg(not(target_os = "linux"))]
    fn log(&self, _ident: Ident, _priority: Priority, _message: &str) {}
}

/// `message[:1000]`, in characters as Python counts them.
pub fn truncate(message: &str) -> &str {
    match message.char_indices().nth(MAX_MESSAGE_CHARS) {
        Some((index, _)) => &message[..index],
        None => message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_after_1000_characters() {
        assert_eq!(truncate("abc"), "abc");
        let long = "a".repeat(1001);
        assert_eq!(truncate(&long).len(), 1000);
        let wide = "é".repeat(1001);
        assert_eq!(truncate(&wide).chars().count(), 1000);
        assert_eq!(truncate(&"x".repeat(1000)).len(), 1000);
    }

    #[test]
    fn a_message_libc_cannot_take_is_dropped() {
        // `openlog` only; the NUL byte stops the line before libc `syslog`,
        // and nothing panics.
        SysLog.log(Ident::Shadow, Priority::Warning, "a\0b");
        assert_eq!(Ident::Guard.name(), crate::PROGRAM);
    }
}
