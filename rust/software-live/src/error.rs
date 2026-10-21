//! The error of a step that Python would raise as an exception.
//!
//! Observations report errors as `"<Class>: <message>"` (PLAN.md 3.3), so an
//! error carries a class name. Messages the Python code raises itself
//! (`ValueError("host is required")`, …) are reproduced verbatim with the
//! Python class; errors of the interpreter or a library (a `KeyError`, an
//! unhashable value, an OS error) carry the Python class or a stable Rust
//! category and a message of our own (PLAN.md 4.2 item 5).

use std::fmt;
use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyError {
    pub class: &'static str,
    pub message: String,
}

impl PyError {
    pub fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    pub fn value(message: impl Into<String>) -> Self {
        Self::new("ValueError", message)
    }

    pub fn type_error(message: impl Into<String>) -> Self {
        Self::new("TypeError", message)
    }

    /// `KeyError(key)`: Python prints the key's repr.
    pub fn key(key: &str) -> Self {
        Self::new("KeyError", format!("'{key}'"))
    }

    /// An OS error under the Python class for its kind (`FileNotFoundError`,
    /// `PermissionError`, …, else `OSError`); the message is Rust's.
    pub fn os(error: &io::Error) -> Self {
        let class = match error.kind() {
            io::ErrorKind::NotFound => "FileNotFoundError",
            io::ErrorKind::PermissionDenied => "PermissionError",
            io::ErrorKind::IsADirectory => "IsADirectoryError",
            io::ErrorKind::NotADirectory => "NotADirectoryError",
            io::ErrorKind::AlreadyExists => "FileExistsError",
            io::ErrorKind::Interrupted => "InterruptedError",
            _ => "OSError",
        };
        Self::new(class, error.to_string())
    }
}

impl fmt::Display for PyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class, self.message)
    }
}

impl std::error::Error for PyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_class_and_message() {
        assert_eq!(
            PyError::value("host is required").to_string(),
            "ValueError: host is required"
        );
        assert_eq!(PyError::key("traefik").to_string(), "KeyError: 'traefik'");
    }

    #[test]
    fn os_errors_use_the_python_class_of_their_kind() {
        let missing = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(PyError::os(&missing).class, "FileNotFoundError");
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(PyError::os(&denied).class, "PermissionError");
        let other = io::Error::other("boom");
        assert_eq!(PyError::os(&other).class, "OSError");
    }
}
