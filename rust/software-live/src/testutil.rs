//! Helpers shared by the fixture tests (`fixtures/*.json`, written by
//! `fixtures/generate.py` from the Python oracle).

use serde::Deserialize;
use serde_json::Value;

use crate::error::PyError;

/// A Python exception as a fixture records it: the class always; the
/// message only where the Python code raises it itself (`own`), since the
/// interpreter's texts differ between Python versions and are not part of
/// the contract (PLAN.md 4.2 item 5).
#[derive(Clone, Debug, Deserialize)]
pub struct ErrorSpec {
    pub class: String,
    #[serde(default)]
    pub message: Option<String>,
}

impl ErrorSpec {
    pub fn assert_matches(&self, error: &PyError, id: &str) {
        assert_eq!(error.class, self.class, "{id}: {error}");
        if let Some(message) = &self.message {
            assert_eq!(&error.message, message, "{id}");
        }
    }
}

/// JSON equality where numbers compare by value: integers by their
/// canonical text, other numbers as `f64` (Python and Rust may spell the
/// same float differently, PLAN.md 4.2 item 3).
pub fn json_eq(left: &Value, right: &Value) -> bool {
    use crate::pyjson::{canonical_int, is_int_token, token_f64};
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            let (a, b) = (a.as_str(), b.as_str());
            match (is_int_token(a), is_int_token(b)) {
                (true, true) => canonical_int(a) == canonical_int(b),
                (false, false) => token_f64(a).to_bits() == token_f64(b).to_bits(),
                _ => false,
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| json_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((ka, va), (kb, vb))| ka == kb && json_eq(va, vb))
        }
        _ => left == right,
    }
}
