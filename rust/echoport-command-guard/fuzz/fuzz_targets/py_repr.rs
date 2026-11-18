//! Python's `repr` for the log lines on arbitrary bytes (PLAN.md 7.4, target
//! `py_repr`): no panic, and the result is one quoted printable-ASCII string
//! (no control character reaches the log, PLAN.md 4.3).
#![no_main]

use echoport_command_guard::repr::{py_repr, py_repr_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let repr = py_repr_bytes(data);
    assert!(repr.len() >= 2, "{repr:?}");
    assert!(
        repr.bytes().all(|b| (b' '..=b'~').contains(&b)),
        "{data:?} gave {repr:?}"
    );
    let quote = repr.as_bytes()[0];
    assert!(quote == b'\'' || quote == b'"', "{repr:?}");
    assert_eq!(repr.as_bytes()[repr.len() - 1], quote, "{repr:?}");
    if let Ok(text) = std::str::from_utf8(data) {
        assert_eq!(py_repr(text), repr, "{text:?}");
    }
});
