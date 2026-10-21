//! `version()` and `numeric_version()` of `software_live.py:33-44`: release
//! numbers as tuples of unbounded integers, compared element by element
//! (a shorter tuple that is a prefix of a longer one is less).
//!
//! Digits are ASCII only, where Python's `\d` and `int()` also accept other
//! Unicode decimal digits (PLAN.md 4.2 item 11). Whitespace is Python's
//! (`str.strip()` and `\s`), which is Unicode `White_Space` plus the
//! separators U+001C..U+001F.

use std::cmp::Ordering;
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;

use crate::error::PyError;
use crate::pyjson::{INT_MAX_STR_DIGITS, int_digits_error};

/// A non-negative integer of any size, kept as its canonical decimal digits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Int(String);

impl Int {
    /// `int(digits)` for a non-empty string of ASCII digits: more than
    /// 4300 digits (leading zeros count) is Python's `ValueError`.
    fn from_digits(digits: &str) -> Result<Self, PyError> {
        debug_assert!(!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
        if digits.len() > INT_MAX_STR_DIGITS {
            return Err(int_digits_error(digits.len()));
        }
        let trimmed = digits.trim_start_matches('0');
        Ok(Self(
            if trimmed.is_empty() { "0" } else { trimmed }.to_owned(),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Ord for Int {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A release number; `Vec`'s ordering is Python's tuple ordering.
pub type Release = Vec<Int>;

/// Python's `str.isspace()`, which is also what `\s` matches in a `str`
/// pattern and what `str.strip()` removes.
pub fn is_python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()` without arguments.
pub fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$").expect("valid pattern"));

// `\s` plus U+001C..U+001F is Python's `\s`; `.` excludes only `\n` in both.
static NUMERIC_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9]+(?:\.[0-9]+)+)(?:[\s\x1c-\x1f]+.*)?$").expect("valid pattern")
});

/// `version(value)`: `v?N.N.N`, exactly.
pub fn version(value: &str) -> Result<Release, PyError> {
    let captures = VERSION
        .captures(value)
        .ok_or_else(|| PyError::value("unsupported version"))?;
    (1..=3)
        .map(|group| Int::from_digits(&captures[group]))
        .collect()
}

/// `numeric_version(value)`: `N.N[.N…]` after stripping, optionally followed
/// by whitespace and a suffix without line breaks.
pub fn numeric_version(value: &str) -> Result<Release, PyError> {
    let captures = NUMERIC_VERSION
        .captures(python_strip(value))
        .ok_or_else(|| PyError::value("unsupported numeric version"))?;
    captures[1].split('.').map(Int::from_digits).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ErrorSpec;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixtures {
        python_whitespace: Vec<u32>,
        cases: Vec<Case>,
        comparisons: Vec<Comparison>,
    }

    #[derive(Deserialize)]
    struct Case {
        function: String,
        input: String,
        result: Option<Vec<String>>,
        error: Option<ErrorSpec>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Deserialize)]
    struct Comparison {
        function: String,
        left: String,
        right: String,
        ordering: String,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/version.json")).unwrap()
    }

    fn call(function: &str, input: &str) -> Result<Release, PyError> {
        match function {
            "version" => version(input),
            "numeric_version" => numeric_version(input),
            other => panic!("unknown function {other}"),
        }
    }

    #[test]
    fn parsing_matches_python() {
        let cases = fixtures().cases;
        assert!(cases.len() >= 40);
        for case in cases {
            let id = format!("{}({:?})", case.function, case.input);
            let result = call(&case.function, &case.input);
            if let Some(tag) = &case.p3 {
                // PLAN.md 4.2 item 11: Python accepts non-ASCII digits.
                assert_eq!(tag, "unicode-digits", "{id}");
                assert!(
                    case.result.is_some(),
                    "{id}: P3 case must be one Python accepts"
                );
                assert_eq!(result.unwrap_err().class, "ValueError", "{id}");
                continue;
            }
            match (&case.result, &case.error) {
                (Some(expected), None) => {
                    let parts: Vec<_> = result
                        .unwrap_or_else(|e| panic!("{id}: {e}"))
                        .iter()
                        .map(|i| i.to_string())
                        .collect();
                    assert_eq!(&parts, expected, "{id}");
                }
                (None, Some(expected)) => expected.assert_matches(&result.unwrap_err(), &id),
                _ => panic!("{id}: fixture needs a result or an error"),
            }
        }
    }

    #[test]
    fn comparisons_match_python() {
        let comparisons = fixtures().comparisons;
        assert!(comparisons.len() >= 10);
        for case in comparisons {
            let left = call(&case.function, &case.left).unwrap();
            let right = call(&case.function, &case.right).unwrap();
            let ordering = match left.cmp(&right) {
                Ordering::Less => "lt",
                Ordering::Equal => "eq",
                Ordering::Greater => "gt",
            };
            assert_eq!(
                ordering, case.ordering,
                "{:?} vs {:?}",
                case.left, case.right
            );
        }
    }

    #[test]
    fn whitespace_is_pythons() {
        let expected = fixtures().python_whitespace;
        let actual: Vec<u32> = (0..=0x10FFFFu32)
            .filter_map(char::from_u32)
            .filter(|c| is_python_space(*c))
            .map(u32::from)
            .collect();
        assert_eq!(actual, expected);
        // The regex class agrees with the predicate.
        let class = Regex::new(r"^[\s\x1c-\x1f]$").unwrap();
        for c in (0..=0x10FFFFu32).filter_map(char::from_u32) {
            assert_eq!(
                class.is_match(c.encode_utf8(&mut [0; 4])),
                is_python_space(c),
                "{c:?}"
            );
        }
    }

    #[test]
    fn numbers_are_unbounded() {
        let big = version("99999999999999999999999999.0.0").unwrap();
        let bigger = version("100000000000000000000000000.0.0").unwrap();
        assert!(big < bigger);
        assert_eq!(version("v007.08.0009").unwrap(), version("7.8.9").unwrap());
    }
}
