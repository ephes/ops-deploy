//! Python-compatible JSON (PLAN.md 4.2.5, D-4, D-5).
//!
//! The Python endpoints serve `json.dumps(json.loads(<file>), sort_keys=True)`.
//! This module reproduces those bytes from a `serde_json::Value`:
//!
//! - keys sorted at every level: `serde_json`'s default map is a `BTreeMap`,
//!   which orders by UTF-8 bytes = code points, as Python sorts `str` keys;
//! - separators `", "` and `": "`;
//! - `ensure_ascii`: everything outside printable ASCII (`' '..='~'`) as
//!   `\uXXXX` (lowercase hex, astral characters as surrogate pairs), the short
//!   escapes `\" \\ \n \r \t \b \f`;
//! - Python's number round trip: an int lexeme (no `.`, `e`, `E`) verbatim at
//!   any size (`arbitrary_precision` keeps the lexeme) except `-0` → `0`;
//!   every other lexeme is a Python `float`, written as `float.__repr__`.
//!
//! [`parse`] is the input side: `serde_json` plus the checks where Python's
//! `json.loads` result would differ or fail (D-4, D-5): non-finite floats
//! (`1e400`), int lexemes longer than CPython's `int_max_str_digits` (4300).
//!
//! It also holds the Python value semantics the modes need: truthiness
//! (`bool(v)`), `isinstance(v, int)`, exact ints for arithmetic and the `in`
//! operator with a `str` needle.

use std::fmt;
use std::io;

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, Serializer};
use serde_json::{Number, Value};

/// CPython's default `sys.int_info.default_max_str_digits`: `int()` of a
/// longer digit string raises `ValueError` (sign not counted).
pub const INT_MAX_STR_DIGITS: usize = 4300;

/// Why an input document is not served (all map to 502 `invalid_json`).
#[derive(Debug)]
pub enum ParseError {
    /// `serde_json` refused the text: syntax, invalid UTF-8, lone
    /// surrogates, `NaN`/`Infinity` tokens, nesting deeper than 128.
    Syntax(serde_json::Error),
    /// A float lexeme that overflows `f64` (Python: `inf`, served as
    /// `Infinity`).
    NonFinite(String),
    /// An int lexeme with more than [`INT_MAX_STR_DIGITS`] digits, anywhere
    /// in the text (also a value a later duplicate key replaces: Python
    /// converts every token).
    IntTooLong(usize),
    /// An object key equal to `serde_json`'s internal number marker, which
    /// `arbitrary_precision` would read as a number instead of an object.
    ReservedKey,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "{error}"),
            // Not the lexeme: the text goes to the log (D-9: no file content).
            Self::NonFinite(_) => write!(f, "number out of range (overflows to infinity)"),
            Self::IntTooLong(digits) => write!(
                f,
                "integer has {digits} digits, more than the limit of {INT_MAX_STR_DIGITS}"
            ),
            Self::ReservedKey => write!(f, "object key {NUMBER_TOKEN:?} is not supported"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses a document as Python's `json.loads` would, refusing what Python
/// would accept differently (D-4) or not at all (D-5).
pub fn parse(bytes: &[u8]) -> Result<Value, ParseError> {
    let value: Value = serde_json::from_slice(bytes).map_err(ParseError::Syntax)?;
    // The text is valid JSON now, so the token scan below sees exactly the
    // tokens serde_json saw, including the ones duplicate keys dropped.
    scan_tokens(bytes)?;
    check_floats(&value)?;
    Ok(value)
}

/// The key `serde_json` (`arbitrary_precision`) uses to carry a number
/// through serde; an object with this single key deserialises as a number.
const NUMBER_TOKEN: &str = "$serde_json::private::Number";

/// Walks the tokens of a valid JSON text: every int lexeme must be within
/// CPython's digit limit (Python's `int()` raises for any token, even one a
/// later duplicate key replaces), and no object key may be
/// [`NUMBER_TOKEN`] (D-4: refused, since `serde_json` cannot keep it).
/// Strings are only delimited here; their content is decoded by
/// `serde_json`.
fn scan_tokens(bytes: &[u8]) -> Result<(), ParseError> {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let mut end = i + 1;
                while end < bytes.len() && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let end = end.min(bytes.len() - 1);
                let token = &bytes[i..=end];
                let next = bytes[end + 1..]
                    .iter()
                    .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'));
                if next == Some(&b':')
                    && token.len() >= NUMBER_TOKEN.len() + 2
                    && serde_json::from_slice::<String>(token).is_ok_and(|key| key == NUMBER_TOKEN)
                {
                    return Err(ParseError::ReservedKey);
                }
                i = end + 1;
            }
            b'-' | b'0'..=b'9' => {
                let mut end = i;
                while end < bytes.len()
                    && matches!(bytes[end], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    end += 1;
                }
                let lexeme = &bytes[i..end];
                if !lexeme.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                    let digits = lexeme.iter().filter(|b| b.is_ascii_digit()).count();
                    if digits > INT_MAX_STR_DIGITS {
                        return Err(ParseError::IntTooLong(digits));
                    }
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Float lexemes of the parsed value must be finite (D-4). Only the values
/// that survive duplicate keys matter: Python accepts an overflowing float
/// it then drops.
fn check_floats(value: &Value) -> Result<(), ParseError> {
    // An explicit stack: serde_json already bounds the depth at 128, but the
    // walk does not rely on it.
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Number(number) => {
                let lexeme = number.as_str();
                if !is_int_lexeme(lexeme) && !lexeme.parse::<f64>().is_ok_and(f64::is_finite) {
                    return Err(ParseError::NonFinite(lexeme.to_owned()));
                }
            }
            Value::Array(items) => stack.extend(items),
            Value::Object(map) => stack.extend(map.values()),
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

/// `json.dumps(value, sort_keys=True)` as bytes.
pub fn dumps(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let mut serializer = Serializer::with_formatter(&mut out, PyFormatter);
    // Writing to a Vec cannot fail, and a Value always serialises.
    value
        .serialize(&mut serializer)
        .expect("serialising JSON into memory");
    out
}

/// A JSON number lexeme without fraction or exponent: a Python `int`.
pub fn is_int_lexeme(lexeme: &str) -> bool {
    !lexeme.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
}

/// The bytes Python writes for a number lexeme after `json.loads`.
fn python_number(lexeme: &str) -> String {
    if is_int_lexeme(lexeme) {
        if lexeme == "-0" {
            "0".to_owned()
        } else {
            lexeme.to_owned()
        }
    } else {
        // `parse` refused non-finite lexemes; a Number built from an f64 is
        // finite by construction.
        float_repr(lexeme.parse().unwrap_or(f64::NAN))
    }
}

/// `repr(x)` of a Python `float` (`float.__repr__`, `PyOS_double_to_string`
/// with mode `'r'` and `Py_DTSF_ADD_DOT_0`).
///
/// Digits: the shortest string that round-trips, and among equally short
/// ones the one closest to the exact binary value (David Gay `dtoa` mode 0).
/// Rust's shortest `{:e}` has the right length but may pick the other
/// candidate, so the exact value correctly rounded to that many digits wins
/// when it round-trips (PLAN.md D-5). Layout: fixed-point with at least one
/// fractional digit for decimal exponents −4 ≤ e < 16, else
/// `d[.ddd]e±XX`.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".to_owned();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let (negative, mut digits, mut exp) = split_sci(&format!("{x:e}"));
    let rounded = format!("{:.*e}", digits.len() - 1, x);
    if rounded.parse::<f64>() == Ok(x) {
        (_, digits, exp) = split_sci(&rounded);
    }
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let mut out = String::with_capacity(digits.len() + 8);
    if negative {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let int_len = usize::try_from(exp).unwrap_or(0) + 1;
            if digits.len() <= int_len {
                out.push_str(&digits);
                out.extend(std::iter::repeat_n('0', int_len - digits.len()));
                out.push_str(".0");
            } else {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            }
        } else {
            out.push_str("0.");
            let zeros = usize::try_from(-exp - 1).unwrap_or(0);
            out.extend(std::iter::repeat_n('0', zeros));
            out.push_str(&digits);
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exp.unsigned_abs()));
    }
    out
}

/// Splits Rust's `{:e}` output (`-1.2345e-7`) into sign, digit string and
/// decimal exponent.
fn split_sci(sci: &str) -> (bool, String, i32) {
    let (negative, rest) = match sci.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, sci),
    };
    let (mantissa, exp) = rest.split_once('e').unwrap_or((rest, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    (negative, digits, exp.parse().unwrap_or(0))
}

/// The `serde_json` formatter that writes Python's `json.dumps` layout.
#[derive(Clone, Copy, Debug, Default)]
pub struct PyFormatter;

impl Formatter for PyFormatter {
    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        writer.write_all(float_repr(value).as_bytes())
    }

    fn write_f32<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        self.write_f64(writer, f64::from(value))
    }

    fn write_number_str<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        value: &str,
    ) -> io::Result<()> {
        writer.write_all(python_number(value).as_bytes())
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (index, ch) in fragment.char_indices() {
            if (' '..='~').contains(&ch) {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..index])?;
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            start = index + ch.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        char_escape: CharEscape,
    ) -> io::Result<()> {
        let escape: &[u8] = match char_escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(byte) => return write!(writer, "\\u{byte:04x}"),
        };
        writer.write_all(escape)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }
}

/// A Python `int` value of a JSON document, for arithmetic (D-5: exact).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyInt {
    Value(i128),
    /// An int lexeme outside `i128`: never used for a computed number.
    OutOfRange,
}

/// `isinstance(v, int)`: an int lexeme or a boolean (`bool` subclasses
/// `int`); floats such as `1e9` or `5.0` are not.
pub fn is_py_int(value: &Value) -> bool {
    match value {
        Value::Bool(_) => true,
        Value::Number(number) => is_int_lexeme(number.as_str()),
        _ => false,
    }
}

/// The value of a Python `int` (`True` = 1), `None` for anything else.
pub fn py_int(value: &Value) -> Option<PyInt> {
    match value {
        Value::Bool(flag) => Some(PyInt::Value(i128::from(*flag))),
        Value::Number(number) if is_int_lexeme(number.as_str()) => Some(
            number
                .as_str()
                .parse::<i128>()
                .map_or(PyInt::OutOfRange, PyInt::Value),
        ),
        _ => None,
    }
}

/// `bool(v)` (Python truthiness).
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number_is_nonzero(number),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn number_is_nonzero(number: &Number) -> bool {
    let lexeme = number.as_str();
    if is_int_lexeme(lexeme) {
        lexeme.bytes().any(|b| matches!(b, b'1'..=b'9'))
    } else {
        lexeme.parse::<f64>() != Ok(0.0)
    }
}

/// The `TypeError` of `needle in haystack` for a haystack that is not a
/// container (`argument of type 'int' is not iterable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotIterable(pub &'static str);

impl fmt::Display for NotIterable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "argument of type '{}' is not iterable", self.0)
    }
}

impl std::error::Error for NotIterable {}

/// Python's `needle in haystack` for a `str` needle: list element equality,
/// substring for a string, key membership for an object; a `TypeError` for
/// numbers, booleans and `None`.
pub fn contains_str(haystack: &Value, needle: &str) -> Result<bool, NotIterable> {
    match haystack {
        Value::Array(items) => Ok(items
            .iter()
            .any(|item| matches!(item, Value::String(text) if text == needle))),
        Value::String(text) => Ok(text.contains(needle)),
        Value::Object(map) => Ok(map.contains_key(needle)),
        Value::Null => Err(NotIterable("NoneType")),
        Value::Bool(_) => Err(NotIterable("bool")),
        Value::Number(number) if is_int_lexeme(number.as_str()) => Err(NotIterable("int")),
        Value::Number(_) => Err(NotIterable("float")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roundtrip(input: &str) -> String {
        String::from_utf8(dumps(&parse(input.as_bytes()).unwrap())).unwrap()
    }

    #[test]
    fn plan_d5_float_cases() {
        for (input, expected) in [
            ("1e2", "100.0"),
            ("1.00", "1.0"),
            ("9007199254740993.0", "9007199254740992.0"),
            ("1e16", "1e+16"),
            ("0.0001", "0.0001"),
            ("0.00001", "1e-05"),
            ("-0.0", "-0.0"),
            ("181703637716804.125", "181703637716804.12"),
            ("-0", "0"),
            ("1e-400", "0.0"),
            ("-1e-400", "-0.0"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            (
                "123456789012345678901234567890",
                "123456789012345678901234567890",
            ),
        ] {
            assert_eq!(roundtrip(input), expected, "{input}");
        }
    }

    #[test]
    fn layout_follows_python() {
        let value = json!({"b": [1, "é😀\u{7f}\"\\\n\u{1}"], "a": {}, "c": []});
        assert_eq!(
            String::from_utf8(dumps(&value)).unwrap(),
            r#"{"a": {}, "b": [1, "\u00e9\ud83d\ude00\u007f\"\\\n\u0001"], "c": []}"#
        );
        assert_eq!(String::from_utf8(dumps(&json!(12.0))).unwrap(), "12.0");
    }

    #[test]
    fn refused_inputs() {
        for input in [
            "NaN",
            "Infinity",
            "-Infinity",
            "1e400",
            "[-1e309]",
            r#""\ud800""#,
            "{\"a\": 1,}",
        ] {
            assert!(parse(input.as_bytes()).is_err(), "{input}");
        }
        let limit = "9".repeat(INT_MAX_STR_DIGITS);
        assert!(parse(limit.as_bytes()).is_ok());
        assert!(parse(format!("-{limit}").as_bytes()).is_ok());
        assert!(matches!(
            parse(format!("{limit}9").as_bytes()),
            Err(ParseError::IntTooLong(4301))
        ));
        // Python converts every token, also one a duplicate key replaces.
        assert!(matches!(
            parse(format!("{{\"a\": {limit}9, \"a\": 1}}").as_bytes()),
            Err(ParseError::IntTooLong(4301))
        ));
        // A long digit run inside a string is not a number.
        assert!(parse(format!("{{\"{limit}9\": \"{limit}9\"}}").as_bytes()).is_ok());
        // A dropped overflowing float is accepted, as by Python.
        assert!(parse(b"{\"a\": 1e400, \"a\": 1}").is_ok());
        // serde_json reads this object as the number 2.5 (or refuses it,
        // for a value that is not a number): refused either way.
        assert!(matches!(
            parse(br#"{"a": {"$serde_json::private::Number": "2.5"}}"#),
            Err(ParseError::ReservedKey)
        ));
        assert!(matches!(
            parse(br#"{"a": {"\u0024serde_json::private::Number" : "1"}}"#),
            Err(ParseError::ReservedKey)
        ));
        assert!(parse(br#"{"$serde_json::private::Number": "x"}"#).is_err());
        assert!(parse(br#"["$serde_json::private::Number"]"#).is_ok());
    }

    #[test]
    fn python_value_semantics() {
        let v = |text: &str| parse(text.as_bytes()).unwrap();
        assert!(is_py_int(&v("true")) && is_py_int(&v("-3")));
        assert!(!is_py_int(&v("1e9")) && !is_py_int(&v("5.0")) && !is_py_int(&v("\"1\"")));
        assert_eq!(py_int(&v("true")), Some(PyInt::Value(1)));
        assert_eq!(py_int(&v(&"9".repeat(60))), Some(PyInt::OutOfRange));
        assert_eq!(py_int(&v("1.0")), None);
        for (text, expected) in [
            ("0", false),
            ("-0", false),
            ("0.0", false),
            ("1e-400", false),
            ("0.5", true),
            ("\"\"", false),
            ("[]", false),
            ("{}", false),
            ("null", false),
            ("[0]", true),
        ] {
            assert_eq!(truthy(&v(text)), expected, "{text}");
        }
        assert_eq!(
            contains_str(&v("[\"stale_kernel\"]"), "stale_kernel"),
            Ok(true)
        );
        assert_eq!(
            contains_str(&v("\"xstale_kernelx\""), "stale_kernel"),
            Ok(true)
        );
        assert_eq!(
            contains_str(&v("{\"stale_kernel\": 0}"), "stale_kernel"),
            Ok(true)
        );
        assert_eq!(
            contains_str(&v("[[\"stale_kernel\"]]"), "stale_kernel"),
            Ok(false)
        );
        assert_eq!(contains_str(&v("3"), "x"), Err(NotIterable("int")));
    }
}
