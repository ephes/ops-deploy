//! JSON the way `software_live.py` reads and hashes it (PLAN.md 3.2).
//!
//! - [`loads`] parses losslessly (`serde_json` with `arbitrary_precision`:
//!   every number keeps its JSON text, so `18446744073709551617` is never
//!   rounded) and applies the integer limit of Python's `json.loads` (more
//!   than 4300 digits is a `ValueError`). Like every reader of this crate it
//!   rejects what Python accepts but standard JSON does not (`NaN`,
//!   `Infinity`, lone surrogate escapes) and nesting deeper than serde_json's
//!   limit of 128 (PLAN.md 4.2 item 4).
//! - [`python_dumps`] is byte-identical to `json.dumps(value, sort_keys=True)`:
//!   separators `", "` and `": "`, `ensure_ascii` escaping with surrogate
//!   pairs, integers as canonical decimals and every other number as
//!   Python's float `repr`. It is the input of `policy_sha256`.
//! - [`dumps_compact`] is what this program writes (caches, state,
//!   projection): sorted keys, compact separators (PLAN.md 4.2 item 3),
//!   `ensure_ascii` escaping as Python's `json.dump`, so a Python reader
//!   decodes it whatever its locale, and every number as the JSON text it
//!   was read or created with (never rounded).
//! - [`float_repr`], [`py_str`], [`type_name`] and [`eq_int`] give the
//!   Python view of a JSON value where `validate_policy` and
//!   `with_freshness` depend on it.

use std::fmt;
use std::io;
use std::str::FromStr;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::ser::{CharEscape, Formatter};
use serde_json::value::RawValue;
use serde_json::{Map, Number, Value};

use crate::error::PyError;

/// Python's default `sys.get_int_max_str_digits()`: `int()` of a longer
/// decimal string (the sign does not count) raises `ValueError`.
pub const INT_MAX_STR_DIGITS: usize = 4300;

/// The deepest nesting of arrays and objects [`loads`] accepts (PLAN.md
/// 4.2 item 4; Python's limit is its interpreter's recursion limit).
pub const MAX_DEPTH: usize = 128;

fn decode_error(error: serde_json::Error) -> PyError {
    PyError::new("JSONDecodeError", error.to_string())
}

/// `json.loads(text)` for the JSON this program reads.
///
/// The text is taken apart level by level through `RawValue`, never through
/// `Value`'s own deserializer: with `arbitrary_precision` that deserializer
/// reads an object whose only key is serde_json's internal number token
/// (`{"$serde_json::private::Number": "7"}`) as the number 7, while Python
/// keeps the object. Every number token is checked as it is read, including
/// one a later duplicate key replaces (Python converts it before the
/// replacement).
pub fn loads(text: &str) -> Result<Value, PyError> {
    let raw: &RawValue = serde_json::from_str(text).map_err(decode_error)?;
    convert(raw, 0)
}

/// `json.loads(raw)` of bytes: UTF-8, with a UTF-8 byte order mark dropped
/// (Python decodes such bytes as `utf-8-sig`). Python also detects UTF-16
/// and UTF-32 and decodes UTF-8 with `surrogatepass`; this program refuses
/// both (PLAN.md 4.2 item 4). Its own writers write ASCII.
pub fn loads_bytes(raw: &[u8]) -> Result<Value, PyError> {
    let raw = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(raw)
        .map_err(|error| PyError::new("UnicodeDecodeError", error.to_string()))?;
    loads(text)
}

/// The members of a JSON object in text order, duplicates included.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de: 'a, 'a> Deserialize<'de> for Members<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MembersVisitor;
        impl<'de> Visitor<'de> for MembersVisitor {
            type Value = Members<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = access.next_entry::<String, &'de RawValue>()? {
                    members.push(member);
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(MembersVisitor)
    }
}

fn convert(raw: &RawValue, depth: usize) -> Result<Value, PyError> {
    let text = raw.get();
    let container = |depth: usize| {
        if depth >= MAX_DEPTH {
            Err(PyError::value(format!(
                "JSON nested deeper than {MAX_DEPTH} levels"
            )))
        } else {
            Ok(depth + 1)
        }
    };
    match text.as_bytes().first() {
        Some(b'{') => {
            let inner = container(depth)?;
            let members: Members<'_> = serde_json::from_str(text).map_err(decode_error)?;
            let mut map = Map::new();
            for (key, value) in members.0 {
                // The last duplicate wins, as in Python.
                map.insert(key, convert(value, inner)?);
            }
            Ok(Value::Object(map))
        }
        Some(b'[') => {
            let inner = container(depth)?;
            let items: Vec<&RawValue> = serde_json::from_str(text).map_err(decode_error)?;
            items
                .into_iter()
                .map(|item| convert(item, inner))
                .collect::<Result<_, _>>()
                .map(Value::Array)
        }
        Some(b'"') => serde_json::from_str::<String>(text)
            .map(Value::String)
            .map_err(decode_error),
        _ => match text {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            "null" => Ok(Value::Null),
            token => {
                check_int_digits(token)?;
                Number::from_str(token)
                    .map(Value::Number)
                    .map_err(decode_error)
            }
        },
    }
}

fn check_int_digits(token: &str) -> Result<(), PyError> {
    if is_int_token(token) {
        let digits = token.trim_start_matches('-').len();
        if digits > INT_MAX_STR_DIGITS {
            return Err(int_digits_error(digits));
        }
    }
    Ok(())
}

/// Python's `ValueError` for an `int()` of more than 4300 digits.
pub fn int_digits_error(digits: usize) -> PyError {
    PyError::value(format!(
        "Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string \
         conversion: value has {digits} digits"
    ))
}

/// A JSON number token that Python reads as `int` (no fraction, no exponent).
pub fn is_int_token(token: &str) -> bool {
    !token.contains(['.', 'e', 'E'])
}

/// Whether Python reads this value as an `int` (not `bool`, not `float`).
pub fn is_int(value: &Value) -> bool {
    matches!(value, Value::Number(number) if is_int_token(number.as_str()))
}

/// The canonical decimal of an integer token as Python's `repr(int)` writes
/// it. JSON allows no leading zeros, so only `-0` needs a change.
pub fn canonical_int(token: &str) -> &str {
    if token.trim_start_matches('-').bytes().all(|b| b == b'0') {
        "0"
    } else {
        token
    }
}

/// The value of a number token as Python's `float()` (correctly rounded;
/// out of range gives an infinity).
pub fn token_f64(token: &str) -> f64 {
    // A serde_json number token is always valid Rust float syntax.
    token.parse().unwrap_or(f64::NAN)
}

/// The value of an integer token, if it fits.
pub fn token_i128(token: &str) -> Option<i128> {
    if is_int_token(token) {
        token.parse().ok()
    } else {
        None
    }
}

/// Python's `repr(float)` (as used by `json.dumps`, which writes `NaN`,
/// `Infinity` and `-Infinity` for the non-finite values): the shortest
/// round-trip digits, positional for exponents in [-4, 16), else `d.ddde±XX`.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    // ryu gives the shortest digits that round-trip and, like Python's
    // dtoa, breaks an exact tie to the even digit (Rust's `{:e}` rounds it
    // up: -85917593882605.625 is `…605.62` in Python).
    let mut buffer = ryu::Buffer::new();
    let (digits, decpt) = decimal_digits(buffer.format_finite(value.abs()));
    let ndigits = digits.len() as i32;
    let mut out = String::new();
    if value.is_sign_negative() {
        out.push('-');
    }
    if !(-4 < decpt && decpt <= 16) {
        out.push_str(&digits[..1]);
        if ndigits > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let shown = decpt - 1;
        out.push('e');
        out.push(if shown < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", shown.abs()));
    } else if decpt <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-decpt) as usize));
        out.push_str(&digits);
    } else if decpt >= ndigits {
        out.push_str(&digits);
        out.push_str(&"0".repeat((decpt - ndigits) as usize));
        out.push_str(".0");
    } else {
        out.push_str(&digits[..decpt as usize]);
        out.push('.');
        out.push_str(&digits[decpt as usize..]);
    }
    out
}

/// The significant digits of a non-negative decimal text and the position
/// of the decimal point: `value = 0.<digits> × 10^decpt` (zero is `"0"`, 1).
fn decimal_digits(text: &str) -> (String, i32) {
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().unwrap_or(0)),
        None => (text, 0),
    };
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{integer}{fraction}");
    let significant = all.trim_start_matches('0');
    let leading = (all.len() - significant.len()) as i32;
    let digits = significant.trim_end_matches('0');
    if digits.is_empty() {
        return ("0".into(), 1);
    }
    (digits.into(), integer.len() as i32 + exponent - leading)
}

/// `json.dumps(value, sort_keys=True)`, byte for byte.
pub fn python_dumps(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, PythonFormatter);
    // Sorted keys: `serde_json::Map` is a `BTreeMap` (the `preserve_order`
    // feature is not enabled; a test fails if it ever is), and byte order of
    // UTF-8 is code point order, which is how Python sorts `str` keys.
    serde::Serialize::serialize(value, &mut serializer)
        .expect("serializing a JSON value into memory cannot fail");
    out
}

/// The `serde_json` formatter for [`python_dumps`].
struct PythonFormatter;

impl Formatter for PythonFormatter {
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
        if is_int_token(value) {
            writer.write_all(canonical_int(value).as_bytes())
        } else {
            writer.write_all(float_repr(token_f64(value)).as_bytes())
        }
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        write_ascii_fragment(writer, fragment)
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        write_python_escape(writer, escape)
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

/// `ensure_ascii`: serde_json escapes `"`, `\` and C0 controls itself
/// ([`write_python_escape`]); this also escapes DEL and everything beyond
/// ASCII, as UTF-16 units (surrogate pairs above U+FFFF).
fn write_ascii_fragment<W: ?Sized + io::Write>(writer: &mut W, fragment: &str) -> io::Result<()> {
    let mut start = 0;
    for (index, c) in fragment.char_indices() {
        if (' '..='~').contains(&c) {
            continue;
        }
        writer.write_all(&fragment.as_bytes()[start..index])?;
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            write!(writer, "\\u{unit:04x}")?;
        }
        start = index + c.len_utf8();
    }
    writer.write_all(&fragment.as_bytes()[start..])
}

/// The escapes of Python's `json` encoder for the characters serde_json
/// escapes itself.
fn write_python_escape<W: ?Sized + io::Write>(
    writer: &mut W,
    escape: CharEscape,
) -> io::Result<()> {
    let text: &[u8] = match escape {
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
    writer.write_all(text)
}

/// The JSON this program writes: sorted keys, compact separators, ASCII
/// only (`ensure_ascii`), numbers as their JSON text. Python's `json.loads`
/// reads it back to equal values (PLAN.md 4.2 item 3).
pub fn dumps_compact(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, CompactAsciiFormatter);
    serde::Serialize::serialize(value, &mut serializer)
        .expect("serializing a JSON value into memory cannot fail");
    out
}

/// The `serde_json` formatter for [`dumps_compact`]: serde_json's compact
/// layout, number tokens written as they are, strings as [`python_dumps`].
struct CompactAsciiFormatter;

impl Formatter for CompactAsciiFormatter {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        write_ascii_fragment(writer, fragment)
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        write_python_escape(writer, escape)
    }
}

/// Python's truth value of a JSON value (`bool(value)`): `None`, `False`,
/// zero, and empty strings, lists and dicts are false.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => {
            let token = number.as_str();
            if is_int_token(token) {
                canonical_int(token) != "0"
            } else {
                token_f64(token) != 0.0
            }
        }
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python's type name of a JSON value (`type(value).__name__`).
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if is_int_token(number.as_str()) => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `str(value)` where only its text matters for an ASCII-digit pattern:
/// strings, `None`, booleans and numbers as Python prints them. A list or a
/// dict gives its type in brackets, which no such pattern matches (Python's
/// `repr` of a container starts with `[` or `{` as well).
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(number) => {
            let token = number.as_str();
            if is_int_token(token) {
                canonical_int(token).into()
            } else {
                // str(float) is repr(float), except for the infinities.
                let value = token_f64(token);
                if value.is_infinite() {
                    if value > 0.0 { "inf" } else { "-inf" }.into()
                } else {
                    float_repr(value)
                }
            }
        }
        Value::String(text) => text.clone(),
        Value::Array(_) => "[list]".into(),
        Value::Object(_) => "{dict}".into(),
    }
}

/// Python's `value == number` for an `int` constant: ints by value, floats
/// numerically, and `bool` as the int it is (`False == 0`, `True == 1`).
pub fn eq_int(value: &Value, number: i64) -> bool {
    match value {
        Value::Bool(flag) => i64::from(*flag) == number,
        Value::Number(n) => {
            let token = n.as_str();
            if is_int_token(token) {
                token_i128(token) == Some(i128::from(number))
            } else {
                token_f64(token) == number as f64
            }
        }
        _ => false,
    }
}

/// A finite `f64` as a JSON number (shortest round-trip text).
pub fn number_from_f64(value: f64) -> Option<Number> {
    Number::from_f64(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixtures {
        dumps: Vec<DumpsCase>,
        loads: Vec<LoadsCase>,
        floats: Vec<FloatCase>,
        py_str: Vec<PyStrCase>,
    }

    #[derive(Deserialize)]
    struct DumpsCase {
        id: String,
        text: String,
        dumps: String,
    }

    #[derive(Deserialize)]
    struct LoadsCase {
        id: String,
        text: String,
        error: Option<crate::testutil::ErrorSpec>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Deserialize)]
    struct FloatCase {
        bits: String,
        repr: String,
    }

    #[derive(Deserialize)]
    struct PyStrCase {
        text: String,
        str: String,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/pyjson.json")).unwrap()
    }

    #[test]
    fn dumps_matches_python() {
        let cases = fixtures().dumps;
        assert!(cases.len() >= 20);
        for case in cases {
            let value = loads(&case.text).unwrap_or_else(|e| panic!("{}: {e}", case.id));
            let dumped = String::from_utf8(python_dumps(&value)).unwrap();
            assert_eq!(dumped, case.dumps, "{}", case.id);
        }
    }

    #[test]
    fn loads_accepts_and_rejects_like_python() {
        for case in fixtures().loads {
            let result = loads(&case.text);
            match (&case.p3, &case.error) {
                // PLAN.md 4.2 item 4: Python accepts it, Rust rejects it.
                (Some(_), None) => assert!(result.is_err(), "{}: must be rejected", case.id),
                (Some(tag), Some(_)) => panic!("{}: P3 tag {tag} on a Python error", case.id),
                (None, None) => {
                    result.unwrap_or_else(|e| panic!("{}: {e}", case.id));
                }
                (None, Some(expected)) => {
                    let error = result.expect_err(&case.id);
                    expected.assert_matches(&error, &case.id);
                }
            }
        }
    }

    #[test]
    fn float_repr_matches_python() {
        let cases = fixtures().floats;
        assert!(cases.len() >= 1000);
        for case in cases {
            let bits = u64::from_str_radix(&case.bits, 16).unwrap();
            assert_eq!(float_repr(f64::from_bits(bits)), case.repr, "{}", case.bits);
        }
    }

    #[test]
    fn py_str_matches_python_for_scalars() {
        for case in fixtures().py_str {
            let value = loads(&case.text).unwrap();
            assert_eq!(py_str(&value), case.str, "{}", case.text);
        }
    }

    #[test]
    fn numbers_keep_their_json_text() {
        let value = loads(r#"[18446744073709551617, -0, 1E2, 1e400, 0.1]"#).unwrap();
        let tokens: Vec<_> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_number().unwrap().as_str().to_owned())
            .collect();
        // serde_json normalises the exponent spelling, never the digits.
        assert_eq!(
            tokens,
            ["18446744073709551617", "-0", "1e+2", "1e+400", "0.1"]
        );
    }

    #[test]
    fn keys_are_sorted_whatever_the_insertion_order() {
        let mut map = serde_json::Map::new();
        for key in ["b", "\u{e9}", "a", "B", "\u{1F600}", "aa"] {
            map.insert(key.into(), Value::Null);
        }
        let dumped = String::from_utf8(python_dumps(&Value::Object(map))).unwrap();
        assert_eq!(
            dumped,
            concat!(
                r#"{"B": null, "a": null, "aa": null, "b": null, "#,
                r#""\u00e9": null, "\ud83d\ude00": null}"#
            )
        );
    }

    #[test]
    fn eq_int_follows_python_equality() {
        let two = |text: &str| eq_int(&loads(text).unwrap(), 2);
        assert!(two("2") && two("2.0") && two("2e0") && two("2.0000000000000001"));
        assert!(!two("true") && !two("\"2\"") && !two("null") && !two("3"));
        assert!(eq_int(&Value::Bool(false), 0) && eq_int(&Value::Bool(true), 1));
        assert!(!two("18446744073709551617"));
    }

    #[test]
    fn serde_jsons_number_token_is_an_ordinary_key() {
        let text =
            r#"{"$serde_json::private::Number": "7", "n": {"$serde_json::private::Number": 7}}"#;
        let value = loads(text).unwrap();
        assert!(value.is_object());
        assert_eq!(value["$serde_json::private::Number"], "7");
        assert!(value["n"].is_object());
        assert_eq!(
            String::from_utf8(python_dumps(&value)).unwrap(),
            r#"{"$serde_json::private::Number": "7", "n": {"$serde_json::private::Number": 7}}"#
        );
    }

    #[test]
    fn a_replaced_duplicate_is_still_checked() {
        let text = format!(r#"{{"a": {}, "a": 0}}"#, "1".repeat(INT_MAX_STR_DIGITS + 1));
        assert_eq!(loads(&text).unwrap_err().class, "ValueError");
        assert_eq!(loads(r#"{"a": 1, "a": 2}"#).unwrap()["a"], 2);
    }

    #[test]
    fn nesting_limit() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(loads(&deep(MAX_DEPTH)).is_ok());
        assert!(loads(&deep(MAX_DEPTH + 1)).is_err());
    }

    #[test]
    fn integer_digit_limit_ignores_the_sign() {
        let ok = format!("-{}", "1".repeat(INT_MAX_STR_DIGITS));
        assert!(loads(&ok).is_ok());
        let too_long = "1".repeat(INT_MAX_STR_DIGITS + 1);
        assert_eq!(loads(&too_long).unwrap_err().class, "ValueError");
        // A float token of any length is converted, not refused.
        let float = format!("{}.0", "1".repeat(INT_MAX_STR_DIGITS + 1));
        assert!(loads(&float).is_ok());
    }
}
