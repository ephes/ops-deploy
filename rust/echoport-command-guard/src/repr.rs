//! Python's `repr()` of a `str`, as the guard's messages use it (PLAN.md 3.6,
//! 4.3).
//!
//! Exact for printable ASCII and tab, which is everything an accepted command
//! or a valid policy value consists of: the quote character is `'` unless the
//! text contains `'` and no `"`, and `\`, the chosen quote, tab, newline and
//! carriage return are escaped as Python escapes them. Everything else is
//! escaped, stricter than Python (which prints printable non-ASCII
//! literally): other control characters and DEL as `\xNN` (as Python does),
//! non-ASCII as `\xNN`, `\uNNNN` or `\UNNNNNNNN` by code point.
//! [`py_repr_bytes`] is the `repr` of bytes Python decoded with
//! `surrogateescape` (`SSH_ORIGINAL_COMMAND`): an undecodable byte is
//! `\udcNN`, as in Python.

use std::fmt::Write;

/// One unit of a Python `str`: a character, or an undecodable byte that
/// `surrogateescape` turned into the lone surrogate `U+DC00 + byte`.
#[derive(Clone, Copy)]
enum Unit {
    Char(char),
    Byte(u8),
}

/// `repr(text)` (see the module documentation for the non-ASCII rule).
pub fn py_repr(text: &str) -> String {
    repr_units(text.chars().map(Unit::Char))
}

/// `repr(os.fsdecode(bytes))`: the bytes as UTF-8, where each byte of an
/// invalid sequence becomes `\udcNN` (Python's `surrogateescape`; both
/// decoders resynchronise after the maximal invalid subpart).
pub fn py_repr_bytes(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        units.extend(chunk.valid().chars().map(Unit::Char));
        units.extend(chunk.invalid().iter().copied().map(Unit::Byte));
    }
    repr_units(units.into_iter())
}

fn repr_units(units: impl Iterator<Item = Unit> + Clone) -> String {
    let has = |c: char| {
        units
            .clone()
            .any(|unit| matches!(unit, Unit::Char(u) if u == c))
    };
    let quote = if has('\'') && !has('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for unit in units {
        let ch = match unit {
            Unit::Char(ch) => ch,
            Unit::Byte(byte) => {
                let _ = write!(out, "\\udc{byte:02x}");
                continue;
            }
        };
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(ch),
            // Writing to a String cannot fail.
            c if u32::from(c) <= 0xff => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if u32::from(c) <= 0xffff => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => {
                let _ = write!(out, "\\U{:08x}", u32::from(c));
            }
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::py_repr;

    #[test]
    fn printable_ascii_and_tab_as_python() {
        // Expected values printed by CPython 3.12 (`print(repr(x))`).
        let cases = [
            ("", "''"),
            ("abc", "'abc'"),
            ("it's", "\"it's\""),
            ("say \"hi\"", "'say \"hi\"'"),
            ("both ' and \"", "'both \\' and \"'"),
            ("back\\slash", "'back\\\\slash'"),
            ("tab\there", "'tab\\there'"),
            ("/tmp/a b", "'/tmp/a b'"),
            (
                "~!@#$%^&*()_+`-={}[]|:;<>?,./",
                "'~!@#$%^&*()_+`-={}[]|:;<>?,./'",
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(py_repr(text), expected, "{text:?}");
        }
    }

    #[test]
    fn control_characters_as_python() {
        assert_eq!(py_repr("a\nb\rc"), "'a\\nb\\rc'");
        assert_eq!(py_repr("\0\x1b\x1c\x7f"), "'\\x00\\x1b\\x1c\\x7f'");
    }

    #[test]
    fn non_ascii_is_always_escaped() {
        assert_eq!(py_repr("\u{85}\u{a0}é"), "'\\x85\\xa0\\xe9'");
        assert_eq!(py_repr("\u{200b}\u{2028}ä¸"), "'\\u200b\\u2028\\xe4\\xb8'");
        assert_eq!(py_repr("\u{1f600}"), "'\\U0001f600'");
    }

    #[test]
    fn undecodable_bytes_as_surrogate_escapes() {
        use super::py_repr_bytes;
        // Expected values printed by CPython 3.12
        // (`print(repr(os.fsdecode(b)))` under a UTF-8 locale).
        assert_eq!(py_repr_bytes(b"id"), "'id'");
        assert_eq!(py_repr_bytes(b"cat \xff"), "'cat \\udcff'");
        assert_eq!(py_repr_bytes(b"\xe2\x82A"), "'\\udce2\\udc82A'");
        assert_eq!(py_repr_bytes(b"\xed\xa0\x80"), "'\\udced\\udca0\\udc80'");
        assert_eq!(py_repr_bytes(b"it's \xff"), "\"it's \\udcff\"");
        assert_eq!(py_repr_bytes(b"\xc3\xa9\xff"), "'\\xe9\\udcff'");
        assert_eq!(py_repr_bytes("\u{e9}".as_bytes()), py_repr("\u{e9}"));
    }
}
