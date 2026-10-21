//! Python's pre-checks of a command (PLAN.md 3.3.1, `guard.py:454-455`) and
//! the stricter command prefilter right after them (PLAN.md 4.1).
//!
//! After [`command_text`] a command is valid UTF-8 of printable ASCII
//! (0x20-0x7e) and tab, without `\` and `#`. Over that alphabet the `shlex`
//! crate splits like Python's `shlex.split` and `\S` means the same in both
//! regex engines (PLAN.md 5.2, 3.3.2).

use crate::MAX_COMMAND_LENGTH;
use crate::decision::Refused;

pub const NON_ASCII: &str = "non-ASCII or control characters in command";
pub const UNSUPPORTED: &str = "unsupported character in command";

/// The command (`SSH_ORIGINAL_COMMAND`, as bytes) as text the rest of
/// `check()` may parse, or Python's refusal, or the prefilter's.
///
/// Python counts the length in characters of the decoded string; so does
/// this for valid UTF-8, and it counts bytes for a command that is not.
pub fn command_text(command: &[u8]) -> Result<&str, Refused> {
    match std::str::from_utf8(command) {
        Ok(text) => {
            python_prechecks(text.chars().count(), |c| text.as_bytes().contains(&c))?;
            if !text.bytes().all(is_printable_ascii_or_tab) {
                return Err(Refused::new(NON_ASCII));
            }
            if text.bytes().any(|b| b == b'\\' || b == b'#') {
                return Err(Refused::new(UNSUPPORTED));
            }
            Ok(text)
        }
        Err(_) => {
            python_prechecks(command.len(), |c| command.contains(&c))?;
            Err(Refused::new(NON_ASCII))
        }
    }
}

/// `guard.py:454-455`, with the same order and reasons.
fn python_prechecks(length: usize, contains: impl Fn(u8) -> bool) -> Result<(), Refused> {
    if length == 0 || length > MAX_COMMAND_LENGTH {
        return Err(Refused::new("empty or oversized command"));
    }
    if contains(b'\n') || contains(b'\0') || contains(b'\r') {
        return Err(Refused::new("control characters in command"));
    }
    Ok(())
}

pub fn is_printable_ascii_or_tab(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(command: &[u8]) -> Option<String> {
        command_text(command).err().map(|r| r.reason().to_owned())
    }

    #[test]
    fn python_prechecks_come_first() {
        assert_eq!(reason(b"").as_deref(), Some("empty or oversized command"));
        let long = "a".repeat(MAX_COMMAND_LENGTH + 1);
        assert_eq!(
            reason(long.as_bytes()).as_deref(),
            Some("empty or oversized command")
        );
        assert_eq!(
            command_text(&long.as_bytes()[1..]).ok().map(str::len),
            Some(4096)
        );
        for command in [&b"id\nx"[..], b"id\rx", b"id\0x", b"\xff\n"] {
            assert_eq!(
                reason(command).as_deref(),
                Some("control characters in command"),
                "{command:?}"
            );
        }
    }

    #[test]
    fn length_counts_characters_or_invalid_bytes() {
        // 4096 characters of two bytes each pass the length check (and are
        // then refused as non-ASCII).
        let wide = "é".repeat(MAX_COMMAND_LENGTH);
        assert_eq!(reason(wide.as_bytes()).as_deref(), Some(NON_ASCII));
        let wider = "é".repeat(MAX_COMMAND_LENGTH + 1);
        assert_eq!(
            reason(wider.as_bytes()).as_deref(),
            Some("empty or oversized command")
        );
        let invalid = vec![0xffu8; MAX_COMMAND_LENGTH + 1];
        assert_eq!(
            reason(&invalid).as_deref(),
            Some("empty or oversized command")
        );
    }

    #[test]
    fn only_printable_ascii_and_tab_pass() {
        assert_eq!(command_text(b"a\tb ~").ok(), Some("a\tb ~"));
        for command in [
            &b"cat \x1b"[..],
            b"cat \x1c",
            b"cat \x7f",
            "cat \u{a0}".as_bytes(),
            "cat \u{200b}".as_bytes(),
            b"cat \xff",
            b"cat \xed\xa0\x80",
        ] {
            assert_eq!(reason(command).as_deref(), Some(NON_ASCII), "{command:?}");
        }
    }

    #[test]
    fn backslash_and_hash_are_unsupported() {
        for command in ["systemctl start marina\\.service", "id #x", "a\\", "#"] {
            assert_eq!(
                reason(command.as_bytes()).as_deref(),
                Some(UNSUPPORTED),
                "{command:?}"
            );
        }
    }
}
