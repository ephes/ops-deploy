//! Tokenising (PLAN.md 3.3.2-3.3.3, 5.2): the two shapes `check()` matches on
//! the raw command before splitting it (`_TAR_RE`, `_CAT_TO_FILE_RE`,
//! `guard.py:44-45, 457-476`) and `shlex.split` (`guard.py:478-481`).
//!
//! Every function here expects a command that passed
//! [`crate::prefilter::command_text`]: printable ASCII and tab, no `\` and no
//! `#`. Over that alphabet the `shlex` crate's POSIX splitting equals Python's
//! `shlex.split` (no comments, no escapes; quotes `'` and `"`; whitespace space
//! and tab), and Python's `\S` is `[!-~]`. The differential tests against the
//! Python oracle (`tests/tokeniser.rs`) prove it. [`split`] refuses anything
//! outside that alphabet instead of guessing.

use std::sync::LazyLock;

use regex_lite::Regex;

use crate::prefilter::is_printable_ascii_or_tab;

/// A pattern that is a constant of this crate. Each one is compiled by a unit
/// test, so the `expect` cannot fire on input.
#[allow(clippy::expect_used)]
pub(crate) fn constant_regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("constant pattern")
}

// `\S` of Python over the prefiltered alphabet: anything but space and tab.
static TAR: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^umask 077 && (tar -C [!-~]+ -czf [!-~]+ -- [!-~]+)$"));
static CAT_TO_FILE: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^umask 077 && cat > ([!-~]+)$"));

/// `_TAR_RE.match(command).group(1)`: the `tar ...` part of `umask 077 && tar
/// -C <dir> -czf <archive> -- <name>`.
pub fn tar_shape(command: &str) -> Option<&str> {
    Some(TAR.captures(command)?.get(1)?.as_str())
}

/// `_CAT_TO_FILE_RE.match(command).group(1)`: the target of `umask 077 && cat
/// > <path>`.
pub fn cat_to_file_shape(command: &str) -> Option<&str> {
    Some(CAT_TO_FILE.captures(command)?.get(1)?.as_str())
}

/// Why [`split`] gave no tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    /// An unterminated quote. With `\` refused, this is the only error
    /// Python's `shlex.split` can raise; the text is its `ValueError`.
    NoClosingQuotation,
    /// A character outside the prefiltered alphabet; never reached after the
    /// prefilter.
    UnsupportedCharacter,
}

impl std::fmt::Display for SplitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SplitError::NoClosingQuotation => "No closing quotation",
            SplitError::UnsupportedCharacter => "unsupported character in command",
        })
    }
}

impl std::error::Error for SplitError {}

/// `shlex.split(command)` for a prefiltered command.
pub fn split(command: &str) -> Result<Vec<String>, SplitError> {
    if !command
        .bytes()
        .all(|b| is_printable_ascii_or_tab(b) && b != b'\\' && b != b'#')
    {
        return Err(SplitError::UnsupportedCharacter);
    }
    shlex::split(command).ok_or(SplitError::NoClosingQuotation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(command: &str) -> Vec<String> {
        split(command).unwrap()
    }

    #[test]
    fn patterns_compile() {
        LazyLock::force(&TAR);
        LazyLock::force(&CAT_TO_FILE);
    }

    #[test]
    fn splits_like_python() {
        // Expected values from Python 3.12 `shlex.split` (PLAN.md 3.3.3).
        assert_eq!(words("a \"b c\"d"), ["a", "b cd"]);
        assert_eq!(words("''"), [""]);
        assert_eq!(words("x'' \"\"y"), ["x", "y"]);
        assert_eq!(
            words(" \tsystemctl\t stop  gotosocial "),
            ["systemctl", "stop", "gotosocial"]
        );
        assert_eq!(words("sh -c 'it'\"'\"'s'"), ["sh", "-c", "it's"]);
        assert_eq!(words("echo \"$(id)\" '`id`'"), ["echo", "$(id)", "`id`"]);
        assert_eq!(words("a;b|c&&d"), ["a;b|c&&d"]);
        assert!(words("   ").is_empty());
    }

    #[test]
    fn unterminated_quotes_are_errors() {
        assert_eq!(split("cat 'x"), Err(SplitError::NoClosingQuotation));
        assert_eq!(split("cat \"x"), Err(SplitError::NoClosingQuotation));
        assert_eq!(
            split("'\"'\"").map(|_| ()),
            Err(SplitError::NoClosingQuotation)
        );
    }

    #[test]
    fn refuses_characters_outside_the_prefiltered_alphabet() {
        for command in ["a\\ b", "a #b", "a\nb", "a\rb", "é"] {
            assert_eq!(
                split(command),
                Err(SplitError::UnsupportedCharacter),
                "{command:?}"
            );
        }
    }

    #[test]
    fn shapes() {
        let tar = "umask 077 && tar -C /home/p/site -czf /tmp/echoport-pp-private-media.Ab12/private_media.tar.gz -- private_media";
        assert_eq!(
            tar_shape(tar),
            Some(
                "tar -C /home/p/site -czf /tmp/echoport-pp-private-media.Ab12/private_media.tar.gz -- private_media"
            )
        );
        assert_eq!(tar_shape("umask 077 && tar -C a -czf b -- c d"), None);
        assert_eq!(tar_shape("umask 077 && tar -C a -czf b --\tc"), None);
        assert_eq!(tar_shape(" umask 077 && tar -C a -czf b -- c"), None);
        assert_eq!(
            cat_to_file_shape("umask 077 && cat > /var/tmp/x.AbCdEf/db.dump"),
            Some("/var/tmp/x.AbCdEf/db.dump")
        );
        assert_eq!(cat_to_file_shape("umask 077 && cat > a b"), None);
        assert_eq!(cat_to_file_shape("umask 077 && cat >  a"), None);
        assert_eq!(cat_to_file_shape("umask 077 && cat > 'a'"), Some("'a'"));
    }
}
