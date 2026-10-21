//! The pre-checks, the prefilter and the tokeniser on arbitrary bytes
//! (PLAN.md 7.4, target `prefilter+tokens`): no panic, and whatever passes
//! the prefilter is the alphabet the tokeniser and the regexes rely on
//! (PLAN.md 4.1, 5.2).
#![no_main]

use echoport_command_guard::MAX_COMMAND_LENGTH;
use echoport_command_guard::prefilter::{command_text, is_printable_ascii_or_tab};
use echoport_command_guard::tokens;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = command_text(data) else {
        return;
    };
    assert!(!text.is_empty() && text.chars().count() <= MAX_COMMAND_LENGTH);
    assert!(
        text.bytes()
            .all(|b| is_printable_ascii_or_tab(b) && b != b'\\' && b != b'#'),
        "{text:?} passed the prefilter"
    );
    if let Some(group) = tokens::tar_shape(text) {
        assert!(text.ends_with(group) && !group.contains(['\t']));
    }
    if let Some(target) = tokens::cat_to_file_shape(text) {
        assert!(text.ends_with(target) && !target.contains([' ', '\t']));
    }
    match tokens::split(text) {
        Ok(words) => {
            for word in &words {
                assert!(
                    word.bytes().all(is_printable_ascii_or_tab),
                    "token {word:?} of {text:?}"
                );
            }
            // A prefiltered command never needs the defensive refusal.
        }
        Err(error) => assert_eq!(error, tokens::SplitError::NoClosingQuotation, "{text:?}"),
    }
});
