//! The tokeniser against Python's `shlex.split` (PLAN.md 5.2, 7.3): through
//! the oracle server `parity/oracle.py`. Property: when a command passes the
//! pre-checks and the prefilter, the Rust tokens equal Python's, errors
//! included. Any disagreement blocks the slice (PLAN.md 5.2).
//!
//! `PROPTEST_CASES` sets the number of random cases (default 2,000; the
//! seed is fixed, `PROPTEST_RNG_SEED` changes it).

mod common;

use std::cell::RefCell;

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use common::Oracle;
use echoport_command_guard::prefilter::command_text;
use echoport_command_guard::tokens::split;

fn rust_split(command: &str) -> Result<Vec<String>, String> {
    split(command).map_err(|error| error.to_string())
}

/// Every fixture command that passes the prefilter, split by both.
#[test]
fn fixture_commands_split_like_python() {
    let mut oracle = Oracle::start();
    let mut compared = 0;
    let mut seen = std::collections::BTreeSet::new();
    for case in common::decision_cases() {
        let bytes = case.command_bytes();
        let Ok(command) = command_text(&bytes) else {
            continue;
        };
        if !seen.insert(command.to_owned()) {
            continue;
        }
        assert_eq!(
            rust_split(command),
            oracle.split(command),
            "{}: {command:?}",
            case.id
        );
        compared += 1;
    }
    eprintln!("compared {compared} distinct fixture commands");
    assert!(compared > 5000);
}

/// One character, weighted towards what matters to a tokeniser: quotes,
/// space and tab, shell metacharacters, and what the prefilter must catch
/// (`\`, `#`, control and non-ASCII characters; rare enough that most
/// commands still reach the tokeniser).
fn character() -> impl Strategy<Value = char> {
    prop_oneof![
        8 => Just('\''),
        8 => Just('"'),
        8 => Just(' '),
        4 => Just('\t'),
        12 => prop::char::range('a', 'e'),
        4 => prop::sample::select(vec!['-', '/', '.', '_', '=', ':', '0', '9']),
        1 => Just('\\'),
        1 => Just('#'),
        3 => Just('$'),
        4 => prop::sample::select(vec![';', '&', '|', '<', '>', '(', ')', '`', '*', '?', '~', '!', '{', '}']),
        1 => prop::sample::select(vec!['\n', '\r', '\0', '\x0b', '\x0c', '\x1b', '\x1c', '\x1f', '\x7f']),
        1 => prop::sample::select(vec!['\u{a0}', '\u{85}', '\u{200b}', '\u{2028}', 'é', '\u{1f600}']),
    ]
}

fn command() -> impl Strategy<Value = String> {
    prop::collection::vec(character(), 0..32).prop_map(|chars| chars.into_iter().collect())
}

#[test]
fn random_commands_split_like_python() {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let seed: u64 = std::env::var("PROPTEST_RNG_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0x5eed_0001);
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner = TestRunner::new_with_rng(
        config,
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed_bytes),
    );
    let oracle = RefCell::new(Oracle::start());
    let passed = RefCell::new(0usize);
    let result = runner.run(&command(), |command| {
        if command_text(command.as_bytes()).is_ok() {
            *passed.borrow_mut() += 1;
            let python = oracle.borrow_mut().split(&command);
            prop_assert_eq!(rust_split(&command), python, "{:?}", command);
        }
        Ok(())
    });
    if let Err(error) = result {
        panic!("{error}");
    }
    let passed = *passed.borrow();
    eprintln!("{cases} random commands, {passed} passed the prefilter and were compared");
    assert!(
        passed * 3 >= cases as usize,
        "too few commands reach the tokeniser"
    );
}
