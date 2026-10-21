//! Decision property tests (PLAN.md 7.3): random commands against both
//! guards, through the oracle server `parity/oracle.py`, each in a random
//! virtual host.
//!
//! The commands are grammar-aware: an accepted command of the curated
//! fixture sources (`runner`, `journal`, `unit`, `fs`) with its recorded
//! host, or a tool followed by tokens of the policies' vocabulary, then up to
//! four mutation operators of PLAN.md 7.2 item 4 (drop, duplicate, swap,
//! replace or insert a token; append a shell metacharacter sequence; requote
//! a token; change the whitespace; path forms `.`, `..`, `//` and a trailing
//! `/`; control, non-ASCII and invalid UTF-8 characters; lengths around
//! 4096). The host gives every path the command could name a random `lstat`
//! answer (absent, the seven file types with modes, owners and link counts,
//! `lstat` errors) and a random `realpath` (itself, another of the paths, a
//! policy root or below it, or outside), runs as root or not, and sometimes
//! lacks a user.
//!
//! Properties:
//!
//! - Rust accepts ⇒ Python accepts with an identical decision (PLAN.md 4),
//!   and the decision keeps the invariants of `common::invariants`.
//! - Rust refuses ⇒ Python refuses with the same reason, except for the
//!   PLAN.md 4.4 classes: a command outside the prefilter's alphabet
//!   (`prefilter`, `invalid-utf8`), refused by the prefilter, and a
//!   `check()` crash of Python (`python-error`), which Rust refuses as
//!   `unparsable command: <Python's error>`.
//!
//! `PROPTEST_CASES` sets the number of cases (default 2,000; the seed is
//! fixed, `PROPTEST_RNG_SEED` changes it).

mod common;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use serde_json::{Value, json};

use common::Oracle;
use common::invariants::decision_invariants;
use echoport_command_guard::decision::{Decision, Refused};
use echoport_command_guard::env::VirtualEnv;
use echoport_command_guard::policy::{Policy, parse_policy};
use echoport_command_guard::prefilter::{command_text, is_printable_ascii_or_tab};
use echoport_command_guard::rules::{TOOLS, check};
use echoport_command_guard::tokens;

/// The users of `parity/oracle.py` (`USERS`).
const USERS: [(&str, u32); 7] = [
    ("root", 0),
    ("postgres", 110),
    ("gotosocial", 120),
    ("homepage", 1004),
    ("marina", 1001),
    ("python-podcast", 1003),
    ("villakunterbunt", 1002),
];
const UIDS: [u32; 7] = [0, 110, 120, 1001, 1002, 1000, 4242];
const MODES: [u32; 7] = [0o700, 0o600, 0o750, 0o755, 0o777, 0o640, 0o1777];
const ERRNOS: [(&str, &str); 4] = [
    ("EACCES", "Permission denied"),
    ("ENOTDIR", "Not a directory"),
    ("ELOOP", "Too many levels of symbolic links"),
    ("ENAMETOOLONG", "File name too long"),
];
const KINDS: [&str; 7] = ["reg", "dir", "lnk", "fifo", "sock", "chr", "blk"];
const OUTSIDE: [&str; 4] = ["/etc/shadow", "/root/.ssh", "/home/marina", "/tmp"];
const APPENDED: [&str; 10] = [
    "; id",
    " && id",
    " | id",
    " $(id)",
    " `id`",
    " #x",
    "\\",
    " > /tmp/x",
    " < /etc/shadow",
    " &",
];
const ODD_CHARACTERS: [&str; 11] = [
    "\x1b", "\x1c", "\x7f", "\u{a0}", "\u{200b}", "\u{2028}", "\u{0455}", "\0", "\n", "\r", "\x0b",
];
/// Extra vocabulary: options and values no policy allows, metacharacters.
const EXTRA_WORDS: [&str; 26] = [
    "root",
    "-r",
    "-p",
    "-d",
    "-L",
    "-R",
    "--delete",
    "--sender",
    "--server",
    "-logDtpre.iLsfxCIvu",
    "-logtpre.iLsfxCIvu",
    ".",
    "..",
    "<",
    ">",
    "&&",
    ";",
    "",
    "/etc/shadow",
    "/tmp/x",
    "/var/lib/gotosocial/../../etc",
    "/home/marina/site/../.ssh",
    "--dbname=postgres",
    "--file=/tmp/echoport_pp_dump_x.dump",
    "sqlite.db",
    "0700",
];

/// The material the generator draws from.
struct Corpus {
    policies: BTreeMap<String, Policy>,
    /// Accepted curated cases: policy, tokens, recorded env.
    bases: Vec<(String, Vec<String>, Value)>,
    vocabulary: Vec<String>,
}

impl Corpus {
    fn load() -> Self {
        let policies: BTreeMap<String, Policy> = ["production", "staging"]
            .into_iter()
            .map(|name| {
                let path = common::fixtures_dir().join(format!("policies/{name}.json"));
                (
                    name.to_owned(),
                    parse_policy(&std::fs::read(path).unwrap()).unwrap(),
                )
            })
            .collect();
        let mut bases = Vec::new();
        let mut words = BTreeSet::new();
        // The fixture lines as JSON: the env stays in the fixture form the
        // oracle takes.
        let cases: Vec<Value> = ["runner.jsonl", "journal.jsonl", "unit.jsonl", "fs.jsonl"]
            .into_iter()
            .flat_map(common::read_jsonl::<Value>)
            .collect();
        for case in cases {
            let Some(text) = case["command"].as_str() else {
                continue;
            };
            let Ok(text) = command_text(text.as_bytes()) else {
                continue;
            };
            let Ok(words_of_case) = tokens::split(text) else {
                continue;
            };
            words.extend(words_of_case.iter().cloned());
            if case["expected"]["verdict"] == "allowed" {
                let policy = case["policy"].as_str().unwrap().to_owned();
                bases.push((policy, words_of_case, case["env"].clone()));
            }
        }
        words.extend(EXTRA_WORDS.iter().map(|w| (*w).to_owned()));
        assert!(bases.len() > 400, "{} accepted curated cases", bases.len());
        Self {
            policies,
            bases,
            vocabulary: words.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone)]
enum Quote {
    /// `shlex.quote`.
    Auto,
    Single,
    Double,
    /// `x''`: the token followed by an empty quoted part.
    Trailing,
}

#[derive(Debug, Clone)]
enum Mutation {
    Drop(Index),
    Duplicate(Index),
    Swap(Index, Index),
    Replace(Index, Index),
    Insert(Index, Index),
    Requote(Index, u8),
    PathForm(Index, u8),
    OtherPolicy,
}

#[derive(Debug, Clone)]
enum Tail {
    None,
    Append(Index),
    Character(Index, Index),
    InvalidUtf8(Index),
    /// A backslash escape before a letter, digit or `.`, which Python's
    /// `shlex.split` removes (PLAN.md 4.1).
    Escape(Index),
    Length(u8),
}

#[derive(Debug, Clone)]
enum Base {
    Fixture(Index),
    /// One of the raw `umask 077 && ...` shapes among the fixture bases,
    /// which are too few to be drawn often otherwise.
    RawShape(Index),
    Grammar(bool, Index, Vec<Index>),
}

#[derive(Debug, Clone)]
struct FsChoice {
    lstat: u8,
    kind: Index,
    mode: Index,
    uid: Index,
    realpath: u8,
    target: Index,
}

#[derive(Debug, Clone)]
struct Case {
    base: Base,
    mutations: Vec<Mutation>,
    whitespace: u8,
    tail: Tail,
    fs: Vec<FsChoice>,
    keep_env: bool,
    euid_root: bool,
    missing_user: Option<Index>,
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        1 => any::<Index>().prop_map(Mutation::Drop),
        1 => any::<Index>().prop_map(Mutation::Duplicate),
        1 => (any::<Index>(), any::<Index>()).prop_map(|(a, b)| Mutation::Swap(a, b)),
        3 => (any::<Index>(), any::<Index>()).prop_map(|(a, b)| Mutation::Replace(a, b)),
        1 => (any::<Index>(), any::<Index>()).prop_map(|(a, b)| Mutation::Insert(a, b)),
        2 => (any::<Index>(), any::<u8>()).prop_map(|(a, b)| Mutation::Requote(a, b)),
        2 => (any::<Index>(), any::<u8>()).prop_map(|(a, b)| Mutation::PathForm(a, b)),
        1 => Just(Mutation::OtherPolicy),
    ]
}

fn tail() -> impl Strategy<Value = Tail> {
    prop_oneof![
        12 => Just(Tail::None),
        2 => any::<Index>().prop_map(Tail::Append),
        2 => (any::<Index>(), any::<Index>()).prop_map(|(a, b)| Tail::Character(a, b)),
        1 => any::<Index>().prop_map(Tail::InvalidUtf8),
        1 => any::<Index>().prop_map(Tail::Escape),
        1 => any::<u8>().prop_map(Tail::Length),
    ]
}

fn base() -> impl Strategy<Value = Base> {
    prop_oneof![
        4 => any::<Index>().prop_map(Base::Fixture),
        1 => any::<Index>().prop_map(Base::RawShape),
        1 => (any::<bool>(), any::<Index>(), prop::collection::vec(any::<Index>(), 0..6))
            .prop_map(|(staging, tool, words)| Base::Grammar(staging, tool, words)),
    ]
}

fn fs_choice() -> impl Strategy<Value = FsChoice> {
    (
        any::<u8>(),
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
        any::<u8>(),
        any::<Index>(),
    )
        .prop_map(|(lstat, kind, mode, uid, realpath, target)| FsChoice {
            lstat,
            kind,
            mode,
            uid,
            realpath,
            target,
        })
}

fn case() -> impl Strategy<Value = Case> {
    (
        base(),
        prop::collection::vec(mutation(), 0..4),
        any::<u8>(),
        tail(),
        prop::collection::vec(fs_choice(), 0..10),
        any::<bool>(),
        prop::bool::weighted(0.85),
        prop::option::weighted(0.1, any::<Index>()),
    )
        .prop_map(
            |(base, mutations, whitespace, tail, fs, keep_env, euid_root, missing_user)| Case {
                base,
                mutations,
                whitespace,
                tail,
                fs,
                keep_env,
                euid_root,
                missing_user,
            },
        )
}

/// `shlex.quote`.
fn shlex_quote(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./-_".contains(&b))
    {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', "'\"'\"'"))
}

/// The operator words of the raw shapes (`umask 077 && tar ...`, `umask 077
/// && cat > ...`) and the `< file` of `runuser`: written bare unless a
/// mutation requotes them, so that a fixture base keeps its shape.
/// `shlex.split` (no punctuation characters) splits them like any word.
const OPERATORS: [&str; 6] = ["&&", ">", "<", ";", "|", "&"];

fn render(word: &str, quote: &Quote) -> String {
    match quote {
        Quote::Auto if OPERATORS.contains(&word) => word.to_owned(),
        Quote::Single if !word.contains('\'') => format!("'{word}'"),
        Quote::Double if !word.contains(['"', '$', '`']) => format!("\"{word}\""),
        Quote::Trailing => format!("{}''", shlex_quote(word)),
        _ => shlex_quote(word),
    }
}

/// A path form of `word` (PLAN.md 7.2: `.`, `..`, `//`, trailing `/`).
fn path_form(word: &str, choice: u8) -> String {
    match choice % 6 {
        0 => format!("{word}/"),
        1 => format!("{word}/."),
        2 => format!("{word}/.."),
        3 => word.replacen('/', "//", 2),
        4 => match word.rfind('/') {
            Some(cut) if cut > 0 => format!("{}/../{}", &word[..cut], &word[cut + 1..]),
            _ => format!("{word}/x"),
        },
        _ => format!("{word}/x"),
    }
}

/// The command bytes and the policy of a case.
fn build_command(corpus: &Corpus, case: &Case) -> (Vec<u8>, String, Value) {
    let (mut policy, mut words, env) = match &case.base {
        Base::Fixture(index) => {
            let (policy, words, env) = &corpus.bases[index.index(corpus.bases.len())];
            (policy.clone(), words.clone(), env.clone())
        }
        Base::RawShape(index) => {
            let raw: Vec<_> = corpus
                .bases
                .iter()
                .filter(|(_, words, _)| words.first().is_some_and(|w| w == "umask"))
                .collect();
            let (policy, words, env) = raw[index.index(raw.len())];
            (policy.clone(), words.clone(), env.clone())
        }
        Base::Grammar(staging, tool, rest) => {
            let mut words = vec![TOOLS[tool.index(TOOLS.len())].to_owned()];
            words.extend(
                rest.iter()
                    .map(|i| corpus.vocabulary[i.index(corpus.vocabulary.len())].clone()),
            );
            let policy = if *staging { "staging" } else { "production" };
            (policy.to_owned(), words, json!({}))
        }
    };
    let mut quotes: Vec<Quote> = vec![Quote::Auto; words.len()];
    let vocabulary = &corpus.vocabulary;
    for mutation in &case.mutations {
        let n = words.len();
        match mutation {
            Mutation::Drop(i) if n > 0 => {
                let i = i.index(n);
                words.remove(i);
                quotes.remove(i);
            }
            Mutation::Duplicate(i) if n > 0 => {
                let i = i.index(n);
                words.insert(i, words[i].clone());
                quotes.insert(i, quotes[i].clone());
            }
            Mutation::Swap(a, b) if n > 0 => {
                words.swap(a.index(n), b.index(n));
            }
            Mutation::Replace(i, v) if n > 0 => {
                words[i.index(n)] = vocabulary[v.index(vocabulary.len())].clone();
            }
            Mutation::Insert(i, v) => {
                let i = i.index(n + 1);
                words.insert(i, vocabulary[v.index(vocabulary.len())].clone());
                quotes.insert(i, Quote::Auto);
            }
            Mutation::Requote(i, style) if n > 0 => {
                quotes[i.index(n)] = match style % 3 {
                    0 => Quote::Single,
                    1 => Quote::Double,
                    _ => Quote::Trailing,
                };
            }
            Mutation::PathForm(i, choice) if n > 0 => {
                let paths: Vec<usize> = (0..n).filter(|&k| words[k].contains('/')).collect();
                if !paths.is_empty() {
                    let k = paths[i.index(paths.len())];
                    words[k] = path_form(&words[k], *choice);
                }
            }
            Mutation::OtherPolicy => {
                policy = if policy == "staging" {
                    "production".into()
                } else {
                    "staging".into()
                };
            }
            _ => {}
        }
    }
    let separator = match case.whitespace % 8 {
        0 => "\t",
        1 => "  ",
        2 => " \t",
        _ => " ",
    };
    let mut command = words
        .iter()
        .zip(&quotes)
        .map(|(word, quote)| render(word, quote))
        .collect::<Vec<_>>()
        .join(separator);
    match case.whitespace % 16 {
        8 => command.insert(0, ' '),
        9 => command.push(' '),
        10 => command.push('\t'),
        _ => {}
    }
    let mut bytes = command.into_bytes();
    match &case.tail {
        Tail::None => {}
        Tail::Append(i) => bytes.extend(APPENDED[i.index(APPENDED.len())].as_bytes()),
        Tail::Character(at, c) => {
            let at = at.index(bytes.len() + 1);
            let insert = ODD_CHARACTERS[c.index(ODD_CHARACTERS.len())].as_bytes();
            bytes.splice(at..at, insert.iter().copied());
        }
        Tail::InvalidUtf8(at) => {
            let at = at.index(bytes.len() + 1);
            bytes.splice(at..at, [0xff, 0xc3]);
        }
        Tail::Escape(at) => {
            let plain: Vec<usize> = (0..bytes.len())
                .filter(|&k| bytes[k].is_ascii_alphanumeric() || bytes[k] == b'.')
                .collect();
            if !plain.is_empty() {
                bytes.insert(plain[at.index(plain.len())], b'\\');
            }
        }
        Tail::Length(choice) => {
            // Pad the last word to 4095, 4096 or 4097 characters in all.
            let want = 4095 + usize::from(choice % 3);
            while bytes.len() < want {
                bytes.push(b'a');
            }
        }
    }
    (bytes, policy, env)
}

/// The paths the command could make `check()` look up: each run of path
/// characters that starts with `/`, its parents and its `-wal`/`-shm` base.
fn candidate_paths(command: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(command);
    let path_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-');
    let mut found = BTreeSet::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find('/') {
        let run: String = rest[start..]
            .chars()
            .take_while(|c| path_char(*c))
            .collect();
        rest = &rest[start + run.len()..];
        found.insert(run.clone());
        let mut path = run.trim_end_matches('/').to_owned();
        for side in ["-wal", "-shm"] {
            if let Some(stem) = path.strip_suffix(side) {
                found.insert(stem.to_owned());
            }
        }
        while let Some(cut) = path.rfind('/') {
            found.insert(path.clone());
            path.truncate(cut);
        }
    }
    found.into_iter().collect()
}

/// The virtual host of a case, in the fixtures' `env` form.
fn host(case: &Case, command: &[u8], recorded: &Value) -> Value {
    let mut users: BTreeMap<String, Value> = USERS
        .iter()
        .map(|(name, uid)| ((*name).to_owned(), json!(uid)))
        .collect();
    if let Some(missing) = &case.missing_user {
        let name = USERS[missing.index(USERS.len())].0;
        users.insert(name.to_owned(), Value::Null);
    }
    let (mut lstat, mut realpath) = if case.keep_env {
        (
            recorded["lstat"].as_object().cloned().unwrap_or_default(),
            recorded["realpath"]
                .as_object()
                .cloned()
                .unwrap_or_default(),
        )
    } else {
        Default::default()
    };
    let paths = candidate_paths(command);
    for (path, choice) in paths.iter().zip(&case.fs) {
        let entry = match choice.lstat % 8 {
            0 | 1 => None,
            2 => Some(json!({"absent": true})),
            3 => {
                let (errno, strerror) = ERRNOS[choice.kind.index(ERRNOS.len())];
                Some(json!({"errno": errno, "strerror": strerror}))
            }
            4 => Some(
                json!({"kind": "dir", "mode": 0o700, "uid": UIDS[choice.uid.index(3)], "nlink": 2}),
            ),
            5 => Some(
                json!({"kind": "reg", "mode": 0o600, "uid": UIDS[choice.uid.index(3)], "nlink": 1}),
            ),
            _ => Some(json!({
                "kind": KINDS[choice.kind.index(KINDS.len())],
                "mode": MODES[choice.mode.index(MODES.len())] & 0o7777,
                "uid": UIDS[choice.uid.index(UIDS.len())],
                "nlink": 1 + u64::from(choice.lstat & 8 != 0),
            })),
        };
        if let Some(entry) = entry {
            lstat.insert(path.clone(), entry);
        }
        let resolved = match choice.realpath % 8 {
            0..=3 => None,
            4 => Some(paths[choice.target.index(paths.len())].clone()),
            5 => Some(
                [
                    "/var/lib/gotosocial",
                    "/home/marina/site",
                    "/home/villakunterbunt/data",
                ][choice.target.index(3)]
                .to_owned(),
            ),
            6 => Some(format!(
                "{}/x",
                [
                    "/var/lib/gotosocial",
                    "/home/marina/site",
                    "/home/villakunterbunt/data"
                ][choice.target.index(3)]
            )),
            _ => Some(OUTSIDE[choice.target.index(OUTSIDE.len())].to_owned()),
        };
        if let Some(resolved) = resolved {
            realpath.insert(path.clone(), json!(resolved));
        }
    }
    json!({
        "euid": if case.euid_root { 0 } else { 1000 },
        "users": users,
        "lstat": lstat,
        "realpath": realpath,
    })
}

/// Whether the command falls into a PLAN.md 4.4 command class (`prefilter`,
/// `invalid-utf8`): outside printable ASCII and tab, or with `\` or `#`.
fn p3_command(command: &[u8]) -> bool {
    std::str::from_utf8(command).is_err()
        || command
            .iter()
            .any(|&b| !is_printable_ascii_or_tab(b) || b == b'\\' || b == b'#')
}

#[derive(Debug, Default)]
struct Tally {
    allowed_equal: usize,
    refused_equal: usize,
    refused_p3: usize,
    /// Of those, the ones Python allows (PLAN.md 4.1: backslash escapes).
    p3_python_allows: usize,
    python_error: usize,
    /// Equal acceptances of the raw `umask 077 && tar ...` shape.
    tar_allowed: usize,
    /// Equal acceptances of the raw `umask 077 && cat > ...` shape.
    cat_to_file_allowed: usize,
}

fn judge(
    command: &[u8],
    rust: &Result<Decision, Refused>,
    python: &Value,
    tally: &mut Tally,
) -> Result<(), String> {
    let verdict = python["verdict"].as_str().unwrap_or_default();
    match rust {
        Ok(decision) => {
            decision_invariants(decision)?;
            if verdict != "allowed" || decision.to_json() != *python {
                return Err(format!(
                    "Rust allows {} where Python says {python}",
                    decision.to_json()
                ));
            }
            tally.allowed_equal += 1;
            if decision.umask.is_some() {
                match decision.argv[0].as_str() {
                    "tar" => tally.tar_allowed += 1,
                    "cat" => tally.cat_to_file_allowed += 1,
                    _ => {}
                }
            }
        }
        Err(refused) => match verdict {
            "refused" if python["reason"].as_str() == Some(refused.reason()) => {
                tally.refused_equal += 1;
            }
            "error"
                if python["message"]
                    .as_str()
                    .is_some_and(|m| refused.reason() == format!("unparsable command: {m}")) =>
            {
                tally.python_error += 1;
            }
            _ if p3_command(command) && command_text(command).is_err() => {
                tally.refused_p3 += 1;
                tally.p3_python_allows += usize::from(verdict == "allowed");
            }
            _ => {
                return Err(format!(
                    "Rust refuses ({:?}) where Python says {python}",
                    refused.reason()
                ));
            }
        },
    }
    Ok(())
}

fn runner() -> TestRunner {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let seed: u64 = std::env::var("PROPTEST_RNG_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0x5eed_0005);
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    TestRunner::new_with_rng(
        Config {
            cases,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &bytes),
    )
}

#[test]
fn random_decisions_match_python() {
    let corpus = Corpus::load();
    let oracle = RefCell::new(Oracle::start());
    let tally = RefCell::new(Tally::default());
    let mut runner = runner();
    let cases = runner.config().cases;
    let result = runner.run(&case(), |case| {
        let (command, policy, recorded) = build_command(&corpus, &case);
        let env_json = host(&case, &command, &recorded);
        let env: VirtualEnv = serde_json::from_value(env_json.clone()).unwrap();
        let rust = check(&command, &corpus.policies[&policy], &env);
        let python = oracle.borrow_mut().check(&policy, &command, &env_json);
        let verdict = judge(&command, &rust, &python, &mut tally.borrow_mut());
        prop_assert!(
            verdict.is_ok(),
            "{}: {:?} ({policy}, env {env_json})",
            verdict.unwrap_err(),
            String::from_utf8_lossy(&command)
        );
        Ok(())
    });
    if let Err(error) = result {
        panic!("{error}");
    }
    let tally = tally.into_inner();
    eprintln!("{cases} random decisions: {tally:?}");
    let total = tally.allowed_equal + tally.refused_equal + tally.refused_p3 + tally.python_error;
    assert_eq!(total, cases as usize);
    // The generator must reach acceptances and the rules' refusals, not
    // only the prefilter.
    assert!(tally.allowed_equal * 10 >= total, "{tally:?}");
    assert!(tally.refused_equal * 3 >= total, "{tally:?}");
    // Both raw shapes reach their acceptance, not only their refusals.
    assert!(
        tally.tar_allowed > 0 && tally.cat_to_file_allowed > 0,
        "{tally:?}"
    );
}
