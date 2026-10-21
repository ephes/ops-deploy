//! The Layer-1 runner (PLAN.md 7.2, 4.4): every committed fixture case
//! against the Rust guard, with the virtual environment the case recorded.
//!
//! Rules for a decision case:
//!
//! - Rust allows: Python must allow with an identical decision. No exception.
//! - Rust refuses in a branch that is not ported yet ([`Refused::not_ported`]):
//!   counted as pending, whatever Python decided. Only the branches S3b ports
//!   may be pending ([`s3b_shape`]); every other case must be decided.
//! - Rust refuses in a ported stage: Python must refuse (or crash, verdict
//!   `error`) with the same reason, unless the case is listed in
//!   `parity/allowed_differences.json`, or carries a `p3` tag and is refused
//!   by the prefilter or is a `python-error` case ([`p3_stage`]); for those,
//!   Rust may refuse where Python allows and may give another reason.
//!
//! For a policy case: Rust must accept exactly what Python accepts, with the
//! same normalized policy, and refuse with Python's error type and message,
//! again except for `p3` cases (where Rust may refuse what Python accepts) and
//! listed differences.

mod common;

use std::collections::BTreeMap;

use serde_json::{Value, json};

use common::{DecisionCase, PolicyCase};
use echoport_command_guard::decision::{Decision, Refused};
use echoport_command_guard::policy::{Policy, PolicyError, PolicyErrorKind, parse_policy};
use echoport_command_guard::rules::check;
use echoport_command_guard::{prefilter, tokens};

fn fixture_policies() -> BTreeMap<String, Policy> {
    ["production", "staging"]
        .into_iter()
        .map(|name| {
            let path = common::fixtures_dir().join(format!("policies/{name}.json"));
            let policy = parse_policy(&std::fs::read(&path).unwrap())
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (name.to_owned(), policy)
        })
        .collect()
}

#[derive(Default, Debug)]
struct Tally {
    allowed_equal: usize,
    refused_equal: usize,
    refused_p3: usize,
    pending: usize,
    failures: Vec<String>,
}

/// The tools whose branches look at the filesystem (S3b).
const S3B_TOOLS: [&str; 10] = [
    "scp",
    "rsync",
    "cat",
    "sha256sum",
    "readlink",
    "test",
    "mv",
    "mkdir",
    "chmod",
    "chown",
];

/// Whether `command` reaches a branch of `check()` that S3b ports: the two
/// raw shapes, an S3b tool, or the `-wal`/`-shm` form of `rm -f`
/// (`guard.py:457-476, 521-527`). Worked out from the command, independently
/// of the code under test.
fn s3b_shape(command: &[u8]) -> bool {
    let Ok(text) = prefilter::command_text(command) else {
        return false;
    };
    if tokens::tar_shape(text).is_some() || tokens::cat_to_file_shape(text).is_some() {
        return true;
    }
    let Ok(mut args) = tokens::split(text) else {
        return false;
    };
    if args.len() >= 3 && args[args.len() - 2] == "<" {
        args.truncate(args.len() - 2);
    }
    match args.first().map(String::as_str) {
        Some("rm") => args.len() == 4 && args[1] == "-f",
        Some(tool) => S3B_TOOLS.contains(&tool),
        None => false,
    }
}

fn judge(
    case: &DecisionCase,
    outcome: &Result<Decision, Refused>,
    exempt: bool,
    tally: &mut Tally,
) {
    let python = &case.expected;
    let verdict = python["verdict"].as_str().unwrap();
    match outcome {
        Ok(decision) => {
            if verdict == "allowed" && decision.to_json() == *python {
                tally.allowed_equal += 1;
            } else {
                tally.failures.push(format!(
                    "{}: Rust allows {} where Python says {python}",
                    case.id,
                    decision.to_json()
                ));
            }
        }
        Err(refused) if refused.is_not_ported() => {
            if s3b_shape(&case.command_bytes()) {
                tally.pending += 1;
            } else {
                tally.failures.push(format!(
                    "{}: pending ({:?}) outside the S3b branches",
                    case.id,
                    refused.reason()
                ));
            }
        }
        Err(refused) => {
            let same = verdict == "refused" && python["reason"].as_str() == Some(refused.reason());
            if same {
                tally.refused_equal += 1;
            } else if exempt {
                tally.refused_p3 += 1;
            } else {
                tally.failures.push(format!(
                    "{}: Rust refuses ({:?}) where Python says {python}",
                    case.id,
                    refused.reason()
                ));
            }
        }
    }
}

/// Whether a `p3` case's refusal may differ from Python's: when it comes
/// from a stage the PLAN.md 4.4 exceptions name, the prefilter (the
/// `prefilter` and `invalid-utf8` classes) or a `check()` crash of Python
/// (`python-error`). A `p3` command that passes the prefilter must
/// otherwise get Python's reason.
fn p3_stage(case: &DecisionCase) -> bool {
    !case.p3.is_empty()
        && (prefilter::command_text(&case.command_bytes()).is_err()
            || case.p3.iter().any(|tag| tag == "python-error"))
}

fn report(what: &str, tally: &Tally) {
    eprintln!("{what}: {tally:?}");
    if !tally.failures.is_empty() {
        let shown: Vec<_> = tally.failures.iter().take(30).cloned().collect();
        panic!(
            "{what}: {} failures, the first ones:\n{}",
            tally.failures.len(),
            shown.join("\n")
        );
    }
}

#[test]
fn decision_fixtures() {
    let manifest = common::manifest();
    let policies = fixture_policies();
    let allowed = common::allowed_differences();
    let cases = common::decision_cases();
    assert_eq!(cases.len(), manifest.decisions, "manifest count");
    let mut tally = Tally::default();
    for case in &cases {
        let policy = &policies[&case.policy];
        let outcome = check(&case.command_bytes(), policy, &case.env);
        let exempt = p3_stage(case) || allowed.contains(&case.id);
        judge(case, &outcome, exempt, &mut tally);
    }
    report("decision fixtures", &tally);
    // S3a's branches allow and refuse; S3b's are still pending.
    assert!(tally.allowed_equal > 1700, "{tally:?}");
    assert!(tally.refused_equal > 3300, "{tally:?}");
    assert!(tally.pending < 5100, "{tally:?}");
}

/// `normalize_policy` of `parity/oracle.py`: sets sorted, dicts by key.
fn normalized(policy: &Policy) -> Value {
    json!({
        "dump_databases": policy.dump_databases,
        "restore_databases": policy.restore_databases,
        "temp_file_prefixes": policy.temp_file_prefixes,
        "scratch_restore_prefixes": policy.scratch_restore_prefixes,
        "units": policy.units,
        "private_media_paths": policy.private_media_paths,
        "path_roots": policy.path_roots.iter().map(|r| json!([r.path, r.owner])).collect::<Vec<_>>(),
        "temp_dirs": policy.temp_dirs,
        "sqlite_snapshots": policy.sqlite_snapshots.iter()
            .map(|s| json!({"database": s.database, "owner": s.owner, "temp_dir": s.temp_dir}))
            .collect::<Vec<_>>(),
        "read_files": policy.read_files,
        "ready_urls": policy.ready_urls,
    })
}

/// The error type must be Python's. The message must be too, for the
/// messages the Rust guard reproduces: `Refused` and `KeyError` texts in
/// printable ASCII (PLAN.md 4.3; the wording of JSON, decoding and OS errors
/// may differ, and non-ASCII is escaped where Python prints it).
fn same_error(error: &PolicyError, python: &Value) -> bool {
    let message = python["message"].as_str().unwrap();
    error.kind.python_name() == python["error_type"]
        && match error.kind {
            PolicyErrorKind::Refused | PolicyErrorKind::Key
                if message.bytes().all(|b| (b' '..=b'~').contains(&b)) =>
            {
                error.message == message
            }
            _ => true,
        }
}

#[test]
fn policy_fixtures() {
    let allowed = common::allowed_differences();
    let cases: Vec<PolicyCase> = common::manifest()
        .policy_files
        .iter()
        .flat_map(|name| common::read_jsonl::<PolicyCase>(name))
        .collect();
    assert!(cases.len() > 200);
    let (mut equal, mut p3_refused) = (0, 0);
    let mut failures = Vec::new();
    for case in &cases {
        let python = &case.expected;
        let exempt = !case.p3.is_empty() || allowed.contains(&case.id);
        match (parse_policy(&case.bytes()), python["ok"].as_bool().unwrap()) {
            (Ok(policy), true) if normalized(&policy) == python["normalized"] => equal += 1,
            (Ok(policy), _) => failures.push(format!(
                "{}: Rust accepts {} where Python says {python}",
                case.id,
                normalized(&policy)
            )),
            (Err(_), true) if exempt => p3_refused += 1,
            (Err(error), false) if same_error(&error, python) => equal += 1,
            (Err(_), false) if exempt => p3_refused += 1,
            (Err(error), _) => failures.push(format!(
                "{}: Rust refuses ({} {:?}) where Python says {python}",
                case.id,
                error.kind.python_name(),
                error.message
            )),
        }
    }
    eprintln!("policy fixtures: {equal} equal, {p3_refused} p3 refusals");
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
