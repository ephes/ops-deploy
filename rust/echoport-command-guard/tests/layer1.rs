//! The Layer-1 runner (PLAN.md 7.2, 4.4): every committed fixture case
//! against the Rust guard, with the virtual environment the case recorded.
//!
//! Rules for a decision case:
//!
//! - Rust allows: Python must allow with an identical decision. No exception.
//! - Rust refuses: Python must refuse with the same reason, unless the case
//!   is listed in `parity/allowed_differences.json`, or carries a `p3` tag
//!   and is refused by the prefilter ([`p3_stage`]); for those, Rust may
//!   refuse where Python allows and may give another reason. Where Python's
//!   `check()` crashes (verdict `error`, the `python-error` cases), Rust
//!   refuses with `unparsable command: <Python's error text>`.
//!
//! Every branch of `check()` is ported (S3a, S3b), so no case is pending.
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
use echoport_command_guard::prefilter;
use echoport_command_guard::rules::check;

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
    failures: Vec<String>,
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
        Err(refused) => {
            // Python's `check()` crashes (verdict `error`, PLAN.md 4.2) on an
            // unbalanced quote in the `tar` shape; Rust refuses it as an
            // unparsable command with the same text.
            let same = match verdict {
                "refused" => python["reason"].as_str() == Some(refused.reason()),
                "error" => python["message"]
                    .as_str()
                    .is_some_and(|m| refused.reason() == format!("unparsable command: {m}")),
                _ => false,
            };
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
/// from the stage the PLAN.md 4.4 exceptions name, the prefilter (the
/// `prefilter` and `invalid-utf8` classes). A `p3` command that passes the
/// prefilter must otherwise get Python's reason; for a `check()` crash of
/// Python (`python-error`), that is `unparsable command: <Python's error>`
/// ([`judge`]).
fn p3_stage(case: &DecisionCase) -> bool {
    !case.p3.is_empty() && prefilter::command_text(&case.command_bytes()).is_err()
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
    // Every branch is ported (S3b): every case Python allows, Rust allows
    // with the same decision.
    let python_allowed = cases
        .iter()
        .filter(|case| case.expected["verdict"] == "allowed")
        .count();
    assert_eq!(tally.allowed_equal, python_allowed, "{tally:?}");
    assert!(tally.allowed_equal > 3400, "{tally:?}");
    assert!(tally.refused_equal > 6600, "{tally:?}");
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
