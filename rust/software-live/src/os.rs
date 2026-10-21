//! The OS observation: `platform.freedesktop_os_release()` and `observe_os`
//! (`software_live.py:346-390`), PLAN.md 3.3 "OS".
//!
//! The os-release parser is Python's `platform._parse_os_release` (Python
//! 3.12 and 3.13 are identical), not a shell-quoting parser: a line is used
//! only if it is exactly `NAME=VALUE` with `NAME` of `[a-zA-Z0-9_]+` and
//! `VALUE` optionally enclosed in a matching pair of `"` or `'`; only the
//! five escapes `\\`, `\$`, `\"`, `\'` and `` \` `` are undone. The
//! os-release crates do not follow that rule (`etc-os-release` strips an
//! unmatched opening quote and undoes every backslash escape, `os-release`
//! trims lines and reads known keys only), which would change `id`,
//! `cycle`, `codename` or `pretty_name`, so this port keeps its own small
//! parser, fixture-tested against Python's (PLAN.md 5.3, decided in S3c).

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value};

use crate::error::PyError;
use crate::lifecycle::{
    lifecycle_cycle, lifecycle_ended, lifecycle_evidence, newest_cycle, utc_date,
};
use crate::probe::{System, decode_text};
use crate::report::Observation;

/// `/etc` takes precedence over `/usr/lib` (`platform._os_release_candidates`).
pub const OS_RELEASE_CANDIDATES: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

/// `platform._parse_os_release(lines)`: the defaults, then every matching
/// line in order (a later line wins).
pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut info: BTreeMap<String, String> =
        [("NAME", "Linux"), ("ID", "linux"), ("PRETTY_NAME", "Linux")]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
    // A text file iterates in lines that end at `\n` (after universal
    // newlines); `$` of the line pattern matches before that `\n`, and `.`
    // matches any other character.
    for line in text.split_inclusive('\n') {
        let line = line.strip_suffix('\n').unwrap_or(line);
        if let Some((name, value)) = os_release_line(line) {
            info.insert(name.to_owned(), unescape(value));
        }
    }
    info
}

/// `^(?P<name>[a-zA-Z0-9_]+)=(?P<quote>["']?)(?P<value>.*)(?P=quote)$`
/// on one line without its `\n`.
fn os_release_line(line: &str) -> Option<(&str, &str)> {
    let (name, rest) = line.split_once('=')?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    // The optional quote is tried first; without a closing one after the
    // opening one, the pattern backtracks to no quote at all.
    for quote in ['"', '\''] {
        if rest.len() >= 2
            && let Some(value) = rest.strip_prefix(quote).and_then(|r| r.strip_suffix(quote))
        {
            return Some((name, value));
        }
    }
    Some((name, rest))
}

/// `re.sub(r"\\([\\\$\"\'`])", r"\1", value)`.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && matches!(next, '\\' | '$' | '"' | '\'' | '`')
        {
            out.push(next);
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

/// `platform.freedesktop_os_release()`: the first candidate that can be read
/// (any `OSError` tries the next), decoded as strict UTF-8 with universal
/// newlines. A file that is not UTF-8 is a `UnicodeDecodeError`, which does
/// not fall back. When no candidate can be read: `OSError(errno, "Unable to
/// read files …")` with the last candidate's errno, whose class is the
/// errno's (`FileNotFoundError`, `PermissionError`, …).
pub fn freedesktop_os_release<S: System + ?Sized>(
    system: &S,
) -> Result<BTreeMap<String, String>, PyError> {
    let mut last = None;
    for candidate in OS_RELEASE_CANDIDATES {
        match system.read_file(Path::new(candidate)) {
            Ok(bytes) => return Ok(parse_os_release(&decode_text(bytes)?)),
            Err(error) => last = Some(error),
        }
    }
    let error = last.expect("there are candidates");
    let mut py = PyError::os(&error);
    py.message = format!(
        "[Errno {}] Unable to read files {}",
        error.raw_os_error().unwrap_or_default(),
        OS_RELEASE_CANDIDATES.join(", ")
    );
    Err(py)
}

/// `observe_os(policy["os"], latest, now)`.
///
/// `policy` is the validated `os` policy (`expected_id`, `desired_cycle`),
/// `latest` the OS lifecycle lookup. The result keeps what was observed
/// before a failure (PLAN.md 3.3).
pub fn observe_os<S: System + ?Sized>(
    system: &S,
    policy: &Value,
    latest: &Map<String, Value>,
    now: f64,
) -> Observation {
    let field = |key: &str| policy.get(key).cloned().unwrap_or(Value::Null);
    let mut result = Observation::new();
    result
        .set("expected_id", field("expected_id"))
        .set("desired_cycle", field("desired_cycle"))
        .set("observed", false)
        .reset_issues()
        .set("upstream", Value::Object(lifecycle_evidence(latest)));
    if let Err(error) = observe(system, policy, latest, now, &mut result) {
        result.fail(&error);
    }
    result
}

fn observe<S: System + ?Sized>(
    system: &S,
    policy: &Value,
    latest: &Map<String, Value>,
    now: f64,
    result: &mut Observation,
) -> Result<(), PyError> {
    let release = freedesktop_os_release(system)?;
    // The parser's defaults always hold an `ID`. Python's `str.lower()` and
    // Rust's `to_lowercase()` agree on every text whose lower case is
    // `debian` or `ubuntu`, the only ones that pass the next check.
    let observed_id = release
        .get("ID")
        .map(|id| id.to_lowercase())
        .unwrap_or_default();
    let cycle = release
        .get("VERSION_ID")
        .ok_or_else(|| PyError::key("VERSION_ID"))?
        .clone();
    if policy.get("expected_id") != Some(&Value::String(observed_id.clone())) {
        return Err(PyError::value("operating system does not match policy"));
    }
    result
        .set("observed", true)
        .set("id", observed_id)
        .set("cycle", cycle.clone())
        .set("codename", release.get("VERSION_CODENAME").cloned())
        .set("pretty_name", release.get("PRETTY_NAME").cloned());
    // A desired cycle that is a JSON number never equals the string.
    if policy.get("desired_cycle") != Some(&Value::String(cycle.clone())) {
        result.push_issue("desired_cycle_drift");
    }
    if latest.get("status").and_then(Value::as_str) != Some("ok") {
        result
            .push_issue("upstream_unknown")
            .set("status", "unknown");
        return Ok(());
    }
    let current = lifecycle_cycle(latest, &cycle)?;
    let today = utc_date(now)?;
    let get = |key: &str| current.get(key).cloned().unwrap_or(Value::Null);
    let mut lifecycle = Map::new();
    lifecycle.insert("latest_release".into(), get("latest"));
    lifecycle.insert("support_end".into(), get("support"));
    lifecycle.insert("eol".into(), get("eol"));
    lifecycle.insert("newest_cycle".into(), newest_cycle(latest));
    result.set("lifecycle", Value::Object(lifecycle));
    if lifecycle_ended(&get("eol"), today, true)? {
        result.push_issue("cycle_eol");
    } else if lifecycle_ended(&get("support"), today, false)? {
        result.push_issue("standard_support_ended");
    }
    let status = if result.has_issues() { "warning" } else { "ok" };
    result.set("status", status);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::fake::{FakeSystem, World};
    use crate::testutil::{ErrorSpec, assert_calls, assert_observation, assert_outcome, present};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixtures {
        release: Vec<ReleaseCase>,
        observe: Vec<ObserveCase>,
    }

    #[derive(Deserialize)]
    struct ReleaseCase {
        id: String,
        world: World,
        #[serde(default, deserialize_with = "present")]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        calls: Vec<String>,
    }

    #[derive(Deserialize)]
    struct ObserveCase {
        id: String,
        world: World,
        policy: Value,
        latest: Map<String, Value>,
        now: f64,
        result: Value,
        #[serde(default)]
        error: Option<ErrorSpec>,
        calls: Vec<String>,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/os.json")).unwrap()
    }

    #[test]
    fn os_release_matches_python() {
        let cases = fixtures().release;
        assert!(cases.len() >= 30);
        for case in cases {
            let fake = FakeSystem::new(case.world);
            let actual = freedesktop_os_release(&fake)
                .map(|info| serde_json::to_value(info).expect("strings"));
            assert_outcome(actual, case.result.as_ref(), case.error.as_ref(), &case.id);
            assert_calls(&fake, &case.calls, &case.id);
        }
    }

    /// `test_os_lifecycle_reports_desired_drift_and_lts_phase`,
    /// `test_os_boolean_support_state_is_applied_at_observation_boundary`
    /// and the other recorded worlds.
    #[test]
    fn observe_os_matches_python() {
        let cases = fixtures().observe;
        assert!(cases.len() >= 40);
        for case in cases {
            let fake = FakeSystem::new(case.world);
            let actual = observe_os(&fake, &case.policy, &case.latest, case.now);
            assert_observation(&actual, &case.result, case.error.as_ref(), &case.id);
            assert_calls(&fake, &case.calls, &case.id);
        }
    }

    #[test]
    fn parser_takes_lines_as_python_does() {
        let info = parse_os_release("ID=\"a\\\\\"\nNAME='x'y'\nX=\"\n");
        assert_eq!(info["ID"], "a\\");
        assert_eq!(info["NAME"], "x'y");
        assert_eq!(info["X"], "\"");
        assert_eq!(info["PRETTY_NAME"], "Linux");
    }
}
