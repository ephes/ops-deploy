//! The PostgreSQL observation: `postgres_clusters`,
//! `postgresql_server_version` and `observe_postgresql`
//! (`software_live.py:393-527`), PLAN.md 3.3 "PostgreSQL".
//!
//! The server version comes from the running postmaster's image, pinned by
//! a descriptor: `/proc/<pid>/exe` is opened, the descriptor's target must
//! be the cluster's `postgres` binary, and `/proc/self/fd/<fd> --version`
//! runs with that descriptor inherited, never through the mutable
//! `/proc/<pid>/exe` link. The PID file, the descriptor and the path must
//! not change during the probe.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::error::PyError;
use crate::lifecycle::{
    lifecycle_cycle, lifecycle_ended, lifecycle_evidence, newest_cycle, utc_date,
};
use crate::policy::CLUSTER;
use crate::probe::{
    COMMAND_TIMEOUT, OpenFile, System, command, command_inheriting, translate_newlines,
};
use crate::pyjson::{INT_MAX_STR_DIGITS, eq_int, int_digits_error};
use crate::report::Observation;
use crate::version::{is_python_space, numeric_version};

pub const PG_LSCLUSTERS: &str = "/usr/bin/pg_lsclusters";

/// The bytes a text-mode `open()` reads and decodes before it returns the
/// first line (`TextIOWrapper._CHUNK_SIZE`).
const TEXT_CHUNK: usize = 8192;
/// `stream.readline(32)`: at most 32 characters of the PID file.
const PID_LINE_CHARS: usize = 32;

// `\d` is ASCII here (PLAN.md 4.2 item 11).
static MAJOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").expect("valid pattern"));
static PID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[1-9][0-9]*$").expect("valid pattern"));
// `\s` plus U+001C..U+001F is Python's `\s`; `.` excludes only `\n` in both.
static SERVER_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^postgres \(PostgreSQL\) ([0-9]+(?:\.[0-9]+)+)(?:[\s\x1c-\x1f]+.*)?$")
        .expect("valid pattern")
});

/// One line of `pg_lsclusters` (data directory and log file dropped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cluster {
    pub major: String,
    pub name: String,
    pub port: u16,
    pub status: String,
    pub owner: String,
}

impl Cluster {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("major".into(), self.major.clone().into());
        map.insert("name".into(), self.name.clone().into());
        map.insert("port".into(), self.port.into());
        map.insert("status".into(), self.status.clone().into());
        map.insert("owner".into(), self.owner.clone().into());
        Value::Object(map)
    }
}

/// `str.splitlines()`: the line boundaries of Python's `str`.
fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.char_indices().find(|(_, c)| {
            matches!(
                c,
                '\n' | '\r'
                    | '\x0b'
                    | '\x0c'
                    | '\x1c'
                    | '\x1d'
                    | '\x1e'
                    | '\u{85}'
                    | '\u{2028}'
                    | '\u{2029}'
            )
        }) {
            Some((at, c)) => {
                lines.push(&rest[..at]);
                let mut next = at + c.len_utf8();
                if c == '\r' && rest[next..].starts_with('\n') {
                    next += 1;
                }
                rest = &rest[next..];
            }
            None => {
                lines.push(rest);
                break;
            }
        }
    }
    lines
}

/// `str.split(maxsplit=…)`: runs of Python whitespace separate fields; after
/// `maxsplit` splits the rest (leading whitespace skipped) is the last field.
fn split_whitespace(text: &str, maxsplit: usize) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut rest = text.trim_start_matches(is_python_space);
    while !rest.is_empty() {
        if fields.len() == maxsplit {
            fields.push(rest);
            break;
        }
        let end = rest.find(is_python_space).unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = rest[end..].trim_start_matches(is_python_space);
    }
    fields
}

/// `int(text)` of a `str`, as far as a port range check needs it: an
/// optional sign, ASCII digits with single `_` between them (Python also
/// takes other Unicode digits, PLAN.md 4.2 item 11), surrounding Python
/// whitespace. `None` is a value beyond `i64`.
fn python_int(text: &str) -> Result<Option<i64>, PyError> {
    let invalid = || PyError::value(format!("invalid literal for int() with base 10: {text:?}"));
    let body = text.trim_matches(is_python_space);
    let (negative, digits) = match body.as_bytes().first() {
        Some(b'-') => (true, &body[1..]),
        Some(b'+') => (false, &body[1..]),
        _ => (false, body),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return Err(invalid());
    }
    let digits: String = digits.chars().filter(|c| *c != '_').collect();
    if digits.len() > INT_MAX_STR_DIGITS {
        return Err(int_digits_error(digits.len()));
    }
    let value = digits.parse::<i64>().ok();
    Ok(value.map(|v| if negative { -v } else { v }))
}

/// The clusters of `pg_lsclusters --no-header` output (already stripped).
pub fn parse_clusters(output: &str) -> Result<Vec<Cluster>, PyError> {
    let mut clusters = Vec::new();
    for line in splitlines(output) {
        let fields = split_whitespace(line, 7);
        if fields.len() < 6 {
            return Err(PyError::value("unparseable pg_lsclusters output"));
        }
        if !MAJOR.is_match(fields[0]) || !CLUSTER.is_match(fields[1]) {
            return Err(PyError::value("unsafe pg_lsclusters identity"));
        }
        let port = python_int(fields[2])?
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port >= 1)
            .ok_or_else(|| PyError::value("invalid pg_lsclusters port"))?;
        clusters.push(Cluster {
            major: fields[0].to_owned(),
            name: fields[1].to_owned(),
            port,
            status: fields[3].to_owned(),
            owner: fields[4].to_owned(),
        });
    }
    Ok(clusters)
}

/// `postgres_clusters()`: runs `/usr/bin/pg_lsclusters --no-header`.
pub fn postgres_clusters<S: System + ?Sized>(system: &S) -> Result<Vec<Cluster>, PyError> {
    let output = command(
        system,
        &[OsStr::new(PG_LSCLUSTERS), OsStr::new("--no-header")],
        COMMAND_TIMEOUT,
    )?;
    parse_clusters(&output)
}

/// `pid_path.open()` then `stream.readline(32).strip()`: the text-mode
/// reader decodes the first chunk (strict UTF-8, so an invalid byte anywhere
/// in it fails; an incomplete character at its end waits for more input)
/// with universal newlines.
fn pid_line<S: System + ?Sized>(system: &S, path: &Path) -> Result<String, PyError> {
    let head = system
        .read_head(path, TEXT_CHUNK)
        .map_err(|error| PyError::os(&error))?;
    let decode_error =
        |error: std::str::Utf8Error| PyError::new("UnicodeDecodeError", error.to_string());
    let (text, incomplete) = match std::str::from_utf8(&head) {
        Ok(text) => (text, None),
        Err(error) if error.error_len().is_none() => (
            std::str::from_utf8(&head[..error.valid_up_to()]).expect("checked prefix"),
            Some(error),
        ),
        Err(error) => return Err(decode_error(error)),
    };
    let text = translate_newlines(text);
    let mut line = String::new();
    for c in text.chars().take(PID_LINE_CHARS) {
        line.push(c);
        if c == '\n' {
            break;
        }
    }
    // A line that goes on into the incomplete character needs more input,
    // and at the end of the file that is a decoding error.
    if let Some(error) = incomplete
        && !line.ends_with('\n')
        && line.chars().count() < PID_LINE_CHARS
    {
        return Err(decode_error(error));
    }
    Ok(crate::version::python_strip(&line).to_owned())
}

/// `postgresql_server_version(cluster)`: the version the cluster's running
/// postmaster reports, executed through a descriptor pinned to its image.
pub fn postgresql_server_version<S: System + ?Sized>(
    system: &S,
    cluster: &Cluster,
) -> Result<String, PyError> {
    let os_error = |error: std::io::Error| PyError::os(&error);
    let pid_path = PathBuf::from(format!(
        "/var/run/postgresql/{}-{}.pid",
        cluster.major, cluster.name
    ));
    let pid_text = pid_line(system, &pid_path)?;
    if !PID.is_match(&pid_text) {
        return Err(PyError::value("invalid PostgreSQL postmaster PID"));
    }
    let running_path = PathBuf::from(format!("/proc/{pid_text}/exe"));
    let expected_path = PathBuf::from(format!(
        "/usr/lib/postgresql/{}/bin/postgres",
        cluster.major
    ));
    let (before, output, after) = {
        let stream = system.open(&running_path).map_err(os_error)?;
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", stream.fd()));
        let target = system.readlink(&descriptor_path).map_err(os_error)?;
        if target
            != system
                .realpath(&expected_path)
                .map_err(os_error)?
                .into_os_string()
        {
            return Err(PyError::value(
                "refusing unexpected PostgreSQL process image",
            ));
        }
        let before = system.fstat(&stream).map_err(os_error)?;
        let output = command_inheriting(
            system,
            &stream,
            &[descriptor_path.as_os_str(), OsStr::new("--version")],
            COMMAND_TIMEOUT,
        )?;
        let after = system.fstat(&stream).map_err(os_error)?;
        (before, output, after)
    };
    let last = system.stat(&running_path).map_err(os_error)?;
    let final_pid_text = pid_line(system, &pid_path)?;
    if pid_text != final_pid_text
        || before.identity() != after.identity()
        || before.identity() != last.identity()
    {
        return Err(PyError::value(
            "PostgreSQL process changed during observation",
        ));
    }
    let captures = SERVER_VERSION
        .captures(&output)
        .ok_or_else(|| PyError::value("unparseable PostgreSQL server version"))?;
    Ok(captures[1].to_owned())
}

/// `observe_postgresql(policy["postgresql"], latest, now)`.
///
/// `policy` is the validated `postgresql` policy, `latest` the PostgreSQL
/// lifecycle lookup (`{"status": "not_applicable"}` when PostgreSQL is not
/// expected). The result keeps what was observed before a failure
/// (PLAN.md 3.3).
pub fn observe_postgresql<S: System + ?Sized>(
    system: &S,
    policy: &Value,
    latest: &Map<String, Value>,
    now: f64,
) -> Observation {
    let expected = policy.get("expected").cloned().unwrap_or(Value::Null);
    let mut result = Observation::new();
    result
        .set("expected", expected.clone())
        .set(
            "desired_major",
            policy.get("desired_major").cloned().unwrap_or(Value::Null),
        )
        .set("observed", false)
        .reset_issues();
    // A validated policy has a bool here.
    let expected = expected == Value::Bool(true);
    if let Err(error) = observe(system, policy, expected, latest, now, &mut result) {
        result.fail(&error);
    }
    result
}

/// `policy[key]` inside the observation boundary.
fn subscript<'a>(policy: &'a Value, key: &str) -> Result<&'a Value, PyError> {
    policy.get(key).ok_or_else(|| PyError::key(key))
}

fn observe<S: System + ?Sized>(
    system: &S,
    policy: &Value,
    expected: bool,
    latest: &Map<String, Value>,
    now: f64,
    result: &mut Observation,
) -> Result<(), PyError> {
    let clusters = match postgres_clusters(system) {
        Ok(clusters) => clusters,
        // A missing `pg_lsclusters` means no clusters only when none is
        // expected.
        Err(error) if error.class == "FileNotFoundError" && !expected => Vec::new(),
        Err(error) => return Err(error),
    };
    result.set(
        "clusters",
        Value::Array(clusters.iter().map(Cluster::to_value).collect()),
    );
    if !expected {
        let present = !clusters.is_empty();
        result
            .set("observed", true)
            .set("present", present)
            .set("status", if present { "warning" } else { "ok" });
        if present {
            result.push_issue("unexpected_cluster");
        }
        return Ok(());
    }

    let mut selected = None;
    for cluster in &clusters {
        if subscript(policy, "cluster")? == &Value::String(cluster.name.clone())
            && eq_int(subscript(policy, "port")?, i64::from(cluster.port))
            && cluster.status.starts_with("online")
        {
            selected = Some(cluster);
            break;
        }
    }
    let selected =
        selected.ok_or_else(|| PyError::value("expected PostgreSQL cluster is not online"))?;
    let server_version = postgresql_server_version(system, selected)?;
    let parsed = numeric_version(&server_version)?;
    let major = parsed[0].as_str().to_owned();
    result
        .set("observed", true)
        .set("server_version", server_version.clone())
        .set("major", major.clone())
        .set("cluster", selected.to_value())
        .set("upstream", Value::Object(lifecycle_evidence(latest)));
    // A desired major that is a JSON number never equals the string.
    if subscript(policy, "desired_major")? != &Value::String(major.clone()) {
        result.push_issue("desired_major_drift");
    }
    // `cluster is not selected`: every other line, even an identical one.
    if clusters.len() > 1 {
        result.push_issue("unexpected_cluster");
    }
    if latest.get("status").and_then(Value::as_str) != Some("ok") {
        result
            .push_issue("upstream_unknown")
            .set("status", "unknown");
        return Ok(());
    }
    let current = lifecycle_cycle(latest, &major)?;
    let today = utc_date(now)?;
    let get = |key: &str| current.get(key).cloned().unwrap_or(Value::Null);
    let upstream_minor = get("latest");
    let mut lifecycle = Map::new();
    lifecycle.insert("latest_minor".into(), upstream_minor.clone());
    lifecycle.insert("eol".into(), get("eol"));
    lifecycle.insert("newest_major".into(), newest_cycle(latest));
    result.set("lifecycle", Value::Object(lifecycle));
    if lifecycle_ended(&get("eol"), today, true)? {
        result.push_issue("cycle_eol");
    }
    let Value::String(upstream_minor) = upstream_minor else {
        return Err(PyError::type_error("missing PostgreSQL minor release"));
    };
    if numeric_version(&server_version)? < numeric_version(&upstream_minor)? {
        result.push_issue("outdated_minor");
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
        clusters: Vec<StepCase>,
        server_version: Vec<StepCase>,
        observe: Vec<ObserveCase>,
    }

    #[derive(Deserialize)]
    struct StepCase {
        id: String,
        world: World,
        #[serde(default)]
        cluster: Option<Value>,
        #[serde(default, deserialize_with = "present")]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        calls: Vec<String>,
        #[serde(default)]
        p3: Option<String>,
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
        serde_json::from_str(include_str!("../fixtures/postgresql.json")).unwrap()
    }

    fn cluster(value: &Value) -> Cluster {
        let text = |key: &str| value[key].as_str().unwrap().to_owned();
        Cluster {
            major: text("major"),
            name: text("name"),
            port: u16::try_from(value["port"].as_u64().unwrap()).unwrap(),
            status: text("status"),
            owner: text("owner"),
        }
    }

    /// A P3 case (PLAN.md 4.2 item 11): Python takes the non-ASCII digits,
    /// the Rust code refuses them with the ValueError of the pattern.
    fn assert_p3(case: &StepCase, actual: Result<Value, PyError>, message: &str) {
        assert_eq!(case.p3.as_deref(), Some("unicode-digits"), "{}", case.id);
        let error = actual.unwrap_err();
        assert_eq!(
            (error.class, error.message.as_str()),
            ("ValueError", message),
            "{}",
            case.id
        );
    }

    /// `test_postgresql_cluster_parser_omits_data_paths`,
    /// `test_postgresql_cluster_parser_rejects_unsafe_identity` and the
    /// other recorded outputs.
    #[test]
    fn clusters_match_python() {
        let cases = fixtures().clusters;
        assert!(cases.len() >= 45);
        for case in cases {
            let fake = FakeSystem::new(case.world.clone());
            let actual = postgres_clusters(&fake)
                .map(|clusters| Value::Array(clusters.iter().map(Cluster::to_value).collect()));
            if case.p3.is_some() {
                let message = if case.id.starts_with("port") {
                    "invalid literal for int() with base 10: \"\u{665}\u{664}\u{663}\u{662}\""
                } else {
                    "unsafe pg_lsclusters identity"
                };
                assert_p3(&case, actual, message);
                continue;
            }
            assert_outcome(actual, case.result.as_ref(), case.error.as_ref(), &case.id);
            assert_calls(&fake, &case.calls, &case.id);
        }
    }

    #[test]
    fn server_version_matches_python() {
        let cases = fixtures().server_version;
        assert!(cases.len() >= 55);
        for case in cases {
            let fake = FakeSystem::new(case.world.clone());
            let target = cluster(case.cluster.as_ref().unwrap());
            let actual = postgresql_server_version(&fake, &target).map(Value::String);
            if case.p3.is_some() {
                let message = if case.id.starts_with("pid") {
                    "invalid PostgreSQL postmaster PID"
                } else {
                    "unparseable PostgreSQL server version"
                };
                assert_p3(&case, actual, message);
                continue;
            }
            assert_outcome(actual, case.result.as_ref(), case.error.as_ref(), &case.id);
            assert_calls(&fake, &case.calls, &case.id);
        }
    }

    /// `test_postgresql_minor_and_extra_clusters_are_visible`,
    /// `test_expected_postgresql_absence_is_healthy`,
    /// `test_boolean_lifecycle_fields_preserve_known_support_state` and the
    /// other recorded worlds.
    #[test]
    fn observe_postgresql_matches_python() {
        let cases = fixtures().observe;
        assert!(cases.len() >= 50);
        for case in cases {
            let fake = FakeSystem::new(case.world);
            let actual = observe_postgresql(&fake, &case.policy, &case.latest, case.now);
            assert_observation(&actual, &case.result, case.error.as_ref(), &case.id);
            assert_calls(&fake, &case.calls, &case.id);
        }
    }

    #[test]
    fn python_string_helpers() {
        assert_eq!(
            splitlines("a\r\nb\rc\n\nd\u{2028}"),
            ["a", "b", "c", "", "d"]
        );
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(split_whitespace("  a b\t c  d ", 2), ["a", "b", "c  d "]);
        assert_eq!(split_whitespace("a\u{1f}b", 7), ["a", "b"]);
        assert_eq!(python_int("+5_432").unwrap(), Some(5432));
        assert_eq!(python_int("-0").unwrap(), Some(0));
        assert_eq!(python_int("99999999999999999999").unwrap(), None);
        assert!(python_int("5__4").is_err());
        assert!(python_int("").is_err());
    }
}
