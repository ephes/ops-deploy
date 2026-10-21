//! The Traefik observation (PLAN.md 3.3, "Traefik"): `binary_info`
//! (`software_live.py:90-125`), `main_pid` (`:128-129`) and
//! `observe_traefik` (`:242-319`).
//!
//! The running image is read through `/proc/<MainPID>/exe` but never
//! executed through that mutable link: the file is opened, the descriptor's
//! own target must be the managed binary's real path, and the version probe
//! executes `/proc/self/fd/<fd>` with exactly that descriptor inherited.
//! The file identity must not change while it is hashed and probed, and
//! the whole observation is accepted only when `MainPID` and the link
//! target are unchanged afterwards (two attempts).

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::error::PyError;
use crate::policy::{TRAEFIK_BINARIES, subscript};
use crate::probe::{COMMAND_TIMEOUT, FileStat, OpenFile, System, command, command_inheriting};
use crate::pyjson::{INT_MAX_STR_DIGITS, int_digits_error, type_name};
use crate::report::Observation;
use crate::version::{Release, python_strip, version};

/// The suffix the kernel appends to the target of `/proc/<pid>/exe` when the
/// executable was removed or replaced.
const DELETED: &[u8] = b" (deleted)";

/// `(?m)^Version:\s*(v?\d+\.\d+\.\d+)\s*$` with Python's `\s` (Unicode
/// whitespace plus U+001C..U+001F) and ASCII digits (PLAN.md 4.2 item 11).
/// `\s` may cross a line break in both engines; `$` is the end of a line
/// (before `\n`) or of the text in both.
static VERSION_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^Version:[\s\x1c-\x1f]*(v?[0-9]+\.[0-9]+\.[0-9]+)[\s\x1c-\x1f]*$")
        .expect("valid pattern")
});

/// What `binary_info` returns: the version the probe printed (`None`
/// without a probe) and the sha256 of the file's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryInfo {
    pub version: Option<String>,
    pub sha256: String,
}

impl BinaryInfo {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("version".into(), self.version.clone().into());
        map.insert("sha256".into(), self.sha256.clone().into());
        Value::Object(map)
    }
}

fn os_error(error: std::io::Error) -> PyError {
    PyError::os(&error)
}

/// `binary_info(path, expected_target, probe_version)`.
///
/// Opens `path` once and works on that descriptor only: with an
/// `expected_target`, the descriptor's own target (`/proc/self/fd/<fd>`)
/// must equal `realpath(expected_target)` before anything else happens, and
/// the probe executes the descriptor (`/proc/self/fd/<fd> version`), never
/// `path`. Without one, the probe runs `path version` (the installed binary,
/// as Python does). The identity before the hash, after the probe and of a
/// final `stat(path)` must be equal.
pub fn binary_info<S: System>(
    system: &S,
    path: &Path,
    expected_target: Option<&Path>,
    probe_version: bool,
) -> Result<BinaryInfo, PyError> {
    let mut file = system.open(path).map_err(os_error)?;
    let descriptor = OsString::from(format!("/proc/self/fd/{}", file.fd()));
    if let Some(expected) = expected_target {
        let target = system.readlink(Path::new(&descriptor)).map_err(os_error)?;
        let real = system.realpath(expected).map_err(os_error)?;
        if target != real.into_os_string() {
            return Err(PyError::value(
                "refusing unexpected or deleted process image",
            ));
        }
    }
    let before = system.fstat(&file).map_err(os_error)?;
    let digest = system.sha256(&mut file).map_err(os_error)?;
    let output = match (probe_version, expected_target) {
        (false, _) => String::new(),
        (true, Some(_)) => command_inheriting(
            system,
            &file,
            &[&descriptor, OsStr::new("version")],
            COMMAND_TIMEOUT,
        )?,
        (true, None) => command(
            system,
            &[path.as_os_str(), OsStr::new("version")],
            COMMAND_TIMEOUT,
        )?,
    };
    let after = system.fstat(&file).map_err(os_error)?;
    drop(file);
    let version = VERSION_LINE.captures(&output).map(|captures| {
        let found = &captures[1];
        found.strip_prefix('v').unwrap_or(found).to_owned()
    });
    if probe_version && version.is_none() {
        return Err(PyError::value("unparseable binary version"));
    }
    let last = system.stat(path).map_err(os_error)?;
    if !same_identity(&before, &after) || !same_identity(&before, &last) {
        return Err(PyError::value("binary changed during observation"));
    }
    Ok(BinaryInfo {
        version,
        sha256: digest,
    })
}

fn same_identity(a: &FileStat, b: &FileStat) -> bool {
    a.identity() == b.identity()
}

/// A process id as `int(text)` reads it: any size, kept as its canonical
/// decimal text (with a `-` sign when negative).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pid(String);

impl Pid {
    /// `int(text)` in base 10 with ASCII digits (PLAN.md 4.2 item 11):
    /// surrounding whitespace, a sign, single underscores between digits,
    /// leading zeros; at most 4300 digits.
    pub fn parse(text: &str) -> Result<Self, PyError> {
        let invalid =
            || PyError::value(format!("invalid literal for int() with base 10: '{text}'"));
        let stripped = python_strip(text);
        let (negative, body) = match stripped.as_bytes().first() {
            Some(b'-') => (true, &stripped[1..]),
            Some(b'+') => (false, &stripped[1..]),
            _ => (false, stripped),
        };
        let well_formed = !body.is_empty()
            && body
                .split('_')
                .all(|group| !group.is_empty() && group.bytes().all(|byte| byte.is_ascii_digit()));
        if !well_formed {
            return Err(invalid());
        }
        let digits: String = body.chars().filter(|c| *c != '_').collect();
        if digits.len() > INT_MAX_STR_DIGITS {
            return Err(int_digits_error(digits.len()));
        }
        let magnitude = match digits.trim_start_matches('0') {
            "" => "0",
            trimmed => trimmed,
        };
        Ok(Self(if negative && magnitude != "0" {
            format!("-{magnitude}")
        } else {
            magnitude.to_owned()
        }))
    }

    /// Python's truth value of the number.
    pub fn is_zero(&self) -> bool {
        self.0 == "0"
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_value(&self) -> Value {
        // A canonical integer is a valid JSON number token, kept as written.
        serde_json::from_str(&self.0).expect("a canonical integer is a JSON number")
    }
}

/// `main_pid(unit)`: `int(systemctl show <unit> --property=MainPID --value)`,
/// `systemctl` looked up in `PATH`.
pub fn main_pid<S: System>(system: &S, unit: &str) -> Result<Pid, PyError> {
    let output = command(
        system,
        &[
            OsStr::new("systemctl"),
            OsStr::new("show"),
            OsStr::new(unit),
            OsStr::new("--property=MainPID"),
            OsStr::new("--value"),
        ],
        COMMAND_TIMEOUT,
    )?;
    Pid::parse(&output)
}

/// `version(value)` of a JSON value: anything but a string is the
/// `TypeError` of `re.fullmatch`.
fn version_of(value: &Value) -> Result<Release, PyError> {
    match value {
        Value::String(text) => version(text),
        other => Err(PyError::type_error(format!(
            "expected string or bytes-like object, got '{}'",
            type_name(other)
        ))),
    }
}

/// The part of a validated policy (`policy["traefik"]`) the observation reads.
struct TraefikPolicy<'a> {
    expected: &'a Value,
    unit: &'a str,
    binary_path: &'a str,
    desired_version: Value,
}

impl<'a> TraefikPolicy<'a> {
    fn of(policy: &'a Value) -> Self {
        // `validate_policy` has checked every one of these (PLAN.md 3.2).
        Self {
            expected: &policy["expected"],
            unit: policy["unit"].as_str().unwrap_or_default(),
            binary_path: policy["binary_path"].as_str().unwrap_or_default(),
            desired_version: policy
                .get("desired_version")
                .cloned()
                .unwrap_or(Value::Null),
        }
    }
}

/// The state of the attempt the observation accepted.
struct Accepted {
    pid: Pid,
    target: OsString,
    installed: BinaryInfo,
    running: BinaryInfo,
}

/// `observe_traefik(policy, latest)`: `policy` is the validated
/// `policy["traefik"]`, `latest` the Traefik upstream result. Every failure
/// ends in `status: "unknown"` with the fields and issues known so far.
pub fn observe<S: System>(system: &S, policy: &Value, latest: &Value) -> Observation {
    let policy = TraefikPolicy::of(policy);
    let mut result = Observation::new();
    result
        .set("expected", policy.expected.clone())
        .set("observed", false)
        .set("binary_path", policy.binary_path)
        .set("desired_version", policy.desired_version.clone())
        .reset_issues();
    if let Err(error) = observe_into(system, &policy, latest, &mut result) {
        result.fail(&error);
    }
    result
}

fn observe_into<S: System>(
    system: &S,
    policy: &TraefikPolicy<'_>,
    latest: &Value,
    result: &mut Observation,
) -> Result<(), PyError> {
    let path = Path::new(policy.binary_path);
    let mut accepted = None;
    for attempt in 0..2 {
        result.reset_issues();
        let pid = main_pid(system, policy.unit)?;
        let exists = system.exists(path).map_err(os_error)?;
        if policy.expected != &Value::Bool(true) {
            let mut other = false;
            for candidate in TRAEFIK_BINARIES {
                if system.exists(Path::new(candidate)).map_err(os_error)? {
                    other = true;
                    break;
                }
            }
            let present = !pid.is_zero() || other;
            result
                .set("status", if present { "warning" } else { "ok" })
                .set("present", present)
                .set("observed", true);
            if present {
                result.push_issue("unexpected_installation");
            }
            return Ok(());
        }
        if pid.is_zero() || !exists {
            return Err(PyError::value("service stopped or managed binary missing"));
        }
        let running_path = OsString::from(format!("/proc/{}/exe", pid.as_str()));
        let running_path = Path::new(&running_path);
        let target = system.readlink(running_path).map_err(os_error)?;
        let raw = target.as_bytes();
        if raw.ends_with(DELETED) {
            result.push_issue("deleted_running_executable");
        }
        let real = system.realpath(path).map_err(os_error)?;
        if raw.strip_suffix(DELETED).unwrap_or(raw) != real.as_os_str().as_bytes() {
            result.push_issue("running_path_mismatch");
        }
        let refuse_execution = target != system.realpath(path).map_err(os_error)?.into_os_string();
        let installed = binary_info(system, path, None, true)?;
        let running = if refuse_execution {
            binary_info(system, running_path, None, false)?
        } else {
            binary_info(system, running_path, Some(path), true)?
        };
        if main_pid(system, policy.unit)? == pid
            && system.readlink(running_path).map_err(os_error)? == target
        {
            accepted = Some(Accepted {
                pid,
                target,
                installed,
                running,
            });
            break;
        }
        if attempt == 1 {
            return Err(PyError::value("MainPID changed during observation"));
        }
    }
    let Accepted {
        pid,
        target,
        installed,
        running,
    } = accepted.expect("the second attempt either breaks or fails");
    result
        .set("observed", true)
        .set("installed", installed.to_value())
        .set("running", running.to_value())
        .set("main_pid", pid.to_value())
        .set("running_path", target.to_string_lossy().into_owned())
        .set("upstream", latest.clone());
    if installed.sha256 != running.sha256
        || (running.version.is_some() && installed.version != running.version)
    {
        result.push_issue("installed_running_drift");
    }
    let installed_version = installed.version.clone().map_or(Value::Null, Value::String);
    if policy.desired_version.is_null() {
        result.push_issue("desired_version_unassigned");
    } else if version_of(&policy.desired_version)? != version_of(&installed_version)? {
        result.push_issue("desired_installed_drift");
    }
    if subscript(latest, "status")? != "ok" {
        result.push_issue("upstream_unknown");
        result.set("status", "unknown");
    } else {
        if let Some(running_version) = &running.version
            && version(running_version)? < version_of(subscript(latest, "version")?)?
        {
            result.push_issue("outdated_running_version");
        }
        let status = if result.has_issues() { "warning" } else { "ok" };
        result.set("status", status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::fake::{FakeSystem, World};
    use crate::testutil::{ErrorSpec, json_eq};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixtures {
        binary_info: Vec<BinaryInfoCase>,
        observe: Vec<ObserveCase>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BinaryInfoCase {
        id: String,
        world: World,
        path: String,
        expected_target: Option<String>,
        probe_version: bool,
        result: Option<Value>,
        error: Option<ErrorSpec>,
        calls: Vec<String>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ObserveCase {
        id: String,
        world: World,
        policy: Value,
        latest: Value,
        result: Map<String, Value>,
        error: Option<ErrorSpec>,
        calls: Vec<String>,
        #[serde(default)]
        p3: Option<String>,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/traefik.json")).unwrap()
    }

    fn calls(fake: &FakeSystem) -> Vec<String> {
        fake.calls.borrow().clone()
    }

    #[test]
    fn binary_info_matches_python() {
        let cases = fixtures().binary_info;
        assert!(cases.len() >= 30, "{}", cases.len());
        for case in cases {
            let id = &case.id;
            let fake = FakeSystem::new(case.world);
            let outcome = binary_info(
                &fake,
                Path::new(&case.path),
                case.expected_target.as_deref().map(Path::new),
                case.probe_version,
            );
            if case.p3.is_some() {
                // Python reads non-ASCII digits as a version; Rust does not
                // (PLAN.md 4.2 item 11).
                let error = outcome.expect_err(id);
                assert_eq!(
                    error.to_string(),
                    "ValueError: unparseable binary version",
                    "{id}"
                );
                continue;
            }
            match (&case.result, &case.error, outcome) {
                (Some(expected), None, Ok(info)) => {
                    assert!(json_eq(&info.to_value(), expected), "{id}: {info:?}")
                }
                (None, Some(spec), Err(error)) => spec.assert_matches(&error, id),
                (_, _, outcome) => panic!("{id}: unexpected {outcome:?}"),
            }
            assert_eq!(calls(&fake), case.calls, "{id}");
            assert_eq!(fake.pending_commands(), 0, "{id}");
        }
    }

    #[test]
    fn observation_matches_python() {
        let cases = fixtures().observe;
        assert!(cases.len() >= 40, "{}", cases.len());
        for case in cases {
            let id = &case.id;
            let fake = FakeSystem::new(case.world);
            let result = observe(&fake, &case.policy, &case.latest);
            let mut actual = result.as_map().clone();
            let error = actual.remove("error");
            if case.p3.is_some() {
                // Python reads a MainPID with non-ASCII digits; Rust does not
                // (PLAN.md 4.2 item 11).
                assert_eq!(actual.get("status"), Some(&Value::from("unknown")), "{id}");
                let text = error.and_then(|e| e.as_str().map(str::to_owned));
                assert!(
                    text.as_deref()
                        .is_some_and(|t| t.starts_with("ValueError: ")),
                    "{id}: {text:?}"
                );
                continue;
            }
            assert!(
                json_eq(
                    &Value::Object(actual.clone()),
                    &Value::Object(case.result.clone())
                ),
                "{id}:\n rust   {actual:?}\n python {:?}",
                case.result
            );
            match (&case.error, error) {
                (None, None) => {}
                (Some(spec), Some(Value::String(text))) => {
                    let (class, message) = text.split_once(": ").expect("Class: message");
                    assert_eq!(class, spec.class, "{id}: {text}");
                    if let Some(expected) = &spec.message {
                        assert_eq!(message, expected, "{id}");
                    }
                    assert!(text.chars().count() <= 240, "{id}");
                }
                (spec, error) => panic!("{id}: expected {spec:?}, got {error:?}"),
            }
            assert_eq!(calls(&fake), case.calls, "{id}");
            assert_eq!(fake.pending_commands(), 0, "{id}");
        }
    }

    fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// `test_binary_identity_and_in_place_change` on a real file: the probe
    /// runs the installed path, and a binary that changes while it is
    /// probed is refused.
    #[test]
    fn real_binary_identity_and_in_place_change() {
        use crate::probe::HostSystem;
        let dir = tempfile::tempdir().unwrap();
        let proxy = script(dir.path(), "proxy", "printf 'Version: 3.7.9\\n'");
        let info = binary_info(&HostSystem, &proxy, None, true).unwrap();
        assert_eq!(info.version.as_deref(), Some("3.7.9"));
        let bytes = std::fs::read(&proxy).unwrap();
        assert_eq!(
            info.sha256,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes))
        );
        let changing = script(
            dir.path(),
            "changing",
            "printf 'Version: 3.7.9\\n'; printf '#' >> \"$0\"",
        );
        let error = binary_info(&HostSystem, &changing, None, true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ValueError: binary changed during observation"
        );
        // Without a probe nothing is executed: the file need not be executable.
        let data = dir.path().join("data");
        std::fs::write(&data, b"unexpected bytes").unwrap();
        let info = binary_info(&HostSystem, &data, None, false).unwrap();
        assert_eq!(info.version, None);
    }

    #[test]
    fn pid_parsing_follows_int() {
        let ok = |text: &str| Pid::parse(text).unwrap().as_str().to_owned();
        assert_eq!(ok("11"), "11");
        assert_eq!(ok(" 11\n"), "11");
        assert_eq!(ok("+11"), "11");
        assert_eq!(ok("1_1"), "11");
        assert_eq!(ok("0011"), "11");
        assert_eq!(ok("-0"), "0");
        assert_eq!(ok("000"), "0");
        assert_eq!(ok("-5"), "-5");
        assert_eq!(ok("99999999999999999999999"), "99999999999999999999999");
        assert!(Pid::parse("0").unwrap().is_zero());
        for invalid in [
            "", "x", "1__1", "_1", "1_", "+", "-", "1 1", "0x10", "1.0", "+-1", "\u{661}",
        ] {
            assert_eq!(
                Pid::parse(invalid).unwrap_err().class,
                "ValueError",
                "{invalid:?}"
            );
        }
        let error = Pid::parse(&"1".repeat(4301)).unwrap_err();
        assert!(
            error.message.starts_with("Exceeds the limit (4300 digits)"),
            "{error}"
        );
        assert_eq!(Pid::parse(&"1".repeat(4300)).unwrap().as_str().len(), 4300);
        assert_eq!(
            Pid::parse("-12").unwrap().to_value(),
            serde_json::json!(-12)
        );
    }
}
