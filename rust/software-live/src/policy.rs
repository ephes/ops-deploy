//! The collector policy: `validate_policy` (`software_live.py:607-641`) and
//! `policy_sha256` (`:666-668`), PLAN.md 3.2.
//!
//! The policy stays a JSON value, as in Python: extra keys are allowed and
//! go into the hash. Validation follows the Python code step by step,
//! including the order of the checks and the exception class each step
//! raises on a value of the wrong type (a missing key is a `KeyError`, a
//! subscript of a non-mapping a `TypeError`, `.get` on a non-mapping an
//! `AttributeError`, set membership of a list or mapping a `TypeError`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::PyError;
use crate::pyjson::{self, py_str, token_i128, type_name};
use crate::version::version;

/// `apt_max_age_seconds` when the policy has none.
pub const DEFAULT_APT_MAX_AGE: i64 = 172_800;

/// The Traefik binaries a policy may name (also the paths an unexpected
/// installation is looked for at, `software_live.py:262-265`).
pub const TRAEFIK_BINARIES: [&str; 2] = ["/usr/bin/traefik", "/usr/local/bin/traefik"];
const OS_IDS: [&str; 2] = ["debian", "ubuntu"];

// Python's `\d` also matches non-ASCII digits (PLAN.md 4.2 item 11).
static CYCLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+(?:\.[0-9]+)?$").expect("valid pattern"));
static MAJOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").expect("valid pattern"));
/// The PostgreSQL cluster name pattern (also used for `pg_lsclusters`).
pub static CLUSTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_-]*$").expect("valid pattern"));

/// `value.get(key)`: an `AttributeError` unless `value` is a mapping.
fn get<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>, PyError> {
    match value {
        Value::Object(map) => Ok(map.get(key)),
        other => Err(PyError::new(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", type_name(other)),
        )),
    }
}

/// `value[key]` with a `str` key.
pub(crate) fn subscript<'a>(value: &'a Value, key: &str) -> Result<&'a Value, PyError> {
    match value {
        Value::Object(map) => map.get(key).ok_or_else(|| PyError::key(key)),
        Value::Array(_) => Err(PyError::type_error(
            "list indices must be integers or slices, not str",
        )),
        Value::String(_) => Err(PyError::type_error(
            "string indices must be integers, not 'str'",
        )),
        other => Err(PyError::type_error(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        ))),
    }
}

/// `value in {<strings>}`: hashing a list or a mapping is a `TypeError`.
fn in_str_set(value: &Value, set: &[&str]) -> Result<bool, PyError> {
    match value {
        Value::Array(_) | Value::Object(_) => Err(PyError::type_error(format!(
            "unhashable type: '{}'",
            type_name(value)
        ))),
        Value::String(text) => Ok(set.contains(&text.as_str())),
        _ => Ok(false),
    }
}

/// `re.fullmatch(pattern, value)`: anything but a `str` is a `TypeError`.
fn fullmatch(pattern: &Regex, value: &Value) -> Result<bool, PyError> {
    match value {
        Value::String(text) => Ok(pattern.is_match(text)),
        other => Err(PyError::type_error(format!(
            "expected string or bytes-like object, got '{}'",
            type_name(other)
        ))),
    }
}

/// `isinstance(value, int) and not isinstance(value, bool) and low <= value <= high`.
fn int_in_range(value: Option<&Value>, low: i128, high: i128) -> bool {
    // An integer token beyond i128 is out of every range checked here.
    match value {
        Some(Value::Number(number)) => {
            token_i128(number.as_str()).is_some_and(|n| (low..=high).contains(&n))
        }
        _ => false,
    }
}

fn empty_str() -> Value {
    Value::String(String::new())
}

/// `validate_policy(policy)`.
pub fn validate(policy: &Value) -> Result<(), PyError> {
    match get(policy, "host")? {
        Some(Value::String(host)) if !host.is_empty() => {}
        _ => return Err(PyError::value("host is required")),
    }

    let traefik = subscript(policy, "traefik")?;
    if !subscript(traefik, "expected")?.is_boolean()
        || subscript(traefik, "unit")?.as_str() != Some("traefik.service")
    {
        return Err(PyError::value("invalid Traefik policy"));
    }
    if !in_str_set(subscript(traefik, "binary_path")?, &TRAEFIK_BINARIES)? {
        return Err(PyError::value("unsupported binary path"));
    }
    match get(traefik, "desired_version")? {
        None | Some(Value::Null) => {}
        Some(Value::String(desired)) => {
            version(desired)?;
        }
        Some(other) => {
            return Err(PyError::type_error(format!(
                "expected string or bytes-like object, got '{}'",
                type_name(other)
            )));
        }
    }

    let os = subscript(policy, "os")?;
    let expected_id = get(os, "expected_id")?.unwrap_or(&Value::Null);
    if !in_str_set(expected_id, &OS_IDS)? {
        return Err(PyError::value("unsupported operating system policy"));
    }
    if get(os, "product")? != Some(subscript(os, "expected_id")?) {
        return Err(PyError::value(
            "operating system lifecycle product mismatch",
        ));
    }
    let cycle = get(os, "desired_cycle")?.cloned().unwrap_or_else(empty_str);
    if !CYCLE.is_match(&py_str(&cycle)) {
        return Err(PyError::value("invalid desired operating system cycle"));
    }

    let postgresql = subscript(policy, "postgresql")?;
    let Some(Value::Bool(expected)) = get(postgresql, "expected")? else {
        return Err(PyError::type_error("invalid PostgreSQL expected state"));
    };
    if *expected {
        let major = get(postgresql, "desired_major")?
            .cloned()
            .unwrap_or_else(empty_str);
        if !MAJOR.is_match(&py_str(&major)) {
            return Err(PyError::value("invalid desired PostgreSQL major"));
        }
        let cluster = get(postgresql, "cluster")?
            .cloned()
            .unwrap_or_else(empty_str);
        if !fullmatch(&CLUSTER, &cluster)? {
            return Err(PyError::value("invalid PostgreSQL cluster"));
        }
        if !int_in_range(get(postgresql, "port")?, 1, 65_535) {
            return Err(PyError::value("invalid PostgreSQL port"));
        }
    }

    let age = match get(policy, "apt_max_age_seconds")? {
        None => Some(Value::from(DEFAULT_APT_MAX_AGE)),
        Some(value) => Some(value.clone()),
    };
    if !int_in_range(age.as_ref(), 3_600, 1_209_600) {
        return Err(PyError::value("invalid APT age budget"));
    }
    Ok(())
}

/// `policy_sha256`: sha256 of `json.dumps(policy, sort_keys=True)`.
pub fn sha256(policy: &Value) -> String {
    hex::encode(Sha256::digest(pyjson::python_dumps(policy)))
}

/// The fields of a policy that [`validate`] has accepted, for the collector.
#[derive(Clone, Debug)]
pub struct Policy {
    pub raw: Value,
}

impl Policy {
    /// Validate a parsed policy.
    pub fn new(raw: Value) -> Result<Self, PyError> {
        validate(&raw)?;
        Ok(Self { raw })
    }

    fn map(&self) -> &Map<String, Value> {
        self.raw
            .as_object()
            .expect("a validated policy is a mapping")
    }

    pub fn host(&self) -> &str {
        self.map()["host"]
            .as_str()
            .expect("a validated host is a string")
    }

    pub fn traefik_expected(&self) -> bool {
        self.map()["traefik"]["expected"] == true
    }

    pub fn postgresql_expected(&self) -> bool {
        self.map()["postgresql"]["expected"] == true
    }

    /// `policy.get("apt_max_age_seconds", 172800)`.
    pub fn apt_max_age_seconds(&self) -> i64 {
        self.map()
            .get("apt_max_age_seconds")
            .and_then(|value| value.as_number())
            .and_then(|number| token_i128(number.as_str()))
            .and_then(|n| i64::try_from(n).ok())
            .unwrap_or(DEFAULT_APT_MAX_AGE)
    }

    pub fn sha256(&self) -> String {
        sha256(&self.raw)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::ErrorSpec;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Case {
        id: String,
        text: String,
        #[serde(default)]
        load_error: Option<ErrorSpec>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        #[serde(default)]
        policy_sha256: Option<String>,
        #[serde(default)]
        p3: Option<String>,
    }

    fn cases() -> Vec<Case> {
        serde_json::from_str(include_str!("../fixtures/policy.json")).unwrap()
    }

    #[test]
    fn validation_and_hash_match_python() {
        let cases = cases();
        assert!(cases.len() >= 60, "{}", cases.len());
        let mut hashed = 0;
        for case in cases {
            let id = &case.id;
            let loaded = pyjson::loads(&case.text);
            if let Some(tag) = &case.p3 {
                // PLAN.md 4.2 items 4 and 11: Python accepts, Rust refuses.
                assert!(
                    case.load_error.is_none() && case.error.is_none(),
                    "{id}: {tag}"
                );
                let refused = match loaded {
                    Err(_) => true,
                    Ok(value) => validate(&value).is_err(),
                };
                assert!(refused, "{id}: P3 {tag} must be refused");
                continue;
            }
            if let Some(expected) = &case.load_error {
                expected.assert_matches(&loaded.unwrap_err(), id);
                continue;
            }
            let value = loaded.unwrap_or_else(|e| panic!("{id}: {e}"));
            match (&case.error, &case.policy_sha256) {
                (Some(expected), None) => {
                    expected.assert_matches(&validate(&value).unwrap_err(), id)
                }
                (None, Some(expected)) => {
                    let policy = Policy::new(value).unwrap_or_else(|e| panic!("{id}: {e}"));
                    assert_eq!(&policy.sha256(), expected, "{id}");
                    hashed += 1;
                }
                _ => panic!("{id}: fixture needs an error or a hash"),
            }
        }
        assert!(hashed >= 15, "{hashed}");
    }

    #[test]
    fn accessors_read_the_validated_policy() {
        let text = r#"{"host": "h", "traefik": {"expected": false, "unit": "traefik.service",
            "binary_path": "/usr/bin/traefik"}, "os": {"expected_id": "debian", "product": "debian",
            "desired_cycle": "13"}, "postgresql": {"expected": true, "desired_major": "17",
            "cluster": "main", "port": 5432}, "apt_max_age_seconds": 3600}"#;
        let policy = Policy::new(pyjson::loads(text).unwrap()).unwrap();
        assert_eq!(policy.host(), "h");
        assert!(!policy.traefik_expected());
        assert!(policy.postgresql_expected());
        assert_eq!(policy.apt_max_age_seconds(), 3600);
        let mut raw = policy.raw.clone();
        raw.as_object_mut().unwrap().remove("apt_max_age_seconds");
        assert_eq!(
            Policy::new(raw).unwrap().apt_max_age_seconds(),
            DEFAULT_APT_MAX_AGE
        );
    }
}
