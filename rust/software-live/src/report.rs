//! The report (`collect`, `software_live.py:644-684`), its summary and
//! `with_freshness` (`:687-710`), PLAN.md 3.3 and 3.4.
//!
//! An observation (`traefik`, `os`, `postgresql`, `apt`) is a JSON object
//! that its `observe_*` step fills field by field and, on any failure,
//! closes with `status: "unknown"` and `error: "<Class>: <message>"[:240]`
//! while keeping every field and issue set so far ("accumulate, then fail
//! with what is known"). [`Observation`] is that object.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::PyError;
use crate::policy::Policy;
use crate::pyjson::{self, eq_int, is_int_token, token_f64};

pub const SCHEMA_VERSION: i64 = 2;
/// A report older than this (seconds) is not fresh (`MAX_REPORT_AGE`).
pub const MAX_REPORT_AGE: i64 = 1800;
/// `error` texts are cut to this many characters (code points).
pub const ERROR_LIMIT: usize = 240;
/// The summary keys `with_freshness` requires to be booleans.
pub const SUMMARY_KEYS: [&str; 6] = [
    "observation_ok",
    "os_ok",
    "postgresql_ok",
    "traefik_ok",
    "security_updates_ok",
    "apt_indexes_fresh",
];

/// `f"{type(exc).__name__}: {exc}"[:240]`.
pub fn error_text(error: &PyError) -> String {
    error.to_string().chars().take(ERROR_LIMIT).collect()
}

/// One observation object of the report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Observation(Map<String, Value>);

impl Observation {
    pub fn new() -> Self {
        Self::default()
    }

    /// An observation from its JSON object (`None` for anything else).
    pub fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Object(map) => Some(Self(map)),
            _ => None,
        }
    }

    pub fn set(&mut self, key: &str, value: impl Into<Value>) -> &mut Self {
        self.0.insert(key.to_owned(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// `result["issues"].append(issue)` (creates the list if needed).
    pub fn push_issue(&mut self, issue: &str) -> &mut Self {
        let issues = self
            .0
            .entry("issues")
            .or_insert_with(|| Value::Array(Vec::new()));
        if !issues.is_array() {
            *issues = Value::Array(Vec::new());
        }
        if let Value::Array(list) = issues {
            list.push(Value::String(issue.to_owned()));
        }
        self
    }

    /// `result["issues"] = []`.
    pub fn reset_issues(&mut self) -> &mut Self {
        self.set("issues", Value::Array(Vec::new()))
    }

    pub fn has_issues(&self) -> bool {
        matches!(self.get("issues"), Some(Value::Array(list)) if !list.is_empty())
    }

    /// `result["observed"]` (always a bool in a report).
    pub fn observed(&self) -> bool {
        self.get("observed") == Some(&Value::Bool(true))
    }

    pub fn status(&self) -> Option<&str> {
        self.get("status").and_then(Value::as_str)
    }

    /// The exception boundary of an `observe_*` step:
    /// `result.update(status="unknown", error=f"{Class}: {message}"[:240])`.
    pub fn fail(&mut self, error: &PyError) -> &mut Self {
        self.set("status", "unknown");
        self.set("error", error_text(error))
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// The `summary` of a report (without `fresh`, which only
/// [`with_freshness`] adds).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub observation_ok: bool,
    pub os_ok: bool,
    pub postgresql_ok: bool,
    pub traefik_ok: bool,
    pub security_updates_ok: bool,
    pub apt_indexes_fresh: bool,
}

impl Summary {
    /// `software_live.py:673-683`.
    pub fn of(
        traefik: &Observation,
        os: &Observation,
        postgresql: &Observation,
        apt: &Observation,
    ) -> Self {
        let ok = |item: &Observation| item.status() == Some("ok");
        Self {
            observation_ok: traefik.observed()
                && os.observed()
                && postgresql.observed()
                && apt.status() != Some("unknown"),
            os_ok: ok(os),
            postgresql_ok: ok(postgresql),
            traefik_ok: ok(traefik),
            // `pending_security_count == 0`: false for `null`.
            security_updates_ok: apt
                .get("pending_security_count")
                .is_some_and(|count| eq_int(count, 0)),
            // The APT observation always carries a bool here (PLAN.md 3.3).
            apt_indexes_fresh: apt.get("indexes_fresh") == Some(&Value::Bool(true)),
        }
    }
}

/// A complete report (`schema_version` 2).
#[derive(Clone, Debug)]
pub struct Report {
    pub host: String,
    pub generated_at_epoch: f64,
    pub policy_sha256: String,
    pub traefik: Observation,
    pub os: Observation,
    pub postgresql: Observation,
    pub apt: Observation,
    pub summary: Summary,
}

impl Report {
    /// The report of `collect` from its observations; `generated_at_epoch`
    /// is the clock read after the last observation (PLAN.md 3.3).
    pub fn new(
        policy: &Policy,
        traefik: Observation,
        os: Observation,
        postgresql: Observation,
        apt: Observation,
        generated_at_epoch: f64,
    ) -> Result<Self, PyError> {
        if !generated_at_epoch.is_finite() {
            return Err(PyError::value("invalid timestamp"));
        }
        let summary = Summary::of(&traefik, &os, &postgresql, &apt);
        Ok(Self {
            host: policy.host().to_owned(),
            generated_at_epoch,
            policy_sha256: policy.sha256(),
            traefik,
            os,
            postgresql,
            apt,
            summary,
        })
    }

    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("schema_version".into(), SCHEMA_VERSION.into());
        map.insert("host".into(), self.host.clone().into());
        map.insert(
            "generated_at_epoch".into(),
            Value::Number(
                pyjson::number_from_f64(self.generated_at_epoch).expect("checked to be finite"),
            ),
        );
        map.insert("policy_sha256".into(), self.policy_sha256.clone().into());
        map.insert("os".into(), self.os.clone().into_value());
        map.insert("postgresql".into(), self.postgresql.clone().into_value());
        map.insert("traefik".into(), self.traefik.clone().into_value());
        map.insert("apt".into(), self.apt.clone().into_value());
        map.insert(
            "summary".into(),
            serde_json::to_value(self.summary).expect("a summary is plain booleans"),
        );
        Value::Object(map)
    }
}

/// `generated_at_epoch` as Python's `math.isfinite` sees it: an `int` or
/// `float` (never `bool`), finite; an `int` too large for a float is an
/// `OverflowError`.
fn timestamp(value: &Value) -> Result<f64, PyError> {
    let Value::Number(number) = value else {
        return Err(PyError::value("invalid timestamp"));
    };
    let token = number.as_str();
    let seconds = token_f64(token);
    if seconds.is_finite() {
        Ok(seconds)
    } else if is_int_token(token) {
        Err(PyError::new(
            "OverflowError",
            "int too large to convert to float",
        ))
    } else {
        Err(PyError::value("invalid timestamp"))
    }
}

/// `with_freshness(data, now)`: check the report shape, then add
/// `meta {age_seconds, max_age_seconds}` and `summary.fresh`. Every other
/// key stays as it is. A stale report is fresh `false`, not an error.
pub fn with_freshness(mut data: Value, now: f64) -> Result<Value, PyError> {
    let schema = PyError::value("invalid report schema");
    let Value::Object(map) = &mut data else {
        return Err(schema);
    };
    let schema_ok = map
        .get("schema_version")
        .is_some_and(|value| eq_int(value, SCHEMA_VERSION));
    if !schema_ok || !map.get("summary").is_some_and(Value::is_object) {
        return Err(schema);
    }
    let summary = &map["summary"];
    if SUMMARY_KEYS
        .iter()
        .any(|key| !summary.get(key).is_some_and(Value::is_boolean))
    {
        return Err(PyError::type_error("invalid summary"));
    }
    let generated = map
        .get("generated_at_epoch")
        .ok_or_else(|| PyError::key("generated_at_epoch"))?;
    let age = now - timestamp(generated)?;
    let age_number =
        pyjson::number_from_f64(age).ok_or_else(|| PyError::value("invalid timestamp"))?;
    let mut meta = Map::new();
    meta.insert("age_seconds".into(), Value::Number(age_number));
    meta.insert("max_age_seconds".into(), MAX_REPORT_AGE.into());
    map.insert("meta".into(), Value::Object(meta));
    let fresh = (0.0..=MAX_REPORT_AGE as f64).contains(&age);
    if let Some(Value::Object(summary)) = map.get_mut("summary") {
        summary.insert("fresh".into(), Value::Bool(fresh));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ErrorSpec, json_eq};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixtures {
        summary: Vec<SummaryCase>,
        freshness: Vec<FreshnessCase>,
        errors: Vec<ErrorCase>,
    }

    #[derive(Deserialize)]
    struct SummaryCase {
        id: String,
        policy: String,
        observations: Map<String, Value>,
        generated_at_epoch: f64,
        report_keys: Vec<String>,
        policy_sha256: String,
        summary: Summary,
    }

    #[derive(Deserialize)]
    struct FreshnessCase {
        id: String,
        text: String,
        now: f64,
        #[serde(default)]
        result: Option<String>,
        #[serde(default)]
        error: Option<ErrorSpec>,
    }

    #[derive(Deserialize)]
    struct ErrorCase {
        class: String,
        message: String,
        text: String,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/report.json")).unwrap()
    }

    fn observation(observations: &Map<String, Value>, name: &str) -> Observation {
        Observation::from_value(observations[name].clone()).unwrap()
    }

    #[test]
    fn summary_and_report_shape_match_python() {
        let cases = fixtures().summary;
        assert!(cases.len() >= 12);
        for case in cases {
            let policy = Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap();
            let obs = &case.observations;
            let report = Report::new(
                &policy,
                observation(obs, "traefik"),
                observation(obs, "os"),
                observation(obs, "postgresql"),
                observation(obs, "apt"),
                case.generated_at_epoch,
            )
            .unwrap();
            assert_eq!(report.summary, case.summary, "{}", case.id);
            assert_eq!(report.policy_sha256, case.policy_sha256, "{}", case.id);
            let value = report.to_value();
            let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
            assert_eq!(keys, case.report_keys, "{}", case.id);
            for name in ["traefik", "os", "postgresql", "apt"] {
                assert!(json_eq(&value[name], &obs[name]), "{}: {name}", case.id);
            }
            assert_eq!(value["host"], policy.host(), "{}", case.id);
            assert_eq!(value["schema_version"], 2, "{}", case.id);
        }
    }

    #[test]
    fn freshness_matches_python() {
        let cases = fixtures().freshness;
        assert!(cases.len() >= 25);
        for case in cases {
            let id = &case.id;
            let data = pyjson::loads(&case.text).unwrap_or_else(|e| panic!("{id}: {e}"));
            let result = with_freshness(data, case.now);
            match (&case.result, &case.error) {
                (Some(expected), None) => {
                    let expected = pyjson::loads(expected).unwrap();
                    let actual = result.unwrap_or_else(|e| panic!("{id}: {e}"));
                    assert!(json_eq(&actual, &expected), "{id}: {actual} != {expected}");
                }
                (None, Some(expected)) => expected.assert_matches(&result.unwrap_err(), id),
                _ => panic!("{id}: fixture needs a result or an error"),
            }
        }
    }

    #[test]
    fn error_texts_are_cut_like_python() {
        let cases = fixtures().errors;
        assert!(cases.len() >= 3);
        for case in cases {
            let class: &'static str = Box::leak(case.class.into_boxed_str());
            let mut item = Observation::new();
            item.set("observed", false).push_issue("kept");
            item.fail(&PyError::new(class, case.message));
            assert_eq!(item.get("error").unwrap(), &Value::String(case.text));
            assert_eq!(item.status(), Some("unknown"));
            assert_eq!(item.get("issues").unwrap(), &serde_json::json!(["kept"]));
        }
    }

    #[test]
    fn issues_accumulate_and_reset() {
        let mut item = Observation::new();
        assert!(!item.has_issues());
        item.push_issue("a").push_issue("b");
        assert_eq!(item.get("issues").unwrap(), &serde_json::json!(["a", "b"]));
        item.reset_issues();
        assert!(!item.has_issues());
        assert_eq!(item.get("issues").unwrap(), &serde_json::json!([]));
    }

    #[test]
    fn non_finite_generation_time_is_refused() {
        let text = r#"{"host": "h", "traefik": {"expected": false, "unit": "traefik.service",
            "binary_path": "/usr/bin/traefik"}, "os": {"expected_id": "debian", "product": "debian",
            "desired_cycle": "13"}, "postgresql": {"expected": false}}"#;
        let policy = Policy::new(pyjson::loads(text).unwrap()).unwrap();
        let empty = Observation::new;
        assert!(Report::new(&policy, empty(), empty(), empty(), empty(), f64::NAN).is_err());
    }
}
