//! Lifecycle evaluation of endoflife.date cycles, shared by the OS and the
//! PostgreSQL observations: `lifecycle_ended` (`software_live.py:55-59`, on
//! `upstream::lifecycle_date`, `YYYY-MM-DD` only, PLAN.md 4.2 item 6), `lifecycle_cycle`, `lifecycle_evidence`
//! (`:320-343`) and the UTC date of the observation time
//! (`datetime.fromtimestamp(now, UTC).date()`), PLAN.md 3.3.
//!
//! `latest` is what the lifecycle upstream lookup returns (S3a, PLAN.md 3.3
//! "Upstream lookups and caches"): an object with `status` and, when `ok`,
//! the validated `cycles` (objects with a string `cycle`).

use chrono::{DateTime, Datelike, NaiveDate};
use serde_json::{Map, Value};

use crate::error::PyError;
use crate::pyjson::{py_str, type_name};
use crate::upstream::lifecycle_date;

/// The keys of `latest` that `lifecycle_evidence` copies.
const EVIDENCE_KEYS: [&str; 5] = ["status", "product", "checked_at_epoch", "cached", "error"];

/// `lifecycle_ended(value, today, true_means_ended=…)`: a bool is the state
/// itself (`eol: true` means ended, `support: true` means still supported),
/// a date has passed when `today >= end`, `null` never ends.
pub fn lifecycle_ended(
    value: &Value,
    today: NaiveDate,
    true_means_ended: bool,
) -> Result<bool, PyError> {
    if let Value::Bool(flag) = value {
        return Ok(*flag == true_means_ended);
    }
    Ok(lifecycle_date(Some(value))?.is_some_and(|end| today >= end))
}

/// `datetime.fromtimestamp(now, UTC).date()`. As CPython, the timestamp is
/// first rounded to microseconds, half to even, so a time a fraction of a
/// microsecond before midnight is already the next day.
pub fn utc_date(now: f64) -> Result<NaiveDate, PyError> {
    if now.is_nan() {
        return Err(PyError::value("Invalid value NaN (not a number)"));
    }
    if now.is_infinite() {
        return Err(PyError::new(
            "OverflowError",
            "cannot convert float infinity to integer",
        ));
    }
    // `_PyTime_DoubleToDenominator(…, 1e6, _PyTime_ROUND_HALF_EVEN)`.
    let mut seconds = now.trunc();
    let mut micros = ((now - seconds) * 1e6).round_ties_even();
    if micros >= 1e6 {
        seconds += 1.0;
        micros -= 1e6;
    } else if micros < 0.0 {
        seconds -= 1.0;
        micros += 1e6;
    }
    debug_assert!((0.0..1e6).contains(&micros));
    // time_t is 64 bits on the hosts.
    if !(-9.223_372_036_854_776e18..9.223_372_036_854_776e18).contains(&seconds) {
        return Err(PyError::new(
            "OverflowError",
            "timestamp out of range for platform time_t",
        ));
    }
    let date = DateTime::from_timestamp(seconds as i64, 0)
        .map(|moment| moment.date_naive())
        .ok_or_else(|| PyError::value("year is out of range"))?;
    if !(1..=9999).contains(&date.year()) {
        return Err(PyError::value(format!(
            "year {} is out of range",
            date.year()
        )));
    }
    Ok(date)
}

/// `str(item.get("cycle")) == cycle`. A string, a number, a bool and `null`
/// compare as Python's `str()` writes them. A list or an object never
/// matches: Python would compare its `repr`, but the upstream lookup keeps
/// only cycles whose `cycle` is a string (PLAN.md 3.3), so `latest` never
/// holds one.
fn cycle_matches(item: &Map<String, Value>, cycle: &str) -> bool {
    match item.get("cycle").unwrap_or(&Value::Null) {
        Value::String(text) => text == cycle,
        Value::Array(_) | Value::Object(_) => false,
        other => py_str(other) == cycle,
    }
}

/// `lifecycle_cycle(latest, cycle)`: the first upstream cycle whose `cycle`
/// is `cycle`. Python iterates `latest["cycles"]` and calls `.get` on each
/// item, so the errors for a malformed list are Python's.
pub fn lifecycle_cycle<'a>(
    latest: &'a Map<String, Value>,
    cycle: &str,
) -> Result<&'a Map<String, Value>, PyError> {
    if latest.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(PyError::value("lifecycle upstream unavailable"));
    }
    let missing = || PyError::value("observed cycle missing from lifecycle upstream");
    let no_get = |value: &Value| {
        PyError::new(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", type_name(value)),
        )
    };
    match latest.get("cycles").ok_or_else(|| PyError::key("cycles"))? {
        Value::Array(items) => {
            for item in items {
                let Value::Object(map) = item else {
                    return Err(no_get(item));
                };
                if cycle_matches(map, cycle) {
                    return Ok(map);
                }
            }
            Err(missing())
        }
        // Iterating a dict or a str yields strings.
        Value::Object(map) if map.is_empty() => Err(missing()),
        Value::String(text) if text.is_empty() => Err(missing()),
        Value::Object(_) | Value::String(_) => Err(no_get(&Value::String(String::new()))),
        other => Err(PyError::type_error(format!(
            "'{}' object is not iterable",
            type_name(other)
        ))),
    }
}

/// `latest["cycles"][0].get("cycle")`, after [`lifecycle_cycle`] found a
/// cycle (so `cycles` is a list whose first item is an object).
pub fn newest_cycle(latest: &Map<String, Value>) -> Value {
    latest
        .get("cycles")
        .and_then(Value::as_array)
        .and_then(|cycles| cycles.first())
        .and_then(Value::as_object)
        .and_then(|first| first.get("cycle"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `lifecycle_evidence(latest)`: the lookup's status fields, plus
/// `last_success_checked_at_epoch` of a stale cache kept as evidence.
pub fn lifecycle_evidence(latest: &Map<String, Value>) -> Map<String, Value> {
    let mut evidence: Map<String, Value> = EVIDENCE_KEYS
        .iter()
        .filter_map(|key| Some(((*key).to_owned(), latest.get(*key)?.clone())))
        .collect();
    if let Some(Value::Object(previous)) = latest.get("last_success")
        && let Some(checked) = previous.get("checked_at_epoch")
    {
        evidence.insert("last_success_checked_at_epoch".into(), checked.clone());
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ErrorSpec, assert_outcome, json_eq, present};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixtures {
        dates: Vec<DateCase>,
        ended: Vec<EndedCase>,
        now_dates: Vec<NowCase>,
        evidence: Vec<EvidenceCase>,
        cycles: Vec<CycleCase>,
    }

    #[derive(Deserialize)]
    struct DateCase {
        value: Value,
        #[serde(default, deserialize_with = "present")]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Deserialize)]
    struct EndedCase {
        value: Value,
        today: String,
        true_means_ended: bool,
        #[serde(default, deserialize_with = "present")]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
    }

    #[derive(Deserialize)]
    struct NowCase {
        now: f64,
        #[serde(default)]
        date: Option<String>,
        #[serde(default)]
        error: Option<ErrorSpec>,
    }

    #[derive(Deserialize)]
    struct EvidenceCase {
        latest: Map<String, Value>,
        result: Value,
    }

    #[derive(Deserialize)]
    struct CycleCase {
        latest: Map<String, Value>,
        cycle: String,
        #[serde(default, deserialize_with = "present")]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/lifecycle.json")).unwrap()
    }

    fn iso(date: Option<NaiveDate>) -> Value {
        date.map_or(Value::Null, |d| {
            Value::String(format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day()))
        })
    }

    #[test]
    fn dates_match_python() {
        let cases = fixtures().dates;
        assert!(cases.len() >= 30);
        for case in cases {
            let id = format!("lifecycle_date({})", case.value);
            let actual = lifecycle_date(Some(&case.value)).map(iso);
            if let Some(tag) = &case.p3 {
                // PLAN.md 4.2 item 6: only YYYY-MM-DD.
                assert_eq!(tag, "iso-date", "{id}");
                assert!(
                    case.result.is_some(),
                    "{id}: P3 case must be one Python accepts"
                );
                assert_eq!(actual.unwrap_err().class, "ValueError", "{id}");
                continue;
            }
            assert_outcome(actual, case.result.as_ref(), case.error.as_ref(), &id);
        }
    }

    #[test]
    fn ended_matches_python() {
        let cases = fixtures().ended;
        assert!(cases.len() >= 18);
        for case in cases {
            let id = format!("lifecycle_ended({}, {})", case.value, case.true_means_ended);
            let today = lifecycle_date(Some(&Value::String(case.today.clone())))
                .unwrap()
                .unwrap();
            let actual =
                lifecycle_ended(&case.value, today, case.true_means_ended).map(Value::Bool);
            assert_outcome(actual, case.result.as_ref(), case.error.as_ref(), &id);
        }
    }

    #[test]
    fn utc_dates_match_python() {
        let cases = fixtures().now_dates;
        assert!(cases.len() >= 15);
        for case in cases {
            let id = format!("fromtimestamp({:?})", case.now);
            let actual = utc_date(case.now).map(|date| iso(Some(date)));
            assert_outcome(
                actual,
                case.date.map(Value::String).as_ref(),
                case.error.as_ref(),
                &id,
            );
        }
        assert_eq!(utc_date(f64::NAN).unwrap_err().class, "ValueError");
        assert_eq!(utc_date(f64::INFINITY).unwrap_err().class, "OverflowError");
        assert_eq!(utc_date(1e19).unwrap_err().class, "OverflowError");
    }

    #[test]
    fn evidence_matches_python() {
        let cases = fixtures().evidence;
        assert!(cases.len() >= 8);
        for case in cases {
            let actual = Value::Object(lifecycle_evidence(&case.latest));
            assert!(
                json_eq(&actual, &case.result),
                "{actual} != {}",
                case.result
            );
        }
    }

    #[test]
    fn cycle_lookup_matches_python() {
        let cases = fixtures().cycles;
        assert!(cases.len() >= 20);
        for case in cases {
            let id = format!("lifecycle_cycle({:?}, {:?})", case.latest, case.cycle);
            let actual =
                lifecycle_cycle(&case.latest, &case.cycle).map(|m| Value::Object(m.clone()));
            assert_outcome(actual, case.result.as_ref(), case.error.as_ref(), &id);
        }
    }
}
