//! Mode `apt-state` (PLAN.md 4.5, `os_apt_maintenance`): serves the apt
//! maintenance state file with the computed `summary`, `meta` and reboot
//! state.
//!
//! Python (`roles/os_apt_maintenance/templates/os_apt_maintenance_httpd.py.j2`,
//! `do_GET` after the gate and the file steps of PLAN.md 4.2):
//!
//! ```python
//! last_success_epoch = data.get("last_success_epoch")
//! last_success_age_seconds = None
//! if isinstance(last_success_epoch, int):
//!     last_success_age_seconds = max(0, served_at_epoch - last_success_epoch)
//! last_status = data.get("last_status")
//! state_reboot_required = bool(data.get("reboot_required"))
//! reboot_details = reboot_state(data, flag_present=os.path.exists(REBOOT_REQUIRED_FLAG),
//!                               running_release=os.uname().release)
//! state_file_fresh = age_seconds <= STATE_MAX_AGE_SECONDS
//! last_success_fresh = last_success_age_seconds is not None and last_success_age_seconds <= FRESHNESS_MAX_AGE_SECONDS
//! currently_running = last_status == "running"
//! last_run_ok = last_status == "success" or (currently_running and last_success_fresh)
//! data["meta"] = {generated_at, generated_at_epoch, served_at_epoch, age_seconds,
//!                 state_file_fresh, state_max_age_seconds, state_reboot_required}
//! data["reboot_required"] = reboot_details["required"]
//! data["reboot_required_details"] = reboot_details
//! data["summary"] = {last_run_ok, currently_running, last_success_fresh, last_success_age_seconds,
//!                    freshness_max_age_seconds, reboot_required,
//!                    overall_ok: last_run_ok and last_success_fresh and state_file_fresh}
//! ```
//!
//! Where Python raises inside the handler and drops the connection, Rust
//! answers (D-2): a top-level value that is not an object → 502
//! `invalid_json`; a `reasons` value `in` cannot search (a number, `true`)
//! → 500 `internal_error`; and (D-5) an int that exact `i128` arithmetic
//! cannot hold → 500 `internal_error`, never a wrong number.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::Args;
use hyper::StatusCode;
use serde_json::{Map, Number, Value};

use crate::clock::SharedClock;
use crate::meta::{self, Document, FileError};
use crate::modes::{AuthArgs, Gate, ListenArgs, Mode, NotFound, PathMatch, Problems};
use crate::pyjson::{self, NotIterable, PyInt};
use crate::server::{self, AccessLog, HttpResponse, Request, ServerConfig, Service};

/// `os.path.exists("/var/run/reboot-required")` in Python.
pub const DEFAULT_REBOOT_FLAG: &str = "/var/run/reboot-required";

/// The keys of the persisted kernel signal that are served with it.
const KERNEL_KEYS: [&str; 3] = [
    "running_kernel",
    "running_kernel_version",
    "newest_installed_kernel",
];

#[derive(Args, Debug, Clone)]
pub struct AptStateArgs {
    #[command(flatten)]
    pub listen: ListenArgs,
    #[command(flatten)]
    pub auth: AuthArgs,
    /// The state file written by os-apt-maintenance.
    #[arg(long, value_name = "F")]
    pub json_path: PathBuf,
    /// FRESHNESS_MAX_AGE_SECONDS: the last success must be at most this old.
    #[arg(long, value_name = "SECS", allow_negative_numbers = true)]
    pub freshness_max_age: i64,
    /// STATE_MAX_AGE_SECONDS: the state file must be at most this old.
    #[arg(long, value_name = "SECS", allow_negative_numbers = true)]
    pub state_max_age: i64,
    /// The flag file whose existence means a reboot is required.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_REBOOT_FLAG)]
    pub reboot_flag: PathBuf,
    /// Validate the configuration without binding, print a summary, exit 0 or 2.
    #[arg(long)]
    pub check_config: bool,
}

impl Mode for AptStateArgs {
    type Service = AptState;
    const NAME: &'static str = "apt-state";

    fn addr(&self) -> SocketAddr {
        self.listen.addr()
    }

    fn check_config(&self) -> Result<String, Problems> {
        let mut problems = Problems::default();
        let entries = problems.htpasswd(&self.auth.htpasswd_file);
        problems.parent_dir("state file", &self.json_path);
        if !problems.0.is_empty() {
            return Err(problems);
        }
        Ok(format!(
            "bind {} path {} state {} freshness-max-age {} state-max-age {} reboot-flag {} htpasswd {} (bcrypt entries: {entries}) realm {}",
            self.addr(),
            self.auth.path,
            self.json_path.display(),
            self.freshness_max_age,
            self.state_max_age,
            self.reboot_flag.display(),
            self.auth.htpasswd_file.display(),
            self.auth.realm,
        ))
    }

    fn server_config(&self, clock: SharedClock) -> ServerConfig {
        ServerConfig {
            request_timeout: self.auth.request_timeout,
            access_log: AccessLog::Stderr,
            server_header: server::server_header(&self.auth.server_name),
            clock,
        }
    }

    fn service(&self, clock: SharedClock) -> AptState {
        AptState {
            gate: Gate::new(&self.auth, PathMatch::Exact, NotFound::Json),
            json_path: self.json_path.clone(),
            limits: Limits {
                freshness_max_age: self.freshness_max_age,
                state_max_age: self.state_max_age,
            },
            reboot_flag: self.reboot_flag.clone(),
            kernel_release: KernelRelease::Uname,
            clock,
        }
    }
}

/// The two template-baked constants of the Python script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `FRESHNESS_MAX_AGE_SECONDS`.
    pub freshness_max_age: i64,
    /// `STATE_MAX_AGE_SECONDS`.
    pub state_max_age: i64,
}

/// Where the running kernel release comes from (`os.uname().release`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelRelease {
    /// `uname(2)`, read per request as in Python.
    Uname,
    /// A fixed release (tests and fixture replay).
    Fixed(String),
}

impl KernelRelease {
    pub fn read(&self) -> String {
        match self {
            Self::Uname => rustix::system::uname()
                .release()
                .to_string_lossy()
                .into_owned(),
            Self::Fixed(release) => release.clone(),
        }
    }
}

/// The host facts `reboot_state` reads per request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// `os.path.exists(REBOOT_REQUIRED_FLAG)`.
    pub flag_present: bool,
    /// `os.uname().release`.
    pub running_release: String,
}

/// Why a payload cannot be computed: Python would raise (or, for an int
/// outside `i128`, compute a number Rust does not); 500 `internal_error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeError {
    /// `"stale_kernel" in reasons` on a value that is not a container (D-2).
    NotIterable(NotIterable),
    /// An int used in arithmetic that `i128` cannot hold (D-5).
    IntOutOfRange(&'static str),
    /// `datetime.fromtimestamp` of the mtime raises (years outside 1–9999).
    Timestamp,
}

impl std::fmt::Display for ComputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotIterable(error) => write!(f, "reboot_required_details.reasons: {error}"),
            Self::IntOutOfRange(key) => write!(f, "{key}: integer outside the supported range"),
            Self::Timestamp => write!(f, "the state file mtime is outside the years 1-9999"),
        }
    }
}

/// `value == "<text>"` in Python for a JSON value.
fn equals_str(value: Option<&Value>, text: &str) -> bool {
    matches!(value, Some(Value::String(value)) if value == text)
}

/// The script's `reboot_state(state, flag_present=…, running_release=…)`:
/// the live marker plus the persisted kernel signal, served while the host
/// still runs the kernel the maintenance run observed.
pub fn reboot_state(
    state: &Map<String, Value>,
    flag_present: bool,
    running_release: &str,
) -> Result<Map<String, Value>, NotIterable> {
    let mut reasons = Vec::new();
    let mut details = Map::new();
    details.insert("flag_present".to_owned(), Value::Bool(flag_present));
    if flag_present {
        reasons.push(Value::String("reboot_required_flag".to_owned()));
    }
    if let Some(Value::Object(persisted)) = state.get("reboot_required_details") {
        // `"stale_kernel" in (persisted.get("reasons") or [])`, evaluated
        // before the kernel comparison (Python's `and` order), so a reasons
        // value `in` cannot search raises even for another kernel.
        let stale = match persisted.get("reasons") {
            Some(reasons) if pyjson::truthy(reasons) => {
                pyjson::contains_str(reasons, "stale_kernel")?
            }
            _ => false,
        };
        if stale && equals_str(persisted.get("running_kernel"), running_release) {
            reasons.push(Value::String("stale_kernel".to_owned()));
            for key in KERNEL_KEYS {
                if let Some(value) = persisted.get(key) {
                    details.insert(key.to_owned(), value.clone());
                }
            }
        }
    }
    details.insert("required".to_owned(), Value::Bool(!reasons.is_empty()));
    details.insert("reasons".to_owned(), Value::Array(reasons));
    Ok(details)
}

/// `isinstance(v, int)` → `max(0, served - v)`, exact; `None` for any
/// other value (floats such as `1e9`, strings, `null`, absent).
fn last_success_age(
    value: Option<&Value>,
    served_at_epoch: i64,
) -> Result<Option<i128>, ComputeError> {
    const KEY: &str = "last_success_epoch";
    match value.and_then(pyjson::py_int) {
        None => Ok(None),
        Some(PyInt::OutOfRange) => Err(ComputeError::IntOutOfRange(KEY)),
        Some(PyInt::Value(epoch)) => i128::from(served_at_epoch)
            .checked_sub(epoch)
            .map(|age| Some(age.max(0)))
            .ok_or(ComputeError::IntOutOfRange(KEY)),
    }
}

/// The served document: the state file's data with `meta`,
/// `reboot_required`, `reboot_required_details` and `summary` set.
pub fn payload(
    document: Document,
    facts: &HostFacts,
    limits: Limits,
) -> Result<Map<String, Value>, ComputeError> {
    let age_seconds = document.age_seconds();
    let mut meta_fields = meta::meta_fields(&document).ok_or(ComputeError::Timestamp)?;
    let Document {
        mut data,
        served_at_epoch,
        ..
    } = document;

    let last_success_age_seconds =
        last_success_age(data.get("last_success_epoch"), served_at_epoch)?;
    let state_reboot_required = data.get("reboot_required").is_some_and(pyjson::truthy);
    let details = reboot_state(&data, facts.flag_present, &facts.running_release)
        .map_err(ComputeError::NotIterable)?;
    let reboot_required = details
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let state_file_fresh = age_seconds <= limits.state_max_age;
    let last_success_fresh =
        last_success_age_seconds.is_some_and(|age| age <= i128::from(limits.freshness_max_age));
    let last_status = data.get("last_status");
    let currently_running = equals_str(last_status, "running");
    let last_run_ok =
        equals_str(last_status, "success") || (currently_running && last_success_fresh);

    meta_fields.insert("state_file_fresh".to_owned(), Value::Bool(state_file_fresh));
    meta_fields.insert(
        "state_max_age_seconds".to_owned(),
        limits.state_max_age.into(),
    );
    meta_fields.insert(
        "state_reboot_required".to_owned(),
        Value::Bool(state_reboot_required),
    );
    data.insert("meta".to_owned(), Value::Object(meta_fields));
    data.insert("reboot_required".to_owned(), Value::Bool(reboot_required));
    data.insert("reboot_required_details".to_owned(), Value::Object(details));

    let mut summary = Map::new();
    summary.insert("last_run_ok".to_owned(), Value::Bool(last_run_ok));
    summary.insert(
        "currently_running".to_owned(),
        Value::Bool(currently_running),
    );
    summary.insert(
        "last_success_fresh".to_owned(),
        Value::Bool(last_success_fresh),
    );
    summary.insert(
        "last_success_age_seconds".to_owned(),
        last_success_age_seconds.map_or(Value::Null, |age| Value::Number(Number::from(age))),
    );
    summary.insert(
        "freshness_max_age_seconds".to_owned(),
        limits.freshness_max_age.into(),
    );
    summary.insert("reboot_required".to_owned(), Value::Bool(reboot_required));
    summary.insert(
        "overall_ok".to_owned(),
        Value::Bool(last_run_ok && last_success_fresh && state_file_fresh),
    );
    data.insert("summary".to_owned(), Value::Object(summary));
    Ok(data)
}

/// The apt-state endpoint.
pub struct AptState {
    pub gate: Gate,
    pub json_path: PathBuf,
    pub limits: Limits,
    pub reboot_flag: PathBuf,
    pub kernel_release: KernelRelease,
    pub clock: SharedClock,
}

impl AptState {
    /// The flag file and `uname`, read per request (on the blocking pool).
    async fn host_facts(&self) -> HostFacts {
        let flag = self.reboot_flag.clone();
        let release = self.kernel_release.clone();
        let read = move || HostFacts {
            // os.path.exists: false for a broken symlink or a denied stat.
            flag_present: Path::new(&flag).exists(),
            running_release: release.read(),
        };
        match tokio::task::spawn_blocking(read.clone()).await {
            Ok(facts) => facts,
            Err(_) => read(),
        }
    }
}

/// A JSON error answer with its D-9 log line.
fn fail(status: StatusCode, error_type: &str, message: &str) -> HttpResponse {
    server::log_line(&format!(
        "metrics-httpd apt-state: {} {error_type}: {message}",
        status.as_u16()
    ));
    server::json_error(status, error_type, message)
}

impl Service for AptState {
    async fn call(&self, request: Request) -> HttpResponse {
        if let Some(response) = self.gate.check(&request).await {
            return response;
        }
        let document = match meta::read_document(self.json_path.clone(), self.clock.clone()).await {
            Ok(document) => document,
            Err(FileError::Missing) => {
                return fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "state_file_missing",
                    "Apt maintenance state file not found",
                );
            }
            Err(FileError::Read(error)) => {
                return fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "read_error",
                    &format!("Cannot read state file: {error}"),
                );
            }
            Err(FileError::Invalid(detail)) => {
                return fail(
                    StatusCode::BAD_GATEWAY,
                    "invalid_json",
                    &format!("Invalid JSON in state file: {detail}"),
                );
            }
        };
        let facts = self.host_facts().await;
        match payload(document, &facts, self.limits) {
            Ok(data) => server::json_response(StatusCode::OK, pyjson::dumps(&data)),
            Err(error) => fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("Cannot evaluate the state file: {error}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    //! The port of `tests/test_monitoring_pipeline_repair.py`
    //! `EndpointRebootStateTests` (same inputs, same assertions), plus the
    //! payload rules of PLAN.md 4.5. The fixture replay (`tests/apt_state.rs`)
    //! compares the same functions with the Python script's answers.

    use super::*;
    use serde_json::json;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    fn stale_state() -> Map<String, Value> {
        object(json!({
            "reboot_required": true,
            "reboot_required_details": {
                "required": true,
                "reasons": ["stale_kernel"],
                "flag_present": false,
                "running_kernel": "5.10.0-23-amd64",
                "running_kernel_version": "5.10.0-23",
                "newest_installed_kernel": "6.1.0-52",
            },
        }))
    }

    #[test]
    fn the_persisted_kernel_signal_is_served() {
        let details = reboot_state(&stale_state(), false, "5.10.0-23-amd64").unwrap();
        assert_eq!(details["required"], json!(true));
        assert_eq!(details["reasons"], json!(["stale_kernel"]));
        assert_eq!(details["newest_installed_kernel"], json!("6.1.0-52"));
        assert_eq!(details["flag_present"], json!(false));
    }

    #[test]
    fn a_reboot_into_the_new_kernel_clears_the_signal_at_once() {
        let details = reboot_state(&stale_state(), false, "6.1.0-52-amd64").unwrap();
        assert_eq!(details["required"], json!(false));
        assert_eq!(details["reasons"], json!([]));
        assert!(!details.contains_key("newest_installed_kernel"));
    }

    #[test]
    fn the_live_marker_still_wins_on_its_own() {
        let state = object(json!({"reboot_required": false}));
        let details = reboot_state(&state, true, "6.8.0-138-generic").unwrap();
        assert_eq!(details["required"], json!(true));
        assert_eq!(details["reasons"], json!(["reboot_required_flag"]));
    }

    #[test]
    fn both_signals_are_reported_together() {
        let details = reboot_state(&stale_state(), true, "5.10.0-23-amd64").unwrap();
        assert_eq!(
            details["reasons"],
            json!(["reboot_required_flag", "stale_kernel"])
        );
    }

    #[test]
    fn old_state_files_without_details_keep_marker_only_behaviour() {
        for legacy in [
            json!({"reboot_required": true}),
            json!({"reboot_required_details": null}),
            json!({}),
        ] {
            let details = reboot_state(&object(legacy.clone()), false, "5.10.0-23-amd64").unwrap();
            assert_eq!(details["required"], json!(false), "{legacy}");
        }
    }

    fn document(data: Value, generated_at_epoch: i64, served_at_epoch: i64) -> Document {
        Document {
            data: object(data),
            generated_at_epoch,
            served_at_epoch,
        }
    }

    const SERVED: i64 = 1_792_576_800;
    const LIMITS: Limits = Limits {
        freshness_max_age: 1_209_600,
        state_max_age: 1_296_000,
    };

    fn facts(flag_present: bool, release: &str) -> HostFacts {
        HostFacts {
            flag_present,
            running_release: release.to_owned(),
        }
    }

    /// Python's `test_the_handler_serves_the_merged_state` checks the source
    /// text: the served reboot state comes from `reboot_state()`, not from
    /// the marker alone. Here: the payload serves exactly `reboot_state`'s
    /// answer, with the kernel signal and without the marker.
    #[test]
    fn the_handler_serves_the_merged_state() {
        let mut state = stale_state();
        state.insert("reboot_required".to_owned(), json!(false));
        let expected = reboot_state(&state, false, "5.10.0-23-amd64").unwrap();
        let data = payload(
            document(Value::Object(state), SERVED - 60, SERVED),
            &facts(false, "5.10.0-23-amd64"),
            LIMITS,
        )
        .unwrap();
        assert_eq!(data["reboot_required_details"], Value::Object(expected));
        assert_eq!(data["reboot_required"], json!(true));
        assert_eq!(data["summary"]["reboot_required"], json!(true));
        // The state file's own flag is reported separately.
        assert_eq!(data["meta"]["state_reboot_required"], json!(false));
    }

    #[test]
    fn payload_follows_the_python_rules() {
        let data = payload(
            document(
                json!({
                    "last_status": "success",
                    "last_success_epoch": SERVED - 3_600,
                    "meta": {"stale": true},
                    "summary": "replaced",
                    "steps": {"update_cache": {"duration_seconds": 1.50}},
                }),
                SERVED - 60,
                SERVED,
            ),
            &facts(false, "6.8.0-138-generic"),
            LIMITS,
        )
        .unwrap();
        assert_eq!(
            Value::Object(data),
            json!({
                "last_status": "success",
                "last_success_epoch": SERVED - 3_600,
                "steps": {"update_cache": {"duration_seconds": 1.5}},
                "meta": {
                    "generated_at": "2026-10-21T09:59:00+00:00",
                    "generated_at_epoch": SERVED - 60,
                    "served_at_epoch": SERVED,
                    "age_seconds": 60,
                    "state_file_fresh": true,
                    "state_max_age_seconds": 1_296_000,
                    "state_reboot_required": false,
                },
                "reboot_required": false,
                "reboot_required_details": {"flag_present": false, "required": false, "reasons": []},
                "summary": {
                    "last_run_ok": true,
                    "currently_running": false,
                    "last_success_fresh": true,
                    "last_success_age_seconds": 3_600,
                    "freshness_max_age_seconds": 1_209_600,
                    "reboot_required": false,
                    "overall_ok": true,
                },
            })
        );
    }

    fn summary(data: Value, generated_at_epoch: i64) -> Value {
        let data = payload(
            document(data, generated_at_epoch, SERVED),
            &facts(false, "6.8.0-138-generic"),
            LIMITS,
        )
        .unwrap();
        json!({
            "summary": data["summary"],
            "state_file_fresh": data["meta"]["state_file_fresh"],
            "state_reboot_required": data["meta"]["state_reboot_required"],
        })
    }

    #[test]
    fn freshness_and_status_rules() {
        let fresh = SERVED - 1_209_600;
        // Running with a fresh last success counts as ok; without it not.
        let s = summary(
            json!({"last_status": "running", "last_success_epoch": fresh}),
            SERVED,
        );
        assert_eq!(s["summary"]["last_run_ok"], json!(true));
        assert_eq!(s["summary"]["currently_running"], json!(true));
        assert_eq!(s["summary"]["last_success_fresh"], json!(true));
        let s = summary(
            json!({"last_status": "running", "last_success_epoch": fresh - 1}),
            SERVED,
        );
        assert_eq!(s["summary"]["last_run_ok"], json!(false));
        assert_eq!(s["summary"]["overall_ok"], json!(false));
        // The state file age limit is inclusive; a future mtime is fresh.
        assert_eq!(
            summary(json!({}), SERVED - 1_296_000)["state_file_fresh"],
            json!(true)
        );
        assert_eq!(
            summary(json!({}), SERVED - 1_296_001)["state_file_fresh"],
            json!(false)
        );
        assert_eq!(
            summary(json!({}), SERVED + 100)["state_file_fresh"],
            json!(true)
        );
        // Success without a last success epoch: ok, but not fresh.
        let s = summary(json!({"last_status": "success"}), SERVED);
        assert_eq!(s["summary"]["last_run_ok"], json!(true));
        assert_eq!(s["summary"]["last_success_age_seconds"], Value::Null);
        assert_eq!(s["summary"]["overall_ok"], json!(false));
        // A non-string status is neither success nor running.
        let s = summary(json!({"last_status": 1}), SERVED);
        assert_eq!(s["summary"]["last_run_ok"], json!(false));
        // bool(reboot_required) is Python truthiness.
        for (value, expected) in [
            (json!("yes"), true),
            (json!(0), false),
            (json!([]), false),
            (json!({"a": 1}), true),
            (json!(null), false),
        ] {
            let s = summary(json!({"reboot_required": value}), SERVED);
            assert_eq!(s["state_reboot_required"], json!(expected), "{value}");
        }
    }

    fn age(text: &str) -> Result<Option<i128>, ComputeError> {
        let value = pyjson::parse(text.as_bytes()).unwrap();
        last_success_age(Some(&value), SERVED)
    }

    #[test]
    fn last_success_age_is_exact_and_typed_like_python() {
        assert_eq!(age("1792573200"), Ok(Some(3_600)));
        // isinstance(True, int): True is 1.
        assert_eq!(age("true"), Ok(Some(i128::from(SERVED) - 1)));
        assert_eq!(age("false"), Ok(Some(i128::from(SERVED))));
        // In the future: max(0, …).
        assert_eq!(age("1792577300"), Ok(Some(0)));
        // Floats and strings are not ints.
        for text in ["1792573200.0", "1e9", "\"1792573200\"", "null", "[1]"] {
            assert_eq!(age(text), Ok(None), "{text}");
        }
        // Beyond i64, within i128: exact.
        assert_eq!(
            age("-1000000000000000000000000000000"),
            Ok(Some(
                i128::from(SERVED) + 1_000_000_000_000_000_000_000_000_000_000
            ))
        );
        assert_eq!(age("1000000000000000000000000000000"), Ok(Some(0)));
        // Outside i128, or a difference outside i128: refused (D-5).
        for text in [
            "1000000000000000000000000000000000000000",
            "-170141183460469231731687303715884105728",
        ] {
            assert_eq!(
                age(text),
                Err(ComputeError::IntOutOfRange("last_success_epoch")),
                "{text}"
            );
        }
    }

    #[test]
    fn reasons_follow_python_in_and_truthiness() {
        let with_reasons = |reasons: Value| {
            object(json!({"reboot_required_details": {
                "reasons": reasons,
                "running_kernel": "k",
                "newest_installed_kernel": null,
            }}))
        };
        for (reasons, stale) in [
            (json!("prefix stale_kernel suffix"), true),
            (json!({"stale_kernel": false}), true),
            (json!(["x", "stale_kernel"]), true),
            (json!([["stale_kernel"]]), false),
            (json!(0), false),
            (json!(false), false),
            (json!(""), false),
            (json!(null), false),
        ] {
            let details = reboot_state(&with_reasons(reasons.clone()), false, "k").unwrap();
            assert_eq!(details["required"], json!(stale), "{reasons}");
            // A present key is copied even when null.
            assert_eq!(
                details.contains_key("newest_installed_kernel"),
                stale,
                "{reasons}"
            );
        }
        // A truthy non-container raises in Python (D-2: 500), also for
        // another kernel, because `in` runs before the comparison.
        for reasons in [json!(1), json!(true), json!(2.5)] {
            assert!(reboot_state(&with_reasons(reasons.clone()), false, "other").is_err());
            let error = payload(
                document(Value::Object(with_reasons(reasons)), SERVED, SERVED),
                &facts(false, "other"),
                LIMITS,
            )
            .unwrap_err();
            assert!(matches!(error, ComputeError::NotIterable(_)));
        }
        // running_kernel must equal the release as a string.
        let state = object(json!({"reboot_required_details": {
            "reasons": ["stale_kernel"], "running_kernel": 5,
        }}));
        assert_eq!(
            reboot_state(&state, false, "5").unwrap()["required"],
            json!(false)
        );
        // A details value that is not an object is ignored.
        let state = object(json!({"reboot_required_details": ["stale_kernel"]}));
        assert_eq!(
            reboot_state(&state, false, "k").unwrap()["required"],
            json!(false)
        );
    }

    #[test]
    fn an_mtime_outside_python_datetime_is_an_internal_error() {
        let error = payload(
            document(json!({}), 253_402_300_800, SERVED),
            &facts(false, "k"),
            LIMITS,
        )
        .unwrap_err();
        assert_eq!(error, ComputeError::Timestamp);
    }

    #[test]
    fn uname_release_is_not_empty() {
        assert!(!KernelRelease::Uname.read().is_empty());
        assert_eq!(KernelRelease::Fixed("k".to_owned()).read(), "k");
    }
}
