//! `collect(policy, cache)` of `software_live.py:644-684` and the state
//! write of its `main` (`:924-931`), PLAN.md 3.1, 3.3 and 3.5.
//!
//! The order of the steps is part of the contract (PLAN.md 3.3): the clock,
//! the Traefik upstream (only if Traefik is expected, otherwise
//! `{"status": "not_applicable"}`), Traefik, the OS lifecycle upstream, the
//! OS, the PostgreSQL lifecycle upstream (only if PostgreSQL is expected),
//! PostgreSQL, APT, and the clock again for `generated_at_epoch`. Every
//! observation step closes its own failures into its result; the only error
//! that stops `collect` is a cache path without a name, which Python's
//! `cache_variant` raises outside the lookups' error boundary.
//!
//! The steps go through [`Steps`], so a test can replace them the way the
//! Python tests patch the functions of the module; [`collect`] runs the real
//! steps on a [`System`].

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use serde_json::{Map, Value};

use crate::apt;
use crate::error::PyError;
use crate::os::observe_os;
use crate::policy::Policy;
use crate::postgresql::observe_postgresql;
use crate::probe::System;
use crate::pyjson;
use crate::report::{Observation, Report, with_freshness};
use crate::traefik;
use crate::upstream;

/// The steps of `collect`, one per function `collect` calls in
/// `software_live.py`.
pub trait Steps {
    /// `time.time()`.
    fn now(&self) -> f64;
    /// `upstream(cache, now)`: the Traefik release.
    fn upstream(&self, cache: Option<&Path>, now: f64) -> Value;
    /// `observe_traefik(policy["traefik"], latest)`.
    fn observe_traefik(&self, policy: &Value, latest: &Value) -> Observation;
    /// `lifecycle_upstream(product, cache, now)`.
    fn lifecycle_upstream(
        &self,
        product: &str,
        cache: Option<&Path>,
        now: f64,
    ) -> Result<Value, PyError>;
    /// `observe_os(policy["os"], latest, now)`.
    fn observe_os(&self, policy: &Value, latest: &Map<String, Value>, now: f64) -> Observation;
    /// `observe_postgresql(policy["postgresql"], latest, now)`.
    fn observe_postgresql(
        &self,
        policy: &Value,
        latest: &Map<String, Value>,
        now: f64,
    ) -> Observation;
    /// `observe_apt(policy.get("apt_max_age_seconds", 172800), now)`.
    fn observe_apt(&self, max_age: i64, now: f64) -> Observation;
}

/// The real steps on a [`System`].
pub struct HostSteps<'a, S>(pub &'a S);

impl<S: System> Steps for HostSteps<'_, S> {
    fn now(&self) -> f64 {
        self.0.now()
    }

    fn upstream(&self, cache: Option<&Path>, now: f64) -> Value {
        upstream::upstream(self.0, cache, now)
    }

    fn observe_traefik(&self, policy: &Value, latest: &Value) -> Observation {
        traefik::observe(self.0, policy, latest)
    }

    fn lifecycle_upstream(
        &self,
        product: &str,
        cache: Option<&Path>,
        now: f64,
    ) -> Result<Value, PyError> {
        upstream::lifecycle_upstream(self.0, product, cache, now)
    }

    fn observe_os(&self, policy: &Value, latest: &Map<String, Value>, now: f64) -> Observation {
        observe_os(self.0, policy, latest, now)
    }

    fn observe_postgresql(
        &self,
        policy: &Value,
        latest: &Map<String, Value>,
        now: f64,
    ) -> Observation {
        observe_postgresql(self.0, policy, latest, now)
    }

    fn observe_apt(&self, max_age: i64, now: f64) -> Observation {
        apt::observe_apt(self.0, max_age, now)
    }
}

/// `{"status": "not_applicable"}`.
fn not_applicable() -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("status".into(), "not_applicable".into());
    map
}

/// A lookup result as the mapping the observations read. Every lookup
/// answers an object; anything else would be read as an empty mapping.
fn mapping(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `collect(policy, cache)` with the given steps. `policy` has been
/// validated ([`Policy::new`], the `validate_policy` call at the start of
/// `collect`).
pub fn collect_with(
    steps: &impl Steps,
    policy: &Policy,
    cache: Option<&Path>,
) -> Result<Report, PyError> {
    let raw = &policy.raw;
    let now = steps.now();
    let latest = if policy.traefik_expected() {
        steps.upstream(cache, now)
    } else {
        Value::Object(not_applicable())
    };
    let traefik = steps.observe_traefik(&raw["traefik"], &latest);
    let product = raw["os"]["product"]
        .as_str()
        .expect("a validated product is a string");
    let os_latest = mapping(steps.lifecycle_upstream(product, cache, now)?);
    let os = steps.observe_os(&raw["os"], &os_latest, now);
    let postgres_latest = if policy.postgresql_expected() {
        mapping(steps.lifecycle_upstream("postgresql", cache, now)?)
    } else {
        not_applicable()
    };
    let postgresql = steps.observe_postgresql(&raw["postgresql"], &postgres_latest, now);
    let apt = steps.observe_apt(policy.apt_max_age_seconds(), now);
    // `generated_at_epoch` is read after all observations (PLAN.md 3.3).
    let generated_at_epoch = steps.now();
    Report::new(policy, traefik, os, postgresql, apt, generated_at_epoch)
}

/// `collect(policy, cache)` on a host.
pub fn collect<S: System>(
    system: &S,
    policy: &Policy,
    cache: Option<&Path>,
) -> Result<Report, PyError> {
    collect_with(&HostSteps(system), policy, cache)
}

/// The state write of `main` (`software_live.py:925-929`):
/// `atomic_json(output, report, grp.getgrnam(group).gr_gid if group else
/// None)`. The group is looked up after the collection, as in Python, and
/// an unknown group (`KeyError`) or a failed write leaves the previous
/// state untouched (PLAN.md 3.5).
pub fn write_state<S: System>(
    system: &S,
    output: &Path,
    report: &Report,
    group: Option<&OsStr>,
) -> Result<(), PyError> {
    let gid = group
        .filter(|name| !name.is_empty())
        .map(crate::export::group_id)
        .transpose()?;
    system
        .write_json(output, &report.to_value(), gid)
        .map_err(|error: io::Error| PyError::os(&error))
}

/// What `collect` without `--output` prints (the manual SSH mode,
/// `software_live.py:930-931`): the report with its freshness
/// ([`with_freshness`] at a third clock read), as JSON and a newline in the
/// format of the state file (PLAN.md 4.2 item 3).
pub fn manual_output<S: System>(system: &S, report: &Report) -> Result<Vec<u8>, PyError> {
    let fresh = with_freshness(report.to_value(), system.now())?;
    let mut text = pyjson::dumps_compact(&fresh);
    text.push(b'\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::HostSystem;
    use crate::probe::fake::{FakeSystem, World};
    use crate::testutil::{ErrorSpec, json_eq};
    use serde::Deserialize;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// The summary cases of `fixtures/report.json`: Python's `collect` with
    /// every step patched, and the steps in the order it called them.
    #[derive(Deserialize)]
    struct OrderCase {
        id: String,
        policy: String,
        cache: Option<String>,
        observations: Map<String, Value>,
        generated_at_epoch: f64,
        calls: Vec<String>,
    }

    #[derive(Deserialize)]
    struct ReportFixtures {
        summary: Vec<OrderCase>,
    }

    /// The times the generator's patched `time.time` answers.
    const TIMES: [f64; 2] = [1_760_000_000.25, 1_760_000_042.75];

    /// Steps that answer like the generator's patches and log every call
    /// as `call_text` in `fixtures/generate.py` does.
    struct Recorder {
        observations: Map<String, Value>,
        times: RefCell<VecDeque<f64>>,
        calls: RefCell<Vec<String>>,
        lifecycle_error: Option<&'static str>,
    }

    fn arg(value: &Value) -> String {
        String::from_utf8(pyjson::python_dumps(value)).unwrap()
    }

    fn path_arg(path: Option<&Path>) -> String {
        arg(&path.map_or(Value::Null, |p| Value::String(p.display().to_string())))
    }

    fn number(value: f64) -> String {
        arg(&Value::Number(pyjson::number_from_f64(value).unwrap()))
    }

    impl Recorder {
        fn new(observations: Map<String, Value>) -> Self {
            Self {
                observations,
                times: RefCell::new(TIMES.into_iter().collect()),
                calls: RefCell::new(Vec::new()),
                lifecycle_error: None,
            }
        }

        fn log(&self, name: &str, args: &[String]) {
            self.calls
                .borrow_mut()
                .push(format!("{name}({})", args.join(", ")));
        }

        fn observation(&self, name: &str) -> Observation {
            Observation::from_value(self.observations[name].clone()).unwrap()
        }
    }

    impl Steps for Recorder {
        fn now(&self) -> f64 {
            self.calls.borrow_mut().push("time".into());
            self.times
                .borrow_mut()
                .pop_front()
                .expect("two clock reads")
        }

        fn upstream(&self, cache: Option<&Path>, now: f64) -> Value {
            self.log("upstream", &[path_arg(cache), number(now)]);
            serde_json::json!({"status": "ok", "version": "3.7.9", "cached": true})
        }

        fn observe_traefik(&self, policy: &Value, latest: &Value) -> Observation {
            self.log("observe_traefik", &[arg(policy), arg(latest)]);
            self.observation("traefik")
        }

        fn lifecycle_upstream(
            &self,
            product: &str,
            cache: Option<&Path>,
            now: f64,
        ) -> Result<Value, PyError> {
            self.log(
                "lifecycle_upstream",
                &[arg(&product.into()), path_arg(cache), number(now)],
            );
            if let Some(class) = self.lifecycle_error {
                return Err(PyError::new(class, "boundary"));
            }
            Ok(serde_json::json!({"status": "ok", "product": product}))
        }

        fn observe_os(&self, policy: &Value, latest: &Map<String, Value>, now: f64) -> Observation {
            let latest = Value::Object(latest.clone());
            self.log("observe_os", &[arg(policy), arg(&latest), number(now)]);
            self.observation("os")
        }

        fn observe_postgresql(
            &self,
            policy: &Value,
            latest: &Map<String, Value>,
            now: f64,
        ) -> Observation {
            let latest = Value::Object(latest.clone());
            self.log(
                "observe_postgresql",
                &[arg(policy), arg(&latest), number(now)],
            );
            self.observation("postgresql")
        }

        fn observe_apt(&self, max_age: i64, now: f64) -> Observation {
            self.log("observe_apt", &[max_age.to_string(), number(now)]);
            self.observation("apt")
        }
    }

    fn order_cases() -> Vec<OrderCase> {
        let fixtures: ReportFixtures =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        fixtures.summary
    }

    #[test]
    fn steps_run_in_pythons_order_with_pythons_arguments() {
        let cases = order_cases();
        assert!(cases.len() >= 12);
        let mut with_cache = 0;
        for case in cases {
            let id = &case.id;
            let policy = Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap();
            let recorder = Recorder::new(case.observations.clone());
            let cache = case.cache.as_deref().map(Path::new);
            with_cache += usize::from(cache.is_some());
            let report = collect_with(&recorder, &policy, cache).unwrap();
            assert_eq!(*recorder.calls.borrow(), case.calls, "{id}");
            // The second clock read, after APT, is the report's time.
            assert_eq!(report.generated_at_epoch, case.generated_at_epoch, "{id}");
            assert_eq!(report.generated_at_epoch, TIMES[1], "{id}");
            let value = report.to_value();
            for name in ["traefik", "os", "postgresql", "apt"] {
                assert!(
                    json_eq(&value[name], &case.observations[name]),
                    "{id}: {name}"
                );
            }
        }
        assert!(with_cache > 0);
    }

    #[test]
    fn a_lookup_error_outside_the_boundary_stops_collect() {
        let case = order_cases().into_iter().next().unwrap();
        let policy = Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap();
        let mut recorder = Recorder::new(case.observations);
        recorder.lifecycle_error = Some("ValueError");
        let error = collect_with(&recorder, &policy, Some(Path::new("/"))).unwrap_err();
        assert_eq!(error.class, "ValueError");
        let calls = recorder.calls.borrow();
        // The clock, the Traefik lookup and observation, the failed OS
        // lookup; nothing after it, and no second clock read.
        assert_eq!(calls.len(), 4, "{calls:?}");
        assert!(calls[3].starts_with("lifecycle_upstream(\"ubuntu\""));
    }

    /// `fixtures/collect.json`: Python's `collect` end to end in a recorded
    /// world.
    #[derive(Deserialize)]
    struct EndToEnd {
        id: String,
        policy: String,
        cache: Option<String>,
        world: World,
        calls: Vec<String>,
        #[serde(default)]
        report: Option<String>,
        #[serde(default)]
        errors: BTreeMap<String, ErrorSpec>,
        #[serde(default)]
        error: Option<ErrorSpec>,
    }

    fn end_to_end_cases() -> Vec<EndToEnd> {
        serde_json::from_str(include_str!("../fixtures/collect.json")).unwrap()
    }

    /// The `error` texts of the observations, split as the fixture records
    /// them (class, and the message where it is the Python code's own).
    fn take_errors(value: &mut Value, expected: &BTreeMap<String, ErrorSpec>, id: &str) {
        for name in ["traefik", "os", "postgresql"] {
            let text = value[name]
                .as_object_mut()
                .unwrap()
                .remove("error")
                .map(|text| text.as_str().unwrap().to_owned());
            match (text, expected.get(name)) {
                (None, None) => {}
                (Some(text), Some(spec)) => {
                    let (class, message) = text.split_once(": ").unwrap();
                    let class: &'static str = Box::leak(class.to_owned().into_boxed_str());
                    spec.assert_matches(&PyError::new(class, message), &format!("{id}: {name}"));
                }
                (text, spec) => panic!("{id}: {name}: error {text:?}, expected {spec:?}"),
            }
        }
    }

    #[test]
    fn collect_matches_python_end_to_end() {
        let cases = end_to_end_cases();
        assert!(cases.len() >= 6);
        for case in cases {
            let id = &case.id;
            let policy = Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap();
            let system = FakeSystem::new(case.world.clone());
            let result = collect(&system, &policy, case.cache.as_deref().map(Path::new));
            assert_eq!(*system.calls.borrow(), case.calls, "{id}");
            assert_eq!(system.pending_commands(), 0, "{id}");
            assert_eq!(system.pending_http(), 0, "{id}");
            match (&case.report, &case.error) {
                (Some(expected), None) => {
                    let report = result.unwrap_or_else(|e| panic!("{id}: {e}"));
                    let mut value = report.to_value();
                    take_errors(&mut value, &case.errors, id);
                    let expected = pyjson::loads(expected).unwrap();
                    assert!(json_eq(&value, &expected), "{id}:\n{value}\n!=\n{expected}");
                }
                (None, Some(spec)) => spec.assert_matches(&result.unwrap_err(), id),
                _ => panic!("{id}: a report or an error"),
            }
        }
    }

    fn all_expected() -> (Policy, FakeSystem) {
        let case = end_to_end_cases()
            .into_iter()
            .find(|case| case.id == "all_expected")
            .unwrap();
        let policy = Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap();
        (policy, FakeSystem::new(case.world))
    }

    fn own_group() -> String {
        nix::unistd::Group::from_gid(nix::unistd::getgid())
            .unwrap()
            .unwrap()
            .name
    }

    #[test]
    fn the_state_is_written_with_the_group_after_the_collection() {
        let (policy, system) = all_expected();
        let report = collect(&system, &policy, None).unwrap();
        let group = own_group();
        write_state(
            &system,
            Path::new("/var/lib/software-live/state.json"),
            &report,
            Some(OsStr::new(&group)),
        )
        .unwrap();
        let writes = system.writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, "/var/lib/software-live/state.json");
        assert_eq!(writes[0].group, Some(nix::unistd::getgid().as_raw()));
        assert_eq!(writes[0].value, report.to_value());
        assert_eq!(
            system.calls.borrow().last().unwrap(),
            "write_json /var/lib/software-live/state.json"
        );
    }

    #[test]
    fn no_group_or_an_empty_group_writes_without_one() {
        for group in [None, Some(OsStr::new(""))] {
            let (policy, system) = all_expected();
            let report = collect(&system, &policy, None).unwrap();
            write_state(&system, Path::new("state.json"), &report, group).unwrap();
            assert_eq!(system.writes.borrow()[0].group, None);
        }
    }

    #[test]
    fn an_unknown_group_is_a_key_error_and_nothing_is_written() {
        let (policy, system) = all_expected();
        let report = collect(&system, &policy, None).unwrap();
        let error = write_state(
            &system,
            Path::new("state.json"),
            &report,
            Some(OsStr::new("software-live-no-such-group")),
        )
        .unwrap_err();
        assert_eq!(error.class, "KeyError");
        assert!(system.writes.borrow().is_empty());
    }

    #[test]
    fn a_failed_write_is_the_os_error() {
        let (policy, mut world) = {
            let case = end_to_end_cases().into_iter().next().unwrap();
            (
                Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap(),
                case.world,
            )
        };
        world
            .write_errors
            .insert("/var/lib/software-live/state.json".into(), "EACCES".into());
        let system = FakeSystem::new(world);
        let report = collect(&system, &policy, None).unwrap();
        let error = write_state(
            &system,
            Path::new("/var/lib/software-live/state.json"),
            &report,
            None,
        )
        .unwrap_err();
        assert_eq!(error.class, "PermissionError");
    }

    #[test]
    fn the_manual_mode_prints_the_report_with_its_freshness() {
        let case = end_to_end_cases().into_iter().next().unwrap();
        let policy = Policy::new(pyjson::loads(&case.policy).unwrap()).unwrap();
        let mut world = case.world;
        let generated = world.now[1];
        world.now.push(generated + 2000.0);
        let system = FakeSystem::new(world);
        let report = collect(&system, &policy, None).unwrap();
        let text = manual_output(&system, &report).unwrap();
        assert_eq!(text.last(), Some(&b'\n'));
        assert!(text.is_ascii());
        let value = pyjson::loads_bytes(&text).unwrap();
        let expected = with_freshness(report.to_value(), generated + 2000.0).unwrap();
        assert!(json_eq(&value, &expected));
        assert_eq!(value["meta"]["age_seconds"], 2000.0);
        assert_eq!(value["summary"]["fresh"], false);
        assert!(system.writes.borrow().is_empty());
        assert_eq!(
            system.calls.borrow().iter().filter(|c| *c == "now").count(),
            3
        );
    }

    /// `test_atomic_state_permissions_and_failure_preserves_previous` for
    /// the state file on a real file system: mode 0640, the group through
    /// the descriptor, and a failed write keeps the previous state and
    /// leaves no temporary file.
    #[test]
    fn the_state_file_on_disk_keeps_its_previous_content_on_failure() {
        let (policy, system) = all_expected();
        let report = collect(&system, &policy, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let group = own_group();
        write_state(&HostSystem, &state, &report, Some(OsStr::new(&group))).unwrap();
        let metadata = std::fs::metadata(&state).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o640);
        assert_eq!(metadata.gid(), nix::unistd::getgid().as_raw());
        let written = std::fs::read(&state).unwrap();
        assert_eq!(written, crate::atomic::render(&report.to_value()));
        assert!(json_eq(
            &pyjson::loads_bytes(&written).unwrap(),
            &report.to_value()
        ));

        // An unknown group: nothing is written, the state stays.
        let error = write_state(
            &HostSystem,
            &state,
            &report,
            Some(OsStr::new("software-live-no-such-group")),
        )
        .unwrap_err();
        assert_eq!(error.class, "KeyError");
        assert_eq!(std::fs::read(&state).unwrap(), written);

        // A failed rename (the target is now a non-empty directory) keeps it.
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("kept"), b"x").unwrap();
        assert!(write_state(&HostSystem, &blocked, &report, None).is_err());
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["blocked", "state.json"]);
        assert_eq!(std::fs::read(&state).unwrap(), written);
    }
}
