//! The APT observation of `collect` (PLAN.md 3.3 "APT", 5.2): run the
//! helper `software-live-apt` and take its JSON object, or report
//! `unknown`.
//!
//! The helper links libapt-pkg through rust-apt (GPL-3.0-or-later), so it
//! is a separate executable; this crate links neither. Contract:
//!
//! - The helper lies next to this program's executable (the directory of
//!   `/proc/self/exe`); it runs only if it is a regular file (not a
//!   symbolic link) owned by root and not writable by group or others.
//! - argv `software-live-apt observe --max-age <seconds> --now <epoch>`
//!   (`now` as Python's float `repr`, which the helper reads back exactly),
//!   no stdin, killed after 60 seconds.
//! - Exit 0 and at most 4 MiB on each stream (read no further: the helper
//!   is killed at the limit), stdout holding one JSON object with
//!   exactly the keys of `observe_apt`'s result (`ok`, or the helper's own
//!   `unknown`); anything else is the `unknown` object with a class of
//!   this module (PLAN.md 4.2 item 8): `HelperMissing`, `HelperUnsafe`,
//!   `HelperStart`, `HelperTimeout`, `HelperExit`, `InvalidHelperOutput`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use crate::probe::{CommandError, System};
use crate::pyjson;
use crate::report::Observation;

/// The helper's file name, next to this program's executable.
pub const HELPER_NAME: &str = "software-live-apt";
/// How long the helper may run (the collector unit allows 90 s in all).
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(60);
/// The most stdout the helper may print.
pub const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
/// The owner the helper must have (root).
pub const HELPER_OWNER: u32 = 0;
/// The fixed `index_source` text of an `ok` observation.
pub const INDEX_SOURCE: &str = "cached security InRelease publication mtimes; no refresh performed";

/// The keys of an `ok` observation and of one pending update.
const OK_KEYS: [&str; 7] = [
    "status",
    "pending_security_count",
    "pending_security_updates",
    "indexes_fresh",
    "oldest_security_index_age_seconds",
    "index_age_limit_seconds",
    "index_source",
];
const UPDATE_KEYS: [&str; 5] = [
    "package",
    "installed",
    "security_version",
    "candidate",
    "held",
];
const UNKNOWN_KEYS: [&str; 4] = ["status", "error", "indexes_fresh", "pending_security_count"];

/// The `error` of the helper's own `unknown` result.
static HELPER_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\AAPT observation failed \([A-Za-z][A-Za-z0-9]{0,63}\)\z").expect("valid regex")
});

/// The `unknown` observation (`software_live.py:597-603`).
pub fn unknown(class: &str) -> Observation {
    let mut result = Observation::new();
    result
        .set("status", "unknown")
        .set("error", format!("APT observation failed ({class})"))
        .set("indexes_fresh", false)
        .set("pending_security_count", Value::Null);
    result
}

/// `observe_apt(max_age, now)` through the helper next to this executable.
pub fn observe_apt<S: System + ?Sized>(system: &S, max_age: i64, now: f64) -> Observation {
    match helper_path(system) {
        Some(helper) => observe_with(system, &helper, HELPER_OWNER, max_age, now, HELPER_TIMEOUT),
        None => unknown("HelperMissing"),
    }
}

/// `<directory of /proc/self/exe>/software-live-apt`. A link target with
/// the suffix ` (deleted)` names the same directory.
fn helper_path<S: System + ?Sized>(system: &S) -> Option<PathBuf> {
    let exe = PathBuf::from(system.readlink(Path::new("/proc/self/exe")).ok()?);
    if !exe.is_absolute() {
        return None;
    }
    Some(exe.parent()?.join(HELPER_NAME))
}

/// Run the helper at `helper` (owned by `owner`) and take its result.
pub fn observe_with<S: System + ?Sized>(
    system: &S,
    helper: &Path,
    owner: u32,
    max_age: i64,
    now: f64,
    timeout: Duration,
) -> Observation {
    run(system, helper, owner, max_age, now, timeout).unwrap_or_else(unknown)
}

fn run<S: System + ?Sized>(
    system: &S,
    helper: &Path,
    owner: u32,
    max_age: i64,
    now: f64,
    timeout: Duration,
) -> Result<Observation, &'static str> {
    let stat = system.lstat(helper).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "HelperMissing"
        } else {
            "HelperUnsafe"
        }
    })?;
    let regular = stat.mode & 0o170_000 == 0o100_000;
    if !regular || stat.uid != owner || stat.mode & 0o022 != 0 {
        return Err("HelperUnsafe");
    }
    let max_age_arg = OsString::from(max_age.to_string());
    let now_arg = OsString::from(pyjson::float_repr(now));
    let argv: [&OsStr; 6] = [
        helper.as_os_str(),
        OsStr::new("observe"),
        OsStr::new("--max-age"),
        &max_age_arg,
        OsStr::new("--now"),
        &now_arg,
    ];
    // Neither stream is read past OUTPUT_LIMIT: the helper is killed there.
    let output = system
        .run_bounded(&argv, timeout, OUTPUT_LIMIT)
        .map_err(|error| match error {
            CommandError::Spawn(_) => "HelperStart",
            CommandError::Timeout(_) => "HelperTimeout",
            CommandError::Io(_) | CommandError::OutputLimit(_) => "InvalidHelperOutput",
        })?;
    if !output.success() {
        return Err("HelperExit");
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "InvalidHelperOutput")?;
    let value = pyjson::loads(text).map_err(|_| "InvalidHelperOutput")?;
    if !valid_result(&value, max_age) {
        return Err("InvalidHelperOutput");
    }
    Observation::from_value(value).ok_or("InvalidHelperOutput")
}

fn has_exactly(map: &serde_json::Map<String, Value>, keys: &[&str]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}

/// Whether `value` is an APT observation as `observe_apt` returns it.
fn valid_result(value: &Value, max_age: i64) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    match map.get("status").and_then(Value::as_str) {
        Some("ok") => valid_ok(map, max_age),
        Some("unknown") => {
            has_exactly(map, &UNKNOWN_KEYS)
                && map
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|error| HELPER_ERROR.is_match(error))
                && map["indexes_fresh"] == Value::Bool(false)
                && map["pending_security_count"].is_null()
        }
        _ => false,
    }
}

fn valid_ok(map: &serde_json::Map<String, Value>, max_age: i64) -> bool {
    if !has_exactly(map, &OK_KEYS) {
        return false;
    }
    let Some(updates) = map["pending_security_updates"].as_array() else {
        return false;
    };
    let count_ok = pyjson::is_int(&map["pending_security_count"])
        && pyjson::eq_int(
            &map["pending_security_count"],
            i64::try_from(updates.len()).unwrap_or(i64::MAX),
        );
    let mut previous: Option<&str> = None;
    for update in updates {
        let Value::Object(entry) = update else {
            return false;
        };
        let strings = ["package", "installed", "security_version"]
            .iter()
            .all(|key| entry.get(*key).is_some_and(Value::is_string));
        let candidate = entry
            .get("candidate")
            .is_some_and(|c| c.is_string() || c.is_null());
        let held = entry.get("held").is_some_and(Value::is_boolean);
        if !(has_exactly(entry, &UPDATE_KEYS) && strings && candidate && held) {
            return false;
        }
        let package = entry["package"].as_str().unwrap_or_default();
        if previous.is_some_and(|before| before > package) {
            return false;
        }
        previous = Some(package);
    }
    let fresh = &map["indexes_fresh"];
    let oldest = &map["oldest_security_index_age_seconds"];
    // A float (`now - st_mtime`) or `null` when no index exists, which is
    // never fresh.
    let oldest_ok = match oldest {
        Value::Null => *fresh == Value::Bool(false),
        Value::Number(_) => !pyjson::is_int(oldest),
        _ => false,
    };
    count_ok
        && fresh.is_boolean()
        && oldest_ok
        && pyjson::is_int(&map["index_age_limit_seconds"])
        && pyjson::eq_int(&map["index_age_limit_seconds"], max_age)
        && map["index_source"] == Value::String(INDEX_SOURCE.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::HostSystem;
    use crate::probe::fake::{FakeSystem, World};
    use serde_json::json;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const EXE: &str = "/usr/local/lib/software-live/releases/0.1.0/software-live";
    const HELPER: &str = "/usr/local/lib/software-live/releases/0.1.0/software-live-apt";

    fn ok_output() -> Value {
        json!({
            "status": "ok",
            "pending_security_count": 2,
            "pending_security_updates": [
                {"package": "libexpat1:amd64", "installed": "2.6.1-2", "security_version": "2.6.1-2ubuntu0.1",
                 "candidate": "2.6.1-2ubuntu0.1", "held": true},
                {"package": "openssl:amd64", "installed": "3.0.13-0ubuntu3", "security_version": "3.0.13-0ubuntu3.5",
                 "candidate": null, "held": false},
            ],
            "indexes_fresh": true,
            "oldest_security_index_age_seconds": 3599.25,
            "index_age_limit_seconds": 172800,
            "index_source": INDEX_SOURCE,
        })
    }

    /// The world of one helper run: the executable link, the helper's
    /// `lstat` and the expected command with its result.
    fn world(mode: u32, uid: u32, command: Value) -> World {
        let mut command = command;
        command["argv"] = json!([
            HELPER,
            "observe",
            "--max-age",
            "172800",
            "--now",
            "1761000000.5"
        ]);
        serde_json::from_value(json!({
            "readlink": {"/proc/self/exe": [{"ok": EXE}]},
            "lstat": {HELPER: [{"ok": {"mode": mode, "uid": uid}}]},
            "commands": [command],
        }))
        .unwrap()
    }

    fn observe_world(world: World) -> (Observation, usize) {
        let fake = FakeSystem::new(world);
        let result = observe_apt(&fake, 172_800, 1_761_000_000.5);
        (result, fake.pending_commands())
    }

    fn error_of(observation: &Observation) -> &str {
        assert_eq!(observation.status(), Some("unknown"));
        assert_eq!(observation.get("indexes_fresh"), Some(&Value::Bool(false)));
        assert_eq!(
            observation.get("pending_security_count"),
            Some(&Value::Null)
        );
        assert_eq!(observation.as_map().len(), 4);
        observation.get("error").and_then(Value::as_str).unwrap()
    }

    #[test]
    fn the_helpers_result_is_the_observation() {
        let stdout = ok_output().to_string();
        let (result, pending) = observe_world(world(
            0o100_755,
            0,
            json!({"stdout": format!("{stdout}\n")}),
        ));
        assert_eq!(pending, 0);
        assert!(crate::testutil::json_eq(&result.into_value(), &ok_output()));
    }

    #[test]
    fn the_helpers_own_unknown_result_is_kept() {
        let own = json!({"status": "unknown", "error": "APT observation failed (CacheOpen)",
                         "indexes_fresh": false, "pending_security_count": null});
        let (result, _) = observe_world(world(0o100_755, 0, json!({"stdout": own.to_string()})));
        assert_eq!(error_of(&result), "APT observation failed (CacheOpen)");
    }

    #[test]
    fn an_unsafe_or_missing_helper_never_runs() {
        for (mode, uid, class) in [
            (0o100_775, 0, "HelperUnsafe"),
            (0o100_757, 0, "HelperUnsafe"),
            (0o100_755, 1000, "HelperUnsafe"),
            (0o120_777, 0, "HelperUnsafe"),
            (0o040_755, 0, "HelperUnsafe"),
        ] {
            let fake = FakeSystem::new(world(mode, uid, json!({})));
            let result = observe_apt(&fake, 172_800, 1_761_000_000.5);
            assert_eq!(
                error_of(&result),
                format!("APT observation failed ({class})"),
                "{mode:o} {uid}"
            );
            assert_eq!(fake.pending_commands(), 1, "the helper must not run");
        }
        let mut missing = world(0o100_755, 0, json!({}));
        missing.lstat.clear();
        let fake = FakeSystem::new(missing);
        assert_eq!(
            error_of(&observe_apt(&fake, 172_800, 1_761_000_000.5)),
            "APT observation failed (HelperMissing)"
        );
        let mut denied = world(0o100_755, 0, json!({}));
        denied.lstat = serde_json::from_value(json!({HELPER: [{"errno": "EACCES"}]})).unwrap();
        let fake = FakeSystem::new(denied);
        assert_eq!(
            error_of(&observe_apt(&fake, 172_800, 1_761_000_000.5)),
            "APT observation failed (HelperUnsafe)"
        );
        let mut no_exe = world(0o100_755, 0, json!({}));
        no_exe.readlink.clear();
        let fake = FakeSystem::new(no_exe);
        assert_eq!(
            error_of(&observe_apt(&fake, 172_800, 1_761_000_000.5)),
            "APT observation failed (HelperMissing)"
        );
    }

    #[test]
    fn the_helper_next_to_a_replaced_executable_is_found() {
        let mut deleted = world(0o100_755, 0, json!({"stdout": ok_output().to_string()}));
        deleted.readlink =
            serde_json::from_value(json!({"/proc/self/exe": [{"ok": format!("{EXE} (deleted)")}]}))
                .unwrap();
        let (result, pending) = observe_world(deleted);
        assert_eq!((result.status(), pending), (Some("ok"), 0));
    }

    #[test]
    fn helper_failures_are_unknown_with_their_class() {
        for (command, class) in [
            (
                json!({"exit": 1, "stdout": ok_output().to_string()}),
                "HelperExit",
            ),
            (json!({"exit": 101}), "HelperExit"),
            (json!({"error": "timeout"}), "HelperTimeout"),
            (json!({"error": "ENOENT"}), "HelperStart"),
            (json!({"error": "EACCES"}), "HelperStart"),
            (json!({"stdout": ""}), "InvalidHelperOutput"),
            (
                json!({"stdout": "{\"status\": \"ok\""}),
                "InvalidHelperOutput",
            ),
            (json!({"stdout": "[]"}), "InvalidHelperOutput"),
            (
                json!({"stdout": " ".repeat(OUTPUT_LIMIT + 1)}),
                "InvalidHelperOutput",
            ),
        ] {
            let (result, _) = observe_world(world(0o100_755, 0, command.clone()));
            assert_eq!(
                error_of(&result),
                format!("APT observation failed ({class})"),
                "{command}"
            );
        }
    }

    /// Every change of a valid result that `observe_apt` could not have
    /// returned makes it `InvalidHelperOutput`.
    type Mutation = Box<dyn Fn(&mut Value)>;

    #[test]
    fn malformed_results_are_rejected() {
        let mutations: Vec<Mutation> = vec![
            Box::new(|v| v["status"] = json!("warning")),
            Box::new(|v| v["extra"] = json!(1)),
            Box::new(|v| {
                v.as_object_mut().unwrap().remove("index_source");
            }),
            Box::new(|v| v["index_source"] = json!("other")),
            Box::new(|v| v["pending_security_count"] = json!(3)),
            Box::new(|v| v["pending_security_count"] = json!(2.0)),
            Box::new(|v| v["pending_security_count"] = json!(true)),
            Box::new(|v| v["pending_security_updates"] = json!({})),
            Box::new(|v| v["pending_security_updates"][0]["extra"] = json!(1)),
            Box::new(|v| v["pending_security_updates"][0]["held"] = json!(1)),
            Box::new(|v| v["pending_security_updates"][0]["candidate"] = json!(1)),
            Box::new(|v| v["pending_security_updates"][0]["package"] = json!(null)),
            Box::new(|v| v["pending_security_updates"][0]["installed"] = json!(2)),
            Box::new(|v| v["pending_security_updates"][1]["security_version"] = json!(null)),
            Box::new(|v| v["pending_security_updates"][0]["package"] = json!("zz")),
            Box::new(|v| v["pending_security_updates"][0] = json!("x")),
            Box::new(|v| v["indexes_fresh"] = json!(null)),
            Box::new(|v| v["oldest_security_index_age_seconds"] = json!(3599)),
            Box::new(|v| v["oldest_security_index_age_seconds"] = json!("1.0")),
            Box::new(|v| v["oldest_security_index_age_seconds"] = json!(null)),
            Box::new(|v| v["index_age_limit_seconds"] = json!(3600)),
            Box::new(|v| v["index_age_limit_seconds"] = json!(172800.0)),
            Box::new(|v| {
                *v = json!({"status": "unknown", "error": "APT observation failed (x y)",
                                     "indexes_fresh": false, "pending_security_count": null})
            }),
            Box::new(|v| {
                *v = json!({"status": "unknown", "error": "APT observation failed (A)",
                                     "indexes_fresh": true, "pending_security_count": null})
            }),
            Box::new(|v| {
                *v = json!({"status": "unknown", "error": "APT observation failed (A)",
                                     "indexes_fresh": false, "pending_security_count": 0})
            }),
            Box::new(|v| {
                *v = json!({"status": "unknown", "error": "APT observation failed (A)",
                                     "indexes_fresh": false})
            }),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut output = ok_output();
            mutate(&mut output);
            let (result, _) =
                observe_world(world(0o100_755, 0, json!({"stdout": output.to_string()})));
            assert_eq!(
                error_of(&result),
                "APT observation failed (InvalidHelperOutput)",
                "mutation {index}: {output}"
            );
        }
        // Not standard JSON, as Python's json.loads would accept it.
        let nan = ok_output().to_string().replace("3599.25", "NaN");
        let (result, _) = observe_world(world(0o100_755, 0, json!({"stdout": nan})));
        assert_eq!(
            error_of(&result),
            "APT observation failed (InvalidHelperOutput)"
        );
        // No index at all: `null` and not fresh is valid.
        let mut none = ok_output();
        none["oldest_security_index_age_seconds"] = Value::Null;
        none["indexes_fresh"] = json!(false);
        let (result, _) = observe_world(world(0o100_755, 0, json!({"stdout": none.to_string()})));
        assert_eq!(result.status(), Some("ok"));
    }

    #[test]
    fn now_is_passed_as_pythons_float_repr() {
        let mut command = json!({"stdout": ok_output().to_string()});
        command["argv"] = json!([HELPER, "observe", "--max-age", "3600", "--now", "1e+16"]);
        let world: World = serde_json::from_value(json!({
            "readlink": {"/proc/self/exe": [{"ok": EXE}]},
            "lstat": {HELPER: [{"ok": {"mode": 0o100_755, "uid": 0}}]},
            "commands": [command],
        }))
        .unwrap();
        let fake = FakeSystem::new(world);
        // The limit differs from the output's 172800: invalid, but the
        // command line was the expected one (the fake asserts the argv).
        let result = observe_apt(&fake, 3600, 1e16);
        assert_eq!(
            error_of(&result),
            "APT observation failed (InvalidHelperOutput)"
        );
        assert_eq!(fake.pending_commands(), 0);
    }

    // --- the real host: a shell script as the helper ---------------------

    /// One process-starting test at a time (see `probe::tests::SPAWN`).
    static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
        SPAWN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A helper script in a fresh directory, owned by the test user.
    fn script(body: &str) -> (tempfile::TempDir, PathBuf, u32) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HELPER_NAME);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let uid = std::fs::metadata(&path).unwrap().uid();
        (dir, path, uid)
    }

    fn host_run(path: &Path, uid: u32, timeout: Duration) -> Observation {
        observe_with(&HostSystem, path, uid, 172_800, 1_761_000_000.5, timeout)
    }

    #[test]
    fn a_real_helper_gets_the_contract_argv_and_no_stdin() {
        let _serial = spawn_lock();
        let output = ok_output().to_string().replace('\'', "");
        let (dir, path, uid) = script(&format!(
            "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv\"\n\
             if read -r line; then echo stdin >> \"$(dirname \"$0\")/argv\"; fi\n\
             printf '%s\\n' '{output}'"
        ));
        let result = host_run(&path, uid, Duration::from_secs(10));
        assert_eq!(result.status(), Some("ok"), "{result:?}");
        let argv = std::fs::read_to_string(dir.path().join("argv")).unwrap();
        assert_eq!(argv, "observe\n--max-age\n172800\n--now\n1761000000.5\n");
    }

    #[test]
    fn real_helper_failures() {
        let _serial = spawn_lock();
        let (_dir, path, uid) = script("exit 3");
        assert_eq!(
            error_of(&host_run(&path, uid, Duration::from_secs(10))),
            "APT observation failed (HelperExit)"
        );
        let (_dir, path, uid) = script("exec sleep 10");
        let started = std::time::Instant::now();
        assert_eq!(
            error_of(&host_run(&path, uid, Duration::from_millis(300))),
            "APT observation failed (HelperTimeout)"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // More than 4 MiB on stdout, or on stderr, then a long sleep: the
        // helper is killed at the limit, long before its timeout.
        for stream in ["", ">&2"] {
            let (_dir, path, uid) = script(&format!(
                "head -c 8388608 /dev/zero | tr '\\0' ' ' {stream}; exec sleep 30"
            ));
            let started = std::time::Instant::now();
            assert_eq!(
                error_of(&host_run(&path, uid, Duration::from_secs(20))),
                "APT observation failed (InvalidHelperOutput)",
                "{stream}"
            );
            assert!(started.elapsed() < Duration::from_secs(10), "{stream}");
        }
        // The helper exits, a child it left behind writes past the limit
        // and keeps the other pipe open: the limit, not the timeout.
        let (_dir, path, uid) =
            script("(sleep 0.1; head -c 4194305 /dev/zero; exec sleep 5 >&2) & exit 0");
        let started = std::time::Instant::now();
        assert_eq!(
            error_of(&host_run(&path, uid, Duration::from_secs(3))),
            "APT observation failed (InvalidHelperOutput)"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        // Exactly the limit on stderr is not too much.
        let output = ok_output().to_string();
        let (_dir, path, uid) = script(&format!(
            "head -c {OUTPUT_LIMIT} /dev/zero >&2; printf '%s\\n' '{output}'"
        ));
        assert_eq!(
            host_run(&path, uid, Duration::from_secs(20)).status(),
            Some("ok")
        );
        // Owned by someone else: refused before it runs.
        let (dir, path, uid) = script("touch \"$(dirname \"$0\")/ran\"");
        assert_eq!(
            error_of(&host_run(
                &path,
                uid.wrapping_add(1),
                Duration::from_secs(10)
            )),
            "APT observation failed (HelperUnsafe)"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            error_of(&host_run(&path, uid, Duration::from_secs(10))),
            "APT observation failed (HelperUnsafe)"
        );
        assert!(!dir.path().join("ran").exists());
    }
}
