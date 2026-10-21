//! The APT observation of `software_live.py` (`security_origin`,
//! `security_packages`, `observe_apt`, `:530-604`) over small traits, so the
//! logic is tested without a package cache. `cache.rs` implements the
//! traits on rust-apt's types (software-live PLAN.md 13.4).

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde_json::{Map, Value, json};

/// The fixed `index_source` text of the observation.
pub const INDEX_SOURCE: &str = "cached security InRelease publication mtimes; no refresh performed";

/// Where APT keeps its downloaded lists (`Path("/var/lib/apt/lists")`).
pub const LISTS: &str = "/var/lib/apt/lists";

/// One origin of a version (python-apt's `apt.package.Origin`).
pub trait Origin {
    fn origin(&self) -> &str;
    fn archive(&self) -> &str;
    fn label(&self) -> &str;
    fn trusted(&self) -> bool;
}

/// One version of a package (python-apt's `apt.package.Version`).
pub trait Version {
    type Origin: Origin;
    fn version(&self) -> &str;
    fn origins(&self) -> Vec<Self::Origin>;
}

/// One package of the cache (python-apt's `apt.package.Package`).
pub trait Package {
    type Version: Version;
    /// `package.fullname`: always with the architecture.
    fn fullname(&self) -> String;
    /// `package.name`: without the architecture for the native one.
    fn name(&self) -> String;
    fn installed(&self) -> Option<Self::Version>;
    /// All versions, in APT's order.
    fn versions(&self) -> Vec<Self::Version>;
    fn candidate(&self) -> Option<Self::Version>;
}

/// `security_origin(origin)` (`:530-541`). The named-origin test runs first
/// and `trusted` only when it holds: the result is the same boolean as
/// Python's `trusted and (…)`, and the index lookup behind `trusted` runs
/// only for origins that matter.
pub fn security_origin(origin: &impl Origin) -> bool {
    let named = (matches!(origin.origin(), "Ubuntu" | "Debian")
        && origin.archive().to_lowercase().contains("security"))
        || origin.origin().starts_with("UbuntuESM")
        || origin.label() == "Debian-Security";
    named && origin.trusted()
}

/// `security_packages(cache, compare, held)` (`:544-571`): every installed
/// package with a newer version from a trusted security origin, the newest
/// such version (the first one wins a tie), sorted by `package`.
pub fn security_packages<P: Package>(
    packages: impl IntoIterator<Item = P>,
    compare: impl Fn(&str, &str) -> Ordering,
    held: &BTreeSet<String>,
) -> Vec<Value> {
    let mut updates: Vec<(String, Value)> = Vec::new();
    for package in packages {
        let Some(installed) = package.installed() else {
            continue;
        };
        let installed = installed.version().to_owned();
        let mut newest: Option<String> = None;
        for version in package.versions() {
            let candidate = version.version();
            if compare(candidate, &installed) != Ordering::Greater
                || !version.origins().iter().any(security_origin)
            {
                continue;
            }
            match &newest {
                Some(current) if compare(candidate, current) != Ordering::Greater => {}
                _ => newest = Some(candidate.to_owned()),
            }
        }
        let Some(newest) = newest else {
            continue;
        };
        let fullname = package.fullname();
        let held = held.contains(&package.name()) || held.contains(&fullname);
        let candidate = package
            .candidate()
            .map(|version| Value::String(version.version().to_owned()));
        let entry = json!({
            "package": fullname,
            "installed": installed,
            "security_version": newest,
            "candidate": candidate.unwrap_or(Value::Null),
            "held": held,
        });
        updates.push((fullname, entry));
    }
    // `sorted(key=package)`: stable, by code point (UTF-8 byte order is the same).
    updates.sort_by(|a, b| a.0.cmp(&b.0));
    updates.into_iter().map(|(_, entry)| entry).collect()
}

/// `p.stat().st_mtime` as CPython computes it: seconds plus nanoseconds
/// times 1e-9, in floating point (bit-identical ages, PLAN.md 13.2).
fn mtime(metadata: &std::fs::Metadata) -> f64 {
    metadata.mtime() as f64 + metadata.mtime_nsec() as f64 * 1e-9
}

/// The ages (`now - st_mtime`) of every `*InRelease` in `lists` whose name
/// contains `security` (case-insensitive), as
/// `Path(lists).glob("*InRelease")` of Python 3.12 lists them: dot files
/// count, a directory that is missing, not a directory or not readable
/// lists nothing, and `stat` follows symbolic links (a broken one is an
/// error).
pub fn security_index_ages(lists: &Path, now: f64) -> io::Result<Vec<f64>> {
    let entries = match std::fs::read_dir(lists) {
        Ok(entries) => entries,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::NotADirectory
                    | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let mut ages = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if !is_security_index(&name) {
            continue;
        }
        ages.push(now - mtime(&std::fs::metadata(entry.path())?));
    }
    Ok(ages)
}

fn is_security_index(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().ends_with(b"InRelease")
        && name.to_string_lossy().to_lowercase().contains("security")
}

/// The `ok` result of `observe_apt` (`:574-596`).
pub fn ok_result(updates: Vec<Value>, ages: &[f64], max_age: u64) -> Value {
    // Exact: max_age is at most 2^53 (checked on the command line).
    let limit = max_age as f64;
    let fresh = !ages.is_empty() && ages.iter().all(|age| (0.0..=limit).contains(age));
    let oldest = ages
        .iter()
        .copied()
        .reduce(f64::max)
        .map_or(Value::Null, |age| {
            serde_json::Number::from_f64(age).map_or(Value::Null, Value::Number)
        });
    let mut result = Map::new();
    result.insert("status".into(), "ok".into());
    result.insert("pending_security_count".into(), updates.len().into());
    result.insert("pending_security_updates".into(), Value::Array(updates));
    result.insert("indexes_fresh".into(), fresh.into());
    result.insert("oldest_security_index_age_seconds".into(), oldest);
    result.insert("index_age_limit_seconds".into(), max_age.into());
    result.insert("index_source".into(), INDEX_SOURCE.into());
    Value::Object(result)
}

/// The `unknown` result of `observe_apt` (`:597-603`); `class` names the
/// failure (software-live PLAN.md 4.2 item 8).
pub fn unknown_result(class: &str) -> Value {
    json!({
        "status": "unknown",
        "error": format!("APT observation failed ({class})"),
        "indexes_fresh": false,
        "pending_security_count": null,
    })
}

/// The failure class of an OS error, as Python names it.
pub fn os_error_class(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "FileNotFoundError",
        io::ErrorKind::PermissionDenied => "PermissionError",
        io::ErrorKind::NotADirectory => "NotADirectoryError",
        io::ErrorKind::IsADirectory => "IsADirectoryError",
        _ => "OSError",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[derive(Clone)]
    struct FakeOrigin {
        trusted: bool,
        origin: &'static str,
        archive: &'static str,
        label: &'static str,
    }

    impl Origin for FakeOrigin {
        fn origin(&self) -> &str {
            self.origin
        }
        fn archive(&self) -> &str {
            self.archive
        }
        fn label(&self) -> &str {
            self.label
        }
        fn trusted(&self) -> bool {
            self.trusted
        }
    }

    #[derive(Clone)]
    struct FakeVersion {
        version: &'static str,
        origins: Vec<FakeOrigin>,
    }

    impl Version for FakeVersion {
        type Origin = FakeOrigin;
        fn version(&self) -> &str {
            self.version
        }
        fn origins(&self) -> Vec<FakeOrigin> {
            self.origins.clone()
        }
    }

    #[derive(Clone)]
    struct FakePackage {
        name: &'static str,
        fullname: &'static str,
        installed: Option<FakeVersion>,
        versions: Vec<FakeVersion>,
        candidate: Option<FakeVersion>,
    }

    impl Package for FakePackage {
        type Version = FakeVersion;
        fn fullname(&self) -> String {
            self.fullname.into()
        }
        fn name(&self) -> String {
            self.name.into()
        }
        fn installed(&self) -> Option<FakeVersion> {
            self.installed.clone()
        }
        fn versions(&self) -> Vec<FakeVersion> {
            self.versions.clone()
        }
        fn candidate(&self) -> Option<FakeVersion> {
            self.candidate.clone()
        }
    }

    fn origin(trusted: bool, origin: &'static str, archive: &'static str) -> FakeOrigin {
        FakeOrigin {
            trusted,
            origin,
            archive,
            label: "",
        }
    }

    fn version(version: &'static str, origins: Vec<FakeOrigin>) -> FakeVersion {
        FakeVersion { version, origins }
    }

    fn numeric(a: &str, b: &str) -> Ordering {
        a.parse::<i64>().unwrap().cmp(&b.parse::<i64>().unwrap())
    }

    #[test]
    fn security_origins_follow_python() {
        let cases = [
            (origin(true, "Debian", "bookworm-security"), true),
            (origin(true, "Ubuntu", "noble-SECURITY"), true),
            (origin(false, "Debian", "bookworm-security"), false),
            (origin(true, "Debian", "bookworm-updates"), false),
            (origin(true, "UbuntuESMApps", ""), true),
            (origin(true, "UbuntuESM", "x"), true),
            (origin(false, "UbuntuESMInfra", ""), false),
            (origin(true, "Example", "trixie-security"), false),
            (origin(true, "debian", "trixie-security"), false),
            (
                FakeOrigin {
                    label: "Debian-Security",
                    ..origin(true, "Example", "")
                },
                true,
            ),
            (
                FakeOrigin {
                    label: "Debian-Security",
                    ..origin(false, "Example", "")
                },
                false,
            ),
            (
                FakeOrigin {
                    label: "debian-security",
                    ..origin(true, "Example", "")
                },
                false,
            ),
        ];
        for (index, (origin, expected)) in cases.iter().enumerate() {
            assert_eq!(security_origin(origin), *expected, "case {index}");
        }
    }

    /// `test_security_packages_include_held_and_pinned_versions`.
    #[test]
    fn security_packages_include_held_and_pinned_versions() {
        let security = origin(true, "Debian", "bookworm-security");
        let package = FakePackage {
            name: "openssl",
            fullname: "openssl:amd64",
            installed: Some(version("1", vec![])),
            versions: vec![version("1", vec![]), version("2", vec![security.clone()])],
            candidate: Some(version("1", vec![])),
        };
        let held = BTreeSet::from(["openssl".to_owned()]);
        let result = security_packages([package.clone()], numeric, &held);
        assert_eq!(
            result,
            vec![json!({
                "package": "openssl:amd64",
                "installed": "1",
                "security_version": "2",
                "candidate": "1",
                "held": true,
            })]
        );
        let untrusted = FakePackage {
            versions: vec![version(
                "2",
                vec![origin(false, "Debian", "bookworm-security")],
            )],
            ..package
        };
        assert_eq!(
            security_packages([untrusted], numeric, &BTreeSet::new()),
            Vec::<Value>::new()
        );
    }

    #[test]
    fn newest_security_version_wins_and_order_is_by_package() {
        let security = origin(true, "UbuntuESMApps", "");
        let other = origin(true, "Ubuntu", "noble-updates");
        let a = FakePackage {
            name: "zeta",
            fullname: "zeta:amd64",
            installed: Some(version("1", vec![])),
            versions: vec![
                version("3", vec![other.clone(), security.clone()]),
                version("5", vec![security.clone()]),
                version("9", vec![other.clone()]),
                version("4", vec![security.clone()]),
                version("1", vec![security.clone()]),
            ],
            candidate: None,
        };
        let b = FakePackage {
            name: "alpha:i386",
            fullname: "alpha:i386",
            installed: Some(version("2", vec![])),
            versions: vec![version("3", vec![security.clone()])],
            candidate: Some(version("3", vec![])),
        };
        let not_installed = FakePackage {
            installed: None,
            ..b.clone()
        };
        let held = BTreeSet::from(["alpha:i386".to_owned()]);
        let result = security_packages([a, not_installed, b], numeric, &held);
        assert_eq!(
            result,
            vec![
                json!({"package": "alpha:i386", "installed": "2", "security_version": "3", "candidate": "3", "held": true}),
                json!({"package": "zeta:amd64", "installed": "1", "security_version": "5", "candidate": null, "held": false}),
            ]
        );
    }

    #[test]
    fn a_tie_keeps_the_first_newest_version() {
        // APT can compare different strings as equal ("1.0" and "1.00").
        let security = origin(true, "Debian", "trixie-security");
        let package = FakePackage {
            name: "p",
            fullname: "p:amd64",
            installed: Some(version("0", vec![])),
            versions: vec![
                version("1.00", vec![security.clone()]),
                version("1.0", vec![security.clone()]),
            ],
            candidate: None,
        };
        let by_value = |a: &str, b: &str| a.parse::<f64>().unwrap().total_cmp(&b.parse().unwrap());
        let result = security_packages([package], by_value, &BTreeSet::new());
        assert_eq!(result[0]["security_version"], "1.00");
    }

    #[test]
    fn index_ages_follow_pathlib_glob_and_stat() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let lists = dir.join("lists");
        std::fs::create_dir(&lists).unwrap();
        for name in [
            "deb.debian.org_debian-security_dists_trixie-security_InRelease",
            ".hidden-Security_InRelease",
            "security.ubuntu.com_ubuntu_dists_noble-security_Release",
            "deb.debian.org_debian_dists_trixie_InRelease",
            "security-InRelease.gpg",
        ] {
            std::fs::write(lists.join(name), b"").unwrap();
        }
        let ages = security_index_ages(&lists, 4.0e9).unwrap();
        assert_eq!(ages.len(), 2, "{ages:?}");
        assert!(ages.iter().all(|age| *age > 1.0e9));
        // Missing directory: nothing listed.
        assert_eq!(
            security_index_ages(&dir.join("missing"), 1.0).unwrap(),
            Vec::<f64>::new()
        );
        // A broken symbolic link is an error, as `Path.stat()`.
        symlink(dir.join("gone"), lists.join("x-security_InRelease")).unwrap();
        let error = security_index_ages(&lists, 1.0).unwrap_err();
        assert_eq!(os_error_class(&error), "FileNotFoundError");
    }

    #[test]
    fn ok_result_has_python_fields() {
        let result = ok_result(vec![], &[10.5, -1.0], 3600);
        assert_eq!(
            result,
            json!({
                "status": "ok",
                "pending_security_count": 0,
                "pending_security_updates": [],
                "indexes_fresh": false,
                "oldest_security_index_age_seconds": 10.5,
                "index_age_limit_seconds": 3600,
                "index_source": INDEX_SOURCE,
            })
        );
        assert_eq!(
            ok_result(vec![], &[0.0, 3600.0], 3600)["indexes_fresh"],
            true
        );
        assert_eq!(ok_result(vec![], &[3600.5], 3600)["indexes_fresh"], false);
        let none = ok_result(vec![], &[], 3600);
        assert_eq!(none["indexes_fresh"], false);
        assert_eq!(none["oldest_security_index_age_seconds"], Value::Null);
        // An integral age stays a float in JSON.
        assert_eq!(
            serde_json::to_string(
                &ok_result(vec![], &[100.0], 3600)["oldest_security_index_age_seconds"]
            )
            .unwrap(),
            "100.0"
        );
    }

    #[test]
    fn unknown_result_has_python_fields() {
        assert_eq!(
            unknown_result("CacheOpen"),
            json!({
                "status": "unknown",
                "error": "APT observation failed (CacheOpen)",
                "indexes_fresh": false,
                "pending_security_count": null,
            })
        );
    }
}
