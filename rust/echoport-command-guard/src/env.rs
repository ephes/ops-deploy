//! What `check()` may ask of the host (PLAN.md 3.3.6-3.3.8, 5.1): the guard's
//! euid, user lookups, `lstat` and the non-strict `realpath`.
//!
//! `check()` takes `&dyn GuardEnv`, so the Layer-1 fixtures run against
//! [`VirtualEnv`], the way the Python tests inject `realpath` and `lstat`. The
//! real implementation (`getpwnam_r`, `geteuid`, `lstat`, and `realpath` as
//! `pyrealpath.rs` over `lstat`/`readlink`) arrives with S2.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The file type of an `lstat` result (the fixtures' `kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    Reg,
    Dir,
    Lnk,
    Fifo,
    Sock,
    Chr,
    Blk,
}

/// The parts of an `lstat` result `check()` looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStat {
    pub kind: FileKind,
    /// Permission bits only (`stat.S_IMODE`).
    pub mode: u32,
    pub uid: u32,
    pub nlink: u64,
}

/// An `OSError` other than `ENOENT`: the errno name and glibc's `strerror`
/// text, which refusal reasons quote (`guard.py:247`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsError {
    pub errno: String,
    pub strerror: String,
}

/// The host as `check()` sees it.
pub trait GuardEnv {
    /// `os.geteuid()`.
    fn euid(&self) -> u32;
    /// `pwd.getpwnam(name).pw_uid` (NSS), `None` when there is no such user.
    fn uid_of(&self, name: &str) -> Option<u32>;
    /// `os.lstat(path)`: `Ok(None)` for `ENOENT`.
    fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError>;
    /// `os.path.realpath(path)` (non-strict, PLAN.md 3.3.6). An error (a
    /// symlink loop, `ENAMETOOLONG`) refuses (PLAN.md 4.2).
    fn realpath(&self, path: &str) -> Result<String, OsError>;
}

/// One `lstat` answer of a fixture env.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum LstatEntry {
    Stat(FileStat),
    Absent(Absent),
    Error(OsError),
}

/// `{"absent": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Absent {
    pub absent: bool,
}

/// A fixture case's `env` (PLAN.md 7.2): every lookup the Python guard made,
/// with its answer. A path missing from `lstat` is absent, a path missing
/// from `realpath` resolves to `normpath(path)`, a user missing from `users`
/// (or `null`) does not exist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirtualEnv {
    #[serde(default)]
    pub euid: u32,
    #[serde(default)]
    pub users: BTreeMap<String, Option<u32>>,
    #[serde(default)]
    pub lstat: BTreeMap<String, LstatEntry>,
    #[serde(default)]
    pub realpath: BTreeMap<String, String>,
}

impl GuardEnv for VirtualEnv {
    fn euid(&self) -> u32 {
        self.euid
    }

    fn uid_of(&self, name: &str) -> Option<u32> {
        self.users.get(name).copied().flatten()
    }

    fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError> {
        match self.lstat.get(path) {
            None => Ok(None),
            Some(LstatEntry::Stat(stat)) => Ok(Some(*stat)),
            // `{"absent": false}` is not a fixture form; treat it as absent.
            Some(LstatEntry::Absent(_)) => Ok(None),
            Some(LstatEntry::Error(error)) => Err(error.clone()),
        }
    }

    fn realpath(&self, path: &str) -> Result<String, OsError> {
        Ok(self
            .realpath
            .get(path)
            .cloned()
            .unwrap_or_else(|| normpath(path)))
    }
}

/// `posixpath.normpath` (CPython 3.12/3.13): collapses `//`, `.` and `..`
/// without looking at the filesystem. Exactly two leading slashes are kept,
/// as POSIX allows them a meaning; three or more become one.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if initial.is_empty() {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    let joined = format!("{initial}{}", parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_as_python() {
        // Expected values from Python 3.12 `os.path.normpath`.
        let cases = [
            ("", "."),
            ("/", "/"),
            ("//", "//"),
            ("///", "/"),
            ("//a//b/", "//a/b"),
            ("///a/./b/../c", "/a/c"),
            ("/..", "/"),
            ("/../a/..", "/"),
            ("/a/b/../../..", "/"),
            ("/home/x/../y", "/home/y"),
            ("/var/lib/gotosocial/.", "/var/lib/gotosocial"),
            ("a/../..", ".."),
            ("../a/../../b", "../../b"),
            ("./", "."),
        ];
        for (path, expected) in cases {
            assert_eq!(normpath(path), expected, "{path:?}");
        }
    }

    #[test]
    fn virtual_env_answers_from_the_fixture() {
        let env: VirtualEnv = serde_json::from_str(
            r#"{"euid": 0, "users": {"postgres": 110, "ghost": null},
                "lstat": {"/a": {"kind": "reg", "mode": 384, "uid": 110, "nlink": 1},
                          "/b": {"absent": true},
                          "/c": {"errno": "EACCES", "strerror": "Permission denied"}},
                "realpath": {"/l": "/target"}}"#,
        )
        .unwrap();
        assert_eq!(env.euid(), 0);
        assert_eq!(env.uid_of("postgres"), Some(110));
        assert_eq!(env.uid_of("ghost"), None);
        assert_eq!(env.uid_of("nobody"), None);
        assert_eq!(
            env.lstat("/a"),
            Ok(Some(FileStat {
                kind: FileKind::Reg,
                mode: 0o600,
                uid: 110,
                nlink: 1
            }))
        );
        assert_eq!(env.lstat("/b"), Ok(None));
        assert_eq!(env.lstat("/missing"), Ok(None));
        assert_eq!(
            env.lstat("/c"),
            Err(OsError {
                errno: "EACCES".into(),
                strerror: "Permission denied".into()
            })
        );
        assert_eq!(env.realpath("/l").as_deref(), Ok("/target"));
        assert_eq!(env.realpath("/x/./y/../z").as_deref(), Ok("/x/z"));
    }

    #[test]
    fn unknown_env_fields_are_an_error() {
        assert!(serde_json::from_str::<VirtualEnv>(r#"{"euid": 0, "readlink": {}}"#).is_err());
    }
}
