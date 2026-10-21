//! What `check()` may ask of the host (PLAN.md 3.3.6-3.3.8, 5.1): the guard's
//! euid, user lookups, `lstat` and the non-strict `realpath`.
//!
//! `check()` takes `&dyn GuardEnv`, so the Layer-1 fixtures run against
//! [`VirtualEnv`], the way the Python tests inject `realpath` and `lstat`.
//! The guard itself runs against [`RealEnv`]: `geteuid`, `getpwnam_r` (NSS,
//! as Python's `pwd.getpwnam`), `lstat`, and `realpath` as
//! [`crate::pyrealpath`] over `lstat`/`readlink`.

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io;
use std::os::unix::fs::MetadataExt;

use nix::errno::Errno;
use nix::unistd::{User, geteuid};
use serde::{Deserialize, Serialize};

use crate::pyrealpath::{self, ResolveFs};

/// The file type of an `lstat` result (the fixtures' `kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OsError {
    pub errno: String,
    pub strerror: String,
}

impl OsError {
    /// The errno name and glibc's `strerror` text of an `io::Error` from a
    /// system call (`EINVAL` for the errors std raises before the call, such
    /// as a NUL byte in a path).
    pub fn from_io(error: &io::Error) -> Self {
        let text = error.to_string();
        match error.raw_os_error() {
            Some(code) => {
                // std's `Display` is `<strerror> (os error <code>)`.
                let strerror = text
                    .strip_suffix(&format!(" (os error {code})"))
                    .unwrap_or(&text)
                    .to_owned();
                Self {
                    errno: format!("{:?}", Errno::from_raw(code)),
                    strerror,
                }
            }
            None => Self {
                errno: "EINVAL".into(),
                strerror: text,
            },
        }
    }
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

/// The real host: what the guard sees when sshd runs it.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEnv;

impl GuardEnv for RealEnv {
    fn euid(&self) -> u32 {
        geteuid().as_raw()
    }

    /// `getpwnam_r` through NSS (glibc), like CPython's `pwd.getpwnam`. A
    /// lookup error counts as "no such user", as in Python (`KeyError`); that
    /// only ever removes a uid from an owner check.
    fn uid_of(&self, name: &str) -> Option<u32> {
        match User::from_name(name) {
            Ok(Some(user)) => Some(user.uid.as_raw()),
            Ok(None) | Err(_) => None,
        }
    }

    fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError> {
        real_lstat(path)
    }

    fn realpath(&self, path: &str) -> Result<String, OsError> {
        pyrealpath::realpath(self, path)
    }
}

impl ResolveFs for RealEnv {
    fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError> {
        real_lstat(path)
    }

    fn readlink(&self, path: &str) -> Result<String, OsError> {
        let target = std::fs::read_link(path).map_err(|error| OsError::from_io(&error))?;
        target.into_os_string().into_string().map_err(|_| OsError {
            errno: "EILSEQ".into(),
            strerror: "link target is not valid UTF-8".into(),
        })
    }
}

/// `os.lstat(path)`: `Ok(None)` for `ENOENT`.
fn real_lstat(path: &str) -> Result<Option<FileStat>, OsError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => file_stat(&metadata).map(Some),
        Err(error) if error.raw_os_error() == Some(Errno::ENOENT as i32) => Ok(None),
        Err(error) => Err(OsError::from_io(&error)),
    }
}

/// The parts of a `stat` result the guard looks at. `kind` comes from the
/// `S_IFMT` bits; a type outside the seven Linux knows is an error.
fn file_stat(metadata: &Metadata) -> Result<FileStat, OsError> {
    let mode = metadata.mode();
    let kind = match mode & 0o170_000 {
        0o100_000 => FileKind::Reg,
        0o040_000 => FileKind::Dir,
        0o120_000 => FileKind::Lnk,
        0o010_000 => FileKind::Fifo,
        0o140_000 => FileKind::Sock,
        0o020_000 => FileKind::Chr,
        0o060_000 => FileKind::Blk,
        _ => {
            return Err(OsError {
                errno: "EINVAL".into(),
                strerror: "unknown file type".into(),
            });
        }
    };
    Ok(FileStat {
        kind,
        // `stat.S_IMODE`
        mode: mode & 0o7777,
        uid: metadata.uid(),
        nlink: metadata.nlink(),
    })
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
