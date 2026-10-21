//! The filesystem helpers of `check()` (PLAN.md 3.3.6-3.3.8): "inside a
//! policy root" through `realpath`, the plain-file and private-directory
//! checks through `lstat`, and the uid sets of owner checks
//! (`guard.py:224-275, 622-629`). Refusal reasons are Python's (PLAN.md
//! 4.4), except the `realpath` errors Python does not have (PLAN.md 4.2).

use std::collections::BTreeSet;

use crate::decision::Refused;
use crate::env::{FileKind, FileStat, GuardEnv};
use crate::policy::{PathRoot, Policy, is_safe_path};
use crate::repr::py_repr;

/// `_user_uids(users, include_self)` (`guard.py:622-629`): the uids of the
/// users that exist (NSS), plus the guard's own euid with `include_self`.
pub fn user_uids(env: &dyn GuardEnv, users: &[&str], include_self: bool) -> BTreeSet<u32> {
    let mut uids = BTreeSet::new();
    if include_self {
        uids.insert(env.euid());
    }
    uids.extend(users.iter().filter_map(|user| env.uid_of(user)));
    uids
}

/// `realpath(path)` for a check: an error (a symlink loop, `ENAMETOOLONG`,
/// … see [`crate::pyrealpath`]) refuses with `path not checkable`, where
/// Python returns a partly resolved path (PLAN.md 4.2).
pub fn resolve(env: &dyn GuardEnv, path: &str) -> Result<String, Refused> {
    env.realpath(path).map_err(|error| {
        Refused::new(format!(
            "path not checkable: {}: {}",
            py_repr(path),
            error.strerror
        ))
    })
}

/// `_root_for` (`guard.py:224-232`): the first policy root that `path`
/// resolves into (or to), `None` for an unsafe path or one outside every
/// root.
pub fn root_for<'p>(
    policy: &'p Policy,
    path: &str,
    env: &dyn GuardEnv,
) -> Result<Option<&'p PathRoot>, Refused> {
    if !is_safe_path(path) {
        return Ok(None);
    }
    let resolved = resolve(env, path)?;
    Ok(policy.path_roots.iter().find(|root| {
        resolved == root.path
            || resolved
                .strip_prefix(root.path.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    }))
}

/// `_require_in_roots` (`guard.py:235-238`).
pub fn require_in_roots<'p>(
    policy: &'p Policy,
    path: &str,
    env: &dyn GuardEnv,
) -> Result<&'p PathRoot, Refused> {
    root_for(policy, path, env)?
        .ok_or_else(|| Refused::new(format!("path outside the allowed roots: {}", py_repr(path))))
}

/// `_lstat_or_none` (`guard.py:241-247`): `None` when the path does not
/// exist; any other error refuses with `<what> not checkable`.
pub fn lstat_or_none(
    env: &dyn GuardEnv,
    path: &str,
    what: &str,
) -> Result<Option<FileStat>, Refused> {
    env.lstat(path).map_err(|error| {
        Refused::new(format!(
            "{what} not checkable: {}: {}",
            py_repr(path),
            error.strerror
        ))
    })
}

/// `_require_plain_file_or_absent` (`guard.py:250-262`): missing, or a
/// regular file (not followed if it is a link) with exactly one link; with
/// `owner`, an existing file must belong to that user (the guard's own euid
/// does not count).
pub fn require_plain_file_or_absent(
    env: &dyn GuardEnv,
    path: &str,
    what: &str,
    owner: Option<&str>,
) -> Result<(), Refused> {
    let Some(stat) = lstat_or_none(env, path, what)? else {
        return Ok(());
    };
    let repr = py_repr(path);
    if stat.kind != FileKind::Reg {
        return Err(Refused::new(format!(
            "{what} is not a regular file: {repr}"
        )));
    }
    if stat.nlink != 1 {
        return Err(Refused::new(format!("{what} has other hard links: {repr}")));
    }
    if let Some(owner) = owner
        && !user_uids(env, &[owner], false).contains(&stat.uid)
    {
        return Err(Refused::new(format!(
            "{what} does not belong to {owner}: {repr}"
        )));
    }
    Ok(())
}

/// `_require_private_dir` (`guard.py:265-275`): a directory (not followed if
/// it is a link) owned by the guard's euid with no group or other access.
pub fn require_private_dir(env: &dyn GuardEnv, path: &str) -> Result<(), Refused> {
    let stat = lstat_or_none(env, path, "directory")?;
    let private = stat.is_some_and(|stat| {
        stat.kind == FileKind::Dir && stat.uid == env.euid() && stat.mode & 0o077 == 0
    });
    if private {
        Ok(())
    } else {
        Err(Refused::new(format!(
            "not a private directory: {}",
            py_repr(path)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::VirtualEnv;
    use crate::policy::parse_policy;

    /// A fixture env (PLAN.md 7.2 format).
    fn env(json: &str) -> VirtualEnv {
        serde_json::from_str(json).unwrap()
    }

    fn reason(result: Result<(), Refused>) -> String {
        result.unwrap_err().reason().to_owned()
    }

    const DUMP: &str = "/tmp/echoport_pp_dump_2026-10-15T02-00-00.dump";

    #[test]
    fn user_uids_as_python() {
        let env = env(r#"{"euid": 0, "users": {"postgres": 110, "ghost": null}}"#);
        assert_eq!(
            user_uids(&env, &["postgres", "ghost", "nobody"], true),
            BTreeSet::from([0, 110])
        );
        assert_eq!(user_uids(&env, &["postgres"], false), BTreeSet::from([110]));
        assert!(user_uids(&env, &["ghost"], false).is_empty());
    }

    /// The reasons of `fixtures/fs.jsonl` (`scp -f <dump>`, `scp -f
    /// <private media archive>`), which S3b's rules produce through these
    /// helpers.
    #[test]
    fn plain_file_reasons_as_python() {
        let absent = env(r#"{"lstat": {}}"#);
        assert_eq!(
            require_plain_file_or_absent(&absent, DUMP, "scp source", Some("postgres")),
            Ok(())
        );
        let cases = [
            (
                r#"{"users": {"postgres": 110}, "lstat": {"P": {"kind": "reg", "mode": 384, "uid": 0, "nlink": 1}}}"#,
                Some("postgres"),
                "scp source does not belong to postgres: 'P'",
            ),
            (
                r#"{"lstat": {"P": {"kind": "lnk", "mode": 511, "uid": 0, "nlink": 1}}}"#,
                None,
                "scp source is not a regular file: 'P'",
            ),
            (
                r#"{"lstat": {"P": {"kind": "fifo", "mode": 384, "uid": 0, "nlink": 1}}}"#,
                Some("postgres"),
                "scp source is not a regular file: 'P'",
            ),
            (
                r#"{"users": {"postgres": 110}, "lstat": {"P": {"kind": "reg", "mode": 384, "uid": 110, "nlink": 2}}}"#,
                Some("postgres"),
                "scp source has other hard links: 'P'",
            ),
            (
                r#"{"lstat": {"P": {"errno": "ENOTDIR", "strerror": "Not a directory"}}}"#,
                Some("postgres"),
                "scp source not checkable: 'P': Not a directory",
            ),
            // The euid alone is not the owner (`include_self=False`).
            (
                r#"{"euid": 0, "users": {}, "lstat": {"P": {"kind": "reg", "mode": 384, "uid": 0, "nlink": 1}}}"#,
                Some("postgres"),
                "scp source does not belong to postgres: 'P'",
            ),
        ];
        for (json, owner, expected) in cases {
            let env = env(&json.replace("\"P\"", &format!("\"{DUMP}\"")));
            assert_eq!(
                reason(require_plain_file_or_absent(
                    &env,
                    DUMP,
                    "scp source",
                    owner
                )),
                expected.replace("'P'", &format!("'{DUMP}'")),
                "{json}"
            );
        }
        let owned = env(
            &r#"{"users": {"postgres": 110}, "lstat": {"P": {"kind": "reg", "mode": 384, "uid": 110, "nlink": 1}}}"#
                .replace("\"P\"", &format!("\"{DUMP}\"")),
        );
        assert_eq!(
            require_plain_file_or_absent(&owned, DUMP, "scp source", Some("postgres")),
            Ok(())
        );
        assert_eq!(
            require_plain_file_or_absent(&owned, DUMP, "scp target", None),
            Ok(())
        );
    }

    #[test]
    fn private_dir_as_python() {
        const DIR: &str = "/tmp/echoport-pp-private-media.Ab12Cd34";
        let check = |json: &str| {
            require_private_dir(&env(&json.replace("\"D\"", &format!("\"{DIR}\""))), DIR)
        };
        assert_eq!(
            check(
                r#"{"euid": 0, "lstat": {"D": {"kind": "dir", "mode": 448, "uid": 0, "nlink": 2}}}"#
            ),
            Ok(())
        );
        let refused = format!("not a private directory: '{DIR}'");
        for json in [
            // absent
            r#"{"lstat": {}}"#,
            // a file, a symlink (not followed)
            r#"{"lstat": {"D": {"kind": "reg", "mode": 384, "uid": 0, "nlink": 1}}}"#,
            r#"{"lstat": {"D": {"kind": "lnk", "mode": 511, "uid": 0, "nlink": 1}}}"#,
            // foreign owner, group or other access
            r#"{"euid": 0, "lstat": {"D": {"kind": "dir", "mode": 448, "uid": 110, "nlink": 2}}}"#,
            r#"{"lstat": {"D": {"kind": "dir", "mode": 488, "uid": 0, "nlink": 2}}}"#,
            r#"{"lstat": {"D": {"kind": "dir", "mode": 449, "uid": 0, "nlink": 2}}}"#,
            r#"{"lstat": {"D": {"kind": "dir", "mode": 511, "uid": 0, "nlink": 2}}}"#,
        ] {
            assert_eq!(reason(check(json)), refused, "{json}");
        }
        // The euid decides, not uid 0.
        assert_eq!(
            check(
                r#"{"euid": 1000, "lstat": {"D": {"kind": "dir", "mode": 448, "uid": 1000, "nlink": 2}}}"#
            ),
            Ok(())
        );
        assert_eq!(
            reason(check(
                r#"{"lstat": {"D": {"errno": "EACCES", "strerror": "Permission denied"}}}"#
            )),
            format!("directory not checkable: '{DIR}': Permission denied")
        );
    }

    fn policy() -> Policy {
        parse_policy(
            br#"{"path_roots": [{"path": "/home/marina/site/", "owner": "marina:marina"},
                                {"path": "/home/marina", "owner": "marina:www-data"}]}"#,
        )
        .unwrap()
    }

    #[test]
    fn roots_as_python() {
        let policy = policy();
        let identity = env("{}");
        // The first matching root wins, trailing `/` stripped by the policy.
        assert_eq!(
            root_for(&policy, "/home/marina/site/media/a.jpg", &identity)
                .unwrap()
                .map(|root| root.owner.as_str()),
            Some("marina:marina")
        );
        assert_eq!(
            root_for(&policy, "/home/marina/site", &identity)
                .unwrap()
                .map(|root| root.path.as_str()),
            Some("/home/marina/site")
        );
        assert_eq!(
            root_for(&policy, "/home/marina/other", &identity)
                .unwrap()
                .map(|root| root.owner.as_str()),
            Some("marina:www-data")
        );
        // A prefix that is not a path prefix, an unsafe path, outside.
        for path in [
            "/home/marinax",
            "/home/marina/../etc",
            "/etc/passwd",
            "relative",
        ] {
            assert_eq!(root_for(&policy, path, &identity), Ok(None), "{path}");
            assert_eq!(
                require_in_roots(&policy, path, &identity)
                    .unwrap_err()
                    .reason(),
                format!("path outside the allowed roots: '{path}'")
            );
        }
        // The resolved path decides (`test_symlink_escape_is_refused`).
        let escaped = env(r#"{"realpath": {"/home/marina/site/link": "/etc/shadow"}}"#);
        assert_eq!(
            root_for(&policy, "/home/marina/site/link", &escaped),
            Ok(None)
        );
        let inside = env(r#"{"realpath": {"/home/marina/link": "/home/marina/site/x"}}"#);
        assert_eq!(
            require_in_roots(&policy, "/home/marina/link", &inside)
                .unwrap()
                .owner,
            "marina:marina"
        );
    }

    /// A `realpath` error refuses (PLAN.md 4.2).
    #[test]
    fn realpath_errors_refuse() {
        struct Looping;
        impl GuardEnv for Looping {
            fn euid(&self) -> u32 {
                0
            }
            fn uid_of(&self, _: &str) -> Option<u32> {
                None
            }
            fn lstat(&self, _: &str) -> Result<Option<FileStat>, crate::env::OsError> {
                Ok(None)
            }
            fn realpath(&self, _: &str) -> Result<String, crate::env::OsError> {
                Err(crate::pyrealpath::eloop())
            }
        }
        assert_eq!(
            require_in_roots(&policy(), "/home/marina/site/x", &Looping)
                .unwrap_err()
                .reason(),
            "path not checkable: '/home/marina/site/x': Too many levels of symbolic links"
        );
        // An unsafe path is refused before any lookup.
        assert_eq!(root_for(&policy(), "/home/marina/./x", &Looping), Ok(None));
    }
}
