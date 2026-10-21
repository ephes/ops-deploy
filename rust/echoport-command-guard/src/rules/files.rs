//! The file and directory tools of `check()` (`guard.py:457-476,
//! 518-612`): the raw `umask 077 && tar …` and `umask 077 && cat > …`
//! shapes, `rm`, `mktemp`, `cat` of a snapshot, `sha256sum`, `du`, the `sh
//! -c` probe of the private media archive, `readlink`, `test`, `mv`,
//! `mkdir`, `chmod` and `chown`. S3a ported the branches without filesystem
//! lookups, S3b the others.

use std::sync::LazyLock;

use regex_lite::Regex;

use super::paths::{
    lstat_or_none, require_in_roots, require_plain_file_or_absent, require_private_dir,
};
use super::transfer::{PRIVATE_ARCHIVE, owner_user};
use super::{is_temp_dump, require, rpartition, split_in_dir, strings};
use crate::decision::{Decision, Redirect, Refused};
use crate::env::GuardEnv;
use crate::policy::{Policy, is_safe_name, is_safe_path};
use crate::repr::py_repr;
use crate::tokens::{self, constant_regex};

/// `_PRIVATE_TMP_DIR_RE` (`guard.py:41`).
static PRIVATE_TMP_DIR: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^/tmp/echoport-pp-private-media\.[A-Za-z0-9]+$"));
/// `_PRIVATE_MKTEMP` (`guard.py:43`).
const PRIVATE_MKTEMP: [&str; 3] = ["mktemp", "-d", "/tmp/echoport-pp-private-media.XXXXXXXX"];

/// `_CHMOD_MODES` (`guard.py:71`).
const CHMOD_MODES: [&str; 2] = ["0600", "0700"];

/// `umask 077 && tar -C <dir> -czf <archive> -- <name>` (`guard.py:457-469`),
/// `group` being the `tar …` part `_TAR_RE` matched on the raw command: the
/// private media archive, written into root's own fresh `mktemp -d`
/// directory with umask `077`.
///
/// Python calls `shlex.split` on the group without catching its
/// `ValueError`, so an unbalanced quote there crashes the Python guard
/// (exit 1, nothing logged or run). Rust refuses it like an unparsable
/// command (PLAN.md 4.2, the fixtures' `python-error` cases).
pub fn tar(policy: &Policy, group: &str, env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let args = tokens::split(group)
        .map_err(|error| Refused::new(format!("unparsable command: {error}")))?;
    require(
        args.len() == 7 && args[1] == "-C" && args[3] == "-czf" && args[5] == "--",
        "unexpected tar arguments",
    )?;
    let (parent, archive, root_name) = (&args[2], &args[4], &args[6]);
    require(
        is_safe_name(root_name) && is_safe_path(parent),
        "unexpected tar arguments",
    )?;
    require(
        policy
            .private_media_paths
            .contains(&format!("{parent}/{root_name}")),
        "tar source not allowed",
    )?;
    require(
        PRIVATE_ARCHIVE.is_match(archive),
        format!("tar archive path not allowed: {}", py_repr(archive)),
    )?;
    // Only into root's own fresh mktemp dir: nobody else can have put a
    // symlink there for tar to write through.
    require_private_dir(env, rpartition(archive).0)?;
    require_plain_file_or_absent(env, archive, "tar archive", None)?;
    Ok(Decision {
        umask: Some(0o077),
        ..Decision::run(args)
    })
}

/// `umask 077 && cat > <path>` (`guard.py:471-476`), `target` being the
/// part `_CAT_TO_FILE_RE` matched on the raw command: a restore dump sent on
/// stdin into a root-only temp directory. The guard creates the file itself
/// (`redirect.rs`).
pub fn cat_to_file(policy: &Policy, target: &str) -> Result<Decision, Refused> {
    let (directory, name) = split_in_dir(target, |d| policy.private_temp_dir(d))?;
    require(
        name.ends_with(".dump"),
        format!("upload target not allowed: {}", py_repr(name)),
    )?;
    Ok(Decision {
        umask: Some(0o077),
        stdout: Some(Redirect {
            directory: directory.to_owned(),
            name: name.to_owned(),
            owners: Vec::new(),
        }),
        ..Decision::run(strings(&["cat"]))
    })
}

/// `rm` (`guard.py:518-537`).
pub fn rm(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let flag = args.get(1).map(String::as_str);
    if flag == Some("-f") && args.len() == 3 && is_temp_dump(policy, &args[2], &["dump", "restore"])
    {
        return Ok(Decision::run(args.to_vec()));
    }
    if flag == Some("-f") && args.len() == 4 {
        // The `-wal`/`-shm` files of a SQLite database inside a path root
        // (`guard.py:521-527`).
        let (wal, shm) = (&args[2], &args[3]);
        // `wal.endswith("-wal") and shm.endswith("-shm") and wal[:-4] == shm[:-4]`
        let Some(database) = wal
            .strip_suffix("-wal")
            .filter(|database| shm.strip_suffix("-shm") == Some(*database))
        else {
            return Err(Refused::new("unexpected rm arguments"));
        };
        require_in_roots(policy, database, env)?;
        require_in_roots(policy, wal, env)?;
        require_in_roots(policy, shm, env)?;
        return Ok(Decision::run(args.to_vec()));
    }
    if args.len() == 4 && args[1..3] == ["-rf", "--"] {
        let target = &args[3];
        require(
            (!policy.private_media_paths.is_empty() && PRIVATE_TMP_DIR.is_match(target))
                || policy.private_temp_dir(target)
                || policy.snapshot_for_temp_dir(target).is_some(),
            format!("rm -rf target not allowed: {}", py_repr(target)),
        )?;
        return Ok(Decision::run(args.to_vec()));
    }
    Err(Refused::new("unexpected rm arguments"))
}

/// `mktemp -d <template>` (`guard.py:539-546`).
pub fn mktemp(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    if args == PRIVATE_MKTEMP {
        require(
            !policy.private_media_paths.is_empty(),
            "unexpected mktemp arguments",
        )?;
        return Ok(Decision::run(args.to_vec()));
    }
    require(
        args.len() == 3 && args[1] == "-d",
        "unexpected mktemp arguments",
    )?;
    let template = &args[2];
    require(
        policy.temp_dirs.contains(template)
            || policy
                .sqlite_snapshots
                .iter()
                .any(|snapshot| snapshot.temp_dir == *template),
        format!("mktemp template not allowed: {}", py_repr(template)),
    )?;
    Ok(Decision::run(args.to_vec()))
}

/// `cat <snapshot>` (`guard.py:548-555`): read a SQLite snapshot out of its
/// temp dir. The service user owns that directory, so the guard opens the
/// file itself (no symlinks, one link) and hands it over as stdin.
pub fn cat(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    require(args.len() == 2, "unexpected cat arguments")?;
    let (directory, name) = split_in_dir(&args[1], |d| policy.snapshot_for_temp_dir(d).is_some())?;
    // `split_in_dir` accepted `directory` only with a snapshot (Python's
    // `assert`); refuse rather than panic if that ever changes.
    let snapshot = policy
        .snapshot_for_temp_dir(directory)
        .ok_or_else(|| Refused::new(format!("path not allowed: {}", py_repr(&args[1]))))?;
    Ok(Decision {
        stdin: Some(Redirect {
            directory: directory.to_owned(),
            name: name.to_owned(),
            owners: vec![snapshot.user().to_owned()],
        }),
        ..Decision::run(strings(&["cat"]))
    })
}

/// `sha256sum <dump>` (`guard.py:557-564`): only inside a root-only temp
/// dir, where nobody else can place a symlink.
pub fn sha256sum(
    policy: &Policy,
    args: &[String],
    env: &dyn GuardEnv,
) -> Result<Decision, Refused> {
    require(args.len() == 2, "unexpected sha256sum arguments")?;
    let path = &args[1];
    let (directory, name) = split_in_dir(path, |d| policy.private_temp_dir(d))?;
    require(
        name.ends_with(".dump"),
        format!("sha256sum target not allowed: {}", py_repr(path)),
    )?;
    require_private_dir(env, directory)?;
    require_plain_file_or_absent(env, path, "sha256sum target", None)?;
    Ok(Decision::run(args.to_vec()))
}

/// `du -sb -- <private media path>` (`guard.py:566-569`).
pub fn du(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    require(
        args.len() == 4 && args[1..3] == ["-sb", "--"],
        "unexpected du arguments",
    )?;
    require(
        policy.private_media_paths.contains(&args[3]),
        format!("du target not allowed: {}", py_repr(&args[3])),
    )?;
    Ok(Decision::run(args.to_vec()))
}

/// `sh -c '<probe>'` (`guard.py:571-575`): only the probe script
/// python_podcast_production_db_backup.py.j2 sends for a private media path.
pub fn sh(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    require(
        args.len() == 3 && args[1] == "-c",
        "unexpected sh arguments",
    )?;
    let script = &args[2];
    require(
        policy
            .private_media_paths
            .iter()
            .filter_map(|path| private_media_probe_script(path))
            .any(|allowed| allowed == *script),
        "sh script not allowed",
    )?;
    Ok(Decision::run(strings(&["sh", "-c", script])))
}

/// `readlink -f <path>` (`guard.py:577-580`) inside a policy root.
pub fn readlink(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    require(
        args.len() == 3 && args[1] == "-f",
        "unexpected readlink arguments",
    )?;
    require_in_roots(policy, &args[2], env)?;
    Ok(Decision::run(args.to_vec()))
}

/// `test -e|-d|-f <path>` (`guard.py:582-585`) inside a policy root.
pub fn test(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    require(
        args.len() == 3 && matches!(args[1].as_str(), "-e" | "-d" | "-f"),
        "unexpected test arguments",
    )?;
    require_in_roots(policy, &args[2], env)?;
    Ok(Decision::run(args.to_vec()))
}

/// `mv <source> <target>` (`guard.py:587-597`): an uploaded `<path>.tmp`
/// put in place, or a rename within one root onto a name that does not
/// exist yet.
pub fn mv(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    require(args.len() == 3, "unexpected mv arguments")?;
    let (source, target) = (&args[1], &args[2]);
    let source_root = require_in_roots(policy, source, env)?;
    let target_root = require_in_roots(policy, target, env)?;
    if *source != format!("{target}.tmp") {
        // Python compares the `(root, owner)` tuples by value.
        require(source_root == target_root, "mv across roots not allowed")?;
        require(
            lstat_or_none(env, target, "mv target")?.is_none(),
            format!("mv target exists: {}", py_repr(target)),
        )?;
    }
    Ok(Decision::run(args.to_vec()))
}

/// `mkdir -p <path>` (`guard.py:599-603`), as the root's owner, like the
/// uploads that fill the directory.
pub fn mkdir(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    require(
        args.len() == 3 && args[1] == "-p",
        "unexpected mkdir arguments",
    )?;
    let root = require_in_roots(policy, &args[2], env)?;
    let mut argv = strings(&["runuser", "-u", owner_user(&root.owner), "--"]);
    argv.extend_from_slice(args);
    Ok(Decision::run(argv))
}

/// `chmod 0600|0700 <path>` (`guard.py:605-608`) inside a policy root.
pub fn chmod(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    require(
        args.len() == 3 && CHMOD_MODES.contains(&args[1].as_str()),
        "unexpected chmod arguments",
    )?;
    require_in_roots(policy, &args[2], env)?;
    Ok(Decision::run(args.to_vec()))
}

/// `chown [-R] <owner> <path>` (`_check_chown`, `guard.py:435-449,
/// 610-612`): a fresh snapshot temp dir handed to its service user, or a
/// path inside a policy root given to that root's owner.
pub fn chown(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    if args.len() == 3
        && let Some(snapshot) = policy.snapshot_for_temp_dir(&args[2])
    {
        // Hand a fresh snapshot temp dir (root's, from mktemp) to the
        // service user.
        require(
            args[1] == snapshot.owner,
            format!(
                "owner {} not allowed for {}",
                py_repr(&args[1]),
                py_repr(&args[2])
            ),
        )?;
        require_private_dir(env, &args[2])?;
        return Ok(Decision::run(args.to_vec()));
    }
    let (owner, path) = if args.len() == 4 && args[1] == "-R" {
        (&args[2], &args[3])
    } else {
        require(args.len() == 3, "unexpected chown arguments")?;
        (&args[1], &args[2])
    };
    let root = require_in_roots(policy, path, env)?;
    require(
        *owner == root.owner,
        format!("owner {} not allowed for {}", py_repr(owner), py_repr(path)),
    )?;
    Ok(Decision::run(args.to_vec()))
}

/// `private_media_probe_script(path)` (`guard.py:286-294`), or `None` when
/// `shlex.quote(path)` would not return `path` unchanged.
///
/// `shlex.quote` leaves a non-empty string of `[A-Za-z0-9_@%+=:,./-]` as it
/// is. Policy paths are safe paths (`[A-Za-z0-9._/-]`, PLAN.md 3.3.9), so
/// that always holds after the policy validation; instead of
/// re-implementing the quoting for the other case, such a path allows no
/// script (fail closed).
pub fn private_media_probe_script(path: &str) -> Option<String> {
    let unchanged_by_quote = !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    unchanged_by_quote.then(|| {
        format!(
            "if test -L {path}; then echo symlink; \
             elif test -d {path}; then echo present; \
             elif test -e {path}; then echo notdir; \
             else echo missing; fi"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::{argv, decide, decide_in, reason};
    use super::*;
    use crate::env::VirtualEnv;

    const MEDIA: &str = "/home/pp/site/private_media";
    const PRIVATE_DIR: &str = "/tmp/echoport-pp-private-media.Ab12Cd34";
    const ARCHIVE: &str = "/tmp/echoport-pp-private-media.Ab12Cd34/private_media.tar.gz";
    const RESTORE_DIR: &str = "/var/tmp/djangochat-restore.Ab12Cd34";
    const SNAPSHOT_DIR: &str = "/var/tmp/echoport-gotosocial.Ab12Cd";

    /// A fixture env; `D` stands for `dir` in the JSON.
    fn env(json: &str, dir: &str) -> VirtualEnv {
        serde_json::from_str(&json.replace("\"D\"", &format!("\"{dir}\""))).unwrap()
    }

    /// Root's private directory `dir` (`mktemp -d` as root).
    fn private(dir: &str) -> VirtualEnv {
        env(
            r#"{"euid": 0, "lstat": {"D": {"kind": "dir", "mode": 448, "uid": 0, "nlink": 2}}}"#,
            dir,
        )
    }

    fn refused_in(command: &str, env: &VirtualEnv) -> String {
        decide_in(command, env).unwrap_err()
    }

    fn tar_command(parent: &str, archive: &str, name: &str) -> String {
        format!("umask 077 && tar -C {parent} -czf {archive} -- {name}")
    }

    #[test]
    fn tar_runs_with_umask() {
        let command = tar_command("/home/pp/site", ARCHIVE, "private_media");
        let decision = decide_in(&command, &private(PRIVATE_DIR)).unwrap();
        assert_eq!(
            decision,
            Decision {
                umask: Some(0o077),
                ..Decision::run(strings(&[
                    "tar",
                    "-C",
                    "/home/pp/site",
                    "-czf",
                    ARCHIVE,
                    "--",
                    "private_media"
                ]))
            }
        );
        // The argv is the split group: quotes are removed.
        let quoted = tar_command("'/home/pp/site'", ARCHIVE, "private_media");
        assert_eq!(decide_in(&quoted, &private(PRIVATE_DIR)).unwrap(), decision);
        let not_private = format!("not a private directory: '{PRIVATE_DIR}'");
        for (json, expected) in [
            // absent, foreign, open, a symlink to a directory
            (r#"{"lstat": {}}"#, not_private.as_str()),
            (
                r#"{"lstat": {"D": {"kind": "dir", "mode": 448, "uid": 1000, "nlink": 2}}}"#,
                &not_private,
            ),
            (
                r#"{"lstat": {"D": {"kind": "dir", "mode": 493, "uid": 0, "nlink": 2}}}"#,
                &not_private,
            ),
            (
                r#"{"lstat": {"D": {"kind": "lnk", "mode": 511, "uid": 0, "nlink": 1}}}"#,
                &not_private,
            ),
        ] {
            assert_eq!(
                refused_in(&command, &env(json, PRIVATE_DIR)),
                expected,
                "{json}"
            );
        }
        let linked_archive = env(
            &format!(
                r#"{{"lstat": {{"D": {{"kind": "dir", "mode": 448, "uid": 0, "nlink": 2}},
                    "{ARCHIVE}": {{"kind": "lnk", "mode": 511, "uid": 0, "nlink": 1}}}}}}"#
            ),
            PRIVATE_DIR,
        );
        assert_eq!(
            refused_in(&command, &linked_archive),
            format!("tar archive is not a regular file: '{ARCHIVE}'")
        );
        for (command, expected) in [
            (
                tar_command("/home/pp/site", ARCHIVE, "other"),
                "tar source not allowed".to_owned(),
            ),
            (
                tar_command("/home/pp/site/", ARCHIVE, "private_media"),
                "tar source not allowed".to_owned(),
            ),
            (
                tar_command("/home/pp/site", ARCHIVE, "private_media/.."),
                "unexpected tar arguments".to_owned(),
            ),
            (
                tar_command("/home/pp/../pp/site", ARCHIVE, "private_media"),
                "unexpected tar arguments".to_owned(),
            ),
            (
                tar_command("/home/pp/site", "''", "private_media"),
                "tar archive path not allowed: ''".to_owned(),
            ),
            (
                tar_command("/home/pp/site", "/tmp/x.tar.gz", "private_media"),
                "tar archive path not allowed: '/tmp/x.tar.gz'".to_owned(),
            ),
            (
                // An empty token.
                tar_command("/home/pp/site", ARCHIVE, "''"),
                "unexpected tar arguments".to_owned(),
            ),
            (
                "umask 077 && tar -C /home/pp/site -czf /x -- a'b".to_owned(),
                "unparsable command: No closing quotation".to_owned(),
            ),
            (
                // Not the raw shape: tokenised as a command `umask`.
                "umask 077 && tar -C /home/pp/site -xzf /x -- private_media".to_owned(),
                "command not allowed: 'umask'".to_owned(),
            ),
        ] {
            assert_eq!(
                refused_in(&command, &private(PRIVATE_DIR)),
                expected,
                "{command}"
            );
        }
    }

    #[test]
    fn cat_to_file_creates_a_dump_in_a_private_temp_dir() {
        let decision = decide(&format!("umask 077 && cat > {RESTORE_DIR}/db.dump")).unwrap();
        assert_eq!(
            decision,
            Decision {
                umask: Some(0o077),
                stdout: Some(Redirect {
                    directory: RESTORE_DIR.into(),
                    name: "db.dump".into(),
                    owners: vec![],
                }),
                ..Decision::run(strings(&["cat"]))
            }
        );
        for (target, expected) in [
            (
                format!("{RESTORE_DIR}/db.sql"),
                "upload target not allowed: 'db.sql'".to_owned(),
            ),
            (
                format!("{RESTORE_DIR}/sub/db.dump"),
                format!("path not allowed: '{RESTORE_DIR}/sub/db.dump'"),
            ),
            (
                format!("{SNAPSHOT_DIR}/db.dump"),
                format!("path not allowed: '{SNAPSHOT_DIR}/db.dump'"),
            ),
            (
                format!("'{RESTORE_DIR}/db.dump'"),
                format!("unsafe path: \"'{RESTORE_DIR}/db.dump'\""),
            ),
            (
                format!("{RESTORE_DIR}/../db.dump"),
                format!("unsafe path: '{RESTORE_DIR}/../db.dump'"),
            ),
        ] {
            assert_eq!(
                reason(&format!("umask 077 && cat > {target}")),
                expected,
                "{target}"
            );
        }
    }

    #[test]
    fn snapshot_cat_reads_as_stdin_from_the_service_users_dir() {
        assert_eq!(
            decide(&format!("cat {SNAPSHOT_DIR}/sqlite.db")).unwrap(),
            Decision {
                stdin: Some(Redirect {
                    directory: SNAPSHOT_DIR.into(),
                    name: "sqlite.db".into(),
                    owners: vec!["gotosocial".into()],
                }),
                ..Decision::run(strings(&["cat"]))
            }
        );
        for (command, expected) in [
            (
                format!("cat {RESTORE_DIR}/db.dump"),
                format!("path not allowed: '{RESTORE_DIR}/db.dump'"),
            ),
            (
                "cat /etc/shadow".to_owned(),
                "path not allowed: '/etc/shadow'".to_owned(),
            ),
            (
                format!("cat {SNAPSHOT_DIR}/sqlite.db x"),
                "unexpected cat arguments".to_owned(),
            ),
            ("cat".to_owned(), "unexpected cat arguments".to_owned()),
        ] {
            assert_eq!(reason(&command), expected, "{command}");
        }
    }

    #[test]
    fn sha256sum_only_in_a_private_temp_dir() {
        let command = format!("sha256sum {RESTORE_DIR}/db.dump");
        assert_eq!(
            decide_in(&command, &private(RESTORE_DIR)).unwrap().argv,
            ["sha256sum", &format!("{RESTORE_DIR}/db.dump")]
        );
        assert_eq!(
            reason(&command),
            format!("not a private directory: '{RESTORE_DIR}'")
        );
        assert_eq!(
            refused_in(
                &format!("sha256sum {RESTORE_DIR}/db.sql"),
                &private(RESTORE_DIR)
            ),
            format!("sha256sum target not allowed: '{RESTORE_DIR}/db.sql'")
        );
        let fifo = env(
            &format!(
                r#"{{"lstat": {{"D": {{"kind": "dir", "mode": 448, "uid": 0, "nlink": 2}},
                    "{RESTORE_DIR}/db.dump": {{"kind": "fifo", "mode": 384, "uid": 0, "nlink": 1}}}}}}"#
            ),
            RESTORE_DIR,
        );
        assert_eq!(
            refused_in(&command, &fifo),
            format!("sha256sum target is not a regular file: '{RESTORE_DIR}/db.dump'")
        );
        assert_eq!(reason("sha256sum -c x"), "unexpected sha256sum arguments");
        assert_eq!(
            reason("sha256sum /tmp/x.dump"),
            "path not allowed: '/tmp/x.dump'"
        );
    }

    #[test]
    fn rm_of_sqlite_side_files_inside_a_root() {
        let command = "rm -f /var/lib/gotosocial/sqlite.db-wal /var/lib/gotosocial/sqlite.db-shm";
        assert_eq!(argv(command).join(" "), command);
        for (command, expected) in [
            (
                "rm -f /var/lib/gotosocial/a-wal /var/lib/gotosocial/b-shm",
                "unexpected rm arguments".to_owned(),
            ),
            (
                "rm -f /var/lib/gotosocial/a-shm /var/lib/gotosocial/a-wal",
                "unexpected rm arguments".to_owned(),
            ),
            (
                "rm -f -wal -shm",
                "path outside the allowed roots: ''".to_owned(),
            ),
            (
                "rm -f /etc/x-wal /etc/x-shm",
                "path outside the allowed roots: '/etc/x'".to_owned(),
            ),
        ] {
            assert_eq!(reason(command), expected, "{command}");
        }
        // Each of the three paths is resolved: a linked side file escapes.
        let escaped = serde_json::from_str::<VirtualEnv>(
            r#"{"realpath": {"/var/lib/gotosocial/sqlite.db-shm": "/etc/shadow"}}"#,
        )
        .unwrap();
        assert_eq!(
            refused_in(command, &escaped),
            "path outside the allowed roots: '/var/lib/gotosocial/sqlite.db-shm'"
        );
    }

    #[test]
    fn readlink_test_and_chmod_inside_a_root() {
        for command in [
            "readlink -f /home/marina/site/media",
            "test -e /home/marina/site",
            "test -d /var/lib/gotosocial/storage",
            "test -f /home/marina/x",
            "chmod 0600 /home/marina/site/db.sqlite3",
            "chmod 0700 /var/lib/gotosocial/storage",
        ] {
            assert_eq!(argv(command).join(" "), command);
        }
        for (command, expected) in [
            (
                "readlink /home/marina/site",
                "unexpected readlink arguments",
            ),
            ("readlink -f /etc", "path outside the allowed roots: '/etc'"),
            ("test -L /home/marina/site", "unexpected test arguments"),
            ("test -e /home/marina/site x", "unexpected test arguments"),
            (
                "test -e /home/marinax",
                "path outside the allowed roots: '/home/marinax'",
            ),
            ("chmod 0755 /home/marina/site", "unexpected chmod arguments"),
            ("chmod 600 /home/marina/site", "unexpected chmod arguments"),
            (
                "chmod 0600 /etc/shadow",
                "path outside the allowed roots: '/etc/shadow'",
            ),
        ] {
            assert_eq!(reason(command), expected, "{command}");
        }
    }

    #[test]
    fn mv_only_onto_new_names_within_one_root() {
        // Putting an upload in place may replace the target, across roots.
        for command in [
            "mv /home/marina/site/db.sqlite3.tmp /home/marina/site/db.sqlite3",
            "mv /home/marina/x.tmp /home/marina/x",
        ] {
            let existing = serde_json::from_str::<VirtualEnv>(
                r#"{"lstat": {"/home/marina/site/db.sqlite3": {"kind": "reg", "mode": 384, "uid": 1000, "nlink": 1},
                              "/home/marina/x": {"kind": "reg", "mode": 384, "uid": 1000, "nlink": 1}}}"#,
            )
            .unwrap();
            assert_eq!(
                decide_in(command, &existing).unwrap().argv.join(" "),
                command
            );
        }
        assert!(decide("mv /home/marina/site.tmp /home/marina/site").is_ok());
        assert!(decide("mv /home/marina/site/a /home/marina/site/b").is_ok());
        let exists = serde_json::from_str::<VirtualEnv>(
            r#"{"lstat": {"/home/marina/site/b": {"kind": "dir", "mode": 493, "uid": 1000, "nlink": 2}}}"#,
        )
        .unwrap();
        assert_eq!(
            refused_in("mv /home/marina/site/a /home/marina/site/b", &exists),
            "mv target exists: '/home/marina/site/b'"
        );
        let unreadable = serde_json::from_str::<VirtualEnv>(
            r#"{"lstat": {"/home/marina/site/b": {"errno": "EACCES", "strerror": "Permission denied"}}}"#,
        )
        .unwrap();
        assert_eq!(
            refused_in("mv /home/marina/site/a /home/marina/site/b", &unreadable),
            "mv target not checkable: '/home/marina/site/b': Permission denied"
        );
        for (command, expected) in [
            (
                "mv /home/marina/site/a /home/marina/b",
                "mv across roots not allowed",
            ),
            (
                "mv /home/marina/site/a.tmp /var/lib/gotosocial/a",
                "mv across roots not allowed",
            ),
            (
                "mv /etc/a /home/marina/a",
                "path outside the allowed roots: '/etc/a'",
            ),
            (
                "mv /home/marina/a /etc/a",
                "path outside the allowed roots: '/etc/a'",
            ),
            ("mv /home/marina/a", "unexpected mv arguments"),
        ] {
            assert_eq!(reason(command), expected, "{command}");
        }
    }

    #[test]
    fn mkdir_runs_as_the_roots_owner() {
        assert_eq!(
            argv("mkdir -p /home/marina/site/media").join(" "),
            "runuser -u marina -- mkdir -p /home/marina/site/media"
        );
        assert_eq!(
            argv("mkdir -p /var/lib/gotosocial/storage").join(" "),
            "runuser -u gotosocial -- mkdir -p /var/lib/gotosocial/storage"
        );
        assert_eq!(reason("mkdir /home/marina/x"), "unexpected mkdir arguments");
        assert_eq!(
            reason("mkdir -p /root/x"),
            "path outside the allowed roots: '/root/x'"
        );
    }

    #[test]
    fn chown_shapes() {
        // A fresh snapshot temp dir, handed to the service user.
        let command = format!("chown gotosocial:gotosocial {SNAPSHOT_DIR}");
        assert_eq!(
            decide_in(&command, &private(SNAPSHOT_DIR))
                .unwrap()
                .argv
                .join(" "),
            command
        );
        assert_eq!(
            reason(&command),
            format!("not a private directory: '{SNAPSHOT_DIR}'")
        );
        assert_eq!(
            reason(&format!("chown marina:marina {SNAPSHOT_DIR}")),
            format!("owner 'marina:marina' not allowed for '{SNAPSHOT_DIR}'")
        );
        // Inside a root, its owner, also recursively.
        for command in [
            "chown marina:marina /home/marina/site/db.sqlite3",
            "chown -R marina:www-data /home/marina/media",
        ] {
            assert_eq!(argv(command).join(" "), command);
        }
        for (command, expected) in [
            (
                "chown marina:www-data /home/marina/site/x".to_owned(),
                "owner 'marina:www-data' not allowed for '/home/marina/site/x'".to_owned(),
            ),
            (
                "chown root:root /home/marina/x".to_owned(),
                "owner 'root:root' not allowed for '/home/marina/x'".to_owned(),
            ),
            (
                "chown -h marina:marina /home/marina/site".to_owned(),
                "unexpected chown arguments".to_owned(),
            ),
            (
                "chown -R gotosocial:gotosocial ".to_owned() + SNAPSHOT_DIR,
                format!("path outside the allowed roots: '{SNAPSHOT_DIR}'"),
            ),
            ("chown".to_owned(), "unexpected chown arguments".to_owned()),
            (
                "chown marina:marina /etc".to_owned(),
                "path outside the allowed roots: '/etc'".to_owned(),
            ),
        ] {
            assert_eq!(reason(&command), expected, "{command}");
        }
    }

    #[test]
    fn patterns_compile() {
        LazyLock::force(&PRIVATE_TMP_DIR);
    }

    #[test]
    fn rm_shapes() {
        for command in [
            "rm -f /tmp/echoport_hp_dump_1.dump",
            "rm -f /tmp/echoport_pp_x_restore_2026-10-15T02-00-00.dump",
            "rm -rf -- /tmp/echoport-pp-private-media.Ab12Cd34",
            "rm -rf -- /var/tmp/djangochat-restore.Ab12Cd34",
            "rm -rf -- /var/tmp/echoport-gotosocial.Ab12Cd",
        ] {
            assert_eq!(argv(command).join(" "), command);
        }
        for (command, expected) in [
            (
                "rm -f /tmp/echoport_xx_dump_1.dump",
                "unexpected rm arguments",
            ),
            ("rm /tmp/echoport_hp_dump_1.dump", "unexpected rm arguments"),
            (
                "rm -rf /tmp/echoport_hp_dump_1.dump",
                "unexpected rm arguments",
            ),
            ("rm", "unexpected rm arguments"),
            ("rm -f", "unexpected rm arguments"),
            (
                "rm -rf -- /var/tmp/djangochat-restore.Ab12Cd3",
                "rm -rf target not allowed: '/var/tmp/djangochat-restore.Ab12Cd3'",
            ),
            (
                "rm -rf -- /tmp/echoport-pp-private-media.Ab12Cd34/x",
                "rm -rf target not allowed: '/tmp/echoport-pp-private-media.Ab12Cd34/x'",
            ),
            ("rm -rf -- /", "rm -rf target not allowed: '/'"),
            ("rm -rf -- /var/tmp/a /var/tmp/b", "unexpected rm arguments"),
        ] {
            assert_eq!(reason(command), expected, "{command}");
        }
        // Without private media paths the private media temp dir is not
        // allowed.
        let policy = Policy::default();
        let args = strings(&["rm", "-rf", "--", "/tmp/echoport-pp-private-media.Ab12Cd34"]);
        assert_eq!(
            rm(&policy, &args, &VirtualEnv::default())
                .unwrap_err()
                .reason(),
            "rm -rf target not allowed: '/tmp/echoport-pp-private-media.Ab12Cd34'"
        );
    }

    #[test]
    fn mktemp_shapes() {
        for command in [
            "mktemp -d /tmp/echoport-pp-private-media.XXXXXXXX",
            "mktemp -d /var/tmp/djangochat-restore.XXXXXXXX",
            "mktemp -d /var/tmp/echoport-gotosocial.XXXXXX",
        ] {
            assert_eq!(argv(command).join(" "), command);
        }
        for (command, expected) in [
            (
                "mktemp -d /var/tmp/x.XXXXXX",
                "mktemp template not allowed: '/var/tmp/x.XXXXXX'",
            ),
            (
                "mktemp /var/tmp/djangochat-restore.XXXXXXXX",
                "unexpected mktemp arguments",
            ),
            ("mktemp -d", "unexpected mktemp arguments"),
            (
                "mktemp -p /tmp -d /var/tmp/djangochat-restore.XXXXXXXX",
                "unexpected mktemp arguments",
            ),
        ] {
            assert_eq!(reason(command), expected, "{command}");
        }
        let args = strings(&PRIVATE_MKTEMP);
        assert_eq!(
            mktemp(&Policy::default(), &args).unwrap_err().reason(),
            "unexpected mktemp arguments"
        );
    }

    #[test]
    fn du_shapes() {
        assert!(decide(&format!("du -sb -- {MEDIA}")).is_ok());
        assert_eq!(
            reason(&format!("du -sb -- {MEDIA}/")),
            format!("du target not allowed: '{MEDIA}/'")
        );
        assert_eq!(
            reason(&format!("du -sb {MEDIA}")),
            "unexpected du arguments"
        );
        assert_eq!(
            reason(&format!("du -s -- {MEDIA}")),
            "unexpected du arguments"
        );
    }

    #[test]
    fn sh_probe() {
        let script = private_media_probe_script(MEDIA).unwrap();
        assert_eq!(
            script,
            "if test -L /home/pp/site/private_media; then echo symlink; \
             elif test -d /home/pp/site/private_media; then echo present; \
             elif test -e /home/pp/site/private_media; then echo notdir; \
             else echo missing; fi"
        );
        let command = format!("sh -c '{script}'");
        assert_eq!(argv(&command), ["sh", "-c", script.as_str()]);
        // The script may be quoted any way that splits to the same token.
        assert!(decide(&format!("sh -c \"{script}\"")).is_ok());
        let other = private_media_probe_script("/home/other/private_media").unwrap();
        assert_eq!(reason(&format!("sh -c '{other}'")), "sh script not allowed");
        assert_eq!(reason("sh -c id"), "sh script not allowed");
        assert_eq!(
            reason(&format!("sh -e '{script}'")),
            "unexpected sh arguments"
        );
        assert_eq!(
            reason(&format!("sh -c '{script}' x")),
            "unexpected sh arguments"
        );
        // Paths shlex.quote would change allow no script.
        for path in ["", "/a b", "/a'b", "/a$b", "/a;b"] {
            assert_eq!(private_media_probe_script(path), None, "{path:?}");
        }
    }
}
