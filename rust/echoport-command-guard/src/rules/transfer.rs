//! The transfer tools of `check()`: `scp -f/-t` (`_check_scp`,
//! `guard.py:393-420`) and the rsync server (`_check_rsync`,
//! `guard.py:423-432`), with the run-as wrapper of `check()`
//! (`guard.py:510-516`). Uploads run as the owner of their target, so the
//! sender cannot create root-owned, setuid or device files.

use std::sync::LazyLock;

use regex_lite::Regex;

use super::paths::{require_in_roots, require_plain_file_or_absent, require_private_dir, resolve};
use super::{is_temp_dump, require, rpartition, strings};
use crate::decision::{Decision, Refused};
use crate::env::GuardEnv;
use crate::policy::{Policy, is_safe_path};
use crate::repr::py_repr;
use crate::tokens::constant_regex;

/// `_PRIVATE_ARCHIVE_RE` (`guard.py:42`).
pub(crate) static PRIVATE_ARCHIVE: LazyLock<Regex> = LazyLock::new(|| {
    constant_regex(r"^/tmp/echoport-pp-private-media\.[A-Za-z0-9]+/private_media\.tar\.gz$")
});

/// `_UPLOAD_SUFFIXES` (`guard.py:72`).
const UPLOAD_SUFFIXES: [&str; 2] = [".tmp", ".restore-tmp"];

/// `RSYNC_SERVER_ARGS` (`guard.py:54-61`), verbatim: the rsync server
/// arguments between `rsync` and `. <dir>/` for exactly the client options
/// the runners use.
const RSYNC_SERVER_ARGS: [&[&str]; 3] = [
    // rsync -a --safe-links <host>:<dir>/ <local>/      (download)
    &[
        "--server",
        "--sender",
        "-logDtpre.iLsfxCIvu",
        "--safe-links",
    ],
    // rsync -a --no-D <local>/ <host>:<dir>/             (upload, keeps extra files)
    &["--server", "-logtpre.iLsfxCIvu"],
    // rsync -a --no-D --delete <local>/ <host>:<dir>/    (upload, mirror)
    &["--server", "-logtpre.iLsfxCIvu", "--delete"],
];

/// `scp …` (`guard.py:510-512`): a download runs as root, an upload as the
/// user `_check_scp` returns.
pub fn scp(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let user = check_scp(policy, args, env)?;
    Ok(Decision::run(run_as(user, args)))
}

/// `rsync …` (`guard.py:514-516`): the sender runs as root, a receiver as
/// the owner of its root.
pub fn rsync(policy: &Policy, args: &[String], env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let user = check_rsync(policy, args, env)?;
    Ok(Decision::run(run_as(user, args)))
}

/// `args`, or `["runuser", "-u", user, "--", *args]`.
fn run_as(user: Option<&str>, args: &[String]) -> Vec<String> {
    match user {
        None => args.to_vec(),
        Some(user) => {
            let mut argv = strings(&["runuser", "-u", user, "--"]);
            argv.extend_from_slice(args);
            argv
        }
    }
}

/// The user part of an `owner` (`owner.split(":", 1)[0]`).
pub(crate) fn owner_user(owner: &str) -> &str {
    owner.split_once(':').map_or(owner, |(user, _)| user)
}

/// `_check_scp` (`guard.py:393-420`): the user an upload runs as, `None` for
/// a download (as root).
fn check_scp<'p>(
    policy: &'p Policy,
    args: &[String],
    env: &dyn GuardEnv,
) -> Result<Option<&'p str>, Refused> {
    require(
        args.len() == 3 && matches!(args[1].as_str(), "-f" | "-t"),
        "unexpected scp arguments",
    )?;
    let (mode, path) = (args[1].as_str(), args[2].as_str());
    require(
        is_safe_path(path),
        format!("unsafe scp path: {}", py_repr(path)),
    )?;
    if mode == "-f" {
        if is_temp_dump(policy, path, &["dump"]) {
            // Written by pg_dump as postgres.
            require_plain_file_or_absent(env, path, "scp source", Some("postgres"))?;
            return Ok(None);
        }
        if !policy.private_media_paths.is_empty() && PRIVATE_ARCHIVE.is_match(path) {
            require_private_dir(env, rpartition(path).0)?;
            require_plain_file_or_absent(env, path, "scp source", None)?;
            return Ok(None);
        }
        if !policy.read_files.contains(path) {
            require_in_roots(policy, path, env)?;
        }
        // Python calls `realpath(path)` again here.
        let resolved = resolve(env, path)?;
        require_plain_file_or_absent(env, &resolved, "scp source", None)?;
        return Ok(None);
    }
    // Upload: onto a new path or an existing plain file, never through a
    // symlink, and as the target's owner (the scp sink takes the file mode
    // from the sender).
    if is_temp_dump(policy, path, &["restore"]) {
        // Read by pg_restore as postgres.
        require_plain_file_or_absent(env, path, "scp target", Some("postgres"))?;
        return Ok(Some("postgres"));
    }
    require(
        UPLOAD_SUFFIXES.iter().any(|suffix| path.ends_with(suffix)),
        format!("scp upload target not allowed: {}", py_repr(path)),
    )?;
    let root = require_in_roots(policy, path, env)?;
    require_plain_file_or_absent(env, path, "scp target", None)?;
    Ok(Some(owner_user(&root.owner)))
}

/// `_check_rsync` (`guard.py:423-432`): the user a receiver runs as, `None`
/// for the sender (as root).
fn check_rsync<'p>(
    policy: &'p Policy,
    args: &[String],
    env: &dyn GuardEnv,
) -> Result<Option<&'p str>, Refused> {
    require(
        args.len() >= 5 && args[args.len() - 2] == ".",
        "unexpected rsync arguments",
    )?;
    let options = &args[1..args.len() - 2];
    require(
        RSYNC_SERVER_ARGS.iter().any(|allowed| options == *allowed),
        "unexpected rsync options",
    )?;
    let path = &args[args.len() - 1];
    require(
        path.ends_with('/'),
        "rsync path must be a directory with a trailing slash",
    )?;
    let root = require_in_roots(policy, path.trim_end_matches('/'), env)?;
    // The receiver runs as the root's owner: -o/-g are ignored, setuid bits
    // and devices cannot be created as root.
    Ok(if args[2] == "--sender" {
        None
    } else {
        Some(owner_user(&root.owner))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::VirtualEnv;
    use crate::policy::parse_policy;

    const DUMP: &str = "/tmp/echoport_hp_dump_2026-10-15T02-00-00.dump";
    const RESTORE: &str = "/tmp/echoport_hp_restore_2026-10-15T02-00-00.dump";
    const ARCHIVE: &str = "/tmp/echoport-pp-private-media.Ab12Cd34/private_media.tar.gz";

    fn policy() -> Policy {
        parse_policy(
            br#"{
              "postgres": {"temp_file_prefixes": ["hp"]},
              "private_media_paths": ["/home/pp/site/private_media"],
              "path_roots": [
                {"path": "/home/marina/site", "owner": "marina:marina"},
                {"path": "/home/marina", "owner": "marina:www-data"},
                {"path": "/var/lib/gotosocial", "owner": "gotosocial:gotosocial"}
              ],
              "read_files": ["/etc/gotosocial/config.yaml"]
            }"#,
        )
        .unwrap()
    }

    fn env(json: &str) -> VirtualEnv {
        serde_json::from_str(json).unwrap()
    }

    fn decide(command: &str, env: &VirtualEnv) -> Result<Vec<String>, String> {
        let args = crate::tokens::split(command).unwrap();
        let outcome = match args[0].as_str() {
            "scp" => scp(&policy(), &args, env),
            _ => rsync(&policy(), &args, env),
        };
        outcome
            .map(|decision| {
                assert_eq!(decision, Decision::run(decision.argv.clone()));
                decision.argv
            })
            .map_err(|refused| refused.reason().to_owned())
    }

    fn argv(command: &str) -> String {
        decide(command, &VirtualEnv::default()).unwrap().join(" ")
    }

    fn reason(command: &str) -> String {
        decide(command, &VirtualEnv::default()).unwrap_err()
    }

    #[test]
    fn patterns_compile() {
        LazyLock::force(&PRIVATE_ARCHIVE);
    }

    #[test]
    fn scp_downloads_run_as_root() {
        for command in [
            format!("scp -f {DUMP}"),
            format!("scp -f {ARCHIVE}"),
            "scp -f /home/marina/site/db.sqlite3".to_owned(),
            "scp -f /etc/gotosocial/config.yaml".to_owned(),
        ] {
            let private = env(r#"{"lstat": {"/tmp/echoport-pp-private-media.Ab12Cd34":
                    {"kind": "dir", "mode": 448, "uid": 0, "nlink": 2}}}"#);
            assert_eq!(decide(&command, &private).unwrap().join(" "), command);
        }
        // The private media archive needs root's private mktemp dir.
        assert_eq!(
            reason(&format!("scp -f {ARCHIVE}")),
            "not a private directory: '/tmp/echoport-pp-private-media.Ab12Cd34'"
        );
        // Without private media paths it is just a path outside the roots.
        let args = strings(&["scp", "-f", ARCHIVE]);
        assert_eq!(
            scp(&Policy::default(), &args, &VirtualEnv::default())
                .unwrap_err()
                .reason(),
            format!("path outside the allowed roots: '{ARCHIVE}'")
        );
        // A dump must belong to postgres when it exists.
        let foreign = env(&format!(
            r#"{{"users": {{"postgres": 110}},
                "lstat": {{"{DUMP}": {{"kind": "reg", "mode": 384, "uid": 0, "nlink": 1}}}}}}"#
        ));
        assert_eq!(
            decide(&format!("scp -f {DUMP}"), &foreign).unwrap_err(),
            format!("scp source does not belong to postgres: '{DUMP}'")
        );
    }

    #[test]
    fn scp_download_checks_the_resolved_path() {
        // A link inside a root to a file inside the root: the target is
        // checked, not the link.
        let linked = env(
            r#"{"realpath": {"/home/marina/site/db": "/home/marina/site/real.db"},
                "lstat": {"/home/marina/site/db": {"kind": "lnk", "mode": 511, "uid": 0, "nlink": 1},
                          "/home/marina/site/real.db": {"kind": "reg", "mode": 384, "uid": 0, "nlink": 2}}}"#,
        );
        assert_eq!(
            decide("scp -f /home/marina/site/db", &linked).unwrap_err(),
            "scp source has other hard links: '/home/marina/site/real.db'"
        );
        // A read file may resolve anywhere, but must be a plain file.
        let read = env(
            r#"{"realpath": {"/etc/gotosocial/config.yaml": "/etc/shadow"},
                "lstat": {"/etc/shadow": {"kind": "fifo", "mode": 384, "uid": 0, "nlink": 1}}}"#,
        );
        assert_eq!(
            decide("scp -f /etc/gotosocial/config.yaml", &read).unwrap_err(),
            "scp source is not a regular file: '/etc/shadow'"
        );
        assert_eq!(
            reason("scp -f /etc/passwd"),
            "path outside the allowed roots: '/etc/passwd'"
        );
    }

    #[test]
    fn scp_uploads_run_as_the_target_owner() {
        assert_eq!(
            argv("scp -t /home/marina/site/db.sqlite3.tmp"),
            "runuser -u marina -- scp -t /home/marina/site/db.sqlite3.tmp"
        );
        assert_eq!(
            argv("scp -t /home/marina/media.restore-tmp"),
            "runuser -u marina -- scp -t /home/marina/media.restore-tmp"
        );
        assert_eq!(
            argv(&format!("scp -t {RESTORE}")),
            format!("runuser -u postgres -- scp -t {RESTORE}")
        );
        for (command, expected) in [
            (
                "scp -t /home/marina/site/db.sqlite3".to_owned(),
                "scp upload target not allowed: '/home/marina/site/db.sqlite3'",
            ),
            (
                format!("scp -t {DUMP}"),
                "scp upload target not allowed: '/tmp/echoport_hp_dump_2026-10-15T02-00-00.dump'",
            ),
            (
                "scp -t /etc/cron.d/x.tmp".to_owned(),
                "path outside the allowed roots: '/etc/cron.d/x.tmp'",
            ),
            (
                "scp -t /home/marina/../x.tmp".to_owned(),
                "unsafe scp path: '/home/marina/../x.tmp'",
            ),
            (
                "scp -r -t /home/marina/x.tmp".to_owned(),
                "unexpected scp arguments",
            ),
            (
                "scp -p /home/marina/x.tmp".to_owned(),
                "unexpected scp arguments",
            ),
            ("scp".to_owned(), "unexpected scp arguments"),
        ] {
            assert_eq!(reason(&command), expected, "{command}");
        }
        // Never through a symlink or onto a linked file.
        let link = env(
            r#"{"lstat": {"/home/marina/x.tmp": {"kind": "lnk", "mode": 511, "uid": 1000, "nlink": 1}}}"#,
        );
        assert_eq!(
            decide("scp -t /home/marina/x.tmp", &link).unwrap_err(),
            "scp target is not a regular file: '/home/marina/x.tmp'"
        );
    }

    #[test]
    fn exact_rsync_commands() {
        assert_eq!(
            argv(
                "rsync --server --sender -logDtpre.iLsfxCIvu --safe-links . /home/marina/site/media/"
            ),
            "rsync --server --sender -logDtpre.iLsfxCIvu --safe-links . /home/marina/site/media/"
        );
        assert_eq!(
            argv("rsync --server -logtpre.iLsfxCIvu . /home/marina/site/media/"),
            "runuser -u marina -- rsync --server -logtpre.iLsfxCIvu . /home/marina/site/media/"
        );
        assert_eq!(
            argv("rsync --server -logtpre.iLsfxCIvu --delete . /var/lib/gotosocial/storage/"),
            "runuser -u gotosocial -- rsync --server -logtpre.iLsfxCIvu --delete . /var/lib/gotosocial/storage/"
        );
        // The root itself, with any number of trailing slashes.
        assert!(
            decide(
                "rsync --server -logtpre.iLsfxCIvu . /home/marina//",
                &VirtualEnv::default()
            )
            .is_ok()
        );
        for (command, expected) in [
            (
                "rsync --server --sender -logDtpre.iLsfxCIvu . /home/marina/",
                "unexpected rsync options",
            ),
            (
                "rsync --server -logtpre.iLsfxCIvu --delete --remove-source-files . /home/marina/",
                "unexpected rsync options",
            ),
            (
                "rsync --server -logDtpre.iLsfxCIvu . /home/marina/",
                "unexpected rsync options",
            ),
            (
                "rsync --server -logtpre.iLsfxCIvu /home/marina/ .",
                "unexpected rsync arguments",
            ),
            ("rsync . /home/marina/", "unexpected rsync arguments"),
            (
                "rsync --server -logtpre.iLsfxCIvu . /home/marina",
                "rsync path must be a directory with a trailing slash",
            ),
            (
                "rsync --server -logtpre.iLsfxCIvu . /etc/",
                "path outside the allowed roots: '/etc'",
            ),
            (
                "rsync --server -logtpre.iLsfxCIvu . /",
                "path outside the allowed roots: ''",
            ),
        ] {
            assert_eq!(reason(command), expected, "{command}");
        }
    }

    #[test]
    fn owner_user_is_the_part_before_the_colon() {
        assert_eq!(owner_user("marina:www-data"), "marina");
        assert_eq!(owner_user("marina"), "marina");
        assert_eq!(owner_user("a:b:c"), "a");
    }
}
