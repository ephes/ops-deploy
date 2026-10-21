//! The file and directory tools of `check()` (`guard.py:518-575`). Ported
//! (S3a): `rm -f` of temp dumps, `rm -rf --` of temp dirs, `mktemp`, `du`
//! and the `sh -c` probe of the private media archive. The `-wal`/`-shm`
//! branch of `rm` resolves paths and is still a stub (S3b).

use std::sync::LazyLock;

use regex_lite::Regex;

use super::{is_temp_dump, require, strings};
use crate::decision::{Decision, Refused};
use crate::policy::Policy;
use crate::repr::py_repr;
use crate::tokens::constant_regex;

/// `_PRIVATE_TMP_DIR_RE` (`guard.py:41`).
static PRIVATE_TMP_DIR: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^/tmp/echoport-pp-private-media\.[A-Za-z0-9]+$"));
/// `_PRIVATE_MKTEMP` (`guard.py:43`).
const PRIVATE_MKTEMP: [&str; 3] = ["mktemp", "-d", "/tmp/echoport-pp-private-media.XXXXXXXX"];

/// `rm` (`guard.py:518-537`).
pub fn rm(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    let flag = args.get(1).map(String::as_str);
    if flag == Some("-f") && args.len() == 3 && is_temp_dump(policy, &args[2], &["dump", "restore"])
    {
        return Ok(Decision::run(args.to_vec()));
    }
    if flag == Some("-f") && args.len() == 4 {
        // The `-wal`/`-shm` files of a SQLite database inside a path root
        // (`guard.py:521-527`), S3b.
        return Err(Refused::not_ported("command not allowed: 'rm'"));
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
    use super::super::tests::{argv, decide, reason};
    use super::*;

    const MEDIA: &str = "/home/pp/site/private_media";

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
            rm(&policy, &args).unwrap_err().reason(),
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
