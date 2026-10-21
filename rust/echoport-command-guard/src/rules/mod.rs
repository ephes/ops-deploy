//! `check()` (PLAN.md 3.4; `guard.py:452-619`): what to execute for an
//! allowed command, or why it is refused.
//!
//! Ported: the pre-checks and the prefilter, the tokeniser, the trailing
//! `< file` of `runuser`, the tool dispatcher (S1), and the branches that
//! need no filesystem (S3a): `sudo` and `runuser` (PostgreSQL and SQLite,
//! [`postgres`], [`sqlite`]), `systemctl`, `curl`, and in [`files`] `rm -f`
//! of temp dumps, `rm -rf --` of temp dirs, `mktemp`, `du` and the `sh -c`
//! probe. The branches that look at the filesystem (the two raw shapes,
//! `scp`, `rsync`, `rm` of `-wal`/`-shm` files, `cat`, `sha256sum`,
//! `readlink`, `test`, `mv`, `mkdir`, `chmod`, `chown`) are still stubs that
//! refuse ([`Refused::not_ported`]); S3b ports them. Every branch keeps the
//! order of `guard.py`'s checks, so that the refusal reasons match (PLAN.md
//! 4.4).

pub mod files;
pub mod postgres;
pub mod sqlite;

use crate::decision::{Decision, Refused};
use crate::env::GuardEnv;
use crate::policy::{Policy, is_safe_name, is_safe_path};
use crate::prefilter;
use crate::repr::py_repr;
use crate::tokens;

/// The tools `check()` has a branch for (`guard.py:489-617`).
pub const TOOLS: [&str; 18] = [
    "sudo",
    "runuser",
    "systemctl",
    "scp",
    "rsync",
    "rm",
    "mktemp",
    "cat",
    "sha256sum",
    "du",
    "sh",
    "readlink",
    "test",
    "mv",
    "mkdir",
    "chmod",
    "chown",
    "curl",
];

/// `check(command, policy, realpath, lstat)` for the bytes of
/// `SSH_ORIGINAL_COMMAND`.
pub fn check(command: &[u8], policy: &Policy, env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let command = prefilter::command_text(command)?;

    if tokens::tar_shape(command).is_some() {
        // `guard.py:457-469`, S3b.
        return Err(Refused::not_ported("command not allowed: 'tar'"));
    }
    if tokens::cat_to_file_shape(command).is_some() {
        // `guard.py:471-476`, S3b.
        return Err(Refused::not_ported("command not allowed: 'cat'"));
    }

    let mut args = tokens::split(command)
        .map_err(|error| Refused::new(format!("unparsable command: {error}")))?;
    if args.is_empty() {
        return Err(Refused::new("empty command"));
    }
    let mut stdin_path = None;
    if args.len() >= 3 && args[args.len() - 2] == "<" {
        stdin_path = args.pop();
        args.pop();
    }
    let Some(tool) = args.first() else {
        return Err(Refused::new("empty command"));
    };
    if stdin_path.is_some() && tool != "runuser" {
        return Err(Refused::new("input redirection not allowed here"));
    }
    dispatch(tool, &args, stdin_path.as_deref(), policy, env)
}

/// The branches of `check()` by tool (`guard.py:489-619`). Each branch
/// returns or refuses, so matching on the tool is Python's `if` chain.
fn dispatch(
    tool: &str,
    args: &[String],
    stdin_path: Option<&str>,
    policy: &Policy,
    _env: &dyn GuardEnv,
) -> Result<Decision, Refused> {
    match tool {
        "sudo" => sudo(policy, args),
        "runuser" => runuser(policy, args, stdin_path),
        "systemctl" => systemctl(policy, args),
        "rm" => files::rm(policy, args),
        "mktemp" => files::mktemp(policy, args),
        "du" => files::du(policy, args),
        "sh" => files::sh(policy, args),
        "curl" => curl(policy, args),
        // S3b.
        "scp" | "rsync" | "cat" | "sha256sum" | "readlink" | "test" | "mv" | "mkdir" | "chmod"
        | "chown" => Err(Refused::not_ported(format!(
            "command not allowed: {}",
            py_repr(tool)
        ))),
        _ => Err(Refused::new(format!(
            "command not allowed: {}",
            py_repr(tool)
        ))),
    }
}

/// `sudo -u postgres <tool> …` (`guard.py:489-492`), run as `sudo -n -u
/// postgres -- <tool> …`.
fn sudo(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    require(
        args.len() >= 4 && args[1..3] == ["-u", "postgres"],
        "only sudo -u postgres is allowed",
    )?;
    postgres::check(policy, &args[3..], None)?;
    let mut argv = strings(&["sudo", "-n", "-u", "postgres", "--"]);
    argv.extend_from_slice(&args[3..]);
    Ok(Decision::run(argv))
}

/// `runuser -u <user> -- <tool> …` (`guard.py:494-500`): PostgreSQL clients
/// as `postgres` (with the `pg_restore … < file` redirect), else `sqlite3` as
/// a snapshot's service user.
fn runuser(
    policy: &Policy,
    args: &[String],
    stdin_path: Option<&str>,
) -> Result<Decision, Refused> {
    require(
        args.len() >= 5 && args[1] == "-u" && args[3] == "--",
        "unexpected runuser arguments",
    )?;
    if args[2] == "postgres" {
        let stdin = postgres::check(policy, &args[4..], stdin_path)?;
        return Ok(Decision {
            stdin,
            ..Decision::run(args.to_vec())
        });
    }
    require(stdin_path.is_none(), "input redirection not allowed here")?;
    sqlite::check(policy, &args[2], &args[4..])?;
    Ok(Decision::run(args.to_vec()))
}

/// `systemctl show --property=LoadState --value <unit>` and `systemctl
/// start|stop <unit>` (`guard.py:502-508`).
fn systemctl(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    if args.len() == 5 && args[1..4] == ["show", "--property=LoadState", "--value"] {
        require(
            policy.units.contains(&args[4]),
            format!("unit not allowed: {}", py_repr(&args[4])),
        )?;
        return Ok(Decision::run(args.to_vec()));
    }
    require(
        args.len() == 3 && matches!(args[1].as_str(), "start" | "stop"),
        "unexpected systemctl arguments",
    )?;
    require(
        policy.units.contains(&args[2]),
        format!("unit not allowed: {}", py_repr(&args[2])),
    )?;
    Ok(Decision::run(args.to_vec()))
}

/// `curl -fsS -o /dev/null <ready URL>` (`guard.py:614-617`).
fn curl(policy: &Policy, args: &[String]) -> Result<Decision, Refused> {
    require(
        args.len() == 5 && args[1..4] == ["-fsS", "-o", "/dev/null"],
        "unexpected curl arguments",
    )?;
    require(
        policy.ready_urls.contains(&args[4]),
        format!("URL not allowed: {}", py_repr(&args[4])),
    )?;
    Ok(Decision::run(args.to_vec()))
}

// --- helpers shared by the branches -------------------------------------------

/// `_require` (`guard.py:198-200`).
pub(crate) fn require(condition: bool, reason: impl Into<String>) -> Result<(), Refused> {
    if condition {
        Ok(())
    } else {
        Err(Refused::new(reason))
    }
}

pub(crate) fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// `path.rpartition("/")` without the separator: `("", path)` when there is
/// no `/`.
pub(crate) fn rpartition(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

/// `_split_in_dir(path, is_dir)` (`guard.py:278-283`): `<dir>/<name>` where
/// `is_dir(dir)` and `name` is a plain file name.
pub(crate) fn split_in_dir(
    path: &str,
    is_dir: impl Fn(&str) -> bool,
) -> Result<(&str, &str), Refused> {
    require(
        is_safe_path(path),
        format!("unsafe path: {}", py_repr(path)),
    )?;
    let (directory, name) = rpartition(path);
    require(
        is_dir(directory) && is_safe_name(name),
        format!("path not allowed: {}", py_repr(path)),
    )?;
    Ok((directory, name))
}

/// `_is_temp_dump(policy, path, kinds)` (`guard.py:209-221`):
/// `/tmp/echoport_<prefix>_<kind>_<stamp>.dump` for a policy temp file
/// prefix, one of `kinds` and a stamp of `[A-Za-z0-9_-]+`. The stamp cannot
/// hold a `.`, so it ends at the `.dump` suffix; trying every prefix is the
/// regex alternation (with backtracking) of Python.
pub(crate) fn is_temp_dump(policy: &Policy, path: &str, kinds: &[&str]) -> bool {
    let Some(middle) = path
        .strip_prefix("/tmp/echoport_")
        .and_then(|rest| rest.strip_suffix(".dump"))
    else {
        return false;
    };
    let is_stamp = |stamp: &str| {
        !stamp.is_empty()
            && stamp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    kinds.iter().any(|kind| {
        policy.temp_file_prefixes.iter().any(|prefix| {
            middle
                .strip_prefix(prefix.as_str())
                .and_then(|rest| rest.strip_prefix('_'))
                .and_then(|rest| rest.strip_prefix(kind))
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(is_stamp)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::VirtualEnv;
    use crate::policy::parse_policy;

    fn refusal(command: &str) -> Refused {
        check(
            command.as_bytes(),
            &Policy::default(),
            &VirtualEnv::default(),
        )
        .unwrap_err()
    }

    pub(crate) fn test_policy() -> Policy {
        parse_policy(
            br#"{
              "postgres": {
                "dump_databases": ["homepage", "djangochat"],
                "restore_databases": {"homepage": "homepage", "marina": "marina_owner"},
                "temp_file_prefixes": ["hp", "pp_x"],
                "scratch_restore_prefixes": ["djangochat_restore"]
              },
              "units": ["gotosocial.service", "marina"],
              "private_media_paths": ["/home/pp/site/private_media"],
              "temp_dirs": ["/var/tmp/djangochat-restore.XXXXXXXX"],
              "sqlite_snapshots": [
                {"database": "/var/lib/gotosocial/sqlite.db", "owner": "gotosocial:gotosocial",
                 "temp_dir": "/var/tmp/echoport-gotosocial.XXXXXX"}
              ],
              "ready_urls": ["http://127.0.0.1:8080/ready"]
            }"#,
        )
        .unwrap()
    }

    /// The decision for `command` under [`test_policy`]: the argv, or the
    /// refusal reason.
    pub(crate) fn decide(command: &str) -> Result<Decision, String> {
        check(command.as_bytes(), &test_policy(), &VirtualEnv::default())
            .map_err(|refused| refused.reason().to_owned())
    }

    pub(crate) fn argv(command: &str) -> Vec<String> {
        decide(command).unwrap().argv
    }

    pub(crate) fn reason(command: &str) -> String {
        decide(command).unwrap_err()
    }

    #[test]
    fn unknown_tools_are_refused_with_pythons_reason() {
        let refused = refusal("id");
        assert_eq!(refused.reason(), "command not allowed: 'id'");
        assert!(!refused.is_not_ported());
        assert_eq!(refusal("'' x").reason(), "command not allowed: ''");
        assert_eq!(
            refusal("\"it's\"").reason(),
            "command not allowed: \"it's\""
        );
    }

    #[test]
    fn only_the_filesystem_branches_are_still_stubs() {
        let s3b = [
            "scp",
            "rsync",
            "cat",
            "sha256sum",
            "readlink",
            "test",
            "mv",
            "mkdir",
            "chmod",
            "chown",
        ];
        for tool in TOOLS {
            let refused = refusal(&format!("{tool} x y z"));
            assert_eq!(refused.is_not_ported(), s3b.contains(&tool), "{tool}");
        }
        assert!(refusal("umask 077 && tar -C /a -czf /b -- c").is_not_ported());
        assert!(refusal("umask 077 && cat > /a/b").is_not_ported());
        // The `-wal`/`-shm` branch of rm resolves paths (S3b).
        assert!(refusal("rm -f /a/db-wal /a/db-shm").is_not_ported());
        assert!(!refusal("rm -f /a/db-wal").is_not_ported());
    }

    #[test]
    fn tokeniser_stage_reasons() {
        assert_eq!(
            refusal("cat 'x").reason(),
            "unparsable command: No closing quotation"
        );
        assert_eq!(refusal("  \t ").reason(), "empty command");
        assert_eq!(
            refusal("cat < /etc/passwd").reason(),
            "input redirection not allowed here"
        );
        // `<` must be the second-to-last token of at least three.
        assert_eq!(refusal("< x").reason(), "command not allowed: '<'");
    }

    #[test]
    fn sudo_runs_postgres_tools_non_interactively() {
        assert_eq!(
            argv("sudo -u postgres pg_dump --format=custom --dbname=homepage"),
            [
                "sudo",
                "-n",
                "-u",
                "postgres",
                "--",
                "pg_dump",
                "--format=custom",
                "--dbname=homepage"
            ]
        );
        for command in [
            "sudo -u postgres",
            "sudo -u root pg_dump --format=custom --dbname=homepage",
            "sudo -n -u postgres pg_dump",
            "sudo postgres -u pg_dump",
        ] {
            assert_eq!(
                reason(command),
                "only sudo -u postgres is allowed",
                "{command}"
            );
        }
        assert_eq!(
            reason("sudo -u postgres -- pg_dump --format=custom --dbname=homepage"),
            "postgres tool not allowed: '--'"
        );
        assert_eq!(
            reason("sudo -u postgres pg_restore < /var/tmp/x"),
            "input redirection not allowed here"
        );
    }

    #[test]
    fn runuser_shapes() {
        assert_eq!(
            argv("runuser -u postgres -- psql -d homepage -c 'SELECT 1'"),
            [
                "runuser", "-u", "postgres", "--", "psql", "-d", "homepage", "-c", "SELECT 1"
            ]
        );
        for command in [
            "runuser -u postgres --",
            "runuser -u postgres pg_dump --format=custom --dbname=homepage",
            "runuser -g postgres -- pg_dump --format=custom --dbname=homepage",
        ] {
            assert_eq!(reason(command), "unexpected runuser arguments", "{command}");
        }
        assert_eq!(
            reason("runuser -u gotosocial -- sqlite3 /x 'PRAGMA integrity_check;' < /tmp/x"),
            "input redirection not allowed here"
        );
        assert_eq!(
            reason("runuser -u root -- sh -c id"),
            "unexpected command for a service user"
        );
    }

    #[test]
    fn systemctl_shapes() {
        for command in [
            "systemctl show --property=LoadState --value marina",
            "systemctl start gotosocial.service",
            "systemctl stop marina",
        ] {
            assert!(decide(command).is_ok(), "{command}");
        }
        assert_eq!(
            reason("systemctl restart marina"),
            "unexpected systemctl arguments"
        );
        assert_eq!(
            reason("systemctl show --property=LoadState --value sshd"),
            "unit not allowed: 'sshd'"
        );
        assert_eq!(
            reason("systemctl show --property=LoadState marina"),
            "unexpected systemctl arguments"
        );
        assert_eq!(reason("systemctl stop sshd"), "unit not allowed: 'sshd'");
        assert_eq!(reason("systemctl"), "unexpected systemctl arguments");
    }

    #[test]
    fn curl_shapes() {
        assert!(decide("curl -fsS -o /dev/null http://127.0.0.1:8080/ready").is_ok());
        assert_eq!(
            reason("curl -fsS -o /dev/null http://127.0.0.1:8081/ready"),
            "URL not allowed: 'http://127.0.0.1:8081/ready'"
        );
        assert_eq!(
            reason("curl -fsS -o /tmp/x http://127.0.0.1:8080/ready"),
            "unexpected curl arguments"
        );
        assert_eq!(reason("curl"), "unexpected curl arguments");
    }

    #[test]
    fn temp_dumps() {
        let policy = test_policy();
        let dump = |path: &str, kinds: &[&str]| is_temp_dump(&policy, path, kinds);
        assert!(dump(
            "/tmp/echoport_hp_dump_2026-10-15T02-00-00.dump",
            &["dump"]
        ));
        assert!(dump("/tmp/echoport_pp_x_restore_a_b.dump", &["restore"]));
        // The prefix `pp_x` and a stamp with `_`: any split that fits.
        assert!(dump("/tmp/echoport_pp_x_dump_x_dump_1.dump", &["dump"]));
        assert!(dump(
            "/tmp/echoport_hp_restore_1.dump",
            &["dump", "restore"]
        ));
        for path in [
            "/tmp/echoport_hp_restore_1.dump",
            "/tmp/echoport_hp_dump_.dump",
            "/tmp/echoport_hp_dump_a.b.dump",
            "/tmp/echoport_hp_dump_a/b.dump",
            "/tmp/echoport_pp_dump_1.dump",
            "/tmp/echoport_hp_dump_1.dump.gz",
            "/var/tmp/echoport_hp_dump_1.dump",
            "/tmp/echoport_hp_dump_1",
        ] {
            assert!(!dump(path, &["dump"]), "{path}");
        }
        assert!(!is_temp_dump(
            &Policy::default(),
            "/tmp/echoport_hp_dump_1.dump",
            &["dump"]
        ));
    }

    #[test]
    fn split_in_dir_as_python() {
        let is_dir = |d: &str| d == "/var/tmp/d.abc";
        assert_eq!(
            split_in_dir("/var/tmp/d.abc/x.dump", is_dir),
            Ok(("/var/tmp/d.abc", "x.dump"))
        );
        assert_eq!(
            split_in_dir("/var/tmp/d.abc/../x", is_dir)
                .unwrap_err()
                .reason(),
            "unsafe path: '/var/tmp/d.abc/../x'"
        );
        for path in ["/var/tmp/d.abc/", "/var/tmp/d.abc/.x", "/var/tmp/x.dump"] {
            assert_eq!(
                split_in_dir(path, is_dir).unwrap_err().reason(),
                format!("path not allowed: '{path}'")
            );
        }
        assert_eq!(rpartition("abc"), ("", "abc"));
        assert_eq!(rpartition("/a/b"), ("/a", "b"));
    }
}
