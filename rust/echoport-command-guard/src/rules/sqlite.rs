//! `_check_sqlite` (`guard.py:371-390`): `sqlite3` as a snapshot's service
//! user, for the online `.backup` into its temp dir (optionally after
//! `.timeout <ms>`) and the integrity check of the snapshot.

use std::sync::LazyLock;

use regex_lite::Regex;

use super::{require, rpartition};
use crate::decision::Refused;
use crate::policy::{Policy, is_mktemp_result, is_safe_name};
use crate::repr::py_repr;
use crate::tokens::constant_regex;

/// `_SQLITE_BACKUP_RE` (`guard.py:67`).
static BACKUP: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^\.backup '(/[A-Za-z0-9._/-]+)'$"));
/// `_SQLITE_TIMEOUT_RE` (`guard.py:69`): the busy handler a runner sets
/// before `.backup`.
static TIMEOUT: LazyLock<Regex> = LazyLock::new(|| constant_regex(r"^\.timeout [1-9][0-9]{0,5}$"));
/// `_SQLITE_INTEGRITY` (`guard.py:70`).
const INTEGRITY: &str = "PRAGMA integrity_check;";

/// Check `args` (`sqlite3 …`) for `runuser -u <user>`.
pub fn check(policy: &Policy, user: &str, args: &[String]) -> Result<(), Refused> {
    require(
        matches!(args.len(), 3 | 4) && args[0] == "sqlite3",
        "unexpected command for a service user",
    )?;
    // sqlite3 <db> ".timeout <ms>" ".backup '<snapshot>'"
    let (database, statement) = if args.len() == 4 {
        require(
            TIMEOUT.is_match(&args[2]) && args[3].starts_with(".backup "),
            "unexpected sqlite3 arguments",
        )?;
        (&args[1], &args[3])
    } else {
        (&args[1], &args[2])
    };
    for snapshot in &policy.sqlite_snapshots {
        if snapshot.user() != user {
            continue;
        }
        let in_temp = |directory: &str| is_mktemp_result(&snapshot.temp_dir, directory);
        if *database == snapshot.database
            && let Some(target) = BACKUP.captures(statement).and_then(|c| c.get(1))
        {
            let (directory, name) = rpartition(target.as_str());
            if in_temp(directory) && is_safe_name(name) {
                return Ok(());
            }
        }
        let (directory, name) = rpartition(database);
        if statement == INTEGRITY && in_temp(directory) && is_safe_name(name) {
            return Ok(());
        }
    }
    Err(Refused::new(format!(
        "sqlite3 call not allowed for {}",
        py_repr(user)
    )))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{decide, reason};
    use super::*;

    const DB: &str = "/var/lib/gotosocial/sqlite.db";
    const SNAPSHOT: &str = "/var/tmp/echoport-gotosocial.Ab12Cd/sqlite.db";

    fn sqlite(user: &str, args: &str) -> Result<(), String> {
        decide(&format!("runuser -u {user} -- sqlite3 {args}")).map(|_| ())
    }

    #[test]
    fn patterns_compile() {
        LazyLock::force(&BACKUP);
        LazyLock::force(&TIMEOUT);
    }

    #[test]
    fn backup_and_integrity_check() {
        for args in [
            format!("{DB} \".backup '{SNAPSHOT}'\""),
            format!("{DB} '.timeout 1' \".backup '{SNAPSHOT}'\""),
            format!("{DB} '.timeout 30000' \".backup '{SNAPSHOT}'\""),
            format!("{DB} '.timeout 999999' \".backup '{SNAPSHOT}'\""),
            format!("{SNAPSHOT} 'PRAGMA integrity_check;'"),
        ] {
            assert_eq!(sqlite("gotosocial", &args), Ok(()), "{args}");
        }
    }

    #[test]
    fn timeout_variants_are_refused() {
        for timeout in ["0", "1000000", "01", "-1", " 1", "1 ", "1s", ""] {
            let args = format!("{DB} '.timeout {timeout}' \".backup '{SNAPSHOT}'\"");
            assert_eq!(
                sqlite("gotosocial", &args),
                Err("unexpected sqlite3 arguments".into()),
                "{args}"
            );
        }
        for args in [
            format!("{DB} '.timeout 1' 'PRAGMA integrity_check;'"),
            format!("{DB} \".backup '{SNAPSHOT}'\" '.timeout 1'"),
            format!("{DB} '.timeout  1' \".backup '{SNAPSHOT}'\""),
        ] {
            assert_eq!(
                sqlite("gotosocial", &args),
                Err("unexpected sqlite3 arguments".into()),
                "{args}"
            );
        }
        // `.backup ` passes the shape check, the target is then checked.
        assert_eq!(
            sqlite("gotosocial", &format!("{DB} '.timeout 1' '.backup x'")),
            Err("sqlite3 call not allowed for 'gotosocial'".into())
        );
    }

    #[test]
    fn refusals() {
        let not_allowed = Err("sqlite3 call not allowed for 'gotosocial'".to_owned());
        for args in [
            format!("/var/lib/other.db \".backup '{SNAPSHOT}'\""),
            format!("{DB} \".backup '/var/tmp/echoport-gotosocial.Ab12C/sqlite.db'\""),
            format!("{DB} \".backup '/var/tmp/echoport-gotosocial.Ab12Cd/.x'\""),
            format!("{DB} \".backup {SNAPSHOT}\""),
            format!("{DB} \".restore '{SNAPSHOT}'\""),
            format!("{DB} 'PRAGMA integrity_check;'"),
            format!("{SNAPSHOT} 'PRAGMA quick_check;'"),
            "sqlite.db 'PRAGMA integrity_check;'".to_owned(),
        ] {
            assert_eq!(sqlite("gotosocial", &args), not_allowed, "{args}");
        }
        assert_eq!(
            sqlite("marina", &format!("{DB} \".backup '{SNAPSHOT}'\"")),
            Err("sqlite3 call not allowed for 'marina'".into())
        );
        assert_eq!(
            reason(&format!("runuser -u gotosocial -- sqlite3 {DB}")),
            "unexpected command for a service user"
        );
        assert_eq!(
            reason(&format!(
                "runuser -u gotosocial -- sqlite3 {DB} '.timeout 1' \".backup '{SNAPSHOT}'\" x"
            )),
            "unexpected command for a service user"
        );
        assert_eq!(
            reason(&format!(
                "runuser -u gotosocial -- sh {DB} \".backup '{SNAPSHOT}'\""
            )),
            "unexpected command for a service user"
        );
    }
}
