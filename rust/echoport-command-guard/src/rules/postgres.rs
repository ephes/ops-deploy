//! `_check_postgres` (`guard.py:297-368`): a PostgreSQL client call run as
//! `postgres` (`sudo -u postgres …` or `runuser -u postgres -- …`).

use std::sync::LazyLock;

use regex_lite::Regex;

use super::{is_temp_dump, require, split_in_dir};
use crate::decision::{Redirect, Refused};
use crate::policy::Policy;
use crate::repr::py_repr;
use crate::tokens::constant_regex;

/// `_PSQL_RUNNER_PREFIX` (`guard.py:63`).
const PSQL_RUNNER_PREFIX: [&str; 5] = ["-X", "-v", "ON_ERROR_STOP=1", "-qAt", "-d"];
/// `_PSQL_ALTER_PREFIX`: the public schema owner statement after `createdb`.
const PSQL_ALTER_PREFIX: [&str; 4] = ["-X", "-v", "ON_ERROR_STOP=1", "-d"];
/// `_SQL_SERVER_VERSION` (`guard.py:64`).
const SQL_SERVER_VERSION: &str = "SHOW server_version;";

static SQL_DB_EXISTS: LazyLock<Regex> = LazyLock::new(|| {
    constant_regex(r"^SELECT 1 FROM pg_database WHERE datname = '([a-z0-9_]+)';$")
});
static SQL_COUNT: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^SELECT count\(\*\) FROM public\.[a-z_][a-z0-9_]*;$"));

/// Check `args` (`<tool> …`, never empty) for the `postgres` user; return
/// the file the guard opens as its stdin, if any (`stdin_path` is the
/// `< file` of `runuser`).
pub fn check(
    policy: &Policy,
    args: &[String],
    stdin_path: Option<&str>,
) -> Result<Option<Redirect>, Refused> {
    let Some((tool, rest)) = args.split_first() else {
        // The callers' length checks rule this out.
        return Err(Refused::new("postgres tool not allowed: ''"));
    };
    if let ("pg_restore", Some(stdin_path)) = (tool.as_str(), stdin_path) {
        // Restore into a fresh scratch database, the dump read from a
        // root-only temp directory (django_chat_staging_db_backup.py.j2).
        require(
            rest.len() == 4 && rest[..3] == ["--no-owner", "--no-privileges", "--exit-on-error"],
            "unexpected pg_restore arguments",
        )?;
        let database = rest[3].strip_prefix("--dbname=");
        require(database.is_some(), "unexpected pg_restore arguments")?;
        let database = database.unwrap_or_default();
        require(
            policy.scratch_database(database),
            format!("pg_restore into {} not allowed", py_repr(database)),
        )?;
        let (directory, name) = split_in_dir(stdin_path, |d| policy.private_temp_dir(d))?;
        require(
            name.ends_with(".dump"),
            format!("pg_restore source not allowed: {}", py_repr(stdin_path)),
        )?;
        return Ok(Some(Redirect {
            directory: directory.to_owned(),
            name: name.to_owned(),
            owners: Vec::new(),
        }));
    }
    require(stdin_path.is_none(), "input redirection not allowed here")?;
    match tool.as_str() {
        "pg_dump" => pg_dump(policy, rest)?,
        "dropdb" => {
            require(
                rest.len() == 3 && rest[..2] == ["--if-exists", "--force"],
                "unexpected dropdb arguments",
            )?;
            require(
                policy.restore_databases.contains_key(&rest[2]),
                format!("dropdb of {} not allowed", py_repr(&rest[2])),
            )?;
        }
        "createdb" => createdb(policy, rest)?,
        "pg_restore" => pg_restore(policy, rest)?,
        "psql" => psql(policy, rest)?,
        _ => {
            return Err(Refused::new(format!(
                "postgres tool not allowed: {}",
                py_repr(tool)
            )));
        }
    }
    Ok(None)
}

/// `pg_dump --format=custom [--file=<temp dump>] --dbname=<db>`
/// (`guard.py:314-327`).
fn pg_dump(policy: &Policy, rest: &[String]) -> Result<(), Refused> {
    if rest.len() == 2 {
        // Dump to stdout (django_chat_staging_db_backup.py.j2).
        let database = rest[1].strip_prefix("--dbname=");
        require(
            rest[0] == "--format=custom" && database.is_some(),
            "unexpected pg_dump arguments",
        )?;
        let database = database.unwrap_or_default();
        return require(
            policy.dump_databases.contains(database),
            format!("pg_dump of {} not allowed", py_repr(database)),
        );
    }
    require(
        rest.len() == 3 && rest[0] == "--format=custom",
        "unexpected pg_dump arguments",
    )?;
    let (dump_file, database) = (
        rest[1].strip_prefix("--file="),
        rest[2].strip_prefix("--dbname="),
    );
    let (Some(dump_file), Some(database)) = (dump_file, database) else {
        return Err(Refused::new("unexpected pg_dump arguments"));
    };
    require(
        policy.dump_databases.contains(database),
        format!("pg_dump of {} not allowed", py_repr(database)),
    )?;
    require(
        is_temp_dump(policy, dump_file, &["dump"]),
        format!("pg_dump target not allowed: {}", py_repr(dump_file)),
    )
}

/// `createdb <scratch db>` or `createdb --owner=<role> <db>`
/// (`guard.py:332-339`).
fn createdb(policy: &Policy, rest: &[String]) -> Result<(), Refused> {
    if rest.len() == 1 {
        return require(
            policy.scratch_database(&rest[0]),
            format!("createdb {} not allowed", py_repr(&rest[0])),
        );
    }
    let owner = if rest.len() == 2 {
        rest[0].strip_prefix("--owner=")
    } else {
        None
    };
    let Some(owner) = owner else {
        return Err(Refused::new("unexpected createdb arguments"));
    };
    let database = &rest[1];
    require(
        policy
            .restore_databases
            .get(database)
            .is_some_and(|role| role == owner),
        format!(
            "createdb {} owner {} not allowed",
            py_repr(database),
            py_repr(owner)
        ),
    )
}

/// `pg_restore --exit-on-error --dbname=<db> --no-owner --role=<role> <temp
/// dump>` (`guard.py:340-347`).
fn pg_restore(policy: &Policy, rest: &[String]) -> Result<(), Refused> {
    require(rest.len() == 5, "unexpected pg_restore arguments")?;
    require(
        rest[0] == "--exit-on-error" && rest[2] == "--no-owner",
        "unexpected pg_restore arguments",
    )?;
    let (Some(database), Some(role)) = (
        rest[1].strip_prefix("--dbname="),
        rest[3].strip_prefix("--role="),
    ) else {
        return Err(Refused::new("unexpected pg_restore arguments"));
    };
    let dump_file = &rest[4];
    require(
        policy
            .restore_databases
            .get(database)
            .is_some_and(|owner| owner == role),
        format!(
            "pg_restore into {} as {} not allowed",
            py_repr(database),
            py_repr(role)
        ),
    )?;
    require(
        is_temp_dump(policy, dump_file, &["restore"]),
        format!("pg_restore source not allowed: {}", py_repr(dump_file)),
    )
}

/// `psql -X -v ON_ERROR_STOP=1 -d <db> -c 'ALTER SCHEMA public OWNER TO
/// "<role>"'`, `psql -d <db> -c 'SELECT 1'` and the read-only queries of
/// django_chat_staging_db_backup.py.j2 (`guard.py:348-367`; the `ALTER
/// SCHEMA` branch is cited by its constant `_PSQL_ALTER_PREFIX`).
fn psql(policy: &Policy, rest: &[String]) -> Result<(), Refused> {
    if rest.len() == 7 {
        // Give the restored database's public schema to its owner right
        // after createdb (createdb copies template1, whose public schema
        // may still belong to postgres; pg_restore --no-owner leaves it).
        require(
            rest[..4] == PSQL_ALTER_PREFIX && rest[5] == "-c",
            "unexpected psql arguments",
        )?;
        let (database, sql) = (&rest[4], &rest[6]);
        let Some(role) = policy.restore_databases.get(database) else {
            return Err(Refused::new(format!(
                "psql on {} not allowed",
                py_repr(database)
            )));
        };
        return require(
            *sql == format!("ALTER SCHEMA public OWNER TO \"{role}\""),
            "psql statement not allowed",
        );
    }
    if rest.len() == 4 {
        require(
            rest[0] == "-d" && rest[2..] == ["-c", "SELECT 1"],
            "unexpected psql arguments",
        )?;
        return require(
            policy.restore_databases.contains_key(&rest[1])
                || policy.dump_databases.contains(&rest[1]),
            format!("psql on {} not allowed", py_repr(&rest[1])),
        );
    }
    require(
        rest.len() == 8 && rest[..5] == PSQL_RUNNER_PREFIX && rest[6] == "-c",
        "unexpected psql arguments",
    )?;
    let (database, sql) = (&rest[5], &rest[7]);
    if sql == SQL_SERVER_VERSION {
        return require(
            policy.dump_databases.contains(database),
            format!("psql on {} not allowed", py_repr(database)),
        );
    }
    if let Some(exists) = SQL_DB_EXISTS.captures(sql) {
        let scratch = exists
            .get(1)
            .is_some_and(|name| policy.scratch_database(name.as_str()));
        return require(database == "postgres" && scratch, "psql query not allowed");
    }
    require(
        SQL_COUNT.is_match(sql) && policy.scratch_database(database),
        "psql query not allowed",
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{decide, reason};
    use super::*;
    use crate::decision::Decision;

    #[test]
    fn patterns_compile() {
        LazyLock::force(&SQL_DB_EXISTS);
        LazyLock::force(&SQL_COUNT);
    }

    #[test]
    fn dump_and_restore_shapes() {
        for command in [
            "sudo -u postgres pg_dump --format=custom --file=/tmp/echoport_hp_dump_1.dump --dbname=homepage",
            "runuser -u postgres -- pg_dump --format=custom --dbname=djangochat",
            "sudo -u postgres dropdb --if-exists --force marina",
            "sudo -u postgres createdb --owner=marina_owner marina",
            "runuser -u postgres -- createdb djangochat_restore_7",
            "sudo -u postgres pg_restore --exit-on-error --dbname=homepage --no-owner --role=homepage /tmp/echoport_hp_restore_1.dump",
            "sudo -u postgres psql -d marina -c 'SELECT 1'",
            "sudo -u postgres psql -d djangochat -c 'SELECT 1'",
        ] {
            assert!(decide(command).is_ok(), "{command}: {:?}", decide(command));
        }
    }

    #[test]
    fn dump_and_restore_refusals() {
        let cases = [
            (
                "sudo -u postgres pg_dump --format=custom --dbname=marina",
                "pg_dump of 'marina' not allowed",
            ),
            (
                "sudo -u postgres pg_dump --format=plain --dbname=homepage",
                "unexpected pg_dump arguments",
            ),
            (
                "sudo -u postgres pg_dump --format=custom homepage",
                "unexpected pg_dump arguments",
            ),
            (
                "sudo -u postgres pg_dump --format=custom --file=/tmp/x.dump --dbname=homepage",
                "pg_dump target not allowed: '/tmp/x.dump'",
            ),
            (
                "sudo -u postgres pg_dump --format=custom --dbname=homepage --file=/tmp/echoport_hp_dump_1.dump",
                "unexpected pg_dump arguments",
            ),
            (
                "sudo -u postgres pg_dump --format=custom --file=/tmp/echoport_hp_dump_1.dump --dbname=marina",
                "pg_dump of 'marina' not allowed",
            ),
            (
                "sudo -u postgres dropdb --if-exists marina",
                "unexpected dropdb arguments",
            ),
            (
                "sudo -u postgres dropdb --if-exists --force djangochat",
                "dropdb of 'djangochat' not allowed",
            ),
            (
                "sudo -u postgres createdb --owner=homepage marina",
                "createdb 'marina' owner 'homepage' not allowed",
            ),
            (
                "sudo -u postgres createdb --owner=x nothere",
                "createdb 'nothere' owner 'x' not allowed",
            ),
            (
                "sudo -u postgres createdb marina",
                "createdb 'marina' not allowed",
            ),
            (
                "sudo -u postgres createdb -O marina_owner marina",
                "unexpected createdb arguments",
            ),
            (
                "sudo -u postgres createdb a b c",
                "unexpected createdb arguments",
            ),
            (
                "sudo -u postgres pg_restore --exit-on-error --dbname=homepage --no-owner --role=postgres /tmp/echoport_hp_restore_1.dump",
                "pg_restore into 'homepage' as 'postgres' not allowed",
            ),
            (
                "sudo -u postgres pg_restore --exit-on-error --dbname=homepage --no-owner --role=homepage /tmp/echoport_hp_dump_1.dump",
                "pg_restore source not allowed: '/tmp/echoport_hp_dump_1.dump'",
            ),
            (
                "sudo -u postgres pg_restore --clean --dbname=homepage --no-owner --role=homepage /tmp/echoport_hp_restore_1.dump",
                "unexpected pg_restore arguments",
            ),
            (
                "sudo -u postgres pg_restore --exit-on-error -d homepage --no-owner --role=homepage /tmp/echoport_hp_restore_1.dump",
                "unexpected pg_restore arguments",
            ),
            (
                "sudo -u postgres pg_restore --exit-on-error --dbname=homepage --no-owner",
                "unexpected pg_restore arguments",
            ),
            (
                "sudo -u postgres psql -d sshd -c 'SELECT 1'",
                "psql on 'sshd' not allowed",
            ),
            (
                "sudo -u postgres psql -d marina -c 'SELECT 2'",
                "unexpected psql arguments",
            ),
            (
                "sudo -u postgres psql -d marina",
                "unexpected psql arguments",
            ),
            (
                "sudo -u postgres pg_dumpall",
                "postgres tool not allowed: 'pg_dumpall'",
            ),
        ];
        for (command, expected) in cases {
            assert_eq!(reason(command), expected, "{command}");
        }
    }

    #[test]
    fn scratch_restore_from_a_private_temp_dir() {
        let command = "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error --dbname=djangochat_restore_3 < /var/tmp/djangochat-restore.Ab12Cd34/db.dump";
        assert_eq!(
            decide(command),
            Ok(Decision {
                stdin: Some(Redirect {
                    directory: "/var/tmp/djangochat-restore.Ab12Cd34".into(),
                    name: "db.dump".into(),
                    owners: vec![],
                }),
                ..Decision::run(
                    "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error --dbname=djangochat_restore_3"
                        .split(' ')
                        .map(str::to_owned)
                        .collect()
                )
            })
        );
        let cases = [
            (
                "runuser -u postgres -- pg_restore --no-owner --no-privileges --dbname=djangochat_restore_3 < /var/tmp/djangochat-restore.Ab12Cd34/db.dump",
                "unexpected pg_restore arguments",
            ),
            (
                "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error djangochat_restore_3 < /var/tmp/djangochat-restore.Ab12Cd34/db.dump",
                "unexpected pg_restore arguments",
            ),
            (
                "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error --dbname=djangochat < /var/tmp/djangochat-restore.Ab12Cd34/db.dump",
                "pg_restore into 'djangochat' not allowed",
            ),
            (
                "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error --dbname=djangochat_restore_3 < /var/tmp/djangochat-restore.Ab12Cd34/../db.dump",
                "unsafe path: '/var/tmp/djangochat-restore.Ab12Cd34/../db.dump'",
            ),
            (
                "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error --dbname=djangochat_restore_3 < /var/tmp/other.Ab12Cd34/db.dump",
                "path not allowed: '/var/tmp/other.Ab12Cd34/db.dump'",
            ),
            (
                "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error --dbname=djangochat_restore_3 < /var/tmp/djangochat-restore.Ab12Cd34/db.sql",
                "pg_restore source not allowed: '/var/tmp/djangochat-restore.Ab12Cd34/db.sql'",
            ),
            (
                "runuser -u postgres -- psql -d marina -c 'SELECT 1' < /var/tmp/djangochat-restore.Ab12Cd34/db.dump",
                "input redirection not allowed here",
            ),
        ];
        for (command, expected) in cases {
            assert_eq!(reason(command), expected, "{command}");
        }
    }

    /// The public schema owner statement after `createdb`: both runner
    /// forms, the role from `restore_databases` (not the database name),
    /// and each of Python's three reasons in its order.
    #[test]
    fn public_schema_owner() {
        let alter = |prefix: &str, database: &str, sql: &str| {
            format!("{prefix} psql -X -v ON_ERROR_STOP=1 -d {database} -c '{sql}'")
        };
        for prefix in ["sudo -u postgres", "runuser -u postgres --"] {
            for (database, role) in [("homepage", "homepage"), ("marina", "marina_owner")] {
                let command = alter(
                    prefix,
                    database,
                    &format!("ALTER SCHEMA public OWNER TO \"{role}\""),
                );
                let tail = [
                    "psql",
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-d",
                    database,
                    "-c",
                    &format!("ALTER SCHEMA public OWNER TO \"{role}\""),
                ]
                .map(str::to_owned);
                let head: &[&str] = if prefix.starts_with("sudo") {
                    &["sudo", "-n", "-u", "postgres", "--"]
                } else {
                    &["runuser", "-u", "postgres", "--"]
                };
                let mut expected: Vec<String> = head.iter().map(|s| (*s).to_owned()).collect();
                expected.extend(tail);
                assert_eq!(decide(&command), Ok(Decision::run(expected)), "{command}");
            }
            for (database, sql, expected) in [
                // Not a restore database: dump-only, scratch, unknown.
                (
                    "djangochat",
                    "ALTER SCHEMA public OWNER TO \"djangochat\"",
                    "psql on 'djangochat' not allowed",
                ),
                (
                    "djangochat_restore_3",
                    "ALTER SCHEMA public OWNER TO \"homepage\"",
                    "psql on 'djangochat_restore_3' not allowed",
                ),
                (
                    "postgres",
                    "ALTER SCHEMA public OWNER TO \"postgres\"",
                    "psql on 'postgres' not allowed",
                ),
                // The database is checked before the statement.
                ("template1", "SELECT 1", "psql on 'template1' not allowed"),
                // The role of another database, or the database name
                // instead of its role.
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"marina_owner\"",
                    "psql statement not allowed",
                ),
                (
                    "marina",
                    "ALTER SCHEMA public OWNER TO \"marina\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"postgres\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO homepage",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"homepage\";",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"homepage\" ",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    " ALTER SCHEMA public OWNER TO \"homepage\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "alter schema public owner to \"homepage\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA \"public\" OWNER TO \"homepage\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA pg_catalog OWNER TO \"homepage\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"homepage\"; DROP TABLE x",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"Homepage\"",
                    "psql statement not allowed",
                ),
                (
                    "homepage",
                    "ALTER SCHEMA public OWNER TO \"homepage\"\"",
                    "psql statement not allowed",
                ),
                ("homepage", "SELECT 1", "psql statement not allowed"),
                ("homepage", "", "psql statement not allowed"),
            ] {
                let command = alter(prefix, database, sql);
                assert_eq!(reason(&command), expected, "{command}");
            }
            let good = "'ALTER SCHEMA public OWNER TO \"homepage\"'";
            for args in [
                format!("-v ON_ERROR_STOP=1 -X -d homepage -c {good}"),
                format!("-X -v ON_ERROR_STOP=0 -d homepage -c {good}"),
                format!("-X -v ON_ERROR_STOP=1 --dbname=homepage -c {good}"),
                format!("-X -v ON_ERROR_STOP=1 -d homepage --command {good}"),
                format!("-X -v ON_ERROR_STOP=1 -d homepage -f {good}"),
                format!("-X -v ON_ERROR_STOP=1 -d homepage -c {good} -c {good}"),
                format!("-X -v ON_ERROR_STOP=1 -d homepage -c {good} -o /tmp/x"),
                format!("-X -v ON_ERROR_STOP=1 -h evil -d homepage -c {good}"),
                format!("-X -X -v ON_ERROR_STOP=1 -d homepage -c {good}"),
                format!("-v ON_ERROR_STOP=1 -d homepage -c {good}"),
                format!("-X -d homepage -c {good}"),
                format!("-d homepage -c {good}"),
                format!("-X -v ON_ERROR_STOP=1 -d homepage {good}"),
                format!("-X -v ON_ERROR_STOP=1 -d homepage -c {good}; id"),
                // A wrong prefix is refused before the database is looked at.
                format!("-X -v ON_ERROR_STOP=0 -d nothere -c {good}"),
            ] {
                let command = format!("{prefix} psql {args}");
                assert_eq!(reason(&command), "unexpected psql arguments", "{command}");
            }
        }
        // Eight arguments are the runner queries' shape, not this one.
        assert_eq!(
            reason(
                "sudo -u postgres psql -X -v ON_ERROR_STOP=1 -qAt -d homepage -c 'ALTER SCHEMA public OWNER TO \"homepage\"'"
            ),
            "psql query not allowed"
        );
        assert_eq!(
            reason(
                "sudo -u homepage psql -X -v ON_ERROR_STOP=1 -d homepage -c 'ALTER SCHEMA public OWNER TO \"homepage\"'"
            ),
            "only sudo -u postgres is allowed"
        );
        assert_eq!(
            reason(
                "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d homepage -c 'ALTER SCHEMA public OWNER TO \"homepage\"' < /var/tmp/djangochat-restore.Ab12Cd34/db.dump"
            ),
            "input redirection not allowed here"
        );
    }

    #[test]
    fn runner_queries() {
        let psql = |database: &str, sql: &str| {
            format!(
                "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -qAt -d {database} -c \"{sql}\""
            )
        };
        for (database, sql) in [
            ("djangochat", "SHOW server_version;"),
            (
                "postgres",
                "SELECT 1 FROM pg_database WHERE datname = 'djangochat_restore_12';",
            ),
            (
                "djangochat_restore_12",
                "SELECT count(*) FROM public.chat_message;",
            ),
        ] {
            let command = psql(database, sql);
            assert!(decide(&command).is_ok(), "{command}");
        }
        for (database, sql, expected) in [
            (
                "marina",
                "SHOW server_version;",
                "psql on 'marina' not allowed",
            ),
            (
                "djangochat",
                "SELECT 1 FROM pg_database WHERE datname = 'djangochat_restore_12';",
                "psql query not allowed",
            ),
            (
                "postgres",
                "SELECT 1 FROM pg_database WHERE datname = 'djangochat';",
                "psql query not allowed",
            ),
            (
                "djangochat",
                "SELECT count(*) FROM public.chat_message;",
                "psql query not allowed",
            ),
            (
                "djangochat_restore_12",
                "SELECT count(*) FROM public.chat_message; DROP TABLE x;",
                "psql query not allowed",
            ),
            (
                "djangochat_restore_12",
                "SELECT count(*) FROM chat_message;",
                "psql query not allowed",
            ),
        ] {
            assert_eq!(reason(&psql(database, sql)), expected, "{database} {sql}");
        }
        assert_eq!(
            reason(
                "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -qAt -d djangochat -C 'SHOW server_version;'"
            ),
            "unexpected psql arguments"
        );
        assert_eq!(
            reason(
                "runuser -u postgres -- psql -X -v ON_ERROR_STOP=0 -qAt -d djangochat -c 'SHOW server_version;'"
            ),
            "unexpected psql arguments"
        );
    }
}
