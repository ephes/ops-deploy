//! The policy loader on arbitrary bytes (PLAN.md 7.4, target `policy`): no
//! panic; an accepted policy satisfies the validation of PLAN.md 3.2 (so a
//! policy value can never widen what a command may name), and `check()` with
//! it keeps the decision invariants.
#![no_main]

#[path = "../../tests/common/invariants.rs"]
mod invariants;

use echoport_command_guard::env::VirtualEnv;
use echoport_command_guard::policy::{is_safe_name, is_safe_path, parse_policy};
use echoport_command_guard::rules::check;
use libfuzzer_sys::fuzz_target;

/// Commands of every branch that reads a policy list, decided against the
/// fuzzed policy.
const COMMANDS: [&str; 12] = [
    "sudo -u postgres pg_dump --format=custom --dbname=homepage",
    "runuser -u postgres -- psql -d homepage -c 'SELECT 1'",
    "systemctl stop homepage",
    "scp -t /home/marina/site/db.sqlite3.tmp",
    "rsync --server -logtpre.iLsfxCIvu . /home/marina/site/media/",
    "mkdir -p /home/marina/site/media",
    "mktemp -d /var/tmp/gotosocial-echoport.XXXXXX",
    "runuser -u gotosocial -- sqlite3 /var/lib/gotosocial/sqlite.db '.backup '\"'\"'/var/tmp/gotosocial-echoport.abc123/sqlite.db'\"'\"''",
    "cat /var/tmp/gotosocial-echoport.abc123/sqlite.db",
    "curl -fsS -o /dev/null http://127.0.0.1:10070/readyz",
    "du -sb -- /home/python-podcast/site/private_media",
    "umask 077 && cat > /var/tmp/django-chat-db-restore.abcdefgh/db.dump",
];

fuzz_target!(|data: &[u8]| {
    let Ok(policy) = parse_policy(data) else {
        return;
    };
    let names = policy
        .dump_databases
        .iter()
        .chain(policy.restore_databases.keys())
        .chain(policy.restore_databases.values())
        .chain(policy.units.iter());
    for name in names {
        assert!(is_safe_name(name) && !name.ends_with('\n'), "{name:?}");
    }
    for path in policy
        .private_media_paths
        .iter()
        .chain(policy.read_files.iter())
    {
        assert!(
            is_safe_path(path) && path.matches('/').count() >= 2,
            "{path:?}"
        );
    }
    for root in &policy.path_roots {
        assert!(
            is_safe_path(&root.path) && !root.path.ends_with('/'),
            "{root:?}"
        );
        assert!(!root.owner.starts_with("root:"), "{root:?}");
    }
    for snapshot in &policy.sqlite_snapshots {
        assert!(is_safe_path(&snapshot.database), "{snapshot:?}");
        assert!(snapshot.user() != "root", "{snapshot:?}");
    }
    let env = VirtualEnv::default();
    for command in COMMANDS {
        if let Ok(decision) = check(command.as_bytes(), &policy, &env) {
            invariants::decision_invariants(&decision)
                .unwrap_or_else(|broken| panic!("{command:?}: {broken}"));
        }
    }
});
