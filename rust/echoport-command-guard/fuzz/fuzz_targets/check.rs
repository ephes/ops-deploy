//! `check()` on an arbitrary command and an arbitrary host (PLAN.md 7.4,
//! target `check`): no panic, and every accepted decision keeps the
//! invariants of PLAN.md 7.3 (`tests/common/invariants.rs`).
//!
//! Input: one flag byte (bit 0: the staging policy instead of production;
//! bit 1: the guard runs as uid 1000 instead of root), the command (the bytes
//! of `SSH_ORIGINAL_COMMAND`) up to the first NUL byte, then the bytes that
//! choose the host. Every path the command could name (each run of path
//! characters that starts with `/`, its parent directories and its `-wal` /
//! `-shm` base) gets an `lstat` answer and a `realpath` answer from those
//! bytes, in order: absent, a file, directory, link, fifo, socket or device
//! with chosen mode, owner and link count, or an `lstat` error; resolved to
//! itself, to another of the paths, into or next to a policy root, or a
//! `realpath` error (PLAN.md 4.2).
#![no_main]

#[path = "../../tests/common/invariants.rs"]
mod invariants;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use echoport_command_guard::env::{FileKind, FileStat, GuardEnv, OsError, normpath};
use echoport_command_guard::policy::{Policy, parse_policy};
use echoport_command_guard::rules::check;
use libfuzzer_sys::fuzz_target;

static POLICIES: LazyLock<[Policy; 2]> = LazyLock::new(|| {
    [
        parse_policy(include_bytes!("../../fixtures/policies/production.json")).unwrap(),
        parse_policy(include_bytes!("../../fixtures/policies/staging.json")).unwrap(),
    ]
});

/// The users of `parity/oracle.py` (`USERS`).
const USERS: [(&str, u32); 7] = [
    ("root", 0),
    ("postgres", 110),
    ("gotosocial", 120),
    ("homepage", 1004),
    ("marina", 1001),
    ("python-podcast", 1003),
    ("villakunterbunt", 1002),
];
const UIDS: [u32; 8] = [0, 110, 120, 1001, 1002, 1003, 1000, 4242];
const ERRORS: [(&str, &str); 5] = [
    ("EACCES", "Permission denied"),
    ("ENOTDIR", "Not a directory"),
    ("ELOOP", "Too many levels of symbolic links"),
    ("ENAMETOOLONG", "File name too long"),
    ("EIO", "Input/output error"),
];
const ROOTS: [&str; 5] = [
    "/var/lib/gotosocial",
    "/home/marina/site",
    "/home/villakunterbunt/data",
    "/home/marina",
    "/etc/gotosocial/config.yaml",
];

struct FuzzEnv {
    euid: u32,
    lstat: BTreeMap<String, Result<Option<FileStat>, OsError>>,
    realpath: BTreeMap<String, Result<String, OsError>>,
}

impl GuardEnv for FuzzEnv {
    fn euid(&self) -> u32 {
        self.euid
    }

    fn uid_of(&self, name: &str) -> Option<u32> {
        USERS
            .iter()
            .find(|(user, _)| *user == name)
            .map(|(_, uid)| *uid)
    }

    fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError> {
        self.lstat.get(path).cloned().unwrap_or(Ok(None))
    }

    fn realpath(&self, path: &str) -> Result<String, OsError> {
        self.realpath
            .get(path)
            .cloned()
            .unwrap_or_else(|| Ok(normpath(path)))
    }
}

fn os_error(index: u8) -> OsError {
    let (errno, strerror) = ERRORS[usize::from(index) % ERRORS.len()];
    OsError {
        errno: errno.into(),
        strerror: strerror.into(),
    }
}

/// The paths a command could make `check()` look up.
fn candidate_paths(command: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(command);
    let path_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-');
    let mut found = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find('/') {
        let run: String = rest[start..]
            .chars()
            .take_while(|c| path_char(*c))
            .collect();
        rest = &rest[start + run.len().max(1)..];
        let mut path = run.trim_end_matches('/').to_owned();
        for side in ["-wal", "-shm"] {
            if let Some(base) = path.strip_suffix(side) {
                found.push(base.to_owned());
            }
        }
        found.push(run.clone());
        while let Some(cut) = path.rfind('/') {
            found.push(path.clone());
            path.truncate(cut);
        }
    }
    found.sort();
    found.dedup();
    found
}

fn host(command: &[u8], euid: u32, mut choices: impl Iterator<Item = u8>) -> FuzzEnv {
    let paths = candidate_paths(command);
    let mut env = FuzzEnv {
        euid,
        lstat: BTreeMap::new(),
        realpath: BTreeMap::new(),
    };
    for path in &paths {
        let (Some(what), Some(detail)) = (choices.next(), choices.next()) else {
            break;
        };
        let stat = |kind| {
            Ok(Some(FileStat {
                kind,
                mode: u32::from(detail) * 7 % 0o1000,
                uid: UIDS[usize::from(detail >> 5)],
                nlink: if detail & 1 == 0 { 1 } else { 2 },
            }))
        };
        let lstat = match what % 10 {
            0 => Ok(None),
            1 | 2 => stat(FileKind::Reg),
            3 => stat(FileKind::Dir),
            4 => stat(FileKind::Lnk),
            5 => stat(FileKind::Fifo),
            6 => stat(FileKind::Sock),
            7 => stat(if detail & 2 == 0 {
                FileKind::Chr
            } else {
                FileKind::Blk
            }),
            _ => Err(os_error(detail)),
        };
        env.lstat.insert(path.clone(), lstat);
        let resolved = match (what / 10) % 6 {
            0 | 1 => continue,
            2 => Ok(paths[usize::from(detail) % paths.len()].clone()),
            3 => Ok(ROOTS[usize::from(detail) % ROOTS.len()].to_owned()),
            4 => Ok(format!("{}/x", ROOTS[usize::from(detail) % ROOTS.len()])),
            _ => Err(os_error(detail)),
        };
        env.realpath.insert(path.clone(), resolved);
    }
    env
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let (command, choices) = match rest.iter().position(|&b| b == 0) {
        Some(nul) => (&rest[..nul], &rest[nul + 1..]),
        None => (rest, &[][..]),
    };
    let policy = &POLICIES[usize::from(flags & 1)];
    let euid = if flags & 2 == 0 { 0 } else { 1000 };
    let env = host(command, euid, choices.iter().copied());
    if let Ok(decision) = check(command, policy, &env) {
        invariants::decision_invariants(&decision)
            .unwrap_or_else(|broken| panic!("{:?}: {broken}", String::from_utf8_lossy(command)));
    }
});
