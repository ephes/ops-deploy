//! Race regressions of the root-run mutations (PLAN.md 4.5, R12; slice H1):
//! the scenarios of `parity/races.json`, which the Python guard runs too
//! (`GuardMutationRaces` in `tests/test_echoport_remote_command_guard.py`),
//! against the Rust guard's `check()` on the real filesystem and
//! [`mutate::perform`] with a test hook. A change between `check()` and
//! `perform()`, or during `perform()`'s walk, must never make the guard
//! change, move or remove anything outside the root, and both guards must
//! reach the same outcome with the same reason.
//!
//! Not root: `{owner}` is the test user and another of their groups, so a
//! `chown` shows in the gid; without a second group the `chown` scenarios
//! are skipped (with a note on stderr). As root: `nobody:nogroup`; the
//! Layer-2 containers run this test binary as root (`parity/e2e/run-layer2.sh`).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::sys::stat::Mode;
use nix::unistd::{Gid, Group, User, geteuid, mkfifo};
use serde::Deserialize;
use serde_json::Value;

use echoport_command_guard::decision::Mutation;
use echoport_command_guard::env::RealEnv;
use echoport_command_guard::mutate;
use echoport_command_guard::policy::parse_policy;
use echoport_command_guard::rules::check;

#[derive(Debug, Deserialize)]
struct Races {
    tree: Tree,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Tree {
    dirs: Vec<(String, String)>,
    files: Vec<(String, String)>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    id: String,
    command: Option<String>,
    mutation: Option<Value>,
    #[serde(default)]
    setup: Vec<Vec<String>>,
    #[serde(default)]
    before_use: Vec<Vec<String>>,
    #[serde(default)]
    hooks: Vec<HookSpec>,
    expect: BTreeMap<String, Value>,
    #[serde(default)]
    after: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookSpec {
    event: String,
    path: String,
    #[serde(default = "first")]
    nth: usize,
    actions: Vec<Vec<String>>,
}

fn first() -> usize {
    1
}

/// `parity/races.json`, or `$ECHOPORT_RACES` (the Layer-2 containers run
/// this test binary as root, away from the source tree).
fn races() -> Races {
    let path = std::env::var_os("ECHOPORT_RACES").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/races.json"),
        PathBuf::from,
    );
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// `{owner}` and its ids; `None` when the test user has no second group.
fn chown_target(base: &Path) -> (String, Option<(u32, u32)>) {
    if geteuid().is_root() {
        let user = User::from_name("nobody").unwrap().unwrap();
        for name in ["nogroup", "nobody"] {
            if let Ok(Some(group)) = Group::from_name(name) {
                return (
                    format!("nobody:{name}"),
                    Some((user.uid.as_raw(), group.gid.as_raw())),
                );
            }
        }
    }
    let me = User::from_uid(geteuid()).unwrap().unwrap();
    let probe = base.join("probe");
    fs::write(&probe, "").unwrap();
    let file_gid = fs::metadata(&probe).unwrap().gid();
    fs::remove_file(probe).unwrap();
    let ids = Command::new("id").arg("-G").output().unwrap();
    let mut gids: Vec<u32> = String::from_utf8(ids.stdout)
        .unwrap()
        .split_whitespace()
        .map(|gid| gid.parse().unwrap())
        .collect();
    gids.sort_unstable();
    gids.dedup();
    let safe_owner = |text: &str| {
        let ok = |part: &str| {
            part.chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        };
        text.split_once(':').is_some_and(|(u, g)| ok(u) && ok(g))
    };
    for gid in gids {
        if gid == file_gid {
            continue;
        }
        if let Ok(Some(group)) = Group::from_gid(Gid::from_raw(gid)) {
            let owner = format!("{}:{}", me.name, group.name);
            if safe_owner(&owner) {
                return (owner, Some((me.uid.as_raw(), gid)));
            }
        }
    }
    let group = Group::from_gid(Gid::from_raw(file_gid)).unwrap().unwrap();
    (format!("{}:{}", me.name, group.name), None)
}

struct Names(Vec<(&'static str, String)>);

impl Names {
    fn sub(&self, text: &str) -> String {
        self.0.iter().fold(text.to_owned(), |text, (key, value)| {
            text.replace(key, value)
        })
    }

    fn sub_all(&self, items: &[String]) -> Vec<String> {
        items.iter().map(|item| self.sub(item)).collect()
    }
}

fn mode(text: &str) -> u32 {
    u32::from_str_radix(text, 8).unwrap()
}

/// The actions of `parity/races.json`.
fn act(action: &[String]) {
    let path = action[1].as_str();
    match (action[0].as_str(), &action[2..]) {
        ("mkdir", []) => fs::create_dir(path).unwrap(),
        ("file", []) => fs::write(path, "new").unwrap(),
        ("fifo", []) => mkfifo(path, Mode::from_bits_truncate(0o600)).unwrap(),
        ("link", [target]) => symlink(target, path).unwrap(),
        ("hardlink", [existing]) => fs::hard_link(existing, path).unwrap(),
        ("remove", []) => fs::remove_file(path).unwrap(),
        ("rename", [to]) => fs::rename(path, to).unwrap(),
        ("chmod", [bits]) => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode(bits))).unwrap();
        }
        ("replace_with_link", [target]) => {
            fs::rename(path, format!("{path}.orig")).unwrap();
            symlink(target, path).unwrap();
        }
        _ => panic!("unknown action {action:?}"),
    }
}

/// `(uid, gid)` of every path below `base`, before `check()`.
fn owners(base: &Path) -> BTreeMap<PathBuf, (u32, u32)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            out.insert(path.clone(), (meta.uid(), meta.gid()));
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    out
}

fn assert_after(
    id: &str,
    names: &Names,
    after: &[Vec<String>],
    before: &BTreeMap<PathBuf, (u32, u32)>,
    new_ids: Option<(u32, u32)>,
) {
    for assertion in after {
        let assertion = names.sub_all(assertion);
        let path = Path::new(&assertion[1]);
        let what = format!("{id}: {assertion:?}");
        if assertion[0] == "absent" {
            assert!(fs::symlink_metadata(path).is_err(), "{what}");
            continue;
        }
        let meta = fs::symlink_metadata(path).unwrap_or_else(|e| panic!("{what}: {e}"));
        match (assertion[0].as_str(), &assertion[2..]) {
            ("mode", [bits]) => assert_eq!(meta.mode() & 0o7777, mode(bits), "{what}"),
            ("owner", [which]) => {
                let expected = if which == "new" {
                    new_ids.unwrap()
                } else {
                    before[path]
                };
                assert_eq!((meta.uid(), meta.gid()), expected, "{what}");
            }
            ("file", []) => assert!(meta.file_type().is_file(), "{what}"),
            ("dir", []) => assert!(meta.file_type().is_dir(), "{what}"),
            ("link", [target]) => {
                assert_eq!(fs::read_link(path).unwrap(), Path::new(target), "{what}");
            }
            ("exists", []) => {}
            _ => panic!("unknown assertion {what}"),
        }
    }
}

fn run(tree: &Tree, scenario: &Scenario) -> Result<(), String> {
    let tmp = tempfile::tempdir().unwrap();
    // macOS: /var is a symlink; the guard walks the canonical path.
    let base = fs::canonicalize(tmp.path()).unwrap();
    let (owner, new_ids) = chown_target(&base);
    let needs_chown = scenario.mutation.is_some()
        || scenario
            .command
            .as_deref()
            .is_some_and(|c| c.starts_with("chown"));
    if needs_chown && new_ids.is_none() {
        eprintln!(
            "{}: skipped, chown scenarios need a second group of the test user (or root)",
            scenario.id
        );
        return Ok(());
    }
    let base_text = base.to_str().unwrap().to_owned();
    let names = Names(vec![
        ("{base}", base_text.clone()),
        ("{root}", format!("{base_text}/root")),
        ("{outside}", format!("{base_text}/outside")),
        ("{owner}", owner.clone()),
    ]);
    for (rel, bits) in &tree.dirs {
        let path = base.join(rel);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode(bits))).unwrap();
    }
    for (rel, bits) in &tree.files {
        let path = base.join(rel);
        fs::write(&path, rel).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode(bits))).unwrap();
    }
    for action in &scenario.setup {
        act(&names.sub_all(action));
    }
    let before = owners(&base);
    let expect = |key: &str| {
        scenario
            .expect
            .get(key)
            .and_then(Value::as_str)
            .map(|text| names.sub(text))
    };

    let mutation: Mutation = if let Some(command) = &scenario.command {
        let command = names.sub(command);
        let policy = parse_policy(
            serde_json::json!({"path_roots": [{"path": names.sub("{root}"), "owner": owner}]})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        match check(command.as_bytes(), &policy, &RealEnv) {
            Err(refused) => {
                if expect("check_refused").as_deref() != Some(refused.reason()) {
                    return Err(format!("check() refused {command:?}: {}", refused.reason()));
                }
                assert_after(&scenario.id, &names, &scenario.after, &before, new_ids);
                return Ok(());
            }
            Ok(decision) => {
                if scenario.expect.contains_key("check_refused") {
                    return Err(format!("check() allowed {command:?}"));
                }
                assert!(decision.argv.is_empty(), "{}", scenario.id);
                decision.mutation.unwrap()
            }
        }
    } else {
        let raw = names.sub(&scenario.mutation.as_ref().unwrap().to_string());
        serde_json::from_str(&raw).unwrap()
    };
    for action in &scenario.before_use {
        act(&names.sub_all(action));
    }
    // Each hook with its paths filled in, and how often its event was seen.
    let mut hooks: Vec<(HookSpec, usize)> = scenario
        .hooks
        .iter()
        .map(|h| {
            let armed = HookSpec {
                event: h.event.clone(),
                path: names.sub(&h.path),
                nth: h.nth,
                actions: h.actions.iter().map(|a| names.sub_all(a)).collect(),
            };
            (armed, 0)
        })
        .collect();
    let result = mutate::perform(&mutation, &RealEnv, &mut |event: &str, path: &str| {
        for (hook, seen) in &mut hooks {
            if hook.event == event && hook.path == path {
                *seen += 1;
                if *seen == hook.nth {
                    for action in &hook.actions {
                        act(action);
                    }
                }
            }
        }
    });
    for (hook, seen) in &hooks {
        if *seen < hook.nth {
            return Err(format!(
                "hook never reached: {} {} #{}",
                hook.event, hook.path, hook.nth
            ));
        }
    }
    match (&result, expect("refused"), expect("refused_prefix")) {
        (Ok(()), None, None) if scenario.expect.get("done") == Some(&Value::Bool(true)) => {}
        (Err(refused), Some(reason), _) if refused.reason() == reason => {}
        (Err(refused), _, Some(prefix)) if refused.reason().starts_with(&prefix) => {}
        _ => {
            return Err(format!(
                "perform() gave {result:?}, expected {:?}",
                scenario.expect
            ));
        }
    }
    assert_after(&scenario.id, &names, &scenario.after, &before, new_ids);
    Ok(())
}

#[test]
fn race_scenarios_of_both_guards() {
    let races = races();
    assert!(races.scenarios.len() >= 40, "the table lost scenarios");
    let failures: Vec<String> = races
        .scenarios
        .iter()
        .filter_map(|scenario| {
            run(&races.tree, scenario)
                .err()
                .map(|error| format!("{}: {error}", scenario.id))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The guard passes a hook that does nothing.
#[test]
fn perform_with_an_empty_hook() {
    let tmp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let file = base.join("f");
    fs::write(&file, "x").unwrap();
    let mutation = Mutation {
        mode: Some(0o600),
        ..Mutation::new("chmod", &[file.to_str().unwrap()])
    };
    mutate::perform(&mutation, &RealEnv, &mut |_, _| {}).unwrap();
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
}
