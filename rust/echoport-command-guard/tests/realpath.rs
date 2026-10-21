//! `pyrealpath` against CPython's `os.path.realpath` (PLAN.md 3.3.6, 4.2,
//! 7.3), through the oracle server `parity/oracle.py`:
//!
//! - over random virtual trees (the oracle's `_FsPatch`), any OS;
//! - over random real trees in a temp directory (`RealEnv`, real `lstat`
//!   and `readlink`, against the real `os.path.realpath`).
//!
//! Property: when Rust resolves a path, Python resolves it to the same
//! string. Rust may refuse where Python returns a path only for the PLAN.md
//! 4.2 classes: a loop or more than 40 links (`ELOOP`), and an `lstat` error
//! other than `ENOENT`/`ENOTDIR` (the virtual trees list some). The Layer-2
//! harness (`parity/e2e/`) repeats the real-tree comparison as root under
//! the hosts' Pythons, 3.12 and 3.13.
//!
//! `PROPTEST_CASES` sets the number of random trees (default 2,000 each;
//! the seed is fixed, `PROPTEST_RNG_SEED` changes it).

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use serde_json::{Map, Value, json};

use common::{Oracle, VirtualTree, naive_realpath};
use echoport_command_guard::env::{GuardEnv, RealEnv};
use echoport_command_guard::policy::is_safe_path;
use echoport_command_guard::pyrealpath::{ResolveFs, realpath};

fn runner(divisor: u32) -> TestRunner {
    let cases: u32 = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2000);
    let seed: u64 = std::env::var("PROPTEST_RNG_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0x5eed_0002);
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    TestRunner::new_with_rng(
        Config {
            cases: (cases / divisor).max(1),
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &bytes),
    )
}

/// What the comparisons saw.
#[derive(Debug, Default)]
struct Tally {
    equal: usize,
    refused_loop: usize,
    refused_lstat_error: usize,
}

/// A component of a link target: names, `.`, `..` and empty ones.
fn target_part() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        6 => prop::sample::select(vec!["a", "b", "c", "r"]),
        2 => Just(".."),
        1 => Just("."),
        1 => Just(""),
    ]
}

fn target() -> impl Strategy<Value = String> {
    (any::<bool>(), prop::collection::vec(target_part(), 0..5)).prop_map(|(absolute, parts)| {
        let joined = parts.join("/");
        if absolute {
            format!("/{joined}")
        } else {
            joined
        }
    })
}

/// The paths a tree may list: `/r` and below, depth 3, names `a b c`.
fn tree_paths() -> Vec<String> {
    let mut paths = vec!["/r".to_owned()];
    let mut level = vec!["/r".to_owned()];
    for _ in 0..3 {
        let next: Vec<String> = level
            .iter()
            .flat_map(|parent| ["a", "b", "c"].map(|name| format!("{parent}/{name}")))
            .collect();
        paths.extend(next.iter().cloned());
        level = next;
    }
    paths
}

#[derive(Debug, Clone)]
enum Node {
    Dir,
    File,
    Link(String),
    Error(&'static str),
}

fn node() -> impl Strategy<Value = Option<Node>> {
    prop_oneof![
        5 => Just(None),
        4 => Just(Some(Node::Dir)),
        2 => Just(Some(Node::File)),
        4 => target().prop_map(|target| Some(Node::Link(target))),
        1 => prop::sample::select(vec!["EACCES", "ENAMETOOLONG", "EIO"])
            .prop_map(|errno| Some(Node::Error(errno))),
    ]
}

/// A probe: a safe path under `/` (PLAN.md 3.3.6: realpath only ever sees
/// paths `_is_safe_path` accepts), sometimes with a trailing `/`.
fn probe() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(prop::sample::select(vec!["a", "b", "c"]), 0..5),
        any::<bool>(),
        prop::sample::select(vec!["/r", "/r", "/r", "/x"]),
    )
        .prop_map(|(parts, slash, start)| {
            let mut path = start.to_owned();
            for part in parts {
                path.push('/');
                path.push_str(part);
            }
            if slash {
                path.push('/');
            }
            path
        })
}

fn strerror(errno: &str) -> &'static str {
    match errno {
        "EACCES" => "Permission denied",
        "ENAMETOOLONG" => "File name too long",
        _ => "Input/output error",
    }
}

fn virtual_tree(nodes: &[Option<Node>]) -> Map<String, Value> {
    let mut fs = Map::new();
    for (path, node) in tree_paths().into_iter().zip(nodes) {
        let entry = match node {
            None => continue,
            Some(Node::Dir) => json!({"kind": "dir", "mode": 0o755, "uid": 0, "nlink": 2}),
            Some(Node::File) => json!({"kind": "reg", "mode": 0o644, "uid": 0, "nlink": 1}),
            Some(Node::Link(target)) => {
                json!({"kind": "lnk", "mode": 0o777, "uid": 0, "nlink": 1, "target": target})
            }
            Some(Node::Error(errno)) => json!({"errno": errno, "strerror": strerror(errno)}),
        };
        fs.insert(path, entry);
    }
    fs
}

/// The 4.2 rule for one path. A loop refusal must be one: the naive
/// resolver (no `seen` map) must not finish with 10,000 links.
fn compare(
    fs: &dyn ResolveFs,
    path: &str,
    python: Result<String, String>,
    lstat_errnos: &[&str],
    tally: &mut Tally,
) -> Result<(), String> {
    let rust = realpath(fs, path).map_err(|error| error.errno);
    match (&rust, &python) {
        (Ok(rust), Ok(python)) if rust == python => tally.equal += 1,
        (Err(errno), Ok(_)) if errno == "ELOOP" => {
            if let Some(naive) = naive_realpath(fs, path, 10_000) {
                return Err(format!(
                    "{path}: Rust refuses a loop, but it resolves to {naive:?}"
                ));
            }
            tally.refused_loop += 1;
        }
        (Err(errno), Ok(_)) if lstat_errnos.contains(&errno.as_str()) => {
            tally.refused_lstat_error += 1;
        }
        _ => return Err(format!("{path}: Rust {rust:?}, Python {python:?}")),
    }
    Ok(())
}

#[test]
fn virtual_trees_resolve_like_python() {
    let oracle = RefCell::new(Oracle::start());
    let tally = RefCell::new(Tally::default());
    let count = tree_paths().len();
    let strategy = (
        prop::collection::vec(node(), count),
        prop::collection::vec(probe(), 1..6),
    );
    runner(1)
        .run(&strategy, |(nodes, probes)| {
            let fs = virtual_tree(&nodes);
            let errnos: Vec<String> = fs
                .values()
                .filter_map(|entry| entry.get("errno").and_then(Value::as_str))
                .map(str::to_owned)
                .collect();
            let errnos: Vec<&str> = errnos.iter().map(String::as_str).collect();
            let tree = VirtualTree(fs.clone());
            let fs = Value::Object(fs);
            for path in probes {
                assert!(is_safe_path(&path), "{path}");
                let python = oracle.borrow_mut().realpath_virtual(&path, &fs);
                compare(&tree, &path, python, &errnos, &mut tally.borrow_mut())
                    .map_err(|message| TestCaseError::fail(format!("{message}\n{fs}")))?;
            }
            Ok(())
        })
        .unwrap();
    let tally = tally.into_inner();
    eprintln!("virtual trees: {tally:?}");
    assert!(tally.equal > 4 * (tally.refused_loop + tally.refused_lstat_error));
    assert!(tally.refused_loop > 0 && tally.refused_lstat_error > 0);
}

/// Fixed virtual cases, with Python's answers checked in as well as asked.
#[test]
fn virtual_cases() {
    let mut oracle = Oracle::start();
    let dir = json!({"kind": "dir", "mode": 0o755, "uid": 0, "nlink": 2});
    let file = json!({"kind": "reg", "mode": 0o644, "uid": 0, "nlink": 1});
    let link = |target: &str| json!({"kind": "lnk", "mode": 0o777, "uid": 0, "nlink": 1, "target": target});
    let cases: Vec<(&str, Value, Result<&str, &str>)> = vec![
        // `..` in a target applies to the resolved path.
        (
            "/a/link/x",
            json!({"/a": dir, "/a/link": link("../b/c/.."), "/b": dir}),
            Ok("/b/x"),
        ),
        // A dangling link is followed by its text.
        (
            "/a/dangling/y",
            json!({"/a": dir, "/a/dangling": link("/etc/missing/z")}),
            Ok("/etc/missing/z/y"),
        ),
        // Missing components are appended literally.
        (
            "/a/no/such/path/",
            json!({"/a": dir}),
            Ok("/a/no/such/path"),
        ),
        // Below a file: ENOTDIR, appended literally.
        (
            "/a/file/x",
            json!({"/a": dir, "/a/file": file}),
            Ok("/a/file/x"),
        ),
        // A chain, and a link met twice (cached).
        (
            "/l1/l1",
            json!({"/l1": link("l2"), "/l2": link("/d"), "/d": dir, "/d/l1": link("/l1")}),
            Ok("/d"),
        ),
        // `//` and repeated slashes.
        ("//", json!({}), Ok("/")),
        ("/a//b///", json!({"/a": dir}), Ok("/a/b")),
        // An absolute target restarts at `/`, `..` stops at `/`.
        (
            "/a/up/x",
            json!({"/a": dir, "/a/up": link("/../../e")}),
            Ok("/e/x"),
        ),
        // Loops: Python returns a partial path, Rust refuses.
        (
            "/l1/x",
            json!({"/l1": link("/l2"), "/l2": link("/l1")}),
            Err("ELOOP"),
        ),
        ("/self", json!({"/self": link("self")}), Err("ELOOP")),
        (
            "/a/l",
            json!({"/a": dir, "/a/l": link("/a/l/..")}),
            Err("ELOOP"),
        ),
        // lstat errors other than ENOENT/ENOTDIR refuse.
        (
            "/a/x",
            json!({"/a": {"errno": "EACCES", "strerror": "Permission denied"}}),
            Err("EACCES"),
        ),
    ];
    for (path, fs, expected) in cases {
        let tree = VirtualTree(fs.as_object().unwrap().clone());
        let rust = realpath(&tree, path).map_err(|error| error.errno);
        let python = oracle.realpath_virtual(path, &fs);
        assert_eq!(
            rust.as_deref().map_err(String::as_str),
            expected,
            "{path} {fs}"
        );
        match expected {
            Ok(resolved) => assert_eq!(python.as_deref(), Ok(resolved), "{path}"),
            Err(errno) => {
                assert!(python.is_ok(), "{path}: Python {python:?}");
                if errno == "ELOOP" {
                    assert_eq!(naive_realpath(&tree, path, 10_000), None, "{path}");
                }
            }
        }
    }
}

/// More than 40 links refuse; 40 resolve as in Python.
#[test]
fn link_limit() {
    let mut oracle = Oracle::start();
    for (length, refused) in [(40, false), (41, true)] {
        let mut fs = Map::new();
        for i in 0..length {
            let target = if i + 1 == length {
                "/end".to_owned()
            } else {
                format!("/l{}", i + 1)
            };
            fs.insert(
                format!("/l{i}"),
                json!({"kind": "lnk", "mode": 0o777, "uid": 0, "nlink": 1, "target": target}),
            );
        }
        let rust = realpath(&VirtualTree(fs.clone()), "/l0/x").map_err(|error| error.errno);
        let python = oracle.realpath_virtual("/l0/x", &Value::Object(fs));
        assert_eq!(python.as_deref(), Ok("/end/x"));
        let expected = if refused { Err("ELOOP") } else { Ok("/end/x") };
        assert_eq!(rust.as_deref().map_err(String::as_str), expected);
    }
}

/// Builds `nodes` under `base` on the real filesystem (dirs before what is
/// inside them; a node under a non-directory is skipped). Absolute link
/// targets are made absolute below `base`.
fn build_real_tree(base: &Path, nodes: &[Option<Node>]) {
    for (path, node) in tree_paths().into_iter().zip(nodes) {
        let real = base.join(path.trim_start_matches('/'));
        // Never through a link: a relative target can point out of `base`.
        let parent_is_dir = real
            .parent()
            .unwrap()
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_dir());
        if !parent_is_dir || real.symlink_metadata().is_ok() {
            continue;
        }
        match node {
            None | Some(Node::Error(_)) => {}
            Some(Node::Dir) => std::fs::create_dir(&real).unwrap(),
            Some(Node::File) => std::fs::write(&real, b"x").unwrap(),
            Some(Node::Link(target)) => {
                let target = match target.strip_prefix('/') {
                    Some(rest) => format!("{}/{rest}", base.display()),
                    None => target.clone(),
                };
                std::os::unix::fs::symlink(target, &real).unwrap();
            }
        }
    }
}

#[test]
fn real_trees_resolve_like_python() {
    let oracle = RefCell::new(Oracle::start());
    let tally = RefCell::new(Tally::default());
    let count = tree_paths().len();
    let strategy = (
        prop::collection::vec(node(), count),
        prop::collection::vec(probe(), 1..6),
    );
    // Real trees are slower: a quarter of the virtual count.
    runner(4)
        .run(&strategy, |(nodes, probes)| {
            let scratch = tempfile::tempdir().unwrap();
            let base = scratch.path().to_str().unwrap().to_owned();
            build_real_tree(scratch.path(), &nodes);
            for probe in probes {
                let path = format!("{base}{probe}");
                if !is_safe_path(&path) {
                    return Err(TestCaseError::reject("temp dir is not a safe path"));
                }
                let python = oracle.borrow_mut().realpath_os(&path);
                compare(&RealEnv, &path, python, &[], &mut tally.borrow_mut())
                    .map_err(TestCaseError::fail)?;
            }
            Ok(())
        })
        .unwrap();
    let tally = tally.into_inner();
    eprintln!("real trees: {tally:?}");
    assert!(tally.equal > 4 * tally.refused_loop);
    assert_eq!(tally.refused_lstat_error, 0);
}

/// `RealEnv`: the lookups `check()` makes, on a real temp directory.
#[test]
fn real_env_lookups() {
    use echoport_command_guard::env::FileKind;
    use std::os::unix::fs::PermissionsExt;

    let env: &dyn GuardEnv = &RealEnv;
    let scratch = tempfile::tempdir().unwrap();
    let base = scratch.path().to_str().unwrap();
    let path = |name: &str| format!("{base}/{name}");
    std::fs::write(path("file"), b"x").unwrap();
    std::fs::set_permissions(path("file"), std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::hard_link(path("file"), path("hard")).unwrap();
    std::fs::create_dir(path("dir")).unwrap();
    std::fs::set_permissions(path("dir"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink("file", path("link")).unwrap();
    std::os::unix::fs::symlink("missing", path("dangling")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(path("sock")).unwrap();
    let mkfifo = std::process::Command::new("mkfifo")
        .arg(path("fifo"))
        .status()
        .unwrap();
    assert!(mkfifo.success());

    let euid = env.euid();
    let id = std::process::Command::new("id").arg("-u").output().unwrap();
    assert_eq!(
        String::from_utf8(id.stdout).unwrap().trim(),
        euid.to_string()
    );

    let mut kinds = BTreeMap::new();
    for name in ["file", "hard", "dir", "link", "dangling", "sock", "fifo"] {
        let stat = env.lstat(&path(name)).unwrap().unwrap();
        assert_eq!(stat.uid, euid, "{name}");
        kinds.insert(name, (stat.kind, stat.nlink));
        if name == "file" {
            assert_eq!(stat.mode, 0o640);
        }
        if name == "dir" {
            assert_eq!(stat.mode, 0o700);
        }
    }
    assert_eq!(kinds["file"], (FileKind::Reg, 2));
    assert_eq!(kinds["dir"].0, FileKind::Dir);
    assert_eq!(kinds["link"], (FileKind::Lnk, 1));
    assert_eq!(kinds["dangling"].0, FileKind::Lnk);
    assert_eq!(kinds["sock"].0, FileKind::Sock);
    assert_eq!(kinds["fifo"].0, FileKind::Fifo);
    assert_eq!(env.lstat("/dev/null").unwrap().unwrap().kind, FileKind::Chr);

    assert_eq!(env.lstat(&path("missing")), Ok(None));
    let below_file = env.lstat(&path("file/x")).unwrap_err();
    assert_eq!(
        (below_file.errno.as_str(), below_file.strerror.as_str()),
        ("ENOTDIR", "Not a directory")
    );
    let too_long = env
        .lstat(&format!("{base}/{}", "x".repeat(300)))
        .unwrap_err();
    assert_eq!(
        (too_long.errno.as_str(), too_long.strerror.as_str()),
        ("ENAMETOOLONG", "File name too long")
    );
    assert_eq!(env.lstat("/a\0b").unwrap_err().errno, "EINVAL");

    // realpath through the real tree, dangling link followed.
    assert_eq!(
        env.realpath(&path("dangling/x")).unwrap(),
        format!("{}/missing/x", RealEnv.realpath(base).unwrap())
    );
    // A component too long refuses (PLAN.md 4.2).
    assert_eq!(
        env.realpath(&format!("{base}/{}", "x".repeat(300)))
            .unwrap_err()
            .errno,
        "ENAMETOOLONG"
    );

    // Users through NSS.
    assert_eq!(env.uid_of("root"), Some(0));
    assert_eq!(env.uid_of("echoport-no-such-user"), None);
    assert_eq!(env.uid_of(""), None);
}

/// A link target that is not UTF-8 refuses (PLAN.md 4.2). Linux only: APFS
/// does not keep arbitrary bytes in link targets.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_link_target_refuses() {
    use std::os::unix::ffi::OsStrExt;
    let scratch = tempfile::tempdir().unwrap();
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(b"\xff"), &link).unwrap();
    let error = RealEnv
        .realpath(&format!("{}/x", link.to_str().unwrap()))
        .unwrap_err();
    assert_eq!(error.errno, "EILSEQ");
}
