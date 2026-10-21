//! Process tests of the binary (PLAN.md 3.1, 3.6): the argv grammar,
//! `--version` and `--check-policy`. S4 adds forced-command mode, `--decide`
//! and `--shadow` here (in a container).

mod common;

use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_echoport-command-guard");
const PREFIX: &str = "echoport-remote-command-guard: ";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("SSH_ORIGINAL_COMMAND")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

#[test]
fn version() {
    let output = run(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = text(&output.stdout);
    let rest = stdout
        .strip_prefix(&format!(
            "echoport-command-guard {} (",
            env!("CARGO_PKG_VERSION")
        ))
        .unwrap_or_else(|| panic!("{stdout:?}"));
    let commit = rest.strip_suffix(")\n").unwrap();
    assert!(
        commit == "unknown"
            || ((7..=40).contains(&commit.len())
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "{commit:?}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn usage_errors_exit_2() {
    let usage = "echoport-remote-command-guard: usage: echoport-remote-command-guard <policy.json> | --check-policy <policy.json>\n";
    for args in [
        &[][..],
        &["a", "b"],
        &["--check-policy", "a", "b"],
        &["--decide", "a"],
        &["--version", "x"],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&output.stderr), usage, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn check_policy_accepts_the_test_policies() {
    for name in ["production", "staging"] {
        let path = common::fixtures_dir().join(format!("policies/{name}.json"));
        let output = run(&["--check-policy", path.to_str().unwrap()]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{name}: {}",
            text(&output.stderr)
        );
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
}

#[test]
fn check_policy_refuses_with_the_detail() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cases = [
        ("broken.json", &b"{not json"[..], "invalid policy: "),
        (
            "unit.json",
            br#"{"units": ["a b"]}"#,
            "invalid policy: invalid unit name in policy: 'a b'\n",
        ),
        (
            "list.json",
            b"[]",
            "invalid policy: policy must be a JSON object\n",
        ),
    ];
    for (name, content, expected) in cases {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        let output = run(&["--check-policy", path.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(1), "{name}");
        let stderr = text(&output.stderr);
        assert!(
            stderr.starts_with(&format!("{PREFIX}{expected}")),
            "{name}: {stderr:?}"
        );
        assert!(output.stdout.is_empty());
    }
    let missing = dir.join("missing.json");
    let output = run(&["--check-policy", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).starts_with(&format!("{PREFIX}invalid policy: ")));
}

#[test]
fn forced_command_mode_refuses_until_s4() {
    let policy = common::fixtures_dir().join("policies/staging.json");
    // `<prog> --check-policy` is forced-command mode too, as in Python.
    for (arg, command) in [
        (policy.as_os_str(), None),
        (policy.as_os_str(), Some("systemctl stop marina")),
        (policy.as_os_str(), Some("id")),
        ("--check-policy".as_ref(), Some("id")),
    ] {
        let mut child = Command::new(BIN);
        child.arg(arg).stdin(Stdio::null());
        match command {
            Some(command) => child.env("SSH_ORIGINAL_COMMAND", command),
            None => child.env_remove("SSH_ORIGINAL_COMMAND"),
        };
        let output = child.output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{command:?}");
        assert_eq!(
            text(&output.stderr),
            format!("{PREFIX}command not allowed\n")
        );
        assert!(output.stdout.is_empty());
    }
}
