//! Process tests of the binary (PLAN.md 3.1, 3.6): the argv grammar,
//! `--version`, `--check-policy`, and forced-command mode, `--decide` and
//! `--shadow` with the real `check()` and syslog. What an allowed command
//! inherits is `tests/flow.rs` (it needs a stub `check()` until S3a/S3b).

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
        &["--decide", "a", "b"],
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

fn guard(args: &[&std::ffi::OsStr], command: Option<&str>) -> Output {
    let mut child = Command::new(BIN);
    child
        .args(args)
        .env("SSH_CLIENT", "192.0.2.10 50000 22")
        .stdin(Stdio::null());
    match command {
        Some(command) => child.env("SSH_ORIGINAL_COMMAND", command),
        None => child.env_remove("SSH_ORIGINAL_COMMAND"),
    };
    child.output().unwrap()
}

#[test]
fn forced_command_mode_refuses() {
    let policy = common::fixtures_dir().join("policies/staging.json");
    let policy = policy.as_os_str();
    // `GuardMain.test_interactive_session_is_refused`.
    let output = guard(&[policy], None);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stderr),
        format!("{PREFIX}interactive sessions are not allowed\n")
    );
    assert!(output.stdout.is_empty());
    // `GuardMain.test_refused_command_is_not_executed`; `systemctl` is a
    // branch S3a ports, and refuses until then.
    for command in ["id", "systemctl stop marina", "sh -c id", "cat\u{a0}x"] {
        let output = guard(&[policy], Some(command));
        assert_eq!(output.status.code(), Some(1), "{command:?}");
        assert_eq!(
            text(&output.stderr),
            format!("{PREFIX}command not allowed\n")
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn broken_policy_refuses_everything() {
    // `GuardMain.test_broken_policy_refuses_everything`, and `<prog>
    // --check-policy` with two arguments, which is forced-command mode with
    // the policy file `--check-policy`, as in Python.
    let tmp = tempfile::tempdir().unwrap();
    let mut policies = vec![tmp.path().join("missing.json")];
    for (n, broken) in ["{not json", "[]", r#"{"units": ["a b"]}"#]
        .iter()
        .enumerate()
    {
        let path = tmp.path().join(format!("{n}.json"));
        std::fs::write(&path, broken).unwrap();
        policies.push(path);
    }
    policies.push("--check-policy".into());
    for policy in &policies {
        let output = guard(
            &[policy.as_os_str()],
            Some("systemctl start marina.service"),
        );
        assert_eq!(output.status.code(), Some(1), "{policy:?}");
        assert_eq!(text(&output.stderr), format!("{PREFIX}policy error\n"));
        assert!(output.stdout.is_empty());
        // Interactive is refused before the policy is read.
        let output = guard(&[policy.as_os_str()], None);
        assert_eq!(
            text(&output.stderr),
            format!("{PREFIX}interactive sessions are not allowed\n")
        );
    }
}

#[test]
fn decide_prints_the_decision_only() {
    let policy = common::fixtures_dir().join("policies/staging.json");
    let decide = |command| guard(&["--decide".as_ref(), policy.as_os_str()], command);
    let output = decide(Some("id"));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output.stdout),
        "{\"reason\":\"command not allowed: 'id'\",\"verdict\":\"refused\"}\n"
    );
    assert!(output.stderr.is_empty());
    // S3a's `systemctl` branch allows this; `--decide` never executes it.
    let output = decide(Some("systemctl start marina.service"));
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        text(&output.stdout),
        "{\"argv\":[\"systemctl\",\"start\",\"marina.service\"],\"stdin\":null,\"stdout\":null,\"umask\":null,\"verdict\":\"allowed\"}\n"
    );
    assert!(output.stderr.is_empty());
    let output = decide(None);
    assert_eq!(text(&output.stdout), "{\"verdict\":\"interactive\"}\n");
    let output = guard(
        &["--decide".as_ref(), "/nonexistent.json".as_ref()],
        Some("id"),
    );
    assert_eq!(output.status.code(), Some(1));
    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["verdict"], "policy-error");
    assert_eq!(record["error_type"], "FileNotFoundError");
}

#[test]
fn shadow_requires_the_python_guards_forced_command() {
    let policy = "/etc/echoport/remote-command-guard.json";
    let usage = "echoport-remote-command-guard: usage: echoport-remote-command-guard --shadow <policy.json> </abs/python> -I </abs/guard> <policy.json>\n";
    for args in [
        &["--shadow", policy][..],
        &[
            "--shadow",
            policy,
            "/usr/bin/python3",
            "-I",
            "/g",
            "/other.json",
        ],
        &["--shadow", policy, "python3", "-I", "/g", policy],
        &["--shadow", policy, "/usr/bin/python3", "-I", "g", policy],
        &["--shadow", policy, "/usr/bin/python3", "-E", "/g", policy],
        &[
            "--shadow",
            policy,
            "/usr/bin/python3",
            "-I",
            "/g",
            policy,
            "x",
        ],
        &["--shadow", policy, "/usr/bin/python3", "/g", policy],
    ] {
        let args: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_ref()).collect();
        let output = guard(&args, Some("id"));
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&output.stderr), usage, "{args:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn shadow_execs_the_python_guard_with_the_same_pid() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let python = tmp.path().join("python3");
    std::fs::write(
        &python,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$$\" \"$@\" \"$PATH\" \"${{LC_CTYPE-unset}}\" > '{}'\nexit 7\n",
            out.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();
    let policy = common::fixtures_dir().join("policies/staging.json");
    let policy = policy.to_str().unwrap();
    let guard_py = "/usr/local/sbin/echoport-remote-command-guard";
    for command in [Some("id"), None] {
        let mut child = Command::new(BIN);
        child
            .args([
                "--shadow",
                policy,
                python.to_str().unwrap(),
                "-I",
                guard_py,
                policy,
            ])
            .env("PATH", "/evil")
            .env_remove("LC_CTYPE")
            .env_remove("LC_ALL")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match command {
            Some(command) => child.env("SSH_ORIGINAL_COMMAND", command),
            None => child.env_remove("SSH_ORIGINAL_COMMAND"),
        };
        let child = child.spawn().unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(7), "{}", text(&output.stderr));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            format!("{pid}\n-I\n{guard_py}\n{policy}\n/evil\nunset\n")
        );
    }
    // A Python that cannot be executed: 127, and nothing else runs.
    let output = guard(
        &[
            "--shadow".as_ref(),
            policy.as_ref(),
            "/nonexistent/python3".as_ref(),
            "-I".as_ref(),
            guard_py.as_ref(),
            policy.as_ref(),
        ],
        Some("id"),
    );
    assert_eq!(output.status.code(), Some(127));
    assert_eq!(
        text(&output.stderr),
        format!("{PREFIX}cannot run /nonexistent/python3: No such file or directory\n")
    );
}
