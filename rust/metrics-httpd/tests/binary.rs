//! Process-level tests of the built binary: `--version` and usage errors
//! (PLAN.md 4.8, 4.9; PLAN-foundation.md slice F1).

use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_metrics-httpd");
/// The commit `build.rs` embedded into this build of the package.
const COMMIT: &str = env!("METRICS_HTTPD_GIT_COMMIT");

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

fn is_commit(value: &str) -> bool {
    value == "unknown"
        || (7..=40).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn version_names_crate_version_and_commit() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let line = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        line,
        format!("metrics-httpd {} ({COMMIT})\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(is_commit(COMMIT), "{COMMIT:?}");
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &[][..],
        &["--bogus"],
        &["--version", "--version"],
        &["version"],
        &["json-file"],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "usage: metrics-httpd --version\n",
            "{args:?}"
        );
    }
}
