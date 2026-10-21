//! The command line of `software-live` against the Python program's exit
//! codes (`fixtures/cli.json`, PLAN.md 3.1): every case runs the real
//! binary with the argv the Python program got, in a directory with the
//! same files.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Deserialize;

#[derive(Deserialize)]
struct Fixtures {
    files: BTreeMap<String, String>,
    binary_files: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    argv: Vec<String>,
    exit: i32,
    #[serde(default)]
    stderr: Option<String>,
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_software-live")
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn write_files(dir: &Path, fixtures: &Fixtures) {
    for (name, text) in &fixtures.files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    for (name, hex) in &fixtures.binary_files {
        std::fs::write(dir.join(name), decode_hex(hex)).unwrap();
    }
}

#[test]
fn exit_codes_match_python() {
    let fixtures: Fixtures = serde_json::from_str(include_str!("../fixtures/cli.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), &fixtures);
    let dir_text = dir.path().to_str().unwrap();
    assert!(fixtures.cases.len() >= 30);
    for case in &fixtures.cases {
        let argv: Vec<String> = case
            .argv
            .iter()
            .map(|arg| arg.replace("{dir}", dir_text))
            .collect();
        let output = Command::new(binary())
            .args(&argv)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(case.exit),
            "{}: {output:?}",
            case.id
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        if let Some(expected) = &case.stderr {
            assert_eq!(&stderr, expected, "{}", case.id);
        }
        let help = case
            .argv
            .iter()
            .any(|a| a.starts_with("-h") || a.starts_with("--he"));
        if case.exit == 0 && !help {
            assert!(
                output.stdout.is_empty(),
                "{}: validate prints nothing",
                case.id
            );
            assert!(stderr.is_empty(), "{}", case.id);
        }
        if case.exit == 1 {
            // One line, never a traceback (PLAN.md 3.8, 4.2 item 7).
            assert_eq!(stderr.lines().count(), 1, "{}: {stderr}", case.id);
        }
    }
}

#[test]
fn version_names_the_crate_version_and_the_commit() {
    let output = Command::new(binary()).arg("--version").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let rest = text
        .strip_prefix(concat!("software-live ", env!("CARGO_PKG_VERSION"), " ("))
        .unwrap_or_else(|| panic!("{text:?}"));
    let commit = rest.strip_suffix(")\n").unwrap();
    assert!(
        commit == "unknown"
            || ((7..=40).contains(&commit.len())
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "{commit:?}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn the_error_line_never_quotes_a_policy_value() {
    let secret = "do-not-print-me";
    let policy = format!(r#"{{"host": "h", "traefik": {{"expected": true, "unit": "{secret}"}}}}"#);
    let output = Command::new(binary())
        .args(["validate", "--config-json", &policy])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("ValueError: invalid Traefik policy"),
        "{stderr}"
    );
    assert!(!stderr.contains(secret), "{stderr}");
}

#[test]
fn serve_stops_with_exit_1_until_its_slice() {
    let output = Command::new(binary())
        .args(["serve", "--config-json", "{}"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not implemented yet"), "{stderr}");
}

/// `collect --report-usage` (PLAN.md 3.1): one usage line on stderr after
/// the run, also after a failed one; other modes ignore the flag. (A
/// successful `collect` is not run here: it would read this host and ask
/// GitHub and endoflife.date; `collect::tests` run it in recorded worlds.)
#[test]
fn report_usage_adds_one_line_to_collect() {
    let usage = regex::Regex::new(
        r"^software-live: usage wall_s=\d+\.\d{3} cpu_s=\d+\.\d{3} maxrss_kib=\d+ self_cpu_s=\d+\.\d{3} self_maxrss_kib=\d+ children_cpu_s=\d+\.\d{3} children_maxrss_kib=\d+$",
    )
    .unwrap();
    for flag in ["--report-usage", "--rep"] {
        let output = Command::new(binary())
            .args(["collect", flag, "--config-json", r#"{"host": ""}"#])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{flag}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        let lines: Vec<_> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{stderr}");
        assert!(lines[0].starts_with("software-live: invalid policy: ValueError"));
        assert!(usage.is_match(lines[1]), "{stderr}");
    }
    let output = Command::new(binary())
        .args([
            "validate",
            "--report-usage",
            "--config-json",
            r#"{"host": ""}"#,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8(output.stderr).unwrap().lines().count(), 1);
    // A flag, not an option with a value; a usage error as in argparse.
    for argv in [
        &["collect", "--report-usage=yes"][..],
        &["collect", "--group", "--report-usage"],
    ] {
        let output = Command::new(binary()).args(argv).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{argv:?}");
    }
}
