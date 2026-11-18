//! Embeds the git commit into `software-live-apt --version`
//! (`software-live/PLAN.md` 5.2, PLAN-foundation.md section 4).
//!
//! Source of the commit, in order: `SOFTWARE_LIVE_APT_GIT_COMMIT` (set by the
//! release workflow), `git rev-parse HEAD`, else `unknown`. The value must be
//! 7 to 40 lowercase hex digits (or `unknown`); anything else fails the build.
//! Copied from `software-live/build.rs` (the same lineage: `metrics-httpd`,
//! `mailgun-relay:rust/build.rs`, `nyxmon:agent-rs/crates/nyxmon-agent/build.rs`).

use std::path::{Path, PathBuf};
use std::process::Command;

const ENV: &str = "SOFTWARE_LIVE_APT_GIT_COMMIT";

fn is_commit(value: &str) -> bool {
    (7..=40).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

/// Paths whose change means HEAD may have moved: the HEAD file,
/// `packed-refs`, and the nearest existing directory above the branch's loose
/// ref (a packed branch gets a new loose file there on its next commit).
fn git_head_paths() -> Vec<PathBuf> {
    let git_path = |name: &str| {
        git(&["rev-parse", "--path-format=absolute", "--git-path", name]).map(PathBuf::from)
    };
    let mut paths = Vec::new();
    paths.extend(git_path("HEAD"));
    paths.extend(git_path("packed-refs").filter(|path| path.exists()));
    if let Some(file) = git(&["symbolic-ref", "-q", "HEAD"]).and_then(|r| git_path(&r)) {
        paths.extend(
            file.ancestors()
                .skip(1)
                .find(|dir| dir.is_dir())
                .map(Path::to_path_buf),
        );
    }
    paths
}

fn main() {
    println!("cargo:rerun-if-env-changed={ENV}");
    println!("cargo:rerun-if-changed=build.rs");
    let commit = match std::env::var(ENV) {
        Ok(value) if !value.is_empty() => {
            assert!(
                is_commit(&value),
                "{ENV} must be 7 to 40 lowercase hex digits, got {value:?}"
            );
            value
        }
        _ => {
            for path in git_head_paths() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
            git(&["rev-parse", "HEAD"])
                .filter(|value| is_commit(value))
                .unwrap_or_else(|| "unknown".to_owned())
        }
    };
    println!("cargo:rustc-env={ENV}={commit}");
}
