//! software-live: read-only Linux software observations and their
//! authenticated endpoint, the Rust port of `software_live.py`
//! (`rust/software-live/PLAN.md`).
//!
//! Command line (PLAN.md 3.1), as the Python `argparse` parser: one mode
//! (`collect | serve | validate | export-inventory`) and the options
//! `--config`, `--config-json`, `--output`, `--cache`, `--group`, accepted
//! with every mode, in any order, as `--opt value` or `--opt=value`, by any
//! unambiguous prefix, the last occurrence winning. Usage errors exit 2.
//! New and only additive: `--version` (`software-live <version> (<commit>)`).
//!
//! Slice S2 implements `validate` and the shared parts of the other modes
//! (configuration loading and policy validation for `collect`, the argument
//! check of `export-inventory`); `collect` (S3f), `serve` (S4) and
//! `export-inventory` (S3e) then stop with exit 1.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser, ValueEnum};
use serde_json::Value;

use software_live::error::PyError;
use software_live::policy::{self, Policy};
use software_live::probe::{HostSystem, System};
use software_live::pyjson;

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("SOFTWARE_LIVE_GIT_COMMIT"),
    ")"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    Collect,
    Serve,
    Validate,
    ExportInventory,
}

/// Read-only Linux software observations; no package updates or service mutations.
#[derive(Debug, Parser)]
#[command(
    name = "software-live",
    version = VERSION,
    disable_version_flag = true,
    args_override_self = true,
    infer_long_args = true
)]
struct Cli {
    #[arg(value_enum)]
    mode: Mode,
    #[arg(long, value_name = "CONFIG")]
    config: Option<PathBuf>,
    #[arg(
        long = "config-json",
        value_name = "CONFIG_JSON",
        allow_negative_numbers = true
    )]
    config_json: Option<OsString>,
    #[arg(long, value_name = "OUTPUT")]
    output: Option<PathBuf>,
    #[arg(long, value_name = "CACHE")]
    cache: Option<PathBuf>,
    #[arg(long, value_name = "GROUP")]
    group: Option<OsString>,
    /// Print the version and the commit it was built from.
    #[arg(long, action = ArgAction::Version)]
    version: Option<bool>,
}

/// A fatal error: one line on stderr, exit 1 (PLAN.md 3.8, 4.2 item 7).
/// The line names the error class and our own message, never a credential
/// or a policy value other than the host.
struct Fatal(String);

impl From<PyError> for Fatal {
    fn from(error: PyError) -> Self {
        Self(error.to_string())
    }
}

/// The JSON configuration of `collect`, `serve` and `validate`:
/// `--config-json` if it is non-empty, else the file `--config`.
fn load_config(cli: &Cli, system: &impl System) -> Result<Value, Fatal> {
    let text = match cli.config_json.as_ref().filter(|json| !json.is_empty()) {
        Some(json) => json
            .clone()
            .into_string()
            .map_err(|_| PyError::new("UnicodeDecodeError", "--config-json is not valid UTF-8"))?,
        None => {
            let path = cli.config.as_ref().ok_or_else(|| {
                PyError::new("AttributeError", "--config or --config-json is required")
            })?;
            let bytes = system.read_file(path).map_err(|error| {
                let mut py = PyError::os(&error);
                py.message = format!("{}: {}", py.message, path.display());
                py
            })?;
            String::from_utf8(bytes)
                .map_err(|error| PyError::new("UnicodeDecodeError", error.to_string()))?
        }
    };
    Ok(pyjson::loads(&text)?)
}

fn not_implemented(mode: &str, slice: &str) -> Fatal {
    Fatal(format!(
        "{mode} is not implemented yet (PLAN.md slice {slice})"
    ))
}

fn run(cli: &Cli, system: &impl System) -> Result<(), Fatal> {
    if cli.mode == Mode::ExportInventory {
        // `software_live.py:895-902`: any failure is this one line.
        let missing = cli.config.is_none()
            || cli.output.is_none()
            || cli.group.as_ref().is_none_or(|group| group.is_empty());
        if missing {
            return Err(Fatal("inventory export failed: ValueError".into()));
        }
        return Err(not_implemented("export-inventory", "S3e"));
    }
    let config = load_config(cli, system)?;
    match cli.mode {
        Mode::Validate => {
            policy::validate(&config).map_err(|error| Fatal(format!("invalid policy: {error}")))?;
            Ok(())
        }
        Mode::Collect => {
            Policy::new(config).map_err(|error| Fatal(format!("invalid policy: {error}")))?;
            Err(not_implemented("collect", "S3f"))
        }
        Mode::Serve => Err(not_implemented("serve", "S4")),
        Mode::ExportInventory => unreachable!("handled above"),
    }
}

fn main() -> ExitCode {
    // Help and --version exit 0, usage errors 2 (as argparse).
    let cli = Cli::parse();
    match run(&cli, &HostSystem) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fatal(line)) => {
            if line.starts_with("inventory export failed: ") {
                eprintln!("{line}");
            } else {
                eprintln!("software-live: {line}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn options_follow_argparse() {
        let cli = Cli::try_parse_from([
            "software-live",
            "--out=/a",
            "validate",
            "--config",
            "/b",
            "--config-j",
            "-1",
        ])
        .unwrap();
        assert_eq!(cli.mode, Mode::Validate);
        assert_eq!(cli.config, Some(PathBuf::from("/b")));
        assert_eq!(cli.output, Some(PathBuf::from("/a")));
        assert_eq!(cli.config_json, Some(OsString::from("-1")));
        // A prefix of two options is ambiguous, as in argparse.
        assert!(Cli::try_parse_from(["software-live", "validate", "--conf", "/a"]).is_err());
        assert!(Cli::try_parse_from(["software-live", "validate", "--conf=/a"]).is_err());
    }
}
