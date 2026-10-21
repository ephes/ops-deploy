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
//! `validate` (S2) and `export-inventory` (S3e) are complete; `collect`
//! validates its policy and `serve` reads its configuration, then both stop
//! with exit 1 until their slices (S3f, S4).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use std::sync::LazyLock;

use clap::{ArgAction, CommandFactory, Parser, ValueEnum};
use regex::Regex;
use serde_json::Value;

use software_live::error::PyError;
use software_live::export;
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
    // Values may start with `-`: `check_option_values` has already refused
    // the ones argparse reads as an option.
    #[arg(long, value_name = "CONFIG", allow_hyphen_values = true)]
    config: Option<PathBuf>,
    #[arg(
        long = "config-json",
        value_name = "CONFIG_JSON",
        allow_hyphen_values = true
    )]
    config_json: Option<OsString>,
    #[arg(long, value_name = "OUTPUT", allow_hyphen_values = true)]
    output: Option<PathBuf>,
    #[arg(long, value_name = "CACHE", allow_hyphen_values = true)]
    cache: Option<PathBuf>,
    #[arg(long, value_name = "GROUP", allow_hyphen_values = true)]
    group: Option<OsString>,
    /// Print the version and the commit it was built from.
    #[arg(long, action = ArgAction::Version)]
    version: Option<bool>,
}

/// The long options; `--version` is the only one argparse does not have.
const LONG_OPTIONS: [&str; 7] = [
    "--config",
    "--config-json",
    "--output",
    "--cache",
    "--group",
    "--help",
    "--version",
];
const VALUE_OPTIONS: [&str; 5] = [
    "--config",
    "--config-json",
    "--output",
    "--cache",
    "--group",
];

/// argparse's `_negative_number_matcher` of Python 3.12 and 3.13 (the
/// hosts' versions; 3.14 also accepts `-1e5` and `-1.`).
static NEGATIVE_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-\d+$|^-\d*\.\d+$").expect("valid pattern"));

/// A long option by its exact name or an unambiguous prefix.
fn resolve_long(name: &str) -> Option<&'static str> {
    if let Some(exact) = LONG_OPTIONS.iter().find(|option| **option == name) {
        return Some(exact);
    }
    let mut matches = LONG_OPTIONS
        .iter()
        .filter(|option| option.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// Whether argparse classifies a command-line word as an option
/// (`ArgumentParser._parse_optional` returns something): then it can never
/// be the value of an option given as a separate word.
fn argparse_reads_as_option(arg: &str) -> bool {
    if !arg.starts_with('-') || arg == "-" {
        return false;
    }
    let name = arg.split_once('=').map_or(arg, |(name, _)| name);
    if name == "-h" || LONG_OPTIONS.contains(&name) {
        return true;
    }
    // Abbreviations: any option a `--` word is a prefix of (one is a match,
    // several an error), and `-h` with an attached value.
    if arg.starts_with("--") {
        if LONG_OPTIONS.iter().any(|option| option.starts_with(name)) {
            return true;
        }
    } else if arg.starts_with("-h") {
        return true;
    }
    !(NEGATIVE_NUMBER.is_match(arg) || arg.contains(' '))
}

/// What a word that names help or `--version` does where it stands.
#[derive(Debug, PartialEq, Eq)]
enum HelpWord {
    /// Help or the version is shown; later words are not looked at.
    Shown,
    /// argparse's usage error `ignored explicit argument` with this
    /// argument (`-h=x`, `--help=x`, `-h-x`).
    IgnoredArgument(String),
}

/// `--help`, `--version` or an unambiguous prefix of them, and `-h` with
/// whatever is attached, as `consume_optional` of argparse (Python 3.12
/// and 3.13) reads it: each further `h` is help again; after an `h`, `=`
/// starts an explicit argument and a `-` is one, both usage errors; any
/// other character ends the word as unknown options after help (`-hx`,
/// `-hx=y`). `--version=x` is left to clap, which refuses it as argparse
/// (which has no `--version`) does.
fn help_word(word: &str) -> Option<HelpWord> {
    if word.starts_with("--") {
        let (name, value) = match word.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (word, None),
        };
        return match (resolve_long(name), value) {
            (Some("--help"), Some(value)) => Some(HelpWord::IgnoredArgument(value.into())),
            (Some("--help" | "--version"), None) => Some(HelpWord::Shown),
            _ => None,
        };
    }
    let mut rest = word.strip_prefix("-h")?;
    loop {
        match rest.chars().next() {
            Some('h') => rest = &rest[1..],
            Some('=') => return Some(HelpWord::IgnoredArgument(rest[1..].into())),
            Some('-') => return Some(HelpWord::IgnoredArgument(rest.into())),
            _ => return Some(HelpWord::Shown),
        }
    }
}

/// Python's `repr` of a string, as argparse puts it into a message.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if u32::from(c) < 0x20 || c == '\x7f' => {
                out.push_str(&format!("\\x{:02x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// argparse takes the value of `--opt value` only from a word it does not
/// read as an option, so `--group -x` and `--config --output` are usage
/// errors while `--group -1`, `--config '-a b'` and `--group=-x` are values.
/// clap is told to accept values starting with `-`; this check refuses the
/// rest first.
fn check_option_values(args: &[OsString]) -> Result<(), String> {
    let words: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
    let mut index = 0;
    while index < words.len() {
        let word = &words[index];
        // argparse acts on the words in order: help (and our --version)
        // ends the command line before any later word is looked at, and
        // help with an explicit argument is a usage error right there.
        if word == "--" {
            break;
        }
        match help_word(word) {
            Some(HelpWord::Shown) => break,
            Some(HelpWord::IgnoredArgument(argument)) => {
                return Err(format!(
                    "argument -h/--help: ignored explicit argument {}",
                    py_repr(&argument)
                ));
            }
            None => {}
        }
        let value_option = (word.starts_with("--") && !word.contains('='))
            .then(|| resolve_long(word))
            .flatten()
            .filter(|option| VALUE_OPTIONS.contains(option));
        if let Some(option) = value_option {
            match words.get(index + 1) {
                Some(value) if value != "--" && !argparse_reads_as_option(value) => {
                    index += 2;
                    continue;
                }
                _ => return Err(format!("argument {option}: expected one argument")),
            }
        }
        index += 1;
    }
    Ok(())
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

/// `export-inventory` (`software_live.py:895-902`): it reads only the
/// state file named by `--config` (never `--config-json`), so it takes no
/// [`System`]: it neither collects nor connects. Any failure is the one
/// line `inventory export failed: <Class>`, also for the failures Python
/// leaves to a traceback (PLAN.md 4.2 item 7).
fn export_inventory(cli: &Cli) -> Result<(), Fatal> {
    let failed = |class: &str| Fatal(format!("inventory export failed: {class}"));
    let (Some(source), Some(output), Some(group)) = (
        cli.config.as_ref(),
        cli.output.as_ref(),
        cli.group.as_ref().filter(|group| !group.is_empty()),
    ) else {
        return Err(failed("ValueError"));
    };
    export::export_inventory(source, output, group).map_err(|error| failed(error.class))
}

fn run(cli: &Cli, system: &impl System) -> Result<(), Fatal> {
    if cli.mode == Mode::ExportInventory {
        return export_inventory(cli);
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
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Err(message) = check_option_values(&args) {
        Cli::command()
            .error(clap::error::ErrorKind::InvalidValue, message)
            .exit();
    }
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

    #[test]
    fn option_values_follow_argparse() {
        let check = |words: &[&str]| {
            let args: Vec<OsString> = words.iter().map(OsString::from).collect();
            check_option_values(&args)
        };
        for ok in [
            &["validate", "--group", "-1"][..],
            &["--cache", "-.5", "validate"],
            &["--output", "-1.5"],
            &["--config", "-a b"],
            &["--group=-x"],
            &["--gro", "-"],
            &["--", "--group", "-x"],
            &["--config-json", "{}"],
            &["--help", "--config"],
            &["-h", "--group", "-x"],
            &["-hx", "--group"],
            &["validate", "--he", "--group", "-x"],
            &["--vers", "--config"],
            &["-hx", "--config"],
            &["-hx=y", "--config"],
            &["-hh", "--config"],
            &["--help", "-h=x"],
        ] {
            assert_eq!(check(ok), Ok(()), "{ok:?}");
        }
        for bad in [
            &["validate", "--group", "-x"][..],
            &["--group", "-1e5"],
            &["--output", "-1."],
            &["--config", "--output"],
            &["--config", "--out=x"],
            &["--config", "--ver"],
            &["--config", "-h"],
            &["--config", "-hx"],
            &["--config", "--"],
            &["--config"],
            &["--co", "x", "--cache", "-y"],
            &["--config", "--help"],
            &["--help=x", "--group", "-x"],
            &["-h=x"],
            &["-h="],
            &["-h=x", "--config"],
            &["-h=", "--config"],
            &["validate", "-h=x"],
            &["-hh=x"],
            &["-h-x"],
            &["--help=", "--config"],
        ] {
            assert!(check(bad).is_err(), "{bad:?}");
        }
        // argparse's message, at the help word before a later error.
        assert_eq!(
            check(&["-h=x", "--config"]),
            Err("argument -h/--help: ignored explicit argument 'x'".into())
        );
        assert_eq!(
            check(&["--he=", "--group", "-x"]),
            Err("argument -h/--help: ignored explicit argument ''".into())
        );
    }

    #[test]
    fn help_words_follow_argparse() {
        let ignored = |argument: &str| Some(HelpWord::IgnoredArgument(argument.into()));
        for shown in [
            "-h",
            "-hx",
            "-hx=y",
            "-hx=",
            "-hh",
            "-h x",
            "--help",
            "--h",
            "--version",
            "--vers",
        ] {
            assert_eq!(help_word(shown), Some(HelpWord::Shown), "{shown:?}");
        }
        assert_eq!(help_word("-h=x"), ignored("x"));
        assert_eq!(help_word("-h="), ignored(""));
        assert_eq!(help_word("-hh=x"), ignored("x"));
        assert_eq!(help_word("-hhh="), ignored(""));
        assert_eq!(help_word("-h-x"), ignored("-x"));
        assert_eq!(help_word("-hh-"), ignored("-"));
        assert_eq!(help_word("--help=x"), ignored("x"));
        assert_eq!(help_word("--he="), ignored(""));
        for other in [
            "-x",
            "--version=x",
            "--group",
            "--",
            "--bogus=x",
            "validate",
            "-",
        ] {
            assert_eq!(help_word(other), None, "{other:?}");
        }
    }

    #[test]
    fn repr_follows_python() {
        assert_eq!(py_repr("x"), "'x'");
        assert_eq!(py_repr(""), "''");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("'\""), "'\\'\"'");
        assert_eq!(py_repr("a\\b\n\x01"), "'a\\\\b\\n\\x01'");
    }
}
