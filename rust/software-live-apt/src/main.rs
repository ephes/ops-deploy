//! software-live-apt: the APT observation of `software-live collect`
//! (software-live PLAN.md 3.3 "APT", 5.2), a separate executable because
//! it links the distribution's libapt-pkg through rust-apt
//! (GPL-3.0-or-later, `LICENSE.GPL-3.0`).
//!
//! `software-live-apt observe --max-age <seconds> --now <epoch>` prints the
//! `apt` object of the report as one line of JSON on stdout and exits 0,
//! also when the observation is `unknown` (`"APT observation failed
//! (<Class>)"`). A usage error exits 2, a failed write of the result 1.
//! `software-live-apt --version` prints `software-live-apt <version>
//! (<commit>)`. No stdin, no APT lock, no write under `/var/cache/apt`.

mod cache;
mod observe;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;

const VERSION: &str = concat!(
    "software-live-apt ",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("SOFTWARE_LIVE_APT_GIT_COMMIT"),
    ")"
);

const USAGE: &str = "usage: software-live-apt observe --max-age <seconds> --now <epoch>\n       software-live-apt --version";

/// The largest `--max-age` (2^53): every value up to it is exact as a float,
/// so `age <= max_age` compares as Python's int/float comparison does.
const MAX_AGE_LIMIT: u64 = 1 << 53;

#[derive(Debug, PartialEq)]
enum Command {
    Version,
    Observe { max_age: u64, now: f64 },
}

/// The command line: `--version`, or `observe` with both options exactly
/// once each, in either order, as `--opt value`.
fn parse(args: &[OsString]) -> Result<Command, String> {
    let args: Vec<&str> = args
        .iter()
        .map(|arg| arg.to_str().ok_or("arguments must be UTF-8"))
        .collect::<Result<_, _>>()?;
    match args.as_slice() {
        ["--version"] => Ok(Command::Version),
        ["observe", rest @ ..] => {
            let mut max_age = None;
            let mut now = None;
            let mut rest = rest.iter();
            while let Some(option) = rest.next() {
                let value = rest.next().ok_or(format!("{option} needs a value"))?;
                let slot = match *option {
                    "--max-age" => &mut max_age,
                    "--now" => &mut now,
                    other => return Err(format!("unknown argument {other:?}")),
                };
                if slot.replace(*value).is_some() {
                    return Err(format!("{option} given twice"));
                }
            }
            let max_age = max_age.ok_or("--max-age is required")?;
            let now = now.ok_or("--now is required")?;
            let max_age = max_age
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| max_age.parse::<u64>().ok())
                .flatten()
                .filter(|age| *age <= MAX_AGE_LIMIT)
                .ok_or(format!(
                    "--max-age {max_age:?} is not an integer in 0..=2^53"
                ))?;
            let now = now
                .parse::<f64>()
                .ok()
                .filter(|now| now.is_finite())
                .ok_or(format!("--now {now:?} is not a finite number"))?;
            Ok(Command::Observe { max_age, now })
        }
        _ => Err("expected `observe` or `--version`".into()),
    }
}

/// `observe_apt(max_age, now)` (`software_live.py:574-603`): the index ages
/// first, then the cache; any failure is the `unknown` result.
fn observe(max_age: u64, now: f64) -> Value {
    let ages = match observe::security_index_ages(Path::new(observe::LISTS), now) {
        Ok(ages) => ages,
        Err(error) => return observe::unknown_result(observe::os_error_class(&error)),
    };
    let Ok(cache) = cache::open() else {
        return observe::unknown_result("CacheOpen");
    };
    let held = cache::holds(&cache);
    let updates =
        observe::security_packages(cache::installed_packages(&cache), cache::compare, &held);
    observe::ok_result(updates, &ages, max_age)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("software-live-apt: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let line = match command {
        Command::Version => VERSION.to_owned(),
        Command::Observe { max_age, now } => observe(max_age, now).to_string(),
    };
    let mut stdout = io::stdout().lock();
    match writeln!(stdout, "{line}").and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("software-live-apt: cannot write the result: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn version_line_names_the_binary() {
        assert!(VERSION.starts_with("software-live-apt 0."), "{VERSION}");
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
    }

    #[test]
    fn observe_takes_both_options_in_either_order() {
        let expected = Ok(Command::Observe {
            max_age: 172_800,
            now: 1_761_000_000.25,
        });
        assert_eq!(
            parse(&args(&[
                "observe",
                "--max-age",
                "172800",
                "--now",
                "1761000000.25"
            ])),
            expected
        );
        assert_eq!(
            parse(&args(&[
                "observe",
                "--now",
                "1761000000.25",
                "--max-age",
                "172800"
            ])),
            expected
        );
        // Python's float repr reads back exactly.
        assert_eq!(
            parse(&args(&["observe", "--max-age", "0", "--now", "1e+16"])),
            Ok(Command::Observe {
                max_age: 0,
                now: 1e16
            })
        );
    }

    #[test]
    fn usage_errors() {
        for list in [
            &[][..],
            &["observe"],
            &["observe", "--max-age", "1"],
            &["observe", "--now", "1"],
            &["observe", "--max-age", "1", "--now"],
            &["observe", "--max-age", "1", "--now", "1", "--now", "2"],
            &["observe", "--max-age", "-1", "--now", "1"],
            &["observe", "--max-age", "+1", "--now", "1"],
            &["observe", "--max-age", "1.0", "--now", "1"],
            &["observe", "--max-age", "9007199254740993", "--now", "1"],
            &["observe", "--max-age", "1", "--now", "nan"],
            &["observe", "--max-age", "1", "--now", "inf"],
            &["observe", "--max-age", "1", "--now", "1", "--extra", "x"],
            &["observe", "--max-age=1", "--now", "1"],
            &["--version", "observe"],
            &["collect"],
        ] {
            assert!(parse(&args(list)).is_err(), "{list:?}");
        }
    }
}
