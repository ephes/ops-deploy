//! The Layer-2 probe (PLAN.md 7.5; `parity/e2e/`): answers the lookups of
//! the real `GuardEnv` (`RealEnv`) as JSON lines, so that
//! `parity/e2e/layer2_realpath.py` can compare them with CPython's
//! `os.path.realpath`, `os.lstat`, `pwd.getpwnam` and `os.geteuid` on real
//! trees inside the distribution containers. Not part of the guard binary.
//!
//! One request per stdin line, one answer per stdout line:
//!
//! ```text
//! {"op": "realpath", "path": "/x"}  -> {"resolved": "/y"} | {"error": {"errno", "strerror"}}
//! {"op": "lstat", "path": "/x"}     -> {"stat": {kind, mode, uid, nlink}} | {"absent": true} | {"error": {...}}
//! {"op": "uid_of", "name": "x"}     -> {"uid": 110 | null}
//! {"op": "euid"}                    -> {"euid": 0}
//! ```

use std::io::{BufRead, Write};

use echoport_command_guard::env::{GuardEnv, RealEnv};
use serde_json::{Value, json};

fn answer(env: &dyn GuardEnv, request: &Value) -> Value {
    let text = |key: &str| request[key].as_str().unwrap_or_default();
    match request["op"].as_str() {
        Some("realpath") => match env.realpath(text("path")) {
            Ok(resolved) => json!({"resolved": resolved}),
            Err(error) => json!({"error": error}),
        },
        Some("lstat") => match env.lstat(text("path")) {
            Ok(Some(stat)) => json!({"stat": stat}),
            Ok(None) => json!({"absent": true}),
            Err(error) => json!({"error": error}),
        },
        Some("uid_of") => json!({"uid": env.uid_of(text("name"))}),
        Some("euid") => json!({"euid": env.euid()}),
        _ => json!({"bad_request": request}),
    }
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => answer(&RealEnv, &request),
            Err(error) => json!({"bad_request": error.to_string()}),
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}
