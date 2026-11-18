//! Shared helpers of the integration tests: the Layer-1 fixtures and the
//! Python oracle (PLAN.md 7.2, 7.3).

#![allow(dead_code)]

pub mod invariants;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde::Deserialize;
use serde_json::{Value, json};

use echoport_command_guard::env::VirtualEnv;

pub fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixtures_dir() -> PathBuf {
    crate_dir().join("fixtures")
}

pub fn read_jsonl<T: for<'de> Deserialize<'de>>(name: &str) -> Vec<T> {
    let path = fixtures_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(n, line)| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{}:{}: {e}", path.display(), n + 1))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub guard_sha256: String,
    pub decision_files: Vec<String>,
    pub policy_files: Vec<String>,
    pub total: usize,
    pub decisions: usize,
}

pub fn manifest() -> Manifest {
    let text = std::fs::read_to_string(fixtures_dir().join("manifest.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A decision case (PLAN.md 7.2; `rust/echoport-command-guard/README.md`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCase {
    pub id: String,
    pub source: String,
    pub policy: String,
    pub command: Option<String>,
    pub command_hex: Option<String>,
    pub env: VirtualEnv,
    pub expected: Value,
    #[serde(default)]
    pub p3: Vec<String>,
}

impl DecisionCase {
    /// The bytes of `SSH_ORIGINAL_COMMAND`.
    pub fn command_bytes(&self) -> Vec<u8> {
        match (&self.command, &self.command_hex) {
            (Some(text), None) => text.as_bytes().to_vec(),
            (None, Some(hex)) => decode_hex(hex),
            _ => panic!("{}: exactly one of command and command_hex", self.id),
        }
    }
}

/// A `--check-policy` case.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCase {
    pub id: String,
    pub source: String,
    pub policy_text: Option<String>,
    pub policy_hex: Option<String>,
    pub expected: Value,
    #[serde(default)]
    pub p3: Vec<String>,
}

impl PolicyCase {
    pub fn bytes(&self) -> Vec<u8> {
        match (&self.policy_text, &self.policy_hex) {
            (Some(text), None) => text.as_bytes().to_vec(),
            (None, Some(hex)) => decode_hex(hex),
            _ => panic!("{}: exactly one of policy_text and policy_hex", self.id),
        }
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn decision_cases() -> Vec<DecisionCase> {
    manifest()
        .decision_files
        .iter()
        .flat_map(|name| read_jsonl::<DecisionCase>(name))
        .collect()
}

/// The ids of `parity/allowed_differences.json` `rust` (PLAN.md 4.4).
pub fn allowed_differences() -> BTreeSet<String> {
    let path = crate_dir().join("parity/allowed_differences.json");
    let data: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    data["rust"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap().to_owned())
        .collect()
}

/// `parity/oracle.py` as a JSON-lines server (PLAN.md 7.3). The interpreter
/// is `$ECHOPORT_ORACLE_PYTHON` (CI: Python 3.12 from uv), else `python3`.
/// There is no skip: the oracle tests fail when it cannot start.
pub struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    pub fn start() -> Self {
        let python = std::env::var("ECHOPORT_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into());
        let mut child = Command::new(&python)
            .arg("-I")
            .arg(crate_dir().join("parity/oracle.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot start the oracle with {python:?}: {e}"));
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut oracle = Self {
            child,
            stdin,
            stdout,
        };
        let pong = oracle.ask(&json!({"op": "ping"}));
        let recorded = std::fs::read_to_string(fixtures_dir().join("GUARD_SHA256")).unwrap();
        assert_eq!(
            pong["guard_sha256"].as_str(),
            Some(recorded.trim()),
            "the oracle's guard is not the one the fixtures were generated from"
        );
        eprintln!("oracle: Python {}", pong["python"]);
        oracle
    }

    pub fn ask(&mut self, request: &Value) -> Value {
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("oracle answered {line:?} to {request}: {e}"));
        assert_eq!(
            response["ok"],
            json!(true),
            "oracle error for {request}: {response}"
        );
        response
    }

    /// The Python guard's `check()` of `command` (the bytes of
    /// `SSH_ORIGINAL_COMMAND`) under a fixture policy in the virtual host
    /// `env` (a fixture case's `env` form): the case's `expected`.
    pub fn check(&mut self, policy: &str, command: &[u8], env: &Value) -> Value {
        let mut request = json!({"op": "check", "policy_ref": policy, "env": env});
        match std::str::from_utf8(command) {
            Ok(text) => request["command"] = json!(text),
            Err(_) => request["command_hex"] = json!(encode_hex(command)),
        }
        self.ask(&request)["expected"].clone()
    }

    /// `shlex.split(command)`: the tokens, or the `ValueError` text.
    pub fn split(&mut self, command: &str) -> Result<Vec<String>, String> {
        let response = self.ask(&json!({"op": "split", "command": command}));
        if let Some(error) = response.get("error") {
            return Err(error.as_str().unwrap().to_owned());
        }
        Ok(serde_json::from_value(response["tokens"].clone()).unwrap())
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Oracle {
    /// Python's `os.path.realpath(path)` over the virtual tree `fs` (the
    /// oracle's `_FsPatch`): `Ok(resolved)` or `Err(errno name)`.
    pub fn realpath_virtual(&mut self, path: &str, fs: &Value) -> Result<String, String> {
        let response = self.ask(&json!({"op": "realpath", "path": path, "fs": fs}));
        realpath_outcome(&response)
    }

    /// Python's `os.path.realpath(path)` on the real filesystem.
    pub fn realpath_os(&mut self, path: &str) -> Result<String, String> {
        let response = self.ask(&json!({"op": "os_realpath", "path": path}));
        realpath_outcome(&response)
    }
}

fn realpath_outcome(response: &Value) -> Result<String, String> {
    match (response.get("resolved"), response.get("error")) {
        (Some(resolved), None) => Ok(resolved.as_str().unwrap().to_owned()),
        (None, Some(error)) => Err(error["errno"].as_str().unwrap().to_owned()),
        _ => panic!("unexpected realpath answer {response}"),
    }
}

/// A virtual tree as the oracle's `_FsPatch` serves it (`parity/oracle.py`):
/// path → `{kind, mode, uid, nlink[, target]}`, `{"absent": true}` or
/// `{errno, strerror}`. A path that is not listed is `ENOENT`, or `ENOTDIR`
/// when a listed ancestor is neither a directory nor a link; `/` is a
/// directory.
pub struct VirtualTree(pub serde_json::Map<String, Value>);

impl echoport_command_guard::pyrealpath::ResolveFs for VirtualTree {
    fn lstat(
        &self,
        path: &str,
    ) -> Result<Option<echoport_command_guard::env::FileStat>, echoport_command_guard::env::OsError>
    {
        use echoport_command_guard::env::{FileStat, OsError};
        let error = |errno: &str, strerror: &str| OsError {
            errno: errno.into(),
            strerror: strerror.into(),
        };
        let Some(entry) = self.0.get(path) else {
            let mut parent = posix_dirname(path);
            while !parent.is_empty() && parent != "/" {
                if let Some(entry) = self.0.get(parent)
                    && !matches!(
                        entry.get("kind").and_then(Value::as_str),
                        None | Some("dir" | "lnk")
                    )
                {
                    return Err(error("ENOTDIR", "Not a directory"));
                }
                parent = posix_dirname(parent);
            }
            if path == "/" {
                return Ok(Some(
                    serde_json::from_value(
                        json!({"kind": "dir", "mode": 0o755, "uid": 0, "nlink": 2}),
                    )
                    .unwrap(),
                ));
            }
            return Ok(None);
        };
        if entry.get("absent").is_some() {
            return Ok(None);
        }
        if let Some(errno) = entry.get("errno") {
            return Err(error(
                errno.as_str().unwrap(),
                entry["strerror"].as_str().unwrap(),
            ));
        }
        let mut stat = entry.clone();
        stat.as_object_mut().unwrap().remove("target");
        Ok(Some(serde_json::from_value::<FileStat>(stat).unwrap()))
    }

    fn readlink(&self, path: &str) -> Result<String, echoport_command_guard::env::OsError> {
        use echoport_command_guard::env::OsError;
        match self.0.get(path) {
            None => Err(OsError {
                errno: "ENOENT".into(),
                strerror: "No such file or directory".into(),
            }),
            Some(entry) if entry.get("kind").and_then(Value::as_str) == Some("lnk") => {
                Ok(entry["target"].as_str().unwrap().to_owned())
            }
            Some(_) => Err(OsError {
                errno: "EINVAL".into(),
                strerror: "Invalid argument".into(),
            }),
        }
    }
}

/// `posixpath.dirname`.
pub fn posix_dirname(path: &str) -> &str {
    let head = match path.rfind('/') {
        Some(index) => &path[..=index],
        None => "",
    };
    let trimmed = head.trim_end_matches('/');
    if trimmed.is_empty() { head } else { trimmed }
}

/// An independent check for the `ELOOP` refusals: Python's non-strict
/// resolution without its `seen` map, following at most `budget` links.
/// The resolved path and the number of symlink traversals it took (each
/// link followed counts, as in the kernel), or `None` when the budget runs
/// out, which for the small test trees means the resolution never ends.
pub fn naive_realpath(
    fs: &dyn echoport_command_guard::pyrealpath::ResolveFs,
    path: &str,
    budget: usize,
) -> Option<(String, usize)> {
    use echoport_command_guard::env::FileKind;
    let mut stack: Vec<String> = path.split('/').rev().map(str::to_owned).collect();
    let mut resolved = String::from("/");
    let mut links = 0;
    while let Some(name) = stack.pop() {
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            let cut = resolved.rfind('/').unwrap_or(0);
            resolved.truncate(cut.max(1));
            continue;
        }
        let newpath = if resolved == "/" {
            format!("/{name}")
        } else {
            format!("{resolved}/{name}")
        };
        let is_link = matches!(fs.lstat(&newpath), Ok(Some(stat)) if stat.kind == FileKind::Lnk);
        if !is_link {
            resolved = newpath;
            continue;
        }
        links += 1;
        if links > budget {
            return None;
        }
        let target = fs.readlink(&newpath).ok()?;
        if target.starts_with('/') {
            resolved = String::from("/");
        }
        stack.extend(target.split('/').rev().map(str::to_owned));
    }
    Some((resolved, links))
}
