//! Process tests of the forced-command flow, `--decide` and `--shadow`
//! (PLAN.md 3.1, 3.5, 3.6; `GuardMain` of the Python tests).
//!
//! This test has its own `main` (`harness = false`): it re-runs its own
//! executable as a single-threaded child that is the guard, with
//! `modes::forced_command`/`decide`/`shadow`, a stub `check()` that returns
//! the decision a test asks for (the real rules are tested by the Layer-1
//! runner and `tests/cli.rs`), a search path of test directories instead of
//! `SAFE_PATH`, and a log file instead of syslog. The child then really sets the umask, opens the
//! redirects, and execs a probe script that records what it inherited:
//! argv, environment, umask, ignored signals, open fds, stdin, stdout.
//!
//! The probes read `/proc`, so the tests run on Linux (CI) and print a skip
//! line elsewhere. The locale coercion is compared with the CPython of
//! `$ECHOPORT_ORACLE_PYTHON` (default `python3`), as the oracle tests do.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use serde_json::{Value, json};

use echoport_command_guard::decision::{Decision, Redirect, Refused};
use echoport_command_guard::env::{FileStat, GuardEnv, OsError};
use echoport_command_guard::modes::{self, Host, PythonGuard};
use echoport_command_guard::policy::Policy;
use echoport_command_guard::syslog::{Ident, Logger, Priority};

const CHILD: &str = "ECHOPORT_FLOW_CHILD";
const DECISION: &str = "ECHOPORT_FLOW_DECISION";
const SEARCH_PATH: &str = "ECHOPORT_FLOW_PATH";
const LOG: &str = "ECHOPORT_FLOW_LOG";
const POLICY: &str = "ECHOPORT_FLOW_POLICY";
const SHADOW_PYTHON: &str = "ECHOPORT_FLOW_PYTHON";
const SHADOW_GUARD: &str = "ECHOPORT_FLOW_GUARD";
const PROBE_OUT: &str = "ECHOPORT_PROBE_OUT";
const CLIENT: &str = "192.0.2.10 50000 22";
const SIGPIPE_BIT: u64 = 1 << 12;
const SIGXFSZ_BIT: u64 = 1 << 24;

// --- the child: the guard ---------------------------------------------------

/// The host's euid and NSS users; `lstat`/`realpath` are not used by the
/// stub check.
struct ChildEnv;

impl GuardEnv for ChildEnv {
    fn euid(&self) -> u32 {
        nix::unistd::geteuid().as_raw()
    }
    fn uid_of(&self, name: &str) -> Option<u32> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
    }
    fn lstat(&self, _path: &str) -> Result<Option<FileStat>, OsError> {
        unreachable!("the stub check does not look at files")
    }
    fn realpath(&self, _path: &str) -> Result<String, OsError> {
        unreachable!("the stub check does not look at files")
    }
}

struct FileLog(PathBuf);

impl Logger for FileLog {
    fn log(&self, ident: Ident, priority: Priority, message: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.0)
            .unwrap();
        writeln!(file, "{}\t{}\t{message}", ident.name(), priority.name()).unwrap();
    }
}

/// The decision of `$ECHOPORT_FLOW_DECISION`: `{"refused": reason}`,
/// `{"panic": text}`, or a decision in the fixtures' form. Without it, the
/// real `check()`.
fn stub_check(command: &[u8], policy: &Policy, env: &dyn GuardEnv) -> Result<Decision, Refused> {
    let Ok(spec) = std::env::var(DECISION) else {
        return echoport_command_guard::rules::check(command, policy, env);
    };
    let spec: Value = serde_json::from_str(&spec).unwrap();
    if let Some(reason) = spec.get("refused") {
        return Err(Refused::new(reason.as_str().unwrap()));
    }
    if let Some(text) = spec.get("panic") {
        panic!("{}", text.as_str().unwrap());
    }
    let redirect = |value: &Value| {
        (!value.is_null()).then(|| Redirect {
            directory: value["directory"].as_str().unwrap().into(),
            name: value["name"].as_str().unwrap().into(),
            owners: serde_json::from_value(value["owners"].clone()).unwrap(),
        })
    };
    Ok(Decision {
        argv: serde_json::from_value(spec["argv"].clone()).unwrap(),
        umask: spec["umask"].as_u64().map(|m| u32::try_from(m).unwrap()),
        stdin: redirect(&spec["stdin"]),
        stdout: redirect(&spec["stdout"]),
    })
}

fn child(mode: &str) -> ExitCode {
    let search_path = std::env::var(SEARCH_PATH).unwrap();
    let policy = std::env::var_os(POLICY).unwrap();
    let log_path = PathBuf::from(std::env::var_os(LOG).unwrap());
    // What this process inherited, for the signal and fd assertions:
    // glibc's `posix_spawn`, which `Command` uses, may leave its internal
    // signals ignored (sshd's fork and exec does not), and a CI runner passes
    // its own open fds down the process tree, as sshd may (PLAN.md 3.5).
    if cfg!(target_os = "linux") {
        std::fs::write(log_path.with_extension("sigign"), own_status("SigIgn")).unwrap();
        let fds: Vec<String> = open_fds().iter().map(u32::to_string).collect();
        std::fs::write(log_path.with_extension("fds"), fds.join("\n")).unwrap();
    }
    let log = FileLog(log_path);
    let host = Host {
        env: &ChildEnv,
        log: &log,
        check: stub_check,
        search_path: &search_path,
    };
    modes::install_panic_hook();
    match mode {
        "forced" => modes::forced_command(&host, &policy),
        "decide" => modes::decide(&host, &policy, &mut std::io::stdout().lock()),
        "shadow" => {
            let python = std::env::var_os(SHADOW_PYTHON).unwrap();
            let guard = std::env::var_os(SHADOW_GUARD).unwrap();
            modes::shadow(
                &host,
                &PythonGuard {
                    python: &python,
                    guard: &guard,
                    policy: &policy,
                },
            )
        }
        other => panic!("unknown child mode {other:?}"),
    }
}

// --- the parent: the tests --------------------------------------------------

/// The exec target: records what it inherited, copies stdin, writes one
/// line to stdout. `/proc/$$` is the shell itself; the targets of fds 0-2
/// are read before any redirection. The fd list comes from an `exec`'d
/// `ls`, which has only what the guard passed on (the shell's own script fd
/// is close-on-exec) plus its own directory fd.
const PROBE: &str = r#"#!/bin/sh
out="$ECHOPORT_PROBE_OUT"
std0=$(/usr/bin/readlink /proc/$$/fd/0)
std1=$(/usr/bin/readlink /proc/$$/fd/1)
std2=$(/usr/bin/readlink /proc/$$/fd/2)
printf '%s\n' "$std0" "$std1" "$std2" > "$out.std"
/usr/bin/grep -E '^(SigIgn|Umask):' /proc/$$/status > "$out.status"
/usr/bin/tr '\0' '\n' < /proc/$$/environ > "$out.env"
printf '%s\n' "$0" "$@" > "$out.argv"
/usr/bin/cat > "$out.stdin"
printf 'probe stdout\n'
exec /usr/bin/ls -l /proc/self/fd/ > "$out.fds"
"#;

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    policy: PathBuf,
    log: PathBuf,
    probe_out: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let bin = root.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let policy = root.join("policy.json");
        let staging = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/policies/staging.json");
        std::fs::copy(staging, &policy).unwrap();
        let fixture = Self {
            log: root.join("guard.log"),
            probe_out: root.join("probe"),
            _tmp: tmp,
            root,
            bin,
            policy,
        };
        fixture.script(&fixture.bin.join("probe"), PROBE, 0o755);
        fixture
    }

    fn script(&self, path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A 0700 directory, like the runners' `mktemp -d`.
    fn private_dir(&self, name: &str) -> PathBuf {
        let dir = self.root.join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env(CHILD, mode)
            .env(SEARCH_PATH, self.bin.to_str().unwrap())
            .env(LOG, &self.log)
            .env(POLICY, &self.policy)
            .env(PROBE_OUT, &self.probe_out)
            .env("SSH_CLIENT", CLIENT)
            .env("LANG", "C.UTF-8")
            .env("PATH", "/evil");
        command
    }

    fn log_lines(&self) -> Vec<(String, String, String)> {
        let Ok(text) = std::fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        text.lines()
            .map(|line| {
                let mut parts = line.splitn(3, '\t');
                let mut next = || parts.next().unwrap().to_owned();
                (next(), next(), next())
            })
            .collect()
    }

    fn probe(&self, part: &str) -> Option<String> {
        std::fs::read_to_string(format!("{}.{part}", self.probe_out.display())).ok()
    }

    fn probe_ran(&self) -> bool {
        self.probe("argv").is_some()
    }

    fn probe_env(&self) -> BTreeMap<String, String> {
        self.probe("env")
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn probe_status(&self, key: &str) -> String {
        let status = self.probe("status").unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}:")))
            .unwrap()
            .trim()
            .to_owned()
    }

    /// The fds the command inherited: the exec'd `ls`'s fds without its
    /// own directory fd.
    fn probe_fds(&self) -> Vec<u32> {
        let mut fds: Vec<u32> = self
            .probe("fds")
            .unwrap()
            .lines()
            .filter_map(|line| {
                let (left, target) = line.split_once(" -> ")?;
                let fd = left.rsplit(' ').next()?.parse().ok()?;
                let own_dir = target.starts_with("/proc/") && target.ends_with("/fd");
                (!own_dir).then_some(fd)
            })
            .collect();
        fds.sort_unstable();
        fds
    }

    /// The fds the guard child had when it started: 0-2 and whatever its
    /// parent passed on. The command must get exactly these, no fd of the
    /// guard's own.
    fn inherited_fds(&self) -> Vec<u32> {
        let text = std::fs::read_to_string(self.log.with_extension("fds")).unwrap();
        let fds: Vec<u32> = text.lines().map(|line| line.parse().unwrap()).collect();
        assert!(fds.starts_with(&[0, 1, 2]), "{fds:?}");
        fds
    }

    /// The targets of the command's fds 0, 1 and 2.
    fn probe_std(&self) -> Vec<String> {
        self.probe("std")
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

struct Run {
    code: Option<i32>,
    pid: u32,
    stdout: Vec<u8>,
    stderr: String,
}

fn spawn(mut command: Command, stdin: &[u8]) -> Run {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let pid = child.id();
    // The guard may exit without reading; a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let output = child.wait_with_output().unwrap();
    Run {
        code: output.status.code(),
        pid,
        stdout: output.stdout,
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn guard_line(priority: &str, message: &str) -> (String, String, String) {
    (
        "echoport-remote-command-guard".into(),
        priority.into(),
        message.into(),
    )
}

/// `GuardMain.test_allowed_command_is_executed_without_shell`, plus what the
/// command inherits (PLAN.md 3.5).
fn allowed_command_runs_with_the_python_guards_inheritance() {
    let f = Fixture::new();
    let mut command = f.command("forced");
    command
        .env("SSH_ORIGINAL_COMMAND", "systemctl start marina.service")
        .env(
            DECISION,
            json!({"argv": ["probe", "start", "marina.service"]}).to_string(),
        )
        .env("KEEP_ME", "x y");
    let run = spawn(command, b"client data");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.stderr, "");
    // Nothing on stdout but the command's own output; stdin untouched.
    assert_eq!(run.stdout, b"probe stdout\n");
    assert_eq!(f.probe("stdin").unwrap(), "client data");
    assert_eq!(
        f.probe("argv").unwrap(),
        format!("{}\nstart\nmarina.service\n", f.bin.join("probe").display())
    );
    let env = f.probe_env();
    assert_eq!(env["PATH"], f.bin.to_str().unwrap());
    assert_eq!(env["KEEP_ME"], "x y");
    assert_eq!(env["LANG"], "C.UTF-8");
    assert!(!env.contains_key("LC_CTYPE"), "{env:?}");
    assert_eq!(
        f.log_lines(),
        [guard_line(
            "info",
            "allowed from 192.0.2.10: 'systemctl start marina.service'"
        )]
    );
    // Only fds 0-2 and what the guard inherited reach the command.
    assert_eq!(
        f.probe_fds(),
        f.inherited_fds(),
        "{}",
        f.probe("fds").unwrap()
    );
    assert_eq!(f.probe_std().len(), 3);
    // SIGPIPE and SIGXFSZ ignored, as by CPython; the rest as inherited.
    let inherited = std::fs::read_to_string(f.log.with_extension("sigign")).unwrap();
    let inherited = u64::from_str_radix(&inherited, 16).unwrap();
    let sigign = u64::from_str_radix(&f.probe_status("SigIgn"), 16).unwrap();
    assert_eq!(sigign, inherited | SIGPIPE_BIT | SIGXFSZ_BIT, "{sigign:x}");
    assert_eq!(sigign & !(inherited | SIGPIPE_BIT | SIGXFSZ_BIT), 0);
    // The umask is inherited when the decision has none.
    assert_eq!(f.probe_status("Umask"), own_status("Umask"));
}

/// This process's open fds, sorted, without the directory fd that lists
/// them.
fn open_fds() -> Vec<u32> {
    let mut fds: Vec<u32> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            let own_dir = target.starts_with("/proc/") && target.ends_with("fd");
            (!own_dir).then(|| entry.file_name().to_str()?.parse().ok())?
        })
        .collect();
    fds.sort_unstable();
    fds
}

fn own_status(key: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .unwrap()
        .trim()
        .to_owned()
}

/// `umask 077 && cat > <dir>/<name>`: the umask before the create, the file
/// as fd 1, mode 0600, nothing else on stdout.
fn create_redirect_with_umask() {
    let f = Fixture::new();
    let dir = f.private_dir("dump.abcdef");
    let decision = json!({"argv": ["probe"], "umask": 0o077,
        "stdout": {"directory": dir, "name": "db.dump", "owners": ["nobody"]}});
    let mut command = f.command("forced");
    command
        .env("SSH_ORIGINAL_COMMAND", "umask 077 && cat > x")
        .env(DECISION, decision.to_string());
    let run = spawn(command, b"payload");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stdout.is_empty());
    let target = dir.join("db.dump");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "probe stdout\n");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
    assert_eq!(f.probe_status("Umask"), "0077");
    assert_eq!(f.probe("stdin").unwrap(), "payload");
    assert_eq!(f.probe_std()[1], target.to_str().unwrap());
    assert_eq!(
        f.probe_fds(),
        f.inherited_fds(),
        "{}",
        f.probe("fds").unwrap()
    );
}

/// `runuser ... pg_restore < <file>`: the file as fd 0.
fn read_redirect() {
    let f = Fixture::new();
    let dir = f.private_dir("restore.abcdef");
    std::fs::write(dir.join("db.dump"), "dump bytes").unwrap();
    let decision = json!({"argv": ["probe"],
        "stdin": {"directory": dir, "name": "db.dump", "owners": []}});
    let mut command = f.command("forced");
    command
        .env("SSH_ORIGINAL_COMMAND", "pg_restore < x")
        .env(DECISION, decision.to_string());
    let run = spawn(command, b"ignored");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(f.probe("stdin").unwrap(), "dump bytes");
    assert_eq!(run.stdout, b"probe stdout\n");
    assert_eq!(f.probe_std()[0], dir.join("db.dump").to_str().unwrap());
    assert_eq!(
        f.probe_fds(),
        f.inherited_fds(),
        "{}",
        f.probe("fds").unwrap()
    );
}

/// A redirect that cannot be opened refuses with Python's `OSError` text.
fn redirect_failure_refuses() {
    let f = Fixture::new();
    let dir = f.private_dir("dump.abcdef");
    std::fs::write(dir.join("db.dump"), "old").unwrap();
    let decision = json!({"argv": ["probe"], "umask": 0o077,
        "stdout": {"directory": dir, "name": "db.dump", "owners": []}});
    let mut command = f.command("forced");
    command
        .env("SSH_ORIGINAL_COMMAND", "umask 077 && cat > x")
        .env(DECISION, decision.to_string());
    let run = spawn(command, b"");
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.stderr,
        "echoport-remote-command-guard: command not allowed\n"
    );
    assert!(run.stdout.is_empty());
    assert!(!f.probe_ran());
    assert_eq!(std::fs::read_to_string(dir.join("db.dump")).unwrap(), "old");
    assert_eq!(
        f.log_lines(),
        [guard_line(
            "warning",
            "refused from 192.0.2.10: [Errno 17] File exists: 'db.dump': 'umask 077 && cat > x'"
        )]
    );
}

/// `GuardMain.test_refused_command_is_not_executed`.
fn refused_command_is_not_executed() {
    let f = Fixture::new();
    let mut command = f.command("forced");
    command.env("SSH_ORIGINAL_COMMAND", "id").env(
        DECISION,
        json!({"refused": "command not allowed: 'id'"}).to_string(),
    );
    let run = spawn(command, b"data");
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.stderr,
        "echoport-remote-command-guard: command not allowed\n"
    );
    assert!(run.stdout.is_empty());
    assert!(!f.probe_ran());
    assert_eq!(
        f.log_lines(),
        [guard_line(
            "warning",
            "refused from 192.0.2.10: command not allowed: 'id': 'id'"
        )]
    );
}

/// The real `check()` on a command that is not UTF-8: refused after the
/// pre-checks, logged with Python's `surrogateescape` repr; a long command
/// is cut at 1000 characters.
fn real_check_refusals_and_log_text() {
    let f = Fixture::new();
    let mut command = f.command("forced");
    command.env("SSH_ORIGINAL_COMMAND", OsStr::from_bytes(b"cat \xff"));
    let run = spawn(command, b"");
    assert_eq!(run.code, Some(1));
    assert_eq!(
        f.log_lines(),
        [guard_line(
            "warning",
            "refused from 192.0.2.10: non-ASCII or control characters in command: 'cat \\udcff'"
        )]
    );

    let f = Fixture::new();
    let long = format!("id {}", "a".repeat(2000));
    let mut command = f.command("forced");
    command
        .env("SSH_ORIGINAL_COMMAND", &long)
        .env_remove("SSH_CLIENT");
    let run = spawn(command, b"");
    assert_eq!(run.code, Some(1));
    let lines = f.log_lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].2.chars().count(), 1000);
    assert!(
        lines[0]
            .2
            .starts_with("refused from -: command not allowed: 'id': 'id aaa")
    );
}

/// `GuardMain.test_interactive_session_is_refused`: before the policy.
fn interactive_session_is_refused() {
    let f = Fixture::new();
    std::fs::write(&f.policy, "{not json").unwrap();
    let run = spawn(f.command("forced"), b"");
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.stderr,
        "echoport-remote-command-guard: interactive sessions are not allowed\n"
    );
    assert!(run.stdout.is_empty());
    assert_eq!(
        f.log_lines(),
        [guard_line(
            "warning",
            "refused interactive session from 192.0.2.10"
        )]
    );
}

/// `GuardMain.test_broken_policy_refuses_everything`.
fn broken_policy_refuses_everything() {
    for (text, kind) in [
        ("{not json", "JSONDecodeError"),
        ("[]", "Refused"),
        (r#"{"units": ["a b"]}"#, "Refused"),
    ] {
        let f = Fixture::new();
        std::fs::write(&f.policy, text).unwrap();
        let mut command = f.command("forced");
        command
            .env("SSH_ORIGINAL_COMMAND", "systemctl start marina.service")
            .env(DECISION, json!({"argv": ["probe"]}).to_string());
        let run = spawn(command, b"");
        assert_eq!(run.code, Some(1), "{text}");
        assert_eq!(run.stderr, "echoport-remote-command-guard: policy error\n");
        assert!(!f.probe_ran());
        assert_eq!(
            f.log_lines(),
            [guard_line(
                "err",
                &format!("policy error ({kind}): refusing 'systemctl start marina.service'")
            )]
        );
    }
    let f = Fixture::new();
    std::fs::remove_file(&f.policy).unwrap();
    let mut command = f.command("forced");
    command.env("SSH_ORIGINAL_COMMAND", "id");
    spawn(command, b"");
    assert_eq!(
        f.log_lines()[0].2,
        "policy error (FileNotFoundError): refusing 'id'"
    );
}

/// A panic in `check()` refuses; nothing panics onto stderr.
fn panic_never_execs() {
    let f = Fixture::new();
    let mut command = f.command("forced");
    command
        .env("SSH_ORIGINAL_COMMAND", "id")
        .env(DECISION, json!({"panic": "boom"}).to_string());
    let run = spawn(command, b"");
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.stderr,
        "echoport-remote-command-guard: command not allowed\n"
    );
    assert!(!f.probe_ran());
    let lines = f.log_lines();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0]
            .2
            .starts_with("refused from 192.0.2.10: internal error: panicked at ")
            && lines[0].2.ends_with(" boom: 'id'"),
        "{lines:?}"
    );
}

/// CPython's `os.execvp` search (PLAN.md 3.5): no `/bin/sh` fallback, the
/// search goes on after `ENOEXEC`/`EACCES`, the first such error is
/// reported, 127 only when nothing ran.
fn exec_search_is_cpythons() {
    let shebangless = "touch \"$ECHOPORT_PROBE_OUT.shell-ran\"\n";
    let ran = "#!/bin/sh\nprintf ran > \"$ECHOPORT_PROBE_OUT.ran\"\n";
    // (setup, expected exit, expected stderr, expected "ran")
    type Setup = fn(&Fixture, &Path, &Path, &str, &str);
    let cases: [(&str, Setup, Option<i32>, &str, bool); 6] = [
        (
            "only a shebang-less candidate",
            |f, d1, _, shebangless, _| f.script(&d1.join("tool"), shebangless, 0o755),
            Some(127),
            "echoport-remote-command-guard: cannot run tool: Exec format error\n",
            false,
        ),
        (
            "shebang-less, then a valid one",
            |f, d1, d2, shebangless, ran| {
                f.script(&d1.join("tool"), shebangless, 0o755);
                f.script(&d2.join("tool"), ran, 0o755);
            },
            Some(0),
            "",
            true,
        ),
        (
            "not executable, then a valid one",
            |f, d1, d2, _, ran| {
                f.script(&d1.join("tool"), ran, 0o644);
                f.script(&d2.join("tool"), ran, 0o755);
            },
            Some(0),
            "",
            true,
        ),
        (
            "a directory named like the tool",
            |_, d1, _, _, _| std::fs::create_dir(d1.join("tool")).unwrap(),
            Some(127),
            "echoport-remote-command-guard: cannot run tool: Permission denied\n",
            false,
        ),
        (
            "not executable, then shebang-less: the first error",
            |f, d1, d2, shebangless, ran| {
                f.script(&d1.join("tool"), ran, 0o644);
                f.script(&d2.join("tool"), shebangless, 0o755);
            },
            Some(127),
            "echoport-remote-command-guard: cannot run tool: Permission denied\n",
            false,
        ),
        (
            "missing",
            |_, _, _, _, _| {},
            Some(127),
            "echoport-remote-command-guard: cannot run tool: No such file or directory\n",
            false,
        ),
    ];
    for (name, setup, code, stderr, expect_ran) in cases {
        let f = Fixture::new();
        let d1 = f.root.join("d1");
        let d2 = f.root.join("d2");
        std::fs::create_dir(&d1).unwrap();
        std::fs::create_dir(&d2).unwrap();
        setup(&f, &d1, &d2, shebangless, ran);
        let mut command = f.command("forced");
        command
            .env(
                SEARCH_PATH,
                format!("{}:/nonexistent:{}", d1.display(), d2.display()),
            )
            .env("SSH_ORIGINAL_COMMAND", "tool")
            .env(DECISION, json!({"argv": ["tool"]}).to_string());
        let run = spawn(command, b"");
        assert_eq!(run.code, code, "{name}: {}", run.stderr);
        assert_eq!(run.stderr, stderr, "{name}");
        assert_eq!(f.probe("ran").is_some(), expect_ran, "{name}");
        assert!(
            f.probe("shell-ran").is_none(),
            "{name}: run through a shell"
        );
        // The `allowed` line comes before the exec, also when it fails.
        assert_eq!(f.log_lines()[0].1, "info", "{name}");
    }
    // An argv[0] with a `/` is executed as it is.
    let f = Fixture::new();
    let mut command = f.command("forced");
    command
        .env(SEARCH_PATH, "/nonexistent")
        .env("SSH_ORIGINAL_COMMAND", "x")
        .env(DECISION, json!({"argv": [f.bin.join("probe")]}).to_string());
    let run = spawn(command, b"");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(f.probe_ran());
}

/// The interpreter CPython the locale coercion is compared with.
fn python() -> String {
    std::env::var("ECHOPORT_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// What `python3 -I` exports as `LC_CTYPE` for `env` (PEP 538).
fn cpython_lc_ctype(env: &[(&str, &str)]) -> Option<String> {
    let output = Command::new(python())
        .env_clear()
        .envs(env.iter().copied())
        .args([
            "-I",
            "-c",
            "import os; print(os.environ.get('LC_CTYPE', '<unset>'))",
        ])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", python()));
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    (text != "<unset>").then_some(text)
}

/// PEP 538 locale coercion: what the command finds in `LC_CTYPE` equals
/// what CPython exports for the same environment.
fn locale_coercion_matches_cpython() {
    let cases: [&[(&str, &str)]; 9] = [
        &[],
        &[("LANG", "C.UTF-8")],
        &[("LANG", "C")],
        &[("LC_ALL", "C")],
        &[("LC_ALL", "")],
        &[("LC_CTYPE", "POSIX")],
        &[("LC_CTYPE", "C"), ("LANG", "C.UTF-8")],
        &[("LANG", "xx_XX.UTF-8")],
        &[("LC_CTYPE", "C.UTF-8")],
    ];
    let mut coerced_once = false;
    for env in cases {
        let f = Fixture::new();
        let mut command = f.command("forced");
        command
            .env_remove("LANG")
            .envs(env.iter().copied())
            .env("SSH_ORIGINAL_COMMAND", "x")
            .env(DECISION, json!({"argv": ["probe"]}).to_string());
        let run = spawn(command, b"");
        assert_eq!(run.code, Some(0), "{env:?}: {}", run.stderr);
        let got = f.probe_env().get("LC_CTYPE").cloned();
        let expected = cpython_lc_ctype(env);
        assert_eq!(got, expected, "{env:?}");
        coerced_once |= got.is_some() && !env.iter().any(|(k, _)| *k == "LC_CTYPE");
    }
    assert!(coerced_once, "no case was coerced; is C.UTF-8 missing?");
}

/// `--decide`: the decision as JSON on stdout, nothing executed or logged.
fn decide_prints_the_decision() {
    let f = Fixture::new();
    let dir = f.private_dir("dump.abcdef");
    let decision = json!({"argv": ["probe"], "umask": 63,
        "stdin": null, "stdout": {"directory": dir, "name": "db.dump", "owners": []}});
    let mut command = f.command("decide");
    command
        .env("SSH_ORIGINAL_COMMAND", "umask 077 && cat > x")
        .env(DECISION, decision.to_string());
    let run = spawn(command, b"");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let mut expected = decision.clone();
    expected["verdict"] = json!("allowed");
    let printed: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(printed, expected);
    assert!(run.stdout.ends_with(b"}\n"));
    assert!(!f.probe_ran() && f.log_lines().is_empty());
    assert!(!dir.join("db.dump").exists());

    for (env, expected, code) in [
        (
            Some(json!({"refused": "nope"})),
            json!({"verdict": "refused", "reason": "nope"}),
            1,
        ),
        (None, json!({"verdict": "interactive"}), 1),
    ] {
        let f = Fixture::new();
        let mut command = f.command("decide");
        if let Some(env) = env {
            command
                .env("SSH_ORIGINAL_COMMAND", "x")
                .env(DECISION, env.to_string());
        }
        let run = spawn(command, b"");
        assert_eq!(run.code, Some(code));
        assert_eq!(
            serde_json::from_slice::<Value>(&run.stdout).unwrap(),
            expected
        );
        assert!(f.log_lines().is_empty());
    }
}

/// `--shadow`: the Rust decision under its own identifier, then the Python
/// guard with the same PID and the environment unchanged; also after a
/// panic.
fn shadow_logs_then_execs_python() {
    for (decision, verdict) in [
        (json!({"argv": ["probe"], "umask": 63}), "allowed"),
        (json!({"refused": "command not allowed: 'id'"}), "refused"),
        (json!({"panic": "boom"}), "panic"),
    ] {
        let f = Fixture::new();
        let python = f.root.join("python3");
        f.script(
            &python,
            "#!/bin/sh\nprintf '%s\\n' \"$$\" \"$@\" > \"$ECHOPORT_PROBE_OUT.argv\"\n\
             /usr/bin/tr '\\0' '\\n' < /proc/$$/environ > \"$ECHOPORT_PROBE_OUT.env\"\n\
             /usr/bin/grep -E '^(SigIgn|Umask):' /proc/$$/status > \"$ECHOPORT_PROBE_OUT.status\"\n\
             echo 'python guard stderr' >&2\nexit 3\n",
            0o755,
        );
        let mut command = f.command("shadow");
        command
            .env(SHADOW_PYTHON, &python)
            .env(
                SHADOW_GUARD,
                "/usr/local/sbin/echoport-remote-command-guard",
            )
            .env("SSH_ORIGINAL_COMMAND", "id")
            .env(DECISION, decision.to_string());
        let run = spawn(command, b"stdin for python");
        assert_eq!(run.code, Some(3), "{verdict}: {}", run.stderr);
        assert_eq!(run.stderr, "python guard stderr\n", "{verdict}");
        assert!(run.stdout.is_empty());
        assert_eq!(
            f.probe("argv").unwrap(),
            format!(
                "{}\n-I\n/usr/local/sbin/echoport-remote-command-guard\n{}\n",
                run.pid,
                f.policy.display()
            )
        );
        let env = f.probe_env();
        assert_eq!(env["PATH"], "/evil");
        assert!(!env.contains_key("LC_CTYPE"));
        assert_eq!(f.probe_status("Umask"), own_status("Umask"));
        let lines = f.log_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0].0, "echoport-remote-command-guard-shadow");
        assert_eq!(lines[0].1, "info");
        let record: Value = serde_json::from_str(&lines[0].2).unwrap();
        assert_eq!(record["verdict"], verdict, "{record}");
        if verdict == "allowed" {
            assert_eq!(record["argv"], json!(["probe"]));
            assert_eq!(record["umask"], 63);
        }
    }
}

const TESTS: &[(&str, fn())] = &[
    (
        "allowed_command_runs_with_the_python_guards_inheritance",
        allowed_command_runs_with_the_python_guards_inheritance,
    ),
    ("create_redirect_with_umask", create_redirect_with_umask),
    ("read_redirect", read_redirect),
    ("redirect_failure_refuses", redirect_failure_refuses),
    (
        "refused_command_is_not_executed",
        refused_command_is_not_executed,
    ),
    (
        "real_check_refusals_and_log_text",
        real_check_refusals_and_log_text,
    ),
    (
        "interactive_session_is_refused",
        interactive_session_is_refused,
    ),
    (
        "broken_policy_refuses_everything",
        broken_policy_refuses_everything,
    ),
    ("panic_never_execs", panic_never_execs),
    ("exec_search_is_cpythons", exec_search_is_cpythons),
    (
        "locale_coercion_matches_cpython",
        locale_coercion_matches_cpython,
    ),
    ("decide_prints_the_decision", decide_prints_the_decision),
    (
        "shadow_logs_then_execs_python",
        shadow_logs_then_execs_python,
    ),
];

fn main() -> ExitCode {
    if let Ok(mode) = std::env::var(CHILD) {
        return child(&mode);
    }
    if !cfg!(target_os = "linux") {
        println!(
            "flow: {} tests skipped: they read /proc (Linux only; CI runs them)",
            TESTS.len()
        );
        return ExitCode::SUCCESS;
    }
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    let mut failed = Vec::new();
    let mut ran = 0;
    for (name, test) in TESTS {
        if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        match std::panic::catch_unwind(test) {
            Ok(()) => println!("test flow::{name} ... ok"),
            Err(_) => {
                println!("test flow::{name} ... FAILED");
                failed.push(*name);
            }
        }
    }
    println!(
        "\nflow: {} passed; {} failed",
        ran - failed.len(),
        failed.len()
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
