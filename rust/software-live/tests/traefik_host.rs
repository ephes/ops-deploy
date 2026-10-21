//! The Traefik observation against real processes and files (Linux only:
//! it needs `/proc`). PLAN.md 3.3, "Traefik", and the risk "re-exec / fd
//! inheritance mistakes execute the wrong image" (section 11).
//!
//! The fake Traefik is a copy of this test binary named `traefik` (an ELF
//! the test does not have to build): `traefik version` runs libtest with the
//! filter `version`, which selects only `fake_traefik_version`, and that test
//! prints a Traefik version banner when its executable is called `traefik`.
//! `traefik fake_traefik_serve --exact` stays up as the running Traefik. In
//! a normal test run both tests do nothing. No other test in this file may
//! have `version` in its name.
//!
//! `systemctl` is the only thing faked: [`Host`] answers it with the PID of
//! the process the test started and passes everything else to
//! [`HostSystem`].
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use software_live::probe::{
    COMMAND_TIMEOUT, CommandError, CommandOutput, FileStat, HostFile, HostSystem, OpenFile, System,
};
use software_live::traefik::{binary_info, observe};

const FAKE: &str = "traefik";

/// Whether this process is the fake (this test binary itself is called
/// `traefik_host-<hash>`).
fn running_as_fake() -> bool {
    std::env::current_exe()
        .ok()
        .is_some_and(|path| path.file_name() == Some(OsStr::new(FAKE)))
}

/// `traefik version` in the fake: the banner Traefik prints (after a line
/// break, since libtest may have started a line of its own).
#[test]
fn fake_traefik_version() {
    if running_as_fake() {
        let mut stdout = io::stdout();
        stdout
            .write_all(b"\nVersion:      3.7.9\nCodename:     fake\n")
            .unwrap();
        stdout.flush().unwrap();
    }
}

/// `traefik fake_traefik_serve --exact` in the fake: the running service.
#[test]
fn fake_traefik_serve() {
    if running_as_fake() {
        std::thread::sleep(Duration::from_secs(120));
    }
}

/// The tests that write executables and start processes run one at a time
/// (a child forked by another test thread could hold a file open for
/// writing while it is executed: `ETXTBSY`).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The host, with `systemctl show … --property=MainPID --value` answered by
/// the given PID.
struct Host {
    pid: u32,
}

impl System for Host {
    type File = HostFile;

    fn now(&self) -> f64 {
        HostSystem.now()
    }
    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        HostSystem.read_file(path)
    }
    fn stat(&self, path: &Path) -> io::Result<FileStat> {
        HostSystem.stat(path)
    }
    fn lstat(&self, path: &Path) -> io::Result<FileStat> {
        HostSystem.lstat(path)
    }
    fn readlink(&self, path: &Path) -> io::Result<std::ffi::OsString> {
        HostSystem.readlink(path)
    }
    fn run(&self, argv: &[&OsStr], timeout: Duration) -> Result<CommandOutput, CommandError> {
        if argv.first() == Some(&OsStr::new("systemctl")) {
            assert_eq!(
                argv,
                [
                    "systemctl",
                    "show",
                    "traefik.service",
                    "--property=MainPID",
                    "--value"
                ]
                .map(OsStr::new)
            );
            return Ok(CommandOutput {
                stdout: format!("{}\n", self.pid).into_bytes(),
                code: Some(0),
                ..CommandOutput::default()
            });
        }
        HostSystem.run(argv, timeout)
    }
    fn open(&self, path: &Path) -> io::Result<HostFile> {
        HostSystem.open(path)
    }
    fn fstat(&self, file: &HostFile) -> io::Result<FileStat> {
        HostSystem.fstat(file)
    }
    fn sha256(&self, file: &mut HostFile) -> io::Result<String> {
        HostSystem.sha256(file)
    }
    fn run_inheriting(
        &self,
        file: &HostFile,
        argv: &[&OsStr],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError> {
        HostSystem.run_inheriting(file, argv, timeout)
    }
}

/// A child process that is killed when the test ends.
struct Running(Child);

impl Running {
    fn start(program: &Path, args: &[&str]) -> Self {
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A directory under Cargo's target directory (never a `noexec` /tmp).
fn workdir() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

fn sha256_of(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

/// Install `bytes` at `path` as an executable, replacing what is there by a
/// rename (as a package manager does).
fn install(path: &Path, bytes: &[u8]) {
    let staging = path.with_extension("new");
    std::fs::write(&staging, bytes).unwrap();
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&staging, path).unwrap();
}

/// The fake Traefik installed at `<dir>/traefik`, its real path.
fn fake_traefik(dir: &Path) -> PathBuf {
    let path = std::fs::canonicalize(dir).unwrap().join(FAKE);
    install(
        &path,
        &std::fs::read(std::env::current_exe().unwrap()).unwrap(),
    );
    path
}

fn serve(path: &Path) -> Running {
    Running::start(path, &["fake_traefik_serve", "--exact"])
}

fn policy(path: &Path) -> Value {
    json!({
        "expected": true,
        "unit": "traefik.service",
        "binary_path": path.to_str().unwrap(),
        "desired_version": "3.7.9",
    })
}

fn latest() -> Value {
    json!({"status": "ok", "version": "3.7.9", "checked_at_epoch": 1.0, "cached": true})
}

fn issues(result: &Value) -> Vec<&str> {
    result["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue.as_str().unwrap())
        .collect()
}

#[test]
fn matching_process_is_probed_through_its_pinned_descriptor() {
    let _serial = serial();
    let dir = workdir();
    let path = fake_traefik(dir.path());
    let traefik = serve(&path);
    let host = Host { pid: traefik.pid() };
    let result = observe(&host, &policy(&path), &latest()).into_value();
    assert_eq!(result["status"], "ok", "{result:#}");
    assert_eq!(result["observed"], true);
    assert_eq!(result["main_pid"], json!(traefik.pid()));
    assert_eq!(result["running_path"], path.to_str().unwrap());
    let digest = sha256_of(&path);
    assert_eq!(
        result["installed"],
        json!({"version": "3.7.9", "sha256": digest})
    );
    assert_eq!(
        result["running"],
        json!({"version": "3.7.9", "sha256": digest})
    );
    assert_eq!(result["upstream"], latest());
}

#[test]
fn replaced_binary_is_reported_and_the_old_image_is_never_executed() {
    let _serial = serial();
    let dir = workdir();
    let path = fake_traefik(dir.path());
    let traefik = serve(&path);
    let old_digest = sha256_of(&path);
    // An update replaces the file; the running process keeps the old inode.
    let mut newer = std::fs::read(&path).unwrap();
    newer.extend_from_slice(b"padding of the newer build");
    install(&path, &newer);
    let host = Host { pid: traefik.pid() };
    let result = observe(&host, &policy(&path), &latest()).into_value();
    assert_eq!(result["status"], "warning", "{result:#}");
    assert_eq!(
        issues(&result),
        ["deleted_running_executable", "installed_running_drift"]
    );
    assert_eq!(
        result["running_path"],
        format!("{} (deleted)", path.display())
    );
    assert_eq!(
        result["installed"],
        json!({"version": "3.7.9", "sha256": sha256_of(&path)})
    );
    // Hashed through /proc/<pid>/exe, not executed (`version: null`).
    assert_eq!(
        result["running"],
        json!({"version": null, "sha256": old_digest})
    );
}

#[test]
fn foreign_process_image_is_hashed_but_never_executed() {
    let _serial = serial();
    let dir = workdir();
    let path = fake_traefik(dir.path());
    // The unit's MainPID runs some other program: `sleep version` would fail
    // and turn the observation unknown, so a warning proves it never ran.
    let sleep = std::fs::canonicalize("/bin/sleep").unwrap();
    let other = Running::start(&sleep, &["120"]);
    let host = Host { pid: other.pid() };
    let result = observe(&host, &policy(&path), &latest()).into_value();
    assert_eq!(result["status"], "warning", "{result:#}");
    assert_eq!(
        issues(&result),
        ["running_path_mismatch", "installed_running_drift"]
    );
    assert_eq!(result["running_path"], sleep.to_str().unwrap());
    assert_eq!(
        result["running"],
        json!({"version": null, "sha256": sha256_of(&sleep)})
    );
}

#[test]
fn stopped_service_is_unknown() {
    let _serial = serial();
    let dir = workdir();
    let path = fake_traefik(dir.path());
    let result = observe(&Host { pid: 0 }, &policy(&path), &latest()).into_value();
    assert_eq!(result["status"], "unknown");
    assert_eq!(
        result["error"],
        "ValueError: service stopped or managed binary missing"
    );
}

fn script(path: &Path, output: &str) {
    install(
        path,
        format!("#!/bin/sh\nprintf '{output}\\n'\n").as_bytes(),
    );
}

/// The probe executes the opened inode: replacing the path between the
/// open and the execution changes nothing.
#[test]
fn execution_follows_the_descriptor_not_the_path() {
    let _serial = serial();
    let dir = workdir();
    let path = dir.path().join("proxy");
    script(&path, "Version: 1.0.0");
    let file = HostSystem.open(&path).unwrap();
    script(&path, "Version: 2.0.0");
    let descriptor = format!("/proc/self/fd/{}", file.fd());
    let argv = [OsStr::new(&descriptor), OsStr::new("version")];
    let pinned = HostSystem
        .run_inheriting(&file, &argv, COMMAND_TIMEOUT)
        .unwrap();
    assert_eq!(pinned.stdout, b"Version: 1.0.0\n");
    let by_path = HostSystem
        .run(&[path.as_os_str(), OsStr::new("version")], COMMAND_TIMEOUT)
        .unwrap();
    assert_eq!(by_path.stdout, b"Version: 2.0.0\n");
    // Without the inherited descriptor there is nothing to execute.
    let error = HostSystem.run(&argv, COMMAND_TIMEOUT);
    assert!(!matches!(&error, Ok(out) if out.success()), "{error:?}");
}

#[test]
fn binary_info_checks_the_descriptor_target_before_executing() {
    let _serial = serial();
    let dir = workdir();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let path = root.join("proxy");
    script(&path, "Version: 3.7.9");
    let info = binary_info(&HostSystem, &path, Some(&path), true).unwrap();
    assert_eq!(info.version.as_deref(), Some("3.7.9"));
    // A link to the binary resolves to it (`realpath`).
    let link = root.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(binary_info(&HostSystem, &path, Some(&link), true).is_ok());
    // Any other file is refused before anything runs: this one would leave
    // a marker if it were executed.
    let marker = root.join("executed");
    let other = root.join("other");
    install(
        &other,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
    );
    let error = binary_info(&HostSystem, &other, Some(&path), true).unwrap_err();
    assert_eq!(
        error.to_string(),
        "ValueError: refusing unexpected or deleted process image"
    );
    assert!(!marker.exists());
    // A binary that changes itself while probed through its descriptor.
    let changing = root.join("changing");
    install(
        &changing,
        b"#!/bin/sh\nprintf 'Version: 3.7.9\\n'\nprintf '#' >> \"$0\"\n",
    );
    let error = binary_info(&HostSystem, &changing, Some(&changing), true).unwrap_err();
    assert_eq!(
        error.to_string(),
        "ValueError: binary changed during observation"
    );
}
