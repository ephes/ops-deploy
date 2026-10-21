//! `System`: everything an observation reads from the host (PLAN.md 5.1).
//!
//! The observation code never touches the clock, the file system or a child
//! process directly; it asks a [`System`]. [`HostSystem`] is the real host.
//! The fixture tests replay the world that `fixtures/generate.py` recorded
//! around the Python code through a fake `System` (`probe::fake`), so the
//! Rust code sees the same answers Python saw.
//!
//! S2 provided the clock, file reads, `exists`, `stat`/`lstat`, `readlink`,
//! `realpath` and child processes with a timeout. S3b added the
//! pinned-descriptor operations: open a file, `fstat` and hash it through
//! its descriptor, and run a child that inherits exactly that descriptor, so
//! it can be executed as `/proc/self/fd/<fd>` (PLAN.md 3.3, Traefik). S3a
//! added the upstream HTTPS request and the atomic JSON write. The slices
//! that need more add it to this trait with their host and fake
//! implementations.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
// wait-timeout installs a SIGCHLD handler and waits on an AF_UNIX socket
// pair: fine in the collector unit, which restricts no address family.
use wait_timeout::ChildExt;

use serde_json::Value;

use crate::error::PyError;
use crate::http::{HttpClient, HttpRequest};
use crate::version::python_strip;

/// The default timeout of `command()` (`software_live.py:68`).
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// The fields of `os.stat_result` the observations use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

/// `file_identity(stat)` of `software_live.py:80-87`.
pub type Identity = (u64, u64, i128, i128, u64);

impl FileStat {
    pub fn identity(&self) -> Identity {
        (self.dev, self.ino, self.mtime_ns, self.ctime_ns, self.size)
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170_000 == 0o120_000
    }

    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        let ns = |seconds: i64, nanos: i64| i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.size(),
            mtime_ns: ns(metadata.mtime(), metadata.mtime_nsec()),
            ctime_ns: ns(metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// What a finished child process left: both captured streams and how it
/// ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The exit code; `None` when a signal ended the child.
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// How running a child process failed before it finished, as
/// `subprocess.run(timeout=…)` raises it. A non-zero exit is not an error
/// here: [`command`] decides that after decoding, as Python does.
#[derive(Debug)]
pub enum CommandError {
    /// The program could not be started (`FileNotFoundError`, `PermissionError`, `OSError`).
    Spawn(io::Error),
    /// The timeout passed; the child was killed (`TimeoutExpired`).
    Timeout(Duration),
    /// Reading the child's output failed.
    Io(io::Error),
}

impl CommandError {
    /// The error as an observation reports it. The classes are Python's;
    /// the messages name the program but no arguments (PLAN.md 4.2 item 5).
    pub fn to_py(&self, program: &OsStr) -> PyError {
        let program = program.to_string_lossy();
        match self {
            Self::Spawn(error) => {
                let mut py = PyError::os(error);
                py.message = format!("{}: '{program}'", py.message);
                py
            }
            Self::Timeout(timeout) => PyError::new(
                "TimeoutExpired",
                format!(
                    "Command '{program}' timed out after {} seconds",
                    timeout.as_secs()
                ),
            ),
            Self::Io(error) => PyError::os(error),
        }
    }

    /// Whether the program does not exist (`except FileNotFoundError`).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Spawn(error) if error.kind() == io::ErrorKind::NotFound)
    }
}

/// A file an observation holds open (`open(path, "rb")`). Its descriptor
/// pins the inode: the checks, the hash and an execution through
/// `/proc/self/fd/<fd>` all see the same file, whatever happens to its path
/// meanwhile.
pub trait OpenFile {
    /// The descriptor number (`stream.fileno()`).
    fn fd(&self) -> RawFd;
}

/// What an observation reads from the host.
pub trait System {
    /// A file [`System::open`] returns.
    type File: OpenFile;

    /// `time.time()`.
    fn now(&self) -> f64;
    /// The bytes of a file (`Path.read_bytes()`).
    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// `os.stat(path)` (follows symbolic links).
    fn stat(&self, path: &Path) -> io::Result<FileStat>;
    /// `os.lstat(path)`.
    fn lstat(&self, path: &Path) -> io::Result<FileStat>;
    /// `os.readlink(path)`.
    fn readlink(&self, path: &Path) -> io::Result<OsString>;
    /// Run `argv` (the program looked up in `PATH` unless it contains a
    /// `/`), no stdin, stdout and stderr captured, killed when `timeout`
    /// passes; returns what the finished child left, whatever its exit.
    fn run(&self, argv: &[&OsStr], timeout: Duration) -> Result<CommandOutput, CommandError>;
    /// `open(path, "rb")` (follows symbolic links, also `/proc/<pid>/exe`).
    fn open(&self, path: &Path) -> io::Result<Self::File>;
    /// `os.fstat(file.fileno())`.
    fn fstat(&self, file: &Self::File) -> io::Result<FileStat>;
    /// `hashlib.file_digest(file, "sha256").hexdigest()`: the bytes from the
    /// file's position (the start, for a file just opened) to its end.
    fn sha256(&self, file: &mut Self::File) -> io::Result<String>;
    /// [`System::run`] with `subprocess.run(…, pass_fds=(file.fileno(),))`:
    /// the child inherits exactly this descriptor under its own number, so
    /// `argv[0]` may be `/proc/self/fd/<fd>`.
    fn run_inheriting(
        &self,
        file: &Self::File,
        argv: &[&OsStr],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError>;
    /// One HTTPS GET (`urlopen` plus `read(limit)`, see [`crate::http`]);
    /// the error carries the class the observation reports.
    fn http_get(&self, request: &HttpRequest<'_>) -> Result<Vec<u8>, PyError>;
    /// `atomic_json(path, value, group)` (see [`crate::atomic`]).
    fn write_json(&self, path: &Path, value: &Value, group: Option<u32>) -> io::Result<()>;

    /// `Path(path).exists()` of Python 3.12 and 3.13 (the hosts'
    /// versions): `False` for a missing path, a non-directory in the path, a
    /// bad descriptor or a symlink loop; any other error (e.g. `EACCES`) is
    /// raised. (Python 3.14 reports every error as `False`.)
    fn exists(&self, path: &Path) -> io::Result<bool> {
        match self.stat(path) {
            Ok(_) => Ok(true),
            Err(error) if is_ignored_exists_error(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// `os.path.realpath(path)` (not strict) of Python 3.12.
    fn realpath(&self, path: &Path) -> io::Result<PathBuf> {
        realpath_with(
            path.as_os_str().as_bytes(),
            |p| self.lstat(Path::new(OsStr::from_bytes(p))),
            |p| {
                self.readlink(Path::new(OsStr::from_bytes(p)))
                    .map(OsString::into_vec)
            },
        )
        .map(|bytes| PathBuf::from(OsString::from_vec(bytes)))
    }
}

/// The errors pathlib's `exists()` treats as "does not exist" (Python 3.12
/// `pathlib._IGNORED_ERRNOS`).
fn is_ignored_exists_error(error: &io::Error) -> bool {
    use rustix::io::Errno;
    let ignored = [Errno::NOENT, Errno::NOTDIR, Errno::BADF, Errno::LOOP];
    error
        .raw_os_error()
        .is_some_and(|code| ignored.iter().any(|errno| errno.raw_os_error() == code))
}

/// `subprocess.run(text=True)` decoding: strict UTF-8, universal newlines.
fn decode_text(bytes: Vec<u8>) -> Result<String, PyError> {
    let text = String::from_utf8(bytes)
        .map_err(|error| PyError::new("UnicodeDecodeError", error.to_string()))?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `command(argv, timeout)` of `software_live.py:68-77`. As
/// `subprocess.run(capture_output=True, text=True, check=True)`: both
/// streams are decoded first (a stream that is not UTF-8 is a
/// `UnicodeDecodeError`, whatever the exit), then a non-zero exit is a
/// `CalledProcessError`; stdout is returned stripped.
pub fn command<S: System + ?Sized>(
    system: &S,
    argv: &[&OsStr],
    timeout: Duration,
) -> Result<String, PyError> {
    let program = argv.first().copied().unwrap_or_default();
    finish(program, system.run(argv, timeout))
}

/// `command(argv, timeout, pass_fds=(file.fileno(),))`: [`command`] with
/// `file`'s descriptor inherited by the child ([`System::run_inheriting`]).
pub fn command_inheriting<S: System + ?Sized>(
    system: &S,
    file: &S::File,
    argv: &[&OsStr],
    timeout: Duration,
) -> Result<String, PyError> {
    let program = argv.first().copied().unwrap_or_default();
    finish(program, system.run_inheriting(file, argv, timeout))
}

/// The part of `command()` after the child has finished.
fn finish(program: &OsStr, result: Result<CommandOutput, CommandError>) -> Result<String, PyError> {
    let output = result.map_err(|error| error.to_py(program))?;
    let success = output.success();
    let (code, signal) = (output.code, output.signal);
    let stdout = decode_text(output.stdout)?;
    decode_text(output.stderr)?;
    if !success {
        let program = program.to_string_lossy();
        let message = match code {
            Some(code) => format!("Command '{program}' returned non-zero exit status {code}."),
            None => format!(
                "Command '{program}' died with signal {}.",
                signal.unwrap_or_default()
            ),
        };
        return Err(PyError::new("CalledProcessError", message));
    }
    Ok(python_strip(&stdout).to_owned())
}

/// A file the host opened. `std::fs::File` opens with `O_CLOEXEC`, so no
/// child inherits it unless [`System::run_inheriting`] passes it.
#[derive(Debug)]
pub struct HostFile(std::fs::File);

impl OpenFile for HostFile {
    fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// The real host.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostSystem;

impl System for HostSystem {
    type File = HostFile;

    fn now(&self) -> f64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs_f64(),
            Err(before) => -before.duration().as_secs_f64(),
        }
    }

    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn stat(&self, path: &Path) -> io::Result<FileStat> {
        std::fs::metadata(path).map(|m| FileStat::from_metadata(&m))
    }

    fn lstat(&self, path: &Path) -> io::Result<FileStat> {
        std::fs::symlink_metadata(path).map(|m| FileStat::from_metadata(&m))
    }

    fn readlink(&self, path: &Path) -> io::Result<OsString> {
        std::fs::read_link(path).map(PathBuf::into_os_string)
    }

    fn run(&self, argv: &[&OsStr], timeout: Duration) -> Result<CommandOutput, CommandError> {
        spawn_and_wait(argv, timeout, || {})
    }

    fn open(&self, path: &Path) -> io::Result<HostFile> {
        std::fs::File::open(path).map(HostFile)
    }

    fn fstat(&self, file: &HostFile) -> io::Result<FileStat> {
        file.0.metadata().map(|m| FileStat::from_metadata(&m))
    }

    fn sha256(&self, file: &mut HostFile) -> io::Result<String> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1 << 18];
        loop {
            match file.0.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// The equivalent of `pass_fds` without `pre_exec` (which is `unsafe`):
    /// `FD_CLOEXEC` is cleared on exactly this descriptor right before the
    /// spawn and set again as soon as the spawn returns. `spawn` returns only
    /// after the child has executed its program (or failed to), so the child
    /// keeps the descriptor under the same number and no later child sees
    /// it. This is race-free because `collect` is single-threaded and starts
    /// no other child meanwhile (PLAN.md 3.3).
    fn run_inheriting(
        &self,
        file: &HostFile,
        argv: &[&OsStr],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError> {
        use rustix::io::{FdFlags, fcntl_setfd};
        fcntl_setfd(&file.0, FdFlags::empty())
            .map_err(|errno| CommandError::Spawn(errno.into()))?;
        spawn_and_wait(argv, timeout, || {
            // Cannot fail on a descriptor that is open; the file is closed
            // when the observation drops it either way.
            let _ = fcntl_setfd(&file.0, FdFlags::CLOEXEC);
        })
    }

    fn http_get(&self, request: &HttpRequest<'_>) -> Result<Vec<u8>, PyError> {
        // The system store is read once per process (collect makes up to
        // three requests).
        static CLIENT: OnceLock<Result<HttpClient, PyError>> = OnceLock::new();
        match CLIENT.get_or_init(HttpClient::system) {
            Ok(client) => client.get(request),
            Err(error) => Err(error.clone()),
        }
    }

    fn write_json(&self, path: &Path, value: &Value, group: Option<u32>) -> io::Result<()> {
        crate::atomic::write_json(path, value, group)
    }
}

/// Start `argv` (no stdin, both streams captured), call `after_spawn` as
/// soon as the spawn has returned (whether it worked or not), then wait for
/// the child until `timeout` passes.
fn spawn_and_wait(
    argv: &[&OsStr],
    timeout: Duration,
    after_spawn: impl FnOnce(),
) -> Result<CommandOutput, CommandError> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| CommandError::Spawn(io::Error::other("empty command")))?;
    let deadline = Instant::now() + timeout;
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    after_spawn();
    let mut child = spawned.map_err(CommandError::Spawn)?;
    // Drain both pipes while waiting, as `communicate()` does, so a
    // chatty child never blocks on a full pipe.
    let (sender, receiver) = mpsc::channel();
    let stdout = child
        .stdout
        .take()
        .map(|pipe| drain(pipe, 0, sender.clone()));
    let stderr = child.stderr.take().map(|pipe| drain(pipe, 1, sender));
    let status = match child.wait_timeout(remaining(deadline)) {
        Ok(Some(status)) => status,
        Ok(None) => return Err(kill(&mut child, timeout)),
        Err(error) => {
            kill(&mut child, timeout);
            return Err(CommandError::Io(error));
        }
    };
    // A grandchild may still hold a pipe open: wait for the end of
    // both pipes only until the deadline (Python's `communicate()` times
    // out the same way).
    let mut output = CommandOutput {
        code: status.code(),
        signal: status.signal(),
        ..CommandOutput::default()
    };
    for _ in [&stdout, &stderr].iter().filter(|pipe| pipe.is_some()) {
        match receiver.recv_timeout(remaining(deadline)) {
            Ok((0, Ok(bytes))) => output.stdout = bytes,
            Ok((_, Ok(bytes))) => output.stderr = bytes,
            Ok((_, Err(error))) => return Err(CommandError::Io(error)),
            Err(_) => return Err(CommandError::Timeout(timeout)),
        }
    }
    Ok(output)
}

type Drained = (u8, io::Result<Vec<u8>>);

fn drain<R: Read + Send + 'static>(
    mut pipe: R,
    which: u8,
    sender: mpsc::Sender<Drained>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe.read_to_end(&mut bytes).map(|_| bytes);
        // The receiver is gone after a timeout; nothing left to report.
        let _ = sender.send((which, result));
    })
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Kill and reap the child, as `subprocess.run` does on a timeout.
fn kill(child: &mut Child, timeout: Duration) -> CommandError {
    // Fails only if the child has already exited; it is reaped either way.
    let _ = child.kill();
    let _ = child.wait();
    CommandError::Timeout(timeout)
}

/// `posixpath.join(a, b)` for a relative `b`.
fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    if !out.is_empty() && !out.ends_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(b);
    out
}

/// `posixpath.split(path)`.
fn split(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cut = path.iter().rposition(|b| *b == b'/').map_or(0, |i| i + 1);
    let (head, tail) = path.split_at(cut);
    let trimmed: &[u8] = if !head.is_empty() && head.iter().any(|b| *b != b'/') {
        let end = head.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
        &head[..end]
    } else {
        head
    };
    (trimmed.to_vec(), tail.to_vec())
}

/// `posixpath.normpath(path)`.
fn normpath(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return b".".to_vec();
    }
    let initial = if path.starts_with(b"//") && !path.starts_with(b"///") {
        2
    } else if path.starts_with(b"/") {
        1
    } else {
        0
    };
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in path.split(|b| *b == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part != b".." || (initial == 0 && parts.is_empty()) || parts.last() == Some(&&b".."[..])
        {
            parts.push(part);
        } else if !parts.is_empty() {
            parts.pop();
        }
    }
    let mut out = b"/".repeat(initial);
    out.extend_from_slice(&parts.join(&b'/'));
    if out.is_empty() { b".".to_vec() } else { out }
}

/// `os.path.realpath(path, strict=False)` of Python 3.12 (`posixpath`),
/// over the given `lstat` and `readlink`: symbolic links are resolved where
/// a component exists, the rest of the path is kept, a loop leaves the
/// looping link unresolved. A relative path is made absolute first.
pub fn realpath_with(
    path: &[u8],
    lstat: impl Fn(&[u8]) -> io::Result<FileStat>,
    readlink: impl Fn(&[u8]) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    let absolute = if path.starts_with(b"/") {
        path.to_vec()
    } else {
        join(std::env::current_dir()?.as_os_str().as_bytes(), path)
    };
    let mut seen = std::collections::HashMap::new();
    let (resolved, _) = join_realpath(Vec::new(), &absolute, &lstat, &readlink, &mut seen)?;
    Ok(normpath(&resolved))
}

type Seen = std::collections::HashMap<Vec<u8>, Option<Vec<u8>>>;

/// `posixpath._joinrealpath` (Python 3.12, `strict=False`).
fn join_realpath(
    mut path: Vec<u8>,
    rest: &[u8],
    lstat: &impl Fn(&[u8]) -> io::Result<FileStat>,
    readlink: &impl Fn(&[u8]) -> io::Result<Vec<u8>>,
    seen: &mut Seen,
) -> io::Result<(Vec<u8>, bool)> {
    let mut rest = rest;
    if rest.starts_with(b"/") {
        rest = &rest[1..];
        path = b"/".to_vec();
    }
    while !rest.is_empty() {
        let (name, tail) = match rest.iter().position(|b| *b == b'/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &b""[..]),
        };
        rest = tail;
        if name.is_empty() || name == b"." {
            continue;
        }
        if name == b".." {
            if path.is_empty() {
                path = b"..".to_vec();
            } else {
                let (head, last) = split(&path);
                path = if last == b".." {
                    join(&join(&head, b".."), b"..")
                } else {
                    head
                };
            }
            continue;
        }
        let newpath = join(&path, name);
        let is_link = lstat(&newpath).is_ok_and(|st| st.is_symlink());
        if !is_link {
            path = newpath;
            continue;
        }
        if let Some(known) = seen.get(&newpath) {
            match known {
                Some(resolved) => {
                    path = resolved.clone();
                    continue;
                }
                // A symlink loop: return the rest unresolved.
                None => return Ok((join(&newpath, rest), false)),
            }
        }
        seen.insert(newpath.clone(), None);
        let target = readlink(&newpath)?;
        let (resolved, ok) = join_realpath(path, &target, lstat, readlink, seen)?;
        if !ok {
            return Ok((join(&resolved, rest), false));
        }
        seen.insert(newpath, Some(resolved.clone()));
        path = resolved;
    }
    Ok((path, true))
}

/// A recorded world for the fixture tests: the `System` answers what the
/// generator's patches answered Python, and logs every call.
#[cfg(test)]
pub mod fake {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};

    use serde::Deserialize;

    use super::*;

    /// An error by its errno name (`ENOENT`, `EACCES`, …).
    fn errno(name: &str) -> io::Error {
        use rustix::io::Errno;
        let errno = match name {
            "ENOENT" => Errno::NOENT,
            "EACCES" => Errno::ACCESS,
            "ENOTDIR" => Errno::NOTDIR,
            "ELOOP" => Errno::LOOP,
            "EISDIR" => Errno::ISDIR,
            "EINVAL" => Errno::INVAL,
            "EBADF" => Errno::BADF,
            "EEXIST" => Errno::EXIST,
            "EROFS" => Errno::ROFS,
            other => panic!("unknown errno {other} in a fixture world"),
        };
        io::Error::from_raw_os_error(errno.raw_os_error())
    }

    /// One answer: `{"ok": value}` or `{"errno": "ENOENT"}`. (A struct, not
    /// an untagged enum: serde's buffering of untagged content loses
    /// `arbitrary_precision` numbers.)
    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Entry<T> {
        // A missing `Option` field is `None` without `#[serde(default)]`.
        ok: Option<T>,
        errno: Option<String>,
    }

    impl<T: Clone> Entry<T> {
        fn get(&self) -> io::Result<T> {
            match (&self.ok, &self.errno) {
                (Some(ok), None) => Ok(ok.clone()),
                (None, Some(name)) => Err(errno(name)),
                _ => panic!("an answer is either ok or an errno"),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct StatSpec {
        #[serde(default)]
        pub dev: u64,
        #[serde(default)]
        pub ino: u64,
        pub mode: u32,
        #[serde(default = "one")]
        pub nlink: u64,
        #[serde(default)]
        pub uid: u32,
        #[serde(default)]
        pub gid: u32,
        #[serde(default)]
        pub size: u64,
        #[serde(default)]
        pub mtime_ns: i128,
        #[serde(default)]
        pub ctime_ns: i128,
    }

    fn one() -> u64 {
        1
    }

    impl From<StatSpec> for FileStat {
        fn from(s: StatSpec) -> Self {
            Self {
                dev: s.dev,
                ino: s.ino,
                mode: s.mode,
                nlink: s.nlink,
                uid: s.uid,
                gid: s.gid,
                size: s.size,
                mtime_ns: s.mtime_ns,
                ctime_ns: s.ctime_ns,
            }
        }
    }

    /// A file of the world: text, raw bytes (hex) or an errno.
    #[derive(Clone, Debug, Deserialize)]
    #[serde(untagged)]
    pub enum FileEntry {
        Text { ok: String },
        Bytes { hex: String },
        Err { errno: String },
    }

    impl FileEntry {
        fn get(&self) -> io::Result<Vec<u8>> {
            match self {
                Self::Text { ok } => Ok(ok.clone().into_bytes()),
                Self::Bytes { hex } => {
                    Ok(::hex::decode(hex).expect("hex bytes in a fixture world"))
                }
                Self::Err { errno: name } => Err(errno(name)),
            }
        }
    }

    /// One expected HTTPS request: its URL, headers (names in lower case)
    /// and timeout, and the answer — a body (cut at the request's limit,
    /// as `read(limit)`) or an error class.
    #[derive(Clone, Debug, Deserialize)]
    pub struct HttpSpec {
        pub url: String,
        pub headers: BTreeMap<String, String>,
        pub timeout: f64,
        #[serde(default)]
        pub body: Option<String>,
        #[serde(default)]
        pub body_hex: Option<String>,
        /// The body continues with `pad` copies of `pad_char` (default a
        /// space) and then `suffix`, so a fixture can describe a long body.
        #[serde(default)]
        pub pad: usize,
        #[serde(default)]
        pub pad_char: Option<String>,
        #[serde(default)]
        pub suffix: String,
        #[serde(default)]
        pub error: Option<String>,
    }

    impl HttpSpec {
        pub fn bytes(&self) -> Vec<u8> {
            let mut bytes = match (&self.body, &self.body_hex) {
                (Some(text), None) => text.clone().into_bytes(),
                (None, Some(hex)) => ::hex::decode(hex).expect("hex bytes in a fixture world"),
                (None, None) => Vec::new(),
                _ => panic!("a fixture body is text or hex, not both"),
            };
            let pad = self.pad_char.as_deref().unwrap_or(" ");
            bytes.extend(pad.repeat(self.pad).into_bytes());
            bytes.extend(self.suffix.as_bytes());
            bytes
        }
    }

    /// One expected child process: its argv and what it did.
    #[derive(Clone, Debug, Deserialize)]
    pub struct CommandSpec {
        pub argv: Vec<String>,
        #[serde(default)]
        pub stdout: String,
        #[serde(default)]
        pub stderr: String,
        /// Exit code (0 when absent).
        #[serde(default)]
        pub exit: i32,
        /// `"timeout"` or an errno name for a failed start.
        #[serde(default)]
        pub error: Option<String>,
        /// The descriptors the child inherits (`pass_fds`).
        #[serde(default)]
        pub pass_fds: Vec<RawFd>,
    }

    /// What `open(path, "rb")` gives: a descriptor number, the file's bytes
    /// and the answers of `fstat` on it (consumed in order, the last one
    /// repeats; none left is `EBADF`).
    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OpenSpec {
        pub fd: RawFd,
        pub data: String,
        #[serde(default)]
        pub fstat: Vec<Entry<StatSpec>>,
    }

    pub struct FakeFile {
        fd: RawFd,
        data: Vec<u8>,
        fstat: RefCell<VecDeque<Entry<StatSpec>>>,
    }

    impl OpenFile for FakeFile {
        fn fd(&self) -> RawFd {
            self.fd
        }
    }

    /// The world of one fixture case. Paths map to a value or an errno;
    /// a path that is not listed does not exist (`ENOENT`). A list of
    /// answers for a path is consumed in order (the last one repeats), as
    /// the `side_effect` lists of the Python tests.
    #[derive(Clone, Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct World {
        #[serde(default)]
        pub now: Vec<f64>,
        #[serde(default)]
        pub files: BTreeMap<String, FileEntry>,
        #[serde(default)]
        pub stat: BTreeMap<String, Vec<Entry<StatSpec>>>,
        #[serde(default)]
        pub lstat: BTreeMap<String, Vec<Entry<StatSpec>>>,
        #[serde(default)]
        pub readlink: BTreeMap<String, Vec<Entry<String>>>,
        #[serde(default)]
        pub commands: Vec<CommandSpec>,
        /// `open(path, "rb")` answers per path.
        #[serde(default)]
        pub open: BTreeMap<String, Vec<Entry<OpenSpec>>>,
        /// `os.path.realpath(path)` answers; a path not listed is its own
        /// real path (the fixture generator patches `realpath` the same way).
        #[serde(default)]
        pub realpath: BTreeMap<String, String>,
        #[serde(default)]
        pub http: Vec<HttpSpec>,
        /// Paths whose `write_json` fails with this errno.
        #[serde(default)]
        pub write_errors: BTreeMap<String, String>,
    }

    /// A `write_json` the code under test made.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Write {
        pub path: String,
        pub value: Value,
        pub group: Option<u32>,
    }

    pub struct FakeSystem {
        now: RefCell<VecDeque<f64>>,
        last_now: RefCell<f64>,
        world: World,
        files: RefCell<BTreeMap<String, FileEntry>>,
        http: RefCell<VecDeque<HttpSpec>>,
        pub writes: RefCell<Vec<Write>>,
        stat: RefCell<BTreeMap<String, VecDeque<Entry<StatSpec>>>>,
        lstat: RefCell<BTreeMap<String, VecDeque<Entry<StatSpec>>>>,
        readlink: RefCell<BTreeMap<String, VecDeque<Entry<String>>>>,
        open: RefCell<BTreeMap<String, VecDeque<Entry<OpenSpec>>>>,
        commands: RefCell<VecDeque<CommandSpec>>,
        pub calls: RefCell<Vec<String>>,
    }

    fn queues<T: Clone>(map: &BTreeMap<String, Vec<T>>) -> BTreeMap<String, VecDeque<T>> {
        map.iter()
            .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
            .collect()
    }

    /// The next answer; the last one repeats.
    fn next<T: Clone>(queues: &RefCell<BTreeMap<String, VecDeque<T>>>, key: &str) -> Option<T> {
        let mut queues = queues.borrow_mut();
        let queue = queues.get_mut(key)?;
        if queue.len() > 1 {
            queue.pop_front()
        } else {
            queue.front().cloned()
        }
    }

    fn key(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    impl FakeSystem {
        pub fn new(world: World) -> Self {
            Self {
                now: RefCell::new(world.now.iter().copied().collect()),
                last_now: RefCell::new(0.0),
                stat: RefCell::new(queues(&world.stat)),
                lstat: RefCell::new(queues(&world.lstat)),
                readlink: RefCell::new(queues(&world.readlink)),
                open: RefCell::new(queues(&world.open)),
                commands: RefCell::new(world.commands.iter().cloned().collect()),
                files: RefCell::new(world.files.clone()),
                http: RefCell::new(world.http.iter().cloned().collect()),
                writes: RefCell::new(Vec::new()),
                world,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn log(&self, call: String) {
            self.calls.borrow_mut().push(call);
        }

        /// Commands the world expected that were never run.
        pub fn pending_commands(&self) -> usize {
            self.commands.borrow().len()
        }

        /// The next expected command; its argv and inherited descriptors
        /// must be the ones the code runs.
        fn next_command(
            &self,
            argv: &[&OsStr],
            pass_fds: &[RawFd],
            timeout: Duration,
        ) -> Result<CommandOutput, CommandError> {
            let argv: Vec<String> = argv
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let fds: String = pass_fds
                .iter()
                .map(|fd| format!(" pass_fds={fd}"))
                .collect();
            self.log(format!("run {}{fds}", argv.join(" ")));
            let spec = self
                .commands
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected command {argv:?}"));
            assert_eq!(spec.argv, argv, "the commands ran out of order");
            assert_eq!(spec.pass_fds, pass_fds, "inherited descriptors of {argv:?}");
            match spec.error.as_deref() {
                Some("timeout") => Err(CommandError::Timeout(timeout)),
                Some(name) => Err(CommandError::Spawn(errno(name))),
                None => Ok(CommandOutput {
                    stdout: spec.stdout.into_bytes(),
                    stderr: spec.stderr.into_bytes(),
                    code: Some(spec.exit),
                    signal: None,
                }),
            }
        }

        /// HTTPS requests the world expected that were never made.
        pub fn pending_http(&self) -> usize {
            self.http.borrow().len()
        }

        /// Expect these HTTPS requests after the ones already expected.
        pub fn push_http(&self, specs: &[HttpSpec]) {
            self.http.borrow_mut().extend(specs.iter().cloned());
        }

        /// The current bytes of a file of the world (after writes).
        pub fn file(&self, path: &str) -> Option<io::Result<Vec<u8>>> {
            self.files.borrow().get(path).map(FileEntry::get)
        }
    }

    impl System for FakeSystem {
        type File = FakeFile;

        fn now(&self) -> f64 {
            self.log("now".into());
            if let Some(now) = self.now.borrow_mut().pop_front() {
                *self.last_now.borrow_mut() = now;
            }
            *self.last_now.borrow()
        }

        fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.log(format!("read_file {}", path.display()));
            match self.files.borrow().get(&key(path)) {
                Some(entry) => entry.get(),
                None => Err(errno("ENOENT")),
            }
        }

        fn stat(&self, path: &Path) -> io::Result<FileStat> {
            self.log(format!("stat {}", path.display()));
            next(&self.stat, &key(path))
                .map_or_else(|| Err(errno("ENOENT")), |e| e.get().map(Into::into))
        }

        fn lstat(&self, path: &Path) -> io::Result<FileStat> {
            self.log(format!("lstat {}", path.display()));
            next(&self.lstat, &key(path))
                .map_or_else(|| Err(errno("ENOENT")), |e| e.get().map(Into::into))
        }

        fn readlink(&self, path: &Path) -> io::Result<OsString> {
            self.log(format!("readlink {}", path.display()));
            next(&self.readlink, &key(path))
                .map_or_else(|| Err(errno("ENOENT")), |e| e.get().map(OsString::from))
        }

        fn run(&self, argv: &[&OsStr], timeout: Duration) -> Result<CommandOutput, CommandError> {
            self.next_command(argv, &[], timeout)
        }

        fn open(&self, path: &Path) -> io::Result<FakeFile> {
            self.log(format!("open {}", path.display()));
            let spec =
                next(&self.open, &key(path)).map_or_else(|| Err(errno("ENOENT")), |e| e.get())?;
            Ok(FakeFile {
                fd: spec.fd,
                data: spec.data.into_bytes(),
                fstat: RefCell::new(spec.fstat.into_iter().collect()),
            })
        }

        fn fstat(&self, file: &FakeFile) -> io::Result<FileStat> {
            self.log(format!("fstat {}", file.fd));
            let mut queue = file.fstat.borrow_mut();
            let entry = if queue.len() > 1 {
                queue.pop_front()
            } else {
                queue.front().cloned()
            };
            entry.map_or_else(|| Err(errno("EBADF")), |e| e.get().map(Into::into))
        }

        fn sha256(&self, file: &mut FakeFile) -> io::Result<String> {
            self.log(format!("sha256 {}", file.fd));
            Ok(hex::encode(Sha256::digest(&file.data)))
        }

        fn run_inheriting(
            &self,
            file: &FakeFile,
            argv: &[&OsStr],
            timeout: Duration,
        ) -> Result<CommandOutput, CommandError> {
            self.next_command(argv, &[file.fd], timeout)
        }

        fn realpath(&self, path: &Path) -> io::Result<PathBuf> {
            self.log(format!("realpath {}", path.display()));
            Ok(self
                .world
                .realpath
                .get(&key(path))
                .map_or_else(|| path.to_path_buf(), PathBuf::from))
        }

        fn http_get(&self, request: &HttpRequest<'_>) -> Result<Vec<u8>, PyError> {
            self.log(format!("http_get {}", request.url));
            let spec = self
                .http
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected request {}", request.url));
            assert_eq!(spec.url, request.url, "the requests ran out of order");
            let headers: BTreeMap<String, String> = request
                .headers
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned()))
                .collect();
            assert_eq!(spec.headers, headers, "{}", request.url);
            assert_eq!(
                spec.timeout,
                request.timeout.as_secs_f64(),
                "{}",
                request.url
            );
            if let Some(class) = &spec.error {
                let class: &'static str = Box::leak(class.clone().into_boxed_str());
                return Err(PyError::new(class, "fixture"));
            }
            let mut body = spec.bytes();
            body.truncate(usize::try_from(request.limit).unwrap_or(usize::MAX));
            Ok(body)
        }

        fn write_json(&self, path: &Path, value: &Value, group: Option<u32>) -> io::Result<()> {
            let path = key(path);
            self.log(format!("write_json {path}"));
            self.writes.borrow_mut().push(Write {
                path: path.clone(),
                value: value.clone(),
                group,
            });
            if let Some(name) = self.world.write_errors.get(&path) {
                return Err(errno(name));
            }
            let text = String::from_utf8(crate::atomic::render(value)).expect("ASCII JSON");
            self.files
                .borrow_mut()
                .insert(path, FileEntry::Text { ok: text });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{FakeSystem, World};
    use super::*;
    use serde::Deserialize;
    use std::os::unix::fs::symlink;

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    /// The tests that start processes run one at a time: macOS has no
    /// `pipe2`, so a pipe is briefly inheritable while another thread
    /// spawns, and a lingering grandchild of one test would then hold the
    /// pipe of another (the collector itself runs one child at a time).
    static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
        SPAWN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn host_clock_is_epoch_seconds() {
        // After 2023-11 and before 2100.
        let now = HostSystem.now();
        assert!((1.7e9..4.1e9).contains(&now), "{now}");
    }

    #[test]
    fn command_output_is_decoded_translated_and_stripped() {
        let _serial = spawn_lock();
        let out = command(
            &HostSystem,
            &[
                os("/bin/sh"),
                os("-c"),
                os("printf ' \\034a\\r\\nb\\rc\\n '"),
            ],
            COMMAND_TIMEOUT,
        )
        .unwrap();
        assert_eq!(out, "a\nb\nc");
    }

    #[test]
    fn command_failures_have_python_classes() {
        let _serial = spawn_lock();
        let class =
            |argv: &[&OsStr], timeout| command(&HostSystem, argv, timeout).unwrap_err().class;
        assert_eq!(
            class(&[os("/bin/sh"), os("-c"), os("exit 3")], COMMAND_TIMEOUT),
            "CalledProcessError"
        );
        assert_eq!(
            class(&[os("/nonexistent/program")], COMMAND_TIMEOUT),
            "FileNotFoundError"
        );
        assert_eq!(
            class(
                &[os("/bin/sh"), os("-c"), os("printf '\\377'")],
                COMMAND_TIMEOUT
            ),
            "UnicodeDecodeError"
        );
        // Both streams are decoded before the exit status counts.
        assert_eq!(
            class(
                &[os("/bin/sh"), os("-c"), os("printf ok; printf '\\377' >&2")],
                COMMAND_TIMEOUT
            ),
            "UnicodeDecodeError"
        );
        assert_eq!(
            class(
                &[os("/bin/sh"), os("-c"), os("printf '\\377'; exit 4")],
                COMMAND_TIMEOUT
            ),
            "UnicodeDecodeError"
        );
        assert_eq!(
            class(
                &[os("/bin/sh"), os("-c"), os("kill -9 $$")],
                COMMAND_TIMEOUT
            ),
            "CalledProcessError"
        );
        let started = Instant::now();
        assert_eq!(
            class(&[os("/bin/sleep"), os("10")], Duration::from_millis(200)),
            "TimeoutExpired"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let error = HostSystem
            .run(&[os("/nonexistent/program")], COMMAND_TIMEOUT)
            .unwrap_err();
        assert!(error.is_not_found());
    }

    #[test]
    fn a_grandchild_holding_the_pipe_times_out() {
        let _serial = spawn_lock();
        let started = Instant::now();
        let error = HostSystem
            .run(
                &[os("/bin/sh"), os("-c"), os("sleep 3 & echo started")],
                Duration::from_millis(300),
            )
            .unwrap_err();
        assert!(matches!(error, CommandError::Timeout(_)), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn large_output_on_both_pipes_does_not_block() {
        let _serial = spawn_lock();
        let script = "head -c 300000 /dev/zero | tr '\\0' a; head -c 300000 /dev/zero >&2";
        let out = HostSystem
            .run(&[os("/bin/sh"), os("-c"), os(script)], COMMAND_TIMEOUT)
            .unwrap();
        assert_eq!((out.stdout.len(), out.stderr.len()), (300_000, 300_000));
        assert!(out.success());
    }

    fn cloexec(file: &HostFile) -> bool {
        rustix::io::fcntl_getfd(&file.0)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    }

    #[test]
    fn open_file_is_hashed_and_stated_through_its_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary");
        std::fs::write(&path, b"unexpected bytes").unwrap();
        let mut file = HostSystem.open(&path).unwrap();
        assert!(cloexec(&file), "opened with O_CLOEXEC");
        let before = HostSystem.fstat(&file).unwrap();
        assert_eq!(
            before.identity(),
            HostSystem.stat(&path).unwrap().identity()
        );
        assert_eq!(before.size, 16);
        // sha256(b"unexpected bytes"), as the Python test computes it.
        assert_eq!(
            HostSystem.sha256(&mut file).unwrap(),
            hex::encode(Sha256::digest(b"unexpected bytes"))
        );
        // Replacing the path leaves the descriptor on the old inode (whose
        // ctime may move as its last link goes).
        std::fs::write(dir.path().join("new"), b"other").unwrap();
        std::fs::rename(dir.path().join("new"), &path).unwrap();
        let pinned = HostSystem.fstat(&file).unwrap();
        assert_eq!(
            (pinned.dev, pinned.ino, pinned.size),
            (before.dev, before.ino, 16)
        );
        assert_ne!(HostSystem.stat(&path).unwrap().ino, before.ino);
    }

    #[test]
    fn only_run_inheriting_passes_the_descriptor() {
        let _serial = spawn_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pinned");
        std::fs::write(&path, b"pinned bytes").unwrap();
        let file = HostSystem.open(&path).unwrap();
        // `/dev/fd/<n>` is the child's own descriptor n (Linux and macOS).
        let script = format!("cat /dev/fd/{}", file.fd());
        let argv = [os("/bin/sh"), os("-c"), os(&script)];
        let out = HostSystem
            .run_inheriting(&file, &argv, COMMAND_TIMEOUT)
            .unwrap();
        assert!(out.success(), "{out:?}");
        assert_eq!(out.stdout, b"pinned bytes");
        assert!(cloexec(&file), "close-on-exec is set again after the spawn");
        let out = HostSystem.run(&argv, COMMAND_TIMEOUT).unwrap();
        assert!(!out.success(), "a plain run must not see the descriptor");
        assert!(out.stdout.is_empty());
        // A failed start and a timeout restore the flag as well.
        let error = HostSystem
            .run_inheriting(&file, &[os("/nonexistent/program")], COMMAND_TIMEOUT)
            .unwrap_err();
        assert!(error.is_not_found());
        assert!(cloexec(&file));
        let error = HostSystem
            .run_inheriting(
                &file,
                &[os("/bin/sleep"), os("10")],
                Duration::from_millis(200),
            )
            .unwrap_err();
        assert!(matches!(error, CommandError::Timeout(_)), "{error:?}");
        assert!(cloexec(&file));
        // A fresh descriptor: on macOS `/dev/fd/<n>` shares the offset that
        // the first `cat` moved to the end.
        let file = HostSystem.open(&path).unwrap();
        let script = format!("cat /dev/fd/{}", file.fd());
        let argv = [os("/bin/sh"), os("-c"), os(&script)];
        assert_eq!(
            command_inheriting(&HostSystem, &file, &argv, COMMAND_TIMEOUT).unwrap(),
            "pinned bytes"
        );
    }

    #[test]
    fn exists_ignores_only_pathlibs_errnos() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(HostSystem.exists(&file).unwrap());
        assert!(!HostSystem.exists(&dir.path().join("missing")).unwrap());
        assert!(!HostSystem.exists(&file.join("below-a-file")).unwrap());
        let a = dir.path().join("a");
        symlink(dir.path().join("b"), &a).unwrap();
        symlink(&a, dir.path().join("b")).unwrap();
        assert!(!HostSystem.exists(&a).unwrap());
    }

    #[derive(Deserialize)]
    struct RealpathFixtures {
        tree: Vec<Node>,
        cases: Vec<RealpathCase>,
    }

    #[derive(Deserialize)]
    struct Node {
        path: String,
        #[serde(default)]
        link: Option<String>,
        #[serde(default)]
        file: bool,
    }

    #[derive(Deserialize)]
    struct RealpathCase {
        path: String,
        result: String,
    }

    #[test]
    fn realpath_matches_python_on_a_real_tree() {
        let fixtures: RealpathFixtures =
            serde_json::from_str(include_str!("../fixtures/realpath.json")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let root_text = root.to_str().unwrap().to_owned();
        let at = |p: &str| PathBuf::from(p.replace("{root}", &root_text));
        for node in &fixtures.tree {
            let path = at(&node.path);
            match (&node.link, node.file) {
                (Some(target), _) => symlink(at(target), &path).unwrap(),
                (None, true) => std::fs::write(&path, b"").unwrap(),
                (None, false) => std::fs::create_dir(&path).unwrap(),
            }
        }
        assert!(fixtures.cases.len() >= 15);
        for case in fixtures.cases {
            let actual = HostSystem.realpath(&at(&case.path)).unwrap();
            assert_eq!(actual, at(&case.result), "{}", case.path);
        }
    }

    #[test]
    fn normpath_and_split_follow_posixpath() {
        assert_eq!(normpath(b"//a//b/./../c/"), b"//a/c");
        assert_eq!(normpath(b"///a/.."), b"/");
        assert_eq!(normpath(b"a/../../b"), b"../b");
        assert_eq!(normpath(b""), b".");
        assert_eq!(split(b"/a/b"), (b"/a".to_vec(), b"b".to_vec()));
        assert_eq!(split(b"/"), (b"/".to_vec(), b"".to_vec()));
        assert_eq!(split(b"//a"), (b"//".to_vec(), b"a".to_vec()));
    }

    #[test]
    fn fake_world_replays_answers_in_order() {
        let world: World = serde_json::from_value(serde_json::json!({
            "now": [10.5, 11.0],
            "files": {"/etc/os-release": {"ok": "ID=debian\n"}, "/denied": {"errno": "EACCES"}},
            "readlink": {"/proc/1/exe": [{"ok": "/usr/bin/a"}, {"ok": "/usr/bin/b"}]},
            "lstat": {"/l": [{"ok": {"mode": 0o120777}}]},
            "commands": [{"argv": ["systemctl", "show"], "stdout": "11\n"}, {"argv": ["x"], "exit": 3}]
        }))
        .unwrap();
        let fake = FakeSystem::new(world);
        assert_eq!((fake.now(), fake.now(), fake.now()), (10.5, 11.0, 11.0));
        assert_eq!(
            fake.read_file(Path::new("/etc/os-release")).unwrap(),
            b"ID=debian\n"
        );
        assert_eq!(
            fake.read_file(Path::new("/denied")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!fake.exists(Path::new("/missing")).unwrap());
        let link = || fake.readlink(Path::new("/proc/1/exe")).unwrap();
        assert_eq!(
            (link(), link(), link()),
            (
                "/usr/bin/a".into(),
                "/usr/bin/b".into(),
                "/usr/bin/b".into()
            )
        );
        assert!(fake.lstat(Path::new("/l")).unwrap().is_symlink());
        assert_eq!(
            command(&fake, &[os("systemctl"), os("show")], COMMAND_TIMEOUT).unwrap(),
            "11"
        );
        assert_eq!(
            command(&fake, &[os("x")], COMMAND_TIMEOUT)
                .unwrap_err()
                .class,
            "CalledProcessError"
        );
        assert_eq!(fake.pending_commands(), 0);
        assert!(
            fake.calls
                .borrow()
                .iter()
                .any(|c| c == "run systemctl show")
        );
    }
}
