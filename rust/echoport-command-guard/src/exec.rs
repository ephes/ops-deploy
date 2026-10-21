//! The hand-off to an allowed command (PLAN.md 3.5; `guard.py:713-717`).
//!
//! What the command inherits is what it inherits from the Python guard:
//!
//! - the environment unchanged, except `PATH = SAFE_PATH` and the
//!   `LC_CTYPE` that CPython's PEP 538 locale coercion exports
//!   ([`coerce_c_locale`]);
//! - SIGPIPE and SIGXFSZ ignored (CPython ignores both at startup);
//! - fds 0, 1 and 2 (every descriptor the guard opens is close-on-exec);
//! - the umask the flow set, or the inherited one.
//!
//! The PATH search is CPython's `os.execvp` (`os._execvpe`), not libc
//! `execvp`: no `/bin/sh` fallback on `ENOEXEC`, and every error but
//! `ENOENT`/`ENOTDIR` is remembered and reported if nothing runs
//! ([`execvp`]).
//!
//! The only `unsafe` code of the crate is here (PLAN.md 5.3): libc
//! `setlocale`/`nl_langinfo`, `std::env::set_var` and `sigaction`, each
//! called from the single-threaded guard right before the exec.

use std::convert::Infallible;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use nix::errno::Errno;
use nix::sys::signal::{SigHandler, Signal, signal};
use nix::unistd::execv;

/// `SAFE_PATH` (`guard.py:33`).
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The locales CPython 3.12/3.13 tries, in order (`_TARGET_LOCALES` in
/// `Python/pylifecycle.c`).
const COERCION_TARGETS: [&CStr; 3] = [c"C.UTF-8", c"C.utf8", c"UTF-8"];

/// CPython's PEP 538 C locale coercion as it runs for `python3 -I` (CPython
/// 3.12 and 3.13, `Python/preconfig.c` and `Python/pylifecycle.c`; `-I`
/// ignores `PYTHONCOERCECLOCALE`):
///
/// 1. `setlocale(LC_CTYPE, "")` from the environment.
/// 2. Legacy locale: `LC_ALL` is unset or empty, and the `LC_CTYPE` locale is
///    now exactly `"C"` (glibc also reports `POSIX` and an unknown locale
///    name as `"C"`).
/// 3. Then the first of `C.UTF-8`, `C.utf8`, `UTF-8` that `setlocale`
///    accepts and whose `nl_langinfo(CODESET)` is not empty is exported as
///    `LC_CTYPE` (`setenv(..., 1)`, so it replaces a set `LC_CTYPE`).
///
/// Returns the exported value. The guard's own locale stays `C`
/// afterwards; nothing in the guard depends on it.
#[allow(unsafe_code)]
pub fn coerce_c_locale() -> Option<&'static str> {
    let lc_all_set = std::env::var_os("LC_ALL").is_some_and(|value| !value.is_empty());
    // SAFETY: the guard is single-threaded here (no thread was ever started),
    // so nothing else reads or changes the locale or the environment while
    // `setlocale`, `nl_langinfo` or `set_var` run. Every pointer passed is a
    // NUL-terminated string literal or NULL; the returned pointers are only
    // read before the next locale call and never stored.
    unsafe {
        libc::setlocale(libc::LC_CTYPE, c"".as_ptr());
        let current = libc::setlocale(libc::LC_CTYPE, std::ptr::null());
        let legacy = !lc_all_set && !current.is_null() && CStr::from_ptr(current) == c"C";
        let mut coerced = None;
        if legacy {
            for target in COERCION_TARGETS {
                if libc::setlocale(libc::LC_CTYPE, target.as_ptr()).is_null() {
                    continue;
                }
                let codeset = libc::nl_langinfo(libc::CODESET);
                if codeset.is_null() || *codeset == 0 {
                    continue;
                }
                let name = target.to_str().unwrap_or("C.UTF-8");
                std::env::set_var("LC_CTYPE", name);
                coerced = Some(name);
                break;
            }
        }
        libc::setlocale(libc::LC_CTYPE, c"C".as_ptr());
        coerced
    }
}

/// `os.environ["PATH"] = SAFE_PATH` (`guard.py:712`), which the exec passes
/// on. `path` is [`SAFE_PATH`] except in the process tests.
#[allow(unsafe_code)]
pub fn set_path(path: &str) {
    // SAFETY: single-threaded, as in `coerce_c_locale`.
    unsafe { std::env::set_var("PATH", path) }
}

/// SIGPIPE and SIGXFSZ ignored, as CPython leaves them for the command it
/// execs (`signal_install_handlers`). An ignored disposition survives
/// `execv`; the others the guard inherited are left as they are.
#[allow(unsafe_code)]
pub fn ignore_signals() -> Result<(), Errno> {
    for sig in [Signal::SIGPIPE, Signal::SIGXFSZ] {
        // SAFETY: `SIG_IGN` installs no handler code, so no async-signal
        // safety question arises; single-threaded, as above.
        unsafe { signal(sig, SigHandler::SigIgn) }?;
    }
    Ok(())
}

/// `os.strerror(errno)`: the C library's text (std's `Display` of an OS
/// error is `<strerror> (os error <n>)`). `Errno::desc` is nix's own table,
/// which differs from glibc for some codes.
pub fn strerror(errno: Errno) -> String {
    let code = errno as i32;
    let text = std::io::Error::from_raw_os_error(code).to_string();
    match text.strip_suffix(&format!(" (os error {code})")) {
        Some(strerror) => strerror.to_owned(),
        None => text,
    }
}

/// `os.path.join(dir, file)` for a `file` without `/`.
fn join(dir: &[u8], file: &[u8]) -> Vec<u8> {
    let mut path = dir.to_vec();
    if !path.is_empty() && !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(file);
    path
}

/// The argv as C strings; a NUL byte cannot reach a command (the prefilter
/// refuses it), and is `EINVAL` if it does.
pub fn c_argv(argv: &[String]) -> Result<Vec<CString>, Errno> {
    argv.iter()
        .map(|arg| CString::new(arg.as_bytes()).map_err(|_| Errno::EINVAL))
        .collect()
}

/// CPython's `os.execvp(argv[0], argv)` (`os._execvpe`, 3.12 and 3.13),
/// with `PATH` already in the environment as `search_path`. Returns only on
/// failure, with the error Python raises:
///
/// - `argv[0]` with a `/`: one `execv`;
/// - else `execv(<dir>/<argv0>)` for each directory of `search_path`; an
///   `ENOENT`/`ENOTDIR` is the last error and the search goes on, any other
///   error is remembered if it is the first such one and the search goes on;
/// - at the end the first remembered error, else the last one.
///
/// It never runs a file through `/bin/sh` (glibc `execvp` does that on
/// `ENOEXEC`).
pub fn execvp(argv: &[CString], search_path: &str) -> Errno {
    let Some(file) = argv.first() else {
        return Errno::EINVAL;
    };
    let file = file.as_bytes();
    if file.is_empty() {
        // `os.execv` refuses an empty argv[0] (ValueError).
        return Errno::EINVAL;
    }
    if file.contains(&b'/') {
        return execv_errno(file, argv);
    }
    let mut saved = None;
    let mut last = Errno::ENOENT;
    for dir in search_path.as_bytes().split(|b| *b == b':') {
        let errno = execv_errno(&join(dir, file), argv);
        last = errno;
        if !matches!(errno, Errno::ENOENT | Errno::ENOTDIR) && saved.is_none() {
            saved = Some(errno);
        }
    }
    saved.unwrap_or(last)
}

fn execv_errno(path: &[u8], argv: &[CString]) -> Errno {
    match CString::new(path) {
        Ok(path) => match execv(&path, argv) {
            Ok(never) => match never {},
            Err(errno) => errno,
        },
        Err(_) => Errno::EINVAL,
    }
}

/// The exec of an allowed command, after the `allowed from` line: `PATH`,
/// the locale coercion and the signals, then [`execvp`]. Returns only on
/// failure.
pub fn exec_command(argv: &[CString], search_path: &str) -> Result<Infallible, Errno> {
    set_path(search_path);
    coerce_c_locale();
    ignore_signals()?;
    Err(execvp(argv, search_path))
}

/// `execv(program, argv)` with the environment unchanged (`--shadow`).
pub fn execv_program(program: &OsStr, argv: &[CString]) -> Errno {
    execv_errno(program.as_bytes(), argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_is_the_c_librarys() {
        assert_eq!(strerror(Errno::ENOENT), "No such file or directory");
        assert_eq!(strerror(Errno::EACCES), "Permission denied");
        assert_eq!(strerror(Errno::ENOEXEC), "Exec format error");
        // nix's table says "Bad file number".
        assert_eq!(strerror(Errno::EBADF), "Bad file descriptor");
    }

    #[test]
    fn join_as_posixpath() {
        assert_eq!(join(b"/usr/bin", b"cat"), b"/usr/bin/cat");
        assert_eq!(join(b"/usr/bin/", b"cat"), b"/usr/bin/cat");
        assert_eq!(join(b"", b"cat"), b"cat");
    }

    #[test]
    fn argv_with_nul_is_einval() {
        assert_eq!(c_argv(&["a\0b".into()]), Err(Errno::EINVAL));
        assert_eq!(c_argv(&["a".into()]).unwrap()[0].as_bytes(), b"a");
    }

    #[test]
    fn failing_searches_report_like_python() {
        // Nothing here can succeed (no such directories), so `execv` never
        // replaces the test process.
        let argv = c_argv(&["echoport-no-such-tool".into()]).unwrap();
        assert_eq!(
            execvp(&argv, "/nonexistent-a:/nonexistent-b"),
            Errno::ENOENT
        );
        let argv = c_argv(&["/nonexistent-a/tool".into()]).unwrap();
        assert_eq!(execvp(&argv, "/usr/bin"), Errno::ENOENT);
        assert_eq!(execvp(&[], "/usr/bin"), Errno::EINVAL);
        assert_eq!(
            execvp(&c_argv(&[String::new()]).unwrap(), "/usr/bin"),
            Errno::EINVAL
        );
    }
}
