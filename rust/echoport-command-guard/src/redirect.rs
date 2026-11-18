//! The files the guard opens itself for `< file`, `> file` and the snapshot
//! `cat` (PLAN.md 3.5; `guard.py:632-651, 698-703`).
//!
//! The directory is opened without following a symlink, its owner and mode
//! are checked on the open descriptor, and the file is opened relative to it,
//! again without following a symlink: `O_EXCL` for a new file (mode `0600`
//! before the umask), and `O_NONBLOCK` for reading, so that a FIFO cannot
//! block the open, cleared once the file is known to be a plain one. Every
//! descriptor is close-on-exec until [`install`] puts it on fd 0 or 1.

use std::fmt;
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl, open, openat};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{dup2_stdin, dup2_stdout};

use crate::decision::{Decision, Redirect, Refused};
use crate::env::GuardEnv;
use crate::exec::strerror;
use crate::repr::py_repr;

/// Why a redirect cannot be opened: `str(exc)` of the Python guard's
/// `Refused` or `OSError` (`[Errno 17] File exists: 'a.dump'`), which goes
/// into the `refused from` log line (PLAN.md 3.1 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectError {
    Refused(Refused),
    Os {
        errno: Errno,
        /// The path Python's `OSError` names, if any.
        filename: Option<String>,
    },
}

impl RedirectError {
    fn os(errno: Errno, filename: Option<&str>) -> Self {
        Self::Os {
            errno,
            filename: filename.map(str::to_owned),
        }
    }
}

impl fmt::Display for RedirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedirectError::Refused(refused) => f.write_str(refused.reason()),
            RedirectError::Os { errno, filename } => {
                write!(f, "[Errno {}] {}", *errno as i32, strerror(*errno))?;
                match filename {
                    Some(name) => write!(f, ": {}", py_repr(name)),
                    None => Ok(()),
                }
            }
        }
    }
}

/// `_user_uids(owners)` (`guard.py:622-629`): the guard's euid and the uid of
/// each owner that exists.
fn allowed_uids(owners: &[String], env: &dyn GuardEnv) -> Vec<u32> {
    let mut uids = vec![env.euid()];
    uids.extend(owners.iter().filter_map(|owner| env.uid_of(owner)));
    uids
}

/// `open_redirect(redirect, create)` (`guard.py:632-651`): the open file.
pub fn open_redirect(
    redirect: &Redirect,
    create: bool,
    env: &dyn GuardEnv,
) -> Result<OwnedFd, RedirectError> {
    let directory = redirect.directory.as_str();
    let dir_fd = open(
        directory,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| RedirectError::os(errno, Some(directory)))?;
    let st = fstat(&dir_fd).map_err(|errno| RedirectError::os(errno, None))?;
    if !allowed_uids(&redirect.owners, env).contains(&st.st_uid) {
        return Err(RedirectError::Refused(Refused::new(format!(
            "unexpected owner of {}",
            py_repr(directory)
        ))));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(RedirectError::Refused(Refused::new(format!(
            "{} is accessible to others",
            py_repr(directory)
        ))));
    }
    let flags = if create {
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW
    } else {
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK
    };
    let name = redirect.name.as_str();
    let fd = openat(
        &dir_fd,
        name,
        flags | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|errno| RedirectError::os(errno, Some(name)))?;
    drop(dir_fd);
    let st = fstat(&fd).map_err(|errno| RedirectError::os(errno, None))?;
    let is_regular = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
    if !is_regular || st.st_nlink != 1 {
        return Err(RedirectError::Refused(Refused::new(format!(
            "not a plain file: {directory}/{name}"
        ))));
    }
    // `os.set_blocking(fd, True)`.
    let status = fcntl(&fd, FcntlArg::F_GETFL).map_err(|errno| RedirectError::os(errno, None))?;
    let status = OFlag::from_bits_retain(status);
    if status.contains(OFlag::O_NONBLOCK) {
        fcntl(&fd, FcntlArg::F_SETFL(status & !OFlag::O_NONBLOCK))
            .map_err(|errno| RedirectError::os(errno, None))?;
    }
    Ok(fd)
}

/// `os.dup2(fd, target); os.close(fd)`: the file becomes fd 0 or 1 and is
/// inherited by the command. If the open already returned the target number
/// (sshd started the guard with that fd closed), it only loses its
/// close-on-exec flag.
pub fn install(fd: OwnedFd, target: RawFd) -> Result<(), RedirectError> {
    if fd.as_raw_fd() == target {
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::empty()))
            .map_err(|errno| RedirectError::os(errno, None))?;
        let _ = fd.into_raw_fd();
        return Ok(());
    }
    let result = match target {
        0 => dup2_stdin(fd.as_fd()),
        1 => dup2_stdout(fd.as_fd()),
        _ => Err(Errno::EBADF),
    };
    result.map_err(|errno| RedirectError::os(errno, None))
}

/// The redirect step of the forced-command flow (`guard.py:698-703`): stdin
/// first (read), then stdout (create). The umask is already set.
pub fn apply(decision: &Decision, env: &dyn GuardEnv) -> Result<(), RedirectError> {
    for (redirect, target, create) in [(&decision.stdin, 0, false), (&decision.stdout, 1, true)] {
        if let Some(redirect) = redirect {
            install(open_redirect(redirect, create, env)?, target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! `GuardRedirects` of `tests/test_echoport_remote_command_guard.py`, on
    //! real temporary directories.

    use std::io::{Read, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::env::VirtualEnv;

    /// Like the runners' `mktemp -d`: a 0700 directory of the test's user.
    struct Dir {
        _tmp: tempfile::TempDir,
        path: PathBuf,
    }

    fn private_dir() -> Dir {
        let tmp = tempfile::tempdir().unwrap();
        // macOS: /tmp and /var are symlinks; the guard does not follow one.
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let path = base.join("echoport-guard-test.dir");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Dir { _tmp: tmp, path }
    }

    fn redirect(dir: &Path, name: &str, owners: &[&str]) -> Redirect {
        Redirect {
            directory: dir.to_str().unwrap().to_owned(),
            name: name.to_owned(),
            owners: owners.iter().map(|o| (*o).to_owned()).collect(),
        }
    }

    fn me() -> VirtualEnv {
        VirtualEnv {
            euid: nix::unistd::geteuid().as_raw(),
            ..VirtualEnv::default()
        }
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn create_is_exclusive_and_private() {
        let dir = private_dir();
        let fd = open_redirect(&redirect(&dir.path, "a.dump", &[]), true, &me()).unwrap();
        std::fs::File::from(fd).write_all(b"dump").unwrap();
        // 0600 under any umask that leaves the owner's bits alone.
        assert_eq!(mode_of(&dir.path.join("a.dump")) & !0o600, 0);
        assert_eq!(mode_of(&dir.path.join("a.dump")), 0o600);
        let error = open_redirect(&redirect(&dir.path, "a.dump", &[]), true, &me()).unwrap_err();
        assert_eq!(error.to_string(), "[Errno 17] File exists: 'a.dump'");
    }

    #[test]
    fn read_plain_file() {
        let dir = private_dir();
        std::fs::write(dir.path.join("a.dump"), b"dump").unwrap();
        let fd = open_redirect(&redirect(&dir.path, "a.dump", &[]), false, &me()).unwrap();
        let status = OFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFL).unwrap());
        assert!(!status.contains(OFlag::O_NONBLOCK), "still non-blocking");
        let flags = FdFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFD).unwrap());
        assert!(flags.contains(FdFlag::FD_CLOEXEC));
        let mut content = Vec::new();
        std::fs::File::from(fd).read_to_end(&mut content).unwrap();
        assert_eq!(content, b"dump");
    }

    #[test]
    fn refuses_links_and_special_files() {
        let dir = private_dir();
        let outside = dir.path.with_file_name("echoport-guard-test.outside");
        std::fs::write(&outside, "x").unwrap();
        symlink(&outside, dir.path.join("link")).unwrap();
        std::fs::hard_link(&outside, dir.path.join("hard")).unwrap();
        nix::unistd::mkfifo(&dir.path.join("fifo"), Mode::from_bits_truncate(0o600)).unwrap();
        std::fs::create_dir(dir.path.join("sub")).unwrap();
        let shown = dir.path.to_str().unwrap();
        let cases = [
            (
                "link",
                false,
                "[Errno 40] Too many levels of symbolic links: 'link'",
            ),
            ("link", true, "[Errno 17] File exists: 'link'"),
            ("hard", false, "not a plain file: {dir}/hard"),
            ("fifo", false, "not a plain file: {dir}/fifo"),
            ("sub", false, "not a plain file: {dir}/sub"),
            ("sub", true, "[Errno 17] File exists: 'sub'"),
            (
                "missing",
                false,
                "[Errno 2] No such file or directory: 'missing'",
            ),
        ];
        for (name, create, expected) in cases {
            let error = open_redirect(&redirect(&dir.path, name, &[]), create, &me()).unwrap_err();
            let text = error.to_string();
            if cfg!(target_os = "linux") {
                assert_eq!(text, expected.replace("{dir}", shown), "{name} {create}");
            } else {
                // Other systems number and word errno differently.
                assert!(!text.is_empty(), "{name} {create}");
            }
        }
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "x");
    }

    #[test]
    fn refuses_a_shared_or_foreign_directory() {
        let dir = private_dir();
        std::fs::write(dir.path.join("a.dump"), b"dump").unwrap();
        let shown = py_repr(dir.path.to_str().unwrap());
        std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = open_redirect(&redirect(&dir.path, "a.dump", &[]), false, &me()).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("{shown} is accessible to others")
        );
        assert!(matches!(error, RedirectError::Refused(_)));
        std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let other = VirtualEnv {
            euid: me().euid + 1,
            ..VirtualEnv::default()
        };
        let error = open_redirect(&redirect(&dir.path, "a.dump", &[]), false, &other).unwrap_err();
        assert_eq!(error.to_string(), format!("unexpected owner of {shown}"));
        // An owner from the decision may own it; a missing owner is no uid.
        let mut owned = other.clone();
        owned.users.insert("svc".into(), Some(me().euid));
        owned.users.insert("ghost".into(), None);
        assert!(open_redirect(&redirect(&dir.path, "a.dump", &["svc"]), false, &owned).is_ok());
        assert!(open_redirect(&redirect(&dir.path, "a.dump", &["ghost"]), false, &owned).is_err());
    }

    #[test]
    fn refuses_a_symlinked_directory() {
        let dir = private_dir();
        let link = dir.path.with_file_name("echoport-guard-test.link");
        symlink(&dir.path, &link).unwrap();
        std::fs::write(dir.path.join("a.dump"), b"dump").unwrap();
        let error = open_redirect(&redirect(&link, "a.dump", &[]), false, &me()).unwrap_err();
        assert!(matches!(error, RedirectError::Os { .. }), "{error}");
        if cfg!(target_os = "linux") {
            assert_eq!(
                error.to_string(),
                format!(
                    "[Errno 20] Not a directory: {}",
                    py_repr(link.to_str().unwrap())
                )
            );
        }
    }

    #[test]
    fn os_error_text_is_pythons() {
        let error = RedirectError::os(Errno::EACCES, Some("it's"));
        assert_eq!(error.to_string(), "[Errno 13] Permission denied: \"it's\"");
        let error = RedirectError::os(Errno::EBADF, None);
        assert_eq!(error.to_string(), "[Errno 9] Bad file descriptor");
    }
}
