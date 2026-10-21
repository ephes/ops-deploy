//! The changes root makes inside the policy roots, made by the guard itself
//! on file descriptors (PLAN.md 4.5, slice H1; the Python guard's
//! `perform()`): `chmod 0600|0700`, `chown [-R]`, `mv` and `rm -f` of SQLite
//! side files.
//!
//! The guard never hands a pathname to a tool or to a path-based system
//! call, which the root's service user could redirect with a symlink after
//! `check()`. It opens `/` and then each directory of the path with
//! `O_NOFOLLOW|O_DIRECTORY`, so a symlink anywhere on the path is refused
//! instead of followed, and works on the last entry relative to the
//! directory it opened: `renameat`/`unlinkat` on the name, or
//! `fchmod`/`fchown` on a descriptor opened with `O_NOFOLLOW` whose inode
//! must be the one `lstat` saw. `chown -R` walks the tree the same way, one
//! directory descriptor per level, and leaves symlinks in it as they are. A
//! regular file to change must have one link, so a hard link cannot bring a
//! file from outside the root into it.
//!
//! Refusal reasons are the Python guard's, word for word; both guards run
//! the race table `parity/races.json` (`tests/mutations.rs`).

use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use nix::NixPath;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
use nix::sys::stat::{FileStat, Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{Gid, Group, Uid, UnlinkatFlags, dup, fchown, unlinkat};

use crate::decision::{Mutation, Refused};
use crate::env::GuardEnv;
use crate::exec::strerror;
use crate::repr::py_repr;

/// The test hook (the Python guard's `hook(event, path)`): called with
/// `("dir", <path>)` after each directory on the way was opened and with
/// `("stat", <path>)` after an entry passed `lstat`, right before it is
/// opened. The guard passes a hook that does nothing.
pub type Hook<'a> = dyn FnMut(&str, &str) + 'a;

/// Why a mutation stopped: the refusal reason, and the errno when an OS
/// error caused it (`rm -f` skips a missing directory on the way).
#[derive(Debug)]
struct Failure {
    reason: String,
    errno: Option<Errno>,
}

impl Failure {
    fn refused(reason: String) -> Self {
        Self {
            reason,
            errno: None,
        }
    }

    /// `_OsRefused(what, path, exc)`: `<what>: <path!r>: <strerror>`.
    fn os(what: &str, path: &str, errno: Errno) -> Self {
        Self {
            reason: format!("{what}: {}: {}", py_repr(path), strerror(errno)),
            errno: Some(errno),
        }
    }
}

fn dir_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn entry_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY | OFlag::O_CLOEXEC
}

fn kind(st: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT
}

/// Whether a failed `O_NOFOLLOW` open met a symlink (Linux says `ELOOP`,
/// macOS `ENOTDIR`).
fn is_link<P: ?Sized + NixPath>(dir_fd: BorrowedFd<'_>, name: &P) -> bool {
    fstatat(dir_fd, name, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|st| kind(&st) == SFlag::S_IFLNK)
}

/// `_open_parent`: the directory holding `path`, opened from `/` without
/// following a symlink, and the last name of `path`.
fn open_parent<'p>(path: &'p str, hook: &mut Hook<'_>) -> Result<(OwnedFd, &'p str), Failure> {
    // `path.split("/")[1:]`
    let parts: Vec<&str> = path.split('/').skip(1).collect();
    let Some((name, directories)) = parts.split_last() else {
        return Err(Failure::refused(format!("unsafe path: {}", py_repr(path))));
    };
    if !path.starts_with('/') || parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return Err(Failure::refused(format!("unsafe path: {}", py_repr(path))));
    }
    let mut fd =
        open("/", dir_flags(), Mode::empty()).map_err(|e| Failure::os("cannot open", "/", e))?;
    let mut prefix = String::new();
    for part in directories {
        prefix.push('/');
        prefix.push_str(part);
        fd = match openat(&fd, *part, dir_flags(), Mode::empty()) {
            Ok(next) => next,
            Err(errno) => {
                if is_link(fd.as_fd(), *part) {
                    return Err(Failure::refused(format!(
                        "symbolic link in the path: {}",
                        py_repr(&prefix)
                    )));
                }
                return Err(Failure::os("cannot open", &prefix, errno));
            }
        };
        hook("dir", &prefix);
    }
    Ok((fd, name))
}

/// `_open_entry`: the entry `name` of `dir_fd`, opened without following
/// it, and its `fstat`; `None` for a symlink with `skip_links`. Only a
/// directory or a regular file with one link, and only the inode `lstat`
/// saw.
fn open_entry(
    dir_fd: BorrowedFd<'_>,
    name: &OsStr,
    path: &str,
    op: &str,
    hook: &mut Hook<'_>,
    skip_links: bool,
) -> Result<Option<(OwnedFd, FileStat)>, Failure> {
    let seen = fstatat(dir_fd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|e| Failure::os("cannot stat", path, e))?;
    let seen_kind = kind(&seen);
    if seen_kind == SFlag::S_IFLNK {
        if skip_links {
            return Ok(None);
        }
        return Err(Failure::refused(format!(
            "{op} target is a symbolic link: {}",
            py_repr(path)
        )));
    }
    let is_dir = seen_kind == SFlag::S_IFDIR;
    if !is_dir && seen_kind != SFlag::S_IFREG {
        return Err(Failure::refused(format!(
            "{op} target is not a regular file or directory: {}",
            py_repr(path)
        )));
    }
    hook("stat", path);
    let flags = if is_dir {
        entry_flags() | OFlag::O_DIRECTORY
    } else {
        entry_flags()
    };
    let fd = match openat(dir_fd, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) => {
            if is_link(dir_fd, name) {
                return Err(Failure::refused(format!(
                    "{op} target is a symbolic link: {}",
                    py_repr(path)
                )));
            }
            return Err(Failure::os("cannot open", path, errno));
        }
    };
    let st = fstat(&fd).map_err(|e| Failure::os("cannot stat", path, e))?;
    if (st.st_dev, st.st_ino) != (seen.st_dev, seen.st_ino) {
        return Err(Failure::refused(format!(
            "{op} target was replaced: {}",
            py_repr(path)
        )));
    }
    if kind(&st) != SFlag::S_IFDIR && st.st_nlink != 1 {
        return Err(Failure::refused(format!(
            "{op} target has other hard links: {}",
            py_repr(path)
        )));
    }
    Ok(Some((fd, st)))
}

/// `_owner_ids`: the uid and gid of `<user>:<group>` (NSS).
fn owner_ids(owner: &str, env: &dyn GuardEnv) -> Result<(Uid, Gid), Failure> {
    let (user, group) = owner.split_once(':').unwrap_or((owner, ""));
    let gid = match Group::from_name(group) {
        Ok(Some(group)) => Some(group.gid),
        Ok(None) | Err(_) => None,
    };
    match (env.uid_of(user), gid) {
        (Some(uid), Some(gid)) => Ok((Uid::from_raw(uid), gid)),
        _ => Err(Failure::refused(format!(
            "unknown owner: {}",
            py_repr(owner)
        ))),
    }
}

fn change_owner(fd: &OwnedFd, (uid, gid): (Uid, Gid), path: &str) -> Result<(), Failure> {
    fchown(fd, Some(uid), Some(gid)).map_err(|e| Failure::os("chown failed", path, e))
}

/// `sorted(os.listdir(fd))`: the names in a directory, by their bytes.
fn names(dir_fd: BorrowedFd<'_>, path: &str) -> Result<Vec<Vec<u8>>, Failure> {
    let cannot_list = |e| Failure::os("cannot list", path, e);
    let mut dir = Dir::from_fd(dup(dir_fd).map_err(cannot_list)?).map_err(cannot_list)?;
    let mut names = Vec::new();
    for entry in dir.iter() {
        let name = entry.map_err(cannot_list)?.file_name().to_bytes().to_vec();
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// One open directory of the `chown -R` walk and the names still to visit.
struct Level {
    /// `None`: the top directory, which the caller holds open.
    fd: Option<OwnedFd>,
    path: String,
    names: std::vec::IntoIter<Vec<u8>>,
}

/// `_chown_tree`: `chown -R` below the directory `top`, one open directory
/// per level.
fn chown_tree(
    top: &OwnedFd,
    top_path: &str,
    ids: (Uid, Gid),
    hook: &mut Hook<'_>,
) -> Result<(), Failure> {
    let mut stack = vec![Level {
        fd: None,
        path: top_path.to_owned(),
        names: names(top.as_fd(), top_path)?.into_iter(),
    }];
    while let Some(level) = stack.last_mut() {
        let Some(name) = level.names.next() else {
            stack.pop();
            continue;
        };
        let path = format!("{}/{}", level.path, String::from_utf8_lossy(&name));
        let dir_fd = level.fd.as_ref().map_or(top.as_fd(), AsFd::as_fd);
        let opened = open_entry(dir_fd, OsStr::from_bytes(&name), &path, "chown", hook, true)?;
        // A symlink: neither followed nor changed.
        let Some((fd, st)) = opened else {
            continue;
        };
        change_owner(&fd, ids, &path)?;
        if kind(&st) == SFlag::S_IFDIR {
            let names = names(fd.as_fd(), &path)?.into_iter();
            stack.push(Level {
                fd: Some(fd),
                path,
                names,
            });
        }
    }
    Ok(())
}

/// `_change`: `chmod` or `chown` of one path (`chown -R`: and everything
/// below it).
fn change(mutation: &Mutation, env: &dyn GuardEnv, hook: &mut Hook<'_>) -> Result<(), Failure> {
    let op = mutation.op.as_str();
    let unusable = || Failure::refused(format!("unusable mutation: {}", py_repr(op)));
    let [path] = mutation.paths.as_slice() else {
        return Err(unusable());
    };
    if op == "chmod" && mutation.mode.is_none() {
        return Err(unusable());
    }
    let ids = if op == "chown" {
        Some(owner_ids(
            mutation.owner.as_deref().unwrap_or_default(),
            env,
        )?)
    } else {
        None
    };
    let (dir_fd, name) = open_parent(path, hook)?;
    let opened = open_entry(dir_fd.as_fd(), OsStr::new(name), path, op, hook, false)?;
    drop(dir_fd);
    let Some((fd, st)) = opened else {
        return Err(Failure::refused(format!(
            "{op} target is a symbolic link: {}",
            py_repr(path)
        )));
    };
    let Some(ids) = ids else {
        let mode = mutation
            .mode
            .and_then(|mode| libc::mode_t::try_from(mode).ok())
            .ok_or_else(unusable)?;
        return fchmod(&fd, Mode::from_bits_truncate(mode))
            .map_err(|e| Failure::os("chmod failed", path, e));
    };
    if mutation.private {
        // Still the fresh snapshot temp dir check() saw: root's, no
        // group/other access.
        let private =
            kind(&st) == SFlag::S_IFDIR && st.st_uid == env.euid() && st.st_mode & 0o077 == 0;
        if !private {
            return Err(Failure::refused(format!(
                "not a private directory: {}",
                py_repr(path)
            )));
        }
    }
    change_owner(&fd, ids, path)?;
    if mutation.recursive && kind(&st) == SFlag::S_IFDIR {
        chown_tree(&fd, path, ids, hook)?;
    }
    Ok(())
}

/// `_rename`: `mv <source> <target>` as one `renameat` between the two
/// directories walked to.
fn rename(mutation: &Mutation, hook: &mut Hook<'_>) -> Result<(), Failure> {
    let [source, target] = mutation.paths.as_slice() else {
        return Err(Failure::refused("unusable mutation: 'mv'".to_owned()));
    };
    let (source_fd, source_name) = open_parent(source, hook)?;
    let (target_fd, target_name) = open_parent(target, hook)?;
    if !mutation.replace {
        match fstatat(&target_fd, target_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(Errno::ENOENT) => {}
            Err(errno) => return Err(Failure::os("mv target not checkable", target, errno)),
            Ok(_) => {
                return Err(Failure::refused(format!(
                    "mv target exists: {}",
                    py_repr(target)
                )));
            }
        }
    }
    renameat(&source_fd, source_name, &target_fd, target_name).map_err(|errno| {
        Failure::refused(format!(
            "mv failed: {} -> {}: {}",
            py_repr(source),
            py_repr(target),
            strerror(errno)
        ))
    })
}

/// `_remove`: `rm -f`; a missing path (or directory on its way) is fine.
fn remove(mutation: &Mutation, hook: &mut Hook<'_>) -> Result<(), Failure> {
    for path in &mutation.paths {
        let (dir_fd, name) = match open_parent(path, hook) {
            Ok(opened) => opened,
            Err(Failure {
                errno: Some(Errno::ENOENT),
                ..
            }) => continue,
            Err(failure) => return Err(failure),
        };
        match unlinkat(&dir_fd, name, UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => {}
            Err(errno) => return Err(Failure::os("rm failed", path, errno)),
        }
    }
    Ok(())
}

/// `perform(mutation, hook)`: make the change a mutation decision
/// describes, or refuse with the reason the forced-command flow logs.
pub fn perform(
    mutation: &Mutation,
    env: &dyn GuardEnv,
    hook: &mut Hook<'_>,
) -> Result<(), Refused> {
    let result = match mutation.op.as_str() {
        "chmod" | "chown" => change(mutation, env, hook),
        "mv" => rename(mutation, hook),
        "rm" => remove(mutation, hook),
        op => Err(Failure::refused(format!(
            "unknown mutation: {}",
            py_repr(op)
        ))),
    };
    result.map_err(|failure| Refused::new(failure.reason))
}
