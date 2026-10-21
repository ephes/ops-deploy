//! Python's non-strict `os.path.realpath` (PLAN.md 3.3.6), over
//! [`ResolveFs`] (`lstat` and `readlink`), for absolute paths.
//!
//! A port of CPython 3.13's `posixpath.realpath` (iterative; 3.12's
//! recursive `_joinrealpath` gives the same result except for loops):
//!
//! - the path is resolved component by component; `.` and empty components
//!   are skipped, and `..` drops the last component of the path resolved so
//!   far, so `..` in a link target applies to the resolved path;
//! - a symlink is replaced by its target, also when the target does not
//!   exist (a dangling link is followed by its text); an absolute target
//!   restarts at `/`;
//! - a component that does not exist (`ENOENT`, or `ENOTDIR` below a
//!   non-directory) is appended literally, and so is everything after it,
//!   unless a later `..` removes it;
//! - a link that was resolved once is not read again (Python's `seen` map).
//!
//! Stricter than Python (PLAN.md 4.2; the guard refuses with `path not
//! checkable`), where Python returns a partly resolved path or appends a
//! component it could not check:
//!
//! - a symlink loop (`ELOOP`; Python 3.12 and 3.13 return different
//!   partial paths), and more than [`MAX_LINKS`] symlinks, the kernel's
//!   limit (`ELOOP`);
//! - an `lstat` error other than `ENOENT`/`ENOTDIR`, for example
//!   `ENAMETOOLONG` or `EACCES` (Python treats the component as "not a
//!   link" and goes on);
//! - a `readlink` error (Python 3.12 raises it, 3.13 appends the link
//!   literally);
//! - a link target that is not valid UTF-8 (`EILSEQ`; Python carries the
//!   bytes as surrogates);
//! - a relative path (`EINVAL`; Python resolves it against the working
//!   directory, the guard only resolves absolute safe paths).

use std::collections::HashMap;

use crate::env::{FileKind, FileStat, OsError};

/// The most symlinks one resolution follows: Linux's `MAXSYMLINKS` (40). A
/// longer chain is one the kernel itself refuses to open (`ELOOP`).
pub const MAX_LINKS: usize = 40;

/// The two lookups `realpath` makes.
pub trait ResolveFs {
    /// `os.lstat(path)`: `Ok(None)` for `ENOENT`.
    fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError>;
    /// `os.readlink(path)`: the link's target text.
    fn readlink(&self, path: &str) -> Result<String, OsError>;
}

/// `ELOOP` with glibc's text.
pub fn eloop() -> OsError {
    OsError {
        errno: "ELOOP".into(),
        strerror: "Too many levels of symbolic links".into(),
    }
}

/// One entry of the stack of unprocessed parts: a path component, or the
/// marker that the link pushed with it is now resolved.
enum Part {
    Name(String),
    Resolved(String),
}

/// The components of `text`, in the order the stack pops them.
fn push_parts(stack: &mut Vec<Part>, text: &str) {
    stack.extend(
        text.split('/')
            .rev()
            .map(|name| Part::Name(name.to_owned())),
    );
}

/// Whether `path` is a symlink, with the errors Python ignores mapped to
/// "not a link" (`ENOENT`, `ENOTDIR`) and every other error returned.
fn is_link(fs: &dyn ResolveFs, path: &str) -> Result<bool, OsError> {
    match fs.lstat(path) {
        Ok(stat) => Ok(stat.is_some_and(|stat| stat.kind == FileKind::Lnk)),
        Err(error) if error.errno == "ENOENT" || error.errno == "ENOTDIR" => Ok(false),
        Err(error) => Err(error),
    }
}

/// `os.path.realpath(path)` (non-strict) for an absolute `path`, with the
/// stricter errors of the module documentation.
pub fn realpath(fs: &dyn ResolveFs, path: &str) -> Result<String, OsError> {
    if !path.starts_with('/') {
        return Err(OsError {
            errno: "EINVAL".into(),
            strerror: "not an absolute path".into(),
        });
    }
    let mut stack: Vec<Part> = Vec::new();
    push_parts(&mut stack, path);
    let mut seen: HashMap<String, Option<String>> = HashMap::new();
    let mut resolved = String::from("/");
    let mut links = 0usize;

    while let Some(part) = stack.pop() {
        let name = match part {
            Part::Resolved(link) => {
                seen.insert(link, Some(resolved.clone()));
                continue;
            }
            Part::Name(name) => name,
        };
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            // `path[:path.rindex(sep)] or sep`
            let cut = resolved.rfind('/').unwrap_or(0);
            resolved.truncate(cut.max(1));
            continue;
        }
        let newpath = if resolved == "/" {
            format!("/{name}")
        } else {
            format!("{resolved}/{name}")
        };
        if !is_link(fs, &newpath)? {
            resolved = newpath;
            continue;
        }
        match seen.get(&newpath) {
            Some(Some(cached)) => {
                resolved = cached.clone();
                continue;
            }
            // Met again while it is still being resolved: a loop.
            Some(None) => return Err(eloop()),
            None => {}
        }
        links += 1;
        if links > MAX_LINKS {
            return Err(eloop());
        }
        let target = fs.readlink(&newpath)?;
        if target.starts_with('/') {
            resolved = String::from("/");
        }
        seen.insert(newpath.clone(), None);
        stack.push(Part::Resolved(newpath));
        push_parts(&mut stack, &target);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Paths to a link target (`Some`) or a directory (`None`); everything
    /// else is absent. `/err` fails `lstat`, `/bad` fails `readlink`.
    struct Tree(HashMap<&'static str, Option<&'static str>>);

    impl ResolveFs for Tree {
        fn lstat(&self, path: &str) -> Result<Option<FileStat>, OsError> {
            if path.starts_with("/err") {
                return Err(OsError {
                    errno: "EIO".into(),
                    strerror: "Input/output error".into(),
                });
            }
            let kind = match self.0.get(path) {
                None if path == "/bad" => FileKind::Lnk,
                None => return Ok(None),
                Some(None) => FileKind::Dir,
                Some(Some(_)) => FileKind::Lnk,
            };
            Ok(Some(FileStat {
                kind,
                mode: 0o755,
                uid: 0,
                nlink: 1,
            }))
        }

        fn readlink(&self, path: &str) -> Result<String, OsError> {
            match self.0.get(path) {
                Some(Some(target)) => Ok((*target).to_owned()),
                _ => Err(OsError {
                    errno: "EINVAL".into(),
                    strerror: "Invalid argument".into(),
                }),
            }
        }
    }

    fn resolve(
        entries: &[(&'static str, Option<&'static str>)],
        path: &str,
    ) -> Result<String, String> {
        realpath(&Tree(entries.iter().copied().collect()), path).map_err(|error| error.errno)
    }

    #[test]
    fn resolves_like_posixpath() {
        let tree = [
            ("/srv", None),
            ("/srv/site", Some("../data/./site/")),
            ("/data", None),
            ("/data/site", None),
            ("/srv/abs", Some("/data//site")),
            ("/srv/dangling", Some("gone/x")),
        ];
        assert_eq!(resolve(&tree, "/srv/site/a").as_deref(), Ok("/data/site/a"));
        assert_eq!(resolve(&tree, "/srv/abs/").as_deref(), Ok("/data/site"));
        assert_eq!(
            resolve(&tree, "/srv/dangling").as_deref(),
            Ok("/srv/gone/x")
        );
        assert_eq!(resolve(&tree, "/").as_deref(), Ok("/"));
        assert_eq!(resolve(&tree, "/x/../..").as_deref(), Ok("/"));
    }

    #[test]
    fn stricter_than_python() {
        assert_eq!(
            resolve(&[("/a", Some("/a"))], "/a"),
            Err("ELOOP".to_owned())
        );
        assert_eq!(resolve(&[], "/err/x"), Err("EIO".to_owned()));
        assert_eq!(resolve(&[], "/bad/x"), Err("EINVAL".to_owned()));
        assert_eq!(resolve(&[], "relative"), Err("EINVAL".to_owned()));
        assert_eq!(resolve(&[], ""), Err("EINVAL".to_owned()));
    }
}
