//! `atomic_json(path, data, group)` of `software_live.py:132-146` (PLAN.md
//! 3.5): a temporary file with the prefix `.software-live-` in the target
//! directory, mode 0640, the group set through the descriptor when one is
//! given, the JSON plus a newline, `fsync`, then `rename` over the target.
//! On any failure the temporary file is removed and the previous target
//! stays as it was.
//!
//! The JSON is [`pyjson::dumps_compact`]: sorted keys, compact separators,
//! ASCII only (PLAN.md 4.2 item 3); Python's `json.loads` reads it back to
//! equal values.

use std::fs::Permissions;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::Value;

use crate::pyjson;

/// The prefix of the temporary file (`tempfile.mkstemp(prefix=…)`).
pub const TEMP_PREFIX: &str = ".software-live-";
/// The mode of every file this program writes.
pub const MODE: u32 = 0o640;

/// The bytes `atomic_json` writes for `value`: the JSON and a newline.
pub fn render(value: &Value) -> Vec<u8> {
    let mut bytes = pyjson::dumps_compact(value);
    bytes.push(b'\n');
    bytes
}

/// `path.parent` as Python's `pathlib` gives it: `.` for a bare name, the
/// root for the root.
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        Some(_) => Path::new("."),
        None => path,
    }
}

/// Write `value` to `path` atomically, mode 0640, with group `group` when
/// given (owner unchanged: the writer's).
pub fn write_json(path: &Path, value: &Value, group: Option<u32>) -> io::Result<()> {
    let mut file = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(parent(path))?;
    // Dropping `file` on any `?` below removes the temporary file.
    file.as_file()
        .set_permissions(Permissions::from_mode(MODE))?;
    if let Some(gid) = group {
        std::os::unix::fs::fchown(file.as_file(), None, Some(gid))?;
    }
    file.write_all(&render(value))?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn writes_mode_0640_json_and_a_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let value =
            serde_json::json!({"version": "3.7.12", "checked_at_epoch": 100.5, "x": "\u{e9}"});
        write_json(&path, &value, None).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, MODE);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"checked_at_epoch\":100.5,\"version\":\"3.7.12\",\"x\":\"\\u00e9\"}\n"
        );
        assert_eq!(names(dir.path()), ["cache.json"]);
    }

    #[test]
    fn replaces_the_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        std::fs::write(&path, b"old").unwrap();
        write_json(&path, &serde_json::json!([1]), None).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"[1]\n");
        assert_eq!(names(dir.path()), ["cache.json"]);
    }

    #[test]
    fn the_group_is_set_through_the_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        // The process's own group is always allowed.
        let gid = std::fs::metadata(dir.path()).unwrap().gid();
        write_json(&path, &serde_json::json!({}), Some(gid)).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().gid(), gid);
    }

    #[test]
    fn a_failure_keeps_the_previous_target_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over a non-empty directory fails.
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("kept"), b"x").unwrap();
        assert!(write_json(&target, &serde_json::json!({}), None).is_err());
        assert_eq!(names(dir.path()), ["target"]);
        assert_eq!(names(&target), ["kept"]);
        // A missing directory fails before anything is created.
        let missing = dir.path().join("missing").join("cache.json");
        let error = write_json(&missing, &serde_json::json!({}), None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_bare_name_is_written_in_the_current_directory() {
        assert_eq!(parent(Path::new("cache.json")), Path::new("."));
        assert_eq!(parent(Path::new("/cache.json")), Path::new("/"));
        assert_eq!(parent(Path::new("/")), Path::new("/"));
        assert_eq!(parent(Path::new("a/b.json")), Path::new("a"));
    }
}
