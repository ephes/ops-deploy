//! The JSON document a file-backed endpoint serves and its `meta` block
//! (PLAN.md 4.2 steps 1–4, D-2, D-12).
//!
//! Python (`backup_metrics_httpd.py.j2` l.51–94):
//!
//! ```python
//! if not os.path.isfile(json_path): -> 503 <missing>
//! stat = os.stat(json_path)
//! generated_at_epoch = int(stat.st_mtime)
//! served_at_epoch = int(datetime.now(tz=timezone.utc).timestamp())
//! age_seconds = served_at_epoch - generated_at_epoch
//! data = json.load(open(json_path, encoding="utf-8"))   # JSONDecodeError -> 502, OSError -> 503
//! generated_at = datetime.fromtimestamp(generated_at_epoch, tz=timezone.utc).isoformat()
//! data["meta"] = {generated_at, generated_at_epoch, served_at_epoch, age_seconds}
//! ```

use std::fs::Metadata;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use chrono::DateTime;
use serde_json::{Map, Value};

use crate::clock::{SharedClock, epoch_seconds};
use crate::pyjson;

/// D-12: a JSON file larger than this is not served (502 `invalid_json`).
pub const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

/// How the `meta` block is added (PLAN.md 4.2 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaMode {
    /// `data["meta"] = {...}` (all variants but dns).
    Replace,
    /// dns: the four keys are set into an existing `meta` object.
    Merge,
}

/// A document read from its file, with the times of PLAN.md 4.2 step 2.
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub data: Map<String, Value>,
    pub generated_at_epoch: i64,
    pub served_at_epoch: i64,
}

impl Document {
    /// `served − generated`; negative for an mtime in the future.
    pub fn age_seconds(&self) -> i64 {
        self.served_at_epoch.saturating_sub(self.generated_at_epoch)
    }
}

/// Why a document cannot be served.
#[derive(Debug)]
pub enum FileError {
    /// `os.path.isfile` is false: missing, not a regular file, broken
    /// symlink, `stat` denied (503 with the variant's missing message).
    Missing,
    /// An `OSError` after the `isfile` check (503 `read_error`).
    Read(io::Error),
    /// Not servable JSON (502 `invalid_json`): parse errors, D-4/D-5
    /// refusals, a top-level value that is not an object (D-2), a file over
    /// [`MAX_DOCUMENT_BYTES`] (D-12).
    Invalid(String),
}

/// Python's `int(os.stat(path).st_mtime)`: CPython builds `st_mtime` as the
/// double `sec + nsec * 1e-9` and `int()` truncates it toward zero, so an
/// mtime a few nanoseconds before a full second rounds up to it.
pub fn mtime_epoch(metadata: &Metadata) -> i64 {
    float_mtime_epoch(metadata.mtime(), metadata.mtime_nsec())
}

/// [`mtime_epoch`] from the raw `stat` fields.
pub fn float_mtime_epoch(sec: i64, nsec: i64) -> i64 {
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let epoch = (sec as f64 + nsec as f64 * 1e-9).trunc() as i64;
    epoch
}

/// `datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()` for an
/// integer epoch (`2026-10-21T10:00:00+00:00`); `None` outside the years
/// 1–9999, where Python raises.
pub fn iso_utc(epoch: i64) -> Option<String> {
    const FIRST: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
    const LAST: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    if !(FIRST..=LAST).contains(&epoch) {
        return None;
    }
    let time = DateTime::from_timestamp(epoch, 0)?;
    Some(time.format("%Y-%m-%dT%H:%M:%S+00:00").to_string())
}

/// The four keys every file-backed variant adds; `None` when Python's
/// `fromtimestamp` would raise (the caller answers 500, D-2).
pub fn meta_fields(document: &Document) -> Option<Map<String, Value>> {
    let mut meta = Map::new();
    meta.insert(
        "generated_at".to_owned(),
        Value::String(iso_utc(document.generated_at_epoch)?),
    );
    meta.insert(
        "generated_at_epoch".to_owned(),
        document.generated_at_epoch.into(),
    );
    meta.insert(
        "served_at_epoch".to_owned(),
        document.served_at_epoch.into(),
    );
    meta.insert("age_seconds".to_owned(), document.age_seconds().into());
    Some(meta)
}

/// Adds `fields` as `data["meta"]` (replace) or into an existing `meta`
/// object (merge; a non-object `meta` is replaced).
pub fn apply_meta(data: &mut Map<String, Value>, fields: Map<String, Value>, mode: MetaMode) {
    if mode == MetaMode::Merge
        && let Some(Value::Object(existing)) = data.get_mut("meta")
    {
        existing.extend(fields);
        return;
    }
    data.insert("meta".to_owned(), Value::Object(fields));
}

/// Reads and parses the document at `path` (on the blocking pool), taking
/// the served time from `clock` after the `stat`, as Python does.
pub async fn read_document(path: PathBuf, clock: SharedClock) -> Result<Document, FileError> {
    tokio::task::spawn_blocking(move || read_document_blocking(&path, clock.as_ref()))
        .await
        .unwrap_or_else(|error| Err(FileError::Read(io::Error::other(error))))
}

fn read_document_blocking(
    path: &Path,
    clock: &dyn crate::clock::Clock,
) -> Result<Document, FileError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return Err(FileError::Missing),
    };
    let generated_at_epoch = mtime_epoch(&metadata);
    let served_at_epoch = epoch_seconds(clock.now());
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(FileError::Read)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(FileError::Invalid(format!(
            "file larger than {MAX_DOCUMENT_BYTES} bytes"
        )));
    }
    match pyjson::parse(&bytes) {
        Ok(Value::Object(data)) => Ok(Document {
            data,
            generated_at_epoch,
            served_at_epoch,
        }),
        Ok(_) => Err(FileError::Invalid(
            "the top-level value is not an object".to_owned(),
        )),
        Err(error) => Err(FileError::Invalid(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use serde_json::json;
    use std::sync::Arc;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    #[test]
    fn iso_utc_matches_python_isoformat() {
        assert_eq!(iso_utc(0).unwrap(), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso_utc(1_792_576_800).unwrap(), "2026-10-21T10:00:00+00:00");
        assert_eq!(iso_utc(-1).unwrap(), "1969-12-31T23:59:59+00:00");
        assert_eq!(
            iso_utc(-62_135_596_800).unwrap(),
            "0001-01-01T00:00:00+00:00"
        );
        assert_eq!(
            iso_utc(253_402_300_799).unwrap(),
            "9999-12-31T23:59:59+00:00"
        );
        assert_eq!(iso_utc(253_402_300_800), None);
        assert_eq!(iso_utc(-62_135_596_801), None);
    }

    #[test]
    fn mtime_rounds_like_cpython_st_mtime() {
        assert_eq!(float_mtime_epoch(1_792_576_800, 0), 1_792_576_800);
        assert_eq!(float_mtime_epoch(1_792_576_800, 999_999_000), 1_792_576_800);
        // 1792576800.99999999 is the double 1792576801.0.
        assert_eq!(float_mtime_epoch(1_792_576_800, 999_999_990), 1_792_576_801);
        assert_eq!(float_mtime_epoch(-2, 500_000_000), -1);
    }

    #[test]
    fn meta_replace_and_merge() {
        let document = Document {
            data: Map::new(),
            generated_at_epoch: 1_792_576_800,
            served_at_epoch: 1_792_576_790,
        };
        let fields = meta_fields(&document).unwrap();
        assert_eq!(
            Value::Object(fields.clone()),
            json!({
                "generated_at": "2026-10-21T10:00:00+00:00",
                "generated_at_epoch": 1_792_576_800,
                "served_at_epoch": 1_792_576_790,
                "age_seconds": -10,
            })
        );
        let mut data = object(json!({"meta": {"collector_ipv6_capable": true, "age_seconds": 1}}));
        apply_meta(&mut data, fields.clone(), MetaMode::Merge);
        assert_eq!(data["meta"]["collector_ipv6_capable"], json!(true));
        assert_eq!(data["meta"]["age_seconds"], json!(-10));
        let mut data = object(json!({"meta": {"collector_ipv6_capable": true}}));
        apply_meta(&mut data, fields.clone(), MetaMode::Replace);
        assert_eq!(data["meta"], Value::Object(fields.clone()));
        let mut data = object(json!({"meta": [1]}));
        apply_meta(&mut data, fields.clone(), MetaMode::Merge);
        assert_eq!(data["meta"], Value::Object(fields));
        let far = Document {
            generated_at_epoch: 253_402_300_800,
            ..document
        };
        assert!(meta_fields(&far).is_none());
    }

    #[tokio::test]
    async fn read_document_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let clock: SharedClock = Arc::new(FixedClock::at_epoch(1_792_576_900));
        let read = |name: &str| read_document(dir.path().join(name), clock.clone());

        assert!(matches!(read("absent.json").await, Err(FileError::Missing)));
        std::fs::create_dir(dir.path().join("dir.json")).unwrap();
        assert!(matches!(read("dir.json").await, Err(FileError::Missing)));
        std::os::unix::fs::symlink("absent.json", dir.path().join("broken.json")).unwrap();
        assert!(matches!(read("broken.json").await, Err(FileError::Missing)));

        for (name, text) in [
            ("list.json", "[1]"),
            ("bad.json", "{"),
            ("inf.json", "{\"a\": 1e400}"),
        ] {
            std::fs::write(dir.path().join(name), text).unwrap();
            assert!(
                matches!(read(name).await, Err(FileError::Invalid(_))),
                "{name}"
            );
        }

        let path = dir.path().join("ok.json");
        std::fs::write(&path, "{\"b\": 1, \"a\": 2.50}").unwrap();
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_792_576_800);
        file.set_modified(mtime).unwrap();
        let document = read("ok.json").await.unwrap();
        assert_eq!(document.generated_at_epoch, 1_792_576_800);
        assert_eq!(document.served_at_epoch, 1_792_576_900);
        assert_eq!(document.age_seconds(), 100);
        assert_eq!(pyjson::dumps(&document.data), b"{\"a\": 2.5, \"b\": 1}");
    }
}
