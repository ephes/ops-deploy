//! `export-inventory`: `inventory_projection` and `export_inventory` of
//! `software_live.py:764-881` (PLAN.md 3.6).
//!
//! The collector's report (`state.json`) is read through a descriptor that
//! cannot follow a link, only when its directory and the file itself are
//! root-owned and writable by root alone, and only up to 1 MiB. The
//! projection keeps an allowlist of fields and nothing else (no paths,
//! hashes, package names or extra keys) and is written atomically, mode
//! 0640, group `--group` (`software-estate-publisher` on the hosts), for the
//! unprivileged `software_estate` reader (`collect.py:376-470`), whose key
//! sets are exact. Any failure leaves the previous projection untouched.
//!
//! The checks run in Python's order, so the same input fails with the same
//! class and, where the Python code raises it itself, the same message.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use rustix::fs::{Mode, OFlags};
use serde_json::{Map, Number, Value};

use crate::atomic;
use crate::error::PyError;
use crate::probe::FileStat;
use crate::pyjson::{self, canonical_int, is_int_token, token_f64};
use crate::report::{MAX_REPORT_AGE, SCHEMA_VERSION};

/// The largest source the export reads (`stream.read(1024 * 1024 + 1)`).
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
/// Version texts and issues are cut to this many characters (code points).
pub const TEXT_LIMIT: usize = 160;
/// At most this many issues per check are exported.
pub const ISSUE_LIMIT: usize = 20;
/// The checks of the projection, in the order Python validates them.
pub const CHECKS: [&str; 3] = ["os", "postgresql", "traefik"];

/// `[A-Za-z0-9_.-]{1,128}` with `re.fullmatch`.
static HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9_.-]{1,128}\z").expect("valid pattern"));

/// `value[:160] if isinstance(value, str) and value else None`.
fn text(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Value::String(cut(text)),
        _ => Value::Null,
    }
}

/// The first 160 characters (Python slices by code point).
fn cut(text: &str) -> String {
    text.chars().take(TEXT_LIMIT).collect()
}

/// `mapping.get(key)` of a field that may be any JSON value: `None` unless
/// it is an object (`isinstance(x, dict)`) holding the key.
fn field<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    value
        .and_then(Value::as_object)
        .and_then(|map| map.get(key))
}

/// The source time as `math.isfinite` and `> 0` see it: an `int` or a
/// `float` (never `bool`), finite and positive. An `int` beyond the float
/// range is Python's `OverflowError` (raised by `math.isfinite`, before the
/// sign is looked at).
fn check_time(value: Option<&Value>) -> Result<(), PyError> {
    let invalid = || PyError::value("invalid source time");
    let Some(Value::Number(number)) = value else {
        return Err(invalid());
    };
    let token = number.as_str();
    let seconds = token_f64(token);
    if !seconds.is_finite() {
        return Err(if is_int_token(token) {
            PyError::new("OverflowError", "int too large to convert to float")
        } else {
            invalid()
        });
    }
    if seconds <= 0.0 {
        return Err(invalid());
    }
    Ok(())
}

/// The security count: `None`, or an `int` (not `bool`) that is not
/// negative; `None` only when the APT status is not `ok`.
fn check_count(count: Option<&Value>, status_ok: bool) -> Result<Value, PyError> {
    let invalid = || PyError::value("invalid security count");
    match count {
        None | Some(Value::Null) if status_ok => Err(invalid()),
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::Number(number)) if is_int_token(number.as_str()) => {
            // `-0` is the int 0, written as Python writes it.
            let canonical = canonical_int(number.as_str());
            if canonical.starts_with('-') {
                Err(invalid())
            } else {
                Ok(Value::Number(
                    Number::from_str(canonical).expect("an integer token"),
                ))
            }
        }
        Some(_) => Err(invalid()),
    }
}

/// One entry of `checks` (`software_live.py:793-841`).
fn project_check(name: &str, item: Option<&Value>) -> Result<Value, PyError> {
    let Some(Value::Object(item)) = item else {
        return Err(PyError::value("invalid source check"));
    };
    let status = match item.get("status") {
        Some(Value::String(status)) if ["ok", "warning", "unknown"].contains(&status.as_str()) => {
            status.clone()
        }
        _ => return Err(PyError::value("invalid source check")),
    };
    let Some(Value::Bool(observed)) = item.get("observed") else {
        return Err(PyError::value("invalid observation flag"));
    };
    let expected = if name == "os" {
        true
    } else {
        match item.get("expected") {
            Some(Value::Bool(expected)) => *expected,
            _ => return Err(PyError::value("invalid expectation flag")),
        }
    };
    let issues: &[Value] = match item.get("issues") {
        None => &[],
        Some(Value::Array(issues)) if issues.iter().all(Value::is_string) => issues,
        Some(_) => return Err(PyError::value("invalid source issues")),
    };
    let installed = match name {
        "os" => text(item.get("cycle")),
        "postgresql" => Value::Null,
        _ => text(field(item.get("installed"), "version")),
    };
    let running = match name {
        "postgresql" => text(item.get("server_version")),
        _ => text(field(item.get("running"), "version")),
    };
    let upstream = match name {
        "traefik" => text(field(item.get("upstream"), "version")),
        _ => Value::Null,
    };
    let exported: Vec<Value> = issues
        .iter()
        .take(ISSUE_LIMIT)
        .map(|issue| Value::String(cut(issue.as_str().unwrap_or_default())))
        .collect();
    let mut check = Map::new();
    check.insert("status".into(), Value::String(status));
    check.insert("observed".into(), Value::Bool(*observed));
    check.insert("expected".into(), Value::Bool(expected));
    check.insert("installed_version".into(), installed);
    check.insert("running_version".into(), running);
    check.insert("upstream_version".into(), upstream);
    check.insert("issues".into(), Value::Array(exported));
    check.insert(
        "issues_truncated".into(),
        Value::Bool(issues.len() > ISSUE_LIMIT),
    );
    Ok(Value::Object(check))
}

/// `inventory_projection(data)`: the allowlisted metadata of a report, or
/// the error of the first check that fails. `observed_at_epoch` is the
/// source's `generated_at_epoch` as it was read.
pub fn inventory_projection(data: &Value) -> Result<Value, PyError> {
    let Value::Object(data) = data else {
        // `data.get(...)` on a list, string, number or None.
        return Err(PyError::new(
            "AttributeError",
            format!(
                "'{}' object has no attribute 'get'",
                pyjson::type_name(data)
            ),
        ));
    };
    let schema_ok = matches!(
        data.get("schema_version"),
        Some(Value::Number(number))
            if is_int_token(number.as_str())
                && canonical_int(number.as_str()) == SCHEMA_VERSION.to_string()
    );
    if !schema_ok {
        return Err(PyError::value("unsupported source schema"));
    }
    let host = match data.get("host") {
        Some(Value::String(host)) if HOST.is_match(host) => host.clone(),
        _ => return Err(PyError::value("invalid source identity")),
    };
    let observed = data.get("generated_at_epoch");
    check_time(observed)?;
    let mut checks = Map::new();
    for name in CHECKS {
        checks.insert(name.into(), project_check(name, data.get(name))?);
    }
    let apt = data.get("apt");
    let apt_status = match field(apt, "status") {
        Some(Value::String(status)) if status == "ok" || status == "unknown" => status.clone(),
        _ => return Err(PyError::value("invalid APT evidence")),
    };
    let Some(Value::Bool(indexes_fresh)) = field(apt, "indexes_fresh") else {
        return Err(PyError::value("invalid APT evidence"));
    };
    let count = check_count(field(apt, "pending_security_count"), apt_status == "ok")?;
    let mut apt = Map::new();
    apt.insert("status".into(), Value::String(apt_status));
    apt.insert("indexes_fresh".into(), Value::Bool(*indexes_fresh));
    apt.insert("pending_security_count".into(), count);
    let mut projection = Map::new();
    projection.insert("schema_version".into(), 1.into());
    projection.insert(
        "source".into(),
        format!("software-live/{SCHEMA_VERSION}").into(),
    );
    projection.insert("host".into(), host.into());
    projection.insert(
        "observed_at_epoch".into(),
        observed.cloned().unwrap_or(Value::Null),
    );
    projection.insert("max_age_seconds".into(), MAX_REPORT_AGE.into());
    projection.insert("checks".into(), Value::Object(checks));
    projection.insert("apt".into(), Value::Object(apt));
    Ok(Value::Object(projection))
}

/// The uid that counts as root for the export directory and for the
/// source. Always 0 on a host; the tests emulate root ownership with their
/// own uid, as the Python tests patch `lstat` and `fstat`.
#[derive(Clone, Copy, Debug)]
struct Owners {
    directory: u32,
    source: u32,
}

const ROOT: Owners = Owners {
    directory: 0,
    source: 0,
};

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;

/// Writable by group or others (`st_mode & 0o022`).
fn writable_by_others(stat: &FileStat) -> bool {
    stat.mode & 0o022 != 0
}

/// The export directory: a directory (not a link to one), root-owned,
/// writable by root alone.
fn safe_directory(stat: &FileStat, root: u32) -> bool {
    stat.mode & S_IFMT == S_IFDIR && stat.uid == root && !writable_by_others(stat)
}

/// The source: a regular file, root-owned, with one name, writable by root
/// alone.
fn safe_source(stat: &FileStat, root: u32) -> bool {
    stat.mode & S_IFMT == S_IFREG
        && stat.uid == root
        && stat.nlink == 1
        && !writable_by_others(stat)
}

/// A path as Python's `pathlib.Path` spells it (`str(Path(text))`, Python
/// 3.12 and 3.13): empty and `.` parts dropped, a trailing slash removed,
/// exactly two leading slashes kept, `.` for nothing. `Path(p).parent`
/// drops the last part (the root's and `.`'s parent are themselves).
struct PyPath {
    root: &'static [u8],
    parts: Vec<Vec<u8>>,
}

impl PyPath {
    fn new(path: &Path) -> Self {
        let bytes = path.as_os_str().as_bytes();
        let root: &'static [u8] = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
            b"//"
        } else if bytes.starts_with(b"/") {
            b"/"
        } else {
            b""
        };
        let parts = bytes
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty() && *part != b".")
            .map(<[u8]>::to_vec)
            .collect();
        Self { root, parts }
    }

    fn render(root: &[u8], parts: &[Vec<u8>]) -> PathBuf {
        let mut bytes = root.to_vec();
        bytes.extend(parts.join(&b'/'));
        if bytes.is_empty() {
            bytes.push(b'.');
        }
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    }

    fn path(&self) -> PathBuf {
        Self::render(self.root, &self.parts)
    }

    fn parent(&self) -> PathBuf {
        let keep = self.parts.len().saturating_sub(1);
        Self::render(self.root, &self.parts[..keep])
    }
}

fn os_error(error: io::Error) -> PyError {
    PyError::os(&error)
}

/// `os.open(source, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)` and
/// `os.fdopen(fd, "rb")`, which refuses a directory (`IsADirectoryError`)
/// before the export looks at the file. The descriptor is close-on-exec,
/// as every descriptor Python opens.
fn open_source(path: &Path) -> Result<(File, FileStat), PyError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd =
        rustix::fs::open(path, flags, Mode::empty()).map_err(|errno| os_error(errno.into()))?;
    let file = File::from(fd);
    let stat = FileStat::from_metadata(&file.metadata().map_err(os_error)?);
    if stat.mode & S_IFMT == S_IFDIR {
        return Err(PyError::new(
            "IsADirectoryError",
            format!("Is a directory: {}", path.display()),
        ));
    }
    Ok((file, stat))
}

/// `grp.getgrnam(name).gr_gid`; any failure to find the group is Python's
/// `KeyError`.
fn group_id(name: &OsStr) -> Result<u32, PyError> {
    let not_found = || {
        PyError::new(
            "KeyError",
            format!("getgrnam(): name not found: '{}'", name.to_string_lossy()),
        )
    };
    let name = name.to_str().ok_or_else(not_found)?;
    match nix::unistd::Group::from_name(name) {
        Ok(Some(group)) => Ok(group.gid.as_raw()),
        _ => Err(not_found()),
    }
}

/// `export_inventory(source, output, group)` on a host: root ownership is
/// uid 0.
pub fn export_inventory(source: &Path, output: &Path, group: &OsStr) -> Result<(), PyError> {
    export_with(source, output, group, ROOT)
}

fn export_with(source: &Path, output: &Path, group: &OsStr, owners: Owners) -> Result<(), PyError> {
    let output = PyPath::new(output);
    let directory = std::fs::symlink_metadata(output.parent()).map_err(os_error)?;
    if !safe_directory(&FileStat::from_metadata(&directory), owners.directory) {
        return Err(PyError::value("unsafe export directory"));
    }
    let (file, stat) = open_source(&PyPath::new(source).path())?;
    if !safe_source(&stat, owners.source) {
        return Err(PyError::value("unsafe source file"));
    }
    let mut raw = Vec::new();
    file.take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(os_error)?;
    if raw.len() > MAX_SOURCE_BYTES {
        return Err(PyError::value("source too large"));
    }
    let projection = inventory_projection(&pyjson::loads_bytes(&raw)?)?;
    let gid = group_id(group)?;
    atomic::write_json(&output.path(), &projection, Some(gid)).map_err(os_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ErrorSpec, json_eq};
    use serde::{Deserialize, Serialize};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[derive(Deserialize)]
    struct Fixtures {
        projection: Vec<ProjectionCase>,
        source_bytes: Vec<BytesCase>,
        default_source: String,
        files: Vec<FileCase>,
    }

    #[derive(Deserialize)]
    struct ProjectionCase {
        id: String,
        source: String,
        #[serde(default)]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Deserialize)]
    struct BytesCase {
        id: String,
        hex: String,
        #[serde(default)]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        #[serde(default)]
        p3: Option<String>,
    }

    #[derive(Clone, Deserialize)]
    struct FileCase {
        id: String,
        source: String,
        source_mode: u32,
        source_hex: Option<String>,
        pad_to: Option<usize>,
        directory: String,
        directory_mode: u32,
        directory_owner: String,
        source_owner: String,
        source_path: String,
        output_path: String,
        group: String,
        #[serde(default)]
        result: Option<Value>,
        #[serde(default)]
        error: Option<ErrorSpec>,
        #[serde(default)]
        files: Option<Vec<String>>,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/export.json")).unwrap()
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    /// The outcome of a P3 case: Python takes the input, the Rust code
    /// refuses it while reading the JSON (PLAN.md 4.2 item 4).
    fn assert_p3_refused(id: &str, tag: &str, outcome: Result<Value, PyError>) {
        let error = outcome.expect_err(id);
        let expected: &[&str] = match tag {
            // UTF-16 or UTF-32 without a byte order mark can be valid UTF-8
            // (NUL bytes), then the JSON is what is refused.
            "encoding" => &["UnicodeDecodeError", "JSONDecodeError"],
            "non-standard-json" => &["JSONDecodeError"],
            "nesting" => &["ValueError"],
            other => panic!("{id}: unknown p3 tag {other}"),
        };
        assert!(expected.contains(&error.class), "{id}: {error}");
    }

    fn assert_outcome(
        id: &str,
        outcome: Result<Value, PyError>,
        result: Option<&Value>,
        error: Option<&ErrorSpec>,
    ) {
        match (outcome, result, error) {
            (Ok(actual), Some(expected), None) => {
                assert!(json_eq(&actual, expected), "{id}: {actual} != {expected}");
            }
            (Err(actual), None, Some(expected)) => expected.assert_matches(&actual, id),
            (outcome, result, error) => {
                panic!("{id}: {outcome:?} vs result {result:?} error {error:?}")
            }
        }
    }

    #[test]
    fn projection_matches_python() {
        let fixtures = fixtures();
        assert!(fixtures.projection.len() >= 90);
        for case in &fixtures.projection {
            let outcome = pyjson::loads(&case.source).and_then(|data| inventory_projection(&data));
            if let Some(tag) = &case.p3 {
                assert_p3_refused(&case.id, tag, outcome);
                continue;
            }
            assert_outcome(&case.id, outcome, case.result.as_ref(), case.error.as_ref());
        }
    }

    #[test]
    fn source_bytes_are_read_like_python() {
        for case in &fixtures().source_bytes {
            let raw = decode_hex(&case.hex);
            let outcome = pyjson::loads_bytes(&raw).and_then(|data| inventory_projection(&data));
            if let Some(tag) = &case.p3 {
                assert_p3_refused(&case.id, tag, outcome);
                continue;
            }
            assert_outcome(&case.id, outcome, case.result.as_ref(), case.error.as_ref());
        }
    }

    #[test]
    fn projection_keeps_numbers_as_read_and_copies_nothing_else() {
        let fixtures = fixtures();
        let mut source = pyjson::loads(&fixtures.default_source).unwrap();
        source["generated_at_epoch"] = pyjson::loads("1.76E9").unwrap();
        source["apt"]["pending_security_count"] = pyjson::loads("18446744073709551617").unwrap();
        let projection = inventory_projection(&source).unwrap();
        let text = String::from_utf8(pyjson::dumps_compact(&projection)).unwrap();
        // serde_json spells a number token in its own way (`1.76e+9`); the
        // value is unchanged, not rounded through a float repr.
        assert_eq!(
            token_f64(
                projection["observed_at_epoch"]
                    .as_number()
                    .unwrap()
                    .as_str()
            ),
            1.76e9
        );
        assert!(
            text.contains("\"pending_security_count\":18446744073709551617"),
            "{text}"
        );
        for secret in [
            "synthetic-never-export",
            "/private/path",
            "openssl",
            "sha256",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    }

    #[test]
    fn python_paths_are_normalised_like_pathlib() {
        let cases = [
            ("", ".", "."),
            (".", ".", "."),
            ("a", "a", "."),
            ("a/", "a", "."),
            ("./a/./b/", "a/b", "a"),
            ("a//b", "a/b", "a"),
            ("a/../b", "a/../b", "a/.."),
            ("/", "/", "/"),
            ("/a", "/a", "/"),
            ("//a/b", "//a/b", "//a"),
            ("//", "//", "//"),
            ("///a", "/a", "/"),
            ("////a//", "/a", "/"),
        ];
        for (text, path, parent) in cases {
            let py = PyPath::new(Path::new(text));
            assert_eq!(py.path(), Path::new(path), "{text:?}");
            assert_eq!(py.parent(), Path::new(parent), "{text:?} parent");
        }
    }

    #[test]
    fn ownership_and_modes_are_checked_like_python() {
        let stat = |mode: u32, uid: u32, nlink: u64| FileStat {
            dev: 0,
            ino: 0,
            mode,
            nlink,
            uid,
            gid: 0,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
        };
        assert!(safe_directory(&stat(S_IFDIR | 0o750, 0, 2), 0));
        assert!(safe_directory(&stat(S_IFDIR | 0o1755, 0, 2), 0));
        assert!(!safe_directory(&stat(S_IFDIR | 0o750, 99, 2), 0));
        assert!(!safe_directory(&stat(S_IFDIR | 0o770, 0, 2), 0));
        assert!(!safe_directory(&stat(S_IFDIR | 0o757, 0, 2), 0));
        assert!(!safe_directory(&stat(0o120_777, 0, 1), 0));
        assert!(safe_source(&stat(S_IFREG | 0o640, 0, 1), 0));
        assert!(safe_source(&stat(S_IFREG | 0o4755, 0, 1), 0));
        assert!(!safe_source(&stat(S_IFREG | 0o640, 99, 1), 0));
        assert!(!safe_source(&stat(S_IFREG | 0o640, 0, 2), 0));
        assert!(!safe_source(&stat(S_IFREG | 0o620, 0, 1), 0));
        assert!(!safe_source(&stat(S_IFREG | 0o642, 0, 1), 0));
        assert!(!safe_source(&stat(0o010_640, 0, 1), 0));
    }

    fn own_ids(dir: &Path) -> (u32, u32) {
        let metadata = std::fs::metadata(dir).unwrap();
        (metadata.uid(), nix::unistd::getgid().as_raw())
    }

    fn own_group_name() -> String {
        nix::unistd::Group::from_gid(nix::unistd::getgid())
            .unwrap()
            .unwrap()
            .name
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The files of one case, as `build_export_world` in
    /// `fixtures/generate.py` creates them.
    fn build_world(root: &Path, case: &FileCase, default_source: &str) {
        let out = root.join("out");
        match case.directory.as_str() {
            "dir" => {
                std::fs::create_dir(&out).unwrap();
                let prior = out.join("software-health.json");
                std::fs::write(&prior, b"prior").unwrap();
                set_mode(&prior, 0o600);
                set_mode(&out, case.directory_mode);
            }
            "file" => std::fs::write(&out, b"not a directory").unwrap(),
            "symlink" => {
                std::fs::create_dir(root.join("out-target")).unwrap();
                std::os::unix::fs::symlink("out-target", &out).unwrap();
            }
            "missing" => {}
            other => panic!("{other}"),
        }
        let mut data = match &case.source_hex {
            Some(hex) => decode_hex(hex),
            None => default_source.as_bytes().to_vec(),
        };
        if let Some(size) = case.pad_to {
            data.resize(size, b' ');
        }
        let source = root.join("state.json");
        match case.source.as_str() {
            "file" | "hardlink" => {
                std::fs::write(&source, &data).unwrap();
                set_mode(&source, case.source_mode);
                if case.source == "hardlink" {
                    std::fs::hard_link(&source, root.join("alias.json")).unwrap();
                }
            }
            "symlink" => {
                let target = root.join("state-target.json");
                std::fs::write(&target, &data).unwrap();
                set_mode(&target, case.source_mode);
                std::os::unix::fs::symlink("state-target.json", &source).unwrap();
            }
            "dangling_symlink" => std::os::unix::fs::symlink("missing.json", &source).unwrap(),
            "directory" => {
                std::fs::create_dir(&source).unwrap();
                set_mode(&source, 0o750);
            }
            "fifo" => {
                let status = std::process::Command::new("mkfifo")
                    .args(["-m", "640"])
                    .arg(&source)
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            "missing" => {}
            other => panic!("{other}"),
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Run one file case; returns the outcome and the bytes written.
    fn run_file_case(
        case: &FileCase,
        default_source: &str,
    ) -> (Result<(), PyError>, Option<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let root_text = root.to_str().unwrap();
        build_world(root, case, default_source);
        let (uid, gid) = own_ids(root);
        let owner = |who: &str| if who == "root" { uid } else { uid + 1 };
        let owners = Owners {
            directory: owner(&case.directory_owner),
            source: owner(&case.source_owner),
        };
        let group = if case.group == "{own}" {
            own_group_name()
        } else {
            case.group.clone()
        };
        let target = root.join("out").join("software-health.json");
        let prior_inode = std::fs::metadata(&target).ok().map(|m| m.ino());
        let outcome = export_with(
            Path::new(&case.source_path.replace("{root}", root_text)),
            Path::new(&case.output_path.replace("{root}", root_text)),
            OsStr::new(&group),
            owners,
        );
        let mut written = None;
        if case.directory == "dir" {
            let out = root.join("out");
            set_mode(&out, 0o750);
            assert_eq!(Some(names(&out)), case.files, "{}", case.id);
            let bytes = std::fs::read(&target).unwrap();
            if outcome.is_ok() {
                let metadata = std::fs::metadata(&target).unwrap();
                assert_eq!(metadata.mode() & 0o7777, 0o640, "{}", case.id);
                assert_eq!(metadata.gid(), gid, "{}", case.id);
                assert_eq!(metadata.uid(), uid, "{}", case.id);
                assert_ne!(Some(metadata.ino()), prior_inode, "{}", case.id);
                written = Some(bytes);
            } else {
                assert_eq!(bytes, b"prior", "{}", case.id);
            }
        }
        (outcome, written)
    }

    #[test]
    fn export_files_match_python() {
        let fixtures = fixtures();
        assert!(fixtures.files.len() >= 30);
        for case in &fixtures.files {
            let (outcome, written) = run_file_case(case, &fixtures.default_source);
            match (&outcome, &case.result, &case.error) {
                (Ok(()), Some(expected), None) => {
                    let written = written.expect("written");
                    assert!(
                        written.is_ascii() && written.ends_with(b"}\n"),
                        "{}",
                        case.id
                    );
                    let actual = pyjson::loads(std::str::from_utf8(&written).unwrap()).unwrap();
                    assert!(json_eq(&actual, expected), "{}: {actual}", case.id);
                }
                (Err(actual), None, Some(expected)) => expected.assert_matches(actual, &case.id),
                _ => panic!(
                    "{}: {outcome:?} vs {:?} {:?}",
                    case.id, case.result, case.error
                ),
            }
        }
    }

    #[test]
    fn a_failed_write_keeps_the_previous_projection() {
        let fixtures = fixtures();
        let case = fixtures.files.iter().find(|c| c.id == "written").unwrap();
        let world = || {
            let dir = tempfile::tempdir().unwrap();
            build_world(dir.path(), case, &fixtures.default_source);
            let (uid, _) = own_ids(dir.path());
            (
                dir,
                Owners {
                    directory: uid,
                    source: uid,
                },
            )
        };
        // A group the process may not set: fchown fails after the temporary
        // file exists (`PermissionError`). Not as root, which may set any.
        let (dir, _) = world();
        if own_ids(dir.path()).0 != 0 {
            let mut refused = 0;
            for gid in (0..=100).chain([65_534]).map(nix::unistd::Gid::from_raw) {
                let Ok(Some(group)) = nix::unistd::Group::from_gid(gid) else {
                    continue;
                };
                let (dir, owners) = world();
                let out = dir.path().join("out");
                let outcome = export_with(
                    &dir.path().join("state.json"),
                    &out.join("software-health.json"),
                    OsStr::new(&group.name),
                    owners,
                );
                // A group the process belongs to is simply set.
                if let Err(error) = outcome {
                    assert_eq!(error.class, "PermissionError", "{error}");
                    assert_eq!(names(&out), ["software-health.json"]);
                    assert_eq!(
                        std::fs::read(out.join("software-health.json")).unwrap(),
                        b"prior"
                    );
                    refused += 1;
                }
            }
            assert!(refused > 0, "no foreign group among gids 0..=100 and 65534");
        }
        // A target that cannot be replaced: a non-empty directory.
        let (dir, owners) = world();
        let target = dir.path().join("out/software-health.json");
        std::fs::remove_file(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("kept"), b"x").unwrap();
        let error = export_with(
            &dir.path().join("state.json"),
            &target,
            OsStr::new(&own_group_name()),
            owners,
        )
        .unwrap_err();
        assert!(error.class.ends_with("Error"), "{error}");
        assert_eq!(names(&dir.path().join("out")), ["software-health.json"]);
        assert_eq!(names(&target), ["kept"]);
    }

    /// `fixtures/rust-export.json`: what the Rust export writes, for the
    /// Python reader of `software_estate` (`tests/test_software_live_rust_fixtures.py`).
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct RustExports {
        note: String,
        exports: Vec<RustExport>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct RustExport {
        id: String,
        source: String,
        text: String,
    }

    fn rust_written_exports() -> RustExports {
        let fixtures = fixtures();
        let template = fixtures
            .files
            .iter()
            .find(|case| case.id == "written")
            .unwrap();
        let mut exports = Vec::new();
        for case in fixtures
            .projection
            .iter()
            .filter(|case| case.result.is_some() && case.p3.is_none())
        {
            let file_case = FileCase {
                id: case.id.clone(),
                source_hex: Some(hex::encode(&case.source)),
                files: Some(vec!["software-health.json".into()]),
                ..template.clone()
            };
            let (outcome, written) = run_file_case(&file_case, &fixtures.default_source);
            outcome.unwrap_or_else(|error| panic!("{}: {error}", case.id));
            exports.push(RustExport {
                id: case.id.clone(),
                source: case.source.clone(),
                text: String::from_utf8(written.unwrap()).unwrap(),
            });
        }
        RustExports {
            note: "written by the Rust code (export::tests::rust_written_exports_are_committed); \
                   SOFTWARE_LIVE_BLESS=1 cargo test -p software-live rust_written rewrites it"
                .into(),
            exports,
        }
    }

    #[test]
    fn rust_written_exports_are_committed() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/rust-export.json");
        let actual = rust_written_exports();
        if std::env::var_os("SOFTWARE_LIVE_BLESS").is_some() {
            let text = serde_json::to_string_pretty(&actual).unwrap() + "\n";
            std::fs::write(&path, text).unwrap();
        }
        let committed: RustExports =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            committed, actual,
            "the Rust projection changed: rerun with SOFTWARE_LIVE_BLESS=1 and run \
             `just test-software-live-rust-fixtures`"
        );
        assert!(committed.exports.len() >= 20);
        for export in &committed.exports {
            assert!(
                export.text.is_ascii() && export.text.ends_with("}\n"),
                "{}",
                export.id
            );
        }
    }

    #[test]
    fn unknown_groups_are_key_errors() {
        let error = group_id(OsStr::new("software-live-no-such-group")).unwrap_err();
        assert_eq!(error.class, "KeyError");
        assert_eq!(
            group_id(OsStr::new(&own_group_name())).unwrap(),
            nix::unistd::getgid().as_raw()
        );
    }
}
