//! The policy file (PLAN.md 3.2; `guard.py:85-173, 662-670`).
//!
//! Loading has three steps, each refusing what the one before let through:
//!
//! 1. UTF-8 (`UnicodeDecodeError`), then JSON with `serde_json` into a strict
//!    tree ([`Json`]): duplicate keys anywhere refuse (`TypeError`), and
//!    `serde_json` itself refuses `NaN`, `Infinity`, lone surrogate escapes,
//!    numbers outside the double range and documents nested deeper than 127
//!    arrays and objects (`JSONDecodeError`), all of which Python's `json`
//!    accepts (PLAN.md 4.2).
//! 2. The typed policy, built in the order `Policy.from_dict` builds it, so a
//!    missing entry key is a `KeyError` and a wrong type a `TypeError` as in
//!    Python. Values must have the JSON type the role writes: lists of
//!    strings, an object of strings, objects with string fields, or `null`
//!    (or a missing key) for empty. Unknown keys are ignored (PLAN.md 3.2).
//! 3. The validation of `Policy.from_dict`, in its order and with its
//!    messages. The regexes anchor at the real end of the value, so a value
//!    with a trailing newline is refused where Python's `$` accepts it
//!    (PLAN.md 3.3.5, 4.2).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::LazyLock;

use regex_lite::Regex;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::repr::py_repr;
use crate::tokens::constant_regex;

static SAFE_PATH: LazyLock<Regex> = LazyLock::new(|| constant_regex(r"^/[A-Za-z0-9._/-]+$"));
static SAFE_NAME: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$"));
static SAFE_OWNER: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*$"));
static TEMP_TEMPLATE: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^/(?:var/)?tmp/[a-z0-9][a-z0-9._-]*\.X{6,}$"));
static READY_URL: LazyLock<Regex> =
    LazyLock::new(|| constant_regex(r"^http://127\.0\.0\.1:[0-9]{1,5}/[a-z]+$"));
static TEMP_FILE_PREFIX: LazyLock<Regex> = LazyLock::new(|| constant_regex(r"^[a-z0-9_]+$"));
static SCRATCH_PREFIX: LazyLock<Regex> = LazyLock::new(|| constant_regex(r"^[a-z][a-z0-9_]*$"));

/// `_is_safe_path` (`guard.py:203-206`).
pub fn is_safe_path(path: &str) -> bool {
    SAFE_PATH.is_match(path)
        && path
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "" | "." | ".."))
}

/// `_SAFE_NAME_RE.match` (`guard.py:38`).
pub fn is_safe_name(name: &str) -> bool {
    SAFE_NAME.is_match(name)
}

/// A root that uploads may write into, as its owner (`path_roots`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRoot {
    /// Without trailing `/`.
    pub path: String,
    /// `user:group`, never `root:`.
    pub owner: String,
}

/// `SqliteSnapshot` (`guard.py:85-93`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSnapshot {
    pub database: String,
    pub owner: String,
    pub temp_dir: String,
}

impl SqliteSnapshot {
    /// The user part of `owner`.
    pub fn user(&self) -> &str {
        self.owner.split(':').next().unwrap_or_default()
    }
}

/// `Policy` (`guard.py:96-108`). Lists keep the file's order (the first
/// matching root or snapshot wins); sets only answer membership questions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub dump_databases: BTreeSet<String>,
    pub restore_databases: BTreeMap<String, String>,
    pub temp_file_prefixes: Vec<String>,
    pub scratch_restore_prefixes: Vec<String>,
    pub units: BTreeSet<String>,
    pub private_media_paths: BTreeSet<String>,
    pub path_roots: Vec<PathRoot>,
    pub temp_dirs: Vec<String>,
    pub sqlite_snapshots: Vec<SqliteSnapshot>,
    pub read_files: BTreeSet<String>,
    pub ready_urls: BTreeSet<String>,
}

impl Policy {
    /// `Policy.scratch_database` (`guard.py:162-163`): `<prefix>_<digits>` for
    /// a scratch restore prefix (`re.fullmatch` of the escaped prefix, `_`
    /// and `[0-9]+`).
    pub fn scratch_database(&self, name: &str) -> bool {
        self.scratch_restore_prefixes.iter().any(|prefix| {
            name.strip_prefix(prefix.as_str())
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                })
        })
    }

    /// `Policy.private_temp_dir` (`guard.py:165-167`): a directory `mktemp -d`
    /// can return for one of the policy's `temp_dirs`.
    pub fn private_temp_dir(&self, path: &str) -> bool {
        self.temp_dirs
            .iter()
            .any(|template| is_mktemp_result(template, path))
    }

    /// `Policy.snapshot_for_temp_dir` (`guard.py:169-173`): the first
    /// snapshot whose `temp_dir` template `mktemp -d` turns into `path`.
    pub fn snapshot_for_temp_dir(&self, path: &str) -> Option<&SqliteSnapshot> {
        self.sqlite_snapshots
            .iter()
            .find(|snapshot| is_mktemp_result(&snapshot.temp_dir, path))
    }
}

/// `_temp_dir_re(template).match(path)` (`guard.py:79-82`): what `mktemp -d
/// <template>` can return, i.e. the template with its trailing `X`s replaced
/// by as many ASCII letters and digits. The prefix is compared literally (as
/// `re.escape` makes it). `path` is never a policy value, so Python's `$`
/// before a final `\n` cannot matter (commands cannot contain `\n`).
pub fn is_mktemp_result(template: &str, path: &str) -> bool {
    let prefix = template.trim_end_matches('X');
    let random = template.len() - prefix.len();
    path.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == random && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// The Python exception a policy error corresponds to (PLAN.md 4.3): the
/// name goes into the log line `policy error (<name>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyErrorKind {
    FileNotFound,
    Permission,
    IsADirectory,
    Os,
    UnicodeDecode,
    JsonDecode,
    Key,
    Type,
    Refused,
}

impl PolicyErrorKind {
    pub fn python_name(self) -> &'static str {
        match self {
            PolicyErrorKind::FileNotFound => "FileNotFoundError",
            PolicyErrorKind::Permission => "PermissionError",
            PolicyErrorKind::IsADirectory => "IsADirectoryError",
            PolicyErrorKind::Os => "OSError",
            PolicyErrorKind::UnicodeDecode => "UnicodeDecodeError",
            PolicyErrorKind::JsonDecode => "JSONDecodeError",
            PolicyErrorKind::Key => "KeyError",
            PolicyErrorKind::Type => "TypeError",
            PolicyErrorKind::Refused => "Refused",
        }
    }
}

/// Why a policy cannot be used. `Display` is the detail after `invalid
/// policy:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub kind: PolicyErrorKind,
    pub message: String,
}

impl PolicyError {
    fn new(kind: PolicyErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn type_error(message: impl Into<String>) -> Self {
        Self::new(PolicyErrorKind::Type, message)
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PolicyError {}

/// `load_policy(path)` (`guard.py:662-667`). The file's ownership and mode
/// are not checked (PLAN.md 3.2).
pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    let data = std::fs::read(path).map_err(|error| {
        let kind = match error.kind() {
            std::io::ErrorKind::NotFound => PolicyErrorKind::FileNotFound,
            std::io::ErrorKind::PermissionDenied => PolicyErrorKind::Permission,
            std::io::ErrorKind::IsADirectory => PolicyErrorKind::IsADirectory,
            _ => PolicyErrorKind::Os,
        };
        PolicyError::new(
            kind,
            format!("{}: {error}", py_repr(&path.to_string_lossy())),
        )
    })?;
    parse_policy(&data)
}

/// The policy in the bytes of a policy file.
pub fn parse_policy(data: &[u8]) -> Result<Policy, PolicyError> {
    let text = std::str::from_utf8(data).map_err(|error| {
        PolicyError::new(
            PolicyErrorKind::UnicodeDecode,
            format!(
                "'utf-8' codec can't decode the byte at position {}",
                error.valid_up_to()
            ),
        )
    })?;
    let json: Json = serde_json::from_str(text).map_err(|error| {
        let kind = if error.is_data() {
            PolicyErrorKind::Type
        } else {
            PolicyErrorKind::JsonDecode
        };
        PolicyError::new(kind, error.to_string())
    })?;
    let Json::Object(data) = json else {
        return Err(PolicyError::new(
            PolicyErrorKind::Refused,
            "policy must be a JSON object",
        ));
    };
    let policy = build(&data)?;
    validate(&policy)?;
    Ok(policy)
}

// --- step 1: a strict JSON tree -----------------------------------------------

/// A JSON value with the object members in file order. Numbers keep no value:
/// no policy field takes one.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn type_name(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool => "a boolean",
            Json::Number => "a number",
            Json::String(_) => "a string",
            Json::Array(_) => "a list",
            Json::Object(_) => "an object",
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Json, E> {
        Ok(Json::Bool)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Json, E> {
        Ok(Json::Number)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Json, E> {
        Ok(Json::Number)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Json, E> {
        Ok(Json::Number)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Json, E> {
        Ok(Json::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Json, E> {
        Ok(Json::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members: Vec<(String, Json)> = Vec::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate key {}",
                    py_repr(&key)
                )));
            }
            let value = map.next_value()?;
            members.push((key, value));
        }
        Ok(Json::Object(members))
    }
}

// --- step 2: the typed policy, in Policy.from_dict's order -------------------

type Members = [(String, Json)];

fn get<'a>(members: &'a Members, key: &str) -> Option<&'a Json> {
    members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// `data.get(key) or {}` for an object, `null` or a missing key.
fn object<'a>(members: &'a Members, key: &str) -> Result<&'a Members, PolicyError> {
    match get(members, key) {
        None | Some(Json::Null) => Ok(&[]),
        Some(Json::Object(inner)) => Ok(inner),
        Some(other) => Err(PolicyError::type_error(format!(
            "{key} must be an object, not {}",
            other.type_name()
        ))),
    }
}

/// `data.get(key) or []` for a list, `null` or a missing key.
fn list<'a>(members: &'a Members, key: &str) -> Result<&'a [Json], PolicyError> {
    match get(members, key) {
        None | Some(Json::Null) => Ok(&[]),
        Some(Json::Array(items)) => Ok(items),
        Some(other) => Err(PolicyError::type_error(format!(
            "{key} must be a list, not {}",
            other.type_name()
        ))),
    }
}

fn string<'a>(value: &'a Json, what: &str) -> Result<&'a str, PolicyError> {
    match value {
        Json::String(text) => Ok(text),
        other => Err(PolicyError::type_error(format!(
            "{what} must be a string, not {}",
            other.type_name()
        ))),
    }
}

fn strings<'a>(members: &'a Members, key: &str) -> Result<Vec<&'a str>, PolicyError> {
    list(members, key)?
        .iter()
        .map(|item| string(item, &format!("an entry of {key}")))
        .collect()
}

/// `entry[field]` of a list entry that must be an object of strings.
fn field<'a>(entry: &'a Json, list: &str, name: &str) -> Result<&'a str, PolicyError> {
    let Json::Object(members) = entry else {
        return Err(PolicyError::type_error(format!(
            "an entry of {list} must be an object, not {}",
            entry.type_name()
        )));
    };
    // Python's message is `str(KeyError(name))`.
    let value =
        get(members, name).ok_or_else(|| PolicyError::new(PolicyErrorKind::Key, py_repr(name)))?;
    string(value, &format!("{name} of an entry of {list}"))
}

fn owned<'a>(items: impl IntoIterator<Item = &'a str>) -> impl Iterator<Item = String> {
    items.into_iter().map(str::to_owned)
}

fn build(data: &Members) -> Result<Policy, PolicyError> {
    let postgres = object(data, "postgres")?;
    let dump_databases = owned(strings(postgres, "dump_databases")?).collect();
    let restore_databases = object(postgres, "restore_databases")?
        .iter()
        .map(|(name, owner)| {
            Ok((
                name.clone(),
                string(owner, "a value of restore_databases")?.to_owned(),
            ))
        })
        .collect::<Result<_, PolicyError>>()?;
    let temp_file_prefixes = owned(strings(postgres, "temp_file_prefixes")?).collect();
    let scratch_restore_prefixes = owned(strings(postgres, "scratch_restore_prefixes")?).collect();
    let units = owned(strings(data, "units")?).collect();
    let private_media_paths = strings(data, "private_media_paths")?
        .into_iter()
        .map(|p| p.trim_end_matches('/').to_owned())
        .collect();
    let path_roots = list(data, "path_roots")?
        .iter()
        .map(|entry| {
            Ok(PathRoot {
                path: field(entry, "path_roots", "path")?
                    .trim_end_matches('/')
                    .to_owned(),
                owner: field(entry, "path_roots", "owner")?.to_owned(),
            })
        })
        .collect::<Result<_, PolicyError>>()?;
    let temp_dirs = owned(strings(data, "temp_dirs")?).collect();
    let sqlite_snapshots = list(data, "sqlite_snapshots")?
        .iter()
        .map(|entry| {
            Ok(SqliteSnapshot {
                database: field(entry, "sqlite_snapshots", "database")?.to_owned(),
                owner: field(entry, "sqlite_snapshots", "owner")?.to_owned(),
                temp_dir: field(entry, "sqlite_snapshots", "temp_dir")?.to_owned(),
            })
        })
        .collect::<Result<_, PolicyError>>()?;
    let read_files = owned(strings(data, "read_files")?).collect();
    let ready_urls = owned(strings(data, "ready_urls")?).collect();
    Ok(Policy {
        dump_databases,
        restore_databases,
        temp_file_prefixes,
        scratch_restore_prefixes,
        units,
        private_media_paths,
        path_roots,
        temp_dirs,
        sqlite_snapshots,
        read_files,
        ready_urls,
    })
}

// --- step 3: validation (guard.py:132-159) -----------------------------------

fn require(condition: bool, message: impl FnOnce() -> String) -> Result<(), PolicyError> {
    if condition {
        Ok(())
    } else {
        Err(PolicyError::new(PolicyErrorKind::Refused, message()))
    }
}

fn is_deep_safe_path(path: &str) -> bool {
    is_safe_path(path) && path.matches('/').count() >= 2
}

fn validate(policy: &Policy) -> Result<(), PolicyError> {
    // Python iterates a set here; which of several invalid names the message
    // names may differ (PLAN.md 4.3).
    let names: BTreeSet<&String> = policy
        .dump_databases
        .iter()
        .chain(policy.restore_databases.keys())
        .chain(policy.restore_databases.values())
        .collect();
    for name in names {
        require(is_safe_name(name), || {
            format!("invalid database or role name in policy: {}", py_repr(name))
        })?;
    }
    for prefix in &policy.temp_file_prefixes {
        require(TEMP_FILE_PREFIX.is_match(prefix), || {
            format!("invalid temp file prefix in policy: {}", py_repr(prefix))
        })?;
    }
    for prefix in &policy.scratch_restore_prefixes {
        require(SCRATCH_PREFIX.is_match(prefix), || {
            format!("invalid scratch database prefix: {}", py_repr(prefix))
        })?;
    }
    for unit in &policy.units {
        require(is_safe_name(unit), || {
            format!("invalid unit name in policy: {}", py_repr(unit))
        })?;
    }
    for path in &policy.private_media_paths {
        require(is_deep_safe_path(path), || {
            format!("invalid private media path: {}", py_repr(path))
        })?;
    }
    for root in &policy.path_roots {
        require(is_deep_safe_path(&root.path), || {
            format!("invalid path root: {}", py_repr(&root.path))
        })?;
        require(SAFE_OWNER.is_match(&root.owner), || {
            format!("invalid owner for {}: {}", root.path, py_repr(&root.owner))
        })?;
        require(!root.owner.starts_with("root:"), || {
            format!("uploads into {} must not run as root", root.path)
        })?;
    }
    for template in &policy.temp_dirs {
        require(TEMP_TEMPLATE.is_match(template), || {
            format!("invalid temp dir template: {}", py_repr(template))
        })?;
    }
    for snapshot in &policy.sqlite_snapshots {
        require(is_deep_safe_path(&snapshot.database), || {
            format!("invalid sqlite database: {}", py_repr(&snapshot.database))
        })?;
        require(SAFE_OWNER.is_match(&snapshot.owner), || {
            format!("invalid sqlite owner: {}", py_repr(&snapshot.owner))
        })?;
        require(snapshot.user() != "root", || {
            "sqlite snapshots must run as the service user, not root".to_owned()
        })?;
        require(TEMP_TEMPLATE.is_match(&snapshot.temp_dir), || {
            format!("invalid temp dir template: {}", py_repr(&snapshot.temp_dir))
        })?;
    }
    for path in &policy.read_files {
        require(is_deep_safe_path(path), || {
            format!("invalid read file: {}", py_repr(path))
        })?;
    }
    for url in &policy.ready_urls {
        require(READY_URL.is_match(url), || {
            format!("invalid ready URL: {}", py_repr(url))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(text: &str) -> PolicyError {
        parse_policy(text.as_bytes()).unwrap_err()
    }

    #[test]
    fn patterns_compile() {
        for pattern in [
            &SAFE_PATH,
            &SAFE_NAME,
            &SAFE_OWNER,
            &TEMP_TEMPLATE,
            &READY_URL,
            &TEMP_FILE_PREFIX,
            &SCRATCH_PREFIX,
        ] {
            LazyLock::force(pattern);
        }
    }

    #[test]
    fn empty_and_null_mean_empty() {
        assert_eq!(parse_policy(b"{}"), Ok(Policy::default()));
        let nulls =
            r#"{"postgres": null, "units": null, "path_roots": null, "extra": [1, {"x": NaN}]}"#;
        // NaN is refused even under an unknown key.
        assert_eq!(error(nulls).kind, PolicyErrorKind::JsonDecode);
        let nulls =
            r#"{"postgres": {"dump_databases": null}, "units": null, "extra": [1, {"x": 2.5}]}"#;
        assert_eq!(parse_policy(nulls.as_bytes()), Ok(Policy::default()));
    }

    #[test]
    fn keeps_order_and_strips_trailing_slashes() {
        let policy = parse_policy(
            br#"{"path_roots": [{"path": "/srv/b/", "owner": "b:b"}, {"path": "/srv/a", "owner": "a:a"}],
                 "private_media_paths": ["/home/p/media//"]}"#,
        )
        .unwrap();
        assert_eq!(
            policy.path_roots,
            [
                PathRoot {
                    path: "/srv/b".into(),
                    owner: "b:b".into()
                },
                PathRoot {
                    path: "/srv/a".into(),
                    owner: "a:a".into()
                },
            ]
        );
        assert_eq!(
            policy.private_media_paths,
            BTreeSet::from(["/home/p/media".to_owned()])
        );
    }

    #[test]
    fn strict_types() {
        for text in [
            r#"{"units": "gotosocial"}"#,
            r#"{"units": [1]}"#,
            r#"{"units": false}"#,
            r#"{"postgres": []}"#,
            r#"{"postgres": {"restore_databases": [["a", "b"]]}}"#,
            r#"{"path_roots": [{"path": 1, "owner": "a:a"}]}"#,
            r#"{"units": ["a"], "units": ["b"]}"#,
            r#"{"extra": {"x": 1, "x": 2}}"#,
        ] {
            assert_eq!(error(text).kind, PolicyErrorKind::Type, "{text}");
        }
        assert_eq!(
            error(r#"{"x": "\ud800"}"#).kind,
            PolicyErrorKind::JsonDecode
        );
        assert_eq!(
            error(r#"{"x": Infinity}"#).kind,
            PolicyErrorKind::JsonDecode
        );
    }

    #[test]
    fn nesting_is_limited_to_127_containers() {
        // serde_json's recursion limit (PLAN.md 4.2); the top-level object
        // counts.
        let nested = |containers: usize| {
            let inner = containers - 1;
            format!("{{\"x\": {}{}}}", "[".repeat(inner), "]".repeat(inner))
        };
        assert_eq!(parse_policy(nested(127).as_bytes()), Ok(Policy::default()));
        assert_eq!(error(&nested(128)).kind, PolicyErrorKind::JsonDecode);
    }

    #[test]
    fn key_errors_in_entries() {
        let missing = error(r#"{"path_roots": [{"owner": "a:a"}]}"#);
        assert_eq!(missing.kind, PolicyErrorKind::Key);
        let missing = error(r#"{"sqlite_snapshots": [{"database": "/a/b", "owner": "a:a"}]}"#);
        assert_eq!(missing.kind, PolicyErrorKind::Key);
    }

    #[test]
    fn trailing_newline_is_refused() {
        let refused = error(r#"{"units": ["gotosocial\n"]}"#);
        assert_eq!(refused.kind, PolicyErrorKind::Refused);
        assert_eq!(
            refused.message,
            "invalid unit name in policy: 'gotosocial\\n'"
        );
    }

    #[test]
    fn other_errors() {
        assert_eq!(error("[]").message, "policy must be a JSON object");
        assert_eq!(error("{").kind, PolicyErrorKind::JsonDecode);
        assert_eq!(error("\u{feff}{}").kind, PolicyErrorKind::JsonDecode);
        assert_eq!(
            parse_policy(b"{\"units\": [\"\xff\"]}").unwrap_err().kind,
            PolicyErrorKind::UnicodeDecode
        );
        let missing = load_policy(Path::new("/nonexistent/policy.json")).unwrap_err();
        assert_eq!(missing.kind, PolicyErrorKind::FileNotFound);
        let directory = load_policy(Path::new("/")).unwrap_err();
        assert_eq!(directory.kind, PolicyErrorKind::IsADirectory);
    }

    #[test]
    fn scratch_databases() {
        let policy = Policy {
            scratch_restore_prefixes: vec!["djangochat_restore".into(), "x".into()],
            ..Policy::default()
        };
        for name in ["djangochat_restore_1", "djangochat_restore_20261015", "x_0"] {
            assert!(policy.scratch_database(name), "{name}");
        }
        for name in [
            "djangochat_restore",
            "djangochat_restore_",
            "djangochat_restore_1a",
            "djangochat_restore__1",
            "xdjangochat_restore_1",
            "djangochat_restore_-1",
            "y_1",
            "",
        ] {
            assert!(!policy.scratch_database(name), "{name}");
        }
        assert!(!Policy::default().scratch_database("x_1"));
    }

    #[test]
    fn mktemp_results() {
        let template = "/var/tmp/djangochat-restore.XXXXXXXX";
        assert!(is_mktemp_result(
            template,
            "/var/tmp/djangochat-restore.Ab12Cd34"
        ));
        for path in [
            "/var/tmp/djangochat-restore.Ab12Cd3",
            "/var/tmp/djangochat-restore.Ab12Cd345",
            "/var/tmp/djangochat-restore.Ab12Cd3_",
            "/var/tmp/djangochat-restore.Ab12Cd3/",
            "/var/tmp/djangochat-restoreXAb12Cd34",
            "/tmp/djangochat-restore.Ab12Cd34",
        ] {
            assert!(!is_mktemp_result(template, path), "{path}");
        }
        // `rstrip("X")` takes every trailing X, also one before the dot.
        assert!(is_mktemp_result("/tmp/aX.XXXXXX", "/tmp/aX.abcdef"));
        let policy = Policy {
            temp_dirs: vec![template.into()],
            sqlite_snapshots: vec![
                SqliteSnapshot {
                    database: "/var/lib/a/a.db".into(),
                    owner: "a:a".into(),
                    temp_dir: "/var/tmp/s.XXXXXX".into(),
                },
                SqliteSnapshot {
                    database: "/var/lib/b/b.db".into(),
                    owner: "b:b".into(),
                    temp_dir: "/var/tmp/s.XXXXXX".into(),
                },
            ],
            ..Policy::default()
        };
        assert!(policy.private_temp_dir("/var/tmp/djangochat-restore.abcdefgh"));
        assert!(!policy.private_temp_dir("/var/tmp/s.abcdef"));
        // The first matching snapshot wins (PLAN.md 3.2).
        assert_eq!(
            policy
                .snapshot_for_temp_dir("/var/tmp/s.abcdef")
                .map(|s| s.owner.as_str()),
            Some("a:a")
        );
        assert_eq!(policy.snapshot_for_temp_dir("/var/tmp/s.abcde"), None);
    }

    #[test]
    fn safe_paths() {
        for path in ["/a", "/a/b", "/a/b/", "/a.b/c-d_e"] {
            assert!(is_safe_path(path), "{path}");
        }
        for path in [
            "", "/", "a/b", "/a//b", "/a/./b", "/a/../b", "/a/b\n", "/a b", "/a/..",
        ] {
            assert!(!is_safe_path(path), "{path:?}");
        }
    }
}
