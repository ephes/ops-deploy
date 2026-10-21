//! Upstream lookups and their daily caches: `upstream` (the latest stable
//! Traefik release on GitHub) and `lifecycle_upstream` (an endoflife.date
//! product), `software_live.py:149-239`; `cache_variant` (`:62-65`) and
//! `lifecycle_date` (`:47-52`). PLAN.md 3.3 "Upstream lookups and caches".
//!
//! An answer is a JSON object: `{…, "status": "ok", "cached": bool}` with
//! the fetched or cached fields, or `{"status": "unknown", "error":
//! "<Class>", "last_success": <cache or null>}`. A lookup never raises: every
//! failure after the cache read becomes the "unknown" answer, and a failed
//! refresh never rewrites or re-dates the cache.
//!
//! The cache files are shared with the Python program (P1): this module
//! reads what Python wrote (`json.dump(…, sort_keys=True)`, separators
//! `", "`) and writes what Python reads (sorted, compact, ASCII only,
//! numbers as they were read). A cache is used only when it parses and
//! validates exactly as Python validates it; anything else is ignored. Where
//! Python's own check raises an exception it does not catch (a lifecycle
//! cache that is not an object, a timestamp integer too large for a float),
//! the Rust code ignores the cache instead (PLAN.md 4.2 item 12).

use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use serde_json::{Map, Value};

use crate::error::PyError;
use crate::http::{BODY_LIMIT, HttpRequest, TIMEOUT};
use crate::probe::System;
use crate::pyjson::{self, is_int_token, token_f64, truthy};
use crate::version::version;

/// `UPSTREAM_URL`: the latest Traefik release.
pub const UPSTREAM_URL: &str = "https://api.github.com/repos/traefik/traefik/releases/latest";
/// `UPSTREAM_TTL`: a cache is fresh for this many seconds.
pub const UPSTREAM_TTL: f64 = 86400.0;
/// The `User-Agent` of both requests.
pub const USER_AGENT: &str = "ops-library-software-live/1";
/// The `Accept` header of the GitHub request.
pub const GITHUB_ACCEPT: &str = "application/vnd.github+json";

/// `LIFECYCLE_URL.format(product=product)`.
pub fn lifecycle_url(product: &str) -> String {
    format!("https://endoflife.date/api/{product}.json")
}

/// `cache_path.with_name(f"{cache_path.stem}-{name}{cache_path.suffix}")`
/// with the `pathlib` rules of Python 3.12 and 3.13: the path is split into
/// its root (`/`, or `//` but not `///`) and its non-empty parts other than
/// `.`; the suffix is the last `.` and what follows, unless that dot starts
/// or ends the name. A path without a name (`""`, `.`, `/`) is a
/// `ValueError`, which Python raises outside the lookup's error boundary.
pub fn cache_variant(cache_path: &Path, name: &str) -> Result<PathBuf, PyError> {
    let bytes = cache_path.as_os_str().as_bytes();
    let root: &[u8] = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
        b"//"
    } else if bytes.starts_with(b"/") {
        b"/"
    } else {
        b""
    };
    let parts: Vec<&[u8]> = bytes
        .split(|b| *b == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect();
    let Some((last, parents)) = parts.split_last() else {
        return Err(PyError::value(format!(
            "{} has an empty name",
            cache_path.display()
        )));
    };
    let (stem, suffix): (&[u8], &[u8]) = match last.iter().rposition(|b| *b == b'.') {
        Some(dot) if 0 < dot && dot < last.len() - 1 => (&last[..dot], &last[dot..]),
        _ => (last, b""),
    };
    let mut new_name = stem.to_vec();
    new_name.push(b'-');
    new_name.extend_from_slice(name.as_bytes());
    new_name.extend_from_slice(suffix);
    let mut out = root.to_vec();
    for part in parents.iter().copied().chain([new_name.as_slice()]) {
        if out.len() > root.len() {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(out)))
}

/// `lifecycle_date(value)` for `cycle.get(key)` (`None` when the key is
/// missing): `null` and booleans give no date, a string must be an ISO
/// date, anything else is a `TypeError`.
///
/// Only `YYYY-MM-DD` with ASCII digits is a date here (PLAN.md 4.2 item 6):
/// Python 3.11+ `date.fromisoformat` also reads `YYYYMMDD` and ISO week
/// dates, which endoflife.date never sends.
pub fn lifecycle_date(value: Option<&Value>) -> Result<Option<NaiveDate>, PyError> {
    match value {
        None | Some(Value::Null | Value::Bool(_)) => Ok(None),
        Some(Value::String(text)) => iso_date(text)
            .map(Some)
            .ok_or_else(|| PyError::value(format!("Invalid isoformat string: '{text}'"))),
        Some(_) => Err(PyError::type_error("invalid lifecycle date")),
    }
}

/// `YYYY-MM-DD`, year 1 to 9999 (`datetime.MINYEAR`, `MAXYEAR`).
fn iso_date(text: &str) -> Option<NaiveDate> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = &bytes[range];
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0, |n, b| n * 10 + u32::from(b - b'0')))
    };
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    if year == 0 {
        return None;
    }
    NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)
}

/// `json.loads(response.read(…))`: the bytes are UTF-8, a UTF-8 byte order
/// mark is dropped (Python decodes bytes as `utf-8-sig`); UTF-16 and UTF-32
/// bodies, which Python would detect, are refused (PLAN.md 4.2 item 4).
fn loads_body(body: &[u8]) -> Result<Value, PyError> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let text = std::str::from_utf8(body)
        .map_err(|error| PyError::new("UnicodeDecodeError", error.to_string()))?;
    pyjson::loads(text)
}

/// `json.loads(path.read_text())` of a cache file as a JSON object, or
/// `None` for a file Python would not use (unreadable, not UTF-8, not JSON,
/// not an object).
fn read_cache<S: System + ?Sized>(system: &S, path: &Path) -> Option<Map<String, Value>> {
    let bytes = system.read_file(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    match pyjson::loads(&text).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// `checked_at_epoch` as `now - checked` reads it: an int, a float or a
/// bool. `None` for a missing key or another type (Python's `KeyError`,
/// `TypeError`) and for an integer beyond the float range (Python's
/// uncaught `OverflowError`, PLAN.md 4.2 item 12).
fn checked_at(cache: &Map<String, Value>) -> Option<f64> {
    match cache.get("checked_at_epoch")? {
        Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
        Value::Number(number) => {
            let token = number.as_str();
            let seconds = token_f64(token);
            (!is_int_token(token) || seconds.is_finite()).then_some(seconds)
        }
        _ => None,
    }
}

/// A cache file that is valid evidence: it parses as an object, passes
/// `valid` and has a usable `checked_at_epoch`. Returns it and that time.
fn usable_cache<S: System + ?Sized>(
    system: &S,
    path: &Path,
    valid: impl Fn(&Map<String, Value>) -> bool,
) -> Option<(Map<String, Value>, f64)> {
    let cache = read_cache(system, path)?;
    if !valid(&cache) {
        return None;
    }
    let checked = checked_at(&cache)?;
    Some((cache, checked))
}

/// `0 <= now - checked < UPSTREAM_TTL`.
fn is_fresh(now: f64, checked: f64) -> bool {
    let age = now - checked;
    (0.0..UPSTREAM_TTL).contains(&age)
}

/// `{**fields, "status": "ok", "cached": cached}`.
fn ok(mut fields: Map<String, Value>, cached: bool) -> Value {
    fields.insert("status".into(), "ok".into());
    fields.insert("cached".into(), cached.into());
    Value::Object(fields)
}

/// The answer of a failed refresh: the class only, and the valid cache as
/// evidence (never as success).
fn unknown(error: &PyError, cached: Option<Map<String, Value>>) -> Value {
    let mut fields = Map::new();
    fields.insert("status".into(), "unknown".into());
    fields.insert("error".into(), error.class.into());
    fields.insert(
        "last_success".into(),
        cached.map_or(Value::Null, Value::Object),
    );
    Value::Object(fields)
}

/// `now` as the JSON number Python writes for a float.
fn epoch_value(now: f64) -> Value {
    pyjson::number_from_f64(now).map_or(Value::Null, Value::Number)
}

/// `upstream(cache_path, now)`: the latest stable Traefik release.
pub fn upstream<S: System + ?Sized>(system: &S, cache_path: Option<&Path>, now: f64) -> Value {
    let mut cached = None;
    if let Some((cache, checked)) = cache_path.and_then(|path| {
        usable_cache(system, path, |cache| {
            // `version(cached["version"])`
            cache
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|text| version(text).is_ok())
        })
    }) {
        if is_fresh(now, checked) {
            return ok(cache, true);
        }
        cached = Some(cache);
    }
    match refresh_release(system, cache_path, now) {
        Ok(answer) => answer,
        Err(error) => unknown(&error, cached),
    }
}

fn refresh_release<S: System + ?Sized>(
    system: &S,
    cache_path: Option<&Path>,
    now: f64,
) -> Result<Value, PyError> {
    let body = system.http_get(&HttpRequest {
        url: UPSTREAM_URL,
        headers: &[("User-Agent", USER_AGENT), ("Accept", GITHUB_ACCEPT)],
        timeout: TIMEOUT,
        limit: BODY_LIMIT,
    })?;
    let data = loads_body(&body)?;
    let Value::Object(data) = data else {
        // `data["tag_name"]` on a list, a string, a number or None.
        return Err(PyError::type_error(format!(
            "'{}' object cannot be indexed by 'tag_name'",
            pyjson::type_name(&data)
        )));
    };
    let tag = data
        .get("tag_name")
        .ok_or_else(|| PyError::key("tag_name"))?;
    let Value::String(tag) = tag else {
        return Err(PyError::type_error("expected string or bytes-like object"));
    };
    version(tag)?;
    let flag = |key: &str| data.get(key).is_some_and(truthy);
    if flag("draft") || flag("prerelease") {
        return Err(PyError::value("upstream release is not stable"));
    }
    let mut result = Map::new();
    result.insert(
        "version".into(),
        tag.strip_prefix('v').unwrap_or(tag).into(),
    );
    result.insert("checked_at_epoch".into(), epoch_value(now));
    if let Some(path) = cache_path {
        system
            .write_json(path, &Value::Object(result.clone()), None)
            .map_err(|error| PyError::os(&error))?;
    }
    Ok(ok(result, false))
}

/// `lifecycle_upstream(product, cache_path, now)`: the release cycles of an
/// endoflife.date product. The cache is `<cache stem>-<product><suffix>`
/// next to `cache_path`. `Err` only for a cache path without a name
/// ([`cache_variant`]), which Python raises outside the error boundary.
pub fn lifecycle_upstream<S: System + ?Sized>(
    system: &S,
    product: &str,
    cache_path: Option<&Path>,
    now: f64,
) -> Result<Value, PyError> {
    let path = cache_path
        .map(|path| cache_variant(path, product))
        .transpose()?;
    let mut cached = None;
    if let Some((cache, checked)) = path.as_deref().and_then(|path| {
        usable_cache(system, path, |cache| {
            cache.get("product").and_then(Value::as_str) == Some(product)
                && cache.get("cycles").is_some_and(Value::is_array)
        })
    }) {
        if is_fresh(now, checked) {
            return Ok(ok(cache, true));
        }
        cached = Some(cache);
    }
    Ok(
        match refresh_lifecycle(system, product, path.as_deref(), now) {
            Ok(answer) => answer,
            Err(error) => unknown(&error, cached),
        },
    )
}

/// A cycle Python keeps: an object with a string `cycle`, an `eol` that is
/// missing, `null`, a bool or a date, and a `support` that is missing,
/// `null`, a bool or a date.
fn valid_cycle(cycle: &Value) -> bool {
    let Value::Object(fields) = cycle else {
        return false;
    };
    if !fields.get("cycle").is_some_and(Value::is_string) {
        return false;
    }
    if lifecycle_date(fields.get("eol")).is_err() {
        return false;
    }
    match fields.get("support") {
        None | Some(Value::Null) => true,
        support => lifecycle_date(support).is_ok(),
    }
}

fn refresh_lifecycle<S: System + ?Sized>(
    system: &S,
    product: &str,
    path: Option<&Path>,
    now: f64,
) -> Result<Value, PyError> {
    let url = lifecycle_url(product);
    let body = system.http_get(&HttpRequest {
        url: &url,
        headers: &[("User-Agent", USER_AGENT)],
        timeout: TIMEOUT,
        limit: BODY_LIMIT,
    })?;
    let cycles = match loads_body(&body)? {
        Value::Array(cycles) if !cycles.is_empty() => cycles,
        _ => return Err(PyError::value("empty lifecycle response")),
    };
    // Each kept cycle is stored whole, with every upstream key.
    let valid: Vec<Value> = cycles.into_iter().filter(valid_cycle).collect();
    if valid.is_empty() {
        return Err(PyError::value("lifecycle response has no valid cycles"));
    }
    let mut result = Map::new();
    result.insert("product".into(), product.into());
    result.insert("cycles".into(), Value::Array(valid));
    result.insert("checked_at_epoch".into(), epoch_value(now));
    if let Some(path) = path {
        system
            .write_json(path, &Value::Object(result.clone()), None)
            .map_err(|error| PyError::os(&error))?;
    }
    Ok(ok(result, false))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::http::HttpClient;
    use crate::probe::fake::{FakeSystem, FileEntry, HttpSpec, World};
    use crate::probe::{CommandError, CommandOutput, FileStat, HostFile, HostSystem};
    use crate::testutil::https::{Reply, TestServer};
    use crate::testutil::{ErrorSpec, json_eq};

    /// The directory of the fake world's cache files.
    const ROOT: &str = "/srv/software-live";

    fn at(name: &str) -> String {
        if name.starts_with('/') {
            name.to_owned()
        } else {
            format!("{ROOT}/{name}")
        }
    }

    #[derive(Deserialize)]
    struct Fixtures {
        cache_variant: Vec<VariantCase>,
        cases: Vec<Case>,
        constants: Constants,
    }

    #[derive(Deserialize)]
    struct Constants {
        upstream_url: String,
        lifecycle_url: String,
        ttl: f64,
    }

    #[derive(Deserialize)]
    struct VariantCase {
        path: String,
        name: String,
        result: Option<String>,
        error: Option<ErrorSpec>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        files: BTreeMap<String, FileEntry>,
        write_errors: BTreeMap<String, String>,
        calls: Vec<Call>,
    }

    #[derive(Deserialize)]
    struct Call {
        function: String,
        #[serde(default)]
        product: Option<String>,
        cache: Option<String>,
        now: f64,
        #[serde(default)]
        result: Option<String>,
        #[serde(default)]
        raises: Option<ErrorSpec>,
        http: Vec<HttpSpec>,
        writes: Vec<WriteSpec>,
        #[serde(default)]
        p3: Option<P3>,
    }

    #[derive(Deserialize)]
    struct WriteSpec {
        path: String,
        data: String,
        group: Option<u32>,
    }

    /// What the Rust code does instead (PLAN.md 4.2), as the Python code
    /// does for the input the Rust code effectively sees.
    #[derive(Deserialize)]
    struct P3 {
        tag: String,
        result: String,
        writes: Vec<WriteSpec>,
        #[serde(default)]
        http: Option<Vec<HttpSpec>>,
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/upstream.json")).unwrap()
    }

    fn call<S: System + ?Sized>(system: &S, call: &Call) -> Result<Value, PyError> {
        let cache = call.cache.as_deref().map(|name| PathBuf::from(at(name)));
        match call.function.as_str() {
            "upstream" => Ok(upstream(system, cache.as_deref(), call.now)),
            "lifecycle_upstream" => lifecycle_upstream(
                system,
                call.product.as_deref().expect("a product"),
                cache.as_deref(),
                call.now,
            ),
            other => panic!("unknown function {other}"),
        }
    }

    #[test]
    fn lookups_and_caches_match_python() {
        let cases = fixtures().cases;
        assert!(cases.len() >= 150, "{}", cases.len());
        let mut p3_tags = std::collections::BTreeSet::new();
        for case in cases {
            let world = World {
                files: case.files.iter().map(|(k, v)| (at(k), v.clone())).collect(),
                write_errors: case
                    .write_errors
                    .iter()
                    .map(|(k, v)| (at(k), v.clone()))
                    .collect(),
                ..World::default()
            };
            let fake = FakeSystem::new(world);
            for (index, step) in case.calls.iter().enumerate() {
                let id = format!("{}[{index}]", case.id);
                let (result, raises, writes, http) = match &step.p3 {
                    Some(p3) => {
                        p3_tags.insert(p3.tag.clone());
                        (
                            Some(&p3.result),
                            None,
                            &p3.writes,
                            p3.http.as_ref().unwrap_or(&step.http),
                        )
                    }
                    None => (
                        step.result.as_ref(),
                        step.raises.as_ref(),
                        &step.writes,
                        &step.http,
                    ),
                };
                fake.push_http(http);
                let before = fake.writes.borrow().len();
                let actual = call(&fake, step);
                match (result, raises) {
                    (Some(expected), None) => {
                        let expected = pyjson::loads(expected).unwrap();
                        let actual = actual.unwrap_or_else(|e| panic!("{id}: {e}"));
                        assert!(json_eq(&actual, &expected), "{id}: {actual} != {expected}");
                    }
                    (None, Some(expected)) => expected.assert_matches(&actual.unwrap_err(), &id),
                    _ => panic!("{id}: a result or an exception"),
                }
                assert_eq!(fake.pending_http(), 0, "{id}: requests not made");
                let made = fake.writes.borrow()[before..].to_vec();
                assert_eq!(made.len(), writes.len(), "{id}: writes {made:?}");
                for (write, expected) in made.iter().zip(writes) {
                    assert_eq!(write.path, at(&expected.path), "{id}");
                    let data = pyjson::loads(&expected.data).unwrap();
                    assert!(json_eq(&write.value, &data), "{id}: {}", write.value);
                    assert_eq!(write.group, expected.group, "{id}");
                }
            }
        }
        let expected = [
            "cache-crash",
            "iso-date",
            "non-standard-json",
            "unicode-digits",
            "utf16-body",
        ];
        assert_eq!(p3_tags.into_iter().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn cache_variant_matches_python() {
        let cases = fixtures().cache_variant;
        assert!(cases.len() >= 20);
        for case in cases {
            let actual = cache_variant(Path::new(&case.path), &case.name);
            match (&case.result, &case.error) {
                (Some(expected), None) => {
                    let actual = actual.unwrap_or_else(|e| panic!("{:?}: {e}", case.path));
                    assert_eq!(actual, PathBuf::from(expected), "{:?}", case.path);
                }
                (None, Some(expected)) => expected.assert_matches(&actual.unwrap_err(), &case.path),
                _ => panic!("{:?}: a result or an error", case.path),
            }
        }
    }

    #[test]
    fn cache_variant_follows_python_3_12_and_3_13() {
        // Python 3.14 reads `a.` as stem `a`, suffix `.` and `..json` as a
        // stem without suffix; the hosts run 3.12 and 3.13 (PLAN.md 1.1).
        for (path, expected) in [
            ("a.", "a.-ubuntu"),
            ("a..", "a..-ubuntu"),
            ("..json", ".-ubuntu.json"),
            ("a.b.", "a.b.-ubuntu"),
            ("/x/.json.", "/x/.json.-ubuntu"),
        ] {
            assert_eq!(
                cache_variant(Path::new(path), "ubuntu").unwrap(),
                PathBuf::from(expected),
                "{path}"
            );
        }
    }

    #[test]
    fn constants_match_python() {
        let constants = fixtures().constants;
        assert_eq!(UPSTREAM_URL, constants.upstream_url);
        assert_eq!(lifecycle_url("{product}"), constants.lifecycle_url);
        assert_eq!(UPSTREAM_TTL, constants.ttl);
    }

    #[test]
    fn lifecycle_dates() {
        let date = |text: &str| lifecycle_date(Some(&Value::String(text.into())));
        assert_eq!(
            date("2024-02-29").unwrap(),
            NaiveDate::from_ymd_opt(2024, 2, 29)
        );
        for invalid in [
            "2023-02-29",
            "0000-01-01",
            "20240229",
            "2024-W09",
            "2024-02-2\u{0669}",
        ] {
            assert_eq!(date(invalid).unwrap_err().class, "ValueError", "{invalid}");
        }
        assert_eq!(lifecycle_date(None).unwrap(), None);
        assert_eq!(lifecycle_date(Some(&Value::Bool(true))).unwrap(), None);
        let number = lifecycle_date(Some(&serde_json::json!(2024))).unwrap_err();
        assert_eq!(number.to_string(), "TypeError: invalid lifecycle date");
    }

    /// The host's file system and process calls, with HTTPS from a fake
    /// world or from a local test server.
    struct LocalHost {
        fake: Option<FakeSystem>,
        server: Option<(HttpClient, String)>,
    }

    impl System for LocalHost {
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
        fn readlink(&self, path: &Path) -> io::Result<OsString> {
            HostSystem.readlink(path)
        }
        fn run(&self, argv: &[&OsStr], timeout: Duration) -> Result<CommandOutput, CommandError> {
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
        fn http_get(&self, request: &HttpRequest<'_>) -> Result<Vec<u8>, PyError> {
            if let Some(fake) = &self.fake {
                return fake.http_get(request);
            }
            let (client, base) = self.server.as_ref().expect("a fake or a server");
            // The real URL's path, sent to the local server.
            let path = ["https://api.github.com", "https://endoflife.date"]
                .iter()
                .find_map(|origin| request.url.strip_prefix(origin))
                .expect("an upstream URL");
            let url = format!("{base}{path}");
            client.get(&HttpRequest {
                url: &url,
                ..*request
            })
        }
        fn write_json(&self, path: &Path, value: &Value, group: Option<u32>) -> io::Result<()> {
            HostSystem.write_json(path, value, group)
        }
    }

    fn spec(url: &str, accept: bool, body: &str) -> HttpSpec {
        let mut headers = BTreeMap::from([("user-agent".to_owned(), USER_AGENT.to_owned())]);
        if accept {
            headers.insert("accept".into(), GITHUB_ACCEPT.into());
        }
        serde_json::from_value(serde_json::json!({
            "url": url, "headers": headers, "timeout": 10.0, "body": body,
        }))
        .unwrap()
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct RustCache {
        id: String,
        function: String,
        product: Option<String>,
        /// The `--cache` path's name; the file is `file` next to it.
        cache: String,
        file: String,
        now: f64,
        text: String,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct RustCaches {
        note: String,
        caches: Vec<RustCache>,
    }

    /// Caches as the Rust code writes them, for the Python test that reads
    /// them with the Python program (`tests/test_software_live_rust_fixtures.py`,
    /// PLAN.md 3.3: cache files are shared across the implementations).
    fn rust_written_caches() -> RustCaches {
        let lifecycle = r#"[{"cycle": "17", "latest": "17.11", "eol": "2029-11-08",
            "releaseDate": "2024-09-26", "lts": false, "support": true,
            "extra": {"n": 18446744073709551617, "f": 1e16, "small": 2.5e-07, "neg": -0,
                      "s": "é😀\u0001\"\\/"}},
            {"cycle": "16", "eol": true, "support": null}]"#;
        type Scenario<'a> = (&'a str, &'a str, Option<&'a str>, &'a str, f64, HttpSpec);
        let scenarios: [Scenario<'_>; 4] = [
            (
                "release",
                "upstream",
                None,
                "upstream.json",
                1_760_000_000.25,
                spec(
                    UPSTREAM_URL,
                    true,
                    r#"{"tag_name": "v3.7.12", "draft": false}"#,
                ),
            ),
            (
                "release_integral_now",
                "upstream",
                None,
                "integral.json",
                1_760_000_000.0,
                spec(UPSTREAM_URL, true, r#"{"tag_name": "3.8.0"}"#),
            ),
            (
                "lifecycle_postgresql",
                "lifecycle_upstream",
                Some("postgresql"),
                "upstream.json",
                1_760_000_000.125,
                spec(&lifecycle_url("postgresql"), false, lifecycle),
            ),
            (
                "lifecycle_ubuntu_without_suffix",
                "lifecycle_upstream",
                Some("ubuntu"),
                "cache",
                1e9,
                spec(
                    &lifecycle_url("ubuntu"),
                    false,
                    r#"[{"cycle": "24.04", "lts": true, "eol": "2029-05-31", "support": "2029-05-31"}]"#,
                ),
            ),
        ];
        let dir = tempfile::tempdir().unwrap();
        let mut caches = Vec::new();
        for (id, function, product, cache, now, response) in scenarios {
            let host = LocalHost {
                fake: Some(FakeSystem::new(World::default())),
                server: None,
            };
            host.fake.as_ref().unwrap().push_http(&[response]);
            let path = dir.path().join(cache);
            let answer = match product {
                None => upstream(&host, Some(&path), now),
                Some(product) => lifecycle_upstream(&host, product, Some(&path), now).unwrap(),
            };
            assert_eq!(answer["status"], "ok", "{id}: {answer}");
            let file = match product {
                None => path.clone(),
                Some(product) => cache_variant(&path, product).unwrap(),
            };
            let text = std::fs::read_to_string(&file).unwrap();
            caches.push(RustCache {
                id: id.into(),
                function: function.into(),
                product: product.map(Into::into),
                cache: cache.into(),
                file: file.file_name().unwrap().to_string_lossy().into_owned(),
                now,
                text,
            });
        }
        RustCaches {
            note: "written by the Rust code (upstream::tests::rust_written_caches_are_committed); \
                   SOFTWARE_LIVE_BLESS=1 cargo test -p software-live rust_written rewrites it"
                .into(),
            caches,
        }
    }

    #[test]
    fn rust_written_caches_are_committed() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/rust-caches.json");
        let actual = rust_written_caches();
        if std::env::var_os("SOFTWARE_LIVE_BLESS").is_some() {
            let text = serde_json::to_string_pretty(&actual).unwrap() + "\n";
            std::fs::write(&path, text).unwrap();
        }
        let committed: RustCaches =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            committed, actual,
            "the Rust cache format changed: rerun with SOFTWARE_LIVE_BLESS=1 and run \
             `just test-software-live-rust-fixtures`"
        );
        for cache in &committed.caches {
            assert!(
                cache.text.is_ascii() && cache.text.ends_with("}\n"),
                "{}",
                cache.id
            );
            assert!(
                !cache.text.contains(": ") && !cache.text.contains(", "),
                "{}",
                cache.id
            );
        }
    }

    #[test]
    fn rust_reads_what_it_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("upstream.json");
        let host = LocalHost {
            fake: Some(FakeSystem::new(World::default())),
            server: None,
        };
        let fake = host.fake.as_ref().unwrap();
        fake.push_http(&[spec(UPSTREAM_URL, true, r#"{"tag_name": "v3.7.12"}"#)]);
        let first = upstream(&host, Some(&cache), 1000.5);
        let second = upstream(&host, Some(&cache), 1000.5 + 86399.0);
        assert_eq!(
            (first["cached"].clone(), second["cached"].clone()),
            (false.into(), true.into())
        );
        assert!(json_eq(
            &first["checked_at_epoch"],
            &second["checked_at_epoch"]
        ));
        // Expired and the refresh fails: the cache is evidence and stays as it was.
        let before = std::fs::read(&cache).unwrap();
        fake.push_http(&[serde_json::from_value(serde_json::json!({
            "url": UPSTREAM_URL,
            "headers": {"user-agent": USER_AGENT, "accept": GITHUB_ACCEPT},
            "timeout": 10.0, "error": "URLError"}))
        .unwrap()]);
        let third = upstream(&host, Some(&cache), 1000.5 + 86400.0);
        assert_eq!(third["status"], "unknown");
        assert_eq!(third["last_success"]["version"], "3.7.12");
        assert_eq!(std::fs::read(&cache).unwrap(), before);
        assert_eq!(fake.pending_http(), 0);
    }

    #[test]
    fn lookups_over_https_with_a_local_server() {
        let releases = br#"{"tag_name": "v3.7.12", "draft": false, "prerelease": false}"#;
        let cycles = br#"[{"cycle": "24.04", "eol": "2029-05-31", "support": "2029-05-31"}]"#;
        let server = TestServer::start(vec![
            Reply::ok(releases),
            Reply::ok(cycles),
            Reply::status(503),
        ]);
        let host = LocalHost {
            fake: None,
            server: Some((HttpClient::with_roots(vec![server.root()]), server.url(""))),
        };
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("upstream.json");
        let now = 1_760_000_000.5;

        let release = upstream(&host, Some(&cache), now);
        assert_eq!(release["status"], "ok", "{release}");
        assert_eq!(
            (release["version"].clone(), release["cached"].clone()),
            ("3.7.12".into(), false.into())
        );
        let cached = upstream(&host, Some(&cache), now + 10.0);
        assert_eq!(cached["cached"], true);

        let lifecycle = lifecycle_upstream(&host, "ubuntu", Some(&cache), now).unwrap();
        assert_eq!(lifecycle["status"], "ok", "{lifecycle}");
        let file = dir.path().join("upstream-ubuntu.json");
        let written = std::fs::read_to_string(&file).unwrap();
        assert!(
            written.starts_with(r#"{"checked_at_epoch":1760000000.5,"cycles":[{"cycle":"24.04""#),
            "{written}"
        );
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o640);
        }

        // A failing refresh after the day: the old cache is evidence only.
        let failed = upstream(&host, Some(&cache), now + 86400.0);
        assert_eq!(failed["status"], "unknown");
        assert_eq!(failed["error"], "HTTPError");
        assert_eq!(failed["last_success"]["version"], "3.7.12");

        let seen = server.requests();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(seen[0].starts_with("GET /repos/traefik/traefik/releases/latest HTTP/1.1\r\n"));
        assert!(seen[1].starts_with("GET /api/ubuntu.json HTTP/1.1\r\n"));
        let lower = seen[1].to_ascii_lowercase();
        assert!(
            lower.contains("user-agent: ops-library-software-live/1\r\n"),
            "{lower}"
        );
        assert!(!lower.contains("application/vnd.github+json"), "{lower}");
    }
}
