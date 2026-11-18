//! The package cache through rust-apt, as `apt.Cache(memonly=True)` and
//! `apt-mark showhold` give it to `software_live.py` (software-live PLAN.md
//! 5.2, mapping in 13.4).
//!
//! - `Dir::Cache::pkgcache ""` as python-apt's `memonly=True`; when the
//!   directory of `srcpkgcache.bin` is writable for this process (an
//!   unsandboxed root run), also `Dir::Cache::srcpkgcache ""`, so libapt-pkg
//!   never writes under `/var/cache/apt`. Inside the collector unit the
//!   directory is read-only and the warm `srcpkgcache.bin` is read.
//! - Holds come from the dpkg selection state of this cache (every package
//!   whose selection is `hold`, printed as `fullname(true)`, what `apt-mark
//!   showhold` prints) instead of an `apt-mark` child.
//! - No APT lock is taken; no volatile files are added (see
//!   `PackageFile::index_file`, 13.4).

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;

use rust_apt::config::Config;
use rust_apt::{Cache, PackageSort, PkgSelectedState};

use crate::observe;

/// The index type of the dpkg status file (`/var/lib/dpkg/status`).
const STATUS_INDEX_TYPE: &str = "Debian dpkg status file";

/// Configure libapt-pkg as described above and open the cache.
pub fn open() -> Result<Cache, rust_apt::error::AptErrors> {
    let config = Config::new();
    config.set("Dir::Cache::pkgcache", "");
    // libapt-pkg writes `srcpkgcache.bin` only when its directory passes
    // `access(W_OK)` (pkgcachegen.cc); the same probe here turns the file
    // off in exactly that case.
    let srcpkgcache = config.file("Dir::Cache::srcpkgcache", "");
    if !srcpkgcache.is_empty() {
        let directory = Path::new(&srcpkgcache)
            .parent()
            .unwrap_or_else(|| Path::new("/"));
        if rustix::fs::access(directory, rustix::fs::Access::WRITE_OK).is_ok() {
            config.set("Dir::Cache::srcpkgcache", "");
        }
    }
    Cache::new::<&str>(&[])
}

/// `apt_pkg.version_compare(a, b)`, after [`open`] has initialised
/// libapt-pkg's configuration and system.
///
/// libapt-pkg's `debVersioningSystem::CmpFragment` reads C strings: it
/// skips leading zeros and walks digit runs without checking the end
/// pointer, so it stops only at a byte that is not a digit. python-apt
/// passes CPython's NUL-terminated buffers. rust-apt passes the bytes of a
/// Rust `&str`, which are followed by whatever lies after them in memory: a
/// version ending in a digit then compares against garbage (seen in the
/// container comparison: `compare(x, x)` was not `Equal` for an owned
/// `String`). Each side is therefore copied into a buffer with a NUL right
/// after the slice that is passed. `rust_apt::raw::cmp_versions` is used
/// because `rust_apt::util::cmp_versions` re-runs `pkgInitSystem` on every
/// call, which re-initialises the dpkg system object under the open cache.
pub fn compare(a: &str, b: &str) -> Ordering {
    let a = format!("{a}\0");
    let b = format!("{b}\0");
    rust_apt::raw::cmp_versions(&a[..a.len() - 1], &b[..b.len() - 1]).cmp(&0)
}

/// `set(command(["apt-mark", "showhold"]).splitlines())`.
pub fn holds(cache: &Cache) -> BTreeSet<String> {
    cache
        .packages(&PackageSort::default().include_virtual())
        .filter(|package| package.selected_state() == PkgSelectedState::Hold)
        .map(|package| package.fullname(true))
        .collect()
}

/// `for package in cache` (only installed packages matter).
pub fn installed_packages(cache: &Cache) -> impl Iterator<Item = Package<'_>> {
    cache
        .packages(&PackageSort::default().installed())
        .map(Package)
}

pub struct Package<'a>(rust_apt::Package<'a>);
pub struct Version<'a>(rust_apt::Version<'a>);
pub struct Origin<'a>(rust_apt::PackageFile<'a>);

impl<'a> observe::Package for Package<'a> {
    type Version = Version<'a>;

    fn fullname(&self) -> String {
        self.0.fullname(false)
    }

    fn name(&self) -> String {
        self.0.fullname(true)
    }

    fn installed(&self) -> Option<Version<'a>> {
        self.0.installed().map(Version)
    }

    fn versions(&self) -> Vec<Version<'a>> {
        self.0.versions().map(Version).collect()
    }

    fn candidate(&self) -> Option<Version<'a>> {
        self.0.candidate().map(Version)
    }
}

impl<'a> observe::Version for Version<'a> {
    type Origin = Origin<'a>;

    fn version(&self) -> &str {
        self.0.version()
    }

    fn origins(&self) -> Vec<Origin<'a>> {
        self.0.package_files().map(Origin).collect()
    }
}

impl observe::Origin for Origin<'_> {
    fn origin(&self) -> &str {
        self.0.origin().unwrap_or("")
    }

    fn archive(&self) -> &str {
        self.0.archive().unwrap_or("")
    }

    fn label(&self) -> &str {
        self.0.label().unwrap_or("")
    }

    /// python-apt looks the index up in the source list only and reports
    /// the dpkg status file as untrusted; rust-apt would find the status
    /// index too. The status file is therefore untrusted here as well
    /// (PLAN.md 5.2, 13.3 item 1).
    fn trusted(&self) -> bool {
        self.0.index_type() != Some(STATUS_INDEX_TYPE) && self.0.index_file().is_trusted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// libapt-pkg's configuration and system are process globals and not
    /// thread-safe: the tests that use them run one at a time, with the
    /// configuration initialised as `open()` does it (the helper itself is
    /// single-threaded).
    fn apt_lock() -> MutexGuard<'static, ()> {
        static APT: Mutex<()> = Mutex::new(());
        let guard = APT.lock().unwrap_or_else(PoisonError::into_inner);
        Config::new();
        guard
    }

    #[test]
    fn compare_never_reads_past_the_slice() {
        let _apt = apt_lock();
        // Each version is a slice of a longer string that continues with
        // digits: an unterminated buffer would compare those too.
        let buffer = "1.0999 2:1.10777 1.9 1.10a 0.21.2-1.1build1 255.4-1ubuntu8.17999";
        let mut versions: Vec<&str> = buffer.split(' ').collect();
        versions[0] = &buffer[..3]; // "1.0", followed by "999"
        versions[1] = &buffer[7..13]; // "2:1.10", followed by "777"
        versions[5] = &versions[5][..17]; // "255.4-1ubuntu8.17", followed by "999"
        for version in &versions {
            assert_eq!(compare(version, version), Ordering::Equal, "{version}");
        }
        assert_eq!(compare(versions[0], "1.0"), Ordering::Equal);
        assert_eq!(compare(versions[0], "1.00"), Ordering::Equal);
        assert_eq!(compare("1.10", "1.9"), Ordering::Greater);
        assert_eq!(compare("1.9", "1.10a"), Ordering::Less);
        assert_eq!(compare(versions[1], "1:9"), Ordering::Greater);
        assert_eq!(compare("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(compare("255.4-1ubuntu8.18", versions[5]), Ordering::Greater);
        assert_eq!(compare(versions[5], "255.4-1ubuntu8.18"), Ordering::Less);
    }

    /// `apt_pkg.version_compare` of python-apt (installed next to the
    /// helper in the variant images) for the given pairs.
    fn python_apt_signs(pairs: &[(&str, &str)]) -> Vec<i64> {
        let script = "import apt_pkg, json, sys\n\
                      apt_pkg.init()\n\
                      pairs = json.load(sys.stdin)\n\
                      print(json.dumps([(c > 0) - (c < 0) for c in \
                      (apt_pkg.version_compare(a, b) for a, b in pairs)]))";
        let mut child = Command::new("python3")
            .args(["-I", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 with python3-apt");
        let input = serde_json::to_vec(pairs).unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), &input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// The comparison of S1 (PLAN.md 13.2): hand-picked edge pairs and
    /// 20 000 pseudo-random pairs over every version string of the cache,
    /// as owned strings (not NUL-terminated), against python-apt.
    #[test]
    fn compare_matches_python_apt_on_the_cache() {
        let _apt = apt_lock();
        let cache = open().expect("the package cache opens");
        let versions: BTreeSet<String> = cache
            .packages(&PackageSort::default())
            .flat_map(|package| {
                package
                    .versions()
                    .map(|version| version.version().to_owned())
                    .collect::<Vec<_>>()
            })
            .collect();
        let versions: Vec<String> = versions.into_iter().collect();
        assert!(versions.len() > 1000, "{} versions", versions.len());
        let mut pairs: Vec<(&str, &str)> = vec![
            ("1.0", "1.0"),
            ("1.0", "1.00"),
            ("1.0~rc1", "1.0"),
            ("1.0+b1", "1.0"),
            ("1:1.0", "2.0"),
            ("0:1.0", "1.0"),
            ("1.0-1", "1.0-1ubuntu0.1"),
            ("2.39.3-9ubuntu6.6", "2.39.3-9ubuntu6.10"),
            ("10.42-4ubuntu2.1", "10.42-4ubuntu2"),
            ("1.9", "1.10"),
            ("a", "1"),
            ("1.0a", "1.0+"),
            ("1~~", "1~~a"),
            ("1~", "1"),
            ("", "0"),
        ];
        // xorshift64: deterministic pairs without a dependency.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % versions.len() as u64).unwrap()
        };
        for _ in 0..20_000 {
            let (a, b) = (next(), next());
            pairs.push((&versions[a], &versions[b]));
        }
        let expected = python_apt_signs(&pairs);
        for ((a, b), sign) in pairs.iter().zip(expected) {
            let ours = match compare(a, b) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            };
            assert_eq!(ours, sign, "compare({a:?}, {b:?})");
        }
    }
}
