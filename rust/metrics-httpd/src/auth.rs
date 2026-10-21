//! Basic authentication against an htpasswd file (PLAN.md 4.1.3, D-6).
//!
//! Python (`backup_metrics_httpd.py.j2` l.122–138):
//!
//! ```python
//! if not header or not header.startswith("Basic "): deny
//! decoded = base64.b64decode(header.split()[1]).decode("utf-8")   # any error: deny
//! user, password = decoded.split(":", 1)
//! subprocess.run(["htpasswd", "-vi", htpasswd_file, user], input=password)  # exit 0: allow
//! ```
//!
//! (`metrics_httpd.py.j2` runs `htpasswd -vb <file> <user> <password>`
//! instead.) The Rust side verifies in process (D-6) with the rules of
//! `htpasswd` (Apache 2.4 `htpasswd.c` and APR, pinned by
//! `fixtures/auth.json`, generated with the real binary):
//!
//! - the password is what `-i` reads from stdin ([`PasswordSource::Stdin`]):
//!   at most 255 bytes (more: "password too long"), one trailing `\n` or
//!   `\r\n` removed, cut at the first NUL; with `-b`
//!   ([`PasswordSource::Argv`], the script mode) at most 255 bytes, taken
//!   verbatim, and a NUL is refused (Python's `subprocess` raises, D-2);
//! - the file is read line by line; leading whitespace is skipped, empty
//!   lines and `#` comments are ignored, a line without `:` makes the whole
//!   file invalid; the user is the text before the first `:`, the hash runs
//!   to the first `\r`/`\n`; an empty hash is invalid;
//! - **every** line of the user must verify (the first failure ends the
//!   check), and at least one must exist;
//! - only the bcrypt hashes APR verifies, `$2y$` and `$2a$` (D-6; APR
//!   refuses `$2b$`), with bcrypt's 72-byte key limit; a `$2a$` hash with a
//!   non-ASCII key is refused, because APR's `$2a$` safety measure may give
//!   a different result than the `bcrypt` crate.
//!
//! Base64 is decoded strictly (D-6): the standard alphabet with canonical
//! padding (Python's `binascii.a2b_base64(…, strict_mode=True)`); Python's
//! default decoder silently drops other characters. The file is read on
//! every request, so a rotated password takes effect without a restart.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

/// `htpasswd` refuses a password of 256 bytes or more.
pub const MAX_PASSWORD_BYTES: usize = 255;

/// Hash prefixes the endpoint accepts (D-6).
pub const BCRYPT_PREFIXES: [&str; 2] = ["$2y$", "$2a$"];

/// How the Python variant hands the password to `htpasswd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSource {
    /// `htpasswd -vi`, password on stdin (every variant but the script mode).
    Stdin,
    /// `htpasswd -vb`, password in argv (`metrics_endpoint`).
    Argv,
}

const STRICT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Credentials from an `Authorization` header.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// `str.isspace()` for a character of a latin-1 decoded header (Python
/// decodes header bytes as ISO-8859-1 and `str.split()` splits on these).
fn is_py_space(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | 0x1c..=0x20 | 0x85 | 0xa0)
}

/// The base64 token of a header: `header.split()[1]` after the
/// `startswith("Basic ")` check.
pub fn basic_token(header: &[u8]) -> Option<&[u8]> {
    if !header.starts_with(b"Basic ") {
        return None;
    }
    header
        .split(|&byte| is_py_space(byte))
        .filter(|field| !field.is_empty())
        .nth(1)
}

/// Strict base64 (D-6): the standard alphabet, canonical padding, trailing
/// bits allowed (as `binascii.a2b_base64(…, strict_mode=True)`).
pub fn decode_base64(token: &[u8]) -> Option<Vec<u8>> {
    STRICT_BASE64.decode(token).ok()
}

/// Python's parsing of the header: `startswith("Basic ")`, the second
/// whitespace-separated field, base64 (strict, D-6), UTF-8, split at the
/// first `:`. `None` is a denial.
pub fn parse_basic(header: Option<&[u8]>) -> Option<Credentials> {
    let decoded = decode_base64(basic_token(header?)?)?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some(Credentials {
        user: user.to_owned(),
        password: password.to_owned(),
    })
}

/// The key `htpasswd` hands to the hash check, `None` when it refuses the
/// password (too long; a NUL in argv).
pub fn htpasswd_password(password: &[u8], source: PasswordSource) -> Option<&[u8]> {
    if password.len() > MAX_PASSWORD_BYTES {
        return None;
    }
    if source == PasswordSource::Argv {
        return (!password.contains(&0)).then_some(password);
    }
    let password = password
        .strip_suffix(b"\r\n")
        .or_else(|| password.strip_suffix(b"\n"))
        .unwrap_or(password);
    let end = password
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(password.len());
    Some(&password[..end])
}

/// One entry of an htpasswd file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    pub user: &'a [u8],
    pub hash: &'a [u8],
}

/// Why `htpasswd` would refuse the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileProblem {
    /// A line that is neither empty, a comment nor `user:hash`.
    NoColon { line: usize },
    /// `user:` with nothing after the colon.
    EmptyHash { line: usize },
}

impl std::fmt::Display for FileProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoColon { line } => write!(f, "line {line} is not user:hash"),
            Self::EmptyHash { line } => write!(f, "line {line} has an empty hash"),
        }
    }
}

/// The entries of an htpasswd file, as `htpasswd` reads it.
pub fn parse_file(contents: &[u8]) -> Result<Vec<Entry<'_>>, FileProblem> {
    let mut entries = Vec::new();
    for (index, line) in contents.split(|&byte| byte == b'\n').enumerate() {
        let start = line
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | 0x0b | 0x0c))
            .unwrap_or(line.len());
        let line_text = &line[start..];
        if line_text.is_empty() || line_text[0] == b'#' {
            continue;
        }
        let colon = line_text
            .iter()
            .position(|&byte| byte == b':')
            .ok_or(FileProblem::NoColon { line: index + 1 })?;
        let rest = &line_text[colon + 1..];
        let hash_end = rest
            .iter()
            .position(|&byte| byte == b'\r')
            .unwrap_or(rest.len());
        let hash = &rest[..hash_end];
        if hash.is_empty() {
            return Err(FileProblem::EmptyHash { line: index + 1 });
        }
        entries.push(Entry {
            user: &line_text[..colon],
            hash,
        });
    }
    Ok(entries)
}

/// Whether `hash` is a bcrypt hash the endpoint accepts (D-6).
pub fn is_supported_hash(hash: &[u8]) -> bool {
    let Ok(hash) = std::str::from_utf8(hash) else {
        return false;
    };
    BCRYPT_PREFIXES
        .iter()
        .any(|prefix| hash.starts_with(prefix))
        && hash.parse::<bcrypt::HashParts>().is_ok()
}

fn verify_entry(key: &[u8], hash: &[u8]) -> bool {
    if !is_supported_hash(hash) || (hash.starts_with(b"$2a$") && !key.is_ascii()) {
        return false;
    }
    std::str::from_utf8(hash).is_ok_and(|hash| bcrypt::verify(key, hash).unwrap_or(false))
}

/// `htpasswd -vi <file> <user>` (password on stdin) or `htpasswd -vb <file>
/// <user> <password>`: true iff it would exit 0.
pub fn verify(contents: &[u8], credentials: &Credentials, source: PasswordSource) -> bool {
    let Some(key) = htpasswd_password(credentials.password.as_bytes(), source) else {
        return false;
    };
    let Ok(entries) = parse_file(contents) else {
        return false;
    };
    let mut found = false;
    for entry in entries
        .iter()
        .filter(|entry| entry.user == credentials.user.as_bytes())
    {
        found = true;
        if !verify_entry(key, entry.hash) {
            return false;
        }
    }
    found
}

/// Checks the request's `Authorization` header against the htpasswd file,
/// reading the file and running bcrypt on the blocking pool. Any failure
/// (missing or malformed header, unreadable file, unknown user, wrong
/// password) is a denial.
pub async fn authorize(header: Option<&[u8]>, htpasswd: &Path, source: PasswordSource) -> bool {
    let Some(credentials) = parse_basic(header) else {
        return false;
    };
    let path: PathBuf = htpasswd.to_owned();
    tokio::task::spawn_blocking(move || {
        std::fs::read(&path).is_ok_and(|contents| verify(&contents, &credentials, source))
    })
    .await
    .unwrap_or(false)
}

/// `--check-config`: the htpasswd file is readable, valid and holds only
/// supported bcrypt entries. Returns the number of entries; the error text
/// never contains a hash.
pub fn check_file(path: &Path) -> Result<usize, String> {
    let contents =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let entries =
        parse_file(&contents).map_err(|problem| format!("{}: {problem}", path.display()))?;
    if entries.is_empty() {
        return Err(format!("{}: no user:hash entry", path.display()));
    }
    for entry in &entries {
        if !is_supported_hash(entry.hash) {
            return Err(format!(
                "{}: the entry of user {:?} is not a bcrypt $2y$/$2a$ hash",
                path.display(),
                String::from_utf8_lossy(entry.user)
            ));
        }
    }
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `htpasswd -nbB -C 4 user secret` (test-only).
    const HASH: &str = "$2y$04$MVw8YOy2swoaijvfegCiiO74DpkrRCnmLv88u9kUtIZJX6EfLNsW2";

    fn header(user_password: &str) -> Vec<u8> {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(user_password)
        )
        .into_bytes()
    }

    #[test]
    fn header_parsing_follows_python() {
        let parsed = parse_basic(Some(&header("u:p:w"))).unwrap();
        assert_eq!(
            (parsed.user.as_str(), parsed.password.as_str()),
            ("u", "p:w")
        );
        assert!(parse_basic(None).is_none());
        assert!(parse_basic(Some(b"basic dTpw")).is_none());
        assert!(parse_basic(Some(b"Basic")).is_none());
        assert!(parse_basic(Some(b"Basic ")).is_none());
        assert!(parse_basic(Some(b"Basic dXNlcg==")).is_none(), "no colon");
        assert!(
            parse_basic(Some(b"Basic dTpw\xa0x")).is_some(),
            "NBSP splits"
        );
        assert!(parse_basic(Some(b"Basic  dTpw extra")).is_some());
        assert!(
            parse_basic(Some(b"Basic dTpw=")).is_none(),
            "non-canonical padding"
        );
        assert!(
            parse_basic(Some(b"Basic dTp-")).is_none(),
            "URL-safe alphabet"
        );
        assert!(parse_basic(Some(b"Basic //79")).is_none(), "not UTF-8");
        // Non-zero trailing bits are accepted, as by Python.
        assert!(parse_basic(Some(b"Basic dTpx")).is_some());
        assert!(format!("{parsed:?}").contains("<redacted>"));
    }

    #[test]
    fn password_rules() {
        let stdin = |pw: &[u8]| htpasswd_password(pw, PasswordSource::Stdin).map(<[u8]>::to_vec);
        assert_eq!(stdin(b"pw\n"), Some(b"pw".to_vec()));
        assert_eq!(stdin(b"pw\r\n"), Some(b"pw".to_vec()));
        assert_eq!(stdin(b"pw\n\n"), Some(b"pw\n".to_vec()));
        assert_eq!(stdin(b"pw\r"), Some(b"pw\r".to_vec()));
        assert_eq!(stdin(b"pw\0zz"), Some(b"pw".to_vec()));
        assert!(stdin(&[b'a'; 255]).is_some());
        assert!(stdin(&[b'a'; 256]).is_none());
        let argv = |pw: &[u8]| htpasswd_password(pw, PasswordSource::Argv).map(<[u8]>::to_vec);
        assert_eq!(argv(b"pw\n"), Some(b"pw\n".to_vec()));
        assert_eq!(argv(b"pw\0zz"), None);
        assert!(argv(&[b'a'; 255]).is_some());
        assert!(argv(&[b'a'; 256]).is_none());
    }

    #[test]
    fn file_parsing_follows_htpasswd() {
        let file = b"# comment\n\n   \n \tu:$2y$x\r\nv:h2\nw:h3";
        let entries = parse_file(file).unwrap();
        let users: Vec<_> = entries
            .iter()
            .map(|entry| (entry.user, entry.hash))
            .collect();
        assert_eq!(
            users,
            [(&b"u"[..], &b"$2y$x"[..]), (b"v", b"h2"), (b"w", b"h3")]
        );
        assert_eq!(
            parse_file(b"u:h\njunk\n"),
            Err(FileProblem::NoColon { line: 2 })
        );
        assert_eq!(parse_file(b"u:\n"), Err(FileProblem::EmptyHash { line: 1 }));
        assert_eq!(
            parse_file(b"u:\r\n"),
            Err(FileProblem::EmptyHash { line: 1 })
        );
    }

    #[test]
    fn hash_support() {
        let mut hash = HASH.to_owned();
        assert!(is_supported_hash(hash.as_bytes()));
        hash.replace_range(..4, "$2a$");
        assert!(is_supported_hash(hash.as_bytes()));
        for prefix in ["$2b$", "$2x$"] {
            hash.replace_range(..4, prefix);
            assert!(!is_supported_hash(hash.as_bytes()), "{prefix}");
        }
        assert!(!is_supported_hash(b"$apr1$abcdefgh$0123456789abcdefghijkl"));
        assert!(!is_supported_hash(b"{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="));
        assert!(!is_supported_hash(&HASH.as_bytes()[..59]));
    }

    #[test]
    fn verify_follows_htpasswd() {
        let ok = |file: &str, password: &str| {
            verify(
                file.as_bytes(),
                &Credentials {
                    user: "user".to_owned(),
                    password: password.to_owned(),
                },
                PasswordSource::Stdin,
            )
        };
        let line = format!("user:{HASH}\n");
        assert!(ok(&line, "secret"));
        assert!(ok(&line, "secret\r\n"));
        assert!(ok(&line, "secret\0ignored"));
        assert!(!ok(&line, "Secret"));
        assert!(!ok(&line, "secret\r"));
        assert!(!ok("other:x\n", "secret"), "unknown user");
        assert!(
            !ok(&format!("{line}user:{HASH}x\n"), "secret"),
            "every entry must verify"
        );
        assert!(!ok(&format!("{line}junk\n"), "secret"), "invalid file");
        let md5 = "user:$apr1$saltsalt$abcdefghijklmnopqrstuv\n";
        assert!(!ok(md5, "secret"), "D-6: only bcrypt");
    }
}
