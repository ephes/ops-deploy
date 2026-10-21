//! `htpasswd -vi <file> <user>` with the password on stdin, in process
//! (PLAN.md 4.2 item 1): the Python endpoint runs that command for every
//! authenticated request (`software_live.py:732-739`); the Rust endpoint
//! verifies the same way without a child process.
//!
//! The rules are Apache 2.4's `support/htpasswd.c` and `passwd_common.c`
//! with APR-util's `apr_password_validate`, pinned by `fixtures/htpasswd.json`,
//! which `fixtures/htpasswd.py` records with the real `htpasswd` of the
//! hosts' distributions (Debian 13 and Ubuntu 24.04 containers):
//!
//! - **user** (argv): at most 255 bytes, no `:`, no NUL (argv cannot carry
//!   one; Python's `subprocess` raises).
//! - **password** (stdin, `get_password`): 256 bytes or more are "password
//!   too long"; one trailing `\n` is removed, and then a `\r` before it; the
//!   rest is a C string, so it ends at the first NUL.
//! - **file**: read in pieces of at most 255 bytes, each ending after a
//!   `\n` (`apr_file_gets` into a 256-byte buffer, so a longer line is read
//!   as several pieces); each piece is a C string. Leading C whitespace is
//!   skipped; empty pieces and `#` comments are ignored; a piece without
//!   `:` makes the whole check fail (`ERR_INVALID`), wherever it is. The
//!   user is the text before the first `:`, the hash the text after it up
//!   to the first `\r` or `\n`; an empty hash of the user fails.
//! - **every** piece of the user must verify (the first mismatch ends the
//!   check), and there must be at least one.
//! - **hash**: bcrypt only. `$2y$` and `$2a$` are APR's own crypt_blowfish,
//!   `$2b$` goes to the C library's `crypt_r` (libxcrypt on both
//!   distributions); the computed string must equal the stored one byte for
//!   byte (`strcmp`), so a non-canonical salt or hash character, a cost
//!   outside 4–31 or trailing text never verifies. Key: the password up to
//!   72 bytes. Not ported (PLAN.md 4.2 item 1): the other formats APR knows
//!   (`$apr1$` MD5, `{SHA}`, `crypt`), `$2x$`, a `$2a$` entry with a
//!   non-ASCII password (APR's `$2a$` safety measure can give another hash
//!   than the correct algorithm), and a cost above [`MAX_COST`] (the Python
//!   endpoint gives `htpasswd` 5 seconds; a cost of 17 takes longer than
//!   that on the hosts) — all of them are refused.

use std::time::Instant;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

/// `MAX_STRING_LEN - 1`: the longest user and password `htpasswd` takes.
pub const MAX_ARGUMENT_BYTES: usize = 255;
/// `apr_file_gets(line, MAX_STRING_LEN, …)`: one piece of a line.
const PIECE_BYTES: usize = 255;
/// The highest bcrypt cost verified (see the module documentation).
pub const MAX_COST: u32 = 16;

/// bcrypt's base64 (`./A-Za-z0-9`, no padding). Trailing bits are allowed
/// when decoding the salt, as crypt_blowfish's `BF_decode` ignores them; its
/// output re-encodes the salt canonically, so the string comparison refuses
/// a stored non-canonical salt.
const BCRYPT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::BCRYPT,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// The key `htpasswd -i` reads from stdin, `None` when it refuses the input.
pub fn stdin_password(input: &[u8]) -> Option<&[u8]> {
    if input.len() > MAX_ARGUMENT_BYTES {
        return None;
    }
    let mut password = input;
    if let Some(rest) = password.strip_suffix(b"\n") {
        password = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    Some(c_string(password))
}

/// The bytes before the first NUL.
fn c_string(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// `apr_isspace` in the C locale.
fn is_c_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The pieces `apr_file_gets` returns for a file of this content.
fn pieces(contents: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = contents;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let limit = rest.len().min(PIECE_BYTES);
        let end = rest[..limit]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(limit, |newline| newline + 1);
        let (piece, tail) = rest.split_at(end);
        rest = tail;
        Some(piece)
    })
}

/// Whether `htpasswd -vi` exits 0 for this file content, user and stdin.
/// An entry reached after `deadline` fails the check, as the Python
/// endpoint's `htpasswd` is killed after 5 seconds; a cost of at most
/// [`MAX_COST`] keeps the one hash under way when it passes short.
pub fn verify(contents: &[u8], user: &[u8], input: &[u8], deadline: Instant) -> bool {
    if user.len() > MAX_ARGUMENT_BYTES || user.contains(&b':') || user.contains(&0) {
        return false;
    }
    // `get_password` runs once, at the first entry of the user.
    let mut key: Option<Option<&[u8]>> = None;
    let mut found = false;
    for piece in pieces(contents) {
        let line = c_string(piece);
        let start = line
            .iter()
            .position(|&byte| !is_c_space(byte))
            .unwrap_or(line.len());
        let line = &line[start..];
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            return false;
        };
        if &line[..colon] != user {
            continue;
        }
        found = true;
        let rest = &line[colon + 1..];
        let hash_end = rest
            .iter()
            .position(|&byte| matches!(byte, b'\r' | b'\n'))
            .unwrap_or(rest.len());
        let hash = &rest[..hash_end];
        if hash.is_empty() {
            return false;
        }
        let Some(password) = *key.get_or_insert_with(|| stdin_password(input)) else {
            return false;
        };
        if Instant::now() >= deadline || !bcrypt_matches(password, hash) {
            return false;
        }
    }
    found
}

/// `apr_password_validate(password, hash) == APR_SUCCESS` for the bcrypt
/// entries this port verifies.
pub fn bcrypt_matches(password: &[u8], hash: &[u8]) -> bool {
    let version = match hash.get(..4) {
        Some(b"$2y$") => bcrypt::Version::TwoY,
        Some(b"$2b$") => bcrypt::Version::TwoB,
        Some(b"$2a$") if password.is_ascii() => bcrypt::Version::TwoA,
        _ => return false,
    };
    // `$2?$NN$` and the 22 salt characters; the rest is only compared.
    let (Some(cost), Some(b'$'), Some(salt)) = (hash.get(4..6), hash.get(6), hash.get(7..29))
    else {
        return false;
    };
    if !cost.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let cost = u32::from(cost[0] - b'0') * 10 + u32::from(cost[1] - b'0');
    if cost > MAX_COST {
        return false;
    }
    let mut salt_bytes = [0u8; 16];
    match BCRYPT_BASE64.decode_slice(salt, &mut salt_bytes) {
        Ok(16) => {}
        _ => return false,
    }
    let Ok(parts) = bcrypt::hash_with_salt(password, cost, salt_bytes) else {
        return false;
    };
    let computed = parts.format_for_version(version);
    constant_time_eq(computed.as_bytes(), hash)
}

/// Byte equality without an early exit (APR's `streq_timingsafe`).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct Fixtures {
        files: BTreeMap<String, String>,
        cases: Vec<Case>,
        images: BTreeMap<String, BTreeMap<String, String>>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        file: String,
        user_hex: String,
        password_hex: String,
        /// `htpasswd -vi` exited 0 (in every image).
        apache: bool,
        /// What this port answers; differs from `apache` only for `p3`.
        rust: bool,
        #[serde(default)]
        p3: Option<String>,
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    fn fixtures() -> Fixtures {
        serde_json::from_str(include_str!("../fixtures/htpasswd.json")).unwrap()
    }

    #[test]
    fn verification_matches_apache_htpasswd() {
        let fixtures = fixtures();
        assert!(fixtures.images.len() >= 2, "both distributions recorded");
        assert!(fixtures.cases.len() >= 80);
        let mut p3 = 0;
        for case in &fixtures.cases {
            let contents = match case.file.as_str() {
                "missing" => None,
                name => Some(fixtures.files[name].as_bytes()),
            };
            let user = decode_hex(&case.user_hex);
            let password = decode_hex(&case.password_hex);
            let answer = contents.is_some_and(|contents| verify(contents, &user, &password, far()));
            assert_eq!(answer, case.rust, "{}", case.id);
            match &case.p3 {
                Some(_) => {
                    p3 += 1;
                    assert_ne!(case.apache, case.rust, "{}: a p3 case differs", case.id);
                }
                None => assert_eq!(case.apache, case.rust, "{}", case.id),
            }
        }
        assert!(p3 >= 4, "the refused formats are recorded");
    }

    fn far() -> Instant {
        Instant::now() + std::time::Duration::from_secs(3600)
    }

    #[test]
    fn the_deadline_ends_the_check() {
        let hash = bcrypt::hash_with_salt("pw", 4, [1; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoY);
        let file = format!("u:{hash}\n");
        assert!(verify(file.as_bytes(), b"u", b"pw", far()));
        assert!(!verify(file.as_bytes(), b"u", b"pw", Instant::now()));
        // Many entries of the user: the check stops at the deadline.
        let slow = bcrypt::hash_with_salt("pw", 10, [1; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoY);
        let many = format!("u:{slow}\n").repeat(200);
        let started = Instant::now();
        let deadline = started + std::time::Duration::from_millis(300);
        assert!(!verify(many.as_bytes(), b"u", b"pw", deadline));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn stdin_rules() {
        assert_eq!(stdin_password(b"pw\n"), Some(&b"pw"[..]));
        assert_eq!(stdin_password(b"pw\r\n"), Some(&b"pw"[..]));
        assert_eq!(stdin_password(b"pw\n\n"), Some(&b"pw\n"[..]));
        assert_eq!(stdin_password(b"pw\r"), Some(&b"pw\r"[..]));
        assert_eq!(stdin_password(b"pw\r\r\n"), Some(&b"pw\r"[..]));
        assert_eq!(stdin_password(b"pw\0x"), Some(&b"pw"[..]));
        assert_eq!(stdin_password(b""), Some(&b""[..]));
        assert!(stdin_password(&[b'a'; 255]).is_some());
        assert!(stdin_password(&[b'a'; 256]).is_none());
    }

    #[test]
    fn files_are_read_in_pieces_of_255_bytes() {
        let text = [vec![b'x'; 300], b"\nab\n".to_vec()].concat();
        let read: Vec<&[u8]> = pieces(&text).collect();
        assert_eq!(read.len(), 3);
        assert_eq!(read[0].len(), 255);
        assert_eq!(read[1], [vec![b'x'; 45], b"\n".to_vec()].concat());
        assert_eq!(read[2], b"ab\n");
        let exact = [vec![b'y'; 254], b"\n".to_vec()].concat();
        assert_eq!(pieces(&exact).count(), 1);
        assert_eq!(pieces(b"no newline").collect::<Vec<_>>(), [b"no newline"]);
    }

    #[test]
    fn costs_above_the_cap_are_refused_without_hashing() {
        // A cost-31 entry would take hours; it is refused at once.
        let hash = b"$2y$31$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyzABCDE";
        let started = std::time::Instant::now();
        assert!(!bcrypt_matches(b"x", hash));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
