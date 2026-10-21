#!/usr/bin/env python3
"""Generate the metrics-httpd fixtures from the Python endpoints (PLAN.md 8.2).

Python is the oracle: every expected value in ``fixtures/`` is what CPython or
one of the rendered Python endpoint scripts produces. The Rust tests
(``tests/fixtures.rs``) replay every case. Families:

``float_repr`` (stdlib)
    ``float_repr/part-*.txt``: ``repr()`` of seeded random finite ``f64``
    values (>= 100,000 uniform bit patterns plus fixed-point, short-decimal,
    subnormal and edge cases), one per line (PLAN.md D-5).
``pyjson`` (stdlib)
    ``pyjson.json``: ``json.dumps(json.loads(<input>), sort_keys=True)`` for
    the D-4/D-5 cases, Unicode, nesting and random documents, plus Python's
    truthiness, ``isinstance(v, int)``, ``int(v)`` and ``"stale_kernel" in v``.
``meta`` (stdlib)
    ``meta.json``: ``datetime.fromtimestamp(e, tz=timezone.utc).isoformat()``
    and ``int(os.stat(f).st_mtime)`` after ``os.utime(f, ns=...)``.
``auth`` (templates, ``htpasswd``)
    ``auth.json``: the decision of the rendered backup script's
    ``_check_auth`` (``htpasswd -vi``) and of ``metrics_endpoint``'s
    (``htpasswd -vb``) for header and htpasswd-file cases, run with the real
    ``htpasswd`` binary against the committed test-only ``htpasswd*`` files.
``http_common`` (templates, ``htpasswd``)
    ``http_common.json``: the rendered scripts' handlers served on loopback
    and driven with raw requests: the 501/404/401 gate of PLAN.md 4.1 for
    every mode the scripts share (S1); later slices extend the matrix.

Commands: ``write`` regenerates the files in place, ``check`` regenerates in
memory and fails on any difference (the drift test,
``tests/test_metrics_httpd_fixtures.py``). ``--stdlib-only`` limits both to
the stdlib families, which must give identical bytes under CPython 3.12
(production hosts) and 3.13 (staging); ``just metrics-httpd-fixtures`` runs
the venv for everything and 3.12/3.13 for the stdlib check.

The ``htpasswd*`` files are created once with ``htpasswd -nbB -C 4`` and
committed (random salts); this script only reads them. Their passwords are
in ``AUTH_USERS`` below; none is a real credential.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import http.client
import importlib.util
import io
import json
import math
import os
import random
import re
import shutil
import socket
import socketserver
import stat
import struct
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

FIXTURES = Path(__file__).resolve().parent
ROOT = FIXTURES.parents[2]
SEED = 20261021

# User -> password of the committed fixtures/htpasswd (test-only).
AUTH_USERS = {
    "user": "secret",
    "alice": "pässwörd",
    "alice2a": "pässwörd",  # alice's $2y$ hash with the prefix $2a$
    "bob": "bob-password",  # $2a$
    "carol": "carol-password",  # $2b$
    "long": "L" * 80,  # bcrypt uses the first 72 bytes
    "": "nobody",  # an entry with an empty user name
    "spaced": "spaced-password",  # line with leading whitespace
    "dup": "dup-password",  # two identical entries
}
# fixtures/htpasswd-mixed (D-6: only bcrypt verifies in Rust).
MIXED_USERS = {
    "user": "secret",
    "md5": "md5-password",
    "sha": "sha-password",
    "crypt": "cryptpw",
    "x2": "x2-password",  # $2x$
    "dupbad": "dupbad-password",  # second entry has another password
}

FLOAT_PART_LINES = 25_000
FLOAT_HEADER = "# repr() of seeded random finite floats (rust/metrics-httpd/fixtures/generate.py, PLAN.md D-5)\n"


# --------------------------------------------------------------------------
# helpers


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=1, ensure_ascii=True) + "\n"


def float_from_bits(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits))[0]


# --------------------------------------------------------------------------
# float_repr


def float_values() -> list[float]:
    rng = random.Random(SEED)
    values: list[float] = []
    # Uniform bit patterns (mostly exponent notation).
    while len(values) < 100_000:
        x = float_from_bits(rng.getrandbits(64))
        if math.isfinite(x):
            values.append(x)
    # Decimal exponents around the fixed-point range -4 <= e < 16.
    for _ in range(30_000):
        mantissa = rng.getrandbits(52)
        exponent = rng.randint(1023 - 17, 1023 + 56)
        values.append(
            float_from_bits((rng.getrandbits(1) << 63) | (exponent << 52) | mantissa)
        )
    # Short decimal literals (few significant digits).
    for _ in range(20_000):
        digits = rng.randint(1, 17)
        mantissa = rng.randint(1, 10**digits - 1)
        exponent = rng.randint(-25, 25)
        values.append(
            float(f"{'-' if rng.random() < 0.5 else ''}{mantissa}e{exponent}")
        )
    # Subnormals.
    for _ in range(2_000):
        values.append(
            float_from_bits((rng.getrandbits(1) << 63) | rng.randint(1, (1 << 52) - 1))
        )
    # Integers near 2**53 and powers of two and ten (asymmetric gaps).
    for k in range(-1074, 1024):
        values.append(math.ldexp(1.0, k))
    for k in range(-330, 309):
        x = float(f"1e{k}")
        if math.isfinite(x) and x != 0.0:
            values.append(x)
            values.append(math.nextafter(x, math.inf))
            values.append(math.nextafter(x, 0.0))
    for n in range(2**53 - 50, 2**53 + 50):
        values.append(float(n))
    values += [
        0.0,
        -0.0,
        5e-324,
        -5e-324,
        2.2250738585072014e-308,
        1.7976931348623157e308,
        100.0,
        1.0,
        1e16,
        9999999999999998.0,
        0.0001,
        0.00001,
        0.1,
        0.2,
        0.3,
        181703637716804.125,
        9007199254740993.0,
        1.5,
        2.5,
        123456.789,
    ]
    return values


def build_float_repr() -> dict[str, str]:
    lines = [repr(x) for x in float_values()]
    files = {}
    for index in range(0, len(lines), FLOAT_PART_LINES):
        name = f"float_repr/part-{index // FLOAT_PART_LINES:02d}.txt"
        files[name] = (
            FLOAT_HEADER + "\n".join(lines[index : index + FLOAT_PART_LINES]) + "\n"
        )
    return files


# --------------------------------------------------------------------------
# pyjson

D4 = "D-4"

# (id, JSON text, D tag when Rust refuses what Python accepts)
DUMPS_CASES: list[tuple[str, str, str | None]] = [
    ("d5-exponent-int", "1e2", None),
    ("d5-trailing-zeros", "1.00", None),
    ("d5-above-2-53", "9007199254740993.0", None),
    ("d5-1e16", "1e16", None),
    ("d5-0.0001", "0.0001", None),
    ("d5-0.00001", "0.00001", None),
    ("d5-negative-zero-float", "-0.0", None),
    ("d5-tie-even", "181703637716804.125", None),
    ("d5-negative-zero-int", "-0", None),
    ("d5-underflow", "1e-400", None),
    ("d5-negative-underflow", "-1e-400", None),
    ("d5-float-5.0", "5.0", None),
    ("d5-float-1e9", "1e9", None),
    (
        "d5-big-int",
        "123456789012345678901234567890123456789012345678901234567890",
        None,
    ),
    (
        "d5-big-negative-int",
        "-98765432109876543210987654321098765432109876543210",
        None,
    ),
    ("d5-int-4300-digits", "9" * 4300, None),
    ("d5-int-4301-digits", "9" * 4301, None),
    ("d5-negative-int-4300-digits", "-" + "1" * 4300, None),
    (
        "d5-many-float-digits",
        "0.1000000000000000055511151231257827021181583404541015625",
        None,
    ),
    ("d5-exponent-plus", "1E+2", None),
    ("d5-largest", "1.7976931348623157e308", None),
    ("d5-smallest", "5e-324", None),
    ("d4-nan", "NaN", D4),
    ("d4-infinity", "Infinity", D4),
    ("d4-negative-infinity", "-Infinity", D4),
    ("d4-overflow", "1e400", D4),
    ("d4-overflow-in-object", '{"a": [1, -1e309]}', D4),
    ("d4-lone-high-surrogate", '"\\ud800"', D4),
    ("d4-lone-low-surrogate", '"x\\udc00y"', D4),
    ("d4-reversed-surrogates", '"\\ude00\\ud83d"', D4),
    ("d4-depth-128", "[" * 128 + "]" * 128, D4),
    ("d4-depth-500", "[" * 500 + "]" * 500, D4),
    ("depth-127", "[" * 127 + "]" * 127, None),
    ("d4-serde-number-key", '{"a": {"$serde_json::private::Number": "2.5"}}', D4),
    ("d4-serde-number-key-escaped", '{"a": {"\\u0024serde_json::private::Number": "1"}}', D4),
    ("d4-serde-number-key-other-value", '{"$serde_json::private::Number": "x"}', D4),
    ("serde-number-token-as-value", '["$serde_json::private::Number", {"k": "$serde_json::private::Number"}]', None),
    ("d5-int-4301-digits-replaced-by-duplicate", '{"a": ' + "9" * 4301 + ', "a": 1}', None),
    ("float-overflow-replaced-by-duplicate", '{"a": 1e400, "a": 1}', None),
    ("long-digit-string", '{"' + "9" * 4400 + '": "' + "9" * 4400 + '"}', None),
    ("depth-127-objects", '{"a": ' * 127 + "1" + "}" * 127, None),
    (
        "sorted-nested",
        '{"b": {"z": 1, "a": [3, {"y": 0, "x": null}]}, "a": true, "B": false}',
        None,
    ),
    (
        "key-order-code-points",
        '{"\\u00e9": 1, "z": 2, "\\ud83d\\ude00": 3, "\\uffff": 4, "": 5, "Z": 6}',
        None,
    ),
    ("duplicate-keys-last-wins", '{"a": 1, "b": 2, "a": 3}', None),
    ("empty-containers", '{"a": {}, "b": [], "c": [{}, []]}', None),
    ("whitespace", ' \n\t{"a" : [ 1 , 2 ] }\r\n', None),
    (
        "escapes",
        '"\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u0000 \\u001f \\u007f \\u0080"',
        None,
    ),
    ("raw-unicode", '"é ü ß € 😀 \u2028 \u00a0"', None),
    ("astral-escaped", '"\\ud83d\\ude00\\udbff\\udfff"', None),
    ("literals", "[true, false, null]", None),
    ("scalar-string", '"x"', None),
    ("bom", "\ufeff{}", None),
    ("trailing-garbage", "{} x", None),
    ("trailing-comma", "[1,]", None),
    ("single-quotes", "{'a': 1}", None),
    ("leading-zero", "01", None),
    ("plus-sign", "+1", None),
    ("control-in-string", '"a\tb"', None),
    ("empty-input", "", None),
]

# (id, bytes as hex): inputs that are not valid UTF-8.
DUMPS_HEX_CASES = [
    ("invalid-utf8-in-string", b'{"a": "\xff"}'.hex()),
    ("utf8-encoded-surrogate", b'"\xed\xa0\x80"'.hex()),
]

VALUE_INPUTS = [
    "0",
    "1",
    "-1",
    "-0",
    "true",
    "false",
    "null",
    "0.0",
    "-0.0",
    "1e-400",
    "0.5",
    "1e9",
    "5.0",
    "2.5",
    '""',
    '"x"',
    "[]",
    "[0]",
    "{}",
    '{"a": 1}',
    "12345678901234567890123456789012345678",
    "170141183460469231731687303715884105727",
    "170141183460469231731687303715884105728",
    "-170141183460469231731687303715884105728",
    "123456789012345678901234567890123456789012",
    '"stale_kernel"',
    '"no"',
    '"prefix stale_kernel suffix"',
    '["stale_kernel"]',
    '["x", "stale_kernel"]',
    '[["stale_kernel"]]',
    '{"stale_kernel": false}',
    '{"x": "stale_kernel"}',
    "[1, true, null]",
    "[0.0]",
]


def python_dumps(data: bytes) -> tuple[str | None, str | None]:
    """What a json-file endpoint does with the file bytes: (output, error)."""
    try:
        text = data.decode("utf-8")
        value = json.loads(text)
        return json.dumps(value, sort_keys=True), None
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        return None, type(error).__name__


def random_documents(rng: random.Random) -> list[tuple[str, str]]:
    docs = []
    for index in range(2_000):
        sig = (
            "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 25))).lstrip(
                "0"
            )
            or "0"
        )
        point = rng.randint(0, len(sig))
        lexeme = (
            sig[:point] + "." + (sig[point:] or "0")
            if point < len(sig) or rng.random() < 0.5
            else sig
        )
        if lexeme.startswith("."):
            lexeme = "0" + lexeme
        if rng.random() < 0.6:
            lexeme += f"e{rng.choice(['', '+', '-'])}{rng.randint(0, 330)}"
        if rng.random() < 0.5:
            lexeme = "-" + lexeme
        docs.append((f"random-number-{index:04d}", lexeme))
    alphabet = [chr(c) for c in range(0x20, 0x7F)] + [
        "\t",
        "\n",
        "\x00",
        "\x1f",
        "\x7f",
        "é",
        "€",
        "\u2028",
        "😀",
        "\U0010ffff",
        "\uffff",
    ]
    for index in range(300):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 20)))
        key = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))
        docs.append(
            (
                f"random-string-{index:03d}",
                json.dumps(
                    {key: text, "n": rng.randint(-(10**20), 10**20)},
                    ensure_ascii=rng.random() < 0.5,
                ),
            )
        )
    return docs


def contains_stale_kernel(value: Any) -> Any:
    try:
        return "stale_kernel" in value
    except TypeError:
        return "TypeError"


def build_pyjson() -> dict[str, str]:
    rng = random.Random(SEED + 1)
    dumps = []
    for case_id, text, tag in DUMPS_CASES + [
        (i, t, None) for i, t in random_documents(rng)
    ]:
        output, error = python_dumps(text.encode("utf-8"))
        if (
            tag is None
            and case_id.startswith("random-number-")
            and output in ("Infinity", "-Infinity")
        ):
            tag = D4  # overflow to infinity
        case: dict[str, Any] = {"id": case_id, "input": text}
        if output is None:
            case.update(python_error=error, rust="invalid")
        elif tag:
            case.update(python=output, rust="invalid", d=tag)
        else:
            if "NaN" in output or "Infinity" in output:
                raise SystemExit(
                    f"{case_id}: Python output needs a D-4 tag: {output[:80]}"
                )
            case.update(python=output, rust="same")
        dumps.append(case)
    for case_id, data_hex in DUMPS_HEX_CASES:
        output, error = python_dumps(bytes.fromhex(data_hex))
        # Python's handler does not catch UnicodeDecodeError (a ValueError):
        # the request crashes; Rust answers 502 invalid_json (D-2).
        assert output is None, case_id
        dumps.append(
            {
                "id": case_id,
                "input_hex": data_hex,
                "python_error": error,
                "rust": "invalid",
                "d": "D-2",
            }
        )
    values = []
    for text in VALUE_INPUTS:
        value = json.loads(text)
        is_int = isinstance(value, int)
        values.append(
            {
                "input": text,
                "truthy": bool(value),
                "is_int": is_int,
                "int": str(int(value)) if is_int else None,
                "contains_stale_kernel": contains_stale_kernel(value),
            }
        )
    return {"pyjson.json": dump_json({"dumps": dumps, "values": values})}


# --------------------------------------------------------------------------
# meta

ISO_EPOCHS = [
    0,
    1,
    -1,
    59,
    86_399,
    86_400,
    951_782_400,
    951_868_799,
    1_792_576_800,
    2_147_483_647,
    2_147_483_648,
    4_107_542_400,
    253_402_300_799,
    253_402_300_800,
    -62_135_596_800,
    -62_135_596_801,
    -2_208_988_800,
    10**12,
]

MTIME_CASES = [
    (1_792_576_800, 0),
    (1_792_576_800, 1),
    (1_792_576_800, 500_000_000),
    (1_792_576_800, 999_999_000),
    (1_792_576_800, 999_999_999),
    (0, 0),
    (0, 999_999_999),
    (1, 1),
    (2_147_483_647, 999_999_999),
    (4_294_967_296, 999_999_999),
    (1_000_000_000, 999_999_940),
] + [(1_792_576_800, n) for n in range(999_999_870, 999_999_900)]


def python_iso(epoch: int) -> str | None:
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def build_meta() -> dict[str, str]:
    rng = random.Random(SEED + 2)
    epochs = ISO_EPOCHS + [
        rng.randint(-62_135_596_800, 253_402_300_799) for _ in range(300)
    ]
    iso = [{"epoch": e, "python": python_iso(e)} for e in epochs]
    mtimes = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "f.json"
        path.write_text("{}", encoding="utf-8")
        for sec, nsec in MTIME_CASES:
            ns = sec * 1_000_000_000 + nsec
            os.utime(path, ns=(ns, ns))
            st = os.stat(path)
            if st.st_mtime_ns != ns:
                raise SystemExit(
                    f"the filesystem of {tmp} does not keep nanosecond mtimes"
                )
            mtimes.append({"sec": sec, "nsec": nsec, "python": int(st.st_mtime)})
    return {"meta.json": dump_json({"iso_utc": iso, "mtime_epoch": mtimes})}


# --------------------------------------------------------------------------
# rendered templates


def render(template: str, variables: dict[str, Any]) -> str:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    path = ROOT / template
    environment = Environment(
        loader=FileSystemLoader(path.parent),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    environment.filters["to_json"] = json.dumps
    return environment.get_template(path.name).render(**variables)


def load_module(
    name: str,
    template: str,
    variables: dict[str, Any],
    tmp: Path,
    env: dict[str, str] | None = None,
):
    source = tmp / f"{name}.py"
    source.write_text(render(template, variables), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(
        f"metrics_httpd_fixture_{name}", source
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    saved = dict(os.environ)
    try:
        os.environ.update(env or {})
        spec.loader.exec_module(module)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    return module


BACKUP = "roles/backup_metrics_endpoint/templates/backup_metrics_httpd.py.j2"
METRICS = "roles/metrics_endpoint/templates/metrics_httpd.py.j2"
TAILSCALE = "roles/tailscale_metrics_endpoint/templates/tailscale_metrics_httpd.py.j2"
APT = "roles/os_apt_maintenance/templates/os_apt_maintenance_httpd.py.j2"
LOGYARD = "roles/logyard_deploy/templates/logyard_health_httpd.py.j2"

PLACEHOLDER_VARS = {
    "backup_metrics_endpoint_json_path": "/nonexistent/backup.json",
    "backup_metrics_endpoint_htpasswd_path": "/nonexistent/htpasswd",
    "metrics_endpoint_script_path": "/nonexistent/script",
    "metrics_endpoint_htpasswd_path": "/nonexistent/htpasswd",
    "metrics_endpoint_script_timeout": 10,
    "tailscale_metrics_endpoint_json_path": "/nonexistent/tailscale.json",
    "tailscale_metrics_endpoint_htpasswd_path": "/nonexistent/htpasswd",
    "os_apt_maintenance_freshness_max_age_seconds": 1_209_600,
    "os_apt_maintenance_endpoint_state_max_age_seconds": 1_296_000,
    "os_apt_maintenance_endpoint_bind": "127.0.0.1",
    "os_apt_maintenance_endpoint_port": 9106,
    "os_apt_maintenance_endpoint_path": "/.well-known/os-apt-maintenance",
    "os_apt_maintenance_state_file": "/nonexistent/state.json",
    "os_apt_maintenance_endpoint_htpasswd_path": "/nonexistent/htpasswd",
}


# --------------------------------------------------------------------------
# auth


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode(
        "ascii"
    )


def auth_cases() -> list[tuple[str, str | None, str]]:
    """(id, header as latin-1 text or None, htpasswd file key)."""
    ok = basic("user", "secret")
    token = ok.split()[1]
    cases: list[tuple[str, str | None, str]] = [
        ("absent", None, "htpasswd"),
        ("empty", "", "htpasswd"),
        ("scheme-only", "Basic", "htpasswd"),
        ("scheme-space", "Basic ", "htpasswd"),
        ("scheme-spaces", "Basic   ", "htpasswd"),
        ("lowercase-scheme", "basic " + token, "htpasswd"),
        ("uppercase-scheme", "BASIC " + token, "htpasswd"),
        ("tab-after-scheme", "Basic\t" + token, "htpasswd"),
        ("bearer", "Bearer " + token, "htpasswd"),
        ("correct", ok, "htpasswd"),
        ("two-spaces", "Basic  " + token, "htpasswd"),
        ("trailing-field", ok + " extra", "htpasswd"),
        ("trailing-space", ok + "  ", "htpasswd"),
        ("nbsp-separator", "Basic \xa0" + token, "htpasswd"),
        ("nbsp-after-token", ok + "\xa0junk", "htpasswd"),
        ("nel-after-token", ok + "\x85junk", "htpasswd"),
        ("non-ascii-in-token", ok + "\xe9", "htpasswd"),
        ("missing-padding", "Basic " + token.rstrip("="), "htpasswd"),
        ("extra-padding", "Basic " + token + "==", "htpasswd"),
        ("dot-inside-token", "Basic " + token[:4] + "." + token[4:], "htpasswd"),
        (
            "urlsafe-alphabet",
            "Basic " + base64.urlsafe_b64encode("user:secret?>>".encode()).decode(),
            "htpasswd",
        ),
        ("standard-alphabet-plus-slash", basic("user", "secret?>>"), "htpasswd"),
        ("leading-padding", "Basic =" + token, "htpasswd"),
        (
            "trailing-bits",
            "Basic " + token[:-2] + chr(ord(token[-2]) + 1) + "=",
            "htpasswd",
        ),
        (
            "not-utf8",
            "Basic " + base64.b64encode(b"user:s\xe9cret").decode(),
            "htpasswd",
        ),
        ("no-colon", "Basic " + base64.b64encode(b"usersecret").decode(), "htpasswd"),
        ("empty-password", basic("user", ""), "htpasswd"),
        ("wrong-password", basic("user", "Secret"), "htpasswd"),
        ("colon-in-password", basic("user", "sec:ret"), "htpasswd"),
        ("unknown-user", basic("nobody", "secret"), "htpasswd"),
        ("user-case", basic("User", "secret"), "htpasswd"),
        ("password-lf", basic("user", "secret\n"), "htpasswd"),
        ("password-crlf", basic("user", "secret\r\n"), "htpasswd"),
        ("password-two-lf", basic("user", "secret\n\n"), "htpasswd"),
        ("password-cr", basic("user", "secret\r"), "htpasswd"),
        ("password-leading-lf", basic("user", "\nsecret"), "htpasswd"),
        ("password-nul", basic("user", "secret\x00tail"), "htpasswd"),
        ("password-255-bytes", basic("long", "L" * 255), "htpasswd"),
        ("password-256-bytes", basic("long", "L" * 256), "htpasswd"),
        ("password-254-bytes-lf", basic("long", "L" * 254 + "\n"), "htpasswd"),
        ("password-255-bytes-lf", basic("long", "L" * 255 + "\n"), "htpasswd"),
        ("password-253-bytes-crlf", basic("long", "L" * 253 + "\r\n"), "htpasswd"),
        ("password-long-nul", basic("long", "L" * 72 + "\x00" + "x" * 200), "htpasswd"),
        ("user-nul", basic("us\x00er", "secret"), "htpasswd"),
        ("user-300-chars", basic("u" * 300, "secret"), "htpasswd"),
        ("utf8-password", basic("alice", "pässwörd"), "htpasswd"),
        ("utf8-password-wrong", basic("alice", "passwort"), "htpasswd"),
        ("bcrypt-2a", basic("bob", "bob-password"), "htpasswd"),
        ("bcrypt-2a-non-ascii", basic("alice2a", "pässwörd"), "htpasswd"),
        ("bcrypt-2b", basic("carol", "carol-password"), "htpasswd"),
        ("bcrypt-72-bytes", basic("long", "L" * 72), "htpasswd"),
        ("bcrypt-72-bytes-plus-tail", basic("long", "L" * 72 + "tail"), "htpasswd"),
        ("bcrypt-71-bytes", basic("long", "L" * 71), "htpasswd"),
        ("empty-user-entry", basic("", "nobody"), "htpasswd"),
        ("leading-whitespace-entry", basic("spaced", "spaced-password"), "htpasswd"),
        ("leading-whitespace-user", basic("  \tspaced", "spaced-password"), "htpasswd"),
        ("duplicate-entries", basic("dup", "dup-password"), "htpasswd"),
        (
            "comment-as-user",
            basic(
                "# Test-only htpasswd file of the metrics-httpd fixtures (bcrypt cost 4).",
                "x",
            ),
            "htpasswd",
        ),
        ("mixed-bcrypt-user", basic("user", "secret"), "htpasswd-mixed"),
        ("mixed-md5", basic("md5", "md5-password"), "htpasswd-mixed"),
        ("mixed-md5-wrong", basic("md5", "wrong"), "htpasswd-mixed"),
        ("mixed-sha", basic("sha", "sha-password"), "htpasswd-mixed"),
        ("mixed-crypt", basic("crypt", "cryptpw"), "htpasswd-mixed"),
        ("mixed-2x", basic("x2", "x2-password"), "htpasswd-mixed"),
        (
            "mixed-duplicate-differs",
            basic("dupbad", "dupbad-password"),
            "htpasswd-mixed",
        ),
        ("invalid-file", ok, "htpasswd-invalid"),
        ("missing-file", ok, "missing"),
        ("unreadable-file", ok, "unreadable"),
    ]
    return cases


def check_auth(handler_class: type, header: str | None, htpasswd: str) -> str:
    handler = handler_class.__new__(handler_class)
    try:
        ok, _message = handler._check_auth(header, {"htpasswd_file": htpasswd})
    except Exception:  # noqa: BLE001 - Python drops the connection here
        return "crash"
    return "ok" if ok else "denied"


def strict_base64(header: str | None) -> bool | None:
    if not header or not header.startswith("Basic "):
        return None
    fields = header.split()
    if len(fields) < 2:
        return None
    try:
        binascii.a2b_base64(fields[1].encode("ascii"), strict_mode=True)
    except (binascii.Error, UnicodeEncodeError):
        return False
    return True


NON_BCRYPT = {"mixed-md5", "mixed-sha", "mixed-crypt", "mixed-2x"}
# $2a$ with a non-ASCII key: APR's crypt_blowfish applies its $2a$ safety
# measure, so Rust refuses rather than risk accepting what htpasswd refuses.
BCRYPT_2A_NON_ASCII = {"bcrypt-2a-non-ascii"}


def rust_expectation(
    case_id: str, python: str, strict: bool | None
) -> tuple[str, str | None]:
    """(Rust decision, D item) for one Python decision."""
    if python == "crash":
        return "denied", "D-2"
    if python == "ok" and strict is False:
        return "denied", "D-6"
    if python == "ok" and (case_id in NON_BCRYPT or case_id in BCRYPT_2A_NON_ASCII):
        return "denied", "D-6"
    return python, None


def build_auth() -> dict[str, str]:
    if shutil.which("htpasswd") is None:
        raise SystemExit("the auth fixtures need the htpasswd binary (apache2-utils)")
    rows = []
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        backup = load_module("backup", BACKUP, PLACEHOLDER_VARS, tmp)
        metrics = load_module("metrics", METRICS, PLACEHOLDER_VARS, tmp)
        unreadable = tmp / "htpasswd-unreadable"
        shutil.copyfile(FIXTURES / "htpasswd", unreadable)
        os.chmod(unreadable, 0)
        files = {
            "htpasswd": str(FIXTURES / "htpasswd"),
            "htpasswd-mixed": str(FIXTURES / "htpasswd-mixed"),
            "htpasswd-invalid": str(FIXTURES / "htpasswd-invalid"),
            "missing": str(tmp / "missing"),
            "unreadable": str(unreadable),
        }
        try:
            for case_id, header, file_key in auth_cases():
                vi = check_auth(backup.BackupMetricsHandler, header, files[file_key])
                vb = check_auth(metrics.MetricsHandler, header, files[file_key])
                strict = strict_base64(header)
                row: dict[str, Any] = {
                    "id": case_id,
                    "header": header,
                    "file": file_key,
                    "strict_base64": strict,
                    "python": {"vi": vi, "vb": vb},
                }
                rust, tags = {}, {}
                for source, python in (("vi", vi), ("vb", vb)):
                    rust[source], tag = rust_expectation(case_id, python, strict)
                    if tag:
                        tags[source] = tag
                row["rust"] = rust
                if tags:
                    row["d"] = tags
                rows.append(row)
        finally:
            os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)
    if os.geteuid() == 0:
        raise SystemExit(
            "generate the auth fixtures as an unprivileged user (unreadable-file case)"
        )
    return {"auth.json": dump_json(rows)}


# --------------------------------------------------------------------------
# http_common


class _CapturedStderr(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.lock = threading.Lock()

    def write(self, text: str) -> int:
        with self.lock:
            return super().write(text)

    def take(self) -> str:
        with self.lock:
            value = self.getvalue()
            self.seek(0)
            self.truncate()
            return value


ACCESS_LINE = re.compile(
    r'^127\.0\.0\.1 - - \[\d\d/\w{3}/\d{4} \d\d:\d\d:\d\d\] (".*" \d{3} -)$'
)


def gate_cases(path: str, path_only: bool) -> list[dict[str, Any]]:
    ok = basic("user", "secret")
    wrong = basic("user", "wrong")
    cases = [
        ("no-auth", "GET", path, []),
        ("wrong-password", "GET", path, [("Authorization", wrong)]),
        ("unknown-user", "GET", path, [("Authorization", basic("nobody", "secret"))]),
        ("malformed-token", "GET", path, [("Authorization", "Basic !!!")]),
        ("bearer", "GET", path, [("Authorization", "Bearer abc")]),
        (
            "lowercase-scheme",
            "GET",
            path,
            [("Authorization", "basic " + ok.split()[1])],
        ),
        (
            "first-header-wins",
            "GET",
            path,
            [("Authorization", wrong), ("Authorization", ok)],
        ),
        ("lowercase-header-name", "GET", path, [("authorization", wrong)]),
        ("wrong-path-with-auth", "GET", "/.well-known/other", [("Authorization", ok)]),
        ("trailing-slash", "GET", path + "/", [("Authorization", ok)]),
        ("root", "GET", "/", [("Authorization", ok)]),
        (
            "percent-encoded",
            "GET",
            path.replace("w", "%77", 1),
            [("Authorization", ok)],
        ),
        ("query", "GET", path + "?x=1", []),
        ("empty-query", "GET", path + "?", []),
        ("fragment", "GET", path + "#frag", []),
        ("double-slash", "GET", "/" + path, []),
        ("triple-slash", "GET", "//" + path, []),
        ("absolute-form", "GET", "http://127.0.0.1" + path, []),
        ("head", "HEAD", path, [("Authorization", ok)]),
        ("post", "POST", path, [("Authorization", ok), ("Content-Length", "0")]),
        ("put", "PUT", path, [("Authorization", ok), ("Content-Length", "0")]),
        ("delete", "DELETE", path, [("Authorization", ok)]),
        ("options", "OPTIONS", path, [("Authorization", ok)]),
        ("lowercase-get", "get", path, [("Authorization", ok)]),
        ("http10", "GET", path, [], "HTTP/1.0"),
    ]
    rows = []
    for case in cases:
        case_id, method, target, headers = case[:4]
        version = case[4] if len(case) > 4 else "HTTP/1.1"
        row: dict[str, Any] = {
            "id": case_id,
            "method": method,
            "target": target,
            "version": version,
            "headers": headers,
        }
        if case_id == "fragment" and not path_only:
            # hyper drops the fragment before the handler sees the target.
            row.update(rust_status=401, d="D-14")
        rows.append(row)
    return rows


def logyard_cases(path: str) -> list[dict[str, Any]]:
    cases = [
        ("wrong-path", "GET", "/.well-known/other"),
        ("root", "GET", "/"),
        ("query", "GET", path + "?x=1"),
        ("trailing-slash", "GET", path + "/"),
        ("head", "HEAD", path),
        ("post", "POST", path),
        ("lowercase-get", "get", path),
    ]
    return [
        {
            "id": i,
            "method": m,
            "target": t,
            "version": "HTTP/1.1",
            "headers": [],
            "compare": "logyard-404",
        }
        for i, m, t in cases
    ]


def variants(tmp: Path) -> list[dict[str, Any]]:
    script = tmp / "script.sh"
    return [
        {
            "variant": "backup",
            "template": BACKUP,
            "module": load_module("backup_http", BACKUP, PLACEHOLDER_VARS, tmp),
            "handler": "BackupMetricsHandler",
            "cfg": {
                "path": "/.well-known/backup",
                "json_path": str(tmp / "missing.json"),
                "htpasswd_file": "{htpasswd}",
            },
            "argv": [
                "json-file",
                "--path",
                "/.well-known/backup",
                "--json-path",
                "{json}",
                "--htpasswd-file",
                "{htpasswd}",
                "--realm",
                "backup-metrics",
                "--server-name",
                "backup-metrics-httpd/0.1",
            ],
            "cases": gate_cases("/.well-known/backup", path_only=False),
        },
        {
            "variant": "tailscale",
            "template": TAILSCALE,
            "module": load_module("tailscale_http", TAILSCALE, PLACEHOLDER_VARS, tmp),
            "handler": "TailscaleMetricsHandler",
            "cfg": {
                "path": "/.well-known/tailscale",
                "json_path": str(tmp / "missing.json"),
                "htpasswd_file": "{htpasswd}",
            },
            "argv": [
                "json-file",
                "--path",
                "/.well-known/tailscale",
                "--json-path",
                "{json}",
                "--htpasswd-file",
                "{htpasswd}",
                "--realm",
                "tailscale-metrics",
                "--server-name",
                "tailscale-metrics-httpd/0.1",
                "--path-match",
                "path-only",
            ],
            "cases": gate_cases("/.well-known/tailscale", path_only=True),
        },
        {
            "variant": "metrics_endpoint",
            "template": METRICS,
            "module": load_module("metrics_http", METRICS, PLACEHOLDER_VARS, tmp),
            "handler": "MetricsHandler",
            "cfg": {
                "path": "/.well-known/health",
                "script": str(script),
                "htpasswd_file": "{htpasswd}",
                "script_timeout": 10,
            },
            "argv": [
                "script",
                "--path",
                "/.well-known/health",
                "--script",
                "{script}",
                "--script-timeout",
                "10",
                "--htpasswd-file",
                "{htpasswd}",
                "--realm",
                "metrics",
                "--server-name",
                "metrics-httpd/0.1",
            ],
            "cases": gate_cases("/.well-known/health", path_only=False),
        },
        {
            "variant": "os_apt",
            "template": APT,
            "module": load_module("apt_http", APT, PLACEHOLDER_VARS, tmp),
            "handler": "AptMaintenanceHandler",
            "cfg": {
                "path": "/.well-known/os-apt-maintenance",
                "json_path": str(tmp / "missing.json"),
                "htpasswd_file": "{htpasswd}",
            },
            "argv": [
                "apt-state",
                "--path",
                "/.well-known/os-apt-maintenance",
                "--json-path",
                "{json}",
                "--htpasswd-file",
                "{htpasswd}",
                "--freshness-max-age",
                "1209600",
                "--state-max-age",
                "1296000",
                "--realm",
                "os-apt-maintenance",
                "--server-name",
                "os-apt-maintenance-httpd/0.1",
            ],
            "cases": gate_cases("/.well-known/os-apt-maintenance", path_only=False),
        },
        {
            "variant": "logyard",
            "template": LOGYARD,
            "module": load_module(
                "logyard_http",
                LOGYARD,
                {},
                tmp,
                env={"LOGYARD_HEALTH_PATH": "/.well-known/logyard"},
            ),
            "handler": "Handler",
            "cfg": None,
            "argv": ["logyard-health"],
            "env": {"LOGYARD_HEALTH_PATH": "/.well-known/logyard"},
            "cases": logyard_cases("/.well-known/logyard"),
        },
    ]


def raw_request(case: dict[str, Any]) -> bytes:
    lines = [f"{case['method']} {case['target']} {case['version']}", "Host: 127.0.0.1"]
    lines += [f"{name}: {value}" for name, value in case["headers"]]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


RECORDED_HEADERS = ("Content-Type", "Content-Length", "WWW-Authenticate", "Connection")


def exchange(port: int, case: dict[str, Any]) -> dict[str, Any]:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(raw_request(case))
        response = http.client.HTTPResponse(sock, method=case["method"])
        response.begin()
        body = response.read()
        return {
            "status": response.status,
            "response_headers": {
                name: response.getheader(name) for name in RECORDED_HEADERS
            },
            "body": body.decode("utf-8"),
        }


def build_http_common() -> dict[str, str]:
    htpasswd = str(FIXTURES / "htpasswd")
    out = []
    captured = _CapturedStderr()
    with tempfile.TemporaryDirectory() as tmp_name, contextlib.redirect_stderr(
        captured
    ):
        for variant in variants(Path(tmp_name)):
            handler = getattr(variant["module"], variant["handler"])
            server = socketserver.TCPServer(("127.0.0.1", 0), handler)
            if variant["cfg"] is not None:
                server.cfg = {k: htpasswd if v == "{htpasswd}" else v for k, v in variant["cfg"].items()}  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                cases = []
                for case in variant["cases"]:
                    captured.take()
                    result = exchange(server.server_address[1], case)
                    access = [
                        m.group(1)
                        for line in captured.take().splitlines()
                        if (m := ACCESS_LINE.match(line))
                    ]
                    compare = case.get("compare", "bytes")
                    if (result["response_headers"]["Content-Type"] or "").startswith(
                        "text/html"
                    ):
                        # send_error's page (D-3): compared without the <style>
                        # block CPython 3.14 added; Content-Length not compared.
                        compare = "html"
                    cases.append(
                        {
                            **case,
                            **result,
                            "access_log": access[0] if access else None,
                            "compare": compare,
                        }
                    )
            finally:
                server.shutdown()
                server.server_close()
            entry = {
                "variant": variant["variant"],
                "template": variant["template"],
                "argv": variant["argv"],
            }
            if "env" in variant:
                entry["env"] = variant["env"]
            entry["cases"] = cases
            out.append(entry)
    return {"http_common.json": dump_json(out)}


# --------------------------------------------------------------------------

FAMILIES: dict[str, tuple[bool, Callable[[], dict[str, str]]]] = {
    "float_repr": (False, build_float_repr),
    "pyjson": (False, build_pyjson),
    "meta": (False, build_meta),
    "auth": (True, build_auth),
    "http_common": (True, build_http_common),
}


def selected(stdlib_only: bool) -> dict[str, str]:
    files: dict[str, str] = {}
    for _name, (needs_templates, build) in FAMILIES.items():
        if stdlib_only and needs_templates:
            continue
        files.update(build())
    return files


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["write", "check"])
    parser.add_argument(
        "--stdlib-only",
        action="store_true",
        help="only the families that need no templates or htpasswd",
    )
    args = parser.parse_args(argv)
    files = selected(args.stdlib_only)
    if args.command == "write":
        stale = sorted(
            p.relative_to(FIXTURES).as_posix()
            for p in (FIXTURES / "float_repr").glob("*.txt")
        )
        for name in stale:
            if name not in files:
                (FIXTURES / name).unlink()
        for name, text in files.items():
            target = FIXTURES / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {len(files)} fixture files with Python {sys.version.split()[0]}")
        return 0
    drift = []
    for name, text in files.items():
        target = FIXTURES / name
        if not target.is_file() or target.read_text(encoding="utf-8") != text:
            drift.append(name)
    on_disk = {
        p.relative_to(FIXTURES).as_posix()
        for p in (FIXTURES / "float_repr").glob("*.txt")
    }
    drift += sorted(on_disk - set(files))
    if drift:
        print(
            f"fixtures differ from Python {sys.version.split()[0]}: {', '.join(drift)}",
            file=sys.stderr,
        )
        print(
            "regenerate with `just metrics-httpd-fixtures` and update the Rust side in the same change",
            file=sys.stderr,
        )
        return 1
    print(f"{len(files)} fixture files match Python {sys.version.split()[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
