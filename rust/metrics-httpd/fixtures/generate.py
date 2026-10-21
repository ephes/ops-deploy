#!/usr/bin/env python3
"""Generate the metrics-httpd fixtures from the Python endpoints (PLAN.md 8.2).

Python is the oracle: every expected value in ``fixtures/`` is what CPython or
one of the rendered Python endpoint scripts produces. The Rust tests
(``tests/fixtures.rs``, ``tests/apt_state.rs``) replay every case. Families:

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
``script`` (templates, ``htpasswd``)
    ``script.json``: ``metrics_httpd.py.j2`` past the gate (S2b): the
    fixture scripts' stdout, exit codes, stderr and timeout as the handler
    answers them, with the Rust expectation next to every case where Python
    drops the connection or the plan allows a difference (D-2, D-3).
``apt_state`` (templates, ``htpasswd``)
    ``apt_state.json``: the rendered os_apt_maintenance script's
    ``reboot_state()`` for the inputs of ``EndpointRebootStateTests`` and
    every branch of the reason check, and its handler on loopback (frozen
    clock, fixed ``uname().release``, a temporary reboot flag) for state
    files covering every branch of PLAN.md 4.5 (S2c).
``json_file`` (templates, ``htpasswd``; S2a)
    ``json_file.json``: the eight json-file scripts of PLAN.md 4.3 (seven in
    ops-library, torrent-vpn in ops-control) served on loopback with a
    frozen clock, each driven through the same file states at its
    ``--json-path`` (documents, ``meta`` forms, numbers, Unicode, mtimes,
    missing/unreadable/invalid files, Python's crash paths and the D-4
    refusals) plus a few gate cases (realm, path match). The torrent-vpn
    script is read from an ops-control checkout (``$METRICS_HTTPD_OPS_CONTROL``,
    else a sibling ``ops-control`` or ``~/projects/ops-control``); without
    one, ``write`` and ``check`` keep the committed torrent-vpn cases.
``static`` (templates)
    ``static.json``: ``static-site-httpd.py.j2`` (S2e) serving a sample tree
    (written by the replay from the fixture) with ``mimetypes``' built-in
    table: files, directories, redirects, conditional and range requests,
    path forms, methods; the Rust expectation next to every case where
    Python drops the connection or the plan allows a difference (D-2, D-3,
    D-11).

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
    (
        "d4-serde-number-key-escaped",
        '{"a": {"\\u0024serde_json::private::Number": "1"}}',
        D4,
    ),
    ("d4-serde-number-key-other-value", '{"$serde_json::private::Number": "x"}', D4),
    (
        "serde-number-token-as-value",
        '["$serde_json::private::Number", {"k": "$serde_json::private::Number"}]',
        None,
    ),
    (
        "d5-int-4301-digits-replaced-by-duplicate",
        '{"a": ' + "9" * 4301 + ', "a": 1}',
        None,
    ),
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


def render(template: str, variables: dict[str, Any], root: Path = ROOT) -> str:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    path = root / template
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
    root: Path = ROOT,
    raw: bool = False,
):
    """Import a rendered template (``raw``: a plain file, not rendered)."""
    source = tmp / f"{name}.py"
    text = (
        (root / template).read_text(encoding="utf-8")
        if raw
        else render(template, variables, root)
    )
    source.write_text(text, encoding="utf-8")
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
# script (S2b): metrics_endpoint past the gate (PLAN.md 4.4)

SCRIPT_PATH = "/.well-known/health"
SCRIPT_ARGV = [
    "script",
    "--path",
    SCRIPT_PATH,
    "--script",
    "{script}",
    "--script-timeout",
    "{timeout}",
    "--htpasswd-file",
    "{htpasswd}",
    "--realm",
    "metrics",
    "--server-name",
    "metrics-httpd/0.1",
]
# More than a pipe buffer (64 KiB) on both pipes at once: the server must
# drain them together.
LARGE_SCRIPT = r"""#!/bin/sh
i=0
while [ "$i" -lt 1100 ]; do
  printf '{"line": %d, "pad": "................................................................"}\n' "$i"
  printf 'stderr line %d ................................................................\n' "$i" >&2
  i=$((i + 1))
done
"""
STDERR_LONG_SCRIPT = r"""#!/bin/sh
i=0
while [ "$i" -lt 300 ]; do
  printf 'err%04d ' "$i" >&2
  i=$((i + 1))
done
exit 1
"""

# (id, script text or None for a missing file, file mode, timeout seconds,
#  Rust expectation when Python has none or differs: {"d", "rust_status",
#  "rust_message" or "rust_body_hex"})
SCRIPT_CASES: list[tuple[str, str | None, int, str, dict[str, Any]]] = [
    (
        "json-unchanged",
        '#!/bin/sh\nprintf \'%s\\n\' \'{"z": 1.50, "a": ["\\u00fc", 12345678901234567890]}\'\n',
        0o755,
        "10",
        {},
    ),
    ("not-json", "#!/bin/sh\nprintf 'plain text, not JSON'\n", 0o755, "10", {}),
    ("empty-stdout", "#!/bin/sh\nexit 0\n", 0o755, "10", {}),
    ("universal-newlines", "#!/bin/sh\nprintf 'a\\r\\nb\\rc\\n\\r'\n", 0o755, "10", {}),
    (
        "utf8-multibyte",
        '#!/bin/sh\nprintf \'{"t": "\\342\\202\\254 \\360\\237\\230\\200"}\'\n',
        0o755,
        "10",
        {},
    ),
    (
        "stderr-ignored-on-success",
        "#!/bin/sh\nprintf '{}'\nprintf 'warning\\n' >&2\n",
        0o755,
        "10",
        {},
    ),
    ("no-arguments", '#!/bin/sh\nprintf \'{"argc": %s}\' "$#"\n', 0o755, "10", {}),
    ("large-output-both-pipes", LARGE_SCRIPT, 0o755, "10", {}),
    ("exit-3-stderr", "#!/bin/sh\nprintf 'boom\\n' >&2\nexit 3\n", 0o755, "10", {}),
    ("exit-1-no-stderr", "#!/bin/sh\nexit 1\n", 0o755, "10", {}),
    (
        "exit-whitespace-stderr",
        "#!/bin/sh\nprintf ' \\t\\n\\r\\n' >&2\nexit 1\n",
        0o755,
        "10",
        {},
    ),
    (
        # str.strip() also strips the information separators U+001C-U+001F.
        "exit-separator-stderr",
        "#!/bin/sh\nprintf '\\037\\034 \\n' >&2\nexit 1\n",
        0o755,
        "10",
        {},
    ),
    (
        "exit-padded-html-stderr",
        "#!/bin/sh\nprintf '\\n  failed: <disk> & co  \\n\\n' >&2\nexit 2\n",
        0o755,
        "10",
        {},
    ),
    (
        "exit-stdout-ignored",
        "#!/bin/sh\nprintf '{\"partial\": true}'\nexit 1\n",
        0o755,
        "10",
        {},
    ),
    (
        "exit-latin1-stderr",
        "#!/bin/sh\nprintf 'Fehler: \\303\\274berlauf\\n' >&2\nexit 1\n",
        0o755,
        "10",
        {},
    ),
    ("killed-by-signal", "#!/bin/sh\nkill -TERM $$\nsleep 5\n", 0o755, "10", {}),
    ("timeout", "#!/bin/sh\nexec sleep 5\n", 0o755, "0.5", {}),
    (
        # A newline in the stderr text breaks Python's status line (the
        # message is the reason phrase); Rust keeps it in the body only.
        "exit-multiline-stderr",
        "#!/bin/sh\nprintf 'line1\\nline2\\n' >&2\nexit 1\n",
        0o755,
        "10",
        {"d": "D-3", "rust_status": 502, "rust_message": "line1 line2"},
    ),
    (
        "exit-long-stderr",
        STDERR_LONG_SCRIPT,
        0o755,
        "10",
        {
            "d": "D-3",
            "rust_status": 502,
            "rust_message": " ".join(f"err{i:04d}" for i in range(300))[:1024],
        },
    ),
    (
        # Python: UnicodeEncodeError for the latin-1 status line, no response.
        "exit-stderr-outside-latin1",
        "#!/bin/sh\nprintf 'kaputt \\342\\202\\254\\n' >&2\nexit 1\n",
        0o755,
        "10",
        {"d": "D-2", "rust_status": 502, "rust_message": "kaputt \u20ac"},
    ),
    (
        # Python: UnicodeDecodeError in subprocess.run, no response.
        "exit-stderr-not-utf8",
        "#!/bin/sh\nprintf 'bad \\377\\n' >&2\nexit 1\n",
        0o755,
        "10",
        {"d": "D-2", "rust_status": 502, "rust_message": "bad \ufffd"},
    ),
    (
        "stdout-not-utf8",
        '#!/bin/sh\nprintf \'{"x": "\\377"}\\r\\n\'\n',
        0o755,
        "10",
        {"d": "D-2", "rust_status": 200, "rust_body_hex": b'{"x": "\xff"}\n'.hex()},
    ),
    (
        # Python: FileNotFoundError / PermissionError from subprocess.run.
        "missing-script",
        None,
        0o755,
        "10",
        {"d": "D-2", "rust_status": 502, "rust_message": "Cannot run metrics script"},
    ),
    (
        "not-executable",
        "#!/bin/sh\nprintf '{}'\n",
        0o644,
        "10",
        {"d": "D-2", "rust_status": 502, "rust_message": "Cannot run metrics script"},
    ),
]


SCRIPT_REQUEST = {
    "method": "GET",
    "target": SCRIPT_PATH,
    "version": "HTTP/1.1",
    "headers": [["Authorization", basic("user", "secret")]],
}


def script_exchange(port: int) -> dict[str, Any]:
    try:
        result = exchange(port, SCRIPT_REQUEST)
    except (http.client.HTTPException, ConnectionError):
        # The handler raised: socketserver closes the connection unanswered.
        return {"status": None}
    return result


def build_script() -> dict[str, str]:
    htpasswd = str(FIXTURES / "htpasswd")
    out = []
    captured = _CapturedStderr()
    with tempfile.TemporaryDirectory() as tmp_name, contextlib.redirect_stderr(
        captured
    ):
        tmp = Path(tmp_name)
        module = load_module("metrics_script", METRICS, PLACEHOLDER_VARS, tmp)
        server = socketserver.TCPServer(("127.0.0.1", 0), module.MetricsHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for case_id, script, mode, timeout, rust in SCRIPT_CASES:
                path = tmp / f"{case_id}.sh"
                if script is not None:
                    path.write_text(script, encoding="ascii")
                    path.chmod(mode)
                # Single-threaded server, one request at a time.
                server.cfg = {  # type: ignore[attr-defined]
                    "path": SCRIPT_PATH,
                    "script": str(path),
                    "htpasswd_file": htpasswd,
                    "script_timeout": float(timeout),
                }
                result = script_exchange(server.server_address[1])
                row: dict[str, Any] = {
                    "id": case_id,
                    "script": script,
                    "mode": f"{mode:04o}",
                    "timeout": timeout,
                    "status": result["status"],
                }
                if result["status"] is None:
                    compare = "no-response"
                elif rust:
                    compare = "status"
                elif (result["response_headers"]["Content-Type"] or "").startswith(
                    "text/html"
                ):
                    compare = "html"
                else:
                    compare = "bytes"
                if compare in ("bytes", "html"):
                    row["response_headers"] = result["response_headers"]
                    row["body"] = result["body"]
                row["compare"] = compare
                row.update(rust)
                out.append(row)
                captured.take()
        finally:
            server.shutdown()
            server.server_close()
    return {
        "script.json": dump_json(
            {"argv": SCRIPT_ARGV, "request": SCRIPT_REQUEST, "cases": out}
        )
    }


# --------------------------------------------------------------------------
# apt_state

APT_SERVED = 1_792_576_800
APT_FRESHNESS = PLACEHOLDER_VARS["os_apt_maintenance_freshness_max_age_seconds"]
APT_STATE_MAX = PLACEHOLDER_VARS["os_apt_maintenance_endpoint_state_max_age_seconds"]
APT_PATH = "/.well-known/os-apt-maintenance"
APT_RELEASE = "6.8.0-138-generic"
APT_STALE_RELEASE = "5.10.0-23-amd64"
APT_ARGV = [
    "apt-state",
    "--path",
    APT_PATH,
    "--json-path",
    "{json}",
    "--htpasswd-file",
    "{htpasswd}",
    "--freshness-max-age",
    str(APT_FRESHNESS),
    "--state-max-age",
    str(APT_STATE_MAX),
    "--reboot-flag",
    "{reboot_flag}",
    "--realm",
    "os-apt-maintenance",
    "--server-name",
    "os-apt-maintenance-httpd/0.1",
]


def apt_stale_state() -> dict[str, Any]:
    """EndpointRebootStateTests._stale_state."""
    return {
        "reboot_required": True,
        "reboot_required_details": {
            "required": True,
            "reasons": ["stale_kernel"],
            "flag_present": False,
            "running_kernel": APT_STALE_RELEASE,
            "running_kernel_version": "5.10.0-23",
            "newest_installed_kernel": "6.1.0-52",
        },
    }


def apt_with_reasons(reasons: Any, **details: Any) -> dict[str, Any]:
    return {
        "reboot_required_details": {
            "reasons": reasons,
            "running_kernel": APT_STALE_RELEASE,
            **details,
        }
    }


# (id, state, flag_present, running_release): the inputs of
# tests/test_monitoring_pipeline_repair.py EndpointRebootStateTests first,
# then the branches of `"stale_kernel" in (persisted.get("reasons") or [])`.
REBOOT_STATE_CASES: list[tuple[str, Any, bool, str]] = [
    ("persisted-kernel-signal-served", apt_stale_state(), False, APT_STALE_RELEASE),
    ("reboot-into-new-kernel-clears", apt_stale_state(), False, "6.1.0-52-amd64"),
    ("live-marker-alone", {"reboot_required": False}, True, APT_RELEASE),
    ("both-signals", apt_stale_state(), True, APT_STALE_RELEASE),
    (
        "legacy-reboot-required-only",
        {"reboot_required": True},
        False,
        APT_STALE_RELEASE,
    ),
    (
        "legacy-details-null",
        {"reboot_required_details": None},
        False,
        APT_STALE_RELEASE,
    ),
    ("legacy-empty", {}, False, APT_STALE_RELEASE),
    ("legacy-with-marker", {}, True, APT_STALE_RELEASE),
    (
        "details-not-object",
        {"reboot_required_details": ["stale_kernel"]},
        False,
        APT_STALE_RELEASE,
    ),
    (
        "details-string",
        {"reboot_required_details": "stale_kernel"},
        False,
        APT_STALE_RELEASE,
    ),
    (
        "reasons-absent",
        {"reboot_required_details": {"running_kernel": APT_STALE_RELEASE}},
        False,
        APT_STALE_RELEASE,
    ),
    (
        "reasons-other",
        apt_with_reasons(["reboot_required_flag"]),
        False,
        APT_STALE_RELEASE,
    ),
    (
        "reasons-two",
        apt_with_reasons(["reboot_required_flag", "stale_kernel"]),
        False,
        APT_STALE_RELEASE,
    ),
    (
        "reasons-nested-list",
        apt_with_reasons([["stale_kernel"]]),
        False,
        APT_STALE_RELEASE,
    ),
    (
        "reasons-substring",
        apt_with_reasons("prefix stale_kernel suffix"),
        False,
        APT_STALE_RELEASE,
    ),
    ("reasons-string-other", apt_with_reasons("stale"), False, APT_STALE_RELEASE),
    (
        "reasons-object-key",
        apt_with_reasons({"stale_kernel": False}),
        False,
        APT_STALE_RELEASE,
    ),
    (
        "reasons-object-value",
        apt_with_reasons({"x": "stale_kernel"}),
        False,
        APT_STALE_RELEASE,
    ),
    ("reasons-null", apt_with_reasons(None), False, APT_STALE_RELEASE),
    ("reasons-false", apt_with_reasons(False), False, APT_STALE_RELEASE),
    ("reasons-zero", apt_with_reasons(0), False, APT_STALE_RELEASE),
    ("reasons-zero-float", apt_with_reasons(0.0), False, APT_STALE_RELEASE),
    ("reasons-empty-string", apt_with_reasons(""), False, APT_STALE_RELEASE),
    ("reasons-empty-list", apt_with_reasons([]), True, APT_STALE_RELEASE),
    ("reasons-int", apt_with_reasons(1), False, APT_STALE_RELEASE),
    ("reasons-int-other-kernel", apt_with_reasons(1), False, APT_RELEASE),
    ("reasons-true", apt_with_reasons(True), True, APT_STALE_RELEASE),
    ("reasons-float", apt_with_reasons(2.5), False, APT_STALE_RELEASE),
    (
        "reasons-not-a-reason-for-other-details",
        {"reboot_required_details": [1]},
        False,
        APT_STALE_RELEASE,
    ),
    (
        "running-kernel-int",
        apt_with_reasons(["stale_kernel"], running_kernel=5),
        False,
        "5",
    ),
    (
        "running-kernel-null",
        apt_with_reasons(["stale_kernel"], running_kernel=None),
        False,
        "None",
    ),
    (
        "running-kernel-absent",
        {"reboot_required_details": {"reasons": ["stale_kernel"]}},
        False,
        "",
    ),
    (
        "kernel-keys-partly-present",
        apt_with_reasons(
            ["stale_kernel"], newest_installed_kernel=None, extra="ignored"
        ),
        False,
        APT_STALE_RELEASE,
    ),
    (
        "kernel-keys-any-value",
        apt_with_reasons(
            ["stale_kernel"],
            running_kernel_version={"major": 5},
            newest_installed_kernel=[6, 1],
        ),
        True,
        APT_STALE_RELEASE,
    ),
]


def python_reboot_state(module: Any, state: Any, flag: bool, release: str) -> Any:
    try:
        return module.reboot_state(state, flag_present=flag, running_release=release)
    except TypeError:
        return "TypeError"


def apt_state_document(**fields: Any) -> dict[str, Any]:
    """A state file as roles/os_apt_maintenance/templates/os_apt_maintenance.py.j2 writes it."""
    state: dict[str, Any] = {
        "schema_version": 1,
        "host_id": "fixture-host",
        "hostname": "fixture-host",
        "generated_at": "2026-10-21T09:00:00+00:00",
        "generated_epoch": APT_SERVED - 3_600,
        "freshness_max_age_seconds": APT_FRESHNESS,
        "last_run_started_at": "2026-10-21T08:59:00+00:00",
        "last_run_started_epoch": APT_SERVED - 3_660,
        "last_run_finished_at": "2026-10-21T09:00:00+00:00",
        "last_run_finished_epoch": APT_SERVED - 3_600,
        "last_success_at": "2026-10-21T09:00:00+00:00",
        "last_success_epoch": APT_SERVED - 3_600,
        "last_exit_code": 0,
        "last_status": "success",
        "last_error": None,
        "last_skipped_at": None,
        "last_skipped_epoch": None,
        "last_skipped_reason": None,
        "reboot_required": False,
        "reboot_required_details": {
            "required": False,
            "reasons": [],
            "flag_present": False,
        },
        "auto_reboot_enabled": False,
        "auto_reboot_attempted": False,
        "auto_reboot_result": None,
        "steps": {
            "update_cache": {
                "enabled": True,
                "attempted": True,
                "started_at": "2026-10-21T08:59:00+00:00",
                "finished_at": "2026-10-21T08:59:12+00:00",
                "duration_seconds": 12.345,
                "exit_code": 0,
                "status": "success",
                "stdout_tail": "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\nReading package lists… Done",
                "stderr_tail": "",
                "error": None,
            }
        },
        "summary": {"last_run_ok": True, "reboot_required": False},
    }
    state.update(fields)
    return state


def apt_http_cases() -> list[dict[str, Any]]:
    """(id, state, mtime offset to the served time, flag, release[, Rust expectation])."""
    fresh = APT_SERVED - APT_FRESHNESS
    s = APT_SERVED
    cases: list[tuple[Any, ...]] = [
        ("success-fresh", apt_state_document(), -60, False, APT_RELEASE),
        (
            "success-file-without-details",
            {"last_status": "success", "last_success_epoch": s - 10},
            -10,
            False,
            APT_RELEASE,
        ),
        (
            "running-fresh-last-success",
            apt_state_document(last_status="running", last_success_epoch=fresh),
            -5,
            False,
            APT_RELEASE,
        ),
        (
            "running-stale-last-success",
            apt_state_document(last_status="running", last_success_epoch=fresh - 1),
            -5,
            False,
            APT_RELEASE,
        ),
        (
            "running-without-last-success",
            apt_state_document(last_status="running", last_success_epoch=None),
            -5,
            False,
            APT_RELEASE,
        ),
        (
            "failed",
            apt_state_document(
                last_status="failed",
                last_exit_code=100,
                last_error="E: Unable to locate package",
            ),
            -60,
            False,
            APT_RELEASE,
        ),
        ("never-run", {"last_status": "never_run"}, 0, False, APT_RELEASE),
        (
            "status-not-a-string",
            apt_state_document(last_status=1),
            -60,
            False,
            APT_RELEASE,
        ),
        ("status-absent", {"last_success_epoch": s - 60}, -60, False, APT_RELEASE),
        (
            "success-without-last-success",
            {"last_status": "success"},
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "state-age-at-limit",
            apt_state_document(),
            -APT_STATE_MAX,
            False,
            APT_RELEASE,
        ),
        (
            "state-age-over-limit",
            apt_state_document(),
            -APT_STATE_MAX - 1,
            False,
            APT_RELEASE,
        ),
        ("mtime-in-the-future", apt_state_document(), 100, False, APT_RELEASE),
        (
            "last-success-in-the-future",
            apt_state_document(last_success_epoch=s + 500),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-true",
            apt_state_document(last_success_epoch=True),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-false",
            apt_state_document(last_success_epoch=False),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-float",
            apt_state_document(last_success_epoch=float(s - 60)),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-exponent",
            '{"last_status": "success", "last_success_epoch": 1.7925768e9}',
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-string",
            apt_state_document(last_success_epoch=str(s - 60)),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-big-negative",
            apt_state_document(last_success_epoch=-(10**30)),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-big-positive",
            apt_state_document(last_success_epoch=10**30),
            -60,
            False,
            APT_RELEASE,
        ),
        (
            "last-success-outside-i128",
            apt_state_document(last_success_epoch=10**40),
            -60,
            False,
            APT_RELEASE,
            {"rust_status": 500, "rust_error_type": "internal_error", "d": "D-5"},
        ),
        (
            "reboot-required-truthy-string",
            {"reboot_required": "yes"},
            -60,
            False,
            APT_RELEASE,
        ),
        ("reboot-required-zero", {"reboot_required": 0}, -60, False, APT_RELEASE),
        (
            "reboot-required-empty-list",
            {"reboot_required": []},
            -60,
            False,
            APT_RELEASE,
        ),
        ("reboot-flag-present", apt_state_document(), -60, True, APT_RELEASE),
        (
            "stale-kernel-served",
            apt_state_document(**apt_stale_state()),
            -60,
            False,
            APT_STALE_RELEASE,
        ),
        (
            "stale-kernel-cleared-by-reboot",
            apt_state_document(**apt_stale_state()),
            -60,
            False,
            "6.1.0-52-amd64",
        ),
        (
            "stale-kernel-and-flag",
            apt_state_document(**apt_stale_state()),
            -60,
            True,
            APT_STALE_RELEASE,
        ),
        (
            "legacy-state-with-flag",
            {"last_status": "success", "reboot_required": True},
            -60,
            True,
            APT_RELEASE,
        ),
        (
            "reasons-substring",
            apt_with_reasons("stale_kernel"),
            -60,
            False,
            APT_STALE_RELEASE,
        ),
        (
            "reasons-int",
            apt_with_reasons(1),
            -60,
            False,
            APT_STALE_RELEASE,
            {"rust_status": 500, "rust_error_type": "internal_error", "d": "D-2"},
        ),
        (
            "reasons-true-other-kernel",
            apt_with_reasons(True),
            -60,
            False,
            APT_RELEASE,
            {"rust_status": 500, "rust_error_type": "internal_error", "d": "D-2"},
        ),
        (
            "computed-keys-replaced",
            {
                "meta": {"collector": "x", "age_seconds": 1},
                "summary": [1, 2],
                "reboot_required": "maybe",
                "reboot_required_details": {
                    "required": True,
                    "reasons": ["reboot_required_flag"],
                },
                "unicode": "é € 😀",
                "big": 123456789012345678901234567890,
                "floats": [1.0, 1e16, 0.00001, 181703637716804.125],
            },
            -60,
            False,
            APT_RELEASE,
        ),
        ("empty-object", "{}", -60, False, APT_RELEASE),
        (
            "whitespace-and-duplicates",
            ' {"last_status": "failed", "last_status": "success"}\n',
            -60,
            False,
            APT_RELEASE,
        ),
        ("invalid-json", '{"last_status": ', -60, False, APT_RELEASE),
        ("empty-file", "", -60, False, APT_RELEASE),
        ("bom", "﻿{}", -60, False, APT_RELEASE),
        (
            "top-level-list",
            "[1, 2]",
            -60,
            False,
            APT_RELEASE,
            {"rust_status": 502, "rust_error_type": "invalid_json", "d": "D-2"},
        ),
        (
            "top-level-null",
            "null",
            -60,
            False,
            APT_RELEASE,
            {"rust_status": 502, "rust_error_type": "invalid_json", "d": "D-2"},
        ),
        (
            "not-utf8",
            {"latin1": '{"last_status": "\xff"}'},
            -60,
            False,
            APT_RELEASE,
            {"rust_status": 502, "rust_error_type": "invalid_json", "d": "D-2"},
        ),
        (
            "nan",
            '{"last_status": "success", "x": NaN}',
            -60,
            False,
            APT_RELEASE,
            {"rust_status": 502, "rust_error_type": "invalid_json", "d": "D-4"},
        ),
        ("missing", {"kind": "missing"}, 0, False, APT_RELEASE),
        ("directory", {"kind": "directory"}, 0, False, APT_RELEASE),
        ("broken-symlink", {"kind": "broken-symlink"}, 0, False, APT_RELEASE),
        ("unreadable", {"kind": "unreadable"}, -60, False, APT_RELEASE),
    ]
    rows = []
    for case in cases:
        case_id, state, offset, flag, release = case[:5]
        row: dict[str, Any] = {"id": case_id}
        if isinstance(state, str):
            row["state_text"] = state
        elif isinstance(state, dict) and set(state) == {"latin1"}:
            # Bytes that are not UTF-8, written as latin-1 text.
            row["state_latin1"] = state["latin1"]
        elif isinstance(state, dict) and set(state) == {"kind"}:
            row["state_kind"] = state["kind"]
        else:
            row["state_text"] = json.dumps(state, ensure_ascii=False)
        row.update(
            mtime_epoch=APT_SERVED + offset, flag_present=flag, running_release=release
        )
        if len(case) > 5:
            row.update(case[5])
        rows.append(row)
    return rows


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return datetime.fromtimestamp(APT_SERVED, tz=tz)


class _UnameOs:
    """The `os` module of the rendered script with a fixed `uname().release`."""

    def __init__(self) -> None:
        self.release = APT_RELEASE

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)

    def uname(self) -> Any:
        real = os.uname()
        return os.uname_result(
            (real.sysname, real.nodename, self.release, real.version, real.machine)
        )


APT_MESSAGE_PREFIXES = {
    "invalid_json": "Invalid JSON in state file: ",
    "read_error": "Cannot read state file: ",
}


def write_state(path: Path, row: dict[str, Any]) -> None:
    kind = row.get("state_kind")
    if kind == "missing":
        return
    if kind == "directory":
        path.mkdir()
        return
    if kind == "broken-symlink":
        path.symlink_to(path.parent / "absent.json")
        return
    if "state_latin1" in row:
        path.write_bytes(row["state_latin1"].encode("latin-1"))
    else:
        path.write_bytes((row["state_text"] if kind is None else "{}").encode("utf-8"))
    os.utime(path, (row["mtime_epoch"], row["mtime_epoch"]))
    if kind == "unreadable":
        os.chmod(path, 0)


def build_apt_state() -> dict[str, str]:
    htpasswd = str(FIXTURES / "htpasswd")
    request = raw_request(
        {
            "method": "GET",
            "target": APT_PATH,
            "version": "HTTP/1.1",
            "headers": [("Authorization", basic("user", "secret"))],
        }
    )
    captured = _CapturedStderr()
    with tempfile.TemporaryDirectory() as tmp_name, contextlib.redirect_stderr(
        captured
    ):
        tmp = Path(tmp_name)
        module = load_module("apt_state", APT, PLACEHOLDER_VARS, tmp)
        reboot_rows = []
        for case_id, state, flag, release in REBOOT_STATE_CASES:
            reboot_rows.append(
                {
                    "id": case_id,
                    "state": state,
                    "flag_present": flag,
                    "running_release": release,
                    "python": python_reboot_state(module, state, flag, release),
                }
            )
        fake_os = _UnameOs()
        module.os = fake_os
        module.datetime = _FrozenDatetime
        flag_path = tmp / "reboot-required"
        module.REBOOT_REQUIRED_FLAG = str(flag_path)
        server = socketserver.TCPServer(("127.0.0.1", 0), module.AptMaintenanceHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        http_rows = []
        try:
            for index, row in enumerate(apt_http_cases()):
                case_dir = tmp / f"case-{index:03d}"
                case_dir.mkdir()
                json_path = case_dir / "state.json"
                write_state(json_path, row)
                if row["flag_present"]:
                    flag_path.write_text("*** System restart required ***\n")
                else:
                    flag_path.unlink(missing_ok=True)
                fake_os.release = row["running_release"]
                server.cfg = {  # type: ignore[attr-defined]
                    "path": APT_PATH,
                    "json_path": str(json_path),
                    "htpasswd_file": htpasswd,
                }
                captured.take()
                try:
                    with socket.create_connection(
                        ("127.0.0.1", server.server_address[1]), timeout=10
                    ) as sock:
                        sock.sendall(request)
                        response = http.client.HTTPResponse(sock, method="GET")
                        response.begin()
                        body = response.read().decode("utf-8")
                    result: dict[str, Any] = {
                        "status": response.status,
                        "response_headers": {
                            name: response.getheader(name)
                            for name in ("Content-Type", "Content-Length")
                        },
                        "body": body,
                    }
                except (http.client.RemoteDisconnected, ConnectionResetError):
                    errors = re.findall(
                        r"^(\w+): ", captured.take(), flags=re.MULTILINE
                    )
                    result = {"python": "crash", "python_exception": errors[-1]}
                finally:
                    if row.get("state_kind") == "unreadable":
                        os.chmod(json_path, stat.S_IRUSR | stat.S_IWUSR)
                if "python" in result:
                    if "rust_status" not in row:
                        raise SystemExit(
                            f"apt_state {row['id']}: Python crashed without a Rust expectation"
                        )
                    compare = "rust_only"
                elif "rust_status" in row:
                    compare = "rust_only"
                elif result["status"] == 200:
                    compare = "bytes"
                else:
                    error_type = json.loads(result["body"])["error_type"]
                    prefix = APT_MESSAGE_PREFIXES.get(error_type)
                    if prefix is None:
                        compare = "bytes"
                    else:
                        if not json.loads(result["body"])["message"].startswith(prefix):
                            raise SystemExit(
                                f"apt_state {row['id']}: unexpected message"
                            )
                        # D-3: the parser's or the OS error's text may differ.
                        compare = "error_type_only"
                        result["message_prefix"] = prefix
                        result["body"] = result["body"].replace(
                            json.dumps(str(tmp))[1:-1], "{tmp}"
                        )
                        # The length depends on the message (and the
                        # temporary path in it): not recorded, not compared.
                        result["response_headers"]["Content-Length"] = None
                http_rows.append({**row, **result, "compare": compare})
        finally:
            server.shutdown()
            server.server_close()
    if os.geteuid() == 0:
        raise SystemExit(
            "generate the apt_state fixtures as an unprivileged user (unreadable case)"
        )
    data = {
        "template": APT,
        "served_at_epoch": APT_SERVED,
        "reboot_state": reboot_rows,
        "http": {"argv": APT_ARGV, "cases": http_rows},
    }
    return {"apt_state.json": dump_json(data)}


# --------------------------------------------------------------------------
# json_file (S2a)

# The Rust replay's frozen clock (tests/fixtures.rs `start`): Python's
# `datetime` is frozen at the same second.
CLOCK_EPOCH = 1_792_576_800
SECOND = 10**9

# The ops-control checkout that holds the torrent-vpn variant (PLAN.md 1.1:
# the only json-file script outside ops-library). Without one, `write` and
# `check` keep the committed torrent-vpn cases.
OPS_CONTROL_ENV = "METRICS_HTTPD_OPS_CONTROL"
TORRENT_ROLE = "roles/torrent_vpn_metrics_endpoint"
TORRENT = f"{TORRENT_ROLE}/templates/torrent_vpn_metrics_httpd.py.j2"


def ops_control_checkout() -> Path | None:
    configured = os.environ.get(OPS_CONTROL_ENV)
    if configured:
        root = Path(configured)
        if not (root / TORRENT).is_file():
            raise SystemExit(f"{OPS_CONTROL_ENV}={configured}: {TORRENT} not found")
        return root
    for root in (ROOT.parent / "ops-control", Path.home() / "projects" / "ops-control"):
        if (root / TORRENT).is_file():
            return root
    return None


def role_defaults(root: Path, role: str) -> dict[str, Any]:
    import yaml

    path = root / "roles" / role / "defaults" / "main.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def json_file_variants(tmp: Path, ops_control: Path | None) -> list[dict[str, Any]]:
    """The eight json-file scripts (PLAN.md 4.3) with the argv of PLAN.md 7.3."""
    table: list[tuple[str, str, str, str, str, list[str]]] = [
        # (variant, template, handler, role, path key, extra argv)
        (
            "backup",
            "roles/backup_metrics_endpoint/templates/backup_metrics_httpd.py.j2",
            "BackupMetricsHandler",
            "backup_metrics_endpoint",
            "backup_metrics_endpoint_path",
            [],
        ),
        (
            "storage",
            "roles/storage_metrics_endpoint/templates/storage_metrics_httpd.py.j2",
            "StorageMetricsHandler",
            "storage_metrics_endpoint",
            "storage_metrics_endpoint_path",
            [],
        ),
        (
            "thermal",
            "roles/thermal_metrics_endpoint/templates/thermal_metrics_httpd.py.j2",
            "ThermalMetricsHandler",
            "thermal_metrics_endpoint",
            "thermal_metrics_endpoint_path",
            [],
        ),
        (
            "tailscale",
            TAILSCALE,
            "TailscaleMetricsHandler",
            "tailscale_metrics_endpoint",
            "tailscale_metrics_endpoint_path",
            ["--path-match", "path-only"],
        ),
        (
            "dns",
            "roles/dns_metrics_endpoint/templates/dns_metrics_httpd.py.j2",
            "DnsMetricsHandler",
            "dns_metrics_endpoint",
            "dns_metrics_endpoint_path",
            [
                "--meta",
                "merge",
                "--request-timeout",
                "{dns_metrics_endpoint_request_timeout}",
            ],
        ),
        (
            "openclaw",
            "roles/openclaw_deploy/templates/openclaw-metrics-httpd.py.j2",
            "OpenClawMetricsHandler",
            "openclaw_deploy",
            "openclaw_metrics_endpoint_path",
            [
                "--missing-message",
                "Metrics file not found - collector timer may not have run yet",
            ],
        ),
        (
            "ddns",
            "roles/dns_deploy/files/ddns_status_httpd.py",
            "DdnsStatusHandler",
            "dns_deploy",
            "dns_ddns_status_endpoint_path",
            [
                "--missing-message",
                "Status file not found - updater may not have run yet",
                "--request-timeout",
                "{handler.timeout}",
            ],
        ),
        (
            "torrent-vpn",
            TORRENT,
            "TorrentVpnMetricsHandler",
            "torrent_vpn_metrics_endpoint",
            "torrent_vpn_metrics_endpoint_path",
            ["--request-timeout", "{handler.timeout}"],
        ),
    ]
    out = []
    for variant, template, handler_name, role, path_key, extra in table:
        if variant == "torrent-vpn":
            if ops_control is None:
                continue
            root, repo = ops_control, "ops-control"
        else:
            root, repo = ROOT, "ops-library"
        defaults = role_defaults(root, role)
        # The templates' only variables: placeholder paths (the server gets
        # the real ones from its cfg) and the dns template's baked defaults.
        variables: dict[str, Any] = {
            f"{name}_metrics_endpoint_{kind}_path": f"/nonexistent/{kind}"
            for name in ("backup", "storage", "thermal", "tailscale", "dns")
            + ("openclaw", "torrent_vpn")
            for kind in ("json", "htpasswd")
        }
        for key in (
            "dns_metrics_endpoint_port",
            "dns_metrics_endpoint_path",
            "dns_metrics_endpoint_request_timeout",
        ):
            if key in defaults:
                variables[key] = defaults[key]
        module = load_module(
            f"json_file_{variant.replace('-', '_')}",
            template,
            variables,
            tmp,
            root=root,
            raw=not template.endswith(".j2"),
        )
        handler = getattr(module, handler_name)
        argv = [
            "json-file",
            "--path",
            defaults[path_key],
            "--json-path",
            "{json}",
            "--htpasswd-file",
            "{htpasswd}",
            "--realm",
            f"{variant}-metrics" if variant not in ("ddns",) else "ddns-status",
            "--server-name",
            handler.server_version,
        ]
        for arg in extra:
            if arg == "{handler.timeout}":
                arg = str(handler.timeout)
            elif arg.startswith("{") and arg.endswith("}"):
                arg = str(defaults[arg[1:-1]])
            argv.append(arg)
        out.append(
            {
                "variant": variant,
                "repo": repo,
                "template": template,
                "module": module,
                "handler": handler,
                "path": defaults[path_key],
                "path_only": "--path-match" in argv,
                "argv": argv,
            }
        )
    return out


def _text(text: str, mtime: int = CLOCK_EPOCH - 100) -> dict[str, Any]:
    return {"kind": "file", "text": text, "mtime_ns": mtime * SECOND}


def _hex(data: bytes) -> dict[str, Any]:
    return {"kind": "file", "hex": data.hex(), "mtime_ns": (CLOCK_EPOCH - 100) * SECOND}


BASIC = '{"c": true, "b": 1, "a": {"y": [1, 2.50, "x"], "x": null}}\n'
INVALID = {"rust_status": 502, "rust_error_type": "invalid_json"}

# name -> file state at the variant's --json-path (data/metrics.json in the
# case directory) and, where Rust answers differently, the allowed difference.
JSON_FILE_STATES: dict[str, dict[str, Any]] = {
    "basic": _text(BASIC),
    "meta-object": _text(
        '{"meta": {"collector_ipv6_capable": true, "age_seconds": "stale", '
        '"zeta": [1]}, "v": 1}'
    ),
    "meta-list": _text('{"meta": [1, 2], "v": 1}'),
    "meta-null": _text('{"meta": null}'),
    "meta-string": _text('{"meta": "x", "v": {}}'),
    "empty-object": _text("{}"),
    "unicode": _text(
        '{"z": "snow \\u2603 \\ud83d\\ude00", "ü": "\U0001f600 raw é", '
        '"esc": "\\"\\\\\\/\\n\\t\\b\\f\\r\\u0001\\u007f", "ä": {"é": 1, "Z": 2}}'
    ),
    "numbers": _text(
        '{"big": 123456789012345678901234567890, "neg0": -0, "e2": 1e2, '
        '"f": 1.00, "e16": 1e16, "small": 0.00001, "tie": 181703637716804.125, '
        '"under": 1e-400, "negf": -0.0, "list": [5.0, 1E+2, -12, 0.1, 9007199254740993.0]}'
    ),
    "duplicate-keys": _text('{"a": 1, "a": {"b": 2}, "meta": 5, "meta": {"k": 1}}'),
    "duplicate-overflow": _text('{"a": 1e400, "a": 1}'),
    "whitespace": _text(' \n\t{"a" : 1 }\r\n\n'),
    "depth-127": _text('{"a": ' + "[" * 126 + "]" * 126 + "}"),
    "future-mtime": _text(BASIC, CLOCK_EPOCH + 50),
    "fractional-mtime": {
        "kind": "file",
        "text": BASIC,
        # st_mtime = sec + nsec * 1e-9 rounds up to the next second.
        "mtime_ns": (CLOCK_EPOCH - 10) * SECOND + 999_999_990,
    },
    "epoch-mtime": _text(BASIC, 0),
    "symlink": {**_text(BASIC), "kind": "symlink"},
    "absent": {"kind": "absent"},
    "directory": {"kind": "directory"},
    "broken-symlink": {"kind": "broken-symlink"},
    "parent-is-file": {"kind": "parent-is-file"},
    "unreadable": {**_text(BASIC), "kind": "unreadable"},
    "empty-file": _text(""),
    "syntax-error": _text('{"a": }'),
    "trailing-data": _text('{"a": 1} {"b": 2}'),
    "single-quotes": _text("{'a': 1}"),
    "control-character": _text('{"a": "x\ty"}'),
    "bom": _hex(b"\xef\xbb\xbf{}"),
    # Python's handler raises and drops the connection (D-2).
    "top-level-list": {**_text("[1, 2]"), **INVALID, "d": "D-2"},
    "top-level-null": {**_text("null"), **INVALID, "d": "D-2"},
    "top-level-number": {**_text("42"), **INVALID, "d": "D-2"},
    "top-level-string": {**_text('"meta"'), **INVALID, "d": "D-2"},
    "invalid-utf8": {**_hex(b'{"a": "\xff"}'), **INVALID, "d": "D-2"},
    # int() refuses more than 4300 digits with a ValueError the handler
    # does not catch (D-5).
    "int-4301-digits": {**_text('{"v": ' + "9" * 4301 + "}"), **INVALID, "d": "D-5"},
    # Python serves them; Rust refuses (D-4).
    "nan": {**_text('{"v": NaN}'), **INVALID, "d": "D-4"},
    "infinity": {**_text('{"v": [Infinity, -Infinity]}'), **INVALID, "d": "D-4"},
    "overflow": {**_text('{"v": 1e400}'), **INVALID, "d": "D-4"},
    "lone-surrogate": {**_text('{"v": "\\ud800"}'), **INVALID, "d": "D-4"},
    "depth-128": {
        **_text('{"a": ' + "[" * 127 + "]" * 127 + "}"),
        **INVALID,
        "d": "D-4",
    },
    "reserved-key": {
        **_text('{"$serde_json::private::Number": "1"}'),
        **INVALID,
        "d": "D-4",
    },
}


def json_file_cases(path: str, path_only: bool) -> list[dict[str, Any]]:
    ok = [("Authorization", basic("user", "secret"))]
    gate = [
        ("no-auth", "GET", path, [], "basic"),
        (
            "wrong-password",
            "GET",
            path,
            [("Authorization", basic("user", "wrong"))],
            "basic",
        ),
        ("wrong-path", "GET", "/.well-known/other", ok, "basic"),
        ("query", "GET", path + "?x=1", ok, "basic"),
        ("post", "POST", path, ok + [("Content-Length", "0")], "basic"),
    ]
    rows = [
        {
            "id": case_id,
            "state": state,
            "method": method,
            "target": target,
            "version": "HTTP/1.1",
            "headers": headers,
        }
        for case_id, method, target, headers, state in gate
    ]
    rows += [
        {
            "id": state,
            "state": state,
            "method": "GET",
            "target": path,
            "version": "HTTP/1.1",
            "headers": ok,
        }
        for state in JSON_FILE_STATES
    ]
    return rows


def prepare_state(base: Path, state: dict[str, Any]) -> Path:
    """Puts ``state`` at ``base/data/metrics.json`` (the --json-path)."""
    data = base / "data"
    if data.is_symlink() or data.is_file():
        data.unlink()
    elif data.exists():
        shutil.rmtree(data)
    target = data / "metrics.json"
    kind = state["kind"]
    if kind == "parent-is-file":
        data.write_text("not a directory\n", encoding="utf-8")
        return target
    data.mkdir()
    if kind == "absent":
        return target
    if kind == "directory":
        target.mkdir()
        return target
    if kind == "broken-symlink":
        target.symlink_to("nowhere.json")
        return target
    content = (
        bytes.fromhex(state["hex"]) if "hex" in state else state["text"].encode("utf-8")
    )
    written = data / "target.json" if kind == "symlink" else target
    written.write_bytes(content)
    os.utime(written, ns=(state["mtime_ns"], state["mtime_ns"]))
    if kind == "symlink":
        target.symlink_to("target.json")
    if kind == "unreadable":
        os.chmod(written, 0)
    return target


def frozen_datetime(epoch: int) -> type:
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return datetime.fromtimestamp(epoch, tz=tz)

    return FrozenDatetime


def exchange_or_drop(port: int, case: dict[str, Any]) -> dict[str, Any] | None:
    """`exchange`, or None when the handler raised and closed the connection."""
    try:
        return exchange(port, case)
    except (http.client.RemoteDisconnected, ConnectionResetError):
        return None


JSON_FILE_RECORDED = (
    "Content-Type",
    "Content-Length",
    "WWW-Authenticate",
    "Connection",
)


def json_file_row(
    case: dict[str, Any], state: dict[str, Any], result: dict[str, Any] | None
) -> dict[str, Any]:
    row: dict[str, Any] = dict(case)
    expected_d = state.get("d") if case["id"] == case["state"] else None
    if result is None:
        if expected_d is None:
            raise SystemExit(
                f"{case['id']}: the Python handler crashed without a named D item"
            )
        row.update(status=None, compare="status")
    else:
        row.update(
            status=result["status"],
            response_headers={
                k: result["response_headers"][k] for k in JSON_FILE_RECORDED
            },
        )
        body = result["body"]
        content_type = result["response_headers"]["Content-Type"] or ""
        error = (
            json.loads(body)
            if content_type == "application/json" and result["status"] != 200
            else None
        )
        if content_type.startswith("text/html"):
            row.update(body=body, compare="html")
        elif error is not None and error["error_type"] in (
            "invalid_json",
            "read_error",
        ):
            # D-3: the message after its fixed prefix is the parser's or the
            # OS's text (it names the temporary path).
            # Only the prefix is recorded, so the fixture does not drift with
            # CPython's parser messages.
            row.update(
                error_type=error["error_type"],
                message_prefix=error["message"].split(": ", 1)[0] + ": ",
                compare="error_type",
            )
            # Its Content-Length counts the message, so it is not recorded.
            row["response_headers"].pop("Content-Length")
        else:
            row.update(body=body, compare="bytes")
    if expected_d is not None:
        rust_status = state["rust_status"]
        if result is not None and result["status"] == rust_status:
            raise SystemExit(
                f"{case['id']}: Python answers {rust_status} too; no difference"
            )
        row.update(
            rust_status=rust_status,
            rust_error_type=state["rust_error_type"],
            d=expected_d,
        )
    return row


def build_json_file() -> dict[str, str]:
    if os.geteuid() == 0:
        raise SystemExit(
            "generate the json_file fixtures as an unprivileged user (unreadable-file case)"
        )
    htpasswd = str(FIXTURES / "htpasswd")
    ops_control = ops_control_checkout()
    captured = _CapturedStderr()
    variants_out = []
    with tempfile.TemporaryDirectory() as tmp_name, contextlib.redirect_stderr(
        captured
    ):
        tmp = Path(tmp_name)
        for variant in json_file_variants(tmp, ops_control):
            module = variant["module"]
            module.datetime = frozen_datetime(CLOCK_EPOCH)
            base = tmp / f"case-{variant['variant']}"
            base.mkdir()
            server = socketserver.TCPServer(("127.0.0.1", 0), variant["handler"])
            server.cfg = {  # type: ignore[attr-defined]
                "path": variant["path"],
                "json_path": str(base / "data" / "metrics.json"),
                "htpasswd_file": htpasswd,
            }
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            rows = []
            try:
                for case in json_file_cases(variant["path"], variant["path_only"]):
                    state = JSON_FILE_STATES[case["state"]]
                    prepare_state(base, state)
                    result = exchange_or_drop(server.server_address[1], case)
                    rows.append(json_file_row(case, state, result))
            finally:
                server.shutdown()
                server.server_close()
                prepare_state(base, {"kind": "absent"})
            variants_out.append(
                {
                    "variant": variant["variant"],
                    "repo": variant["repo"],
                    "template": variant["template"],
                    "server_version": variant["handler"].server_version,
                    "argv": variant["argv"],
                    "cases": rows,
                }
            )
    if ops_control is None:
        committed = FIXTURES / "json_file.json"
        kept = (
            [
                v
                for v in json.loads(committed.read_text(encoding="utf-8"))["variants"]
                if v["variant"] == "torrent-vpn"
            ]
            if committed.is_file()
            else []
        )
        if not kept:
            raise SystemExit(
                f"the torrent-vpn variant needs an ops-control checkout ({OPS_CONTROL_ENV})"
            )
        print(
            "json_file: no ops-control checkout, kept the committed torrent-vpn cases",
            file=sys.stderr,
        )
        variants_out += kept
    fixture = {
        "clock_epoch": CLOCK_EPOCH,
        "states": JSON_FILE_STATES,
        "variants": variants_out,
    }
    return {"json_file.json": dump_json(fixture)}


# --------------------------------------------------------------------------

# static (S2e): static-site-httpd.py.j2 on a sample tree (PLAN.md 4.7, D-11)

STATIC = "roles/static_site_deploy/templates/static-site-httpd.py.j2"
STATIC_ARGV = ["static", "--root", "{root}"]
# Every file's mtime: the live site's Last-Modified (2026-10-03 13:57:50 UTC).
STATIC_MTIME = 1_791_035_870
STATIC_DATE = "Sat, 03 Oct 2026 13:57:50 GMT"
# (kind, path below the tree, content or link target, mode). The site root
# is `site/`; `outside.txt` lies next to it.
STATIC_TREE: list[tuple[str, str, str, int]] = [
    ("file", "site/index.html", "<!doctype html><title>benchpack registry snapshot</title>\n", 0o644),
    ("file", "site/report.md", "# Report\n\nbenchpack registry snapshot ünicode\n", 0o644),
    ("file", "site/snapshot.json", '{"benchmarks": [1, 2, 3]}\n', 0o644),
    ("file", "site/style.css", "body { margin: 0 }\n", 0o644),
    ("file", "site/app.js", "console.log(1);\n", 0o644),
    ("file", "site/notes.txt", "plain text\n", 0o644),
    ("file", "site/logo.svg", '<svg xmlns="http://www.w3.org/2000/svg"/>\n', 0o644),
    ("file", "site/data.csv", "a,b\n1,2\n", 0o644),
    ("file", "site/page.htm", "htm page\n", 0o644),
    ("file", "site/data", "no extension\n", 0o644),
    ("file", "site/archive.tar.gz", "not really gzip\n", 0o644),
    ("file", "site/UPPER.HTML", "upper-case extension\n", 0o644),
    ("file", "site/a b.txt", "space in the name\n", 0o644),
    ("file", "site/ü.txt", "non-ASCII name\n", 0o644),
    ("file", "site/.hidden", "dot file\n", 0o644),
    ("file", "site/empty.txt", "", 0o644),
    ("file", "site/private.txt", "unreadable\n", 0o000),
    ("file", "site/sub/index.html", "sub index\n", 0o644),
    ("file", "site/sub/page.html", "sub page\n", 0o644),
    ("file", "site/htm/index.htm", "htm index\n", 0o644),
    ("dir", "site/empty", "", 0o755),
    ("file", "outside.txt", "outside the root\n", 0o644),
    ("symlink", "site/link.txt", "../outside.txt", 0),
    ("symlink", "site/linkdir", "sub", 0),
]
STATIC_HEADERS = (
    "Content-Type",
    "Content-Length",
    "Last-Modified",
    "Location",
    "Connection",
    "Cache-Control",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)
STATIC_ACCESS_LINE = re.compile(r'^127\.0\.0\.1 - (".*" \d{3} -)$')


def static_cases() -> list[dict[str, Any]]:
    """(id, method, target, headers[, version]) plus the Rust expectation
    where the plan allows a difference."""
    ims = [("If-Modified-Since", STATIC_DATE)]
    later = [("If-Modified-Since", "Sat, 03 Oct 2026 14:57:50 GMT")]
    earlier = [("If-Modified-Since", "Sat, 03 Oct 2026 13:57:49 GMT")]
    cases: list[tuple[Any, ...]] = [
        ("root", "GET", "/", []),
        ("root-head", "HEAD", "/", []),
        ("index", "GET", "/index.html", []),
        ("index-head", "HEAD", "/index.html", []),
        ("report-md", "GET", "/report.md", []),
        ("snapshot-json", "GET", "/snapshot.json", []),
        ("css", "GET", "/style.css", []),
        ("js", "GET", "/app.js", []),
        ("txt", "GET", "/notes.txt", []),
        ("svg", "GET", "/logo.svg", []),
        ("csv", "GET", "/data.csv", []),
        ("htm", "GET", "/page.htm", []),
        ("no-extension", "GET", "/data", []),
        ("gz", "GET", "/archive.tar.gz", []),
        ("upper-case-extension", "GET", "/UPPER.HTML", []),
        ("space-encoded", "GET", "/a%20b.txt", []),
        ("non-ascii-encoded", "GET", "/%C3%BC.txt", []),
        ("hidden", "GET", "/.hidden", []),
        ("empty-file", "GET", "/empty.txt", []),
        ("query", "GET", "/index.html?x=1", []),
        ("empty-query", "GET", "/index.html?", []),
        ("double-slash", "GET", "//index.html", []),
        ("inner-double-slash", "GET", "/sub//page.html", []),
        ("dot-segment", "GET", "/./index.html", []),
        ("encoded-slash", "GET", "/sub%2Fpage.html", []),
        ("sub-index", "GET", "/sub/", []),
        ("sub-page", "GET", "/sub/page.html", []),
        ("dir-redirect", "GET", "/sub", []),
        ("dir-redirect-head", "HEAD", "/sub", []),
        ("dir-redirect-query", "GET", "/sub?x=1", []),
        ("dir-redirect-empty-query", "GET", "/sub?", []),
        ("dir-redirect-double-slash", "GET", "//sub", []),
        ("dir-redirect-encoded", "GET", "/s%75b", []),
        ("empty-dir-redirect", "GET", "/empty", []),
        ("symlink-dir", "GET", "/linkdir/page.html", []),
        ("symlink-outside", "GET", "/link.txt", []),
        ("htm-index", "GET", "/htm/", [], "HTTP/1.1", {"rust_status": 404, "d": "D-11"}),
        # list_directory's "Directory listing is disabled" page; Rust sends
        # the "File not found" page (ServeDir does not say why).
        ("empty-dir", "GET", "/empty/", [], "HTTP/1.1", {"rust_status": 404, "d": "D-3"}),
        ("missing", "GET", "/missing.html", []),
        ("missing-head", "HEAD", "/missing.html", []),
        ("missing-dir", "GET", "/missing/", []),
        ("file-trailing-slash", "GET", "/index.html/", []),
        ("file-as-dir", "GET", "/index.html/x", []),
        ("unreadable", "GET", "/private.txt", []),
        ("parent-escape", "GET", "/../outside.txt", []),
        ("parent-inside", "GET", "/sub/../index.html", [], "HTTP/1.1", {"rust_status": 404, "d": "D-11"}),
        ("encoded-parent", "GET", "/sub/%2e%2e/index.html", [], "HTTP/1.1", {"rust_status": 404, "d": "D-11"}),
        ("backslash", "GET", "/sub%5Cpage.html", []),
        ("nul", "GET", "/index.html%00", [], "HTTP/1.1", {"rust_status": 404, "d": "D-2"}),
        ("invalid-utf8", "GET", "/%FF", []),
        ("absolute-form", "GET", "http://127.0.0.1/index.html", []),
        ("ims-equal", "GET", "/index.html", ims),
        ("ims-equal-head", "HEAD", "/index.html", ims),
        ("ims-later", "GET", "/index.html", later),
        ("ims-earlier", "GET", "/index.html", earlier),
        ("ims-directory-index", "GET", "/", ims),
        ("ims-invalid", "GET", "/index.html", [("If-Modified-Since", "yesterday")]),
        (
            "ims-numeric-zone",
            "GET",
            "/index.html",
            [("If-Modified-Since", "Sat, 03 Oct 2026 13:57:50 +0000")],
            "HTTP/1.1",
            {"rust_status": 200, "d": "D-11"},
        ),
        ("ims-with-if-none-match", "GET", "/index.html", ims + [("If-None-Match", '"x"')]),
        ("if-none-match-star", "GET", "/index.html", [("If-None-Match", "*")]),
        ("if-match", "GET", "/index.html", [("If-Match", '"nope"')]),
        ("if-unmodified-since", "GET", "/index.html", [("If-Unmodified-Since", "Sat, 03 Oct 2026 12:00:00 GMT")]),
        ("range", "GET", "/index.html", [("Range", "bytes=0-4")], "HTTP/1.1", {"rust_status": 206, "d": "D-11"}),
        ("range-multi", "GET", "/index.html", [("Range", "bytes=0-1,3-4")]),
        ("range-unsatisfiable", "GET", "/index.html", [("Range", "bytes=9999-")], "HTTP/1.1", {"rust_status": 416, "d": "D-11"}),
        ("range-malformed", "GET", "/index.html", [("Range", "lines=1-2")], "HTTP/1.1", {"rust_status": 416, "d": "D-11"}),
        ("post", "POST", "/index.html", [("Content-Length", "0")]),
        ("put", "PUT", "/new.txt", [("Content-Length", "0")]),
        ("delete", "DELETE", "/index.html", []),
        ("options", "OPTIONS", "/index.html", []),
        ("lowercase-get", "get", "/index.html", []),
        ("http10", "GET", "/index.html", [], "HTTP/1.0"),
        ("http10-missing", "GET", "/missing.html", [], "HTTP/1.0"),
    ]
    rows = []
    for case in cases:
        case_id, method, target, headers = case[:4]
        row: dict[str, Any] = {
            "id": case_id,
            "method": method,
            "target": target,
            "version": case[4] if len(case) > 4 else "HTTP/1.1",
            "headers": headers,
        }
        row.update(case[5] if len(case) > 5 else {})
        rows.append(row)
    return rows


def build_static_tree(base: Path) -> Path:
    for kind, name, content, mode in STATIC_TREE:
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if kind == "file":
            path.write_text(content, encoding="utf-8")
        elif kind == "dir":
            path.mkdir(exist_ok=True)
        else:
            path.symlink_to(content)
    for kind, name, _content, mode in STATIC_TREE:
        path = base / name
        if kind == "file":
            os.utime(path, (STATIC_MTIME, STATIC_MTIME))
            path.chmod(mode)
    return base / "site"


def static_exchange(port: int, case: dict[str, Any]) -> dict[str, Any]:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(raw_request(case))
            response = http.client.HTTPResponse(sock, method=case["method"])
            response.begin()
            body = response.read()
    except (http.client.HTTPException, ConnectionError):
        # The handler raised: socketserver closes the connection unanswered.
        return {"status": None}
    return {
        "status": response.status,
        "response_headers": {name: response.getheader(name) for name in STATIC_HEADERS},
        "body": body.decode("utf-8"),
    }


@contextlib.contextmanager
def builtin_mimetypes():
    """``mimetypes`` without the host's ``/etc/mime.types``-style files, so
    the fixture does not depend on the machine that generates it (the live
    site's types are pinned from staging, ``parity/static_real_site.json``)."""
    import mimetypes

    saved = mimetypes.knownfiles
    mimetypes.knownfiles = []
    mimetypes.init()
    try:
        yield
    finally:
        mimetypes.knownfiles = saved
        mimetypes.init()


def build_static() -> dict[str, str]:
    import functools

    out = []
    captured_out = _CapturedStderr()
    captured_err = _CapturedStderr()
    with tempfile.TemporaryDirectory() as tmp_name, contextlib.redirect_stdout(
        captured_out
    ), contextlib.redirect_stderr(captured_err), builtin_mimetypes():
        tmp = Path(tmp_name)
        root = build_static_tree(tmp / "tree")
        module = load_module(
            "static_site",
            STATIC,
            {
                "static_site_path": str(root),
                "static_site_bind_host": "127.0.0.1",
                "static_site_port": 0,
            },
            tmp,
        )
        handler = functools.partial(module.StaticHandler, directory=str(root))
        server = module.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for case in static_cases():
                captured_out.take()
                result = static_exchange(server.server_address[1], case)
                access = [
                    m.group(1)
                    for line in captured_out.take().splitlines()
                    if (m := STATIC_ACCESS_LINE.match(line))
                ]
                captured_err.take()
                row = {**case, **result, "access_log": access[0] if access else None}
                if result["status"] is None:
                    compare = "no-response"
                elif "rust_status" in case:
                    compare = "status"
                elif (result["response_headers"]["Content-Type"] or "").startswith(
                    "text/html;charset=utf-8"
                ):
                    # send_error's page (D-3): compared without the <style>
                    # block CPython 3.14 added; Content-Length not compared.
                    compare = "html"
                else:
                    compare = "bytes"
                row["compare"] = compare
                out.append(row)
        finally:
            server.shutdown()
            server.server_close()
            for _kind, name, _content, mode in STATIC_TREE:
                if mode == 0o000:
                    (tmp / "tree" / name).chmod(0o644)
    return {
        "static.json": dump_json(
            {
                "template": STATIC,
                "argv": STATIC_ARGV,
                "mtime": STATIC_MTIME,
                "tree": [list(entry) for entry in STATIC_TREE],
                "cases": out,
            }
        )
    }


# --------------------------------------------------------------------------

FAMILIES: dict[str, tuple[bool, Callable[[], dict[str, str]]]] = {
    "float_repr": (False, build_float_repr),
    "pyjson": (False, build_pyjson),
    "meta": (False, build_meta),
    "auth": (True, build_auth),
    "http_common": (True, build_http_common),
    "script": (True, build_script),
    "apt_state": (True, build_apt_state),
    "json_file": (True, build_json_file),

    "static": (True, build_static),
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
