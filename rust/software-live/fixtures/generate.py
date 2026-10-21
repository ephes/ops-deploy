#!/usr/bin/env python3
"""Generate the fixtures of the Rust port of software_live from the Python code.

The Python program ``roles/software_live/files/software_live.py`` is the
oracle (rust/software-live/PLAN.md 6.1): every expected value in this
directory is what the real Python functions return for a fixed corpus, with
the clock, the observations and the host patched the way the Python tests
patch them. The Rust tests read the files with ``include_str!``;
``tests/test_software_live_rust_fixtures.py`` regenerates them in memory and
fails when a committed file differs.

Usage (stdlib only; the hosts run Python 3.12 and 3.13)::

    python3 -I rust/software-live/fixtures/generate.py          # rewrite every file
    python3 -I rust/software-live/fixtures/generate.py --check  # exit 1 on drift

``just rs-software-live-fixtures`` generates under 3.12 and checks under
3.13. Each slice adds its fixture builders to ``GENERATORS``.

An exception is recorded as its class, and with its message only where the
message is part of the contract: the texts the Python code raises itself
(found in its source) and ``KeyError``. Interpreter texts differ between
Python versions and are not compared (PLAN.md 4.2 item 5). Cases that carry a
``p3`` tag are intentional divergences of PLAN.md 4.2: Python accepts the
input, the Rust code refuses it.
"""

from __future__ import annotations

import argparse
import ast
import collections
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import math
import os
import random
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self
from unittest import mock

FIXTURES_DIR = Path(__file__).resolve().parent
REPO = FIXTURES_DIR.parents[2]
PROGRAM = REPO / "roles" / "software_live" / "files" / "software_live.py"


def load_oracle() -> Any:
    spec = importlib.util.spec_from_file_location("software_live_oracle", PROGRAM)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


live = load_oracle()


def own_messages() -> frozenset[str]:
    """Every literal message of a ``raise X("...")`` in the Python program."""
    messages = set()
    for node in ast.walk(ast.parse(PROGRAM.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and node.exc.args
            and isinstance(node.exc.args[0], ast.Constant)
            and isinstance(node.exc.args[0].value, str)
        ):
            messages.add(node.exc.args[0].value)
    return frozenset(messages)


OWN_MESSAGES = own_messages()


def error(exc: BaseException) -> dict[str, Any]:
    message = str(exc)
    contract = isinstance(exc, KeyError) or message in OWN_MESSAGES
    return {"class": type(exc).__name__, "message": message if contract else None}


# ------------------------------------------------------------------ pyjson


def gen_pyjson() -> dict[str, Any]:
    """json.loads / json.dumps(sort_keys=True) / repr(float) / str()."""
    dumps_texts = {
        "scalars": '[true, false, null, 0, 1, -1, "", "x"]',
        "nested": '{"b": {"d": [1, {"f": null, "e": []}], "c": {}}, "a": [[], {}]}',
        "key_order": '{"b": 1, "a": 2, "B": 3, "\\u00e9": 4, "aa": 5, "\\ud83d\\ude00": 6, "~": 7}',
        "duplicate_keys": '{"a": 1, "a": 2}',
        "non_ascii": '["\\u00e9", "\\u65e5\\u672c", "\\ud83d\\ude00", "\\u2028\\u2029", "\\ufeff", "\\uffff"]',
        "raw_non_ascii": '["\u00e9\u65e5\U0001f600"]',
        "controls": '["' + "".join(f"\\u{c:04x}" for c in range(0x20)) + '\\u007f"]',
        "escapes": r'["\"", "\\", "/", "\/", "\b\f\n\r\t", "a\u0000b"]',
        "big_ints": "[18446744073709551617, -18446744073709551617, 123456789012345678901234567890]",
        "zero_ints": "[-0, 0, -0e0, 0e0]",
        "floats_exact": "[1E2, 1e2, 1.0, 100.0, 1e16, 1e15, 1e-05, 0.0001, 0.1, -0.0, 2.5e-07]",
        "floats_extreme": "[1e400, -1e400, 1e-400, 5e-324, 1.7976931348623157e308, 2.2250738585072014e-308]",
        "floats_digits": "[123456789012345678901234567890.5, 0.30000000000000004, 3.141592653589793238462643, 1.5e300]",
        "floats_boundaries": "[9999999999999998.0, 1e16, 12345678901234567.0, 0.001, 0.00012345, 1.2345e-05]",
        "whitespace": ' \t\n\r{ "a" :\n[ 1 ,2 ] } \n',
        "empty_containers": '{"a": {}, "b": [], "c": [{}], "d": {"e": []}}',
        "policy_like": json.dumps(
            {"host": "h\u00f4st", "extra": {"n": [1, 2.5, None, True]}, "port": 5432}
        ),
        "deep_128": "[" * 127 + "1" + "]" * 127,
        "serde_number_token": '[{"$serde_json::private::Number": "7"}, {"$serde_json::private::Number": 7.5}]',
        "long_string": json.dumps("x" * 5000 + "\u00e9" * 100),
        "int_4300_digits": "1" * 4300,
    }
    dumps = []
    for case_id, text in dumps_texts.items():
        dumps.append(
            {"id": case_id, "text": text, "dumps": json.dumps(json.loads(text), sort_keys=True)}
        )

    loads_texts = {
        "valid_object": ('{"a": 1}', None),
        "trailing_garbage": ('{"a": 1} x', None),
        "trailing_comma": ('{"a": 1,}', None),
        "single_quotes": ("{'a': 1}", None),
        "leading_zero": ("01", None),
        "bare_minus": ("-", None),
        "dot_only_fraction": ("1.", None),
        "raw_control_in_string": ('"a\x01b"', None),
        "raw_newline_in_string": ('"a\nb"', None),
        "bom": ('\ufeff{"a": 1}', None),
        "empty": ("", None),
        "int_4301_digits": ("1" * 4301, None),
        "negative_int_4300_digits": ("-" + "1" * 4300, None),
        "negative_int_4301_digits": ("-" + "1" * 4301, None),
        "replaced_duplicate_4301_digits": ('{"a": ' + "1" * 4301 + ', "a": 0}', None),
        "serde_number_token_key": ('{"$serde_json::private::Number": "7"}', None),
        "nan": ("NaN", "non-standard-json"),
        "infinity": ('{"a": Infinity}', "non-standard-json"),
        "negative_infinity": ("[-Infinity]", "non-standard-json"),
        "lone_high_surrogate": ('"\\ud800"', "non-standard-json"),
        "lone_low_surrogate": ('{"k": "\\udc00x"}', "non-standard-json"),
        "nesting_129": ("[" * 129 + "]" * 129, "nesting"),
    }
    loads = []
    for case_id, (text, p3) in loads_texts.items():
        case: dict[str, Any] = {"id": case_id, "text": text, "error": None}
        try:
            json.loads(text)
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
        if p3:
            case["p3"] = p3
        loads.append(case)

    rng = random.Random(20261021)
    values = [
        0.0, -0.0, 1.0, 0.1, 1e16, 1e15, 9999999999999998.0, 1e-4, 1e-5, 0.00011, 5e-324,
        2.2250738585072014e-308, 1.7976931348623157e308, 1 / 3, 2 / 3, 1e22, 1e23, 123456.789,
    ]
    for _ in range(1500):
        bits = rng.getrandbits(64)
        value = struct.unpack(">d", bits.to_bytes(8, "big"))[0]
        if math.isfinite(value):
            values.append(value)
    for exponent in range(-30, 31):
        for _ in range(8):
            values.append(rng.uniform(1, 10) * 10.0**exponent * rng.choice((1, -1)))
    # Exact ties: in [2**46, 2**47) the doubles are 1/64 apart, so x.625 has
    # two shortest candidates (x.62 and x.63) at the same distance; Python
    # takes the even digit.
    for _ in range(200):
        tie = rng.randrange(2**46, 2**47) + rng.choice((0.125, 0.375, 0.625, 0.875))
        values.append(tie * rng.choice((1, -1)))
    floats = [
        {"bits": struct.pack(">d", value).hex(), "repr": json.dumps(value)} for value in values
    ]

    py_str_texts = [
        "true", "false", "null", "24", "-0", "24.04", "24.10", "1e16", "1E2", "1e400", "-1e400",
        "18446744073709551617", '"24.04"', "0.0001", "1e-05", "-0.0", "17.0",
    ]
    py_str = [{"text": text, "str": str(json.loads(text))} for text in py_str_texts]
    return {"dumps": dumps, "loads": loads, "floats": floats, "py_str": py_str}


# ------------------------------------------------------------------ version


def gen_version() -> dict[str, Any]:
    whitespace = [c for c in range(0x110000) if chr(c).isspace()]
    import re

    assert all(
        bool(re.fullmatch(r"\s", chr(c))) == chr(c).isspace() for c in range(0x110000)
    ), "Python's \\s is no longer str.isspace()"

    inputs = {
        "version": [
            "v3.7.9", "3.7.12", "3.7", "3.7.12-rc1", "development", "3.7.12 junk", "V3.7.9",
            "vv3.7.9", " 3.7.9", "3.7.9\n", "3.7.9 ", "03.007.9", "99999999999999999999999.1.2",
            "", "3..7", "3.7.9.1", "v", "3.7.x", "+3.7.9", "-3.7.9", "3.7.9\x00",
        ],
        "numeric_version": [
            "17.6", "17.6 (Ubuntu 17.6-1.pgdg24.04+1)", "17", " 17.6 ", "17.6\n", "17.6\nmore",
            "17.6 a\nb", "\x1c17.6\x1c", "17.6\x1cx", "17.6\u3000beta", "17.6\u200bbeta", "17.6.",
            "17.6a", "1.2.3.4.5", "", "v17.6", "17.6\t(x)", "17.6\x85x", "\u00a017.6\u2028",
            "17.6 \r", "17.6\r\nx", "17.6  ", "0.0", "007.08",
            "123456789012345678901234567890.1",
        ],
    }
    # Python's int() limit: 4300 digits, leading zeros included.
    inputs["version"] += ["1" * 4300 + ".0.0", "1" * 4301 + ".0.0", "0" * 4301 + ".0.0"]
    inputs["numeric_version"] += ["17." + "1" * 4300, "17." + "1" * 4301 + " x", "0" * 4301 + ".1"]
    p3_inputs = {
        "version": ["\u0663.\u0667.\u0669", "3.7.\uff19"],
        "numeric_version": ["\u0661\u0667.\u0666", "17.\U0001d7d8"],
    }
    cases = []
    for function, values in inputs.items():
        for value in values:
            case: dict[str, Any] = {"function": function, "input": value, "result": None, "error": None}
            try:
                case["result"] = [str(part) for part in getattr(live, function)(value)]
            except Exception as exc:  # noqa: BLE001 - the oracle's answer
                case["error"] = error(exc)
            cases.append(case)
    for function, values in p3_inputs.items():
        for value in values:
            result = [str(part) for part in getattr(live, function)(value)]
            cases.append(
                {"function": function, "input": value, "result": result, "error": None,
                 "p3": "unicode-digits"}
            )

    pairs = [
        ("version", "v3.7.9", "3.7.12"), ("version", "3.7.9", "v3.7.9"),
        ("version", "3.10.0", "3.9.9"), ("version", "3.7.12", "3.7.9"),
        ("version", "99999999999999999999.0.0", "100000000000000000000.0.0"),
        ("version", "03.7.9", "3.7.9"), ("version", "4.0.0", "3.99.99"),
        ("numeric_version", "17.6", "17.6.1"), ("numeric_version", "17.10", "17.9"),
        ("numeric_version", "17.06", "17.6"), ("numeric_version", "17.6 (x)", "17.6"),
        ("numeric_version", "18.0", "17.99.99"), ("numeric_version", "17.6.0", "17.6"),
    ]
    comparisons = []
    for function, left, right in pairs:
        a, b = getattr(live, function)(left), getattr(live, function)(right)
        ordering = "lt" if a < b else "gt" if a > b else "eq"
        comparisons.append({"function": function, "left": left, "right": right, "ordering": ordering})
    return {"python_whitespace": whitespace, "cases": cases, "comparisons": comparisons}


# ------------------------------------------------------------------ policy

BASE = {
    "host": "example",
    "os": {"expected_id": "ubuntu", "desired_cycle": "24.04", "product": "ubuntu"},
    "postgresql": {"expected": True, "desired_major": "17", "cluster": "main", "port": 5432},
    "traefik": {
        "expected": True,
        "unit": "traefik.service",
        "binary_path": "/usr/local/bin/traefik",
        "desired_version": "3.7.9",
    },
}
MISSING = object()


def mutate(path: str, value: Any) -> str:
    """BASE with ``path`` (dotted) set to ``value`` (MISSING deletes it), as text."""
    policy = json.loads(json.dumps(BASE))
    *parents, last = path.split(".") if path else [""]
    target = policy
    for part in parents:
        target = target[part]
    if value is MISSING:
        del target[last]
    else:
        target[last] = value
    return json.dumps(policy)


def with_raw(path: str, raw: str) -> str:
    """BASE with ``path`` set to the raw JSON token ``raw``."""
    marker = "__RAW_TOKEN__"
    return mutate(path, marker).replace(f'"{marker}"', raw)


def hashed(policy: Any) -> str:
    """``policy_sha256`` as ``collect`` computes it (every observation patched)."""
    unknown = {"status": "unknown", "observed": False, "issues": []}
    with (
        mock.patch.object(live, "upstream", return_value={"status": "not_applicable"}),
        mock.patch.object(live, "lifecycle_upstream", return_value={"status": "not_applicable"}),
        mock.patch.object(live, "observe_traefik", return_value=dict(unknown)),
        mock.patch.object(live, "observe_os", return_value=dict(unknown)),
        mock.patch.object(live, "observe_postgresql", return_value=dict(unknown)),
        mock.patch.object(
            live, "observe_apt",
            return_value={"status": "unknown", "indexes_fresh": False, "pending_security_count": None},
        ),
        mock.patch.object(live.time, "time", return_value=1_760_000_000.0),
    ):
        return live.collect(policy)["policy_sha256"]


def policy_texts() -> list[tuple[str, str, str | None]]:
    cases: list[tuple[str, str, str | None]] = [("base", json.dumps(BASE), None)]
    add = lambda case_id, text, p3=None: cases.append((case_id, text, p3))

    for case_id, text in {
        "not_mapping_list": "[]", "not_mapping_str": '"x"', "not_mapping_int": "1",
        "not_mapping_null": "null", "empty_mapping": "{}",
    }.items():
        add(case_id, text)
    # host
    for case_id, value in {"missing": MISSING, "empty": "", "int": 1, "null": None, "list": ["a"],
                           "non_ascii": "h\u00f4st-\u65e5\u672c", "space": " "}.items():
        add(f"host_{case_id}", mutate("host", value))
    # traefik
    for case_id, value in {"missing": MISSING, "list": [], "str": "x", "int": 1, "null": None,
                           "bool": True}.items():
        add(f"traefik_{case_id}", mutate("traefik", value))
    for key, values in {
        "expected": {"missing": MISSING, "str": "true", "int": 1, "null": None, "false": False},
        "unit": {"missing": MISSING, "other": "traefik", "list": ["traefik.service"], "null": None},
        "binary_path": {"missing": MISSING, "sh": "/bin/sh", "tmp": "/tmp/proxy", "list": [],
                        "dict": {}, "int": 1, "null": None, "usr_bin": "/usr/bin/traefik",
                        "bool": True},
        "desired_version": {"missing": MISSING, "null": None, "short": "3.7", "v": "v3.7.9",
                            "int": 3, "false": False, "list": [], "rc": "3.7.9-rc1",
                            "dict": {}},
    }.items():
        for case_id, value in values.items():
            add(f"traefik_{key}_{case_id}", mutate(f"traefik.{key}", value))
    add("traefik_float_expected", with_raw("traefik.expected", "1.0"))
    # os
    for case_id, value in {"missing": MISSING, "list": [], "str": "x", "null": None}.items():
        add(f"os_{case_id}", mutate("os", value))
    for key, values in {
        "expected_id": {"missing": MISSING, "centos": "centos", "list": ["ubuntu"], "dict": {},
                        "upper": "Ubuntu", "debian": "debian", "null": None},
        "product": {"missing": MISSING, "debian": "debian", "null": None},
        "desired_cycle": {"missing": MISSING, "three_parts": "24.04.1", "null": None,
                          "true": True, "empty": "", "list": [24], "newline": "24.04\n",
                          "negative": -1, "int": 24, "thirteen": "13", "dict": {}},
    }.items():
        for case_id, value in values.items():
            add(f"os_{key}_{case_id}", mutate(f"os.{key}", value))
    for case_id, raw in {"float": "24.04", "float_trailing_zero": "24.10", "exponent": "1E2",
                         "big_float": "1e16", "big_int": "18446744073709551617",
                         "minus_zero": "-0", "float_zero_fraction": "24.0",
                         "infinite": "1e400"}.items():
        add(f"os_desired_cycle_raw_{case_id}", with_raw("os.desired_cycle", raw))
    add("os_debian_policy", json.dumps({**BASE, "os": {"expected_id": "debian",
                                                        "desired_cycle": "13", "product": "debian"}}))
    # postgresql
    for case_id, value in {"missing": MISSING, "list": [], "str": "x", "null": None}.items():
        add(f"postgresql_{case_id}", mutate("postgresql", value))
    for key, values in {
        "expected": {"missing": MISSING, "str": "yes", "null": None, "int": 1},
        "desired_major": {"missing": MISSING, "int": 17, "minor": "17.1", "null": None,
                          "empty": "", "list": ["17"]},
        "cluster": {"missing": MISSING, "null": None, "int": 1, "digit_first": "9main",
                    "space": "ma in", "underscore_dash": "_x-1", "newline": "main\n",
                    "non_ascii": "m\u00e4in", "list": ["main"]},
        "port": {"missing": MISSING, "true": True, "zero": 0, "max": 65535, "over": 65536,
                 "one": 1, "str": "5432", "huge": 99999999999999999999999, "negative": -1,
                 "null": None},
    }.items():
        for case_id, value in values.items():
            add(f"postgresql_{key}_{case_id}", mutate(f"postgresql.{key}", value))
    for case_id, raw in {"float": "17.0", "exponent": "1e1"}.items():
        add(f"postgresql_desired_major_raw_{case_id}", with_raw("postgresql.desired_major", raw))
    for case_id, raw in {"float": "5432.0", "exponent": "5.432e3", "minus_zero": "-0"}.items():
        add(f"postgresql_port_raw_{case_id}", with_raw("postgresql.port", raw))
    add("postgresql_not_expected_ignores_the_rest",
        mutate("postgresql", {"expected": False, "desired_major": None, "cluster": 7, "port": "x"}))
    # apt_max_age_seconds
    for case_id, raw in {"null": "null", "below": "3599", "min": "3600", "max": "1209600",
                         "above": "1209601", "float": "172800.0", "true": "true", "str": '"3600"',
                         "exponent": "1e4", "huge": "1" + "0" * 40, "minus_zero": "-0"}.items():
        add(f"apt_max_age_seconds_{case_id}", with_raw("apt_max_age_seconds", raw))
    # first failing check wins
    add("order_host_before_traefik", json.dumps({"host": ""}))
    add("order_traefik_before_os", json.dumps({**BASE, "traefik": {"expected": "x"}, "os": None}))
    add("order_os_before_postgresql", json.dumps({**BASE, "os": {}, "postgresql": None}))
    add("order_postgresql_before_age",
        json.dumps({**json.loads(mutate("postgresql.expected", None)), "apt_max_age_seconds": 1}))
    # policy_sha256 (extra keys go into the hash)
    for case_id, raw in {
        "strings": json.dumps("\u00e9\u65e5\u672c\U0001f600\u2028\x00\x1f\x7f\"\\/"),
        "raw_non_ascii": '"\u00e9\U0001f600"',
        "ints": "[18446744073709551617, -18446744073709551617, -0, 0, 123456789012345678]",
        "floats": "[1E2, 1.0, 1e16, 1e-05, 0.1, -0.0, 5e-324, 1.7976931348623157e308, 2.5e-07]",
        "infinite": "[1e400, -1e400, 1e-400]",
        "scalars": "[true, false, null]",
        "nested": '{"z": {"y": [{"b": 1, "a": 2}]}, "a": {}}',
        "non_ascii_keys": '{"\\u00e9": 1, "e": 2, "\\ud83d\\ude00": 3, "E": 4}',
        "duplicate_keys": '{"a": 1, "a": 2}',
        "deep_120": "[" * 120 + "]" * 120,
    }.items():
        add(f"hash_extra_{case_id}", with_raw("extra", raw))
    add("hash_extra_serde_number_token",
        with_raw("extra", '{"$serde_json::private::Number": "7", "n": {"$serde_json::private::Number": 7}}'))
    add("postgresql_port_serde_number_token",
        with_raw("postgresql.port", '{"$serde_json::private::Number": "5432"}'))
    add("traefik_desired_version_4301_digits", mutate("traefik.desired_version", "1" * 4301 + ".0.0"))
    add("traefik_desired_version_4300_digits", mutate("traefik.desired_version", "1" * 4300 + ".0.0"))
    add("hash_key_order", json.dumps({key: BASE[key] for key in reversed(list(BASE))}))
    add("hash_pretty_printed", json.dumps(BASE, indent=4))
    add("hash_desired_cycle_float", with_raw("os.desired_cycle", "24.04"))
    add("hash_apt_age", with_raw("apt_max_age_seconds", "3600"))
    add("hash_non_ascii_host", mutate("host", "h\u00f4st"))
    # P3: Python accepts these, the Rust code refuses them (PLAN.md 4.2)
    add("p3_nan_extra", with_raw("extra", "NaN"), "non-standard-json")
    add("p3_infinity_extra", with_raw("extra", "[Infinity, -Infinity]"), "non-standard-json")
    add("p3_lone_surrogate_host", with_raw("host", '"h\\ud800"'), "non-standard-json")
    add("p3_nesting_129", with_raw("extra", "[" * 128 + "]" * 128), "nesting")
    add("p3_unicode_digits_cycle", mutate("os.desired_cycle", "\u0662\u0664.\u0660\u0664"),
        "unicode-digits")
    add("p3_unicode_digits_major", mutate("postgresql.desired_major", "\uff11\uff17"),
        "unicode-digits")
    add("p3_unicode_digits_version", mutate("traefik.desired_version", "3.7.\u0669"),
        "unicode-digits")
    return cases


def gen_policy() -> list[dict[str, Any]]:
    out = []
    seen = set()
    for case_id, text, p3 in policy_texts():
        assert case_id not in seen, case_id
        seen.add(case_id)
        case: dict[str, Any] = {"id": case_id, "text": text}
        try:
            value = json.loads(text)
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["load_error"] = error(exc)
        else:
            try:
                live.validate_policy(value)
            except Exception as exc:  # noqa: BLE001 - the oracle's answer
                case["error"] = error(exc)
            else:
                case["policy_sha256"] = hashed(value)
        if p3:
            assert "policy_sha256" in case, f"{case_id}: a P3 case must be one Python accepts"
            case["p3"] = p3
        out.append(case)
    return out


# ------------------------------------------------------------------ report

OBSERVED_OK = {"observed": True, "status": "ok", "issues": []}
APT_OK = {
    "status": "ok",
    "pending_security_count": 0,
    "pending_security_updates": [],
    "indexes_fresh": True,
    "oldest_security_index_age_seconds": 3600.5,
    "index_age_limit_seconds": 172800,
    "index_source": "cached security InRelease publication mtimes; no refresh performed",
}
APT_UNKNOWN = {
    "status": "unknown",
    "error": "APT observation failed (ImportError)",
    "indexes_fresh": False,
    "pending_security_count": None,
}


def summary_cases() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    traefik_ok = {**OBSERVED_OK, "expected": True, "binary_path": "/usr/local/bin/traefik",
                  "installed": {"version": "3.7.9", "sha256": "ab"}, "main_pid": 11}
    warning = lambda item, issue: {**item, "status": "warning", "issues": [issue]}
    unknown = lambda item, text: {**item, "status": "unknown", "error": text}
    all_ok = {"traefik": traefik_ok, "os": {**OBSERVED_OK, "id": "ubuntu", "cycle": "24.04"},
              "postgresql": {**OBSERVED_OK, "expected": True, "server_version": "17.6"},
              "apt": APT_OK}
    not_expected = {**BASE, "traefik": {**BASE["traefik"], "expected": False},
                    "postgresql": {"expected": False}}
    cases = [
        ("all_ok", BASE, all_ok),
        ("traefik_warning", BASE, {**all_ok, "traefik": warning(traefik_ok, "outdated_running_version")}),
        ("traefik_not_observed", BASE, {**all_ok, "traefik": unknown(
            {**traefik_ok, "observed": False}, "ValueError: service stopped or managed binary missing")}),
        ("os_unknown_but_observed", BASE, {**all_ok, "os": unknown(all_ok["os"], "x")}),
        ("os_not_observed", BASE, {**all_ok, "os": {"observed": False, "status": "unknown", "issues": []}}),
        ("postgresql_warning", BASE, {**all_ok, "postgresql": warning(all_ok["postgresql"], "outdated_minor")}),
        ("postgresql_not_observed", BASE, {**all_ok, "postgresql": {
            "observed": False, "status": "unknown", "issues": ["desired_major_drift"],
            "server_version": "16.1", "error": "ValueError: lifecycle upstream unavailable"}}),
        ("apt_unknown", BASE, {**all_ok, "apt": APT_UNKNOWN}),
        ("apt_pending", BASE, {**all_ok, "apt": {**APT_OK, "pending_security_count": 3,
                                                 "pending_security_updates": [{"package": "a:amd64"}]}}),
        ("apt_stale_indexes", BASE, {**all_ok, "apt": {**APT_OK, "indexes_fresh": False}}),
        ("apt_count_float_zero", BASE, {**all_ok, "apt": {**APT_OK, "pending_security_count": 0.0}}),
        ("apt_count_false", BASE, {**all_ok, "apt": {**APT_OK, "pending_security_count": False}}),
        ("apt_count_true", BASE, {**all_ok, "apt": {**APT_OK, "pending_security_count": True}}),
        ("apt_status_other", BASE, {**all_ok, "apt": {**APT_OK, "status": "warning"}}),
        ("nothing_expected", not_expected, {
            "traefik": {"expected": False, "observed": True, "present": False, "status": "ok", "issues": []},
            "os": all_ok["os"],
            "postgresql": {"expected": False, "observed": True, "present": False, "status": "ok",
                           "issues": [], "clusters": []},
            "apt": APT_OK}),
        ("unexpected_installations", not_expected, {
            "traefik": {"expected": False, "observed": True, "present": True, "status": "warning",
                        "issues": ["unexpected_installation"]},
            "os": warning(all_ok["os"], "standard_support_ended"),
            "postgresql": {"expected": False, "observed": True, "present": True, "status": "warning",
                           "issues": ["unexpected_cluster"], "clusters": [{"major": "16"}]},
            "apt": APT_OK}),
        ("everything_unknown", BASE, {
            name: {"observed": False, "status": "unknown", "issues": [], "error": "OSError: x"}
            for name in ("traefik", "os", "postgresql")} | {"apt": APT_UNKNOWN}),
    ]
    return cases


def run_collect(policy: dict[str, Any], observations: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    calls: list[str] = []

    def record(name: str, value: Any) -> Callable[..., Any]:
        def answer(*args: Any) -> Any:
            calls.append(name + "".join(f":{a}" for a in args if isinstance(a, str)))
            return json.loads(json.dumps(value))
        return answer

    times = iter([1_760_000_000.25, 1_760_000_042.75])
    with (
        mock.patch.object(live, "upstream", side_effect=record("upstream", {"status": "ok", "version": "3.7.9"})),
        mock.patch.object(live, "lifecycle_upstream", side_effect=record("lifecycle_upstream", {"status": "ok"})),
        mock.patch.object(live, "observe_traefik", side_effect=record("observe_traefik", observations["traefik"])),
        mock.patch.object(live, "observe_os", side_effect=record("observe_os", observations["os"])),
        mock.patch.object(live, "observe_postgresql",
                          side_effect=record("observe_postgresql", observations["postgresql"])),
        mock.patch.object(live, "observe_apt", side_effect=record("observe_apt", observations["apt"])),
        mock.patch.object(live.time, "time", side_effect=lambda: (calls.append("time"), next(times))[1]),
    ):
        return live.collect(json.loads(json.dumps(policy))), calls


FRESH_SUMMARY = {key: True for key in (
    "observation_ok", "os_ok", "postgresql_ok", "traefik_ok", "security_updates_ok", "apt_indexes_fresh")}


def freshness_cases() -> list[tuple[str, str, float]]:
    state = lambda **changes: json.dumps(
        {"schema_version": 2, "generated_at_epoch": 1000.5, "host": "h", "summary": FRESH_SUMMARY,
         **changes})
    raw = lambda token: state(generated_at_epoch="__T__").replace('"__T__"', token)
    now = 2000.0
    return [
        ("fresh", state(), now),
        ("age_zero", state(), 1000.5),
        ("age_limit", state(), 2800.5),
        ("stale", state(), 2800.75),
        ("future", state(), 999.0),
        ("schema_float", state(schema_version=2.0), now),
        ("schema_str", state(schema_version="2"), now),
        ("schema_true", state(schema_version=True), now),
        ("schema_one", state(schema_version=1), now),
        ("schema_missing", json.dumps({"generated_at_epoch": 1, "summary": FRESH_SUMMARY}), now),
        ("summary_missing", json.dumps({"schema_version": 2, "generated_at_epoch": 1}), now),
        ("summary_list", state(summary=[]), now),
        ("summary_key_missing", state(summary={k: v for k, v in FRESH_SUMMARY.items() if k != "os_ok"}), now),
        ("summary_key_str", state(summary={**FRESH_SUMMARY, "os_ok": "yes"}), now),
        ("summary_key_int", state(summary={**FRESH_SUMMARY, "traefik_ok": 1}), now),
        ("summary_key_null", state(summary={**FRESH_SUMMARY, "apt_indexes_fresh": None}), now),
        ("summary_extra_keys_and_old_fresh", state(summary={**FRESH_SUMMARY, "fresh": "old", "x": 1}), now),
        ("timestamp_missing", json.dumps({"schema_version": 2, "summary": FRESH_SUMMARY}), now),
        ("timestamp_int", state(generated_at_epoch=1000), now),
        ("timestamp_bool", state(generated_at_epoch=True), now),
        ("timestamp_str", state(generated_at_epoch="1000"), now),
        ("timestamp_null", state(generated_at_epoch=None), now),
        ("timestamp_infinite_float", raw("1e400"), now),
        ("timestamp_huge_int", raw("1" + "0" * 400), now),
        ("timestamp_big_int", raw("18446744073709551617"), now),
        ("timestamp_negative_zero", raw("-0.0"), now),
        ("timestamp_exponent", raw("1.0005E3"), now),
        ("old_meta_replaced", state(meta={"age_seconds": -1, "other": True}), now),
        ("extra_keys_kept", state(os={"status": "ok", "nested": [1, 2.5]}, policy_sha256="ab"), now),
        ("not_mapping", "[]", now),
        ("null", "null", now),
        ("fractional_now", state(), 1234.0625),
    ]


def gen_report() -> dict[str, Any]:
    summary = []
    for case_id, policy, observations in summary_cases():
        report, calls = run_collect(policy, observations)
        summary.append({
            "id": case_id,
            "policy": json.dumps(policy),
            "observations": observations,
            "generated_at_epoch": report["generated_at_epoch"],
            "report_keys": sorted(report),
            "policy_sha256": report["policy_sha256"],
            "summary": report["summary"],
            "calls": calls,
        })
    freshness = []
    for case_id, text, now in freshness_cases():
        case: dict[str, Any] = {"id": case_id, "text": text, "now": now}
        try:
            case["result"] = json.dumps(live.with_freshness(json.loads(text), now), sort_keys=True)
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
        freshness.append(case)
    errors = []
    lifecycle = {"status": "unknown", "error": "URLError"}
    for exc in (ValueError("x" * 300), OSError("\u00e9" * 300), KeyError("k"),
                TypeError("\U0001f600" * 250), ValueError("short")):
        with mock.patch.object(live.platform, "freedesktop_os_release", side_effect=exc):
            result = live.observe_os(BASE["os"], lifecycle, 0.0)
        errors.append({"class": type(exc).__name__, "message": str(exc), "text": result["error"]})
    return {"summary": summary, "freshness": freshness, "errors": errors}


# ------------------------------------------------------------------ realpath

REALPATH_TREE = [
    {"path": "{root}/a"},
    {"path": "{root}/a/b"},
    {"path": "{root}/a/b/file", "file": True},
    {"path": "{root}/link_abs", "link": "{root}/a/b"},
    {"path": "{root}/a/rel", "link": "b"},
    {"path": "{root}/a/up", "link": "../a/b"},
    {"path": "{root}/loop1", "link": "{root}/loop2"},
    {"path": "{root}/loop2", "link": "{root}/loop1"},
    {"path": "{root}/self", "link": "self"},
    {"path": "{root}/dangling", "link": "{root}/missing/x"},
    {"path": "{root}/chain", "link": "link_abs"},
    {"path": "{root}/a/b/dotdot", "link": "../../a"},
    {"path": "{root}/a/b/to_file", "link": "file"},
]
REALPATH_QUERIES = [
    "{root}/link_abs/file", "{root}/a/rel/file", "{root}/a/up/file", "{root}/loop1/x/../y",
    "{root}/self/z", "{root}/dangling/q", "{root}/chain/file", "{root}/missing/../a",
    "{root}/a/./b/../b/file", "{root}/a/b/file/..", "{root}//a//b", "{root}/a/b/dotdot/rel",
    "{root}/link_abs/../b", "{root}/chain/../x", "{root}/loop1", "{root}/a/rel/",
    "{root}/nonexistent/link_abs", "{root}/a/b/to_file", "{root}/a/b/to_file/x",
    "{root}/a/b/dotdot/b/dotdot/up/file",
]


def gen_realpath() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        root = os.path.realpath(directory)
        at = lambda path: path.replace("{root}", root)
        for node in REALPATH_TREE:
            if "link" in node:
                os.symlink(at(node["link"]), at(node["path"]))
            elif node.get("file"):
                Path(at(node["path"])).write_bytes(b"")
            else:
                os.mkdir(at(node["path"]))
        cases = []
        for query in REALPATH_QUERIES:
            result = os.path.realpath(at(query))
            assert result.startswith(root), (query, result)
            cases.append({"path": query, "result": "{root}" + result[len(root):]})
    return {"tree": REALPATH_TREE, "cases": cases}


# ------------------------------------------------------------------ traefik
#
# The Traefik cases run the real ``binary_info``/``observe_traefik`` against a
# fake host. ``FakeHost`` is the Python side of ``probe::fake::FakeSystem``:
# it reads the same world (paths map to answers or errno names, consumed in
# order with the last one repeating; a path that is not listed is ENOENT),
# patches the calls the Python code makes (``subprocess.run`` under
# ``command()``, ``open``, ``os.fstat``, ``hashlib.file_digest``,
# ``os.readlink``, ``os.path.realpath``, ``os.stat``, ``Path.exists`` of
# Python 3.12) and logs every call in the format the Rust fake logs it. The
# Rust tests replay each world and compare the result and the call log.

FAKE_ERRNOS = {name: getattr(errno, name)
               for name in ("ENOENT", "EACCES", "ENOTDIR", "ELOOP", "EISDIR", "EINVAL", "EBADF")}
EXISTS_IGNORED = {errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP}
STAT_DEFAULTS = {"dev": 0, "ino": 0, "nlink": 1, "uid": 0, "gid": 0, "size": 0, "mtime_ns": 0, "ctime_ns": 0}


def fake_os_error(name: str, *filename: str) -> OSError:
    code = FAKE_ERRNOS[name]
    return OSError(code, os.strerror(code), *filename)


def fake_stat(spec: dict[str, Any]) -> SimpleNamespace:
    values = {**STAT_DEFAULTS, **spec}
    return SimpleNamespace(**{f"st_{key}": value for key, value in values.items()})


class FakeStream(io.BytesIO):
    def __init__(self, data: bytes, fd: int) -> None:
        super().__init__(data)
        self.fd = fd

    def fileno(self) -> int:
        return self.fd


class FakeHost:
    def __init__(self, world: dict[str, Any]) -> None:
        self.world = world
        self.queues = {
            kind: {key: collections.deque(answers) for key, answers in world.get(kind, {}).items()}
            for kind in ("stat", "lstat", "readlink", "open")
        }
        self.commands = collections.deque(world.get("commands", []))
        self.fstat_queues: dict[int, collections.deque[Any]] = {}
        self.calls: list[str] = []

    @staticmethod
    def take(queue: collections.deque[Any] | None) -> Any:
        if not queue:
            return None
        return queue.popleft() if len(queue) > 1 else queue[0]

    def answer(self, kind: str, key: str) -> Any:
        entry = self.take(self.queues[kind].get(key))
        if entry is None:
            raise fake_os_error("ENOENT", key)
        if "errno" in entry:
            raise fake_os_error(entry["errno"], key)
        return entry["ok"]

    def stat(self, path: Any, *, follow_symlinks: bool = True) -> SimpleNamespace:
        assert follow_symlinks
        self.calls.append(f"stat {path}")
        return fake_stat(self.answer("stat", str(path)))

    def exists(self, path: Any) -> bool:
        try:
            self.stat(path)
        except OSError as exc:
            if exc.errno in EXISTS_IGNORED:
                return False
            raise
        return True

    def readlink(self, path: Any) -> str:
        self.calls.append(f"readlink {path}")
        return self.answer("readlink", str(path))

    def realpath(self, path: Any, *, strict: bool = False) -> str:
        assert not strict
        self.calls.append(f"realpath {path}")
        return self.world.get("realpath", {}).get(str(path), str(path))

    def open(self, path: Any, mode: str = "r", *args: Any, **kwargs: Any) -> FakeStream:
        assert mode == "rb" and not args and not kwargs, (mode, args, kwargs)
        self.calls.append(f"open {path}")
        spec = self.answer("open", str(path))
        self.fstat_queues[spec["fd"]] = collections.deque(spec.get("fstat", []))
        return FakeStream(spec["data"].encode(), spec["fd"])

    def fstat(self, fd: int) -> SimpleNamespace:
        self.calls.append(f"fstat {fd}")
        entry = self.take(self.fstat_queues.get(fd))
        if entry is None:
            raise fake_os_error("EBADF")
        if "errno" in entry:
            raise fake_os_error(entry["errno"])
        return fake_stat(entry["ok"])

    def file_digest(self, stream: FakeStream, name: str) -> Any:
        assert name == "sha256"
        self.calls.append(f"sha256 {stream.fileno()}")
        return hashlib.sha256(stream.read())

    def run(self, argv: list[str], *, capture_output: bool, text: bool, timeout: int, check: bool,
            pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[str]:
        assert capture_output and text and check and timeout == 15
        argv = [str(arg) for arg in argv]
        self.calls.append("run " + " ".join(argv) + "".join(f" pass_fds={fd}" for fd in pass_fds))
        spec = self.commands.popleft()
        assert spec["argv"] == argv and spec.get("pass_fds", []) == list(pass_fds), (spec, argv)
        if spec.get("error") == "timeout":
            raise subprocess.TimeoutExpired(argv, timeout)
        if spec.get("error"):
            raise fake_os_error(spec["error"], argv[0])
        text_mode = lambda value: value.replace("\r\n", "\n").replace("\r", "\n")
        result = subprocess.CompletedProcess(
            argv, spec.get("exit", 0), text_mode(spec.get("stdout", "")), text_mode(spec.get("stderr", ""))
        )
        result.check_returncode()
        return result

    @contextlib.contextmanager
    def patched(self) -> Any:
        with (
            mock.patch.object(live.subprocess, "run", self.run),
            mock.patch.object(live, "open", self.open, create=True),
            mock.patch.object(live.os, "fstat", self.fstat),
            mock.patch.object(live.hashlib, "file_digest", self.file_digest),
            mock.patch.object(live.os, "readlink", self.readlink),
            mock.patch.object(live.os.path, "realpath", self.realpath),
            mock.patch.object(live.os, "stat", self.stat),
            mock.patch.object(live.Path, "exists", lambda path: self.exists(path)),
        ):
            yield self
        assert not self.commands, f"commands left in the world: {list(self.commands)}"


TRAEFIK = "/usr/local/bin/traefik"
SYSTEMCTL = ["systemctl", "show", "traefik.service", "--property=MainPID", "--value"]
TRAEFIK_POLICY = BASE["traefik"]
LATEST = {"status": "ok", "version": "3.7.9", "checked_at_epoch": 1_760_000_000.5, "cached": True}
LATEST_UNKNOWN = {"status": "unknown", "error": "URLError", "last_success": None}
MTIME = 1_760_000_000_123_456_789


def ok(value: Any) -> dict[str, Any]:
    return {"ok": value}


def err(name: str) -> dict[str, str]:
    return {"errno": name}


def st(ino: int, size: int = 4096, mtime_ns: int = MTIME, ctime_ns: int | None = None,
       dev: int = 2049) -> dict[str, Any]:
    return {"dev": dev, "ino": ino, "mode": 0o100755, "size": size, "mtime_ns": mtime_ns,
            "ctime_ns": mtime_ns if ctime_ns is None else ctime_ns}


class Binary:
    """A file: its bytes, what ``<it> version`` prints and its inode."""

    def __init__(self, data: str, output: str = "Version: 3.7.9", ino: int = 101) -> None:
        self.data, self.output, self.ino = data, output, ino

    @property
    def stat(self) -> dict[str, Any]:
        return st(self.ino, size=len(self.data.encode()))


INSTALLED = Binary("traefik 3.7.9 bytes")


class Builder:
    def __init__(self) -> None:
        self.world: dict[str, Any] = {"stat": {}, "readlink": {}, "open": {}, "commands": [], "realpath": {}}

    def add(self, kind: str, key: str, *answers: Any) -> Builder:
        self.world[kind].setdefault(key, []).extend(answers)
        return self

    def run(self, argv: list[str], stdout: str = "", **spec: Any) -> Builder:
        self.world["commands"].append({"argv": argv, "stdout": stdout, **spec})
        return self

    def pid(self, output: str, **spec: Any) -> Builder:
        return self.run(SYSTEMCTL, output, **spec)

    def realpath(self, path: str, result: str) -> Builder:
        self.world["realpath"][path] = result
        return self

    def opened(self, path: str, fd: int, binary: Binary, *fstat: dict[str, Any]) -> Builder:
        answers = [ok(s) for s in fstat] or [ok(binary.stat)]
        return self.add("open", path, ok({"fd": fd, "data": binary.data, "fstat": answers}))

    def build(self) -> dict[str, Any]:
        return {kind: value for kind, value in self.world.items() if value}


def attempt(b: Builder, *, pid: int = 11, target: str = TRAEFIK, installed: Binary = INSTALLED,
            running: Binary | None = None, refused: bool | None = None, fd_target: str | None = None,
            pid_after: int | None = None, target_after: str | None = None, path: str = TRAEFIK,
            real: str | None = None, fds: tuple[int, int] = (3, 4)) -> Builder:
    """One complete attempt of ``observe_traefik`` with an expected Traefik."""
    running = running or installed
    real = real or path
    refused = target != real if refused is None else refused
    exe = f"/proc/{pid}/exe"
    b.pid(str(pid)).add("stat", path, ok(installed.stat)).add("readlink", exe, ok(target))
    b.opened(path, fds[0], installed).run([path, "version"], installed.output)
    b.add("stat", path, ok(installed.stat))
    b.opened(exe, fds[1], running)
    if not refused:
        b.add("readlink", f"/proc/self/fd/{fds[1]}", ok(fd_target or real))
        b.run([f"/proc/self/fd/{fds[1]}", "version"], running.output, pass_fds=[fds[1]])
    b.add("stat", exe, ok(running.stat))
    after = pid if pid_after is None else pid_after
    b.pid(str(after))
    if after == pid:
        b.add("readlink", exe, ok(target if target_after is None else target_after))
    return b


def split_error(text: str) -> dict[str, Any]:
    cls, message = text.split(": ", 1)
    contract = cls == "KeyError" or message in OWN_MESSAGES
    return {"class": cls, "message": message if contract else None}


def observe_cases() -> list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], str | None]]:
    cases: list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], str | None]] = []

    def add(case_id: str, b: Builder, policy: dict[str, Any] = TRAEFIK_POLICY,
            latest: dict[str, Any] = LATEST, p3: str | None = None) -> None:
        cases.append((case_id, b.build(), policy, latest, p3))

    new = Binary("traefik 3.7.12 bytes", "Version: 3.7.12", ino=202)
    other_bytes = Binary("traefik 3.7.9 rebuilt bytes", ino=303)
    unassigned = {**TRAEFIK_POLICY, "desired_version": None}
    no_desired = {key: value for key, value in TRAEFIK_POLICY.items() if key != "desired_version"}
    not_expected = {**TRAEFIK_POLICY, "expected": False}
    usr_bin = {**TRAEFIK_POLICY, "binary_path": "/usr/bin/traefik"}

    # tests/test_software_live.py, in the order of the Python tests
    add("matching_process_and_binary", attempt(Builder()))
    add("replaced_disk_binary_same_path", attempt(Builder(), installed=new, running=INSTALLED))
    add("replaced_disk_binary_deleted", attempt(Builder(), target=TRAEFIK + " (deleted)",
                                                installed=new, running=INSTALLED))
    add("same_version_different_bytes", attempt(Builder(), running=other_bytes))
    add("unknown_upstream", attempt(Builder()), latest=LATEST_UNKNOWN)
    add("new_upstream_and_unassigned_desired", attempt(Builder()), policy=unassigned,
        latest={**LATEST, "version": "3.7.12"})
    add("desired_version_absent", attempt(Builder()), policy=no_desired)
    add("deleted_and_wrong_path", attempt(Builder(), target="/usr/bin/traefik (deleted)"))
    for case_id, target in (("memfd", "/memfd:payload (deleted)"), ("tmp", "/tmp/other"),
                            ("deleted_managed", TRAEFIK + " (deleted)")):
        add(f"unexpected_image_{case_id}_is_not_executed",
            attempt(Builder(), target=target, running=Binary("unexpected bytes", "Version: 9.9.9", ino=404)))
    add("pid_retry_settles", attempt(attempt(Builder(), pid_after=12), pid=12))
    add("pid_retry_exhausted", attempt(attempt(Builder(), pid_after=12), pid=13, pid_after=14))
    add("link_retry_settles", attempt(attempt(Builder(), target_after="/usr/local/bin/traefik (deleted)"),
                                      target=TRAEFIK + " (deleted)"))
    add("link_retry_exhausted", attempt(attempt(Builder(), target_after="/tmp/a"), target="/tmp/a",
                                        target_after="/tmp/b"))
    add("retry_resets_issues", attempt(attempt(Builder(), target="/tmp/a", pid_after=12), pid=12))
    add("stopped_service", Builder().pid("0").add("stat", TRAEFIK, ok(INSTALLED.stat)))
    add("systemctl_fails", Builder().pid("", exit=1))
    add("systemctl_missing", Builder().pid("", error="ENOENT"))
    add("systemctl_timeout", Builder().pid("", error="timeout"))
    add("expected_absence", Builder().pid("0"), policy=not_expected)
    add("unexpected_process", Builder().pid("11"), policy=not_expected)
    add("unexpected_other_path", Builder().pid("0").add("stat", "/usr/bin/traefik", ok(INSTALLED.stat)),
        policy=not_expected)
    add("unexpected_managed_path", Builder().pid("0").add("stat", TRAEFIK, ok(INSTALLED.stat)),
        policy={**not_expected, "binary_path": "/usr/bin/traefik"})
    add("not_expected_exists_denied", Builder().pid("0").add("stat", "/usr/bin/traefik", err("EACCES")),
        policy=not_expected)
    add("not_expected_ignored_errnos", Builder().pid("0").add("stat", TRAEFIK, err("ENOTDIR"))
        .add("stat", "/usr/bin/traefik", err("ELOOP")), policy=not_expected)
    add("not_expected_upstream_is_not_read", Builder().pid("0"), policy=not_expected, latest={})

    # MainPID as int() reads it
    for case_id, output in (("padded", " 11 "), ("plus", "+11"), ("underscore", "1_1"),
                            ("leading_zeros", "011")):
        add(f"pid_{case_id}", _with_pid_output(attempt(Builder()), output))
    add("pid_negative_zero", Builder().pid("-0").add("stat", TRAEFIK, ok(INSTALLED.stat)))
    for case_id, output in (("empty", ""), ("word", "n/a"), ("double_underscore", "1__1"),
                            ("float", "11.0"), ("too_many_digits", "1" * 4301)):
        add(f"pid_invalid_{case_id}", Builder().pid(output))
    add("pid_negative", Builder().pid("-5").add("stat", TRAEFIK, ok(INSTALLED.stat)))
    add("pid_huge", Builder().pid("99999999999999999999999").add("stat", TRAEFIK, ok(INSTALLED.stat)))
    add("pid_unicode_digits", _with_pid_output(attempt(Builder()), "١١"), p3="unicode-digits")

    # the managed binary
    add("binary_missing", Builder().pid("11"))
    add("binary_stat_denied", Builder().pid("11").add("stat", TRAEFIK, err("EACCES")))
    add("usr_bin_policy", attempt(Builder(), path="/usr/bin/traefik", target="/usr/bin/traefik"), policy=usr_bin)
    add("symlinked_binary_is_resolved",
        attempt(Builder().realpath(TRAEFIK, "/opt/traefik/v3.7.9/traefik"),
                target="/opt/traefik/v3.7.9/traefik", real="/opt/traefik/v3.7.9/traefik"))
    add("symlinked_binary_running_the_link_path",
        attempt(Builder().realpath(TRAEFIK, "/opt/traefik/v3.7.9/traefik"), target=TRAEFIK,
                real="/opt/traefik/v3.7.9/traefik"))
    add("non_ascii_running_path", attempt(Builder(), target="/usr/local/bin/träefik"))
    add("exe_link_gone", Builder().pid("11").add("stat", TRAEFIK, ok(INSTALLED.stat)))
    add("exe_link_denied", Builder().pid("11").add("stat", TRAEFIK, ok(INSTALLED.stat))
        .add("readlink", "/proc/11/exe", err("EACCES")))

    # probes and identities
    add("installed_open_denied", prefix(Builder()).add("open", TRAEFIK, err("EACCES")))
    add("installed_probe_fails", prefix(Builder()).opened(TRAEFIK, 3, INSTALLED)
        .run([TRAEFIK, "version"], "", exit=2))
    add("installed_probe_times_out", prefix(Builder()).opened(TRAEFIK, 3, INSTALLED)
        .run([TRAEFIK, "version"], error="timeout"))
    add("installed_version_unparseable", prefix(Builder()).opened(TRAEFIK, 3, INSTALLED)
        .run([TRAEFIK, "version"], "traefik version 3.7.9"))
    add("installed_version_prefixed", attempt(Builder(), installed=Binary(INSTALLED.data, "Version: v3.7.9")))
    add("installed_changed_during_probe",
        prefix(Builder()).opened(TRAEFIK, 3, INSTALLED, INSTALLED.stat, st(101, size=99))
        .run([TRAEFIK, "version"], "Version: 3.7.9"))
    add("installed_replaced_after_probe", prefix(Builder()).opened(TRAEFIK, 3, INSTALLED)
        .run([TRAEFIK, "version"], "Version: 3.7.9").add("stat", TRAEFIK, ok(st(999))))
    add("reexec_after_link_check_is_refused",
        installed_probed(prefix(Builder())).opened("/proc/11/exe", 4, INSTALLED)
        .add("readlink", "/proc/self/fd/4", ok("/memfd:payload (deleted)")))
    add("running_probe_fails",
        installed_probed(prefix(Builder())).opened("/proc/11/exe", 4, INSTALLED)
        .add("readlink", "/proc/self/fd/4", ok(TRAEFIK))
        .run(["/proc/self/fd/4", "version"], "", exit=1, pass_fds=[4]))
    add("running_changed_during_probe",
        installed_probed(prefix(Builder()))
        .opened("/proc/11/exe", 4, INSTALLED, INSTALLED.stat, st(101, mtime_ns=MTIME + 1))
        .add("readlink", "/proc/self/fd/4", ok(TRAEFIK))
        .run(["/proc/self/fd/4", "version"], "Version: 3.7.9", pass_fds=[4])
        .add("stat", "/proc/11/exe", ok(INSTALLED.stat)))
    add("refused_image_gone_before_open", installed_probed(prefix(Builder(), target="/tmp/x")))
    add("refused_image_changed", installed_probed(prefix(Builder(), target="/tmp/x"))
        .opened("/proc/11/exe", 4, INSTALLED).add("stat", "/proc/11/exe", ok(st(5))))
    add("pid_gone_after_probe", attempt(Builder(), pid_after=0).pid("0")
        .add("stat", TRAEFIK, ok(INSTALLED.stat)))
    add("final_link_gone", _final_link(attempt(Builder()), err("ENOENT")))

    # evaluation
    add("desired_installed_drift", attempt(Builder()), policy={**TRAEFIK_POLICY, "desired_version": "v3.7.8"})
    add("desired_matches_with_prefix", attempt(Builder()), policy={**TRAEFIK_POLICY, "desired_version": "v3.7.9"})
    add("running_newer_than_upstream", attempt(Builder()), latest={**LATEST, "version": "3.7.8"})
    add("outdated_and_drift", attempt(Builder(), installed=new, running=INSTALLED),
        latest={**LATEST, "version": "v3.8.0"})
    add("refused_running_is_never_outdated", attempt(Builder(), target="/tmp/x"),
        latest={**LATEST, "version": "4.0.0"})
    add("upstream_not_applicable", attempt(Builder()), latest={"status": "not_applicable"})
    add("upstream_status_missing", attempt(Builder()), latest={"version": "3.7.9"})
    add("upstream_version_missing", attempt(Builder()), latest={"status": "ok"})
    add("upstream_version_not_a_string", attempt(Builder()), latest={"status": "ok", "version": 3})
    add("upstream_version_unparseable", attempt(Builder()), latest={"status": "ok", "version": "latest"})
    add("upstream_version_not_read_without_running_version", attempt(Builder(), target="/tmp/x"),
        latest={"status": "ok"})
    add("installed_version_over_int_limit",
        attempt(Builder(), installed=Binary("big", "Version: " + "1" * 4301 + ".0.0")))
    return cases


def prefix(b: Builder, target: str = TRAEFIK) -> Builder:
    """The start of an attempt up to the installed probe: MainPID 11, the
    managed binary exists, ``/proc/11/exe`` points at ``target``."""
    return b.pid("11").add("stat", TRAEFIK, ok(INSTALLED.stat)).add("readlink", "/proc/11/exe", ok(target))


def installed_probed(b: Builder) -> Builder:
    """The installed binary opened, probed and stat'ed successfully."""
    return (b.opened(TRAEFIK, 3, INSTALLED).run([TRAEFIK, "version"], INSTALLED.output)
            .add("stat", TRAEFIK, ok(INSTALLED.stat)))


def _with_pid_output(b: Builder, output: str) -> Builder:
    """The first ``systemctl`` answer printed as ``output`` (same number)."""
    b.world["commands"][0]["stdout"] = output
    return b


def _final_link(b: Builder, answer: dict[str, Any]) -> Builder:
    b.world["readlink"]["/proc/11/exe"][-1] = answer
    return b


def binary_info_cases() -> list[tuple[str, dict[str, Any], str, str | None, bool, str | None]]:
    cases: list[tuple[str, dict[str, Any], str, str | None, bool, str | None]] = []
    path = "/opt/proxy"
    exe = "/proc/11/exe"

    def probe(output: str, binary: Binary = Binary("bytes")) -> Builder:
        return (Builder().opened(path, 3, binary).run([path, "version"], output)
                .add("stat", path, ok(binary.stat)))

    outputs = {
        "plain": "Version: 3.7.9",
        "prefixed": "Version: v3.7.9",
        "no_space": "Version:3.7.9",
        "tabs_and_trailing": "Version:\t3.7.9 \t",
        "traefik_banner": "Version:      3.7.9\nCodename:     x\nGo version:   go1.25\nBuilt:        now",
        "later_line": "banner\nVersion: 3.7.9\nmore",
        "first_of_two": "Version: 3.7.9\nVersion: 4.0.0",
        "skips_bad_line": "Version: 3.7\nVersion: 3.7.10",
        "spans_a_line_break": "Version:\n3.7.9",
        "trailing_line_break_whitespace": "Version: 3.7.9 \n \nx",
        "python_space_separators": "Version:\x1c3.7.9\x1f",
        "unicode_space": "Version:　3.7.9 ",
        "carriage_return": "Version: 3.7.9\r\nx",
        "big_numbers": "Version: 99999999999999999999.0.1",
        "lowercase": "version: 3.7.9",
        "indented": " Version: 3.7.9",
        "two_parts": "Version: 3.7",
        "rc": "Version: 3.7.9-rc1",
        "double_v": "Version: vv3.7.9",
        "suffix": "Version: 3.7.9 (x)",
        "empty": "",
    }
    for case_id, output in outputs.items():
        cases.append((f"output_{case_id}", probe(output).build(), path, None, True, None))
    cases.append(("output_unicode_digits", probe("Version: ٣.٧.٩").build(), path, None, True,
                  "unicode-digits"))
    cases.append(("no_probe_never_executes",
                  Builder().opened(path, 3, Binary("bytes")).add("stat", path, ok(Binary("bytes").stat)).build(),
                  path, None, False, None))
    pinned = (Builder().opened(exe, 5, Binary("bytes")).add("readlink", "/proc/self/fd/5", ok(path))
              .run(["/proc/self/fd/5", "version"], "Version: 3.7.9", pass_fds=[5])
              .add("stat", exe, ok(Binary("bytes").stat)))
    cases.append(("pinned_descriptor_is_executed", pinned.build(), exe, path, True, None))
    cases.append(("pinned_descriptor_resolved_target",
                  Builder().realpath(path, "/srv/proxy").opened(exe, 5, Binary("bytes"))
                  .add("readlink", "/proc/self/fd/5", ok("/srv/proxy"))
                  .run(["/proc/self/fd/5", "version"], "Version: 3.7.9", pass_fds=[5])
                  .add("stat", exe, ok(Binary("bytes").stat)).build(), exe, path, True, None))
    for case_id, target in (("memfd", "/memfd:payload (deleted)"), ("deleted", path + " (deleted)"),
                            ("other", "/tmp/other"), ("unresolved", path + "/")):
        cases.append((f"descriptor_target_{case_id}_is_refused",
                      Builder().opened(exe, 5, Binary("bytes")).add("readlink", "/proc/self/fd/5", ok(target))
                      .build(), exe, path, True, None))
    cases.append(("descriptor_target_refused_without_probe",
                  Builder().opened(exe, 5, Binary("bytes")).add("readlink", "/proc/self/fd/5", ok("/tmp/x"))
                  .build(), exe, path, False, None))
    cases.append(("open_missing", Builder().build(), path, None, True, None))
    cases.append(("open_denied", Builder().add("open", path, err("EACCES")).build(), path, None, True, None))
    cases.append(("descriptor_link_missing", Builder().opened(exe, 5, Binary("bytes")).build(), exe, path,
                  True, None))
    cases.append(("fstat_fails", Builder().add("open", path, ok({"fd": 3, "data": "x", "fstat": []})).build(),
                  path, None, True, None))
    cases.append(("changed_during_probe",
                  probe("Version: 3.7.9", Binary("bytes")).build() | {"open": {path: [ok(
                      {"fd": 3, "data": "bytes", "fstat": [ok(st(101, size=5)), ok(st(101, size=6))]})]}},
                  path, None, True, None))
    for case_id, changed in (("inode", st(102, size=5)), ("device", st(101, size=5, dev=7)),
                             ("mtime", st(101, size=5, mtime_ns=MTIME + 1)),
                             ("ctime", st(101, size=5, ctime_ns=MTIME + 1)), ("size", st(101, size=6))):
        cases.append((f"final_stat_{case_id}_changed",
                      Builder().opened(path, 3, Binary("bytes")).run([path, "version"], "Version: 3.7.9")
                      .add("stat", path, ok(changed)).build(), path, None, True, None))
    cases.append(("uid_and_mode_are_not_identity",
                  Builder().opened(path, 3, Binary("bytes")).run([path, "version"], "Version: 3.7.9")
                  .add("stat", path, ok({**st(101, size=5), "uid": 7, "mode": 0o100700, "nlink": 2})).build(),
                  path, None, True, None))
    cases.append(("final_stat_missing",
                  Builder().opened(path, 3, Binary("bytes")).run([path, "version"], "Version: 3.7.9").build(),
                  path, None, True, None))
    cases.append(("unparseable_wins_over_change",
                  Builder().add("open", path, ok({"fd": 3, "data": "x", "fstat": [ok(st(1)), ok(st(2))]}))
                  .run([path, "version"], "no version").build(), path, None, True, None))
    cases.append(("no_probe_changed",
                  Builder().opened(path, 3, Binary("bytes")).add("stat", path, ok(st(1))).build(),
                  path, None, False, None))
    cases.append(("probe_stderr_is_ignored",
                  Builder().opened(path, 3, Binary("bytes"))
                  .run([path, "version"], "Version: 3.7.9", stderr="warning\n").add("stat", path,
                                                                                    ok(Binary("bytes").stat))
                  .build(), path, None, True, None))
    cases.append(("probe_missing_program",
                  Builder().opened(path, 3, Binary("bytes")).run([path, "version"], error="EACCES").build(),
                  path, None, True, None))
    return cases


def gen_traefik() -> dict[str, Any]:
    binary_info = []
    for case_id, world, path, expected_target, probe_version, p3 in binary_info_cases():
        host = FakeHost(world)
        case: dict[str, Any] = {"id": case_id, "world": world, "path": path, "expected_target": expected_target,
                                "probe_version": probe_version, "result": None, "error": None}
        with host.patched():
            try:
                case["result"] = live.binary_info(path, expected_target=expected_target,
                                                  probe_version=probe_version)
            except Exception as exc:  # noqa: BLE001 - the oracle's answer
                case["error"] = error(exc)
        case["calls"] = host.calls
        if p3:
            assert case["result"] is not None, case_id
            case["p3"] = p3
        binary_info.append(case)
    observe = []
    seen = set()
    for case_id, world, policy, latest, p3 in observe_cases():
        assert case_id not in seen, case_id
        seen.add(case_id)
        host = FakeHost(world)
        with host.patched():
            result = live.observe_traefik(json.loads(json.dumps(policy)), json.loads(json.dumps(latest)))
        text = result.pop("error", None)
        case = {"id": case_id, "world": world, "policy": policy, "latest": latest, "result": result,
                "error": split_error(text) if text is not None else None, "calls": host.calls}
        if p3:
            assert text is None, case_id
            case["p3"] = p3
        observe.append(case)
    return {"binary_info": binary_info, "observe": observe}


# ------------------------------------------------------------------ cli

CLI_FILES = {
    "valid.json": json.dumps(BASE),
    "invalid.json": mutate("host", ""),
    "broken.json": "{broken",
}
CLI_BINARY_FILES = {"latin1.json": b'{"host": "h\xe9"}'}


def cli_cases() -> list[dict[str, Any]]:
    valid = json.dumps(BASE)
    cases = [
        ("validate_valid", ["validate", "--config", "{dir}/valid.json"]),
        ("validate_equals_form", ["validate", "--config={dir}/valid.json"]),
        ("options_before_mode", ["--config", "{dir}/valid.json", "validate"]),
        ("double_dash", ["--config", "{dir}/valid.json", "--", "validate"]),
        ("ambiguous_prefix", ["validate", "--conf", "{dir}/valid.json"]),
        ("ambiguous_prefix_equals", ["validate", "--conf={dir}/valid.json"]),
        ("unique_prefix", ["validate", "--out", "x", "--config", "{dir}/valid.json"]),
        ("unused_options_accepted", ["validate", "--config", "{dir}/valid.json", "--cache", "c",
                                     "--group", "g", "--output", "o"]),
        ("validate_invalid", ["validate", "--config", "{dir}/invalid.json"]),
        ("validate_missing_file", ["validate", "--config", "{dir}/missing.json"]),
        ("validate_directory", ["validate", "--config", "{dir}"]),
        ("validate_broken_json", ["validate", "--config", "{dir}/broken.json"]),
        ("validate_invalid_utf8", ["validate", "--config", "{dir}/latin1.json"]),
        ("validate_without_config", ["validate"]),
        ("config_json", ["validate", "--config-json", valid]),
        ("config_json_wins", ["validate", "--config", "{dir}/missing.json", "--config-json", valid]),
        ("empty_config_json_falls_back", ["validate", "--config", "{dir}/valid.json", "--config-json", ""]),
        ("empty_config_json_falls_back_invalid",
         ["validate", "--config", "{dir}/invalid.json", "--config-json", ""]),
        ("last_option_wins", ["validate", "--config", "{dir}/invalid.json", "--config", "{dir}/valid.json"]),
        ("config_json_list", ["validate", "--config-json", "[]"]),
        ("config_json_negative_number", ["validate", "--config-json", "-1"]),
        ("config_json_nan", ["validate", "--config-json", "NaN"]),
        ("value_negative_int", ["validate", "--config-json", valid, "--group", "-1"]),
        ("value_negative_fraction", ["validate", "--config-json", valid, "--cache", "-.5"]),
        ("value_negative_float", ["validate", "--config-json", valid, "--output", "-1.5"]),
        # Not here: `-1e5` and `-1.`, which argparse reads as options up to
        # Python 3.13 (the hosts) and as negative numbers from 3.14 on; the
        # Rust code follows 3.12/3.13 (main::tests::option_values_follow_argparse).
        ("value_dash_word", ["validate", "--config-json", valid, "--group", "-x"]),
        ("value_dash_with_space", ["validate", "--config-json", valid, "--group", "-x y"]),
        ("value_single_dash", ["validate", "--config-json", valid, "--group", "-"]),
        ("value_attached_dash_word", ["validate", "--config-json", valid, "--group=-x"]),
        ("value_is_an_option", ["validate", "--config", "--output", "x"]),
        ("value_is_an_option_prefix", ["validate", "--config-json", valid, "--group", "--out"]),
        ("value_is_help", ["validate", "--config-json", valid, "--group", "-h"]),
        ("value_is_help_attached", ["validate", "--config-json", valid, "--group", "-hx"]),
        ("value_is_double_dash", ["validate", "--config-json", valid, "--group", "--"]),
        ("value_after_prefix", ["validate", "--config-json", valid, "--gr", "-x"]),
        ("negative_config_path", ["validate", "--config", "-1"]),
        ("help_before_missing_value", ["--help", "--config"]),
        ("help_before_option_value", ["-h", "--group", "-x"]),
        ("help_prefix_before_option_value", ["validate", "--he", "--group", "-x"]),
        ("help_attached_before_missing_value", ["-hx", "--group"]),
        ("missing_value_before_help", ["validate", "--config", "--help"]),
        ("help_with_value", ["--help=x"]),
        ("help_with_empty_value_before_missing_value", ["--help=", "--config"]),
        ("help_short_with_value", ["-h=x"]),
        ("help_short_with_empty_value", ["-h="]),
        ("help_short_with_value_before_missing_value", ["-h=x", "--config"]),
        ("help_short_with_empty_value_before_missing_value", ["-h=", "--config"]),
        ("help_short_with_value_after_mode", ["validate", "--config-json", valid, "-h=x"]),
        ("help_repeated_with_value", ["-hh=x"]),
        ("help_short_with_dash", ["-h-x"]),
        ("help_attached_before_missing_config", ["-hx", "--config"]),
        ("help_attached_with_equals", ["-hx=y", "--config"]),
        ("help_before_help_with_value", ["--help", "-h=x"]),
        ("help_before_unknown_option", ["--help", "--bogus"]),
        ("no_arguments", []),
        ("unknown_mode", ["nope"]),
        ("extra_positional", ["validate", "extra"]),
        ("option_without_value", ["validate", "--config"]),
        ("unknown_option", ["validate", "--unknown"]),
        ("help", ["--help"]),
        ("help_after_mode", ["validate", "-h"]),
        ("export_without_arguments", ["export-inventory"]),
        ("export_without_group", ["export-inventory", "--config", "x", "--output", "y"]),
        ("export_empty_group", ["export-inventory", "--config", "x", "--output", "y", "--group", ""]),
        ("export_without_output", ["export-inventory", "--config", "x", "--group", "g"]),
        ("collect_invalid_policy", ["collect", "--config", "{dir}/invalid.json"]),
        ("collect_without_config", ["collect"]),
        ("collect_broken_json", ["collect", "--config-json", "{"]),
    ]
    return [{"id": case_id, "argv": argv} for case_id, argv in cases]


def gen_cli() -> dict[str, Any]:
    out = []
    with tempfile.TemporaryDirectory() as directory:
        for name, text in CLI_FILES.items():
            (Path(directory) / name).write_text(text, encoding="utf-8")
        for name, data in CLI_BINARY_FILES.items():
            (Path(directory) / name).write_bytes(data)
        for case in cli_cases():
            argv = [arg.replace("{dir}", directory) for arg in case["argv"]]
            result = subprocess.run(
                [sys.executable, "-I", str(PROGRAM), *argv],
                capture_output=True, text=True, timeout=60, check=False,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"},
            )
            entry = {**case, "exit": result.returncode}
            if case["id"].startswith("export_"):
                entry["stderr"] = result.stderr
            elif result.returncode not in (0, 2):
                assert result.stderr, case
            out.append(entry)
    return {"files": CLI_FILES, "binary_files": {k: v.hex() for k, v in CLI_BINARY_FILES.items()},
            "cases": out}


# ------------------------------------------------------------------ upstream

GITHUB_URL = "https://api.github.com/repos/traefik/traefik/releases/latest"


class FakeResponse:
    """What ``urlopen`` returns: a context manager with ``read(n)``."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]


def transport_error(name: str) -> BaseException:
    """An exception ``urlopen`` raises, by class name (others are made up)."""
    import urllib.error

    known: dict[str, Callable[[], BaseException]] = {
        "URLError": lambda: urllib.error.URLError("offline"),
        "HTTPError": lambda: urllib.error.HTTPError(GITHUB_URL, 503, "unavailable", None, None),  # type: ignore[arg-type]
        "TimeoutError": lambda: TimeoutError("timed out"),
        "OSError": lambda: OSError("offline"),
        "ConnectionResetError": lambda: ConnectionResetError("reset"),
    }
    if name in known:
        return known[name]()
    return type(name, (Exception,), {})("rust category")


def response_bytes(spec: dict[str, Any]) -> bytes:
    body = bytes.fromhex(spec["body_hex"]) if "body_hex" in spec else spec.get("body", "").encode()
    return body + (spec.get("pad_char", " ") * spec.get("pad", 0)).encode() + spec.get("suffix", "").encode()


def python_cache(data: Any) -> str:
    """The text ``atomic_json`` writes for ``data`` (a cache Python wrote)."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "cache.json"
        live.atomic_json(path, data)
        return path.read_text(encoding="utf-8")


def place_files(root: Path, files: dict[str, Any], dirs: list[str]) -> None:
    for name in dirs:
        (root / name).mkdir(parents=True)
    for name, content in files.items():
        if isinstance(content, bytes):
            (root / name).write_bytes(content)
        else:
            (root / name).write_text(content, encoding="utf-8")


def run_lookup(root: Path, call: dict[str, Any], responses: list[dict[str, Any]]) -> dict[str, Any]:
    """Run one ``upstream``/``lifecycle_upstream`` call in ``root``."""
    queue = list(responses)
    http: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []

    def urlopen(request: Any, timeout: Any = None) -> FakeResponse:
        spec = queue.pop(0)
        http.append({
            "url": request.full_url,
            "headers": {key.lower(): value for key, value in request.header_items()},
            "timeout": timeout,
            **{key: value for key, value in spec.items() if key != "raise"},
        })
        if "error" in spec:
            raise transport_error(spec["error"])
        if "raise" in spec:
            raise transport_error(spec["raise"])
        return FakeResponse(response_bytes(spec))

    real = live.atomic_json

    def spy(path: Path, data: Any, group: Any = None) -> None:
        writes.append({"path": str(path.relative_to(root)), "data": json.dumps(data, sort_keys=True),
                       "group": group})
        real(path, data, group)

    # A cache name is relative to the case's directory; "/" stays itself.
    cache = None
    if call.get("cache") is not None:
        cache = Path(call["cache"]) if call["cache"].startswith("/") else root / call["cache"]
    out: dict[str, Any] = {}
    with (
        mock.patch.object(live.urllib.request, "urlopen", side_effect=urlopen),
        mock.patch.object(live, "atomic_json", side_effect=spy),
    ):
        try:
            if call["function"] == "upstream":
                result = live.upstream(cache, call["now"])
            else:
                result = live.lifecycle_upstream(call["product"], cache, call["now"])
            out["result"] = result_text(result)
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            out["raises"] = error(exc)
    # A call that raises may stop before its request.
    assert not queue or "raises" in out, f"unused responses {queue} in {call}"
    out["http"] = http
    out["writes"] = writes
    return out


def result_text(result: Any) -> str:
    """``json.dumps(result, sort_keys=True)`` with an infinite float as the
    number ``1e400``, which both JSON readers take for the same float."""
    import re

    text = json.dumps(result, sort_keys=True)
    return re.sub(r"(?<=[:,\[] )(-?)Infinity|(?<=\[)(-?)Infinity",
                  lambda m: (m.group(1) or m.group(2) or "") + "1e400", text)


def snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def restore(root: Path, files: dict[str, bytes]) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
    for name, data in files.items():
        (root / name).write_bytes(data)


def gen_upstream_case(case: dict[str, Any]) -> dict[str, Any]:
    """Run the calls of a case in one directory, in order.

    A call may carry ``p3``: the input is one Python handles differently on
    purpose (PLAN.md 4.2). Its ``rust`` answer is what the Python code gives
    for the input the Rust code effectively sees: the cache replaced by an
    unusable one (``cache``), the response replaced by an error of the Rust
    class (``error``) or another body (``body``).
    """
    out_calls = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        place_files(root, case.get("files", {}), case.get("dirs", []))
        for call in case["calls"]:
            before = snapshot(root)
            entry = {key: call[key] for key in ("function", "product", "cache", "now") if key in call}
            entry.update(run_lookup(root, call, call.get("responses", [])))
            p3 = call.get("p3")
            if p3:
                assert call is case["calls"][-1], "a P3 call must be the last of its case"
                after = snapshot(root)
                restore(root, before)
                responses = [dict(spec) for spec in call.get("responses", [])]
                if p3["kind"] == "cache":
                    (root / p3["file"]).write_text("not json", encoding="utf-8")
                    responses = p3["responses"]
                elif p3["kind"] == "error":
                    responses[p3.get("index", 0)] = {"error": p3["class"]}
                elif p3["kind"] == "body":
                    responses[p3.get("index", 0)] = {"body": p3["body"]}
                rust = run_lookup(root, call, responses)
                entry["p3"] = {"tag": p3["tag"], "result": rust.get("result"), "writes": rust["writes"]}
                assert "raises" not in rust, rust
                if p3["kind"] == "cache":
                    entry["p3"]["http"] = rust["http"]
                restore(root, after)
            out_calls.append(entry)
    files = {}
    for name, content in case.get("files", {}).items():
        files[name] = {"hex": content.hex()} if isinstance(content, bytes) else {"ok": content}
    for name in case.get("dirs", []):
        files[name] = {"errno": "EISDIR"}
    return {"id": case["id"], "files": files, "write_errors": case.get("write_errors", {}),
            "calls": out_calls}


def release(tag: Any = "v3.7.12", **extra: Any) -> dict[str, str]:
    return {"body": json.dumps({"tag_name": tag, "draft": False, "prerelease": False, **extra})}


CYCLES = [
    {"cycle": "17", "latest": "17.11", "eol": "2029-11-08", "releaseDate": "2024-09-26",
     "lts": False, "support": True},
    {"cycle": "16", "latest": "16.15", "eol": "2028-11-09", "extra": {"nested": [1, 2.5, None]}},
]


def lifecycle_body(cycles: Any) -> dict[str, str]:
    return {"body": json.dumps(cycles)}


def upstream_cases() -> list[dict[str, Any]]:
    up = lambda now, cache="upstream.json", responses=(), **kw: {
        "function": "upstream", "cache": cache, "now": now, "responses": list(responses), **kw}
    lc = lambda product, now, cache="upstream.json", responses=(), **kw: {
        "function": "lifecycle_upstream", "product": product, "cache": cache, "now": now,
        "responses": list(responses), **kw}
    old_release = {"version": "3.7.9", "checked_at_epoch": 1.0}
    py_release = python_cache({"version": "3.7.9", "checked_at_epoch": 1760000000.25})
    py_cycles = python_cache({"product": "postgresql", "cycles": CYCLES, "checked_at_epoch": 1760000000.25})
    T = 1760000000.25
    cases: list[dict[str, Any]] = [
        # test_upstream_daily_cache_and_unparseable_release
        {"id": "release_fetch_then_cached_then_garbage", "calls": [
            up(100.0, responses=[{"body": '{"tag_name":"v3.7.12"}'}]),
            up(101.0),
            up(100000.0, responses=[{"body": '{"tag_name":"garbage"}'}])]},
        # test_failed_upstream_refresh_retains_old_timestamp_only_as_evidence
        {"id": "release_failed_refresh_keeps_evidence",
         "files": {"upstream.json": json.dumps({"version": "3.7.9", "checked_at_epoch": 1})},
         "calls": [up(100000.0, responses=[{"error": "OSError"}])]},
        {"id": "release_no_cache", "calls": [up(T, cache=None, responses=[release()])]},
        {"id": "release_no_cache_failure", "calls": [up(T, cache=None, responses=[{"error": "URLError"}])]},
        {"id": "release_python_written_cache_fresh", "files": {"upstream.json": py_release},
         "calls": [up(T + 86399.5)]},
        {"id": "release_python_written_cache_age_zero", "files": {"upstream.json": py_release},
         "calls": [up(T)]},
        {"id": "release_python_written_cache_expired", "files": {"upstream.json": py_release},
         "calls": [up(T + 86400.0, responses=[release("v3.8.0")])]},
        {"id": "release_cache_from_the_future", "files": {"upstream.json": py_release},
         "calls": [up(T - 0.5, responses=[{"error": "TimeoutError"}])]},
        {"id": "release_cache_extra_keys_are_kept",
         "files": {"upstream.json": json.dumps({**old_release, "checked_at_epoch": T, "note": ["x", 1]})},
         "calls": [up(T + 5.0)]},
        {"id": "release_cache_status_keys_are_replaced",
         "files": {"upstream.json": json.dumps({**old_release, "checked_at_epoch": T, "status": "unknown",
                                               "cached": False})},
         "calls": [up(T + 5.0)]},
    ]
    for name, data in {
        "version_invalid": {"version": "3.7", "checked_at_epoch": T},
        "version_int": {"version": 3, "checked_at_epoch": T},
        "version_missing": {"checked_at_epoch": T},
        "checked_missing": {"version": "3.7.9"},
        "checked_str": {"version": "3.7.9", "checked_at_epoch": "1760000000"},
        "checked_null": {"version": "3.7.9", "checked_at_epoch": None},
        "checked_list": {"version": "3.7.9", "checked_at_epoch": [T]},
        "list": [old_release],
        "string": "3.7.9",
        "null": None,
        "empty_object": {},
    }.items():
        cases.append({"id": f"release_invalid_cache_{name}", "files": {"upstream.json": json.dumps(data)},
                      "calls": [up(T + 5.0, responses=[{"error": "URLError"}])]})
    for name, text in {
        "broken_json": '{"version": "3.7.9", ',
        "bom": '﻿{"version": "3.7.9", "checked_at_epoch": 1760000000.25}',
        "trailing_data": '{"version": "3.7.9", "checked_at_epoch": 1760000000.25} x',
        "empty": "",
    }.items():
        cases.append({"id": f"release_invalid_cache_{name}", "files": {"upstream.json": text},
                      "calls": [up(T + 5.0, responses=[release()])]})
    cases += [
        {"id": "release_invalid_cache_not_utf8",
         "files": {"upstream.json": b'{"version": "3.7.9", "checked_at_epoch": 1760000000.25, "x": "\xff"}'},
         "calls": [up(T + 5.0, responses=[{"error": "URLError"}])]},
        {"id": "release_cache_is_a_directory", "dirs": ["upstream.json"],
         "write_errors": {"upstream.json": "EISDIR"},
         "calls": [up(T, responses=[release()])]},
        {"id": "release_cache_directory_missing", "write_errors": {"missing/upstream.json": "ENOENT"},
         "calls": [up(T, cache="missing/upstream.json", responses=[release()])]},
        {"id": "release_cache_checked_bool",
         "files": {"upstream.json": json.dumps({"version": "3.7.9", "checked_at_epoch": True})},
         "calls": [up(86401.0, responses=[{"error": "URLError"}])]},
        {"id": "release_cache_checked_bool_fresh",
         "files": {"upstream.json": json.dumps({"version": "3.7.9", "checked_at_epoch": True})},
         "calls": [up(86400.5)]},
        {"id": "release_cache_checked_int",
         "files": {"upstream.json": json.dumps({"version": "v3.7.9", "checked_at_epoch": 1760000000})},
         "calls": [up(T)]},
        {"id": "release_cache_checked_big_int",
         "files": {"upstream.json": '{"checked_at_epoch": 18446744073709551617, "version": "3.7.9"}'},
         "calls": [up(T, responses=[{"error": "URLError"}])]},
        {"id": "release_cache_checked_infinite_float",
         "files": {"upstream.json": '{"checked_at_epoch": 1e400, "version": "3.7.9"}'},
         "calls": [up(T, responses=[{"error": "URLError"}])]},
        {"id": "release_cache_checked_exponent",
         "files": {"upstream.json": '{"checked_at_epoch": 1.76E9, "version": "3.7.9"}'},
         "calls": [up(1.76e9 + 1.0)]},
        {"id": "release_cache_negative_zero",
         "files": {"upstream.json": '{"checked_at_epoch": -0.0, "version": "3.7.9"}'},
         "calls": [up(0.0)]},
        # P3 (PLAN.md 4.2 item 12): Python's own check raises OverflowError,
        # which nothing catches; the Rust code ignores such a cache.
        {"id": "p3_release_cache_checked_huge_int",
         "files": {"upstream.json": '{"checked_at_epoch": 1' + "0" * 400 + ', "version": "3.7.9"}'},
         "calls": [up(T, responses=[release()],
                      p3={"tag": "cache-crash", "kind": "cache", "file": "upstream.json",
                          "responses": [release()]})]},
        # P3 (PLAN.md 4.2 item 4): NaN in a cache.
        {"id": "p3_release_cache_checked_nan",
         "files": {"upstream.json": '{"checked_at_epoch": NaN, "version": "3.7.9"}'},
         "calls": [up(T, responses=[{"error": "URLError"}],
                      p3={"tag": "non-standard-json", "kind": "cache", "file": "upstream.json",
                          "responses": [{"error": "URLError"}]})]},
    ]
    # Release responses.
    for name, response in {
        "tag_without_v": release("3.7.12"),
        "tag_short": release("v3.7"),
        "tag_rc": release("v3.8.0-rc1"),
        "tag_int": release(3),
        "tag_null": release(None),
        "tag_missing": {"body": '{"name": "v3.7.12"}'},
        "body_list": {"body": '[{"tag_name": "v3.7.12"}]'},
        "body_string": {"body": '"v3.7.12"'},
        "body_null": {"body": "null"},
        "body_number": {"body": "3"},
        "draft": release(draft=True),
        "prerelease": release(prerelease=True),
        "draft_string_false": release(draft="false"),
        "draft_one": release(draft=1),
        "draft_zero": release(draft=0),
        "draft_float_zero": release(draft=0.0),
        "draft_empty_string": release(draft=""),
        "draft_empty_list": release(draft=[]),
        "draft_empty_object": release(draft={}),
        "draft_list": release(draft=[False]),
        "prerelease_null": release(prerelease=None),
        "flags_missing": {"body": '{"tag_name": "v3.7.12"}'},
        "broken_json": {"body": '{"tag_name": "v3.7.12"'},
        "empty_body": {"body": ""},
        "bom": {"body_hex": (b"\xef\xbb\xbf" + b'{"tag_name": "v3.7.12"}').hex()},
        "not_utf8": {"body_hex": b'{"tag_name": "v3.7.12", "x": "\xff"}'.hex()},
        "trailing_data": {"body": '{"tag_name": "v3.7.12"} x'},
        "duplicate_tag": {"body": '{"tag_name": "garbage", "tag_name": "v3.7.12"}'},
        "big_int_extra": {"body": '{"tag_name": "v3.7.12", "id": 18446744073709551617}'},
        "int_4301_digits": {"body": '{"tag_name": "v3.7.12", "id": ' + "1" * 4301 + "}"},
        "long_whitespace_within_limit": {"body": '{"tag_name": "v3.7.12"}', "pad": 1024 * 1024 - 23},
        "long_body_cut": {"body": '{"tag_name": "v3.7.12", "notes": "', "pad": 1024 * 1024,
                          "pad_char": "a", "suffix": '"}'},
        "non_ascii_extra": {"body": '{"tag_name": "v3.7.12", "name": "é\U0001f600"}'},
    }.items():
        cases.append({"id": f"release_response_{name}",
                      "calls": [up(T, responses=[response])]})
    for name in ("URLError", "HTTPError", "TimeoutError", "OSError", "ConnectionResetError"):
        cases.append({"id": f"release_transport_{name}", "files": {"upstream.json": py_release},
                      "calls": [up(T + 86400.0, responses=[{"error": name}])]})
    cases += [
        # P3 (PLAN.md 4.2 item 4): non-standard JSON and UTF-16 bodies.
        {"id": "p3_release_response_nan",
         "calls": [up(T, responses=[{"body": '{"tag_name": "v3.7.12", "draft": NaN}'}],
                      p3={"tag": "non-standard-json", "kind": "error", "class": "JSONDecodeError"})]},
        {"id": "p3_release_response_utf16",
         "calls": [up(T, responses=[{"body_hex": '{"tag_name": "v3.7.12"}'.encode("utf-16").hex()}],
                      p3={"tag": "utf16-body", "kind": "error", "class": "UnicodeDecodeError"})]},
        {"id": "p3_release_response_unicode_digits",
         "calls": [up(T, responses=[release("v3.7.٩")],
                      p3={"tag": "unicode-digits", "kind": "error", "class": "ValueError"})]},
    ]

    # Lifecycle: test_lifecycle_daily_cache_and_failed_refresh_preserves_evidence
    cases.append({"id": "lifecycle_fetch_then_cached_then_failed_refresh", "calls": [
        lc("postgresql", 100.0, responses=[{"body": '[{"cycle":"17","latest":"17.11","eol":"2029-11-08"}]'}]),
        lc("postgresql", 101.0),
        lc("postgresql", 100000.0, responses=[{"error": "OSError"}])]})
    # test_lifecycle_refresh_skips_malformed_irrelevant_cycles
    cases.append({"id": "lifecycle_skips_malformed_irrelevant_cycles", "calls": [
        lc("postgresql", 100.0, cache=None, responses=[lifecycle_body([
            {"cycle": "old", "latest": "1.0", "eol": {"bad": "value"}},
            {"cycle": "17", "latest": "17.11", "eol": "2029-11-08"}])])]})
    cases += [
        {"id": "lifecycle_products_have_their_own_caches", "calls": [
            lc("ubuntu", T, responses=[lifecycle_body([{"cycle": "24.04", "eol": "2029-05-31",
                                                         "support": "2029-05-31", "lts": True}])]),
            lc("debian", T, responses=[lifecycle_body([{"cycle": "13", "eol": "2028-08-09"}])]),
            lc("ubuntu", T + 1.0),
            lc("debian", T + 1.0),
            up(T + 1.0, responses=[release()])]},
        {"id": "lifecycle_python_written_cache_fresh", "files": {"upstream-postgresql.json": py_cycles},
         "calls": [lc("postgresql", T + 100.0)]},
        {"id": "lifecycle_python_written_cache_expired_failure",
         "files": {"upstream-postgresql.json": py_cycles},
         "calls": [lc("postgresql", T + 86400.0, responses=[{"error": "HTTPError"}])]},
        {"id": "lifecycle_python_written_cache_expired_refresh",
         "files": {"upstream-postgresql.json": py_cycles},
         "calls": [lc("postgresql", T + 86400.0, responses=[lifecycle_body(CYCLES[:1])])]},
        {"id": "lifecycle_cache_of_another_product", "files": {"upstream-ubuntu.json": py_cycles},
         "calls": [lc("ubuntu", T + 5.0, responses=[{"error": "URLError"}])]},
        {"id": "lifecycle_cache_cycles_not_validated",
         "files": {"upstream-postgresql.json": json.dumps(
             {"product": "postgresql", "cycles": [1, "x", {"eol": 5}], "checked_at_epoch": T})},
         "calls": [lc("postgresql", T + 5.0)]},
        {"id": "lifecycle_cache_empty_cycles",
         "files": {"upstream-postgresql.json": json.dumps(
             {"product": "postgresql", "cycles": [], "checked_at_epoch": T})},
         "calls": [lc("postgresql", T + 5.0)]},
        {"id": "lifecycle_no_cache_path", "calls": [lc("debian", T, cache=None, responses=[
            lifecycle_body([{"cycle": "13", "eol": False}])])]},
        {"id": "lifecycle_cache_without_suffix", "calls": [
            lc("ubuntu", T, cache="cache", responses=[lifecycle_body([{"cycle": "24.04", "eol": True}])]),
            lc("ubuntu", T + 1.0, cache="cache")]},
        {"id": "lifecycle_cache_directory_missing",
         "write_errors": {"missing/upstream-debian.json": "ENOENT"},
         "calls": [lc("debian", T, cache="missing/upstream.json",
                      responses=[lifecycle_body([{"cycle": "13", "eol": "2028-08-09"}])])]},
        {"id": "lifecycle_cache_is_a_directory", "dirs": ["upstream-debian.json"],
         "write_errors": {"upstream-debian.json": "EISDIR"},
         "calls": [lc("debian", T, responses=[lifecycle_body([{"cycle": "13", "eol": "2028-08-09"}])])]},
        {"id": "lifecycle_cache_path_without_a_name", "calls": [lc("debian", T, cache="/")]},
    ]
    for name, data in {
        "product_missing": {"cycles": [], "checked_at_epoch": T},
        "product_other": {"product": "ubuntu", "cycles": [], "checked_at_epoch": T},
        "product_int": {"product": 1, "cycles": [], "checked_at_epoch": T},
        "cycles_object": {"product": "postgresql", "cycles": {}, "checked_at_epoch": T},
        "cycles_missing": {"product": "postgresql", "checked_at_epoch": T},
        "checked_missing": {"product": "postgresql", "cycles": []},
        "checked_str": {"product": "postgresql", "cycles": [], "checked_at_epoch": "x"},
    }.items():
        cases.append({"id": f"lifecycle_invalid_cache_{name}",
                      "files": {"upstream-postgresql.json": json.dumps(data)},
                      "calls": [lc("postgresql", T + 5.0, responses=[{"error": "URLError"}])]})
    cases.append({"id": "lifecycle_stale_cache_checked_bool",
                  "files": {"upstream-postgresql.json": json.dumps(
                      {"product": "postgresql", "cycles": ["kept"], "checked_at_epoch": False})},
                  "calls": [lc("postgresql", T, responses=[{"error": "URLError"}])]})
    for name, text in {"list": "[]", "string": '"postgresql"', "null": "null", "number": "1"}.items():
        # P3 (PLAN.md 4.2 item 12): `cached.get` on a non-object raises
        # AttributeError, which nothing catches.
        cases.append({"id": f"p3_lifecycle_cache_{name}", "files": {"upstream-postgresql.json": text},
                      "calls": [lc("postgresql", T, responses=[lifecycle_body(CYCLES)],
                                   p3={"tag": "cache-crash", "kind": "cache",
                                       "file": "upstream-postgresql.json",
                                       "responses": [lifecycle_body(CYCLES)]})]})
    cases.append({"id": "p3_lifecycle_cache_checked_huge_int",
                  "files": {"upstream-postgresql.json":
                            '{"checked_at_epoch": -1' + "0" * 400 + ', "cycles": [], "product": "postgresql"}'},
                  "calls": [lc("postgresql", T, responses=[{"error": "URLError"}],
                               p3={"tag": "cache-crash", "kind": "cache", "file": "upstream-postgresql.json",
                                   "responses": [{"error": "URLError"}]})]})
    # Lifecycle responses.
    for name, body in {
        "not_a_list": {"body": json.dumps({"cycle": "17"})},
        "empty_list": {"body": "[]"},
        "null": {"body": "null"},
        "no_valid_cycle": lifecycle_body([1, "17", None, [], {"cycle": 17}, {"latest": "17.1"}]),
        "broken_json": {"body": "[{"},
        "whole_cycles_kept": lifecycle_body(CYCLES + [{"cycle": "15", "eol": "2027-11-11",
                                                         "n": 18446744073709551617, "f": 1e16,
                                                         "s": "é\U0001f600"}]),
        "duplicate_cycles": lifecycle_body([{"cycle": "17", "eol": False}, {"cycle": "17", "eol": True}]),
        "long_body_cut": {"body": '[{"cycle": "17", "eol": false, "x": "', "pad": 1024 * 1024,
                          "pad_char": "a", "suffix": '"}]'},
    }.items():
        cases.append({"id": f"lifecycle_response_{name}",
                      "calls": [lc("postgresql", T, responses=[body])]})
    values: dict[str, Any] = {
        "true": True, "false": False, "null": None, "date": "2029-11-08", "leap_day": "2024-02-29",
        "no_leap_day": "2023-02-29", "day_31_in_april": "2029-04-31", "month_13": "2029-13-01",
        "month_0": "2029-00-10", "day_0": "2029-01-00", "year_0": "0000-01-01", "year_1": "0001-01-01",
        "year_9999": "9999-12-31", "short_year": "999-01-01", "single_digits": "2029-1-8",
        "slashes": "2029/11/08", "space": " 2029-11-08", "trailing_space": "2029-11-08 ",
        "datetime": "2029-11-08T00:00:00", "empty": "", "text": "soon", "int": 2029, "float": 2029.5,
        "list": ["2029-11-08"], "object": {"date": "2029-11-08"}, "sign": "+2029-11-08",
    }
    for key in ("eol", "support"):
        for name, value in values.items():
            cycle = {"cycle": "17", key: value} if key == "eol" else {"cycle": "17", "eol": False, key: value}
            cases.append({"id": f"lifecycle_{key}_{name}",
                          "calls": [lc("postgresql", T, cache=None,
                                       responses=[lifecycle_body([cycle, {"cycle": "16", "eol": True}])])]})
    cases.append({"id": "lifecycle_eol_missing_support_missing",
                  "calls": [lc("postgresql", T, cache=None, responses=[lifecycle_body([{"cycle": "17"}])])]})
    # P3 (PLAN.md 4.2 item 6): ISO forms Python 3.11+ reads, endoflife.date never sends.
    for name, value in {"basic": "20291108", "week": "2029-W45", "week_day": "2029-W45-4",
                        "basic_week": "2029W45", "basic_week_day": "2029W454"}.items():
        for key in ("eol", "support"):
            cycle = {"cycle": "17", key: value} if key == "eol" else {"cycle": "17", "eol": False, key: value}
            replaced = {**cycle, key: "not a date"}
            cases.append({"id": f"p3_lifecycle_{key}_{name}",
                          "calls": [lc("postgresql", T, cache=None,
                                       responses=[lifecycle_body([cycle, {"cycle": "16", "eol": True}])],
                                       p3={"tag": "iso-date", "kind": "body",
                                           "body": json.dumps([replaced, {"cycle": "16", "eol": True}])})]})
    cases.append({"id": "p3_lifecycle_response_nan",
                  "calls": [lc("postgresql", T, responses=[{"body": '[{"cycle": "17", "eol": false, "x": NaN}]'}],
                               p3={"tag": "non-standard-json", "kind": "error", "class": "JSONDecodeError"})]})
    return cases


# Not here: names that end with a dot or start with two (`a.`, `a..`,
# `..json`, `a.b.`), whose stem and suffix changed in Python 3.14; the Rust
# code follows 3.12 and 3.13, the hosts' versions
# (upstream::tests::cache_variant_follows_python_3_12_and_3_13).
CACHE_VARIANT_PATHS = [
    "/var/lib/software-live/upstream.json", "/var/lib/software-live/shadow/upstream.json",
    "upstream.json", "cache", ".hidden", ".hidden.json", "a.tar.gz", "..", "a/..",
    "a/.", ".", "", "/", "//", "///", "//x/y.json", "///x/y.json", "x/./y.json", "x//y.json",
    "y.json/", "/a/b.c.d", "/a/./b/../c.json", "a.b.c",
]


def gen_upstream() -> dict[str, Any]:
    variants = []
    for path in CACHE_VARIANT_PATHS:
        case: dict[str, Any] = {"path": path, "name": "ubuntu", "result": None, "error": None}
        try:
            case["result"] = str(live.cache_variant(Path(path), "ubuntu"))
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
        variants.append(case)
    return {
        "cache_variant": variants,
        "cases": [gen_upstream_case(case) for case in upstream_cases()],
        "constants": {"upstream_url": live.UPSTREAM_URL, "lifecycle_url": live.LIFECYCLE_URL,
                      "ttl": live.UPSTREAM_TTL},
    }


# ------------------------------------------------------------------ driver

GENERATORS: dict[str, Callable[[], Any]] = {
    "pyjson.json": gen_pyjson,
    "version.json": gen_version,
    "policy.json": gen_policy,
    "report.json": gen_report,
    "realpath.json": gen_realpath,
    "traefik.json": gen_traefik,
    "cli.json": gen_cli,
    "upstream.json": gen_upstream,
}


def render(name: str) -> str:
    return json.dumps(GENERATORS[name](), indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def check_fixtures(directory: Path = FIXTURES_DIR) -> list[str]:
    """The fixture files under ``directory`` that differ from a regeneration."""
    stale = []
    for name in GENERATORS:
        path = directory / name
        if not path.exists() or path.read_text(encoding="utf-8") != render(name):
            stale.append(name)
    return stale


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a committed fixture is stale")
    args = parser.parse_args()
    if args.check:
        stale = check_fixtures()
        for name in stale:
            print(f"stale fixture: {name}", file=sys.stderr)
        return 1 if stale else 0
    for name in GENERATORS:
        (FIXTURES_DIR / name).write_text(render(name), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
