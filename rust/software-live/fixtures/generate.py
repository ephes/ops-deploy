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
import copy
import errno
import functools
import grp
import hashlib
import importlib.util
import io
import json
import math
import os
import random
import stat
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
        ("apt_max_age_from_policy", {**BASE, "apt_max_age_seconds": 3600}, all_ok),
        ("everything_unknown", BASE, {
            name: {"observed": False, "status": "unknown", "issues": [], "error": "OSError: x"}
            for name in ("traefik", "os", "postgresql")} | {"apt": APT_UNKNOWN}),
    ]
    return cases


COLLECT_CACHE = "/var/lib/software-live/upstream.json"


def call_text(name: str, args: tuple[Any, ...]) -> str:
    """A step call as ``collect::tests`` logs it: the name and every argument
    as ``json.dumps(arg, sort_keys=True)`` (a path as its text)."""
    rendered = (json.dumps(str(a) if isinstance(a, Path) else a, sort_keys=True) for a in args)
    return f"{name}({', '.join(rendered)})"


def run_collect(policy: dict[str, Any], observations: dict[str, Any],
                cache: str | None) -> tuple[dict[str, Any], list[str]]:
    """``collect(policy, cache)`` with every step patched: the report and the
    steps in the order Python called them, with their arguments (PLAN.md
    3.3: the order, the time read before and after the observations)."""
    calls: list[str] = []

    def record(name: str, answer: Callable[..., Any]) -> Callable[..., Any]:
        def step(*args: Any) -> Any:
            calls.append(call_text(name, args))
            return json.loads(json.dumps(answer(*args)))
        return step

    fixed = lambda value: lambda *args: value
    times = iter([1_760_000_000.25, 1_760_000_042.75])
    with (
        mock.patch.object(live, "upstream", side_effect=record(
            "upstream", fixed({"status": "ok", "version": "3.7.9", "cached": True}))),
        mock.patch.object(live, "lifecycle_upstream", side_effect=record(
            "lifecycle_upstream", lambda product, *rest: {"status": "ok", "product": product})),
        mock.patch.object(live, "observe_traefik", side_effect=record(
            "observe_traefik", fixed(observations["traefik"]))),
        mock.patch.object(live, "observe_os", side_effect=record("observe_os", fixed(observations["os"]))),
        mock.patch.object(live, "observe_postgresql",
                          side_effect=record("observe_postgresql", fixed(observations["postgresql"]))),
        mock.patch.object(live, "observe_apt", side_effect=record("observe_apt", fixed(observations["apt"]))),
        mock.patch.object(live.time, "time", side_effect=lambda: (calls.append("time"), next(times))[1]),
    ):
        return live.collect(json.loads(json.dumps(policy)), None if cache is None else Path(cache)), calls


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
    for index, (case_id, policy, observations) in enumerate(summary_cases()):
        cache = COLLECT_CACHE if index % 2 else None
        report, calls = run_collect(policy, observations, cache)
        summary.append({
            "id": case_id,
            "policy": json.dumps(policy),
            "cache": cache,
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


# ------------------------------------------------------------------ os, postgresql: world
#
# The OS and PostgreSQL cases run the real Python functions on ``TextHost``
# (``FakeHost`` of the Traefik section plus text files), with the same world
# format and call log as ``probe::fake::FakeSystem``.


FAKE_ERRNOS.update({name: getattr(errno, name) for name in ("EIO", "EPERM")})


def text_file(data: Any) -> dict[str, Any]:
    """A file of the world: ``{"ok": text}``, or ``{"hex": …}`` for bytes
    that are not UTF-8 (given as ``{"hex": …}``)."""
    return dict(data) if isinstance(data, dict) else {"ok": data}


class TextHost(FakeHost):
    """``FakeHost`` plus text files: ``platform``'s ``open(candidate,
    encoding="utf-8")`` (logged as ``read_file``) and ``Path.open()`` of the
    PostgreSQL PID file (logged as ``read_head``), both with Python's real
    text-mode decoding of the bytes. ``files`` maps a path to ``{"ok":
    text}``, ``{"hex": …}`` or ``{"errno": …}`` (``FileEntry`` of the Rust
    fake); ``reads`` maps a path to answers of that form consumed in order
    (the last one repeats), for a file that changes between two reads."""

    def __init__(self, world: dict[str, Any]) -> None:
        super().__init__(world)
        self.reads = {path: collections.deque(answers) for path, answers in world.get("reads", {}).items()}

    def file_bytes(self, path: str) -> bytes:
        entry = self.take(self.reads.get(path)) if path in self.reads else self.world.get("files", {}).get(path)
        if entry is None:
            raise fake_os_error("ENOENT", path)
        if "errno" in entry:
            raise fake_os_error(entry["errno"], path)
        return bytes.fromhex(entry["hex"]) if "hex" in entry else entry["ok"].encode("utf-8")

    def text_open(self, path: Any, mode: str = "r", *args: Any, encoding: str | None = None,
                  **kwargs: Any) -> io.TextIOWrapper:
        assert mode == "r" and not args and not kwargs, (mode, args, kwargs)
        self.calls.append(f"read_file {path}")
        return io.TextIOWrapper(io.BytesIO(self.file_bytes(str(path))), encoding=encoding)

    def path_open(self, path: Any, mode: str = "r", *args: Any, **kwargs: Any) -> io.TextIOWrapper:
        assert mode == "r" and not args and not kwargs, (mode, args, kwargs)
        self.calls.append(f"read_head {path}")
        return io.TextIOWrapper(io.BytesIO(self.file_bytes(str(path))), encoding="utf-8")

    @contextlib.contextmanager
    def patched(self) -> Any:
        with (
            super().patched(),
            mock.patch.object(live.platform, "open", self.text_open, create=True),
            mock.patch.object(live.platform, "_os_release_cache", None),
            # A function, so the Path instance binds as its first argument.
            mock.patch.object(live.Path, "open", lambda path, *a, **k: self.path_open(path, *a, **k)),
        ):
            yield self


def outcome(function: Callable[[], Any], world: dict[str, Any]) -> dict[str, Any]:
    """Run ``function`` in ``world``: its result or exception, and the calls."""
    case: dict[str, Any] = {"world": world}
    host = TextHost(world)
    with host.patched():
        try:
            case["result"] = function()
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
    case["calls"] = host.calls
    return case


def observation(function: Callable[[], dict[str, Any]], world: dict[str, Any]) -> dict[str, Any]:
    """An ``observe_*`` result; its ``error`` text is split into class and
    contract message like any other exception (PLAN.md 4.2 item 5)."""
    case = outcome(function, world)
    result = case["result"]
    text = result.pop("error", None)
    if text is not None:
        cls, _, message = text.partition(": ")
        contract = cls == "KeyError" or message in OWN_MESSAGES
        case["error"] = {"class": cls, "message": message if contract else None}
    return case


# ------------------------------------------------------------------ lifecycle

LIFECYCLE_DATES: list[tuple[Any, str | None]] = [
    ("2028-08-09", None), ("2028-02-29", None), ("2027-02-29", None), ("0001-01-01", None),
    ("9999-12-31", None), ("0000-01-01", None), ("2028-13-01", None), ("2028-00-10", None),
    ("2028-01-32", None), ("2028-04-31", None), ("2028-8-9", None), (" 2028-08-09", None),
    ("2028-08-09 ", None), ("2028-08-09T00:00", None), ("+2028-08-09", None), ("2028/08/09", None),
    ("", None), ("x", None), ("\uff12\uff10\uff12\uff18-08-09", None), ("\u0662028-08-09", None),
    (None, None), (True, None), (False, None), (0, None), (1.5, None), ([], None), ({}, None),
    ("20280809", "iso-date"), ("2028-W32", "iso-date"), ("2028-W32-3", "iso-date"),
    ("2028W32", "iso-date"), ("2028W323", "iso-date"),
]
TODAY = "2026-09-15"
LIFECYCLE_ENDED_VALUES: list[Any] = [
    True, False, None, "2026-09-14", "2026-09-15", "2026-09-16", "2026-13-01", 20260915, ["x"],
]
NOW_DATES: list[float] = [
    0.0, 1_789_344_000.0, 1_789_430_399.999999, 1_789_430_399.9999996, 1_789_430_399.9999994,
    1_789_430_400.0, -0.5, -0.0000004, -0.0000006, -86_400.0, -1.0, 1e9 + 0.5,
    253_402_300_799.0, 253_402_300_800.0, -62_135_596_800.0, -62_135_596_801.0,
]


def gen_lifecycle() -> dict[str, Any]:
    dates = []
    for value, p3 in LIFECYCLE_DATES:
        case: dict[str, Any] = {"value": value}
        try:
            parsed = live.lifecycle_date(value)
            case["result"] = None if parsed is None else parsed.isoformat()
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
        if p3:
            assert "result" in case, value
            case["p3"] = p3
        dates.append(case)
    today = live.date.fromisoformat(TODAY)
    ended = []
    for value in LIFECYCLE_ENDED_VALUES:
        for flag in (True, False):
            case = {"value": value, "today": TODAY, "true_means_ended": flag}
            try:
                case["result"] = live.lifecycle_ended(value, today, true_means_ended=flag)
            except Exception as exc:  # noqa: BLE001 - the oracle's answer
                case["error"] = error(exc)
            ended.append(case)
    now_dates = []
    for now in NOW_DATES:
        case = {"now": now}
        try:
            case["date"] = live.datetime.fromtimestamp(now, live.UTC).date().isoformat()
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
        now_dates.append(case)
    evidence_inputs = [
        {"status": "ok", "product": "ubuntu", "cycles": [{"cycle": "24.04"}], "checked_at_epoch": 99.5,
         "cached": True, "other": 1},
        {"status": "unknown", "error": "URLError", "last_success": {"product": "debian",
                                                                     "checked_at_epoch": 12}},
        {"status": "unknown", "error": "HTTPError", "last_success": None},
        {"status": "unknown", "error": "x", "last_success": {"cycles": []}},
        {"status": "unknown", "last_success": [{"checked_at_epoch": 1}]},
        {"status": "not_applicable"},
        {},
        {"cached": False, "error": None, "last_success": {"checked_at_epoch": None}},
    ]
    evidence = [{"latest": latest, "result": live.lifecycle_evidence(latest)} for latest in evidence_inputs]
    cycle_inputs: list[tuple[Any, str]] = [
        ({"status": "ok", "cycles": [{"cycle": "13"}, {"cycle": "12", "latest": "12.15"}]}, "12"),
        ({"status": "ok", "cycles": [{"cycle": "13"}, {"cycle": "13", "latest": "second"}]}, "13"),
        ({"status": "ok", "cycles": [{"cycle": "13"}]}, "12"),
        ({"status": "ok", "cycles": []}, "12"),
        ({"status": "unknown", "cycles": [{"cycle": "12"}]}, "12"),
        ({"cycles": [{"cycle": "12"}]}, "12"),
        ({"status": "ok"}, "12"),
        ({"status": "ok", "cycles": [{"cycle": 12}]}, "12"),
        ({"status": "ok", "cycles": [{"cycle": 24.04}]}, "24.04"),
        ({"status": "ok", "cycles": [{"cycle": 24.1}]}, "24.10"),
        ({"status": "ok", "cycles": [{"cycle": None}]}, "None"),
        ({"status": "ok", "cycles": [{"cycle": True}]}, "True"),
        ({"status": "ok", "cycles": [{}]}, "None"),
        ({"status": "ok", "cycles": [{"other": 1}, {"cycle": "12"}]}, "12"),
        ({"status": "ok", "cycles": ["12"]}, "12"),
        ({"status": "ok", "cycles": [{"cycle": "12"}, "13"]}, "12"),
        ({"status": "ok", "cycles": [{"cycle": "11"}, None]}, "12"),
        ({"status": "ok", "cycles": {}}, "12"),
        ({"status": "ok", "cycles": {"12": {}}}, "12"),
        ({"status": "ok", "cycles": ""}, "12"),
        ({"status": "ok", "cycles": "12"}, "12"),
        ({"status": "ok", "cycles": None}, "12"),
        ({"status": "ok", "cycles": 12}, "12"),
    ]
    cycles = []
    for latest, cycle in cycle_inputs:
        case = {"latest": latest, "cycle": cycle}
        try:
            case["result"] = live.lifecycle_cycle(latest, cycle)
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
        cycles.append(case)
    return {"dates": dates, "ended": ended, "now_dates": now_dates, "evidence": evidence,
            "cycles": cycles}


# ------------------------------------------------------------------ os

UBUNTU_RELEASE = (
    'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
    'VERSION="24.04.5 LTS (Noble Numbat)"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n'
    'HOME_URL="https://www.ubuntu.com/"\nUBUNTU_CODENAME=noble\n'
    'LOGO=ubuntu-logo\n'
)
DEBIAN_RELEASE = (
    'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\n'
    'VERSION="13 (trixie)"\nVERSION_CODENAME=trixie\nDEBIAN_VERSION_FULL=13.1\nID=debian\n'
    'HOME_URL="https://www.debian.org/"\n'
)
OS_RELEASE_TEXTS: dict[str, Any] = {
    "ubuntu": UBUNTU_RELEASE,
    "debian": DEBIAN_RELEASE,
    "empty": "",
    "no_trailing_newline": "ID=ubuntu\nVERSION_ID=24.04",
    "crlf": "ID=ubuntu\r\nVERSION_ID=\"24.04\"\r\n",
    "cr_only": "ID=ubuntu\rVERSION_ID=24.04\r",
    "double_quotes": 'A="x"\nB="x y"\nC=""\nD="\nE="x\nF=x"\nG="x"y"\nH="x"\'\n',
    "single_quotes": "A='x'\nB='x \"y\"'\nC=''\nD='\nE='x\"\nF=\"x'\n",
    "escapes": 'A="a\\"b"\nB=a\\\\b\nC=\\$HOME\nD=\\`x\\`\nE=\\\'x\nF=a\\nb\nG=trailing\\\nH=\\\\\\"\nI=\\x\\\\\\\\\n',
    "names": "lower=1\n9DIGIT=2\n_U=3\nA-B=4\nA.B=5\n=6\n Ä=7\nÄ=8\nA B=9\n",
    "spacing": "A = b\n B=c\nC=d \nD=\te\nexport E=f\n#F=g\n# comment\n\n   \n",
    "equals_in_value": "A=b=c\nB==\nC='='\n",
    "duplicates": "ID=debian\nID=ubuntu\nVERSION_ID=1\nVERSION_ID=24.04\n",
    "defaults_only": "OTHER=1\n",
    "unicode_values": "PRETTY_NAME=\"\u00dcbuntu \u65e5\u672c \U0001f600\"\nA=\u2028x\u2029\nB=\x0bx\x0c\nC=\x1cx\x1d\x85\nD=a\x00b\n",
    "bom": "\ufeffID=ubuntu\nVERSION_ID=24.04\n",
    "uppercase_id": "ID=Ubuntu\nVERSION_ID=24.04\n",
    "tab_after_value": "ID=ubuntu\t\nVERSION_ID=24.04\n",
    "invalid_utf8": {"hex": "49443d7562756e74750a56455253494f4e5f49443d32342e30340aff0a"},
    "invalid_utf8_late": {"hex": "49443d7562756e74750a" + "41" * 9000 + "c3"},
    "latin1": {"hex": "4e414d453d22c3bc220a50524554545f4e414d453d22fc220a"},
}


def gen_os_release() -> list[dict[str, Any]]:
    cases = []
    for case_id, data in OS_RELEASE_TEXTS.items():
        world = {"files": {"/etc/os-release": text_file(data)}}
        cases.append({"id": case_id, **outcome(live.platform.freedesktop_os_release, world)})
    fallbacks: dict[str, dict[str, Any]] = {
        "fallback_missing": {"/usr/lib/os-release": {"ok": DEBIAN_RELEASE}},
        "fallback_denied": {"/etc/os-release": {"errno": "EACCES"}, "/usr/lib/os-release": {"ok": UBUNTU_RELEASE}},
        "fallback_directory": {"/etc/os-release": {"errno": "EISDIR"}, "/usr/lib/os-release": {"ok": UBUNTU_RELEASE}},
        "fallback_io_error": {"/etc/os-release": {"errno": "EIO"}, "/usr/lib/os-release": {"ok": UBUNTU_RELEASE}},
        "no_fallback_after_decode_error": {"/etc/os-release": {"hex": "ff"},
                                           "/usr/lib/os-release": {"ok": UBUNTU_RELEASE}},
        "both_missing": {},
        "denied_then_missing": {"/etc/os-release": {"errno": "EACCES"}},
        "missing_then_denied": {"/usr/lib/os-release": {"errno": "EACCES"}},
        "missing_then_directory": {"/usr/lib/os-release": {"errno": "EISDIR"}},
        "missing_then_loop": {"/usr/lib/os-release": {"errno": "ELOOP"}},
    }
    for case_id, files in fallbacks.items():
        cases.append({"id": case_id, **outcome(live.platform.freedesktop_os_release, {"files": files})})
    return cases


def os_world(text: Any) -> dict[str, Any]:
    return {"files": {"/etc/os-release": text_file(text)}}


def lifecycle_ok(product: str, cycles: list[Any], **extra: Any) -> dict[str, Any]:
    return {"status": "ok", "product": product, "cycles": cycles, "checked_at_epoch": 1_789_000_000.5,
            "cached": True, **extra}


UBUNTU_CYCLES = [
    {"cycle": "25.10", "lts": False, "releaseDate": "2025-10-09", "support": "2026-07-09",
     "eol": "2026-07-09", "latest": "25.10"},
    {"cycle": "24.04", "lts": True, "releaseDate": "2024-04-25", "support": "2029-05-31",
     "eol": "2029-05-31", "extendedSupport": "2036-04-25", "latest": "24.04.5"},
]
DEBIAN_CYCLES = [
    {"cycle": "13", "support": "2028-08-09", "eol": "2030-06-30"},
    {"cycle": "12", "latest": "12.15", "support": "2026-07-11", "eol": "2028-06-30"},
]
UBUNTU_POLICY = {"expected_id": "ubuntu", "desired_cycle": "24.04", "product": "ubuntu"}
DEBIAN_POLICY = {"expected_id": "debian", "desired_cycle": "13", "product": "debian"}
DEBIAN_12 = 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
DEBIAN_13 = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
UNKNOWN_LATEST = {"status": "unknown", "error": "URLError", "last_success": None}
STALE_LATEST = {"status": "unknown", "error": "HTTPError",
                "last_success": lifecycle_ok("ubuntu", UBUNTU_CYCLES)}


def os_cases() -> list[tuple[str, Any, dict[str, Any], Any, float]]:
    """(id, os-release data or a files map, policy, latest, now)."""
    now = 1_789_344_000.0  # 2026-09-14
    ubuntu = lifecycle_ok("ubuntu", UBUNTU_CYCLES)
    debian = lifecycle_ok("debian", DEBIAN_CYCLES)
    cycles = lambda *items: lifecycle_ok("debian", list(items))
    return [
        # tests/test_software_live.py
        ("desired_drift_and_lts_phase", DEBIAN_12, {"expected_id": "debian", "desired_cycle": "13"},
         {"status": "ok", "cycles": DEBIAN_CYCLES}, 1_789_344_000),
        ("boolean_support_false_warns", DEBIAN_13, {"expected_id": "debian", "desired_cycle": "13"},
         {"status": "ok", "cycles": [{"cycle": "13", "support": False, "eol": False}]}, 1_789_430_400),
        ("boolean_support_true_is_ok", DEBIAN_13, {"expected_id": "debian", "desired_cycle": "13"},
         {"status": "ok", "cycles": [{"cycle": "13", "support": True, "eol": False}]}, 1_789_430_400),
        # the hosts
        ("ubuntu_ok", UBUNTU_RELEASE, UBUNTU_POLICY, ubuntu, now),
        ("debian_ok", DEBIAN_RELEASE, DEBIAN_POLICY, debian, now),
        ("fallback_to_usr_lib", {"/usr/lib/os-release": {"ok": UBUNTU_RELEASE}}, UBUNTU_POLICY, ubuntu, now),
        ("uppercase_id", "ID=UBUNTU\nVERSION_ID=24.04\n", UBUNTU_POLICY, ubuntu, now),
        ("no_codename_or_pretty_name", "ID=ubuntu\nVERSION_ID=24.04\n", UBUNTU_POLICY, ubuntu, now),
        # failures
        ("id_mismatch", DEBIAN_RELEASE, UBUNTU_POLICY, ubuntu, now),
        ("id_default_linux", "VERSION_ID=24.04\n", UBUNTU_POLICY, ubuntu, now),
        ("id_with_tab", "ID=ubuntu\t\nVERSION_ID=24.04\n", UBUNTU_POLICY, ubuntu, now),
        ("version_id_missing", "ID=ubuntu\n", UBUNTU_POLICY, ubuntu, now),
        ("version_id_missing_and_id_mismatch", "ID=debian\n", UBUNTU_POLICY, ubuntu, now),
        ("os_release_unreadable", {}, UBUNTU_POLICY, ubuntu, now),
        ("os_release_denied", {"/etc/os-release": {"errno": "EACCES"},
                               "/usr/lib/os-release": {"errno": "EACCES"}}, UBUNTU_POLICY, ubuntu, now),
        ("os_release_not_utf8", {"hex": "49443d7562756e74750aff"}, UBUNTU_POLICY, ubuntu, now),
        # policy values
        ("desired_cycle_float", UBUNTU_RELEASE, {**UBUNTU_POLICY, "desired_cycle": 24.04}, ubuntu, now),
        ("desired_cycle_int", DEBIAN_RELEASE, {**DEBIAN_POLICY, "desired_cycle": 13}, debian, now),
        ("desired_cycle_other", UBUNTU_RELEASE, {**UBUNTU_POLICY, "desired_cycle": "26.04"}, ubuntu, now),
        # upstream
        ("upstream_unknown", UBUNTU_RELEASE, UBUNTU_POLICY, UNKNOWN_LATEST, now),
        ("upstream_unknown_with_stale_evidence", UBUNTU_RELEASE, UBUNTU_POLICY, STALE_LATEST, now),
        ("upstream_unknown_and_drift", DEBIAN_12, DEBIAN_POLICY, UNKNOWN_LATEST, now),
        ("upstream_not_applicable", UBUNTU_RELEASE, UBUNTU_POLICY, {"status": "not_applicable"}, now),
        ("cycle_missing", 'ID=ubuntu\nVERSION_ID="22.04"\n', {**UBUNTU_POLICY, "desired_cycle": "22.04"},
         ubuntu, now),
        ("cycles_key_missing", DEBIAN_RELEASE, DEBIAN_POLICY, {"status": "ok"}, now),
        ("cycles_not_a_list", DEBIAN_RELEASE, DEBIAN_POLICY, {"status": "ok", "cycles": "13"}, now),
        ("cycle_number", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": 13, "eol": False}), now),
        ("cycle_float_number", UBUNTU_RELEASE, UBUNTU_POLICY,
         lifecycle_ok("ubuntu", [{"cycle": 24.04, "eol": False}]), now),
        # lifecycle evaluation
        ("eol_reached", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "support": "2026-01-01", "eol": "2026-09-14"}), now),
        ("eol_tomorrow_support_ended", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "support": "2026-09-14", "eol": "2026-09-15"}), now),
        ("support_tomorrow", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "support": "2026-09-15", "eol": "2030-06-30"}), now),
        ("eol_true", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": "13", "support": True, "eol": True}), now),
        ("eol_false_support_absent", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": "13", "eol": False}), now),
        ("eol_null_support_null", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "eol": None, "support": None}), now),
        ("eol_missing", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": "13"}), now),
        ("eol_invalid_date", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": "13", "eol": "2030-02-30"}), now),
        ("eol_number", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": "13", "eol": 2030}), now),
        ("support_invalid_after_eol_check", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "eol": "2030-06-30", "support": "soon"}), now),
        ("eol_reached_hides_invalid_support", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "eol": True, "support": "soon"}), now),
        ("newest_cycle_without_cycle_key", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"latest": "x"}, {"cycle": "13", "eol": False}), now),
        ("newest_cycle_number", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": 14}, {"cycle": "13", "eol": False}), now),
        ("today_rounds_to_the_next_day", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "eol": "2026-09-15"}), 1_789_430_399.9999996),
        ("today_stays_before_midnight", DEBIAN_RELEASE, DEBIAN_POLICY,
         cycles({"cycle": "13", "eol": "2026-09-15"}), 1_789_430_399.9999994),
        ("now_out_of_range", DEBIAN_RELEASE, DEBIAN_POLICY, cycles({"cycle": "13", "eol": False}),
         253_402_300_800.0),
    ]


def gen_os() -> dict[str, Any]:
    observe = []
    seen = set()
    for case_id, data, policy, latest, now in os_cases():
        assert case_id not in seen, case_id
        seen.add(case_id)
        is_files_map = isinstance(data, dict) and "hex" not in data
        world = {"files": data} if is_files_map else os_world(data)
        case = observation(
            functools.partial(live.observe_os, copy.deepcopy(policy), copy.deepcopy(latest), now), world)
        observe.append({"id": case_id, "policy": policy, "latest": latest, "now": now, **case})
    return {"release": gen_os_release(), "observe": observe}


# ------------------------------------------------------------------ postgresql

PG_LSCLUSTERS = ["/usr/bin/pg_lsclusters", "--no-header"]
CLUSTER_MAIN = "17  main    5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log"


def lsclusters(stdout: str = "", **spec: Any) -> dict[str, Any]:
    return {"argv": PG_LSCLUSTERS, "stdout": stdout, **spec}


LSCLUSTERS_OUTPUTS: dict[str, Any] = {
    # tests/test_software_live.py
    "omits_data_paths": (
        "17 main 5432 online postgres /var/lib/postgresql/17/main "
        "/var/log/postgresql/postgresql-17-main.log\n"
        "16 old 5433 down,binaries_missing postgres "
        "/var/lib/postgresql/16/old /var/log/postgresql/postgresql-16-old.log"
    ),
    "rejects_unsafe_identity": "17 ../main 5432 online postgres /var/lib/postgresql/17/main",
    # layout
    "host_output": CLUSTER_MAIN + "\n",
    "empty": "",
    "whitespace_only": " \n\t ",
    "six_fields": "17 main 5432 online postgres /data",
    "five_fields": "17 main 5432 online postgres",
    "many_fields": "17 main 5432 online,recovery postgres /data /log extra  fields\there ",
    "blank_line_between": "17 main 5432 online postgres /d /l\n\n16 old 5433 down postgres /d /l",
    "crlf": "17 main 5432 online postgres /d /l\r\n16 old 5433 down postgres /d /l\r\n",
    "cr": "17 main 5432 online postgres /d /l\r16 old 5433 down postgres /d /l",
    "python_line_breaks": "17 a 1 online p /d\x0b17 b 2 online p /d\x0c17 c 3 online p /d\x1c17 d 4 online p /d"
                          "\x1d17 e 5 online p /d\x1e17 f 6 online p /d\x85"
                          "17 g 7 online p /d\u202817 h 8 online p /d\u202917 i 9 online p /d",
    "python_whitespace_separators": "17\x1fmain\u30005432\u00a0online\u2003postgres\x1f/d",
    "python_line_break_inside_fields": "17\x1fmain\u30005432\u00a0online\u2003postgres\x1c/d",
    "tabs": "17\tmain\t5432\tonline\tpostgres\t/d\t/l",
    "unicode_status_and_owner": "17 main 5432 \u00f6nline p\u00f6stgres /d",
    # identity
    "major_with_letter": "17a main 5432 online postgres /d",
    "major_negative": "-17 main 5432 online postgres /d",
    "name_digit_first": "17 9main 5432 online postgres /d",
    "name_dash_underscore": "17 _m-1 5432 online postgres /d",
    "name_dot": "17 m.1 5432 online postgres /d",
    "name_non_ascii": "17 m\u00e4in 5432 online postgres /d",
    # port
    "port_underscore": "17 main 5_432 online postgres /d",
    "port_double_underscore": "17 main 5__432 online postgres /d",
    "port_plus": "17 main +5432 online postgres /d",
    "port_leading_zeros": "17 main 0005432 online postgres /d",
    "port_zero": "17 main 0 online postgres /d",
    "port_negative_zero": "17 main -0 online postgres /d",
    "port_max": "17 main 65535 online postgres /d",
    "port_over": "17 main 65536 online postgres /d",
    "port_negative": "17 main -1 online postgres /d",
    "port_word": "17 main x online postgres /d",
    "port_float": "17 main 5432.0 online postgres /d",
    "port_hex": "17 main 0x10 online postgres /d",
    "port_huge": "17 main 123456789012345678901234567890 online postgres /d",
    "port_4300_digits": "17 main " + "1" * 4300 + " online postgres /d",
    "port_4301_digits": "17 main " + "1" * 4301 + " online postgres /d",
    "unsafe_identity_before_port": "17 ../x port online postgres /d",
    "port_error_after_good_line": "17 main 5432 online postgres /d\n16 old 0 down postgres /d",
}
LSCLUSTERS_P3 = {
    "major_unicode_digits": "\u0661\u0667 main 5432 online postgres /d",
    "port_unicode_digits": "17 main \u0665\u0664\u0663\u0662 online postgres /d",
}
LSCLUSTERS_FAILURES: dict[str, dict[str, Any]] = {
    "missing": lsclusters(error="ENOENT"),
    "denied": lsclusters(error="EACCES"),
    "fails": lsclusters("17 main 5432 online postgres /d", exit=1),
    "times_out": lsclusters(error="timeout"),
}


def gen_clusters() -> list[dict[str, Any]]:
    cases = []
    for case_id, stdout in LSCLUSTERS_OUTPUTS.items():
        cases.append({"id": case_id, **outcome(live.postgres_clusters, {"commands": [lsclusters(stdout)]})})
    for case_id, stdout in LSCLUSTERS_P3.items():
        case = {"id": case_id, **outcome(live.postgres_clusters, {"commands": [lsclusters(stdout)]})}
        assert "result" in case, case_id
        cases.append({**case, "p3": "unicode-digits"})
    for case_id, spec in LSCLUSTERS_FAILURES.items():
        cases.append({"id": case_id, **outcome(live.postgres_clusters, {"commands": [spec]})})
    return cases


PG_PID = "/var/run/postgresql/17-main.pid"
PG_EXE = "/proc/4242/exe"
PG_FD = 7
PG_BINARY = "/usr/lib/postgresql/17/bin/postgres"
PG_IMAGE = {"mode": 0o100755, "dev": 2049, "ino": 1311, "size": 9_876_543,
            "mtime_ns": 1_760_000_000_123_456_789, "ctime_ns": 1_760_000_001_000_000_000}
PG_PID_TEXT = "4242\n/var/lib/postgresql/17/main\n1760000000\n5432\n/var/run/postgresql\n*\n  1234567 0\nready\n"
PG_VERSION = "postgres (PostgreSQL) 17.6 (Ubuntu 17.6-1.pgdg24.04+1)\n"
MAIN_CLUSTER = {"major": "17", "name": "main", "port": 5432, "status": "online", "owner": "postgres"}


def version_probe(stdout: str = PG_VERSION, **spec: Any) -> dict[str, Any]:
    return {"argv": [f"/proc/self/fd/{PG_FD}", "--version"], "pass_fds": [PG_FD], "stdout": stdout, **spec}


def pg_image(fd: int = PG_FD, *fstat: dict[str, Any]) -> dict[str, Any]:
    """``open(/proc/<pid>/exe, "rb")``: descriptor ``fd`` and its ``fstat`` answers."""
    return {"ok": {"fd": fd, "data": "", "fstat": list(fstat) or [{"ok": PG_IMAGE}]}}


def pg_world(**changes: Any) -> dict[str, Any]:
    """The world of a running ``17/main`` postmaster; ``changes`` replace keys."""
    world: dict[str, Any] = {
        "files": {PG_PID: {"ok": PG_PID_TEXT}},
        "open": {PG_EXE: [pg_image()]},
        "readlink": {f"/proc/self/fd/{PG_FD}": [{"ok": PG_BINARY}]},
        "stat": {PG_EXE: [{"ok": PG_IMAGE}]},
        "commands": [version_probe()],
    }
    world.update(changes)
    return world


def server_version_cases() -> list[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """(id, world, cluster or None for MAIN_CLUSTER)."""
    changed = dict(PG_IMAGE, mtime_ns=PG_IMAGE["mtime_ns"] + 1)
    moved = dict(PG_IMAGE, ino=PG_IMAGE["ino"] + 1)
    not_run: dict[str, Any] = {"commands": []}
    pid = lambda text, **more: pg_world(files={PG_PID: text_file(text)}, **more)
    return [
        ("running_postmaster", pg_world(), None),
        ("version_without_suffix", pg_world(commands=[version_probe("postgres (PostgreSQL) 17.6")]), None),
        ("version_three_parts", pg_world(commands=[version_probe("postgres (PostgreSQL) 9.6.24\n")]), None),
        ("version_second_line", pg_world(commands=[version_probe("postgres (PostgreSQL) 17.6\nmore text")]), None),
        ("version_python_space", pg_world(commands=[version_probe("postgres (PostgreSQL) 17.6\x1cx")]), None),
        ("version_stripped", pg_world(commands=[version_probe("  postgres (PostgreSQL) 17.6  \n\n")]), None),
        ("version_leading_zero_major", pg_world(commands=[version_probe("postgres (PostgreSQL) 017.6")]), None),
        ("version_one_part", pg_world(commands=[version_probe("postgres (PostgreSQL) 17")]), None),
        ("version_beta", pg_world(commands=[version_probe("postgres (PostgreSQL) 18beta1")]), None),
        ("version_suffix_without_space", pg_world(commands=[version_probe("postgres (PostgreSQL) 17.6beta")]), None),
        ("version_suffix_then_line", pg_world(commands=[version_probe("postgres (PostgreSQL) 17.6 a\nb")]), None),
        ("version_other_program", pg_world(commands=[version_probe("pg (PostgreSQL) 17.6")]), None),
        ("version_empty", pg_world(commands=[version_probe("")]), None),
        ("version_probe_fails", pg_world(commands=[version_probe(exit=1)]), None),
        ("version_probe_times_out", pg_world(commands=[version_probe(error="timeout")]), None),
        ("version_probe_cannot_start", pg_world(commands=[version_probe(error="ENOENT")]), None),
        # the image
        ("symlinked_install", pg_world(
            readlink={f"/proc/self/fd/{PG_FD}": [{"ok": "/opt/postgresql/17/bin/postgres"}]},
            realpath={PG_BINARY: "/opt/postgresql/17/bin/postgres"}), None),
        ("deleted_image", pg_world(readlink={f"/proc/self/fd/{PG_FD}": [{"ok": PG_BINARY + " (deleted)"}]},
                                   **not_run), None),
        ("other_image", pg_world(readlink={f"/proc/self/fd/{PG_FD}": [{"ok": "/usr/bin/python3.12"}]},
                                 **not_run), None),
        ("other_major_image", pg_world(readlink={f"/proc/self/fd/{PG_FD}": [{"ok": "/usr/lib/postgresql/16/bin/postgres"}]},
                                       **not_run), None),
        ("descriptor_target_unreadable", pg_world(readlink={f"/proc/self/fd/{PG_FD}": [{"errno": "EACCES"}]},
                                                  **not_run), None),
        ("process_gone", pg_world(open={PG_EXE: [{"errno": "ENOENT"}]}, **not_run), None),
        ("process_image_denied", pg_world(open={PG_EXE: [{"errno": "EACCES"}]}, **not_run), None),
        ("image_changed_during_probe", pg_world(open={PG_EXE: [pg_image(PG_FD, {"ok": PG_IMAGE}, {"ok": changed})]}),
         None),
        ("image_replaced_at_path", pg_world(stat={PG_EXE: [{"ok": moved}]}), None),
        ("process_gone_after_probe", pg_world(stat={PG_EXE: [{"errno": "ENOENT"}]}), None),
        ("fstat_fails", pg_world(open={PG_EXE: [pg_image(PG_FD, {"errno": "EIO"})]}, **not_run), None),
        # the PID file
        ("pid_file_missing", pg_world(files={}, open={}, readlink={}, stat={}, **not_run), None),
        ("pid_file_denied", pg_world(files={PG_PID: {"errno": "EACCES"}}, **not_run), None),
        ("pid_only", pid("4242"), None),
        ("pid_padded", pid("  4242 \t\n"), None),
        ("pid_crlf", pid("4242\r\nrest"), None),
        ("pid_cr", pid("4242\rrest"), None),
        ("pid_python_space", pid("\x1c4242\x1d\n"), None),
        ("pid_zero", pid("0\n", **not_run), None),
        ("pid_leading_zero", pid("04242\n", **not_run), None),
        ("pid_negative", pid("-1\n", **not_run), None),
        ("pid_word", pid("abc\n", **not_run), None),
        ("pid_empty", pid("", **not_run), None),
        ("pid_blank_first_line", pid("\n4242\n", **not_run), None),
        ("pid_path_traversal", pid("../1\n", **not_run), None),
        ("pid_line_over_32_chars", pid("1" * 40 + "\n", open={"/proc/" + "1" * 32 + "/exe": [{"errno": "ENOENT"}]},
                                       **not_run), None),
        ("pid_not_utf8", pid({"hex": "34323432ff0a"}, **not_run), None),
        ("pid_not_utf8_in_first_chunk", pid({"hex": "343234320a" + "61" * 100 + "ff"}, **not_run), None),
        ("pid_not_utf8_at_first_chunk_end", pid({"hex": "343234320a" + "61" * 8186 + "ff"}, **not_run), None),
        ("pid_not_utf8_after_first_chunk", pid({"hex": "343234320a" + "61" * 8187 + "ff"}), None),
        ("pid_incomplete_char_after_line", pid({"hex": "343234320ae282"}), None),
        ("pid_incomplete_char_in_line", pid({"hex": "34323432e282"}, **not_run), None),
        ("pid_non_ascii_after_line", pid("4242\n\u00e9\u65e5\n"), None),
        ("pid_changed", pg_world(files={}, reads={PG_PID: [{"ok": PG_PID_TEXT}, {"ok": "4243\n"}]}), None),
        ("pid_file_gone_after_probe", pg_world(files={}, reads={PG_PID: [{"ok": PG_PID_TEXT}, {"errno": "ENOENT"}]}),
         None),
        ("pid_file_rewritten_same_pid", pg_world(files={}, reads={PG_PID: [{"ok": PG_PID_TEXT}, {"ok": "4242\nother\n"}]}),
         None),
        ("other_cluster_paths", pg_world(
            files={"/var/run/postgresql/16-old_1.pid": {"ok": "99\n"}},
            open={"/proc/99/exe": [pg_image(5)]},
            readlink={"/proc/self/fd/5": [{"ok": "/usr/lib/postgresql/16/bin/postgres"}]},
            stat={"/proc/99/exe": [{"ok": PG_IMAGE}]},
            commands=[{"argv": ["/proc/self/fd/5", "--version"], "pass_fds": [5],
                       "stdout": "postgres (PostgreSQL) 16.10\n"}]),
         {"major": "16", "name": "old_1", "port": 5433, "status": "online", "owner": "postgres"}),
    ]


# Python reads non-ASCII digits as digits; the Rust code refuses them
# (PLAN.md 4.2 item 11).
SERVER_VERSION_P3: list[tuple[str, dict[str, Any]]] = [
    ("pid_unicode_digits", pg_world(files={PG_PID: {"ok": "4\u0662\n"}}, open={"/proc/4\u0662/exe": [pg_image()]},
                                    stat={"/proc/4\u0662/exe": [{"ok": PG_IMAGE}]})),
    ("version_unicode_digits", pg_world(commands=[version_probe("postgres (PostgreSQL) 1\u0667.6\n")])),
]


def gen_server_version() -> list[dict[str, Any]]:
    cases = []
    seen = set()
    for case_id, world, cluster in server_version_cases():
        assert case_id not in seen, case_id
        seen.add(case_id)
        cluster = cluster or MAIN_CLUSTER
        case = outcome(functools.partial(live.postgresql_server_version, copy.deepcopy(cluster)), world)
        cases.append({"id": case_id, "cluster": cluster, **case})
    for case_id, world in SERVER_VERSION_P3:
        case = outcome(functools.partial(live.postgresql_server_version, copy.deepcopy(MAIN_CLUSTER)), world)
        assert "result" in case, case_id
        cases.append({"id": case_id, "cluster": MAIN_CLUSTER, **case, "p3": "unicode-digits"})
    return cases


PG_POLICY = {"expected": True, "desired_major": "17", "cluster": "main", "port": 5432}
PG_CYCLES = [
    {"cycle": "18", "latest": "18.1", "eol": "2030-11-14", "releaseDate": "2025-09-25"},
    {"cycle": "17", "latest": "17.6", "eol": "2029-11-08", "releaseDate": "2024-09-26"},
    {"cycle": "16", "latest": "16.10", "eol": "2028-11-09"},
]
PG_OLD = "16 old 5433 down,binaries_missing postgres /var/lib/postgresql/16/old /var/log/postgresql/old.log"


def pg_latest(cycles: list[Any] = PG_CYCLES, **extra: Any) -> dict[str, Any]:
    return lifecycle_ok("postgresql", cycles, **extra)


def observed_world(lines: str = CLUSTER_MAIN, version: str = PG_VERSION, **changes: Any) -> dict[str, Any]:
    """``pg_lsclusters`` lists ``lines``; 17/main runs and reports ``version``."""
    world = pg_world(commands=[lsclusters(lines), version_probe(version)])
    world.update(changes)
    return world


def postgresql_cases() -> list[tuple[str, dict[str, Any], dict[str, Any], Any, float]]:
    """(id, world, policy, latest, now)."""
    now = 1_789_344_000.0  # 2026-09-14
    listed = lambda lines: {"commands": [lsclusters(lines)]}
    not_expected = {"expected": False}
    not_applicable = {"status": "not_applicable"}
    v = lambda text: f"postgres (PostgreSQL) {text}\n"
    return [
        # tests/test_software_live.py
        ("minor_and_extra_clusters", observed_world(CLUSTER_MAIN + "\n" + PG_OLD, v("17.10")), PG_POLICY,
         {"status": "ok", "cycles": [{"cycle": "18", "latest": "18.6", "eol": "2030-11-14"},
                                     {"cycle": "17", "latest": "17.11", "eol": "2029-11-08"}]}, 1_789_344_000),
        ("expected_absence_is_healthy", {"commands": [lsclusters(error="ENOENT")]}, not_expected,
         not_applicable, 1),
        ("boolean_eol_true", observed_world(version=v("17.11")), PG_POLICY,
         {"status": "ok", "cycles": [{"cycle": "17", "latest": "17.11", "eol": True}]}, 1_789_430_400),
        # not expected
        ("not_expected_no_clusters", listed(""), not_expected, not_applicable, now),
        ("not_expected_with_cluster", listed(CLUSTER_MAIN), not_expected, not_applicable, now),
        ("not_expected_with_stopped_cluster", listed(PG_OLD), not_expected, not_applicable, now),
        ("not_expected_full_policy", listed(""), {"expected": False, "desired_major": None}, not_applicable, now),
        ("not_expected_lsclusters_fails", {"commands": [lsclusters(exit=1)]}, not_expected, not_applicable, now),
        ("not_expected_lsclusters_denied", {"commands": [lsclusters(error="EACCES")]}, not_expected,
         not_applicable, now),
        ("not_expected_unparseable", listed("garbage"), not_expected, not_applicable, now),
        # expected
        ("expected_ok", observed_world(), PG_POLICY, pg_latest(), now),
        ("expected_lsclusters_missing", {"commands": [lsclusters(error="ENOENT")]}, PG_POLICY, pg_latest(), now),
        ("expected_lsclusters_times_out", {"commands": [lsclusters(error="timeout")]}, PG_POLICY, pg_latest(), now),
        ("expected_no_clusters", listed(""), PG_POLICY, pg_latest(), now),
        ("expected_cluster_down", listed(PG_OLD.replace("16 old 5433", "17 main 5432")), PG_POLICY,
         pg_latest(), now),
        ("expected_other_port", listed(CLUSTER_MAIN.replace("5432", "5433", 1)), PG_POLICY, pg_latest(), now),
        ("expected_other_name", listed(CLUSTER_MAIN.replace("main ", "other ", 1)), PG_POLICY, pg_latest(), now),
        ("expected_online_recovery", observed_world(CLUSTER_MAIN.replace("online", "online,recovery")),
         PG_POLICY, pg_latest(), now),
        ("expected_status_prefix_only", observed_world(CLUSTER_MAIN.replace("online", "onlineish")),
         PG_POLICY, pg_latest(), now),
        ("expected_first_matching_line", observed_world(CLUSTER_MAIN + "\n" + CLUSTER_MAIN), PG_POLICY,
         pg_latest(), now),
        ("expected_down_line_before_online", observed_world(
            PG_OLD.replace("16 old 5433", "17 main 5432") + "\n" + CLUSTER_MAIN), PG_POLICY, pg_latest(), now),
        ("expected_port_float_policy", observed_world(), {**PG_POLICY, "port": 5432.0}, pg_latest(), now),
        ("expected_cluster_key_missing", listed(CLUSTER_MAIN), {k: v for k, v in PG_POLICY.items() if k != "cluster"},
         pg_latest(), now),
        ("expected_cluster_key_missing_no_clusters", listed(""),
         {k: v for k, v in PG_POLICY.items() if k != "cluster"}, pg_latest(), now),
        ("expected_port_key_missing", listed(CLUSTER_MAIN), {k: v for k, v in PG_POLICY.items() if k != "port"},
         pg_latest(), now),
        ("expected_port_key_missing_other_name", listed(CLUSTER_MAIN.replace("main ", "other ", 1)),
         {k: v for k, v in PG_POLICY.items() if k != "port"}, pg_latest(), now),
        ("expected_desired_major_key_missing", observed_world(),
         {k: v for k, v in PG_POLICY.items() if k != "desired_major"}, pg_latest(), now),
        ("server_version_refused", observed_world(
            readlink={f"/proc/self/fd/{PG_FD}": [{"ok": PG_BINARY + " (deleted)"}]},
            commands=[lsclusters(CLUSTER_MAIN)]), PG_POLICY, pg_latest(), now),
        ("server_version_pid_missing", {"commands": [lsclusters(CLUSTER_MAIN)]}, PG_POLICY, pg_latest(), now),
        # versions and drift
        ("desired_major_drift", observed_world(CLUSTER_MAIN.replace("17 ", "16 ", 1), v("16.10"),
                                               files={"/var/run/postgresql/16-main.pid": {"ok": "4242\n"}},
                                               readlink={f"/proc/self/fd/{PG_FD}": [{"ok": "/usr/lib/postgresql/16/bin/postgres"}]}),
         PG_POLICY, pg_latest(), now),
        ("desired_major_int_policy", observed_world(), {**PG_POLICY, "desired_major": 17}, pg_latest(), now),
        ("leading_zero_major", observed_world(version=v("017.6")), PG_POLICY, pg_latest(), now),
        ("newer_than_upstream", observed_world(version=v("17.7")), PG_POLICY, pg_latest(), now),
        ("outdated_minor", observed_world(version=v("17.5")), PG_POLICY, pg_latest(), now),
        ("outdated_patch_level", observed_world(version=v("17.6")), PG_POLICY,
         pg_latest([{"cycle": "17", "latest": "17.6.1", "eol": False}]), now),
        ("longer_local_version", observed_world(version=v("17.6.0")), PG_POLICY, pg_latest(), now),
        ("numeric_not_lexical", observed_world(version=v("17.9")), PG_POLICY,
         pg_latest([{"cycle": "17", "latest": "17.10", "eol": False}]), now),
        # upstream
        ("upstream_unknown", observed_world(), PG_POLICY, UNKNOWN_LATEST, now),
        ("upstream_unknown_with_stale_evidence", observed_world(CLUSTER_MAIN + "\n" + PG_OLD), PG_POLICY,
         {"status": "unknown", "error": "TimeoutError", "last_success": pg_latest()}, now),
        ("upstream_not_applicable_but_expected", observed_world(), PG_POLICY, not_applicable, now),
        ("cycle_missing", observed_world(), PG_POLICY, pg_latest([{"cycle": "18", "latest": "18.1"}]), now),
        ("cycle_missing_keeps_drift", observed_world(version=v("16.10"), readlink={
            f"/proc/self/fd/{PG_FD}": [{"ok": PG_BINARY}]}), PG_POLICY, pg_latest([{"cycle": "18"}]), now),
        ("latest_minor_missing", observed_world(), PG_POLICY, pg_latest([{"cycle": "17", "eol": False}]), now),
        ("latest_minor_number", observed_world(), PG_POLICY,
         pg_latest([{"cycle": "17", "latest": 17.6, "eol": False}]), now),
        ("latest_minor_missing_after_eol", observed_world(), PG_POLICY,
         pg_latest([{"cycle": "17", "eol": "2026-01-01"}]), now),
        ("latest_minor_unparseable", observed_world(), PG_POLICY,
         pg_latest([{"cycle": "17", "latest": "17", "eol": False}]), now),
        ("eol_reached", observed_world(), PG_POLICY, pg_latest([{"cycle": "17", "latest": "17.6",
                                                                  "eol": "2026-09-14"}]), now),
        ("eol_tomorrow", observed_world(), PG_POLICY, pg_latest([{"cycle": "17", "latest": "17.6",
                                                                   "eol": "2026-09-15"}]), now),
        ("eol_and_outdated", observed_world(version=v("17.1")), PG_POLICY,
         pg_latest([{"cycle": "17", "latest": "17.6", "eol": True}]), now),
        ("eol_invalid", observed_world(), PG_POLICY, pg_latest([{"cycle": "17", "latest": "17.6", "eol": "never"}]),
         now),
        ("eol_number", observed_world(), PG_POLICY, pg_latest([{"cycle": "17", "latest": "17.6", "eol": 2029}]), now),
        ("newest_major_absent", observed_world(), PG_POLICY,
         pg_latest([{"latest": "x"}, {"cycle": "17", "latest": "17.6", "eol": False}]), now),
        ("cycles_not_a_list", observed_world(), PG_POLICY, {"status": "ok", "cycles": {"17": {}}}, now),
    ]


def gen_postgresql() -> dict[str, Any]:
    observe = []
    seen = set()
    for case_id, world, policy, latest, now in postgresql_cases():
        assert case_id not in seen, case_id
        seen.add(case_id)
        case = observation(
            functools.partial(live.observe_postgresql, copy.deepcopy(policy), copy.deepcopy(latest), now),
            world)
        observe.append({"id": case_id, "policy": policy, "latest": latest, "now": now, **case})
    return {"clusters": gen_clusters(), "server_version": gen_server_version(), "observe": observe}


# ------------------------------------------------------------------ export

EXPORT_EPOCH = 1_760_000_000.5
EXPORT_CHECK = {"status": "ok", "observed": True, "expected": True, "issues": []}
EXPORT_SOURCE = {
    "schema_version": 2,
    "host": "example",
    "generated_at_epoch": EXPORT_EPOCH,
    "policy_sha256": "0" * 64,
    "os": {**EXPORT_CHECK, "cycle": "24.04", "id": "ubuntu", "lifecycle": {"status": "ok"}},
    "postgresql": {**EXPORT_CHECK, "server_version": "17.7", "clusters": [{"name": "main"}]},
    "traefik": {
        **EXPORT_CHECK,
        "binary_path": "/private/path",
        "installed": {"version": "3.7.9", "path": "/usr/local/bin/traefik", "sha256": "1" * 64},
        "running": {"version": "3.7.8", "pid": 11},
        "upstream": {"version": "3.7.9", "status": "ok", "request_headers": "synthetic-never-export"},
    },
    "apt": {
        "status": "ok",
        "indexes_fresh": True,
        "pending_security_count": 2,
        "pending_security_updates": [{"package": "openssl"}, {"package": "libc6"}],
    },
    "summary": {"observation_ok": True},
    "private_config": {"opaque_fixture": "synthetic-never-export"},
}


def export_text(*edits: tuple[str, Any]) -> str:
    """EXPORT_SOURCE with each dotted path set to its value (MISSING deletes
    it; a ``RawToken`` is written as that JSON text), as text."""
    data = json.loads(json.dumps(EXPORT_SOURCE))
    raws = {}
    for index, (path, value) in enumerate(edits):
        *parents, last = path.split(".")
        target = data
        for part in parents:
            target = target[part]
        if value is MISSING:
            del target[last]
        elif isinstance(value, RawToken):
            marker = f"__RAW_TOKEN_{index}__"
            raws[f'"{marker}"'] = value.text
            target[last] = marker
        else:
            target[last] = value
    text = json.dumps(data)
    for marker, raw in raws.items():
        text = text.replace(marker, raw)
    return text


class RawToken:
    def __init__(self, text: str) -> None:
        self.text = text


def export_error(exc: BaseException) -> dict[str, Any]:
    """The class always; the message only where the Python code raises it itself."""
    message = str(exc)
    return {"class": type(exc).__name__, "message": message if message in OWN_MESSAGES else None}


def projection_cases() -> list[tuple[str, str, str | None]]:
    long_text = "é" * 100 + "\U0001f600" * 100
    issues = [f"issue-{n}-" + "x" * 200 for n in range(25)]
    cases: list[tuple[str, str, str | None]] = [
        ("base", export_text(), None),
        ("apt_unknown_and_postgresql_not_expected", export_text(
            ("apt", {"status": "unknown", "indexes_fresh": False, "pending_security_count": None}),
            ("postgresql", {"status": "ok", "observed": True, "expected": False, "issues": []})), None),
        ("statuses_warning_and_unknown", export_text(
            ("os.status", "warning"), ("traefik.status", "unknown"), ("traefik.observed", False),
            ("os.issues", ["os_cycle_drift", ""]), ("apt.pending_security_count", 0)), None),
        ("duplicate_keys_last_wins",
         '{"host": "bad host", ' + export_text()[1:], None),
        ("os_expected_is_always_true", export_text(("os.expected", "yes")), None),
        ("os_expected_missing", export_text(("os.expected", MISSING)), None),
        ("os_running_version_is_used", export_text(("os.running", {"version": "6.8.0"})), None),
        ("os_installed_and_upstream_ignored", export_text(
            ("os.installed", {"version": "26.04"}), ("os.upstream", {"version": "26.04"})), None),
        ("os_cycle_not_a_string", export_text(("os.cycle", 24.04)), None),
        ("os_cycle_missing", export_text(("os.cycle", MISSING)), None),
        ("postgresql_installed_and_running_ignored", export_text(
            ("postgresql.installed", {"version": "17.6"}), ("postgresql.running", {"version": "17.5"}),
            ("postgresql.upstream", {"version": "18.0"})), None),
        ("postgresql_server_version_missing", export_text(("postgresql.server_version", MISSING)), None),
        ("postgresql_server_version_empty", export_text(("postgresql.server_version", "")), None),
        ("traefik_versions_missing", export_text(
            ("traefik.installed", MISSING), ("traefik.running", MISSING), ("traefik.upstream", MISSING)), None),
        ("traefik_versions_not_objects", export_text(
            ("traefik.installed", "3.7.9"), ("traefik.running", ["3.7.8"]), ("traefik.upstream", None)), None),
        ("traefik_versions_not_strings", export_text(
            ("traefik.installed", {"version": 3.7}), ("traefik.running", {"version": True}),
            ("traefik.upstream", {"version": ["3.7.9"]})), None),
        ("traefik_versions_empty", export_text(
            ("traefik.installed", {"version": ""}), ("traefik.running", {}), ("traefik.upstream", {"version": None})),
         None),
        ("texts_cut_to_160_code_points", export_text(
            ("traefik.installed", {"version": long_text}), ("traefik.running", {"version": "r" * 161}),
            ("traefik.upstream", {"version": "u" * 160}), ("os.cycle", "é" * 161),
            ("postgresql.server_version", "\U0001f600" * 170)), None),
        ("issues_cut_to_20_of_160", export_text(("traefik.issues", issues), ("os.issues", issues[:20]),
                                                 ("postgresql.issues", issues[:21])), None),
        ("issues_non_ascii_cut", export_text(("os.issues", [long_text, "\u0000\n", ""])), None),
        ("issues_missing", export_text(("traefik.issues", MISSING)), None),
        ("issues_null", export_text(("traefik.issues", None)), None),
        ("issues_not_a_list", export_text(("os.issues", "os_cycle_drift")), None),
        ("issues_an_object", export_text(("os.issues", {"a": "b"})), None),
        ("issues_not_strings", export_text(("postgresql.issues", ["a", 1])), None),
        ("issues_null_item", export_text(("postgresql.issues", [None])), None),
        ("time_integer", export_text(("generated_at_epoch", 1_760_000_000)), None),
        ("time_exponent", export_text(("generated_at_epoch", RawToken("1.76E9"))), None),
        # Written as the parsed float: the projection stays below the reader's 64 KiB.
        ("time_long_spelling",
         export_text(("generated_at_epoch", RawToken("1760000000.5" + "0" * 66_000 + "1"))), None),
        ("time_float_with_integral_value", export_text(("generated_at_epoch", RawToken("17600000E2"))), None),
        ("time_smallest_positive", export_text(("generated_at_epoch", RawToken("5e-324"))), None),
        ("time_underflow_to_zero", export_text(("generated_at_epoch", RawToken("1e-400"))), None),
        ("time_zero", export_text(("generated_at_epoch", 0)), None),
        ("time_zero_float", export_text(("generated_at_epoch", 0.0)), None),
        ("time_negative", export_text(("generated_at_epoch", -1.5)), None),
        ("time_overflow_float", export_text(("generated_at_epoch", RawToken("1e400"))), None),
        ("time_huge_integer", export_text(("generated_at_epoch", RawToken("1" + "0" * 400))), None),
        ("time_huge_negative_integer", export_text(("generated_at_epoch", RawToken("-1" + "0" * 400))), None),
        ("time_big_integer_in_range", export_text(("generated_at_epoch", RawToken("1" + "0" * 300))), None),
        ("time_bool", export_text(("generated_at_epoch", True)), None),
        ("time_string", export_text(("generated_at_epoch", "1760000000")), None),
        ("time_null", export_text(("generated_at_epoch", None)), None),
        ("time_missing", export_text(("generated_at_epoch", MISSING)), None),
        ("time_nan", export_text(("generated_at_epoch", RawToken("NaN"))), "non-standard-json"),
        ("time_infinity", export_text(("generated_at_epoch", RawToken("Infinity"))), "non-standard-json"),
        ("schema_float", export_text(("schema_version", 2.0)), None),
        ("schema_bool", export_text(("schema_version", True)), None),
        ("schema_other", export_text(("schema_version", 99)), None),
        ("schema_one", export_text(("schema_version", 1)), None),
        ("schema_string", export_text(("schema_version", "2")), None),
        ("schema_missing", export_text(("schema_version", MISSING)), None),
        ("schema_big_integer", export_text(("schema_version", RawToken("18446744073709551618"))), None),
        ("host_empty", export_text(("host", "")), None),
        ("host_128", export_text(("host", "h" * 128)), None),
        ("host_129", export_text(("host", "h" * 129)), None),
        ("host_all_classes", export_text(("host", "Web-1.example_X")), None),
        ("host_space", export_text(("host", "exa mple")), None),
        ("host_slash", export_text(("host", "ex/ample")), None),
        ("host_newline", export_text(("host", "example\n")), None),
        ("host_non_ascii", export_text(("host", "éxample")), None),
        ("host_number", export_text(("host", 1)), None),
        ("host_missing", export_text(("host", MISSING)), None),
        ("check_missing", export_text(("traefik", MISSING)), None),
        ("check_not_an_object", export_text(("os", ["ok"])), None),
        ("check_status_missing", export_text(("os.status", MISSING)), None),
        ("check_status_other", export_text(("postgresql.status", "failed")), None),
        ("check_status_not_a_string", export_text(("postgresql.status", ["ok"])), None),
        ("check_observed_missing", export_text(("traefik.observed", MISSING)), None),
        ("check_observed_string", export_text(("os.observed", "yes")), None),
        ("check_observed_integer", export_text(("os.observed", 1)), None),
        ("check_expected_missing", export_text(("postgresql.expected", MISSING)), None),
        ("check_expected_null", export_text(("traefik.expected", None)), None),
        ("check_expected_integer", export_text(("traefik.expected", 0)), None),
        ("check_order_os_first", export_text(("os.observed", None), ("traefik", MISSING)), None),
        ("apt_missing", export_text(("apt", MISSING)), None),
        ("apt_not_an_object", export_text(("apt", [])), None),
        ("apt_status_warning", export_text(("apt.status", "warning")), None),
        ("apt_status_missing", export_text(("apt.status", MISSING)), None),
        ("apt_indexes_fresh_integer", export_text(("apt.indexes_fresh", 1)), None),
        ("apt_indexes_fresh_missing", export_text(("apt.indexes_fresh", MISSING)), None),
        ("apt_count_missing_when_ok", export_text(("apt.pending_security_count", MISSING)), None),
        ("apt_count_null_when_ok", export_text(("apt.pending_security_count", None)), None),
        ("apt_count_missing_when_unknown", export_text(
            ("apt.status", "unknown"), ("apt.pending_security_count", MISSING)), None),
        ("apt_count_when_unknown", export_text(("apt.status", "unknown"), ("apt.pending_security_count", 3)),
         None),
        ("apt_count_negative", export_text(("apt.pending_security_count", -1)), None),
        ("apt_count_negative_zero", export_text(("apt.pending_security_count", RawToken("-0"))), None),
        ("apt_count_bool", export_text(("apt.pending_security_count", True)), None),
        ("apt_count_float", export_text(("apt.pending_security_count", 1.0)), None),
        ("apt_count_string", export_text(("apt.pending_security_count", "1")), None),
        ("apt_count_big_integer", export_text(("apt.pending_security_count", RawToken("18446744073709551617"))),
         None),
        ("source_a_list", "[]", None),
        ("source_null", "null", None),
        ("source_a_string", '"example"', None),
        ("source_a_number", "2", None),
        ("extra_lone_surrogate", export_text(("private_config", RawToken('"\\ud800"'))), "non-standard-json"),
        ("extra_nested_200_levels", export_text(("private_config", RawToken("[" * 200 + "]" * 200))), "nesting"),
    ]
    return cases


def source_bytes_cases() -> list[tuple[str, bytes, str | None]]:
    text = export_text().encode()
    return [
        ("utf8", text, None),
        ("utf8_bom", b"\xef\xbb\xbf" + text, None),
        ("utf8_non_ascii", export_text(("host", "example"), ("os.cycle", "é\U0001f600")).encode(), None),
        ("invalid_utf8", text.replace(b'"opaque_fixture"', b'"opaque\xff"'), None),
        ("latin1", export_text(("os.cycle", "é")).encode("latin-1").replace(b"\\u00e9", b"\xe9"), None),
        ("empty", b"", None),
        ("whitespace_only", b" \n", None),
        ("trailing_garbage", text + b" x", None),
        ("utf8_encoded_surrogate", text.replace(b'"opaque_fixture"', b'"opaque\xed\xa0\x80"'), "encoding"),
        ("utf16_bom", text.decode().encode("utf-16"), "encoding"),
        ("utf16le_without_bom", text.decode().encode("utf-16-le"), "encoding"),
        ("utf32_bom", text.decode().encode("utf-32"), "encoding"),
    ]


def project(text: str | bytes) -> dict[str, Any]:
    try:
        return {"result": live.inventory_projection(json.loads(text))}
    except Exception as exc:  # noqa: BLE001 - the oracle's answer
        return {"error": export_error(exc)}


# The export directory and source on disk, run through the real
# ``export_inventory`` with root ownership emulated the way
# tests/test_software_health_bridge.py does it (uid 0 from ``Path.lstat`` and
# ``os.fstat``; "other" reports uid 99 instead). Everything else is real:
# descriptors, O_NOFOLLOW, modes, link counts, the size bound, the group
# lookup, the temporary file and the rename.
EXPORT_FILE_DEFAULTS = {
    "source": "file",  # file | symlink | dangling_symlink | hardlink | directory | fifo | missing
    "source_mode": 0o640,
    "text": None,  # export_text() unless given (``default_source``)
    "pad_to": None,  # spaces appended up to this many bytes
    "directory": "dir",  # dir | missing | file | symlink
    "directory_mode": 0o750,
    "directory_owner": "root",
    "source_owner": "root",
    "source_path": "{root}/state.json",
    "output_path": "{root}/out/software-health.json",
    "group": "{own}",
}
MISSING_GROUP = "software-live-no-such-group"


def export_file_cases() -> list[dict[str, Any]]:
    cases: list[tuple[str, dict[str, Any]]] = [
        ("written", {}),
        ("written_mode_0600_source", {"source_mode": 0o600}),
        ("written_mode_0644_source", {"source_mode": 0o644}),
        ("written_directory_0755", {"directory_mode": 0o755}),
        ("written_directory_0700", {"directory_mode": 0o700}),
        ("written_exactly_1_mib", {"pad_to": 1024 * 1024}),
        ("written_source_path_trailing_slash", {"source_path": "{root}/state.json/"}),
        ("written_paths_with_dot_and_double_slash",
         {"source_path": "{root}/./state.json", "output_path": "{root}//out/./software-health.json"}),
        ("written_unknowns", {"text": export_text(
            ("apt", {"status": "unknown", "indexes_fresh": False, "pending_security_count": None}),
            ("generated_at_epoch", 1_760_000_000))}),
        ("source_too_large", {"pad_to": 1024 * 1024 + 1}),
        ("source_group_writable", {"source_mode": 0o660}),
        ("source_world_writable", {"source_mode": 0o602}),
        ("source_symlink", {"source": "symlink"}),
        ("source_dangling_symlink", {"source": "dangling_symlink"}),
        ("source_hard_link", {"source": "hardlink"}),
        ("source_directory", {"source": "directory"}),
        ("source_fifo", {"source": "fifo"}),
        ("source_missing", {"source": "missing"}),
        ("source_not_root", {"source_owner": "other"}),
        ("source_invalid_json", {"text": "{broken"}),
        ("source_invalid_projection", {"text": export_text(("host", ""))}),
        ("source_not_utf8", {"text": "{\"host\": \"\udce9\"}"}),
        ("directory_group_writable", {"directory_mode": 0o770}),
        ("directory_world_writable", {"directory_mode": 0o752}),
        ("directory_sticky_world_writable", {"directory_mode": 0o1777}),
        ("directory_not_root", {"directory_owner": "other"}),
        ("directory_missing", {"directory": "missing"}),
        ("directory_a_file", {"directory": "file"}),
        ("directory_a_symlink", {"directory": "symlink"}),
        ("directory_checked_before_source", {"directory_mode": 0o770, "source": "missing"}),
        ("group_missing", {"group": MISSING_GROUP}),
        ("projection_before_group", {"group": MISSING_GROUP, "text": export_text(("apt", MISSING))}),
    ]
    return [{"id": case_id, **EXPORT_FILE_DEFAULTS, **spec} for case_id, spec in cases]


def export_source_bytes(case: dict[str, Any]) -> bytes:
    text = case["text"] if case["text"] is not None else export_text()
    data = text.encode("utf-8", "surrogateescape")
    if case["pad_to"] is not None:
        data += b" " * (case["pad_to"] - len(data))
    return data


def build_export_world(root: Path, case: dict[str, Any]) -> None:
    """The files of one export case under ``root`` (the Rust test builds the same)."""
    out = root / "out"
    if case["directory"] == "dir":
        out.mkdir()
        (out / "software-health.json").write_bytes(b"prior")
        (out / "software-health.json").chmod(0o600)
        out.chmod(case["directory_mode"])
    elif case["directory"] == "file":
        out.write_bytes(b"not a directory")
    elif case["directory"] == "symlink":
        (root / "out-target").mkdir(mode=0o750)
        out.symlink_to("out-target")
    source = root / "state.json"
    kind = case["source"]
    data = export_source_bytes(case)
    if kind in ("file", "hardlink"):
        source.write_bytes(data)
        source.chmod(case["source_mode"])
        if kind == "hardlink":
            os.link(source, root / "alias.json")
    elif kind == "symlink":
        (root / "state-target.json").write_bytes(data)
        (root / "state-target.json").chmod(case["source_mode"])
        source.symlink_to("state-target.json")
    elif kind == "dangling_symlink":
        source.symlink_to("missing.json")
    elif kind == "directory":
        source.mkdir(mode=0o750)
    elif kind == "fifo":
        os.mkfifo(source, 0o640)


def run_export_case(case: dict[str, Any]) -> dict[str, Any]:
    own_group = grp.getgrgid(os.getgid()).gr_name
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        build_export_world(root, case)
        owners = {"root": 0, "other": 99}
        lstat, fstat = Path.lstat, os.fstat

        def emulated(value: os.stat_result, owner: str) -> os.stat_result:
            fields = list(value)
            fields[4] = owners[owner]
            return os.stat_result(fields)

        source = Path(case["source_path"].replace("{root}", directory))
        output = Path(case["output_path"].replace("{root}", directory))
        group = own_group if case["group"] == "{own}" else case["group"]
        outcome: dict[str, Any] = {}
        with (
            mock.patch.object(Path, "lstat", lambda p: emulated(lstat(p), case["directory_owner"])),
            mock.patch.object(os, "fstat", lambda fd: emulated(fstat(fd), case["source_owner"])),
        ):
            try:
                live.export_inventory(source, output, group)
            except Exception as exc:  # noqa: BLE001 - the oracle's answer
                outcome["error"] = export_error(exc)
        out = root / "out"
        if case["directory"] == "dir":
            out.chmod(0o750)
            names = sorted(p.name for p in out.iterdir())
            target = out / "software-health.json"
            if "error" in outcome:
                assert target.read_bytes() == b"prior", case["id"]
            else:
                st = target.stat()
                assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_gid == os.getgid(), case["id"]
                outcome["result"] = json.loads(target.read_bytes())
            outcome["files"] = names
        return outcome


def gen_export() -> dict[str, Any]:
    projection = []
    for case_id, text, p3 in projection_cases():
        case = {"id": case_id, "source": text, **project(text)}
        if p3:
            case["p3"] = p3
        projection.append(case)
    source_bytes = []
    for case_id, data, p3 in source_bytes_cases():
        case = {"id": case_id, "hex": data.hex(), **project(data)}
        if p3:
            assert "result" in case, case_id
            case["p3"] = p3
        source_bytes.append(case)
    files = []
    for case in export_file_cases():
        text = case.pop("text")
        source_hex = None if text is None else text.encode("utf-8", "surrogateescape").hex()
        files.append({**case, "source_hex": source_hex, **run_export_case({**case, "text": text})})
    return {"projection": projection, "source_bytes": source_bytes, "default_source": export_text(),
            "files": files}


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
        # Failures that do not depend on who runs the test: `/` is root-owned
        # and not group/world-writable everywhere, and nothing is written.
        ("export_missing_directory", ["export-inventory", "--config", "{dir}/valid.json",
                                      "--output", "{dir}/missing/software-health.json", "--group", "g"]),
        ("export_missing_source", ["export-inventory", "--config", "{dir}/missing.json",
                                   "--output", "/software-live-never-written.json", "--group", "g"]),
        ("export_source_directory", ["export-inventory", "--config", "{dir}",
                                     "--output", "/software-live-never-written.json", "--group", "g"]),
        ("export_ignores_config_json", ["export-inventory", "--config-json", "{", "--config",
                                        "{dir}/missing.json", "--output", "/software-live-never-written.json",
                                        "--group", "g"]),
        ("collect_invalid_policy", ["collect", "--config", "{dir}/invalid.json"]),
        ("collect_without_config", ["collect"]),
        ("collect_broken_json", ["collect", "--config-json", "{"]),
        # serve: only configurations that stop before listening.
        ("serve_public_bind", ["serve", "--config-json", '{"bind": "0.0.0.0"}']),
        ("serve_missing_bind", ["serve", "--config-json", "{}"]),
        ("serve_ipv6_bind", ["serve", "--config-json", '{"bind": "::1", "port": 9119}']),
        ("serve_invalid_port", ["serve", "--config-json", '{"bind": "127.0.0.1", "port": "x"}']),
        ("serve_port_out_of_range", ["serve", "--config-json", '{"bind": "127.0.0.1", "port": 70000}']),
        ("serve_policy_as_config", ["serve", "--config", "{dir}/valid.json"]),
        ("serve_without_config", ["serve"]),
        ("serve_broken_json", ["serve", "--config-json", "{"]),
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


# ------------------------------------------------------------------ collect
#
# `collect(policy, cache)` end to end (PLAN.md 3.3, slice S3f): the worlds of
# the Traefik, OS and PostgreSQL fixtures put together, the upstream answers
# through a patched `urlopen`, the clock through a patched `time.time`. Python
# observes APT with python-apt, the Rust collector through its helper
# (PLAN.md 5.2): `observe_apt` is patched to return the helper's result, and
# the case adds the helper's link, `lstat` and run to the Rust world and to
# the call log at that point. The call log is the one `FakeSystem` keeps, so
# the Rust test compares the order of every host access, not only results.

COLLECT_TIMES = [1_789_344_000.25, 1_789_344_003.5]
APT_EXE = "/usr/local/lib/software-live/releases/0.1.0/software-live"
APT_HELPER = "/usr/local/lib/software-live/releases/0.1.0/software-live-apt"
COLLECT_APT = {
    "status": "ok",
    "pending_security_count": 1,
    "pending_security_updates": [
        {"package": "openssl:amd64", "installed": "3.0.13-0ubuntu3.5", "security_version": "3.0.13-0ubuntu3.6",
         "candidate": "3.0.13-0ubuntu3.6", "held": False},
    ],
    "indexes_fresh": True,
    "oldest_security_index_age_seconds": 7200.5,
    "index_age_limit_seconds": 172800,
    "index_source": "cached security InRelease publication mtimes; no refresh performed",
}


def merge_worlds(*worlds: dict[str, Any]) -> dict[str, Any]:
    """One world from several: commands in order, every other key once."""
    out: dict[str, Any] = {}
    for world in worlds:
        for kind, value in world.items():
            if kind == "commands":
                out.setdefault(kind, []).extend(copy.deepcopy(value))
                continue
            target = out.setdefault(kind, {})
            for key, answer in value.items():
                assert key not in target, (kind, key)
                target[key] = copy.deepcopy(answer)
    return out


def endoflife(product: str) -> str:
    return live.LIFECYCLE_URL.format(product=product)


def collect_cases() -> list[dict[str, Any]]:
    """(id, policy, world, responses by URL, APT result, cache)."""
    not_expected = {**BASE, "traefik": {**BASE["traefik"], "expected": False},
                    "postgresql": {"expected": False}}
    debian = {**not_expected, "os": DEBIAN_POLICY, "apt_max_age_seconds": 3600}
    all_expected_world = merge_worlds(attempt(Builder()).build(), os_world(UBUNTU_RELEASE), observed_world())
    absent_world = merge_worlds(Builder().pid("0").build(), os_world(DEBIAN_13),
                                {"commands": [lsclusters(error="ENOENT")]})
    release_body = {"body": json.dumps({"tag_name": "v3.7.9", "draft": False, "prerelease": False})}
    all_answers = {
        GITHUB_URL: release_body,
        endoflife("ubuntu"): lifecycle_body(UBUNTU_CYCLES),
        endoflife("postgresql"): lifecycle_body(PG_CYCLES),
    }
    return [
        {"id": "all_expected", "policy": BASE, "world": all_expected_world, "http": all_answers,
         "apt": COLLECT_APT},
        # tests/test_software_live.py
        # test_upstream_failure_warns_without_claiming_local_collection_failed, end to end
        {"id": "upstream_unavailable", "policy": BASE, "world": all_expected_world,
         "http": {GITHUB_URL: {"error": "URLError"}, endoflife("ubuntu"): {"error": "TimeoutError"},
                  endoflife("postgresql"): {"error": "HTTPError"}},
         "apt": COLLECT_APT},
        # An observation that fails keeps its fields; the report is still written.
        {"id": "traefik_probe_fails", "policy": {**BASE, "postgresql": {"expected": False}},
         "world": merge_worlds(Builder().pid("", exit=1).build(), os_world(UBUNTU_RELEASE),
                               {"commands": [lsclusters(error="ENOENT")]}),
         "http": {GITHUB_URL: release_body, endoflife("ubuntu"): lifecycle_body(UBUNTU_CYCLES)},
         "apt": COLLECT_APT},
        {"id": "nothing_expected", "policy": debian, "world": absent_world,
         "http": {endoflife("debian"): lifecycle_body(DEBIAN_CYCLES)},
         "apt": {**COLLECT_APT, "pending_security_count": 0, "pending_security_updates": [],
                 "index_age_limit_seconds": 3600}},
        {"id": "apt_unknown", "policy": debian, "world": absent_world,
         "http": {endoflife("debian"): lifecycle_body(DEBIAN_CYCLES)},
         "apt": {"status": "unknown", "error": "APT observation failed (CacheOpen)", "indexes_fresh": False,
                 "pending_security_count": None}},
        # A cache path without a name: `cache_variant` raises outside the
        # lookup's boundary, so `collect` stops before the OS observation.
        {"id": "cache_without_name", "policy": not_expected, "world": Builder().pid("0").build(),
         "http": {}, "apt": COLLECT_APT, "cache": "/"},
    ]


def run_collect_case(case: dict[str, Any]) -> dict[str, Any]:
    policy = case["policy"]
    world = copy.deepcopy(case["world"])
    host = TextHost(world)
    http: list[dict[str, Any]] = []
    rust_world = copy.deepcopy(world)

    def urlopen(request: Any, timeout: Any = None) -> FakeResponse:
        host.calls.append(f"http_get {request.full_url}")
        spec = case["http"][request.full_url]
        http.append({"url": request.full_url,
                     "headers": {key.lower(): value for key, value in request.header_items()},
                     "timeout": timeout, **spec})
        if "error" in spec:
            raise transport_error(spec["error"])
        return FakeResponse(response_bytes(spec))

    def observe_apt(max_age: int, now: float) -> dict[str, Any]:
        argv = [APT_HELPER, "observe", "--max-age", str(max_age), "--now", repr(now)]
        host.calls.extend(["readlink /proc/self/exe", f"lstat {APT_HELPER}", "run " + " ".join(argv)])
        for kind, key, answer in (("readlink", "/proc/self/exe", ok(APT_EXE)),
                                  ("lstat", APT_HELPER, ok({"mode": 0o100755}))):
            assert key not in rust_world.get(kind, {}), (kind, key)
            rust_world.setdefault(kind, {})[key] = [answer]
        rust_world.setdefault("commands", []).append({"argv": argv, "stdout": json.dumps(case["apt"])})
        return copy.deepcopy(case["apt"])

    def clock() -> float:
        host.calls.append("now")
        return times.pop(0)

    times = list(COLLECT_TIMES)
    out: dict[str, Any] = {"id": case["id"], "policy": json.dumps(policy), "cache": case.get("cache")}
    cache = None if case.get("cache") is None else Path(case["cache"])
    with (
        host.patched(),
        mock.patch.object(live.urllib.request, "urlopen", side_effect=urlopen),
        mock.patch.object(live, "observe_apt", side_effect=observe_apt),
        mock.patch.object(live.time, "time", side_effect=clock),
    ):
        try:
            report = live.collect(copy.deepcopy(policy), cache)
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            out["error"] = error(exc)
        else:
            errors = {}
            for name in ("traefik", "os", "postgresql"):
                text = report[name].pop("error", None)
                if text is not None:
                    errors[name] = split_error(text)
            out["report"] = json.dumps(report, sort_keys=True)
            out["errors"] = errors
    assert len(http) == len(case["http"]), (case["id"], http)
    rust_world["now"] = list(COLLECT_TIMES)
    rust_world["http"] = http
    out["world"] = rust_world
    out["calls"] = host.calls
    return out


def gen_collect() -> list[dict[str, Any]]:
    return [run_collect_case(case) for case in collect_cases()]


# ------------------------------------------------------------------ serve
#
# ``serve.json``: the endpoint (PLAN.md 3.1, 3.4). ``config`` runs the real
# ``main()`` with ``serve --config-json`` and a fake ``HTTPServer`` that
# records the address it would bind, refusing what ``socket.bind`` refuses (a
# host that is not a string, then a port outside 0-65535). ``requests`` feeds
# raw request bytes to the real ``Handler.handle_one_request`` (request line
# and header parsing, the ``//`` collapse, method dispatch, ``do_GET``) with
# ``htpasswd`` replaced by a table (``SERVE_PASSWORDS``) and the clock fixed;
# it records the status, the JSON body, the challenge header and the
# ``htpasswd`` call (user and stdin). The table answers like the real
# ``htpasswd -vi`` for every password here except a trailing NUL, which the
# real one cuts off; the call is what these cases compare, and the verdicts of
# the real ``htpasswd`` are pinned by ``htpasswd.json`` (``htpasswd.py``), whose
# file has the same password.

SERVE_PATH = "/.well-known/software-live"
SERVE_USER = "nyxmon"
SERVE_PASSWORD = "correct horse battery staple"
SERVE_PASSWORDS = {(SERVE_USER, SERVE_PASSWORD)}
SERVE_CONFIG = {
    "auth_user": SERVE_USER,
    "bind": "127.0.0.1",
    "htpasswd": "{dir}/htpasswd",
    "path": SERVE_PATH,
    "port": 9110,
    "state": "{dir}/state.json",
}
SUMMARY_OK = {key: True for key in (
    "observation_ok", "os_ok", "postgresql_ok", "traefik_ok", "security_updates_ok",
    "apt_indexes_fresh")}
STATE_OK = {"schema_version": 2, "host": "example", "generated_at_epoch": 1700000000.25,
            "policy_sha256": "0" * 64, "summary": SUMMARY_OK}
SERVE_NOW = 1700000060.75


class FakeHTTPServer:
    """``http.server.HTTPServer`` up to ``socket.bind``'s argument checks."""

    bound: list[tuple[Any, Any]] = []

    def __init__(self, address: tuple[Any, Any], handler: Any) -> None:
        host, port = address
        if not isinstance(host, str):
            raise TypeError(f"str, bytes or bytearray expected, not {type(host).__name__}")
        if not 0 <= port <= 65535:
            raise OverflowError("bind(): port must be 0-65535.")
        self.address = address

    def serve_forever(self) -> None:
        FakeHTTPServer.bound.append(self.address)


def serve_config(**changes: Any) -> str:
    config = dict(SERVE_CONFIG)
    for key, value in changes.items():
        if value is MISSING:
            del config[key]
        else:
            config[key] = value
    return json.dumps(config)


def serve_config_cases() -> list[tuple[str, str, str | None]]:
    """(id, configuration text, P3 tag)."""
    raw_port = lambda token: serve_config(port="__PORT__").replace('"__PORT__"', token)  # noqa: E731
    cases: list[tuple[str, str, str | None]] = [
        ("loopback", serve_config(), None),
        ("loopback_top", serve_config(bind="127.255.255.255"), None),
        ("loopback_network", serve_config(bind="127.0.0.0"), None),
        ("tailscale_first", serve_config(bind="100.64.0.0"), None),
        ("tailscale", serve_config(bind="100.100.1.2"), None),
        ("tailscale_last", serve_config(bind="100.127.255.255"), None),
        ("public_any", serve_config(bind="0.0.0.0"), None),
        ("below_tailscale", serve_config(bind="100.63.255.255"), None),
        ("above_tailscale", serve_config(bind="100.128.0.0"), None),
        ("private", serve_config(bind="10.0.0.1"), None),
        ("ipv6_loopback", serve_config(bind="::1"), None),
        ("ipv4_mapped", serve_config(bind="::ffff:127.0.0.1"), None),
        ("ipv6_scoped", serve_config(bind="fe80::1%eth0"), None),
        ("leading_zero", serve_config(bind="127.0.0.01"), None),
        ("short_form", serve_config(bind="127.1"), None),
        ("trailing_space", serve_config(bind="127.0.0.1 "), None),
        ("leading_space", serve_config(bind=" 127.0.0.1"), None),
        ("network", serve_config(bind="127.0.0.1/8"), None),
        ("empty_bind", serve_config(bind=""), None),
        ("hostname", serve_config(bind="localhost"), None),
        ("fullwidth_digits", serve_config(bind="１２７.0.0.1"), None),
        ("octet_too_big", serve_config(bind="127.0.0.256"), None),
        ("int_loopback", serve_config(bind=2130706433), None),
        ("int_tailscale", serve_config(bind=1684275458), None),
        ("int_private", serve_config(bind=167772161), None),
        ("int_ipv6", serve_config(bind=2**32), None),
        ("int_negative", serve_config(bind=-1), None),
        ("float_bind", serve_config(bind=1.5), None),
        ("null_bind", serve_config(bind=None), None),
        ("true_bind", serve_config(bind=True), None),
        ("list_bind", serve_config(bind=[]), None),
        ("missing_bind", serve_config(bind=MISSING), None),
        ("int_loopback_bad_port", serve_config(bind=2130706433, port="x"), None),
        ("int_loopback_big_port", serve_config(bind=2130706433, port=70000), None),
        ("public_and_bad_port", serve_config(bind="0.0.0.0", port="x"), None),
        ("port_zero", serve_config(port=0), None),
        ("port_max", serve_config(port=65535), None),
        ("port_too_big", serve_config(port=65536), None),
        ("port_negative", serve_config(port=-1), None),
        ("port_negative_zero", raw_port("-0"), None),
        ("port_huge", raw_port("1" + "0" * 30), None),
        ("port_string", serve_config(port="9110"), None),
        ("port_string_spaces", serve_config(port=" 9110\n"), None),
        ("port_string_plus", serve_config(port="+9110"), None),
        ("port_string_underscore", serve_config(port="9_110"), None),
        ("port_string_double_underscore", serve_config(port="9__110"), None),
        ("port_string_leading_zeros", serve_config(port="009110"), None),
        ("port_string_negative", serve_config(port="-1"), None),
        ("port_string_hex", serve_config(port="0x10"), None),
        ("port_string_float", serve_config(port="9110.0"), None),
        ("port_string_empty", serve_config(port=""), None),
        ("port_string_too_long", serve_config(port="1" * 4301), None),
        ("port_unicode_digits", serve_config(port="٩١١٠"), "unicode-digits"),
        ("port_float", raw_port("9110.0"), None),
        ("port_float_fraction", raw_port("9110.9"), None),
        ("port_float_negative_fraction", raw_port("-0.5"), None),
        ("port_float_exponent", raw_port("9.11e3"), None),
        ("port_float_huge", raw_port("1e300"), None),
        ("port_float_overflow", raw_port("1e400"), None),
        ("port_float_too_big", raw_port("65536.5"), None),
        ("port_true", serve_config(port=True), None),
        ("port_false", serve_config(port=False), None),
        ("port_null", serve_config(port=None), None),
        ("port_list", serve_config(port=[]), None),
        ("missing_port", serve_config(port=MISSING), None),
        ("config_list", "[]", None),
        ("config_string", '"x"', None),
        ("config_null", "null", None),
        ("config_number", "5", None),
        ("extra_keys", serve_config(extra={"x": 1}), None),
        ("missing_path", serve_config(path=MISSING), "startup-config"),
        ("missing_auth_user", serve_config(auth_user=MISSING), "startup-config"),
        ("missing_htpasswd", serve_config(htpasswd=MISSING), "startup-config"),
        ("missing_state", serve_config(state=MISSING), "startup-config"),
        ("path_not_string", serve_config(path=1), "startup-config"),
        ("auth_user_not_string", serve_config(auth_user=None), "startup-config"),
        ("htpasswd_not_string", serve_config(htpasswd=[]), "startup-config"),
        ("state_not_string", serve_config(state={}), "startup-config"),
    ]
    return cases


def gen_serve_config_case(case_id: str, text: str, p3: str | None) -> dict[str, Any]:
    case: dict[str, Any] = {"id": case_id, "config": text, "address": None, "error": None}
    FakeHTTPServer.bound = []
    with (
        mock.patch.object(sys, "argv", ["software_live", "serve", "--config-json", text]),
        mock.patch.object(live.http.server, "HTTPServer", FakeHTTPServer),
    ):
        try:
            live.main()
            [(host, port)] = FakeHTTPServer.bound
            case["address"] = [host, port]
        except Exception as exc:  # noqa: BLE001 - the oracle's answer
            case["error"] = error(exc)
    if p3 is not None:
        case["p3"] = p3
    return case


def basic(credentials: bytes) -> bytes:
    import base64

    return b"Basic " + base64.b64encode(credentials)


def request(target: str = SERVE_PATH, headers: list[bytes] | None = None, method: str = "GET",
            version: str = "HTTP/1.1") -> bytes:
    head = [f"{method} {target} {version}".encode("latin-1"), b"Host: 127.0.0.1"]
    head += headers or []
    return b"\r\n".join(head) + b"\r\n\r\n"


def serve_request_cases() -> list[dict[str, Any]]:
    """Raw requests and states. ``p3``/``rust_status``: PLAN.md 4.2 item 2
    (hyper's framing) and item 4 (non-standard JSON in the state)."""
    good = SERVE_USER.encode() + b":" + SERVE_PASSWORD.encode()
    ok = b"Authorization: " + basic(good)
    token = basic(good)[6:]
    state = json.dumps(STATE_OK)
    out: list[dict[str, Any]] = []

    def add(case_id: str, raw: bytes, state_text: str | bytes | None = state, *,
            now: float = SERVE_NOW, p3: str | None = None, rust_status: int | None = None) -> None:
        entry: dict[str, Any] = {"id": case_id, "request_hex": raw.hex(), "now": now}
        if isinstance(state_text, bytes):
            entry["state_hex"] = state_text.hex()
        else:
            entry["state"] = state_text
        if p3 is not None:
            entry["p3"] = p3
            entry["rust_status"] = rust_status
        out.append(entry)

    def with_state(**changes: Any) -> str:
        data = json.loads(json.dumps(STATE_OK))
        for key, value in changes.items():
            if value is MISSING:
                del data[key]
            else:
                data[key] = value
        return json.dumps(data)

    def summary(**changes: Any) -> str:
        data = dict(SUMMARY_OK)
        for key, value in changes.items():
            if value is MISSING:
                del data[key]
            else:
                data[key] = value
        return with_state(summary=data)

    # Methods and request-targets.
    add("get_valid", request(headers=[ok]))
    add("http_1_0", request(headers=[ok], version="HTTP/1.0"))
    add("query_string", request(SERVE_PATH + "?x=1", [ok]))
    add("empty_query", request(SERVE_PATH + "?", [ok]))
    add("trailing_slash", request(SERVE_PATH + "/", [ok]))
    add("double_slash", request("/" + SERVE_PATH, [ok]))
    add("triple_slash", request("//" + SERVE_PATH, [ok]))
    add("absolute_form", request("http://127.0.0.1:9110" + SERVE_PATH, [ok]))
    add("percent_encoded", request("/.well-known/software%2Dlive", [ok]))
    add("other_case", request("/.Well-Known/software-live", [ok]))
    add("root", request("/", [ok]))
    add("asterisk", request("*", [ok]))
    add("other_path_without_auth", request("/metrics"))
    add("other_path_wrong_auth", request("/metrics", [b"Authorization: Basic eDp5"]))
    add("post", request(headers=[ok], method="POST"))
    add("head", request(headers=[ok], method="HEAD"))
    add("put_other_path", request("/x", method="PUT"))
    add("lowercase_method", request(headers=[ok], method="get"))
    add("options_asterisk", request("*", method="OPTIONS"))
    # Authentication.
    add("no_authorization", request())
    add("empty_authorization", request(headers=[b"Authorization:"]))
    add("scheme_only", request(headers=[b"Authorization: Basic"]))
    add("scheme_space_only", request(headers=[b"Authorization: Basic "]))
    add("lowercase_scheme", request(headers=[b"Authorization: basic " + token]))
    add("bearer", request(headers=[b"Authorization: Bearer " + token]))
    add("two_spaces", request(headers=[b"Authorization: Basic  " + token]))
    add("tab_separator", request(headers=[b"Authorization: Basic\t" + token]))
    add("leading_whitespace", request(headers=[b"Authorization: \t  " + basic(good)]))
    add("no_space_after_colon", request(headers=[b"Authorization:" + basic(good)]))
    add("header_name_case", request(headers=[b"aUTHORIZATION: " + basic(good)]))
    add("trailing_space", request(headers=[ok + b" "]), p3="header-whitespace", rust_status=200)
    add("trailing_tab", request(headers=[ok + b"\t"]), p3="header-whitespace", rust_status=200)
    add("missing_padding", request(headers=[ok.rstrip(b"=")]))
    add("extra_padding", request(headers=[ok + b"="]))
    add("leading_padding", request(headers=[b"Authorization: Basic =" + token]))
    add("dot_inside", request(headers=[b"Authorization: Basic " + token[:4] + b"." + token[4:]]))
    add("url_safe_alphabet", request(headers=[b"Authorization: " + basic(SERVE_USER.encode() + b":\xfb\xff")
                                              .replace(b"+", b"-").replace(b"/", b"_")]))
    bits = token[:-2] + bytes([token[-2] + 1]) + token[-1:]
    add("non_zero_trailing_bits", request(headers=[b"Authorization: Basic " + bits]))
    add("non_ascii_byte", request(headers=[ok + b"\xe9"]))
    add("control_byte", request(headers=[ok + b"\x01"]), p3="framing", rust_status=400)
    add("obs_fold", request(headers=[b"Authorization: Basic", b" " + token]), p3="framing",
        rust_status=400)
    add("not_utf8", request(headers=[b"Authorization: " + basic(SERVE_USER.encode() + b":\xff")]))
    add("no_colon", request(headers=[b"Authorization: " + basic(SERVE_USER.encode())]))
    add("wrong_user", request(headers=[b"Authorization: " + basic(b"Nyxmon:" + SERVE_PASSWORD.encode())]))
    add("empty_user", request(headers=[b"Authorization: " + basic(b":" + SERVE_PASSWORD.encode())]))
    add("wrong_password", request(headers=[b"Authorization: " + basic(SERVE_USER.encode() + b":wrong")]))
    add("empty_password", request(headers=[b"Authorization: " + basic(SERVE_USER.encode() + b":")]))
    add("colon_in_password", request(headers=[b"Authorization: " + basic(SERVE_USER.encode() + b":pa:ss")]))
    add("lf_in_password", request(headers=[b"Authorization: " + basic(good + b"\n")]))
    add("cr_in_password", request(headers=[b"Authorization: " + basic(good + b"\r")]))
    add("nul_in_password", request(headers=[b"Authorization: " + basic(good + b"\x00")]))
    add("non_ascii_password", request(headers=[b"Authorization: " + basic(SERVE_USER.encode()
                                                                           + ":pässwörd".encode())]))
    add("header_4094_bytes", request(headers=[b"Authorization: "
                                              + basic(SERVE_USER.encode() + b":" + b"x" * 3057)]))
    add("header_4098_bytes", request(headers=[b"Authorization: "
                                              + basic(SERVE_USER.encode() + b":" + b"x" * 3060)]))
    add("two_headers_first_wrong", request(headers=[
        b"Authorization: " + basic(SERVE_USER.encode() + b":wrong"), ok]))
    add("two_headers_first_right", request(headers=[ok, b"Authorization: Basic x"]))
    # The observation.
    add("fresh", request(headers=[ok]))
    add("age_limit", request(headers=[ok]), now=STATE_OK["generated_at_epoch"] + 1800)
    add("stale", request(headers=[ok]), now=STATE_OK["generated_at_epoch"] + 1800.5)
    add("future", request(headers=[ok]), now=STATE_OK["generated_at_epoch"] - 5)
    add("int_timestamp", request(headers=[ok]), with_state(generated_at_epoch=1700000000))
    add("schema_1", request(headers=[ok]), with_state(schema_version=1))
    add("schema_float", request(headers=[ok]), with_state(schema_version=2.0))
    add("schema_string", request(headers=[ok]), with_state(schema_version="2"))
    add("schema_true", request(headers=[ok]), with_state(schema_version=True))
    add("schema_missing", request(headers=[ok]), with_state(schema_version=MISSING))
    add("summary_missing", request(headers=[ok]), with_state(summary=MISSING))
    add("summary_list", request(headers=[ok]), with_state(summary=[]))
    add("summary_key_missing", request(headers=[ok]), summary(os_ok=MISSING))
    add("summary_string", request(headers=[ok]), summary(os_ok="yes"))
    add("summary_int", request(headers=[ok]), summary(traefik_ok=1))
    add("summary_extra_and_fresh", request(headers=[ok]), summary(fresh="old", extra=[1]))
    add("timestamp_missing", request(headers=[ok]), with_state(generated_at_epoch=MISSING))
    add("timestamp_bool", request(headers=[ok]), with_state(generated_at_epoch=True))
    add("timestamp_string", request(headers=[ok]), with_state(generated_at_epoch="1700000000"))
    add("timestamp_null", request(headers=[ok]), with_state(generated_at_epoch=None))
    add("timestamp_huge_int", request(headers=[ok]),
        with_state(generated_at_epoch="__T__").replace('"__T__"', "1" + "0" * 400))
    add("timestamp_overflowing_float", request(headers=[ok]),
        with_state(generated_at_epoch="__T__").replace('"__T__"', "1e400"))
    add("timestamp_nan", request(headers=[ok]),
        with_state(generated_at_epoch="__T__").replace('"__T__"', "NaN"))
    add("nan_elsewhere", request(headers=[ok]), with_state(extra="__T__").replace('"__T__"', "NaN"),
        p3="non-standard-json", rust_status=503)
    add("meta_replaced", request(headers=[ok]), with_state(meta={"age_seconds": 1, "other": 2}))
    add("extra_fields", request(headers=[ok]), with_state(os={"status": "ok", "big": "__B__"}, host="hé")
        .replace('"__B__"', "18446744073709551617"))
    add("duplicate_keys", request(headers=[ok]), state[:-1] + ', "host": "second"}')
    add("state_list", request(headers=[ok]), "[]")
    add("state_empty", request(headers=[ok]), "")
    add("state_broken", request(headers=[ok]), "{broken")
    add("state_missing", request(headers=[ok]), None)
    add("state_bom", request(headers=[ok]), b"\xef\xbb\xbf" + state.encode())
    add("state_not_utf8", request(headers=[ok]), with_state(host="hé").encode().replace(b"\\u00e9", b"\xe9"))
    add("state_crlf", request(headers=[ok]), state.replace(", ", ",\r\n"))
    add("state_trailing_data", request(headers=[ok]), state + " x")
    add("stale_without_auth", request(), now=STATE_OK["generated_at_epoch"] + 9999)
    return out


def parse_response(raw: bytes) -> dict[str, Any]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    result: dict[str, Any] = {"status": status, "challenge": headers.get("www-authenticate"),
                              "body": None}
    if headers.get("content-type") == "application/json":
        assert headers["cache-control"] == "no-store"
        assert int(headers["content-length"]) == len(body)
        data = json.loads(body)
        if "NaN" not in body.decode("ascii"):
            result["body"] = data
    return result


def gen_serve_request_case(case: dict[str, Any], directory: str) -> dict[str, Any]:
    state_path = Path(directory) / "state.json"
    state_path.unlink(missing_ok=True)
    if "state_hex" in case:
        state_path.write_bytes(bytes.fromhex(case["state_hex"]))
    elif case["state"] is not None:
        state_path.write_bytes(case["state"].encode())
    calls: list[list[str]] = []

    def fake_htpasswd(argv: list[str], **kwargs: Any) -> Any:
        assert argv[:3] == ["htpasswd", "-vi", SERVE_CONFIG["htpasswd"]]
        calls.append([argv[3], kwargs["input"]])
        if (argv[3], kwargs["input"]) not in SERVE_PASSWORDS:
            raise subprocess.CalledProcessError(3, argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    handler = live.Handler.__new__(live.Handler)
    handler.rfile = io.BytesIO(bytes.fromhex(case["request_hex"]))
    handler.wfile = io.BytesIO()
    handler.client_address = ("127.0.0.1", 40000)
    handler.server = SimpleNamespace(config={**SERVE_CONFIG, "state": str(state_path)})
    handler.close_connection = True
    with (
        mock.patch.object(live.subprocess, "run", side_effect=fake_htpasswd),
        mock.patch.object(live.time, "time", return_value=case["now"]),
    ):
        handler.handle_one_request()
    result = parse_response(handler.wfile.getvalue())
    return {**case, "python": {**result, "htpasswd": calls[0] if calls else None},
            "htpasswd_calls": len(calls)}


def gen_serve() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        requests = [gen_serve_request_case(case, directory) for case in serve_request_cases()]
    return {
        "constants": {"path": SERVE_PATH, "user": SERVE_USER, "password": SERVE_PASSWORD,
                      "realm": "software-live", "max_age": live.MAX_REPORT_AGE},
        "config": [gen_serve_config_case(*case) for case in serve_config_cases()],
        "requests": requests,
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
    "lifecycle.json": gen_lifecycle,
    "os.json": gen_os,
    "postgresql.json": gen_postgresql,
    "export.json": gen_export,
    "collect.json": gen_collect,
    "serve.json": gen_serve,
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
