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
import importlib.util
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
from typing import Any
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


# ------------------------------------------------------------------ driver

GENERATORS: dict[str, Callable[[], Any]] = {
    "pyjson.json": gen_pyjson,
    "version.json": gen_version,
    "policy.json": gen_policy,
    "report.json": gen_report,
    "realpath.json": gen_realpath,
    "cli.json": gen_cli,
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
