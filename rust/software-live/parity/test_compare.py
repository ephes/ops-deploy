"""Tests of parity/compare.py (stdlib; run by the Rust CI job's script tests)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import compare  # noqa: E402


class Differences(unittest.TestCase):
    def test_equal_values_have_no_difference(self) -> None:
        value = {"a": [1, 2.5, None, True, "x"], "b": {"c": {}}}
        self.assertEqual(compare.differences(value, value), [])

    def test_types_matter(self) -> None:
        self.assertEqual(len(compare.differences({"a": 1}, {"a": 1.0})), 1)
        self.assertEqual(len(compare.differences({"a": 1}, {"a": True})), 1)
        self.assertEqual(len(compare.differences([0], [False])), 1)

    def test_key_sets_and_lengths(self) -> None:
        problems = compare.differences({"a": 1, "b": 2}, {"a": 1, "c": 2})
        self.assertEqual(problems, ["$: keys only in Python ['b'], only in Rust ['c']"])
        self.assertEqual(
            compare.differences([1, 2], [1]), ["$: 2 items in Python, 1 in Rust"]
        )

    def test_time_fields_may_differ_but_stay_numbers(self) -> None:
        python = {
            "generated_at_epoch": 1.5,
            "meta": {"age_seconds": 0.25},
            "apt": {"oldest_security_index_age_seconds": 10.0},
        }
        rust = {
            "generated_at_epoch": 2.5,
            "meta": {"age_seconds": 0.5},
            "apt": {"oldest_security_index_age_seconds": 12.0},
        }
        self.assertEqual(compare.differences(python, rust), [])
        self.assertEqual(
            compare.differences(
                {"apt": {"oldest_security_index_age_seconds": None}},
                {"apt": {"oldest_security_index_age_seconds": None}},
            ),
            [],
        )
        self.assertEqual(
            len(
                compare.differences(
                    {"generated_at_epoch": 1.0}, {"generated_at_epoch": True}
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                compare.differences(
                    {"generated_at_epoch": 1.0}, {"generated_at_epoch": None}
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                compare.differences(
                    {"generated_at_epoch": 1.0}, {"generated_at_epoch": float("inf")}
                )
            ),
            1,
        )

    def test_checked_at_differs_only_for_fresh_lookups(self) -> None:
        fresh_py = {"status": "ok", "cached": False, "checked_at_epoch": 1.0}
        fresh_rs = {"status": "ok", "cached": False, "checked_at_epoch": 2.0}
        self.assertEqual(compare.differences(fresh_py, fresh_rs), [])
        cached_py = dict(fresh_py, cached=True)
        cached_rs = dict(fresh_rs, cached=True)
        self.assertEqual(len(compare.differences(cached_py, cached_rs)), 1)
        # last_success comes from the cache file: P1.
        evidence_py = {"status": "unknown", "last_success": {"checked_at_epoch": 1.0}}
        evidence_rs = {"status": "unknown", "last_success": {"checked_at_epoch": 2.0}}
        self.assertEqual(len(compare.differences(evidence_py, evidence_rs)), 1)
        self.assertEqual(
            len(
                compare.differences(
                    {"last_success_checked_at_epoch": 1.0},
                    {"last_success_checked_at_epoch": 2.0},
                )
            ),
            1,
        )

    def test_error_texts(self) -> None:
        own = frozenset({"service stopped or managed binary missing"})
        same = {"error": "ValueError: service stopped or managed binary missing"}
        self.assertEqual(compare.differences(same, dict(same), own_messages=own), [])
        other_own = {"error": "ValueError: service stopped"}
        self.assertEqual(len(compare.differences(same, other_own, own_messages=own)), 1)
        # An OS text: the class counts, the message is the OS's or Rust's.
        python = {
            "error": "FileNotFoundError: [Errno 2] No such file or directory: '/x'"
        }
        rust = {"error": "FileNotFoundError: No such file or directory (os error 2)"}
        self.assertEqual(compare.differences(python, rust, own_messages=own), [])
        self.assertEqual(
            len(compare.differences(python, {"error": "OSError: x"}, own_messages=own)),
            1,
        )
        # Class-only errors (the upstream lookups) are compared as they are.
        self.assertEqual(
            len(compare.differences({"error": "HTTPError"}, {"error": "URLError"})), 1
        )

    def test_time_spread(self) -> None:
        self.assertEqual(compare.time_spread({"t": 1.0}, {"t": 50.0}, "t", 60), [])
        self.assertEqual(len(compare.time_spread({"t": 1.0}, {"t": 100.0}, "t", 60)), 1)


if __name__ == "__main__":
    unittest.main()
