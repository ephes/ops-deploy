"""Tests of parity/shadow_compare.py (stdlib; the oracle checks need Python 3.11+)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import shadow_compare  # noqa: E402

T0 = 1_800_000_000.0
NEEDS_ORACLE = unittest.skipIf(
    sys.version_info < (3, 11), "the Python oracle needs Python 3.11 or later"
)


def state(at: float = T0) -> dict:
    return {
        "schema_version": 2,
        "host": "host-a",
        "generated_at_epoch": at,
        "policy_sha256": "0" * 64,
        "os": {
            "codename": "noble",
            "cycle": "24.04",
            "desired_cycle": "24.04",
            "expected_id": "ubuntu",
            "id": "ubuntu",
            "issues": [],
            "lifecycle": {"eol": "2029-05-31", "latest_release": "24.04.5"},
            "observed": True,
            "pretty_name": "Ubuntu 24.04.5 LTS",
            "status": "ok",
            "upstream": {
                "cached": True,
                "checked_at_epoch": at - 3600,
                "product": "ubuntu",
                "status": "ok",
            },
        },
        "postgresql": {
            "expected": False,
            "issues": [],
            "observed": True,
            "status": "ok",
            "upstream": {"status": "not_applicable"},
        },
        "traefik": {
            "binary_path": "/usr/bin/traefik",
            "expected": True,
            "installed": {"sha256": "a" * 64, "version": "3.7.14"},
            "issues": [],
            "main_pid": 100,
            "observed": True,
            "running": {"sha256": "a" * 64, "version": "3.7.14"},
            "running_path": "/usr/bin/traefik",
            "status": "ok",
            "upstream": {
                "cached": True,
                "checked_at_epoch": at - 3600,
                "status": "ok",
                "version": "3.7.14",
            },
        },
        "apt": {
            "index_age_limit_seconds": 172800,
            "index_source": "cached security InRelease publication mtimes; no refresh performed",
            "indexes_fresh": True,
            "oldest_security_index_age_seconds": 1000.0,
            "pending_security_count": 0,
            "pending_security_updates": [],
            "status": "ok",
        },
        "summary": {
            "apt_indexes_fresh": True,
            "observation_ok": True,
            "os_ok": True,
            "postgresql_ok": True,
            "security_updates_ok": True,
            "traefik_ok": True,
        },
    }


def resummarize(data: dict) -> dict:
    data["summary"] = shadow_compare.expected_summary(data)
    return data


class FakeOracle:
    """Stands in for software_live.inventory_projection where no oracle is needed."""

    @staticmethod
    def inventory_projection(data: dict) -> dict:
        return {"observed_at_epoch": data["generated_at_epoch"], "status": data["os"]["status"]}


def side(data: dict, caches: dict | None = None, oracle=FakeOracle) -> dict:
    return {
        "state": {"json": data},
        "projection": {"json": oracle.inventory_projection(data)},
        "caches": {
            name: {"json": value}
            for name, value in (
                caches
                if caches is not None
                else {
                    "upstream.json": {"version": "3.7.14", "checked_at_epoch": T0 - 3600},
                    "upstream-ubuntu.json": {
                        "product": "ubuntu",
                        "cycles": [{"cycle": "24.04", "eol": "2029-05-31"}],
                        "checked_at_epoch": T0 - 3600,
                    },
                }
            ).items()
        },
    }


def bundle(production: dict, shadow: dict, evidence: dict | None = None, **kw) -> dict:
    return {
        "production": kw.get("production_side") or side(production),
        "shadow": kw.get("shadow_side") or side(shadow),
        "evidence": evidence or {},
    }


def run(b: dict, oracle=FakeOracle) -> dict:
    return shadow_compare.compare(b, oracle=oracle)


class Matching(unittest.TestCase):
    def test_identical_observations_match(self) -> None:
        report = run(bundle(state(), state(T0 + 420)))
        self.assertEqual(report["verdict"], "match")
        self.assertEqual(report["gap_seconds"], 420.0)
        self.assertTrue(all(c["ok"] for c in report["checks"]))

    def test_time_and_separate_cache_fields_are_ignored(self) -> None:
        shadow = state(T0 + 420)
        shadow["apt"]["oldest_security_index_age_seconds"] = 1420.0
        shadow["os"]["upstream"].update(cached=False, checked_at_epoch=T0 + 400)
        shadow["traefik"]["upstream"]["checked_at_epoch"] = T0 + 401
        report = run(bundle(state(), shadow))
        self.assertEqual(report["verdict"], "match")
        self.assertEqual(report["ignored"], 4)

    def test_a_time_field_must_stay_a_number(self) -> None:
        shadow = state(T0 + 420)
        shadow["apt"]["oldest_security_index_age_seconds"] = "1420"
        self.assertEqual(run(bundle(state(), shadow))["verdict"], "mismatch")


class HardChecks(unittest.TestCase):
    def failed(self, report: dict) -> list[str]:
        return [c["check"] for c in report["checks"] if not c["ok"]]

    def test_policy_hash_must_be_identical(self) -> None:
        shadow = state(T0 + 420)
        shadow["policy_sha256"] = "1" * 64
        report = run(bundle(state(), shadow))
        self.assertEqual(self.failed(report), ["same policy_sha256"])
        self.assertEqual(report["verdict"], "mismatch")

    def test_host_must_be_identical(self) -> None:
        shadow = state(T0 + 420)
        shadow["host"] = "host-b"
        self.assertEqual(self.failed(run(bundle(state(), shadow))), ["same host"])

    def test_summary_must_follow_from_the_observations(self) -> None:
        shadow = state(T0 + 420)
        shadow["summary"]["traefik_ok"] = False
        self.assertEqual(
            self.failed(run(bundle(state(), shadow))),
            ["shadow summary follows from its observations"],
        )

    def test_projection_must_be_the_oracles(self) -> None:
        shadow_side = side(state(T0 + 420))
        shadow_side["projection"]["json"]["status"] = "warning"
        report = run(bundle(state(), None, shadow_side=shadow_side))
        failed = [c for c in report["checks"] if not c["ok"]]
        self.assertEqual(len(failed), 1)
        self.assertIn("shadow software-health.json", failed[0]["check"])
        self.assertNotIn("another run", failed[0]["detail"])

    def test_projection_of_another_run_is_named(self) -> None:
        shadow_side = side(state(T0 + 420))
        shadow_side["projection"]["json"]["observed_at_epoch"] = T0 - 480
        report = run(bundle(state(), None, shadow_side=shadow_side))
        failed = [c for c in report["checks"] if not c["ok"]]
        self.assertIn("another run", failed[0]["detail"])

    def test_missing_shadow_state_is_a_mismatch(self) -> None:
        shadow_side = side(state())
        shadow_side["state"] = {"missing": True}
        report = run(bundle(state(), None, shadow_side=shadow_side))
        self.assertEqual(report["verdict"], "mismatch")
        self.assertEqual(self.failed(report), ["shadow state readable (schema 2)"])

    def test_unavailable_oracle_fails_the_projection_check(self) -> None:
        def broken():
            raise RuntimeError("no oracle")

        original = shadow_compare.load_oracle
        shadow_compare.load_oracle = broken
        try:
            report = shadow_compare.compare(bundle(state(), state(T0 + 420)))
        finally:
            shadow_compare.load_oracle = original
        self.assertEqual(report["verdict"], "mismatch")


class Explanations(unittest.TestCase):
    def paths(self, report: dict, kind: str) -> list[str]:
        return [item["path"] for item in report[kind]]

    def test_traefik_restart_explains_pid_and_running_fields(self) -> None:
        shadow = state(T0 + 420)
        shadow["traefik"]["main_pid"] = 200
        shadow["traefik"]["running"] = {"sha256": "b" * 64, "version": "3.7.16"}
        shadow["traefik"]["issues"] = ["installed_running_mismatch"]
        shadow["traefik"]["status"] = "warning"
        report = run(bundle(state(), resummarize(shadow)))
        self.assertEqual(report["unexplained"], [])
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertIn("$.traefik.main_pid", self.paths(report, "explained"))

    def test_running_change_without_restart_is_unexplained(self) -> None:
        shadow = state(T0 + 420)
        shadow["traefik"]["running"]["version"] = "3.7.16"
        report = run(bundle(state(), shadow))
        self.assertEqual(self.paths(report, "unexplained"), ["$.traefik.running.version"])

    def test_different_cached_upstream_data_explain_lifecycle(self) -> None:
        shadow = state(T0 + 420)
        shadow["os"]["lifecycle"]["latest_release"] = "24.04.6"
        caches = {
            "upstream.json": {"version": "3.7.14", "checked_at_epoch": T0 - 3600},
            "upstream-ubuntu.json": {
                "product": "ubuntu",
                "cycles": [{"cycle": "24.04", "eol": "2029-05-31", "latestRelease": "24.04.6"}],
                "checked_at_epoch": T0 + 400,
            },
        }
        report = run(bundle(state(), None, shadow_side=side(shadow, caches)))
        self.assertEqual(report["unexplained"], [])
        self.assertIn("upstream-ubuntu.json", report["explained"][0]["reason"])

    def test_equal_cached_upstream_data_do_not_explain_lifecycle(self) -> None:
        shadow = state(T0 + 420)
        shadow["os"]["lifecycle"]["latest_release"] = "24.04.6"
        report = run(bundle(state(), shadow))
        self.assertEqual(self.paths(report, "unexplained"), ["$.os.lifecycle.latest_release"])

    def test_upstream_version_change_explains_traefik_issues(self) -> None:
        shadow = state(T0 + 420)
        shadow["traefik"]["upstream"]["version"] = "3.7.16"
        shadow["traefik"]["issues"] = ["outdated_running_version"]
        shadow["traefik"]["status"] = "warning"
        caches = {"upstream.json": {"version": "3.7.16", "checked_at_epoch": T0 + 400}}
        report = run(bundle(state(), None, shadow_side=side(resummarize(shadow), caches)))
        self.assertEqual(report["unexplained"], [])
        self.assertEqual(len(report["explained"]), 3)

    def test_failed_shadow_lookup_is_never_explained(self) -> None:
        shadow = state(T0 + 420)
        shadow["traefik"]["upstream"] = {"status": "unknown", "error": "URLError", "last_success": None}
        report = run(bundle(state(), shadow))
        self.assertIn("$.traefik.upstream.status", self.paths(report, "unexplained"))

    def test_failed_production_lookup_is_explained(self) -> None:
        production = state()
        production["traefik"]["upstream"] = {"status": "unknown", "error": "URLError", "last_success": None}
        report = run(bundle(production, state(T0 + 420)))
        self.assertEqual(report["unexplained"], [])
        self.assertIn("production (Python) lookup failed", report["explained"][0]["reason"])

    def apt_change(self, shadow_age: float, evidence: dict | None = None) -> dict:
        shadow = state(T0 + 420)
        shadow["apt"]["oldest_security_index_age_seconds"] = shadow_age
        shadow["apt"]["pending_security_count"] = 1
        shadow["apt"]["pending_security_updates"] = [
            {"candidate": "2", "held": False, "installed": "1", "package": "pkg:amd64", "security_version": "2"}
        ]
        return run(bundle(state(), resummarize(shadow), evidence))

    def test_apt_list_refresh_explains_apt_changes(self) -> None:
        report = self.apt_change(shadow_age=60.0)
        self.assertEqual(report["unexplained"], [])
        self.assertIn("refreshed", report["explained"][0]["reason"])

    def test_apt_change_without_evidence_is_unexplained(self) -> None:
        report = self.apt_change(shadow_age=1420.0)
        self.assertEqual(len(report["unexplained"]), 2)

    def test_dpkg_change_between_the_observations_explains(self) -> None:
        report = self.apt_change(1420.0, {"dpkg_status_mtime": T0 + 100})
        self.assertEqual(report["unexplained"], [])
        self.assertIn("dpkg", report["explained"][0]["reason"])

    def test_dpkg_change_outside_the_observations_does_not_explain(self) -> None:
        report = self.apt_change(1420.0, {"dpkg_status_mtime": T0 - 100})
        self.assertEqual(len(report["unexplained"]), 2)

    def test_explained_differences_never_pass(self) -> None:
        for report in (
            self.apt_change(shadow_age=60.0),
            self.apt_change(1420.0, {"dpkg_status_mtime": T0 + 100}),
        ):
            self.assertEqual(report["verdict"], "inconclusive")

    def test_index_age_crossing_explains_only_freshness(self) -> None:
        production = state()
        production["apt"]["oldest_security_index_age_seconds"] = 172700.0
        shadow = state(T0 + 420)
        shadow["apt"]["oldest_security_index_age_seconds"] = 173120.0
        shadow["apt"]["indexes_fresh"] = False
        shadow["apt"]["pending_security_count"] = 1
        shadow["apt"]["pending_security_updates"] = [
            {"candidate": "2", "held": False, "installed": "1", "package": "pkg:amd64", "security_version": "2"}
        ]
        report = run(bundle(production, resummarize(shadow)))
        self.assertEqual(
            self.paths(report, "unexplained"),
            ["$.apt.pending_security_count", "$.apt.pending_security_updates"],
        )
        self.assertEqual(self.paths(report, "explained"), ["$.apt.indexes_fresh"])
        self.assertEqual(report["verdict"], "mismatch")

    def test_index_age_crossing_the_limit_explains_freshness(self) -> None:
        production = state()
        production["apt"]["oldest_security_index_age_seconds"] = 172700.0
        shadow = state(T0 + 420)
        shadow["apt"]["oldest_security_index_age_seconds"] = 173120.0
        shadow["apt"]["indexes_fresh"] = False
        report = run(bundle(production, resummarize(shadow)))
        self.assertEqual(report["unexplained"], [])
        self.assertIn("crossed", report["explained"][0]["reason"])

    def test_unrelated_field_is_never_explained(self) -> None:
        shadow = state(T0 + 420)
        shadow["traefik"]["main_pid"] = 200
        shadow["traefik"]["binary_path"] = "/opt/traefik"
        shadow["os"]["observed"] = False
        report = run(bundle(state(), shadow), oracle=FakeOracle)
        self.assertIn("$.traefik.binary_path", self.paths(report, "unexplained"))
        self.assertIn("$.os.observed", self.paths(report, "unexplained"))


@NEEDS_ORACLE
class Oracle(unittest.TestCase):
    """The real projection of roles/software_live/files/software_live.py."""

    def test_oracle_projection_matches(self) -> None:
        oracle = shadow_compare.load_oracle()
        b = bundle(
            state(),
            state(T0 + 420),
            production_side=side(state(), oracle=oracle),
            shadow_side=side(state(T0 + 420), oracle=oracle),
        )
        report = shadow_compare.compare(b)
        self.assertEqual(report["verdict"], "match", report)

    def test_oracle_rejects_a_changed_projection(self) -> None:
        oracle = shadow_compare.load_oracle()
        shadow_side = side(state(T0 + 420), oracle=oracle)
        shadow_side["projection"]["json"]["checks"]["traefik"]["running_version"] = "9.9.9"
        b = bundle(state(), None, production_side=side(state(), oracle=oracle), shadow_side=shadow_side)
        self.assertEqual(shadow_compare.compare(b)["verdict"], "mismatch")


class CommandLine(unittest.TestCase):
    def test_bundle_round_trip_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            good.write_text(json.dumps(bundle(state(), state(T0 + 420))))
            original = shadow_compare.load_oracle
            shadow_compare.load_oracle = lambda: FakeOracle
            out, err = io.StringIO(), io.StringIO()
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(shadow_compare.main(["--bundle", str(good)]), 0)
                    bad = copy.deepcopy(bundle(state(), state(T0 + 420)))
                    bad["shadow"]["state"]["json"]["policy_sha256"] = "1" * 64
                    good.write_text(json.dumps(bad))
                    self.assertEqual(shadow_compare.main(["--bundle", str(good), "--json"]), 1)
                    restart = bundle(state(), state(T0 + 420))
                    restart["shadow"]["state"]["json"]["traefik"]["main_pid"] = 200
                    good.write_text(json.dumps(restart))
                    self.assertEqual(shadow_compare.main(["--bundle", str(good)]), 3)
                    (Path(tmp) / "junk.json").write_text("[]")
                    self.assertEqual(shadow_compare.main(["--bundle", str(Path(tmp) / "junk.json")]), 2)
                    self.assertEqual(shadow_compare.main(["--bundle", str(Path(tmp) / "absent.json")]), 2)
            finally:
                shadow_compare.load_oracle = original
            self.assertIn("verdict: match\n", out.getvalue())
            self.assertIn("verdict: inconclusive (", out.getvalue())
            self.assertIn('"verdict": "mismatch"', out.getvalue())
            self.assertIn("not a shadow_compare bundle", err.getvalue())

    def test_quote_survives_the_remote_shell(self) -> None:
        text = "a 'b' \"c\" $d `e` \\f\n"
        out = subprocess.run(
            ["sh", "-c", "printf %s " + shadow_compare._quote(text)],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertEqual(out, text)

    def test_remote_program_reads_a_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "software-live"
            (data / "shadow").mkdir(parents=True)
            (data / "state.json").write_text(json.dumps(state()))
            (data / "upstream-ubuntu.json").write_text('{"product": "ubuntu"}')
            (data / "shadow" / "state.json").write_text("{broken")
            projection = Path(tmp) / "software-health.json"
            out = subprocess.run(
                [sys.executable, "-I", "-c", shadow_compare.REMOTE, str(data), str(projection)],
                capture_output=True, text=True, check=True,
            ).stdout
        result = json.loads(out)
        self.assertEqual(result["production"]["state"]["json"]["host"], "host-a")
        self.assertEqual(result["production"]["projection"], {"missing": True})
        self.assertEqual(list(result["production"]["caches"]), ["upstream-ubuntu.json"])
        self.assertEqual(result["shadow"]["state"], {"error": "JSONDecodeError"})
        self.assertEqual(result["shadow"]["projection"], {"missing": True})
        self.assertIn("dpkg_status_mtime", result["evidence"])


if __name__ == "__main__":
    unittest.main()
