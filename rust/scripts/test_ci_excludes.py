"""Tests of ci_excludes.py (PLAN-foundation.md section 3)."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ci_excludes

RUST = Path(__file__).resolve().parents[1]


def metadata(
    members: list[str], ci: object = None, others: tuple[str, ...] = ("serde",)
) -> dict:
    packages = [
        {"name": name, "id": f"path+file:///w/{name}#0.0.0"} for name in members
    ]
    packages += [
        {"name": name, "id": f"registry+https://x#{name}@1.0.0"} for name in others
    ]
    return {
        "packages": packages,
        "workspace_members": [f"path+file:///w/{name}#0.0.0" for name in members],
        "metadata": ci,
    }


def run_main(argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    old_stdin = ci_excludes.sys.stdin
    ci_excludes.sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = ci_excludes.main(argv)
    finally:
        ci_excludes.sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()


class ExcludesTest(unittest.TestCase):
    def test_no_workspace_metadata(self):
        self.assertEqual(ci_excludes.arguments(metadata(["metrics-httpd"])), "")

    def test_no_ci_table(self):
        self.assertEqual(ci_excludes.arguments(metadata(["a"], {"other": {}})), "")

    def test_empty_list(self):
        self.assertEqual(
            ci_excludes.arguments(metadata(["a"], {"ci": {"exclude": []}})), ""
        )

    def test_members_in_listed_order(self):
        data = metadata(
            ["software-live", "software-live-apt", "zz-apt", "a"],
            {"ci": {"exclude": ["zz-apt", "software-live-apt"]}},
        )
        self.assertEqual(
            ci_excludes.arguments(data), "--exclude zz-apt --exclude software-live-apt"
        )

    def test_rejects(self):
        cases = {
            "non-member": metadata(["a", "b"], {"ci": {"exclude": ["c"]}}),
            "dependency, not a member": metadata(
                ["a", "b"], {"ci": {"exclude": ["serde"]}}
            ),
            "not a list": metadata(["a", "b"], {"ci": {"exclude": "b"}}),
            "not strings": metadata(["a", "b"], {"ci": {"exclude": [1]}}),
            "duplicate": metadata(["a", "b"], {"ci": {"exclude": ["b", "b"]}}),
            "every member": metadata(["a", "b"], {"ci": {"exclude": ["a", "b"]}}),
            "ci not a table": metadata(["a"], {"ci": ["a"]}),
            "metadata not a table": metadata(["a"], ["ci"]),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(ci_excludes.ExcludeError):
                ci_excludes.excludes(data)

    def test_main_reads_file_and_stdin(self):
        data = metadata(["a", "b"], {"ci": {"exclude": ["b"]}})
        self.assertEqual(run_main([], json.dumps(data)), (0, "--exclude b\n", ""))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metadata.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(run_main([str(path)]), (0, "--exclude b\n", ""))
            self.assertEqual(run_main([str(path), "x"])[0], 2)
            code, out, err = run_main([str(Path(tmp) / "missing.json")])
            self.assertEqual((code, out), (1, ""))
            self.assertIn("ci_excludes.py:", err)

    def test_main_errors_exit_1(self):
        for stdin in (
            "not json",
            "[]",
            json.dumps(metadata(["a", "b"], {"ci": {"exclude": ["c"]}})),
        ):
            with self.subTest(stdin=stdin):
                code, out, err = run_main([], stdin)
                self.assertEqual((code, out), (1, ""))
                self.assertTrue(err.startswith("ci_excludes.py: "), err)

    @unittest.skipUnless(shutil.which("cargo"), "cargo not on PATH")
    def test_real_workspace(self):
        """The committed workspace: the list is valid (empty until a crate needs it)."""
        env = dict(os.environ, CARGO_TERM_COLOR="never")
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--locked",
                "--offline",
            ],
            cwd=RUST,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        self.assertIn("metrics-httpd", ci_excludes.workspace_members(data))
        ci_excludes.excludes(data)


if __name__ == "__main__":
    unittest.main()
