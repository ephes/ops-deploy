"""Tests of shadow_compare.py (PLAN.md 10.3) against fake endpoint pairs.

Stdlib only; run from this directory's parent with
``python3 -I -m unittest discover -s parity -p 'test_*.py'``. The comparer
against the real Python scripts and the Rust binary is part of
``run_parity.py`` (family ``shadow``).
"""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Callable

import shadow_compare

PASSWORD = "throwaway-Pa55"  # pragma: allowlist secret (test-only)
DROP = "drop"

Reply = Any  # (status, headers, body) or DROP


def document(served: int, **fields: Any) -> bytes:
    data = {"v": 1, **fields}
    data["meta"] = {
        "age_seconds": served - 100,
        "generated_at": "1970-01-01T00:01:40+00:00",
        "generated_at_epoch": 100,
        "served_at_epoch": served,
    }
    return json.dumps(data, sort_keys=True).encode()


def error(status: int, error_type: str, message: str) -> Reply:
    body = json.dumps(
        {"error": True, "error_type": error_type, "message": message}
    ).encode()
    return (status, {"Content-Type": "application/json"}, body)


def ok(body: bytes) -> Reply:
    return (200, {"Content-Type": "application/json"}, body)


HTML_501 = (
    501,
    {"Content-Type": "text/html;charset=utf-8", "Connection": "close"},
    b"<html>501</html>",
)


def authenticated_endpoint(
    get: Callable[[], Reply], realm: str = "backup-metrics", html404: bool = False
):
    """Answers like a json-file script: path, then auth, then ``get()``."""

    def answer(method: str, path: str, auth: str | None) -> Reply:
        if method != "GET":
            return HTML_501
        if path != "/.well-known/backup":
            if html404:
                return (
                    404,
                    {"Content-Type": "text/html;charset=utf-8", "Connection": "close"},
                    b"<p>404</p>",
                )
            return error(404, "not_found", "Endpoint not found")
        if auth != shadow_compare.authorization_for("user", PASSWORD):
            return (
                401,
                {"WWW-Authenticate": f'Basic realm="{realm}"', "Content-Length": "0"},
                b"",
            )
        return get()

    return answer


class FakeServer:
    def __init__(self, answer: Callable[[str, str, str | None], Reply]) -> None:
        self.answer = answer
        self.requests = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                outer.requests += 1
                reply = outer.answer(
                    self.command, self.path, self.headers.get("Authorization")
                )
                if reply == DROP:
                    self.close_connection = True
                    self.connection.close()
                    return
                status, headers, body = reply
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                if "Content-Length" not in headers:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_POST = _handle  # noqa: N815

            def log_message(self, *args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, args=(0.02,), daemon=True
        )

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> "FakeServer":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


class ShadowCompareTest(unittest.TestCase):
    def setUp(self) -> None:
        shadow_compare.RETRY_DELAY_SECONDS = 0.0
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))
        self.password = self.tmp / "password"
        self.password.write_text(PASSWORD + "\n")
        self.report = self.tmp / "report.jsonl"

    def config(self, endpoints: list[dict[str, Any]]) -> Path:
        path = self.tmp / "shadow.json"
        path.write_text(
            json.dumps(
                {
                    "host": "test",
                    "user": "user",
                    "password_file": str(self.password),
                    "report": str(self.report),
                    "endpoints": endpoints,
                }
            )
        )
        return path

    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = shadow_compare.main(argv)
        return code, out.getvalue(), err.getvalue()

    def compare(
        self,
        python: FakeServer,
        rust: FakeServer,
        mode: str = "json-file",
        **extra: Any,
    ) -> tuple[int, dict[str, Any]]:
        endpoint = {
            "name": "backup",
            "mode": mode,
            "path": "/.well-known/backup",
            "realm": "backup-metrics",
            "python": python.address,
            "rust": rust.address,
            **extra,
        }
        if mode == "static":
            endpoint.pop("path")
            endpoint.pop("realm")
        if mode == "logyard-health":
            endpoint.pop("realm")
        code, _, _ = self.run_main(["run", "--config", str(self.config([endpoint]))])
        line = json.loads(self.report.read_text().splitlines()[-1])
        return code, line

    def pair(
        self,
        python_get: Callable[[], Reply],
        rust_get: Callable[[], Reply],
        **kwargs: Any,
    ):
        return (
            FakeServer(authenticated_endpoint(python_get, **kwargs)),
            FakeServer(authenticated_endpoint(rust_get, **kwargs)),
        )

    def test_equal_documents_with_served_time_one_second_apart(self) -> None:
        python, rust = self.pair(lambda: ok(document(1000)), lambda: ok(document(1001)))
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 0, line)
        backup = line["endpoints"]["backup"]
        self.assertEqual(backup["probes"], 4)
        self.assertEqual(backup["differences"], 0)
        self.assertEqual(backup["statuses"]["get"], [200, 200])
        self.assertEqual(backup["statuses"]["no-auth"], [401, 401])
        self.assertEqual(backup["statuses"]["not-found"], [404, 404])
        self.assertEqual(backup["statuses"]["head"], [501, 501])

    def test_two_seconds_apart_is_a_difference(self) -> None:
        python, rust = self.pair(lambda: ok(document(1000)), lambda: ok(document(1002)))
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(
            line["endpoints"]["backup"]["differing"],
            ["get: body.meta.age_seconds", "get: body.meta.served_at_epoch"],
        )

    def test_value_difference_names_the_key_but_not_the_value(self) -> None:
        python, rust = self.pair(
            lambda: ok(document(1000, sensor="python-only-value")),
            lambda: ok(document(1000, sensor="rust-only-value")),
        )
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(line["endpoints"]["backup"]["differing"], ["get: body.sensor"])
        text = self.report.read_text()
        self.assertNotIn("only-value", text)
        self.assertNotIn(PASSWORD, text)

    def test_number_formatting_is_a_byte_difference(self) -> None:
        python_body = document(1000).replace(b'"v": 1', b'"v": 1.5')
        rust_body = document(1000).replace(b'"v": 1', b'"v": 1.50')
        python, rust = self.pair(lambda: ok(python_body), lambda: ok(rust_body))
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(line["endpoints"]["backup"]["differing"], ["get: body.bytes"])

    def test_python_drop_with_rust_json_error_is_d2(self) -> None:
        python, rust = self.pair(
            lambda: DROP,
            lambda: error(502, "invalid_json", "Invalid JSON in metrics file: x"),
        )
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 0, line)
        self.assertEqual(line["allowed"], {"D-2": 1})
        self.assertEqual(
            line["endpoints"]["backup"]["statuses"]["get"], ["no-answer", 502]
        )

    def test_python_drop_with_another_rust_answer_is_a_difference(self) -> None:
        for rust_reply in (
            error(503, "metrics_file_missing", "Metrics file not found"),
            error(502, "read_error", "Cannot read metrics file: x"),
            ok(document(1000)),
        ):
            with self.subTest(rust_reply[0]):
                python, rust = self.pair(lambda: DROP, lambda: rust_reply)
                with python, rust:
                    code, line = self.compare(python, rust)
                self.assertEqual(code, 1, line)
                self.assertEqual(
                    line["endpoints"]["backup"]["differing"], ["get: python_no_answer"]
                )
        python, rust = self.pair(
            lambda: DROP, lambda: error(500, "internal_error", "Cannot evaluate")
        )
        with python, rust:
            code, line = self.compare(python, rust, mode="apt-state")
        self.assertEqual((code, line["allowed"]), (0, {"D-2": 1}))

    def test_rust_drop_is_a_difference(self) -> None:
        python, rust = self.pair(lambda: ok(document(1000)), lambda: DROP)
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(
            line["endpoints"]["backup"]["differing"], ["get: rust_no_answer"]
        )

    def test_python_nan_document_with_rust_invalid_json_is_d4(self) -> None:
        for python_body in (
            b'{"meta": {}, "v": NaN}',
            b'{"meta": {}, "v": Infinity}',
            b'{"meta": {}, "v": "\\ud800"}',
            b'{"$serde_json::private::Number": "1", "meta": {}}',
            b'{"a": ' + b"[" * 127 + b"]" * 127 + b', "meta": {}}',
        ):
            with self.subTest(python_body[:40]):
                python, rust = self.pair(
                    lambda: ok(python_body),
                    lambda: error(
                        502, "invalid_json", "Invalid JSON in metrics file: nan"
                    ),
                )
                with python, rust:
                    code, line = self.compare(python, rust)
                self.assertEqual(code, 0, line)
                self.assertEqual(line["allowed"], {"D-4": 1})

    def test_rust_refusing_a_valid_document_is_a_difference(self) -> None:
        python_body = (
            b'{"a": ' + b"[" * 126 + b"]" * 126 + b', "meta": {}}'
        )  # depth 127
        python, rust = self.pair(
            lambda: ok(python_body),
            lambda: error(502, "invalid_json", "Invalid JSON in metrics file: x"),
        )
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(line["endpoints"]["backup"]["differing"], ["get: status"])

    def test_error_message_after_the_fixed_prefix_may_differ(self) -> None:
        python, rust = self.pair(
            lambda: error(
                502,
                "invalid_json",
                "Invalid JSON in metrics file: Expecting value: line 1",
            ),
            lambda: error(
                502,
                "invalid_json",
                "Invalid JSON in metrics file: expected value at line 1",
            ),
        )
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 0, line)

    def test_other_error_texts_must_be_equal(self) -> None:
        python, rust = self.pair(
            lambda: error(
                503,
                "metrics_file_missing",
                "Metrics file not found - timer may not have run yet",
            ),
            lambda: error(503, "metrics_file_missing", "Metrics file not found"),
        )
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(
            line["endpoints"]["backup"]["differing"], ["get: body.message"]
        )

    def test_401_on_the_authenticated_probe_is_always_a_difference(self) -> None:
        self.password.write_text("not-the-password\n")
        python, rust = self.pair(lambda: ok(document(1000)), lambda: ok(document(1000)))
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(line["endpoints"]["backup"]["differing"], ["get: auth_401"])
        self.assertEqual(line["endpoints"]["backup"]["statuses"]["get"], [401, 401])

    def test_realm_differences_are_found(self) -> None:
        python = FakeServer(authenticated_endpoint(lambda: ok(document(1000))))
        rust = FakeServer(
            authenticated_endpoint(lambda: ok(document(1000)), realm="other")
        )
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 1)
        self.assertEqual(
            line["endpoints"]["backup"]["differing"],
            ["no-auth: header.WWW-Authenticate"],
        )

    def test_a_difference_that_goes_away_on_the_retry_is_transient(self) -> None:
        answers = iter([document(1000, v=2), document(1005)])
        python, rust = self.pair(lambda: ok(document(1005)), lambda: ok(next(answers)))
        with python, rust:
            code, line = self.compare(python, rust)
        self.assertEqual(code, 0, line)
        self.assertEqual(line["endpoints"]["backup"]["transient"], 1)
        self.assertEqual(line["endpoints"]["backup"]["differences"], 0)

    def test_unreachable_side_is_a_difference(self) -> None:
        python = FakeServer(authenticated_endpoint(lambda: ok(document(1000))))
        with python:
            endpoint = {
                "name": "backup",
                "mode": "json-file",
                "path": "/.well-known/backup",
                "realm": "backup-metrics",
                "python": python.address,
                "rust": "127.0.0.1:9",
                "timeout": 2,
            }
            code, _, _ = self.run_main(
                ["run", "--config", str(self.config([endpoint]))]
            )
        line = json.loads(self.report.read_text())
        self.assertEqual(code, 1)
        self.assertIn("get: rust_unreachable", line["endpoints"]["backup"]["differing"])
        self.assertEqual(
            line["endpoints"]["backup"]["statuses"]["get"], [200, "unreachable"]
        )

    def test_script_mode_pages_compare_status_and_bodies_bytes(self) -> None:
        def page(text: bytes) -> Reply:
            headers = {"Content-Type": "text/html;charset=utf-8", "Connection": "close"}
            return (502, headers, text)

        python, rust = self.pair(
            lambda: page(b"<p>python</p>"), lambda: page(b"<p>rust</p>"), html404=True
        )
        with python, rust:
            code, line = self.compare(python, rust, mode="script")
        self.assertEqual(code, 0, line)
        python, rust = self.pair(
            lambda: ok(b'{"a": 1}\n'), lambda: ok(b'{"a": 1}'), html404=True
        )
        with python, rust:
            code, line = self.compare(python, rust, mode="script")
        self.assertEqual(line["endpoints"]["backup"]["differing"], ["get: body"])
        # D-2: Python drops (stdout not UTF-8), Rust passes it through.
        python, rust = self.pair(
            lambda: DROP, lambda: ok(b'{"x": "\xff"}'), html404=True
        )
        with python, rust:
            code, line = self.compare(python, rust, mode="script")
        self.assertEqual((code, line["allowed"]), (0, {"D-2": 1}))

    def logyard(
        self,
        ready: bool,
        entries: float,
        status: str,
        when: str,
        error: str | None = None,
    ) -> bytes:
        payload = {
            "generated_at": when,
            "selector": '{host="h"}',
            "status": status,
            "loki": {
                "ready": ready,
                "ready_status": 200 if ready else None,
                "ready_body": "ready" if ready else error,
            },
            "ingest": {
                "warning_window_seconds": 900,
                "warning_window_entries": entries,
                "warning_fresh": entries > 0,
                "critical_window_seconds": 3600,
                "critical_window_entries": entries * 4,
                "critical_fresh": entries > 0,
            },
            "units": {
                "vector": {
                    "unit": "vector.service",
                    "exists": True,
                    "load_state": "loaded",
                    "active_state": "active",
                    "sub_state": "running",
                    "result": "success",
                    "error": None,
                }
            },
        }
        return json.dumps(payload, sort_keys=True).encode()

    def logyard_server(self, body: Callable[[], bytes]) -> FakeServer:
        def answer(method: str, path: str, auth: str | None) -> Reply:
            if path != "/.well-known/logyard":
                return (
                    404,
                    {"Content-Type": "application/json"},
                    b'{"error":"not_found"}',
                )
            return ok(body())

        return FakeServer(answer)

    def test_logyard_generated_at_without_timezone_is_a_difference(self) -> None:
        python = self.logyard_server(
            lambda: self.logyard(True, 12.0, "ok", "2026-10-21T10:00:00+00:00")
        )
        rust = self.logyard_server(
            lambda: self.logyard(True, 12.0, "ok", "2026-10-21T10:00:00")
        )
        with python, rust:
            code, line = self.compare(
                python, rust, mode="logyard-health", path="/.well-known/logyard"
            )
        self.assertEqual(code, 1)
        self.assertEqual(
            line["endpoints"]["backup"]["differing"], ["get: body.generated_at"]
        )

    def test_logyard_counts_are_volatile_and_texts_compared_by_presence(self) -> None:
        python = self.logyard_server(
            lambda: self.logyard(True, 12.0, "ok", "2026-10-21T10:00:00+00:00")
        )
        rust = self.logyard_server(
            lambda: self.logyard(True, 15.0, "ok", "2026-10-21T10:00:01+00:00")
        )
        with python, rust:
            code, line = self.compare(
                python, rust, mode="logyard-health", path="/.well-known/logyard"
            )
        self.assertEqual(code, 0, line)
        self.assertEqual(line["endpoints"]["backup"]["probes"], 2)
        python = self.logyard_server(
            lambda: self.logyard(
                False,
                0.0,
                "critical",
                "2026-10-21T10:00:00+00:00",
                "<urlopen error refused>",
            )
        )
        rust = self.logyard_server(
            lambda: self.logyard(
                False,
                0.0,
                "critical",
                "2026-10-21T10:00:00+00:00",
                "connection refused",
            )
        )
        with python, rust:
            code, line = self.compare(
                python, rust, mode="logyard-health", path="/.well-known/logyard"
            )
        self.assertEqual(code, 0, line)
        python = self.logyard_server(
            lambda: self.logyard(True, 12.0, "ok", "2026-10-21T10:00:00+00:00")
        )
        rust = self.logyard_server(
            lambda: self.logyard(True, 0.0, "warning", "2026-10-21T10:00:03+00:00")
        )
        with python, rust:
            code, line = self.compare(
                python, rust, mode="logyard-health", path="/.well-known/logyard"
            )
        self.assertEqual(code, 1)
        self.assertEqual(
            line["endpoints"]["backup"]["differing"],
            [
                "get: body.generated_at",
                "get: body.ingest.critical_fresh",
                "get: body.ingest.warning_fresh",
                "get: body.status",
            ],
        )

    def static_server(self, content_type: str, body: bytes) -> FakeServer:
        headers = {
            "Content-Type": content_type,
            "Cache-Control": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
        }
        return FakeServer(lambda method, path, auth: (200, headers, body))

    def test_static_mime_type_is_d11_but_body_must_match(self) -> None:
        with self.static_server("text/javascript", b"x") as python, self.static_server(
            "application/javascript", b"x"
        ) as rust:
            code, line = self.compare(
                python, rust, mode="static", paths=["/", "/app.js"]
            )
        self.assertEqual(code, 0, line)
        self.assertEqual(line["allowed"], {"D-11": 2})
        with self.static_server("text/html", b"x") as python, self.static_server(
            "text/html", b"y"
        ) as rust:
            code, line = self.compare(python, rust, mode="static", paths=["/"])
        self.assertEqual(code, 1)
        self.assertEqual(line["endpoints"]["backup"]["differing"], ["get:/: body"])

    def test_summary_totals_and_verdict(self) -> None:
        python, rust = self.pair(lambda: ok(document(1000)), lambda: ok(document(1000)))
        with python, rust:
            self.compare(python, rust)
            self.compare(python, rust)
        code, out, _ = self.run_main(["summary", "--report", str(self.report)])
        summary = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(
            (summary["runs"], summary["differences"], summary["pass"]), (2, 0, True)
        )
        python, rust = self.pair(
            lambda: ok(document(1000, v=3)), lambda: ok(document(1000))
        )
        with python, rust:
            self.compare(python, rust)
        code, out, _ = self.run_main(["summary", "--report", str(self.report)])
        summary = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(
            summary["endpoints"]["backup"]["differing"], {"get: body.v": 1}
        )
        empty = self.tmp / "empty.jsonl"
        empty.write_text("")
        self.assertEqual(self.run_main(["summary", "--report", str(empty)])[0], 1)

    def test_preflight_fails_on_401_and_passes_otherwise(self) -> None:
        python, rust = self.pair(
            lambda: error(503, "metrics_file_missing", "m"),
            lambda: error(503, "metrics_file_missing", "m"),
        )
        with python, rust:
            endpoint = {
                "name": "backup",
                "mode": "json-file",
                "path": "/.well-known/backup",
                "realm": "backup-metrics",
                "python": python.address,
                "rust": rust.address,
            }
            config = str(self.config([endpoint]))
            code, out, _ = self.run_main(["preflight", "--config", config])
            self.assertEqual(code, 0, out)
            self.password.write_text("wrong\n")
            code, out, _ = self.run_main(["preflight", "--config", config])
            self.assertEqual(code, 1)
            self.assertIn("backup python: 401 FAIL", out)
            self.assertNotIn("wrong", out)

    def test_configuration_errors_exit_2(self) -> None:
        bad = [
            {"endpoints": []},
            {
                "endpoints": [
                    {
                        "name": "a",
                        "mode": "json-file",
                        "path": "/p",
                        "python": "127.0.0.1:1",
                        "rust": "127.0.0.1:2",
                    }
                ]
            },
            {
                "endpoints": [
                    {
                        "name": "a",
                        "mode": "nope",
                        "path": "/p",
                        "python": "127.0.0.1:1",
                        "rust": "127.0.0.1:2",
                    }
                ]
            },
            {
                "endpoints": [
                    {
                        "name": "a",
                        "mode": "static",
                        "python": "x",
                        "rust": "127.0.0.1:2",
                    }
                ]
            },
            {
                "endpoints": [
                    {
                        "name": "a",
                        "mode": "static",
                        "paths": ["rel"],
                        "python": "127.0.0.1:1",
                        "rust": "127.0.0.1:2",
                    }
                ]
            },
        ]
        for config in bad:
            with self.subTest(config):
                path = self.tmp / "bad.json"
                path.write_text(json.dumps({"report": str(self.report), **config}))
                code, _, err = self.run_main(["run", "--config", str(path)])
                self.assertEqual(code, 2, err)
        self.assertFalse(self.report.exists())

    def test_report_file_is_private(self) -> None:
        python, rust = self.pair(lambda: ok(document(1000)), lambda: ok(document(1000)))
        with python, rust:
            self.compare(python, rust)
        self.assertEqual(os.stat(self.report).st_mode & 0o777, 0o600)

    def test_memory_sampling_reports_systemctl_failures_without_crashing(self) -> None:
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "systemctl"
        fake.write_text(
            "#!/bin/sh\nprintf 'MemoryCurrent=1572864\\nMemoryPeak=[not set]\\nMainPID=0\\n'\n"
        )
        fake.chmod(0o755)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
        try:
            memory = shadow_compare.unit_memory("x.service")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(memory, {"MemoryCurrent": 1572864, "MemoryPeak": None})


class RustRefusesTest(unittest.TestCase):
    def test_documents_rust_refuses(self) -> None:
        refused = [
            b'{"v": NaN}',
            b'{"v": -Infinity}',
            b'{"v": 1e400}',
            b'{"\\udc00": 1}',
            b"[" * 128 + b"]" * 128,
            b'{"$serde_json::private::Number": 1}',
            b"\xff",
        ]
        for body in refused:
            with self.subTest(body[:30]):
                self.assertTrue(shadow_compare.rust_refuses(body))
        accepted = [
            b'{"v": 1e308}',
            b"[" * 127 + b"]" * 127,
            b'{"v": "\\ud83d\\ude00"}',
            b'{"a": 1e400, "a": 1}',
        ]
        for body in accepted:
            with self.subTest(body[:30]):
                self.assertFalse(shadow_compare.rust_refuses(body))


if __name__ == "__main__":
    unittest.main()
