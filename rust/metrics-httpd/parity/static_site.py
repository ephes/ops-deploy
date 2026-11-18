#!/usr/bin/env python3
"""Static-site parity of metrics-httpd (rust/metrics-httpd/PLAN.md 4.7, D-11).

Serves one site directory with the Rust binary (``metrics-httpd static``)
and compares every published file with the Python side, which is either the
rendered ``static-site-httpd.py.j2`` started here on the same directory, or
(``--reference-url``) a deployed Python server, e.g. the live benchmark site
behind Traefik with a copy of its files in ``--site``.

Per regular file below the site (symlinks followed, as both servers do):
GET, HEAD and a GET with ``If-Modified-Since`` set to the Python side's
``Last-Modified``; per directory: GET with and without the trailing ``/``.
Status, body, ``Content-Type``, ``Content-Length``, ``Last-Modified``,
``Location`` and the four headers of the template's ``end_headers`` must be
identical; of an error page (status >= 400), whose text may differ (D-3),
the status, ``Content-Type`` and those four headers. Headers outside that
list are not compared (D-7: ``Server``, keep-alive; D-11: ``Accept-Ranges``;
Traefik's own headers). ``Content-Type`` is compared too, although D-11
allows ``mime_guess`` to differ from ``mimetypes``: a difference on a
published file is what S9e has to decide on. A locally started Python reads
this machine's ``mime.types`` files, a deployed one its host's. Exit 0 when
everything matches, 1 on a difference, 2 on a usage error.

``--record FILE`` writes the compared files (path, size, sha256 and the
Python side's ``Content-Type`` and ``Last-Modified``) as JSON; S2e recorded
the live site that way (``static_real_site.json``), and
``tests/fixtures.rs`` checks the Rust side's types against that record.

Stdlib only; read-only against ``--reference-url`` (GET and HEAD).
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / "roles/static_site_deploy/templates/static-site-httpd.py.j2"
COMPARED = (
    "Content-Type",
    "Content-Length",
    "Last-Modified",
    "Location",
    "Cache-Control",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)


class Side:
    """One server under comparison: scheme, host, port and the path prefix."""

    def __init__(self, url: str) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise SystemExit(f"not an http(s) URL: {url}")
        self.https = parts.scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.https else 80)
        self.prefix = parts.path.rstrip("/")

    def request(
        self, method: str, path: str, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        connection_class = (
            http.client.HTTPSConnection if self.https else http.client.HTTPConnection
        )
        connection = connection_class(self.host, self.port, timeout=30)
        try:
            connection.request(method, self.prefix + path, headers=headers or {})
            response = connection.getresponse()
            body = response.read()
            return {
                "status": response.status,
                "headers": {name: response.getheader(name) for name in COMPARED},
                "sha256": hashlib.sha256(body).hexdigest(),
                "size": len(body),
            }
        finally:
            connection.close()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def render_template(site: Path, port: int) -> str:
    """The template's three variables, without Jinja (stdlib only)."""
    text = TEMPLATE.read_text(encoding="utf-8")
    values = {
        "static_site_path": str(site),
        "static_site_bind_host": "127.0.0.1",
        "static_site_port": str(port),
    }
    for name, value in values.items():
        text = text.replace("{{ " + name + " }}", value)
    if "{{" in text or "{%" in text:
        raise SystemExit(f"{TEMPLATE} uses Jinja beyond its three variables")
    return text


def wait_listening(port: int, process: subprocess.Popen[Any]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"server exited with {process.returncode}")
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise SystemExit(f"nothing listens on 127.0.0.1:{port}")


def start_rust(binary: Path, site: Path) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [str(binary), "static", "--bind", "127.0.0.1", "--port", "0", "--root", str(site)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stderr is not None
    line = process.stderr.readline()
    match = re.search(r" listening on (\S+)$", line.strip())
    if not match:
        process.kill()
        raise SystemExit(f"unexpected startup line: {line!r}")
    return process, f"http://{match.group(1)}"


def start_python(site: Path, workdir: Path) -> tuple[subprocess.Popen[str], str]:
    port = free_port()
    script = workdir / "static-site-httpd.py"
    script.write_text(render_template(site, port), encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, "-I", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    wait_listening(port, process)
    return process, f"http://127.0.0.1:{port}"


def published(site: Path) -> tuple[list[str], list[str]]:
    """URL paths of the regular files and of the directories below `site`."""
    files, dirs = [], []
    for current, dirnames, filenames in os.walk(site, followlinks=True):
        relative = Path(current).relative_to(site)
        for name in sorted(dirnames):
            dirs.append("/" + urllib.parse.quote((relative / name).as_posix()))
        for name in sorted(filenames):
            path = Path(current) / name
            if path.is_file():
                files.append("/" + urllib.parse.quote((relative / name).as_posix()))
        dirnames.sort()
    return sorted(files), sorted(dirs)


def compare(python: Side, rust: Side, site: Path) -> tuple[list[str], list[dict[str, Any]]]:
    files, dirs = published(site)
    differences: list[str] = []
    record: list[dict[str, Any]] = []

    def check(label: str, method: str, path: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        expected = python.request(method, path, headers)
        actual = rust.request(method, path, headers)
        # An error page (send_error) may differ in its text (D-3): status,
        # Content-Type and the end_headers additions are compared.
        error_page = expected["status"] >= 400
        for key in ("status",) if error_page else ("status", "sha256"):
            if expected[key] != actual[key]:
                differences.append(f"{label} {method} {path}: {key} {expected[key]!r} != {actual[key]!r}")
        for name in COMPARED:
            if error_page and name == "Content-Length":
                continue
            if expected["headers"][name] != actual["headers"][name]:
                differences.append(
                    f"{label} {method} {path}: {name} {expected['headers'][name]!r} != {actual['headers'][name]!r}"
                )
        return expected

    for path in ["/", *files]:
        got = check("file", "GET", path)
        check("file", "HEAD", path)
        last_modified = got["headers"]["Last-Modified"]
        if last_modified:
            check("conditional", "GET", path, {"If-Modified-Since": last_modified})
        if path != "/":
            record.append(
                {
                    "path": urllib.parse.unquote(path[1:]),
                    "size": got["size"],
                    "sha256": got["sha256"],
                    "content_type": got["headers"]["Content-Type"],
                    "last_modified": last_modified,
                }
            )
    for path in dirs:
        check("directory", "GET", path)
        check("directory", "GET", path + "/")
    return differences, record


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--site", type=Path, required=True, help="the site directory")
    parser.add_argument("--binary", type=Path, required=True, help="the metrics-httpd binary")
    parser.add_argument(
        "--reference-url",
        help="a deployed Python server serving the same files (default: start the template here)",
    )
    parser.add_argument("--record", type=Path, help="write the compared files as JSON")
    args = parser.parse_args(argv)
    site = args.site.resolve()
    if not site.is_dir():
        parser.error(f"{site} is not a directory")
    processes: list[subprocess.Popen[str]] = []
    try:
        with tempfile.TemporaryDirectory() as workdir:
            if args.reference_url:
                python_url = args.reference_url
                reference = f"{args.reference_url} (deployed)"
            else:
                process, python_url = start_python(site, Path(workdir))
                processes.append(process)
                reference = f"static-site-httpd.py.j2 under Python {sys.version.split()[0]}"
            process, rust_url = start_rust(args.binary, site)
            processes.append(process)
            differences, record = compare(Side(python_url), Side(rust_url), site)
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    for line in differences:
        print(line)
    print(f"{len(record)} files compared against {reference}: {len(differences)} differences")
    if args.record:
        args.record.write_text(
            json.dumps(
                {"reference": reference, "recorded": date.today().isoformat(), "files": record},
                indent=1,
            )
            + "\n",
            encoding="utf-8",
        )
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
