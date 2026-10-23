"""The isolated native compatibility proof (:mod:`ops_deploy.infra.traefik_tx.proof`).

The end-to-end tests run the whole proof on a temporary root: the transient unit is the
only thing replaced. Where the host would call ``systemd-run``, the test runs the unit's
command line itself, ``python3 -I <work dir>/proof.py --inside <spec>``, so the copied
program starts standalone next to its copy of the engine. "Traefik" is a stand-in
executable that answers ``version`` and serves a fixture ``/api/rawdata`` on the
config's ``traefik`` entrypoint, and only when the config sets ``api.insecure``.
Systemd isolation itself is proven on a VM (see ``docs/traefik.md``).
"""

from __future__ import annotations

import ast
import datetime
import fcntl
import http.server
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.helpers.traefik import BasicAuth, HealthCheck, RedirectRegex, TraefikRoute, render_route
from ops_deploy.infra.traefik_tx import engine, proof
from tests.traefik_tx_fixtures import (
    MACHINE_ID,
    NEW,
    OLD,
    RootOwnedPath,
    relaxed_trusted_file,
    release_archive,
    run_scenario,
    sha256,
)

PROOF_PATH = Path(proof.__file__)
GOLDEN = Path(__file__).parent / "golden" / "traefik_tx_proof.json"
# The proof files of the 2026-09 rollout (``/var/lib/traefik-update-proofs/3.7.13-20260914-<host>.json``).
FORMAT_2026_09 = (
    "host",
    "version",
    "architecture",
    "candidate_binary_sha256",
    "live_config_sha256",
    "router_count",
    "disabled",
    "api_reachable",
    "isolation_override",
)
FILE_ROUTERS = ["app-http@file", "app-secure@file", "extra@file", "nested@file", "tcp:db@file"]
INTERNAL_ROUTERS = ["api@internal", "web-to-web-secure@internal"]
STATIC = """# fixture static configuration
[global]
  checkNewVersion = true

[api]
  dashboard = true

[log]
  filePath = "{root}/log/traefik.log"

[providers.file]
  directory = "{root}/etc/dynamic"
  watch = true

[entryPoints]
  [entryPoints.web]
    address = ":80"
  [entryPoints.web-secure]
    address = ":443"
  [entryPoints.traefik]
    address = "127.0.0.1:{port}"

[certificatesResolvers.letsencrypt.acme]
  email = "ops@example.invalid"
  storage = "{root}/etc/dynamic/acme.json"
  [certificatesResolvers.letsencrypt.acme.httpChallenge]
    entryPoint = "web"
"""
APP = """# app routes
http:
  routers:
    app-http:
      rule: "Host(`app.example.test`)"
      entryPoints:
        - web
      service: app
    app-secure:
      rule: "Host(`app.example.test`)"
      entryPoints: [web-secure]
      service: app
      tls:
        certResolver: letsencrypt
  services:
    app:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:9000"
tcp:
  routers:
    db:
      rule: "HostSNI(`db.example.test`)"
      service: db
  services:
    db:
      loadBalancer:
        servers:
          - address: "127.0.0.1:5432"
"""
TRAEFIK = """#!{python}
import http.server, json, sys, tomllib
VERSION, ARCH, MODE = {version!r}, {arch!r}, {mode!r}
if sys.argv[1:] == ["version"]:
    print(f"Version:      {{VERSION}}\\nCodename:     fixture\\nOS/Arch:      {{ARCH}}")
    raise SystemExit(0)
(argument,) = sys.argv[1:]
with open(argument.partition("=")[2], "rb") as stream:
    config = tomllib.load(stream)
with open(MODE) as stream:
    mode = json.load(stream)
if mode.get("exit"):
    raise SystemExit(3)
body = json.dumps(mode["rawdata"]).encode()
insecure = config.get("api", {{}}).get("insecure") is True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        found = insecure and self.path == "/api/rawdata"
        self.send_response(200 if found else 404)
        self.end_headers()
        self.wfile.write(body if found else b"")

    def log_message(self, *args):
        pass

port = int(config["entryPoints"]["traefik"]["address"].rpartition(":")[2])
http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
"""


def native_arch() -> str:
    return f"linux/{proof.GOARCH[os.uname().machine]}"


def router(shown: str) -> tuple[str, str]:
    """The (kind, name) a router is shown as (``proof.qualified`` backwards)."""

    kind, separator, name = shown.partition(":")
    return (kind, name) if separator and kind in proof.KINDS else ("http", shown)


def routers(shown: list[str]) -> set[tuple[str, str]]:
    return {router(name) for name in shown}


def rawdata(shown: list[str], disabled: tuple[str, ...] = ()) -> dict[str, Any]:
    """An ``/api/rawdata`` answer with these routers (as shown)."""

    raw: dict[str, Any] = {"routers": {}, "middlewares": {}, "services": {}}
    for name in shown:
        kind, plain = router(name)
        raw.setdefault(proof.KINDS[kind], {})[plain] = {"status": "disabled" if name in disabled else "enabled"}
    return raw


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@dataclass
class ProofHost:
    """Traefik's files on a temporary root, as the proof reads them through the patched functions."""

    root: Path
    units: list[list[str]] = field(default_factory=list)
    stopped: list[str] = field(default_factory=list)
    identity_changes: int = 0
    euid: int = 0
    handlers: list[tuple[Any, ...]] = field(default_factory=list)

    def __post_init__(self) -> None:
        for directory in ("bin", "etc/dynamic/sub", "log", "proofs", "modes"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.proofs.chmod(0o700)  # as the proof creates it on a host
        self.config.write_text(STATIC.format(root=self.root, port=free_port()))
        (self.dynamic / "app.yml").write_text(APP)
        (self.dynamic / "extra.toml").write_text('[http.routers.extra]\n  rule = "Host(`x.test`)"\n  service = "s"\n')
        (self.dynamic / "sub" / "nested.yml").write_text("http:\n  routers:\n    nested:\n      service: s\n")
        (self.dynamic / "notes.txt").write_text("http:\n  routers:\n    ignored: {}\n")
        (self.dynamic / "acme.json").write_text("{}")
        (self.dynamic / "acme.json").chmod(0o600)
        self.set_mode("baseline", {"rawdata": rawdata(FILE_ROUTERS + INTERNAL_ROUTERS)})
        self.set_mode("candidate", {"rawdata": rawdata(FILE_ROUTERS + INTERNAL_ROUTERS)})
        self.binary.write_text(self.traefik(OLD, "baseline"))
        self.binary.chmod(0o755)
        self.archive(self.traefik(NEW, "candidate"))

    @property
    def binary(self) -> Path:
        return self.root / "bin" / "traefik"

    @property
    def config(self) -> Path:
        return self.root / "etc" / "traefik.toml"

    @property
    def dynamic(self) -> Path:
        return self.root / "etc" / "dynamic"

    @property
    def proofs(self) -> Path:
        return self.root / "proofs"

    def traefik(self, version: str, mode: str, arch: str | None = None) -> str:
        path = self.root / "modes" / f"{mode}.json"
        return TRAEFIK.format(python=sys.executable, version=version, arch=arch or native_arch(), mode=str(path))

    def set_mode(self, mode: str, value: dict[str, Any]) -> None:
        (self.root / "modes" / f"{mode}.json").write_text(json.dumps(value))

    def archive(self, executable: str) -> None:
        release_archive(self.root / "release.tar.gz", [("LICENSE.md", b"license\n"), ("traefik", executable.encode())])

    def policy(self) -> dict[str, Any]:
        return {
            "host": "fixture",
            "binary_path": str(self.binary),
            "config_path": str(self.config),
            "dynamic_path": str(self.dynamic),
            "acme_paths": [str(self.dynamic / "acme.json"), str(self.root / "absent-acme.json")],
        }

    def request(self) -> dict[str, Any]:
        archive = self.root / "release.tar.gz"
        return {
            "policy": self.policy(),
            "release": {"version": NEW, "sha256": sha256(archive.read_bytes())},
            "archive_path": str(archive),
        }

    def identity(self, policy: dict[str, Any]) -> dict[str, Any]:
        live = {
            "machine_id": MACHINE_ID,
            "binary_path": policy["binary_path"],
            "binary_sha256": sha256(Path(policy["binary_path"]).read_bytes()),
            "version": OLD,
            "config_path": policy["config_path"],
            "config_sha256": sha256(Path(policy["config_path"]).read_bytes()),
            "dynamic_sha256": engine.inventory_tree(Path(policy["dynamic_path"])),
            "unit_sha256": sha256(b"unit"),
        }
        if self.identity_changes and len(self.units) == 2:
            self.identity_changes -= 1
            live["unit_sha256"] = sha256(b"another unit")
        return live

    def run(self, argv: list[str], timeout: int = 30) -> str:
        """``engine.run``, except that ``systemd-run`` runs the unit's command line unisolated."""

        if argv[0] != "systemd-run":
            return real_run(argv, timeout)
        self.units.append(argv)
        command = argv[argv.index("--") + 1 :]
        assert command[:2] == ["/usr/bin/python3", "-I"]
        result = subprocess.run(
            [sys.executable, *command[1:]], capture_output=True, text=True, timeout=timeout, check=False
        )
        assert (result.returncode, result.stderr) == (0, "")
        return result.stdout

    @contextmanager
    def patched(self) -> Iterator[None]:
        with ExitStack() as stack:
            for target, name, value in [
                (proof, "PROOF_ROOT", RootOwnedPath(self.proofs)),
                (proof, "working_directory", lambda: self.root),
                (proof, "stop_units", self.stopped.append),
                (proof, "SETTLE", 0.6),
                (proof, "PATIENCE", 1.5),
                (proof, "DEADLINE", 20),
                (engine, "LOCK", self.root / "lock"),
                (engine, "validate_policy", lambda policy: None),
                (engine, "trusted_file", relaxed_trusted_file),
                (engine, "identity", self.identity),
                (engine, "run", self.run),
            ]:
                stack.enter_context(patch.object(target, name, value))
            stack.enter_context(patch("os.geteuid", new=lambda: self.euid))
            # main() installs SIGHUP/SIGTERM handlers; the test process keeps its own.
            stack.enter_context(patch("signal.signal", new=lambda *args: self.handlers.append(args)))
            yield

    def main(self, request: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        path = self.root / "request.json"
        path.write_text(json.dumps(self.request() if request is None else request))
        previous = os.umask(0o022)
        try:
            with self.patched(), patch("builtins.print") as printed:
                code = proof.main(["--request", str(path)])
        finally:
            os.umask(previous)
        (line,), _ = printed.call_args
        return code, json.loads(line)


real_run = engine.run


@pytest.fixture
def host(tmp_path: Path) -> ProofHost:
    previous = os.umask(0o022)
    try:
        return ProofHost(tmp_path.resolve())  # no symlink in the paths (macOS: /var -> /private/var)
    finally:
        os.umask(previous)


def today() -> str:
    return f"{datetime.datetime.now(datetime.UTC):%Y%m%d}"


# -- end to end ---------------------------------------------------------------------------


def test_a_compatible_candidate_passes_and_the_proof_is_written_once(host: ProofHost) -> None:
    code, printed = host.main()

    report = host.proofs / f"{NEW}-{today()}-fixture.json"
    assert code == 0
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert json.loads(report.read_text()) == printed
    assert tuple(printed)[: len(FORMAT_2026_09)] == FORMAT_2026_09
    with host.patched():
        live = host.identity(host.policy())
    assert printed["baseline"] == live
    assert {key: printed[key] for key in FORMAT_2026_09} == {
        "host": "fixture",
        "version": NEW,
        "architecture": os.uname().machine,
        "candidate_binary_sha256": sha256(host.traefik(NEW, "candidate").encode()),
        "live_config_sha256": live["config_sha256"],
        "router_count": 7,
        "disabled": [],
        "api_reachable": True,
        "isolation_override": "api.insecure=true only",
    }
    assert printed["passed"] is printed["baseline_pair_passed"] is printed["same_routers_as_baseline"] is True
    assert printed["baseline_pair"] == {
        "version": OLD,
        "binary_sha256": live["binary_sha256"],
        "router_count": 7,
        "disabled": [],
        "missing": [],
        "unexpected": [],
        "api_reachable": True,
    }
    assert printed["report_reference"] == str(report)
    assert printed["error"] is None
    assert sorted(path.name for path in host.proofs.iterdir()) == [report.name]  # work dir and temp file gone
    run_id = host.stopped[0]
    assert host.stopped == [run_id]
    assert [unit[5] for unit in host.units] == [f"--unit=traefik-proof-{run_id}-{v}" for v in ("baseline", "candidate")]

    code, again = host.main()

    assert code == 0
    assert again["report_reference"] == str(host.proofs / f"{NEW}-{today()}-fixture-2.json")
    assert report.read_text() == json.dumps(printed, indent=2) + "\n"


def test_the_units_get_copies_bound_over_the_live_paths(host: ProofHost) -> None:
    assert host.main()[0] == 0

    run_id = host.stopped[0]
    work = host.proofs / f".work-{run_id}"
    baseline, candidate = host.units
    assert baseline[-1] == str(work / "out-baseline" / "spec.json")
    assert candidate[-1] == str(work / "out-candidate" / "spec.json")
    assert baseline == proof.unit_argv(
        f"traefik-proof-{run_id}-baseline",
        work,
        work / "out-baseline" / "spec.json",
        {
            "BindReadOnlyPaths": [(work / "dynamic", host.dynamic)],
            "BindPaths": [(work / "acme-0", host.dynamic / "acme.json"), (work / "log-0", host.root / "log")],
        },
        host.root,
    )


def test_a_broken_route_fails_both_pairs(host: ProofHost) -> None:
    broken = rawdata(FILE_ROUTERS + INTERNAL_ROUTERS, disabled=("app-secure@file",))
    host.set_mode("baseline", {"rawdata": broken})
    host.set_mode("candidate", {"rawdata": broken})

    code, printed = host.main()

    assert code == 1
    assert printed["passed"] is printed["baseline_pair_passed"] is False
    assert printed["disabled"] == printed["baseline_pair"]["disabled"] == ["app-secure@file"]
    assert Path(printed["report_reference"]).is_file()


def test_routers_of_different_kinds_with_colliding_names_stay_apart(host: ProofHost) -> None:
    """An HTTP router named ``tcp:db`` is not the TCP router ``db``: neither hides the other's status."""

    (host.dynamic / "colliding.yml").write_text('http:\n  routers:\n    "tcp:db":\n      service: nowhere\n')
    shown = [*FILE_ROUTERS, "http:tcp:db@file", *INTERNAL_ROUTERS]
    host.set_mode("baseline", {"rawdata": rawdata(shown, disabled=("http:tcp:db@file",))})
    host.set_mode("candidate", {"rawdata": rawdata(shown, disabled=("http:tcp:db@file",))})

    code, printed = host.main()

    assert code == 1
    assert printed["disabled"] == printed["baseline_pair"]["disabled"] == ["http:tcp:db@file"]
    assert printed["router_count"] == 8
    assert printed["missing"] == printed["unexpected"] == []


def test_a_candidate_that_drops_a_route_fails_while_the_baseline_passes(host: ProofHost) -> None:
    host.set_mode("candidate", {"rawdata": rawdata([*FILE_ROUTERS[1:], *INTERNAL_ROUTERS])})

    code, printed = host.main()

    assert code == 1
    assert (printed["passed"], printed["baseline_pair_passed"], printed["same_routers_as_baseline"]) == (
        False,
        True,
        False,
    )
    assert printed["missing"] == ["app-http@file"]
    assert printed["router_count"] == 6


def test_an_undefined_file_router_fails(host: ProofHost) -> None:
    routers = [*FILE_ROUTERS, "udp:dns@file", *INTERNAL_ROUTERS]
    host.set_mode("baseline", {"rawdata": rawdata(routers)})
    host.set_mode("candidate", {"rawdata": rawdata(routers)})

    code, printed = host.main()

    assert code == 1
    assert printed["unexpected"] == printed["baseline_pair"]["unexpected"] == ["udp:dns@file"]


def test_different_internal_routers_fail(host: ProofHost) -> None:
    host.set_mode("candidate", {"rawdata": rawdata([*FILE_ROUTERS, "api@internal"])})

    code, printed = host.main()

    assert code == 1
    assert (printed["passed"], printed["baseline_pair_passed"], printed["same_routers_as_baseline"]) == (
        False,
        True,
        False,
    )
    assert printed["disabled"] == printed["missing"] == printed["unexpected"] == []


def test_a_candidate_that_does_not_start_fails(host: ProofHost) -> None:
    host.set_mode("candidate", {"exit": True})

    code, printed = host.main()

    assert code == 1
    assert (printed["api_reachable"], printed["router_count"], printed["passed"]) == (False, 0, False)
    assert printed["baseline_pair_passed"] is True


def test_a_live_change_during_the_proof_fails_it(host: ProofHost) -> None:
    host.identity_changes = 1

    code, printed = host.main()

    assert code == 1
    assert printed["error"] == "live identity changed during the proof"
    assert printed["passed"] is printed["baseline_pair_passed"] is False


def assert_refused(host: ProofHost, error: str, request: dict[str, Any] | None = None) -> None:
    assert host.main(request) == (2, {"failed": True, "error": error})
    assert sorted(path.name for path in host.proofs.iterdir()) == []
    assert host.units == []


def test_a_held_transaction_lock_refuses(host: ProofHost) -> None:
    with (host.root / "lock").open("a") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert_refused(host, "transaction lock held")


def test_an_archive_with_another_checksum_refuses(host: ProofHost) -> None:
    request = host.request()
    request["release"]["sha256"] = "0" * 64

    assert_refused(host, "release archive checksum mismatch", request)
    assert host.stopped != []  # the work directory was set up and is gone again


@pytest.mark.parametrize("arch", ["linux/s390x", "darwin/arm64"])
def test_a_candidate_for_another_platform_refuses(host: ProofHost, arch: str) -> None:
    host.archive(host.traefik(NEW, "candidate", arch=arch))

    assert_refused(host, f"not a native build for {os.uname().machine}: candidate")


def test_unreadable_dynamic_yaml_refuses(host: ProofHost) -> None:
    (host.dynamic / "flow.yml").write_text("http: {routers: {x: {service: s}}}\n")

    assert_refused(host, "unsupported YAML in flow.yml, line 1")


def test_a_dynamic_copy_that_differs_from_the_live_tree_refuses(host: ProofHost) -> None:
    copytree = shutil.copytree

    def changing_copy(source: Path, target: Path, *args: Any, **kwargs: Any) -> Any:
        copied = copytree(source, target, *args, **kwargs)
        if Path(target).name == "dynamic":
            (Path(target) / "late.yml").write_text("http: {}\n")
        return copied

    with patch("shutil.copytree", changing_copy):
        assert_refused(host, "dynamic copy differs")


def test_root_is_required(host: ProofHost) -> None:
    host.euid = 1000

    assert_refused(host, "root is required")
    assert not (host.root / "lock").exists()


def test_an_interrupt_cleans_up_and_refuses(host: ProofHost) -> None:
    def interrupt(*args: Any) -> dict[str, Any]:
        proof.interrupted(15, None)
        raise AssertionError("not reached")

    with patch.object(proof, "isolated_start", interrupt):
        assert_refused(host, "interrupted by signal 15")
    assert len(host.stopped) == 1


def test_work_left_by_an_interrupted_proof_is_removed_first(host: ProofHost) -> None:
    stale = host.proofs / ".work-0123456789ab"
    (stale / "dynamic").mkdir(parents=True)
    (host.proofs / ".tmp-left").write_text("partial")

    assert host.main()[0] == 0

    assert host.stopped[0] == "0123456789ab"
    assert not stale.exists()
    assert not (host.proofs / ".tmp-left").exists()


def test_main_installs_the_signal_handlers(host: ProofHost) -> None:
    host.main(request={"policy": {}})

    assert host.handlers == [(signal.SIGHUP, proof.interrupted), (signal.SIGTERM, proof.interrupted)]


def test_the_program_runs_standalone_next_to_the_engine(tmp_path: Path) -> None:
    """``python3 -I proof.py``: no package and no script directory on the path; it imports its neighbour."""

    request = tmp_path / "request.json"
    request.write_text(json.dumps({"policy": {"host": "Not Canonical"}, "release": {}}))

    result = subprocess.run(
        [sys.executable, "-I", str(PROOF_PATH), "--request", str(request)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=tmp_path,
    )

    assert (result.returncode, result.stderr) == (2, "")
    assert json.loads(result.stdout) == {"failed": True, "error": "invalid canonical host"}


# -- the parts ----------------------------------------------------------------------------


def test_the_proof_format_is_golden() -> None:
    """The record, byte for byte; the first nine keys are the 2026-09 format."""

    live = {
        "machine_id": MACHINE_ID,
        "binary_path": "/usr/local/bin/traefik",
        "binary_sha256": "b" * 64,
        "version": OLD,
        "config_path": "/etc/traefik/traefik.toml",
        "config_sha256": "c" * 64,
        "dynamic_sha256": "d" * 64,
        "unit_sha256": "e" * 64,
    }
    passed = proof.pair(
        {"api_reachable": True, "stable": True, "exited": None, "rawdata": rawdata(FILE_ROUTERS)}, routers(FILE_ROUTERS)
    )
    run = {
        "baseline": passed,
        "candidate": passed,
        "architecture": "x86_64",
        "candidate_binary_sha256": "a" * 64,
        "isolation_override": proof.OVERRIDE,
        "started_at": "2026-10-23T08:05:00+00:00",
        "finished_at": "2026-10-23T08:05:21+00:00",
        "report_reference": f"/var/lib/traefik-update-proofs/{NEW}-20261023-canary.json",
        "error": None,
    }

    record = proof.build_proof({"host": "canary"}, {"version": NEW}, live, run)

    assert json.dumps(record, indent=2) + "\n" == GOLDEN.read_text()
    assert tuple(record)[:9] == FORMAT_2026_09


def test_the_unit_isolates_network_and_file_system() -> None:
    work = Path("/var/lib/traefik-update-proofs/.work-0123456789ab")
    spec = work / "out-candidate" / "spec.json"
    mounts = {
        "BindReadOnlyPaths": [(work / "dynamic", Path("/etc/traefik/dynamic"))],
        "BindPaths": [(work / "acme-0", Path("/etc/traefik/acme.json")), (work / "log-0", Path("/var/log/traefik"))],
    }

    argv = proof.unit_argv("traefik-proof-0123456789ab-candidate", work, spec, mounts, Path("/"))

    assert argv == [
        "systemd-run",
        "--quiet",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--unit=traefik-proof-0123456789ab-candidate",
        *("-p", "PrivateNetwork=yes"),
        *("-p", "ProtectSystem=strict"),
        *("-p", "PrivateTmp=yes"),
        *("-p", "NoNewPrivileges=yes"),
        *("-p", "RuntimeMaxSec=150"),
        *("-p", "WorkingDirectory=/"),
        *("-p", f"ReadWritePaths={work}/out-candidate"),
        *("-p", f"BindReadOnlyPaths={work}/dynamic:/etc/traefik/dynamic"),
        *("-p", f"BindPaths={work}/acme-0:/etc/traefik/acme.json"),
        *("-p", f"BindPaths={work}/log-0:/var/log/traefik"),
        "--",
        "/usr/bin/python3",
        "-I",
        f"{work}/proof.py",
        "--inside",
        str(spec),
    ]


@pytest.mark.parametrize(
    ("text", "edited"),
    [
        ("[global]\n  checkNewVersion = true\n", "[global]\n  checkNewVersion = true\n\n[api]\n  insecure = true\n"),
        ("[log]\nlevel = 'INFO'", "[log]\nlevel = 'INFO'\n\n[api]\n  insecure = true\n"),
        ("[api] # dashboard\n  dashboard = true\n", "[api] # dashboard\n  insecure = true\n  dashboard = true\n"),
        ("[api]\n[api.x]\ny = 1\n", "[api]\n  insecure = true\n[api.x]\ny = 1\n"),
    ],
)
def test_the_isolation_override_adds_api_insecure_only(text: str, edited: str) -> None:
    assert proof.isolated_config(text) == (edited, proof.OVERRIDE)


def test_a_config_with_the_insecure_api_is_used_unchanged() -> None:
    assert proof.isolated_config("[api]\ninsecure = true\n") == ("[api]\ninsecure = true\n", None)


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("[api]\ninsecure = false\n", "unsupported api.insecure setting for the isolation override"),
        ("api = true\n", "unsupported api.insecure setting for the isolation override"),
        ("api.dashboard = true\n", "unsupported [api] table for the isolation override"),
        ("api = { dashboard = true }\n", "unsupported [api] table for the isolation override"),
        ('[api]\n[x]\ny = """\n[api]\n"""\n', "unsupported [api] table for the isolation override"),
        ("[x]\n[api.y]\nz = 1\n", "unsupported [api] table for the isolation override"),
        ('[api.x]\ny = 1\n[z]\ns = """\n[api]\n"""\n', "the isolation override must change api.insecure only"),
    ],
)
def test_an_override_that_is_not_certain_is_refused(text: str, error: str) -> None:
    with pytest.raises(engine.Refused, match=f"^{re.escape(error)}$"):
        proof.isolated_config(text)


@pytest.mark.parametrize(
    ("static", "url"),
    [
        ({}, "http://127.0.0.1:8080/api/rawdata"),
        ({"entryPoints": {"web": {"address": ":80"}}}, "http://127.0.0.1:8080/api/rawdata"),
        ({"entryPoints": {"traefik": {"address": "127.0.0.1:18090"}}}, "http://127.0.0.1:18090/api/rawdata"),
        ({"entryPoints": {"traefik": {"address": "[::1]:8080"}}}, "http://[::1]:8080/api/rawdata"),
        ({"entryPoints": {"traefik": {"address": "0.0.0.0:9000/tcp"}}}, "http://127.0.0.1:9000/api/rawdata"),
        (
            {"entryPoints": {"dns": {"address": ":53/udp"}}, "api": {"basePath": "/edge/"}},
            "http://127.0.0.1:8080/edge/api/rawdata",
        ),
        ({"entryPoints": {"traefik": {"address": "localhost:8081"}}}, "http://127.0.0.1:8081/api/rawdata"),
    ],
)
def test_the_api_answers_on_the_traefik_entrypoint(static: dict[str, Any], url: str) -> None:
    assert proof.api_url(static) == url


@pytest.mark.parametrize(
    ("static", "error"),
    [
        ({"entryPoints": {"web": {"address": "192.0.2.10:80"}}}, "entrypoint web listens on an address .*"),
        ({"entryPoints": {"web": {"address": "edge.example.test:80"}}}, "entrypoint web listens on an address .*"),
        ({"entryPoints": {"web": {}}}, "entrypoint without an address: web"),
        ({"entryPoints": {"web": {"address": ":http"}}}, "unsupported address of entrypoint web"),
        ({"entryPoints": {"web": {"address": ":0"}}}, "unsupported address of entrypoint web"),
        ({"entryPoints": {"web": ":80"}}, "unsupported entrypoint web"),
        ({"entryPoints": []}, "unsupported entryPoints"),
        ({"api": {"basePath": "edge"}}, "unsupported api.basePath"),
    ],
)
def test_entrypoints_an_empty_network_cannot_offer_are_refused(static: dict[str, Any], error: str) -> None:
    with pytest.raises(engine.Refused, match=f"^{error}$"):
        proof.api_url(static)


def test_log_directories_are_replaced(tmp_path: Path) -> None:
    (tmp_path / "log").mkdir()
    static = {"log": {"filePath": f"{tmp_path}/log/traefik.log"}, "accessLog": {"filePath": f"{tmp_path}/log/a.log"}}

    assert proof.log_dirs(static, [tmp_path / "dynamic"]) == [tmp_path / "log"]
    assert proof.log_dirs({"accessLog": {"format": "json"}, "log": {"level": "INFO"}}, []) == []


@pytest.mark.parametrize(
    ("path", "error"),
    [
        ("traefik.log", "unsupported log.filePath"),
        ("/var/log/../traefik.log", "unsupported log.filePath"),
        ("/var/log/traefik log", "unsupported log.filePath"),
        ("{root}/absent/traefik.log", "log.filePath directory is absent"),
        ("/traefik.log", "log.filePath directory would hide configuration"),
        ("{root}/traefik.log", "log.filePath directory would hide configuration"),
        ("{root}/dynamic/traefik.log", "log.filePath directory would hide configuration"),
    ],
)
def test_log_directories_that_cannot_be_replaced_are_refused(tmp_path: Path, path: str, error: str) -> None:
    (tmp_path / "dynamic").mkdir()
    with pytest.raises(engine.Refused, match=f"^{error}$"):
        proof.log_dirs({"log": {"filePath": path.format(root=tmp_path)}}, [tmp_path / "dynamic"])


def test_acme_stores_are_the_approved_existing_ones(tmp_path: Path) -> None:
    tmp_path = tmp_path.resolve()
    (tmp_path / "acme.json").write_text("{}")
    (tmp_path / "other.json").write_text("{}")
    static = {
        "certificatesResolvers": {
            "letsencrypt": {"acme": {"storage": str(tmp_path / "other.json")}},
            "fallback": {"acme": {"httpChallenge": {"entryPoint": "web"}}},
            "tailscale": {"tailscale": {}},
        }
    }
    policy = {"acme_paths": [str(tmp_path / "other.json"), str(tmp_path / "acme.json"), str(tmp_path / "new.json")]}

    assert proof.acme_stores(static, policy, tmp_path) == [tmp_path / "other.json", tmp_path / "acme.json"]
    assert proof.acme_stores({}, {}, tmp_path) == []


@pytest.mark.parametrize(
    ("storage", "approved", "error"),
    [
        (
            "{root}/elsewhere.json",
            ["{root}/acme.json"],
            "ACME store of resolver le is not an approved acme_paths entry",
        ),
        (None, ["/acme.json"], "ACME store of resolver le is not an approved acme_paths entry"),
        ("{root}/acme.json", ["{root}/dir"], "ACME store of resolver le is not an approved acme_paths entry"),
        ("{root}/dir", ["{root}/dir"], "ACME store is not a file: {root}/dir"),
        ("{root}/acme.json", ["relative.json"], "unsupported acme_paths entry"),
    ],
)
def test_acme_stores_outside_the_policy_are_refused(
    tmp_path: Path, storage: str | None, approved: list[str], error: str
) -> None:
    tmp_path = tmp_path.resolve()
    (tmp_path / "dir").mkdir()
    acme = {} if storage is None else {"storage": storage.format(root=tmp_path)}
    static = {"certificatesResolvers": {"le": {"acme": acme}}}
    policy = {"acme_paths": [path.format(root=tmp_path) for path in approved]}

    with pytest.raises(engine.Refused, match=f"^{error.format(root=tmp_path)}$"):
        proof.acme_stores(static, policy, tmp_path)


@pytest.mark.parametrize("link", ["directory", "leaf", "dangling leaf"])
def test_an_acme_store_path_through_a_symlink_is_refused(tmp_path: Path, link: str) -> None:
    root = tmp_path.resolve()
    (root / "real").mkdir()
    (root / "real" / "acme.json").write_text("{}")
    if link == "directory":
        (root / "link").symlink_to(root / "real")
        store = root / "link" / "absent.json"
    else:
        store = root / "acme.json"
        store.symlink_to(root / "real" / ("acme.json" if link == "leaf" else "absent.json"))

    with pytest.raises(engine.Refused, match=f"^ACME store path is not canonical: {re.escape(str(store))}$"):
        proof.acme_stores({}, {"acme_paths": [str(store)]}, root)


def test_routers_are_shown_with_their_kind_when_needed() -> None:
    assert [proof.qualified(r) for r in [("http", "a@file"), ("tcp", "a@file"), ("udp", "a@file")]] == [
        "a@file",
        "tcp:a@file",
        "udp:a@file",
    ]
    assert proof.qualified(("http", "tcp:a@file")) == "http:tcp:a@file"


@pytest.mark.parametrize("store", ["/dev/shm/acme.json", "/proc/acme.json", "/sys/fs/acme.json"])
def test_an_absent_store_where_the_unit_could_write_is_refused(tmp_path: Path, store: str) -> None:
    with pytest.raises(engine.Refused, match=f"^absent ACME store would be writable in the unit: {re.escape(store)}$"):
        proof.acme_stores({}, {"acme_paths": [store]}, tmp_path)


def yaml_reference(text: str) -> set[tuple[str, str]]:
    """Router names as a YAML parser reads them."""

    data = yaml.safe_load(text) or {}
    return {(kind, f"{name}@file") for kind in proof.KINDS for name in ((data.get(kind) or {}).get("routers") or {})}


ROUTES = [
    TraefikRoute(name="plain", host="plain.example.test", app_port=8000),
    TraefikRoute(name="titled", host="t.example.test", app_port=8001, title="Titled (fixture)", cert_resolver="le"),
    TraefikRoute(
        name="guarded",
        host="g.example.test",
        app_port=8002,
        basic_auth=BasicAuth(user="admin", password=SecretStr("fixture")),
        middlewares=("extra@file",),
        redirect=RedirectRegex(regex="^https://g.example.test/old(.*)", replacement="https://g.example.test/new$1"),
        health_check=HealthCheck(path="/health"),
    ),
    TraefikRoute(name="inside", host="i.example.test", app_port=8003, internal_only=True, frame_options="SAMEORIGIN"),
]


@pytest.mark.parametrize("route", ROUTES, ids=lambda route: route.name)
def test_the_router_scanner_reads_every_route_ops_deploy_renders(route: TraefikRoute) -> None:
    text = render_route(route, "$2y$05$" + "a" * 53 if route.basic_auth else None)

    assert proof.yaml_routers(text, "route.yml") == yaml_reference(text) != set()


SCANNED = [
    APP,
    "---\nhttp:\n  routers: {}\n",
    "# only middlewares\nhttp:\n  middlewares:\n    m:\n      headers: {}\n",
    'tcp:\n    routers:\n        "quoted": {rule: "HostSNI(`*`)", service: s}\n'
    "        'single':\n          service: s\n",
    "http:\n  routers:\n    a:\n      rule: |\n        Host(`x`)\n        routers:\n      service: s\n    b: {}\n",
    "http:\n  services:\n    s:\n      note: >\n        routers:\n          fake: {}\n"
    "  routers:\n    real:\n      service: s\n",
    "x-defaults: &defaults\n  service: s\nhttp:\n  routers:\n    r:\n      <<: *defaults\n      rule: x\n",
    "udp:\n  routers:\n    dns:  # comment\n      entryPoints:\n      - dns\n      service: s\n",
    "http:\n  routers:\n    r1:\n      service: s\nhttp_extra:\n  routers:\n    not-a-router: {}\n",
    "tls:\n  options:\n    default:\n      minVersion: VersionTLS12\n",
    "",
]


@pytest.mark.parametrize("text", SCANNED)
def test_the_router_scanner_agrees_with_a_yaml_parser(text: str) -> None:
    assert proof.yaml_routers(text, "file.yml") == yaml_reference(text)


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("http: {routers: {x: {}}}\n", 1),
        ("http:\n  routers: &r\n    x: {}\n", 2),
        ("http:\n  routers:\n    <<: *r\n", 3),
        ("http:\n  routers:\n  - x\n", 3),
        ("http:\n\trouters: {}\n", 2),
        ("http:\n  routers:\n    x: {}\n---\nhttp: {}\n", 4),
        ("http:\n  routers:\n    x:{}\n", 3),
        ("? http\n: {}\n", 1),
        ("http: |\n  routers:\n", 1),
        ("http:\n  routers: !!map\n", 2),
        ("{{ if true }}\nhttp: {}\n", 1),
    ],
)
def test_yaml_the_scanner_cannot_read_for_sure_is_refused(text: str, line: int) -> None:
    with pytest.raises(engine.Refused, match=f"^unsupported YAML in x.yml, line {line}$"):
        proof.yaml_routers(text, "x.yml")


def test_defined_routers_come_from_every_dynamic_file_below_the_directory(host: ProofHost) -> None:
    (host.dynamic / "UPPER.YML").write_text("http:\n  routers:\n    loud: {}\n")
    (host.dynamic / "udp.toml").write_text("[udp.routers.dns]\nservice = 's'\n[tcp]\nx = 1\n")

    assert proof.defined_routers(host.dynamic) == routers([*FILE_ROUTERS, "loud@file", "udp:dns@file"])


def test_toml_routers_that_are_not_a_table_are_refused(tmp_path: Path) -> None:
    (tmp_path / "bad.toml").write_text("[http]\nrouters = 1\n")

    with pytest.raises(engine.Refused, match=r"^unsupported routers in bad\.toml$"):
        proof.defined_routers(tmp_path)


def test_a_pair_passes_only_when_settled_running_and_complete() -> None:
    raw = rawdata(FILE_ROUTERS + INTERNAL_ROUTERS)
    good = {"api_reachable": True, "stable": True, "exited": None, "rawdata": raw}
    expected = routers(FILE_ROUTERS)

    assert proof.pair(good, expected)["passed"] is True
    for change in ({"stable": False}, {"exited": 1}, {"api_reachable": False}, {"rawdata": rawdata(INTERNAL_ROUTERS)}):
        assert proof.pair({**good, **change}, expected)["passed"] is False
    assert proof.pair({**good, "rawdata": rawdata(INTERNAL_ROUTERS)}, set())["passed"] is False  # no file router
    raw["routers"]["app-http@file"]["status"] = "warning"
    assert proof.pair(good, expected)["disabled"] == ["app-http@file"]


class Answers(http.server.BaseHTTPRequestHandler):
    """Serves ``answers`` in turn (the last one repeats), as Traefik loading its providers would."""

    answers: ClassVar[list[dict[str, Any]]] = []
    served: ClassVar[int] = 0

    def do_GET(self) -> None:
        body = json.dumps(self.answers[min(type(self).served, len(self.answers) - 1)]).encode()
        type(self).served += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


class Running:
    """A process that keeps running."""

    returncode = None

    def poll(self) -> None:
        return None


@contextmanager
def serving(answers: list[dict[str, Any]]) -> Iterator[str]:
    Answers.answers, Answers.served = answers, 0
    server = http.server.HTTPServer(("127.0.0.1", 0), Answers)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/rawdata"
    finally:
        server.shutdown()
        server.server_close()


def observe(url: str, expected: list[str]) -> tuple[dict[str, Any], float]:
    spec = {
        "api": url,
        "expected": [list(r) for r in sorted(routers(expected))],
        "deadline": 20,
        "settle": 1.2,
        "patience": 3,
    }
    started = time.monotonic()
    result = proof.observe(Running(), spec)  # type: ignore[arg-type]
    return result, time.monotonic() - started


def test_observation_waits_until_the_routers_settle() -> None:
    loading, loaded = rawdata(INTERNAL_ROUTERS), rawdata(FILE_ROUTERS + INTERNAL_ROUTERS)
    with serving([loading, loading, loaded]) as url:
        result, took = observe(url, FILE_ROUTERS)

    assert result == {"api_reachable": True, "stable": True, "exited": None, "rawdata": loaded}
    assert took >= 1.2 + 1.0  # two polls before the routers arrived, then the settle time


def test_observation_waits_longer_for_defined_routers_then_gives_up_waiting() -> None:
    partial = rawdata([*FILE_ROUTERS[1:], *INTERNAL_ROUTERS])
    with serving([partial]) as url:
        result, took = observe(url, FILE_ROUTERS)

    assert result == {"api_reachable": True, "stable": True, "exited": None, "rawdata": partial}
    assert took >= 3


def test_observation_reports_a_traefik_that_exits_or_never_answers() -> None:
    class Exited:
        returncode = 3

        def poll(self) -> int:
            return 3

    spec = {"api": "http://127.0.0.1:9/api/rawdata", "expected": [], "deadline": 1.2, "settle": 1, "patience": 1}
    assert proof.observe(Exited(), spec) == {  # type: ignore[arg-type]
        "api_reachable": False,
        "stable": False,
        "exited": 3,
        "rawdata": None,
    }
    assert proof.observe(Running(), spec) == {  # type: ignore[arg-type]
        "api_reachable": False,
        "stable": False,
        "exited": None,
        "rawdata": None,
    }


def test_compatibility_is_the_engines_block_for_this_identity() -> None:
    record = json.loads(GOLDEN.read_text())
    live = record["baseline"]

    assert proof.compatibility(record, live) == {
        "baseline": live,
        "architecture": "x86_64",
        "candidate_binary_sha256": "a" * 64,
        "candidate_config_sha256": "c" * 64,
        "passed": True,
        "baseline_pair_passed": True,
        "report_reference": record["report_reference"],
    }
    with pytest.raises(engine.Refused, match=r"^compatibility proof is for another live identity$"):
        proof.compatibility(record, {**live, "dynamic_sha256": "f" * 64})
    for key in ("passed", "baseline_pair_passed"):
        with pytest.raises(engine.Refused, match=r"^compatibility proof failed$"):
            proof.compatibility({**record, key: False}, live)


def test_the_engine_accepts_the_compatibility_of_a_passed_proof(tmp_path: Path) -> None:
    def from_proof(setup: Any) -> None:
        request = setup.request
        live = request["compatibility"]["baseline"]
        tested = proof.pair(
            {"api_reachable": True, "stable": True, "exited": None, "rawdata": rawdata(FILE_ROUTERS)},
            routers(FILE_ROUTERS),
        )
        run = {
            "baseline": tested,
            "candidate": tested,
            "architecture": os.uname().machine,
            "candidate_binary_sha256": request["compatibility"]["candidate_binary_sha256"],
            "isolation_override": None,
            "started_at": "",
            "finished_at": "",
            "report_reference": "/var/lib/traefik-update-proofs/fixture.json",
            "error": None,
        }
        record = proof.build_proof(request["policy"], request["release"], live, run)
        request["compatibility"] = proof.compatibility(record, live)

    outcome = run_scenario(engine, tmp_path / "host", from_proof, "binary")

    assert outcome.error is None
    assert outcome.result is not None
    assert outcome.result["changed"] is True
    assert outcome.saved["phase"] == "clear"
    assert outcome.saved["identity"]["version"] == NEW


def test_proof_uses_the_standard_library_and_its_neighbouring_engine_only() -> None:
    tree = ast.parse(PROOF_PATH.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                assert (node.level, node.module, [alias.name for alias in node.names]) == (1, None, ["engine"])
                continue
            assert node.module is not None
            imported.add(node.module.partition(".")[0])

    assert imported - {"__future__", "engine"} <= sys.stdlib_module_names
    ast.parse(PROOF_PATH.read_text(), feature_version=(3, 11))


def test_proofs_go_where_the_earlier_ones_are() -> None:
    assert Path("/var/lib/traefik-update-proofs") == proof.PROOF_ROOT
    # The fixture's static config has an [api] table without insecure, like the role renders it.
    assert tomllib.loads(STATIC.format(root="/r", port=1))["api"] == {"dashboard": True}
