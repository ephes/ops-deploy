"""Traefik health probes: validation, capture/verify over a runner, the pyinfra install, role parity.

The probe program is ops-library's ``traefik_health_probe.py`` byte for byte
(``test_ops_library_drift`` checks it against ``OPS_LIBRARY_PATH``; the pinned
digest below is the file at ops-library ``3110a0f1``). Capture runs for real
here against a local HTTP server, with ``/usr/bin/python3`` replaced by this
interpreter; the install and verification run on the lima VM in
``tests/smoke/test_traefik_probes_smoke.py``.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import traceback
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, SubprocessRunner
from ops_deploy.infra import (
    ProbeBaseline,
    ProbeError,
    ProbeSpec,
    TraefikHealthProbesConfig,
    capture_traefik_health_probes,
    deploy_traefik_health_probes,
    verify_traefik_health_probes,
)
from ops_deploy.infra.traefik_probes import (
    CAPTURE_PREFIX,
    CHECKS_PATH,
    PROBE_DIR,
    PROGRAM,
    PROGRAM_PATH,
    PROGRAM_SHA256,
    PYTHON,
    VERIFY_SCRIPT,
    capture_script,
    config_json,
    probe_commands,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

PARITY = Path(__file__).parent / "parity" / "traefik_deploy"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
# sha256 of roles/traefik_deploy/files/traefik_health_probe.py at ops-library 3110a0f1.
OPS_LIBRARY_3110A0F1_PROGRAM = "f1f826dd121cc24a5b8f5881402de5f31a020c5b367f1e9a5dd192f333f27377"
SPEC = ProbeSpec.model_validate(
    {
        "probes": [{"host": "app.example.org", "scheme": "https", "port": 443, "address": "192.0.2.10"}],
        "entrypoints": ["web", "web-secure"],
    }
)


def baseline_input() -> dict[str, Any]:
    config: dict[str, Any] = json.loads((PARITY / "baseline-input.json").read_text())["traefik_health_probe_config"]
    return config


BASELINE = ProbeBaseline.model_validate(baseline_input())


# The program ------------------------------------------------------------------------------------


def test_program_is_ops_library_3110a0f1_byte_for_byte() -> None:
    assert PROGRAM_SHA256 == OPS_LIBRARY_3110A0F1_PROGRAM


def run_program(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", PROGRAM.decode(), *args], capture_output=True, text=True, timeout=60, check=False
    )


@pytest.mark.parametrize("probes", [[], None, "x"])
def test_program_refuses_an_empty_probe_list(tmp_path: Path, probes: object) -> None:
    config = tmp_path / "checks.json"
    config.write_text(json.dumps({"probes": probes, "entrypoints": ["web"]}))
    for mode in ("capture", "health", "cleanup"):
        result = run_program(mode, str(config))
        assert result.returncode != 0
        assert "At least one explicit ingress probe is required" in result.stderr


# Validation -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"probes": []}, "at least 1 item"),
        ({"entrypoints": []}, "at least 1 item"),
        ({"probes": [{"host": "a.example", "scheme": "ftp", "port": 21, "address": "192.0.2.1"}]}, "scheme"),
        ({"probes": [{"host": "a.example", "scheme": "http", "port": "80", "address": "192.0.2.1"}]}, "port"),
        ({"probes": [{"host": "a.example", "scheme": "http", "port": 0, "address": "192.0.2.1"}]}, "port"),
        ({"probes": [{"host": "a b", "scheme": "http", "port": 80, "address": "192.0.2.1"}]}, "host"),
        ({"probes": [{"host": "a.example", "scheme": "http", "port": 80, "address": "192.0.2.1", "pth": "/"}]}, "pth"),
        ({"probes": [{"host": "a.ex", "scheme": "http", "port": 80, "address": "192.0.2.1", "path": "no"}]}, "path"),
        ({"probes": [{"host": "a.ex", "scheme": "http", "port": 80, "address": "192.0.2.1", "path": None}]}, "path"),
        ({"probes": [{"host": "a.example", "scheme": "http", "port": 80, "address": "localhost"}]}, "IP address"),
        ({"probes": [{"host": "a.example", "scheme": "http", "port": 80, "address": "[2001:db8::1]"}]}, "IP address"),
        ({"probes": [{"host": "a.example", "scheme": "http", "port": 80, "address": "fe80::1%eth0"}]}, "zone"),
        ({"tls_fingerprints": None}, "tls_fingerprints"),
        ({"tls_fingerprint": True}, "tls_fingerprint"),
        ({"tls_fingerprints": "yes"}, "tls_fingerprints"),
        ({"observations": [{"status": "200", "exit": 0}]}, "observations"),
        ({"dynamic": {}}, "dynamic"),
    ],
)
def test_spec_refuses(change: dict[str, Any], message: str) -> None:
    data = {**SPEC.model_dump(exclude_unset=True), **change}
    with pytest.raises(ValidationError, match=message):
        ProbeSpec.model_validate(data)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"probes": []}, "at least 1 item"),
        ({"observations": []}, "one to one"),
        ({"dynamic": {"a.yml": "nothex"}}, "dynamic"),
        ({"dynamic": []}, "dynamic"),
        (
            {"observations": [{"status": "200", "exit": 0}, {"status": "308", "exit": 0}, {"status": "", "exit": 28}]},
            "TLS",
        ),
        ({"observations": [{"status": "200", "exit": 0, "x": 1}] * 3}, "x"),
    ],
)
def test_baseline_refuses(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ProbeBaseline.model_validate({**baseline_input(), **change})


def test_validation_errors_do_not_echo_private_values() -> None:
    data = {**baseline_input(), "observations": []}
    with pytest.raises(ValidationError) as caught:
        ProbeBaseline.model_validate(data)
    assert "192.0.2.10" not in str(caught.value)
    assert "app.example.org" not in str(caught.value)


def test_missing_fingerprints_are_fine_without_tls_fingerprints() -> None:
    data = {**baseline_input(), "tls_fingerprints": False}
    data["observations"] = [{"status": "200", "exit": 0}, {"status": "308", "exit": 0}, {"status": "", "exit": 28}]
    assert ProbeBaseline.model_validate(data).tls_fingerprints is False


# Parity with the role ---------------------------------------------------------------------------


def test_checks_json_is_what_the_role_writes() -> None:
    """``checks.json`` is byte-identical to the role's ``to_nice_json`` copy.

    ``tests/parity/traefik_deploy/checks.json`` was written by ansible-core
    2.19.0's ``copy`` with ``content: '{{ traefik_health_probe_config | to_nice_json }}'``
    (the role's task) from ``baseline-input.json``. Absent keys (``path``,
    ``tls_error``) stay absent and non-ASCII file names are escaped.
    """

    assert config_json(BASELINE).encode() == (PARITY / "checks.json").read_bytes()
    assert ProbeBaseline.model_validate_json((PARITY / "checks.json").read_bytes()) == BASELINE


def test_probe_commands_are_the_roles() -> None:
    commands = probe_commands().as_request()

    assert list(commands) == [
        "baseline_probe",
        "acceptance_probe",
        "alias_acceptance_probe",
        "metrics_bind_acceptance_probe",
        "cleanup_probe",
    ]
    modes = {key: value["argv"] for key, value in commands.items()}
    assert modes["baseline_probe"] == [PROGRAM_PATH, "health", CHECKS_PATH]
    assert modes["alias_acceptance_probe"] == [PROGRAM_PATH, "alias", CHECKS_PATH]
    assert modes["metrics_bind_acceptance_probe"] == [PROGRAM_PATH, "metrics_bind", CHECKS_PATH]
    assert modes["cleanup_probe"] == [PROGRAM_PATH, "cleanup", CHECKS_PATH]
    assert {value["sha256"] for value in commands.values()} == {PROGRAM_SHA256}


def role_tasks(name: str) -> list[dict[str, Any]]:
    assert OPS_LIBRARY is not None
    tasks: list[dict[str, Any]] = yaml.safe_load(Path(OPS_LIBRARY, "roles/traefik_deploy/tasks", name).read_text())
    return tasks


def task(tasks: list[dict[str, Any]], suffix: str) -> dict[str, Any]:
    found = [t for t in tasks if t["name"].endswith(suffix)]
    assert len(found) == 1, suffix
    return found[0]


@needs_ops_library
def test_install_paths_modes_and_commands_match_the_role() -> None:
    tasks = role_tasks("health_probe.yml")

    directory = task(tasks, "Create private probe directory")["ansible.builtin.file"]
    assert (directory["path"], directory["mode"], directory["owner"]) == (PROBE_DIR, "0700", "root")
    program = task(tasks, "Install read-only acceptance program")["ansible.builtin.copy"]
    assert (program["src"], program["dest"], program["mode"]) == ("traefik_health_probe.py", PROGRAM_PATH, "0755")
    checks = task(tasks, "Install captured private acceptance baseline")["ansible.builtin.copy"]
    assert (checks["dest"], checks["mode"]) == (CHECKS_PATH, "0600")
    assert checks["content"] == "{{ traefik_health_probe_config | to_nice_json }}"
    verify = task(tasks, "Verify the captured baseline against live ingress")["ansible.builtin.command"]["argv"]
    assert verify == [PYTHON, PROGRAM_PATH, "health", CHECKS_PATH]
    returned = task(tasks, "Supply transaction probe commands")["ansible.builtin.set_fact"]
    role_commands = returned["traefik_health_probe_commands"]
    ours = probe_commands().as_request()
    assert list(role_commands) == list(ours)
    assert {key: value["argv"] for key, value in role_commands.items()} == {
        key: value["argv"] for key, value in ours.items()
    }
    python = task(tasks, "Check the explicitly pinned probe interpreter")["ansible.builtin.raw"]
    assert python.startswith(f"{PYTHON} -c ")
    assert "(3, 11)" in python


@needs_ops_library
def test_capture_matches_the_role() -> None:
    tasks = role_tasks("health_probe_capture.yml")

    guard = task(tasks, "Require an explicit probe specification")["ansible.builtin.assert"]["that"]
    assert "traefik_health_probe_spec.observations is not defined" in guard
    assert "traefik_health_probe_spec.dynamic is not defined" in guard
    tempdir = task(tasks, "Create private temporary capture directory")["ansible.builtin.tempfile"]
    assert tempdir["prefix"] == CAPTURE_PREFIX
    block = task(tasks, "Capture the live ingress baseline")
    program = task(block["block"], "Copy probe program")["ansible.builtin.copy"]
    spec = task(block["block"], "Write private probe specification")["ansible.builtin.copy"]
    run = task(block["block"], "Run read-only capture")["ansible.builtin.command"]["argv"]
    assert (program["mode"], spec["mode"]) == ("0700", "0600")
    assert spec["content"] == "{{ traefik_health_probe_spec | to_nice_json }}"
    assert run[0] == PYTHON
    assert run[2] == "capture"
    script = capture_script(SPEC)
    assert 'chmod 0700 "$dir/health.py"' in script
    assert 'chmod 0600 "$dir/spec.json"' in script
    assert f'{PYTHON} "$dir/health.py" capture "$dir/spec.json"' in script
    merged = task(block["block"], "Return the merged probe configuration")["ansible.builtin.set_fact"]
    assert "combine(traefik_health_probe_capture_run.stdout | from_json)" in merged["traefik_health_probe_captured"]


# Capture ----------------------------------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200 if self.path == "/" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def web() -> Iterator[int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


needs_curl = pytest.mark.skipif(not shutil.which("curl") or not shutil.which("base64"), reason="needs curl and base64")


class LocalRunner:
    """Runs the scripts with local bash, ``/usr/bin/python3`` swapped for this interpreter."""

    def __init__(self, tmpdir: Path) -> None:
        self.tmpdir = tmpdir
        self.runner = SubprocessRunner(env={"PATH": os.environ["PATH"], "TMPDIR": str(tmpdir)})

    def __call__(self, script: str, args: Sequence[str], timeout: float) -> CommandResult:
        return self.runner(script.replace(PYTHON, sys.executable), args, timeout)


@needs_curl
def test_capture_observes_live_ingress_and_removes_its_directory(tmp_path: Path, web: int) -> None:
    spec = ProbeSpec.model_validate(
        {
            "probes": [
                {"host": "localhost", "scheme": "http", "port": web, "address": "127.0.0.1"},
                {"host": "localhost", "scheme": "http", "port": web, "address": "127.0.0.1", "path": "/missing"},
            ],
            "entrypoints": ["web"],
        }
    )

    baseline = capture_traefik_health_probes(LocalRunner(tmp_path), spec)

    assert [(o.status, o.exit) for o in baseline.observations] == [("200", 0), ("404", 0)]
    assert baseline.probes == spec.probes
    assert baseline.entrypoints == spec.entrypoints
    assert "tls_fingerprints" not in baseline.model_fields_set
    assert "path" not in json.loads(config_json(baseline))["probes"][0]
    assert list(tmp_path.iterdir()) == []


@needs_curl
def test_captured_baseline_passes_health(tmp_path: Path, web: int) -> None:
    spec = ProbeSpec.model_validate(
        {"probes": [{"host": "localhost", "scheme": "http", "port": web, "address": "127.0.0.1"}], "entrypoints": ["w"]}
    )
    baseline = capture_traefik_health_probes(LocalRunner(tmp_path), spec)
    checks = tmp_path / "checks.json"
    checks.write_text(config_json(baseline))

    result = run_program("health", str(checks))

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"ingress_checks": 1, "baseline_preserved": True}


@needs_curl
def test_capture_passes_on_no_program_output(tmp_path: Path) -> None:
    """A failing program's output (it can name hosts) never leaves the host."""

    class Failing(LocalRunner):
        def __call__(self, script: str, args: Sequence[str], timeout: float) -> CommandResult:
            failing = "raise RuntimeError('Ingress changed for: secret.example')"
            script = script.replace(f'{PYTHON} "$dir/health.py" capture', f'{PYTHON} -c "{failing}" capture')
            return super().__call__(script, args, timeout)

    with pytest.raises(ProbeError, match=r"^capture: capture failed$"):
        capture_traefik_health_probes(Failing(tmp_path), SPEC)
    assert list(tmp_path.iterdir()) == []


def test_capture_refuses_a_baseline_before_running() -> None:
    def runner(script: str, args: Sequence[str], timeout: float) -> CommandResult:
        raise AssertionError("must not run")

    with pytest.raises(ProbeError, match="without observations"):
        capture_traefik_health_probes(runner, BASELINE)


def test_capture_script_embeds_program_and_spec() -> None:
    script = capture_script(SPEC)

    assert "set -euo pipefail" in script
    assert "trap 'rm -rf -- \"$dir\"' EXIT" in script
    assert "app.example.org" not in script  # base64 only
    assert subprocess.run(["bash", "-n"], input=script, text=True, check=False).returncode == 0


def fixed(result: CommandResult | Exception) -> Any:
    calls: list[tuple[str, list[str]]] = []

    def runner(script: str, args: Sequence[str], timeout: float) -> CommandResult:
        calls.append((script, list(args)))
        if isinstance(result, Exception):
            raise result
        return result

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (CommandResult(1, "", "traefik probes: /usr/bin/python3 3.11 or newer is required\n"), "3.11 or newer"),
        (CommandResult(1, "", "traefik probes: no probes\n"), "capture: no probes$"),
        (CommandResult(1, "", "Traceback ...\nKeyError: 192.0.2.10\n"), r"capture: failed \(exit 1\)$"),
        (CommandResult(0, "not json", ""), "unusable result"),
        (CommandResult(0, '{"observations": [], "dynamic": {}}', ""), "unusable result"),
        (CommandResult(0, '{"observations": [{"status": "200", "exit": 0}], "dynamic": {}, "x": 1}', ""), "unusable"),
        (RemoteCommandError("ssh 192.0.2.10: no result within 300s; stopped"), "no result"),
    ],
)
def test_capture_failures(result: CommandResult | Exception, message: str) -> None:
    with pytest.raises(ProbeError, match=message) as caught:
        capture_traefik_health_probes(fixed(result), SPEC)
    assert "192.0.2.10" not in "".join(traceback.format_exception(caught.value))


# Verify -----------------------------------------------------------------------------------------


def test_verify_returns_the_commands_for_the_installed_program() -> None:
    runner = fixed(CommandResult(0, PROGRAM_SHA256 + "\n", '{"ingress_checks": 1, "baseline_preserved": true}\n'))

    assert verify_traefik_health_probes(runner) == probe_commands()
    assert runner.calls == [(VERIFY_SCRIPT, [PROGRAM_SHA256])]


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (
            CommandResult(1, "", "traefik probes: /var/lib/traefik-update-probes/health.py is not owned by root\n"),
            "root",
        ),
        (CommandResult(1, "", "traefik probes: ingress changed\n"), "verify: ingress changed$"),
        (CommandResult(1, "", "RuntimeError: Ingress changed for: a.example\n"), r"verify: failed \(exit 1\)$"),
        (CommandResult(0, "0" * 64 + "\n", ""), "could not be confirmed"),
        (RemoteCommandError("cannot run ssh a.example"), "no result"),
    ],
)
def test_verify_failures(result: CommandResult | Exception, message: str) -> None:
    with pytest.raises(ProbeError, match=message) as caught:
        verify_traefik_health_probes(fixed(result))
    assert "a.example" not in "".join(traceback.format_exception(caught.value))


def test_verify_script_reports_fixed_reasons_only() -> None:
    """The program's own failure output names hosts; the script passes on a class of it."""

    assert '"$program" health "$checks" 2>&1' in VERIFY_SCRIPT
    for marker in ("Permanent routing changed", "Ingress changed for", "Missing captured TLS fingerprint baseline"):
        assert marker in PROGRAM.decode()
        assert f'*"{marker}"*) fail' in VERIFY_SCRIPT
    assert '*) fail "health check failed" ;;' in VERIFY_SCRIPT


def test_verify_script_is_bash_without_backslashes() -> None:
    assert "\\" not in VERIFY_SCRIPT
    assert subprocess.run(["bash", "-n"], input=VERIFY_SCRIPT, text=True, check=False).returncode == 0


# pyinfra install --------------------------------------------------------------------------------

CFG = TraefikHealthProbesConfig(baseline=BASELINE)
PYTHON_OK = {f"{PYTHON} -c": ["True"]}


def test_deploy_installs_program_and_private_baseline() -> None:
    result = run_deploy_fake(deploy_traefik_health_probes, CFG, responses={**LINUX, **PYTHON_OK})

    assert result.succeeded, result.error
    assert result.upload(PROGRAM_PATH) == PROGRAM
    assert result.written(CHECKS_PATH) == (PARITY / "checks.json").read_bytes()
    text = result.all_text()
    assert "192.0.2.10" not in text
    assert "app.example.org" not in text
    assert [op.name for op in result.ops] == [
        f"Traefik health probes | Ensure {PROBE_DIR}",
        f"Traefik health probes | Clear special mode bits on {PROBE_DIR}",
        "Traefik health probes | Install the read-only acceptance program",
        "Traefik health probes | Install the captured private acceptance baseline",
        "Traefik health probes | Verify the captured baseline against live ingress",
    ]
    verify = result.op("Traefik health probes | Verify the captured baseline against live ingress")
    assert verify.read_only
    assert any(command.startswith("bash -c ") and PROGRAM_SHA256 in command for command in result.executed_commands)
    assert any(f"mkdir -p {PROBE_DIR}" in command for command in result.executed_commands)
    assert any(f"chmod 700 {PROBE_DIR}" in command for command in result.executed_commands)


def test_converged_host_changes_nothing() -> None:
    responses = {
        **LINUX,
        **PYTHON_OK,
        f"stat -c %a {PROBE_DIR}": ["700"],
        **fakehost.directory(PROBE_DIR, mode="drwx------"),
        **fakehost.file(PROGRAM_PATH, PROGRAM.decode(), mode="-rwxr-xr-x"),
        **fakehost.file(CHECKS_PATH, config_json(BASELINE), mode="-rw-------"),
    }

    result = run_deploy_fake(deploy_traefik_health_probes, CFG, responses=responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert result.uploads == []
    assert result.secret_files == []


@pytest.mark.parametrize("answer", [["False"], []])
def test_deploy_refuses_without_python_3_11(answer: list[str]) -> None:
    result = run_deploy_fake(deploy_traefik_health_probes, CFG, responses={**LINUX, f"{PYTHON} -c": answer})

    assert not result.succeeded
    assert "3.11 or newer" in str(result.error)
    assert result.executed_commands == []
    assert result.uploads == []


def test_deploy_refuses_an_empty_probe_list() -> None:
    with pytest.raises(ValidationError, match="at least 1 item"):
        TraefikHealthProbesConfig.model_validate({"baseline": {**baseline_input(), "probes": [], "observations": []}})
