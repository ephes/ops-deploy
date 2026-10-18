"""Release/custom-unit and route-only integration on a dedicated Linux smoke VM."""

from __future__ import annotations

import base64
import hashlib
import io
import shlex
import tarfile
from typing import Any

import pytest
from pyinfra.operations import server

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.native_app import NativeAppConfig, deploy_native_app
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

ROOT = "/var/lib/radio-fixture"
STATE = "/var/lib/ops-deploy/radio_fixture"
BINARY = "/opt/radio-fixture/server"
PORT = 18645
APP = b"""#!/usr/bin/python3
import http.server,sys,tomllib,os,time
if '--version' in sys.argv:
    print('1.2.3');sys.exit(0)
time.sleep(float(os.environ.get('STARTUP_DELAY','0')))
with open(sys.argv[sys.argv.index('--configfile')+1], 'rb') as f: cfg=tomllib.load(f)
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(b'fixture')
http.server.HTTPServer((cfg['Address'],cfg['Port']),Handler).serve_forever()
"""
REF = SecretRef("secrets/fixture/radio.yml")
VALUES = SecretValues(REF, {"password": "fixture-password"})


def _run(host: SmokeHost, cfg: NativeAppConfig, label: str, *, succeed: bool = True) -> SshRun:
    run = run_deploy_ssh(deploy_native_app, cfg, VALUES, host_name=host.name, host_data=host.host_data)
    TIMINGS[f"native_app {label}"] = run.seconds
    assert run.succeeded == succeed, (label, run.error, [op for op in run.ops if not op.succeeded])
    return run


def _pid(host: SmokeHost, name: str = "radio-fixture") -> str:
    return host.out(f"systemctl show -p MainPID --value {name}")


@pytest.fixture(scope="module")
def native_cfg(smoke_host: SmokeHost) -> NativeAppConfig:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        member = tarfile.TarInfo("server")
        member.size = len(APP)
        member.mode = 0o755
        tar.addfile(member, io.BytesIO(APP))
    body = archive.getvalue()
    smoke_host.run(
        "systemctl stop radio-fixture native-artifact-fixture 2>/dev/null || true; "
        f"rm -rf {ROOT} {STATE} /var/lib/ops-deploy/route_fixture /opt/radio-fixture /tmp/native-artifact-fixture; "
        "rm -f /etc/systemd/system/radio-fixture.service "
        "/etc/traefik/dynamic/radio-fixture.yml /etc/traefik/dynamic/route-fixture.yml; "
        "mkdir -p /etc/systemd/system/radio-fixture.service.d; "
        "printf '[Unit]\\nStartLimitIntervalSec=0\\n' > /etc/systemd/system/radio-fixture.service.d/fixture.conf; "
        "systemctl daemon-reload; systemctl reset-failed radio-fixture 2>/dev/null || true; "
        "mkdir /tmp/native-artifact-fixture; "
        f"printf %s {base64.b64encode(body).decode()} | base64 -d > /tmp/native-artifact-fixture/app.tar.gz; "
        "systemd-run --unit=native-artifact-fixture --property=Restart=on-failure "
        "/usr/bin/python3 -m http.server 18644 --bind 127.0.0.1 --directory /tmp/native-artifact-fixture"
    )
    return NativeAppConfig.model_validate(
        {
            "service_name": "radio_fixture",
            "title": "Radio fixture",
            "user": "radio_fixture",
            "site_path": ROOT,
            "secrets": REF,
            "account": {"name": "radio_fixture", "group": "radio_fixture", "home": ROOT},
            "directories": [{"path": "/opt/radio-fixture", "owner": "root", "group": "root", "mode": "0755"}],
            "source": {
                "version": "1.2.3",
                "url": "http://127.0.0.1:18644/app.tar.gz",
                "insecure_reason": "Isolated VM fixture",
                "checksums": {"aarch64": hashlib.sha256(body).hexdigest(), "x86_64": hashlib.sha256(body).hexdigest()},
                "member": "server",
                "dest": BINARY,
            },
            "configs": [{"path": ROOT + "/app.toml", "data": {"Address": "127.0.0.1", "Port": PORT, "Label": "first"}}],
            "unit": {
                "name": "radio-fixture",
                "description": "Radio fixture",
                "user": "radio_fixture",
                "group": "radio_fixture",
                "working_directory": ROOT,
                "exec_start": [BINARY, "--configfile", ROOT + "/app.toml"],
            },
            "listen_port": PORT,
            "health_url": f"http://127.0.0.1:{PORT}/",
            "route": {
                "name": "radio-fixture",
                "host": "radio.example.invalid",
                "port": PORT,
                "access": "internal_or_basic_auth",
                "basic_auth_user": "fixture",
                "basic_auth_password": {"secret": "password"},
            },
        }
    )


def test_native_install_convert_resume_and_route(
    smoke_host: SmokeHost, native_cfg: NativeAppConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = native_cfg
    traefik = _pid(smoke_host, "traefik")
    first = _run(smoke_host, cfg, "first install")
    assert first.mutating_changed_ops
    pid = _pid(smoke_host)
    assert pid != "0"
    assert _run(smoke_host, cfg, "converged").mutating_changed_ops == []
    assert _pid(smoke_host) == pid
    smoke_host.run(f"echo retained-state > {ROOT}/data.txt")
    # The prior deploy's canonical output is replaced by equivalent role-shaped text.
    smoke_host.run(
        f"sed -i '1c# Managed by Ansible' {ROOT}/app.toml; "
        "sed -i '1c# Managed by Ansible' /etc/systemd/system/radio-fixture.service; "
        f"rm -rf {STATE}; systemctl daemon-reload"
    )
    converted = _run(smoke_host, cfg, "canonical conversion")
    assert len([op for op in converted.mutating_changed_ops if op.endswith("Restart radio-fixture.service")]) == 1
    assert _pid(smoke_host) != pid
    assert not any("Install pinned native release" in op for op in converted.mutating_changed_ops)
    assert smoke_host.out(f"cat {ROOT}/data.txt") == "retained-state"
    assert _run(smoke_host, cfg, "after conversion").mutating_changed_ops == []
    data: dict[str, Any] = cfg.model_dump(mode="python")
    data["configs"][0]["data"]["Label"] = "changed"
    changed = NativeAppConfig.model_validate(data)
    # Fail between input writes and rollout through the production deploy caller.
    import ops_deploy.services.native_app.deploy as module

    original = module.__dict__["service_rollout"]

    def fail_before_rollout(*args: Any, **kwargs: Any) -> Any:
        server.shell(name="Injected native rollout failure", commands=["false"])
        return original(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(module, "service_rollout", fail_before_rollout)
        _run(smoke_host, changed, "interrupted", succeed=False)
    assert smoke_host.out(f"test -e {STATE}/restart && echo owed") == "owed"
    assert smoke_host.out(f"grep changed {ROOT}/app.toml")
    before_resume = _pid(smoke_host)
    resumed = _run(smoke_host, changed, "resume")
    assert any(op.endswith("Resume native restart") for op in resumed.mutating_changed_ops)
    assert _pid(smoke_host) != before_resume
    assert smoke_host.out(f"test ! -e {STATE}/pending && test ! -e {STATE}/restart && echo clear") == "clear"
    assert _run(smoke_host, changed, "after resume").mutating_changed_ops == []
    # In-memory config drift writes and restarts once without touching user data.
    pid = _pid(smoke_host)
    drifted = _run(smoke_host, cfg, "config drift")
    assert drifted.mutating_changed_ops
    assert _pid(smoke_host) != pid
    assert _run(smoke_host, cfg, "after drift").mutating_changed_ops == []
    smoke_host.run(f"cp {BINARY} {BINARY}.drift; echo '# drift' >> {BINARY}.drift; mv {BINARY}.drift {BINARY}")
    repaired = _run(smoke_host, cfg, "binary drift")
    assert any("Install pinned native release" in name for name in repaired.mutating_changed_ops)
    assert _run(smoke_host, cfg, "after binary repair").mutating_changed_ops == []
    assert cfg.source is not None
    older = cfg.model_copy(update={"source": cfg.source.model_copy(update={"version": "1.2.2"})})
    refused = _run(smoke_host, older, "downgrade refusal", succeed=False)
    assert refused.mutating_changed_ops == []
    route_only = NativeAppConfig.model_validate(
        {
            "service_name": "route_fixture",
            "title": "Route fixture",
            "user": "root",
            "site_path": "/var/lib/route-fixture",
            "secrets": REF,
            "route": {
                "name": "route-fixture",
                "host": "remote.example.invalid",
                "port": 18001,
                "backend_host": "backend.example.invalid",
                "remote_reason": "Separate fixture backend",
                "access": "internal_or_basic_auth",
                "basic_auth_user": "fixture",
                "basic_auth_password": {"secret": "password"},
            },
        }
    )
    assert _run(smoke_host, route_only, "route only").mutating_changed_ops
    assert _run(smoke_host, route_only, "route only noop").mutating_changed_ops == []
    smoke_host.run("chmod 0700 /etc/traefik/dynamic")
    directory_repair = _run(smoke_host, route_only, "route directory metadata")
    assert "Mark native apply pending" in directory_repair.mutating_changed_ops
    assert _run(smoke_host, route_only, "after directory repair").mutating_changed_ops == []
    assert _pid(smoke_host, "traefik") == traefik


def test_missing_mount_refuses_before_writes(smoke_host: SmokeHost, native_cfg: NativeAppConfig) -> None:
    cfg = native_cfg.model_copy(update={"mounts_required": (native_cfg.site_path,)})
    before = _pid(smoke_host)
    with pytest.raises(ValueError, match=r"preflight|required mount"):
        _run(smoke_host, cfg, "missing mount")
    assert _pid(smoke_host) == before


def test_corrupt_managed_release_repairs(smoke_host: SmokeHost, native_cfg: NativeAppConfig) -> None:
    _run(smoke_host, native_cfg, "corrupt setup")
    smoke_host.run(
        f"printf '#!/bin/sh\\nexit 2\\n' > {BINARY}.broken; chmod 0755 {BINARY}.broken; mv {BINARY}.broken {BINARY}"
    )
    repaired = _run(smoke_host, native_cfg, "corrupt managed repair")
    assert any("Install pinned native release" in name for name in repaired.mutating_changed_ops)
    assert _run(smoke_host, native_cfg, "after corrupt repair").mutating_changed_ops == []


def test_newer_release_mode_drift_refuses(smoke_host: SmokeHost, native_cfg: NativeAppConfig) -> None:
    _run(smoke_host, native_cfg, "mode downgrade setup")
    assert native_cfg.source is not None
    older = native_cfg.model_copy(update={"source": native_cfg.source.model_copy(update={"version": "1.2.2"})})
    smoke_host.run(f"chmod 0750 {BINARY}")
    try:
        refused = _run(smoke_host, older, "mode drift downgrade refusal", succeed=False)
        assert refused.mutating_changed_ops == []
    finally:
        smoke_host.run(f"chmod 0755 {BINARY}")


def test_delayed_listener_and_literal_environment(smoke_host: SmokeHost, native_cfg: NativeAppConfig) -> None:
    _run(smoke_host, native_cfg, "delayed setup")
    assert native_cfg.unit is not None
    unit = native_cfg.unit.model_copy(update={"environment": {"STARTUP_DELAY": "1.2", "LITERAL": "$prefix $HOME"}})
    delayed = native_cfg.model_copy(update={"unit": unit})
    _run(smoke_host, delayed, "delayed listener")
    code = (
        "from pathlib import Path; import sys; "
        "print(next(x.decode().split('=',1)[1] for x in "
        "Path('/proc/'+sys.argv[1]+'/environ').read_bytes().split(bytes([0])) "
        "if x.startswith(b'LITERAL=')))"
    )
    actual = smoke_host.out(shlex.join(["python3", "-c", code, _pid(smoke_host)]))
    assert actual == "$prefix $HOME"
    assert _run(smoke_host, delayed, "delayed noop").mutating_changed_ops == []


def _replace_fixture(host: SmokeHost, body: bytes, *, mode: str = "0755") -> None:
    # Only this controller-generated benign fixture is installed; no unknown
    # executable or production binary is run by these permission regressions.
    host.run(
        f"printf %s {base64.b64encode(body).decode()} | base64 -d > {BINARY}.fixture; "
        f"chmod {mode} {BINARY}.fixture; mv {BINARY}.fixture {BINARY}"
    )


@pytest.mark.parametrize("mode", ["0777", "0775"])
def test_writable_release_refuses_before_version_execution(
    smoke_host: SmokeHost, native_cfg: NativeAppConfig, mode: str
) -> None:
    _run(smoke_host, native_cfg, "writable trust setup")
    marker = "/tmp/native-trust-version-executed"
    body = APP.replace(
        b"print('1.2.3');sys.exit(0)",
        f"open('{marker}', 'w').write('controlled-fixture-probe');print('1.2.3');sys.exit(0)".encode(),
    )
    compile(body, "controlled-fixture", "exec")
    smoke_host.run(f"rm -f {marker}")
    _replace_fixture(smoke_host, body, mode=mode)
    try:
        run = run_deploy_ssh(
            deploy_native_app, native_cfg, VALUES, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        observed = smoke_host.out(f"if test -e {marker}; then echo executed; else echo blocked; fi")
        assert observed == "blocked", "the controlled version probe executed before unsafe-mode refusal"
        assert not run.succeeded
        assert run.mutating_changed_ops == []
    finally:
        _replace_fixture(smoke_host, APP)
        smoke_host.run(f"rm -f {marker}")


@pytest.mark.parametrize("stream", [1, 2])
def test_undecodable_managed_release_repairs(smoke_host: SmokeHost, native_cfg: NativeAppConfig, stream: int) -> None:
    _run(smoke_host, native_cfg, "undecodable setup")
    body = f"#!/usr/bin/python3\nimport os,sys\nos.write({stream},bytes([255]));sys.exit(2)\n".encode()
    _replace_fixture(smoke_host, body)
    try:
        repaired = _run(smoke_host, native_cfg, "undecodable managed repair")
        assert any("Install pinned native release" in name for name in repaired.mutating_changed_ops)
        assert _run(smoke_host, native_cfg, "after undecodable repair").mutating_changed_ops == []
    finally:
        _replace_fixture(smoke_host, APP)
