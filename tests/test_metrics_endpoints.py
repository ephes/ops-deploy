"""Endpoint contracts: safe configuration, preserved templates and real convergence plans."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.metrics_endpoint import MetricsEndpointConfig, deploy_metrics_endpoint
from ops_deploy.services.metrics_endpoint import deploy as mail
from ops_deploy.services.torrent_vpn_metrics_endpoint import (
    TorrentVpnMetricsEndpointConfig,
    deploy_torrent_vpn_metrics_endpoint,
)
from ops_deploy.services.torrent_vpn_metrics_endpoint import deploy as torrent
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

VALUE = "fixture-endpoint-password"
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {"endpoint_password": VALUE})
BIND = "100.64.0.7"


def config(kind: str, **changes: Any) -> Any:
    cls = MetricsEndpointConfig if kind == "mail" else TorrentVpnMetricsEndpointConfig
    return cls.model_validate({"auth_user": "nyxmon", "bind": BIND, "secrets": "secrets/fixture.yml", **changes})


@pytest.mark.parametrize("kind", ["mail", "torrent"])
@pytest.mark.parametrize(
    "change",
    [
        {"path": "/x;touch /tmp/bad"},
        {"packages": ["python3;bad"]},
        {"user": "root;bad"},
        {"bind": "not-an-address"},
        {"server_path": "/tmp/../../etc/passwd"},
        {"auth_user": "a:b"},
        {"port": True},
        {"port": 1.5},
        {"unknown": True},
    ],
)
def test_invalid_config_never_reaches_the_host(kind: str, change: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        config(kind, **change)


def test_derived_paths_follow_the_role_defaults() -> None:
    cfg = config("torrent", site_path="/srv/vpn", htpasswd_dir="/etc/vpn-auth")
    assert cfg.json_path == Path("/srv/vpn/vpn.json")
    assert cfg.htpasswd_path == Path("/etc/vpn-auth/htpasswd")
    assert config("torrent", json_file="/srv/other.json").json_path == Path("/srv/other.json")


@pytest.mark.parametrize("kind", ["mail", "torrent"])
def test_httpd_switch_inputs_fit_the_existing_role_contract(kind: str) -> None:
    cfg = config(kind)
    module = mail if kind == "mail" else torrent
    endpoint = module.httpd_endpoint(cfg, BIND)
    from ops_deploy.services._metrics_httpd import problems

    assert problems(endpoint) == []
    assert endpoint.probe_realm == ("metrics" if kind == "mail" else "torrent-vpn-metrics")
    assert endpoint.ip_address_allow == ("localhost", "100.64.0.0/10")


def converged(kind: str, **changes: Any) -> tuple[Any, dict[str, Any]]:
    cfg = config(kind, **changes)
    module = mail if kind == "mail" else torrent
    prefix = "metrics_endpoint" if kind == "mail" else "torrent_vpn_metrics_endpoint"
    root = Path(__file__).parents[1] / "src/ops_deploy/services" / prefix / "templates"
    contents = {p.name: module.render_role(p.name, cfg, BIND) for p in root.glob("*.j2")}
    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.deb_installed(*cfg.packages),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.stat(str(cfg.htpasswd_dir), group="metrics", mode="drwxr-x---"),
        **fakehost.file(str(cfg.htpasswd_path), f"nyxmon:{hash_password(VALUE)}\n"),
        **fakehost.stat(str(cfg.htpasswd_path), group="metrics", mode="-rw-r-----"),
        **fakehost.service(cfg.service_name + ".service"),
        "setfacl": ["changed=false"],
    }
    if kind == "mail":
        paths = {
            "mail-metrics.sh.j2": str(cfg.script_path),
            "metrics_httpd.py.j2": str(cfg.server_path),
            "metrics-endpoint.service.j2": "/etc/systemd/system/metrics-endpoint.service",
        }
    else:
        paths = {
            "torrent-vpn-metrics-collect.py.j2": str(cfg.collector_path),
            "torrent_vpn_metrics_httpd.py.j2": str(cfg.server_path),
            "torrent-vpn-metrics-collector.service.j2": f"/etc/systemd/system/{cfg.timer_name}.service",
            "torrent-vpn-metrics-collector.timer.j2": f"/etc/systemd/system/{cfg.timer_name}.timer",
            "torrent-vpn-metrics-endpoint.service.j2": f"/etc/systemd/system/{cfg.service_name}.service",
        }
        responses.update(
            {
                **fakehost.stat(str(cfg.site_path), group="metrics", mode="drwxr-x---"),
                **fakehost.service(cfg.timer_name + ".timer"),
                "time.time()": ["present"],
                f"systemctl show {cfg.timer_name}.timer": ["NextElapseUSecMonotonic=1234"],
            }
        )
    for template, path in paths.items():
        mode = "-rwxr-xr-x" if not path.startswith("/etc/systemd/") else "-rw-r--r--"
        responses.update(fakehost.file(path, contents[template], mode=mode))
    return cfg, responses


@pytest.mark.parametrize("kind", ["mail", "torrent"])
def test_converged_deploy_performs_no_mutations(kind: str) -> None:
    cfg, responses = converged(kind)
    deploy = deploy_metrics_endpoint if kind == "mail" else deploy_torrent_vpn_metrics_endpoint
    result = run_deploy_fake(deploy, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert not any("systemctl start" in c or "systemctl restart" in c for c in result.executed_commands)


def test_invalid_or_stale_torrent_payload_runs_collector_without_restarting_httpd() -> None:
    cfg, responses = converged("torrent")
    responses["time.time()"] = ["invalid"]
    result = run_deploy_fake(deploy_torrent_vpn_metrics_endpoint, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    assert len(result.mutating_changed_ops) == 1
    assert "Initialize torrent VPN metrics" in result.mutating_changed_ops[0]


def test_elapsed_timer_with_valid_payload_seeds_collector_and_rearms() -> None:
    cfg, responses = converged("torrent")
    responses[f"systemctl show {cfg.timer_name}.timer"] = ["NextElapseUSecMonotonic=infinity"]
    result = run_deploy_fake(deploy_torrent_vpn_metrics_endpoint, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    assert len(result.mutating_changed_ops) == 2
    assert any("Initialize torrent VPN metrics" in name for name in result.mutating_changed_ops)
    assert any("Re-arm elapsed" in name for name in result.mutating_changed_ops)


def test_collector_change_recollects_and_rearms_timer_without_httpd_restart() -> None:
    cfg, responses = converged("torrent")
    responses.update(fakehost.file(str(cfg.collector_path), "old collector", mode="-rwxr-xr-x"))
    result = run_deploy_fake(deploy_torrent_vpn_metrics_endpoint, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    names = result.mutating_changed_ops
    assert any("Initialize torrent VPN metrics" in name for name in names)
    assert any("Restart torrent-vpn-metrics-collector.timer" in name for name in names)
    assert not any("Restart torrent-vpn-metrics-endpoint.service" in name for name in names)


@pytest.mark.parametrize("text", ['{"ts": 1}', "not JSON", "[]"])
def test_payload_state_rejects_incomplete_and_stale_output(tmp_path: Path, text: str) -> None:
    path = tmp_path / "vpn.json"
    path.write_text(text)
    script = Path(torrent.__file__).parent / "files/payload_state.py"
    result = subprocess.run([sys.executable, str(script), str(path), "600"], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "invalid"


@pytest.mark.parametrize("kind", ["mail", "torrent"])
def test_python_endpoint_preserves_authentication_and_json(tmp_path: Path, kind: str) -> None:
    import base64
    import http.client
    import http.server
    import json
    import threading
    import time

    cfg = config(kind)
    module = mail if kind == "mail" else torrent
    template = "metrics_httpd.py.j2" if kind == "mail" else "torrent_vpn_metrics_httpd.py.j2"
    scope: dict[str, Any] = {"__name__": "fixture_httpd"}
    exec(compile(module.render_role(template, cfg, "127.0.0.1"), template, "exec"), scope)
    auth_file = tmp_path / "htpasswd"
    auth_file.write_text(f"nyxmon:{hash_password(VALUE)}\n")
    data_file = tmp_path / "vpn.json"
    data_file.write_text(json.dumps({"ts": int(time.time()), "vpn": {"egress_ok": 1}, "error": False}))
    script = tmp_path / "metrics.sh"
    script.write_text('#!/bin/sh\nprintf \'{"mail":{"queue_total":0}}\\n\'\n')
    script.chmod(0o755)
    handler = scope["MetricsHandler" if kind == "mail" else "TorrentVpnMetricsHandler"]
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    server.cfg = {  # type: ignore[attr-defined]
        "path": cfg.path,
        "htpasswd_file": str(auth_file),
        "script": str(script),
        "script_timeout": 10,
        "json_path": str(data_file),
    }
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02))
    thread.start()
    try:
        cases: list[tuple[str | None, int]] = [(None, 401), ("wrong", 401)]
        if kind == "mail":
            cases += [(VALUE + "\n", 401), (VALUE + "\r\n", 401), (VALUE + "\0tail", 401)]
        cases.append((VALUE, 200))
        for password_value, expected in cases:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            headers = {"Connection": "close"}
            if password_value is not None:
                headers["Authorization"] = "Basic " + base64.b64encode(f"nyxmon:{password_value}".encode()).decode()
            conn.request("GET", cfg.path, headers=headers)
            response = conn.getresponse()
            body = response.read()
            assert response.status == expected
            if expected == 401:
                assert (
                    response.headers["WWW-Authenticate"]
                    == 'Basic realm="' + ("metrics" if kind == "mail" else "torrent-vpn-metrics") + '"'
                )
            else:
                parsed = json.loads(body)
                if kind == "mail":
                    assert parsed["mail"]["queue_total"] == 0
                else:
                    assert parsed["vpn"]["egress_ok"] == 1
                    assert parsed["meta"]["age_seconds"] >= 0
            conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    ("output", "changed"),
    [
        ("# file: queue\nqueue: *,*\n", False),
        ("queue: *,*\nmessage: *,*\n\n", False),
        ("queue: u::rwx,u:metrics:r-x,g::---,m::r-x,o::---\n", True),
        ("queue: *,*\nmessage: u::rw-,u:metrics:r--,g::---,m::r--,o::---\n", True),
        ("queue: u::rwx,u:metrics:r-x,g::---,m::r-x,o::---\nmessage: *,*\n", True),
    ],
)
def test_queue_acl_sample_output_through_production_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str, changed: bool
) -> None:
    import os
    import shlex

    queue = tmp_path / "queue"
    (queue / "active").mkdir(parents=True)
    (queue / "deferred").mkdir()
    binary = tmp_path / "bin"
    binary.mkdir()
    sample = tmp_path / "setfacl-output"
    sample.write_text(output)
    stub = binary / "setfacl"
    stub.write_text("#!/bin/sh\ncat " + shlex.quote(str(sample)) + "\n")
    stub.chmod(0o755)
    checks: list[str] = []

    def actual_probe(command: str, *, name: str) -> str:
        argv = shlex.split(command)
        argv[0] = sys.executable
        result = subprocess.run(
            argv,
            env={**os.environ, "PATH": str(binary) + os.pathsep + os.environ.get("PATH", "")},
            capture_output=True,
            text=True,
            check=True,
        )
        checks.append(name)
        return result.stdout.strip()

    monkeypatch.setattr(mail, "probe", actual_probe)
    cfg, responses = converged("mail", queue_path=str(queue))
    result = run_deploy_fake(deploy_metrics_endpoint, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    assert len(checks) == 2
    mutations = [name for name in result.mutating_changed_ops if "Postfix" in name]
    assert len(mutations) == (2 if changed else 0)
    assert result.mutating_changed_ops == mutations
