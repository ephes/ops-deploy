"""Traefik health probes on the smoke VM: capture, install, verify, health, drift.

Probes go to the VM's own Traefik (``smoke/provision.sh``: ``web-secure`` on
:443 with Traefik's default certificate): an HTTPS request (curl refuses the
default certificate: exit 60, with the served leaf fingerprinted) and a plain
HTTP request to the TLS port (Traefik answers 404). A test-owned file in
``/etc/traefik/dynamic`` gives the dynamic tree a known entry. The test needs
``/var/lib/traefik-update-probes`` absent and removes it and its route file
afterwards.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterator

import pytest

from ops_deploy.backups.remote import SshTarget, SubprocessRunner, ssh_runner
from ops_deploy.infra import (
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
    config_json,
    probe_commands,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

ROUTE = "/etc/traefik/dynamic/ops-deploy-probes-smoke.yml"
ROUTE_TMP = "/etc/traefik/ops-deploy-probes-smoke.yml.tmp"
ROUTE_TEXT = (
    "http:\n  routers:\n    ops-deploy-probes-smoke:\n      rule: Host(`probes-smoke.example.test`)\n"
    "      entryPoints: [web-secure]\n      service: ops-deploy-probes-smoke\n      tls: {}\n"
    "  services:\n    ops-deploy-probes-smoke:\n      loadBalancer:\n        servers:\n"
    "          - url: http://127.0.0.1:9\n"
)
SPEC = ProbeSpec.model_validate(
    {
        "tls_fingerprints": True,
        "probes": [
            {"host": "probes-smoke.example.test", "scheme": "https", "port": 443, "address": "127.0.0.1"},
            {"host": "probes-smoke.example.test", "scheme": "http", "port": 443, "address": "127.0.0.1", "path": "/x"},
        ],
        "entrypoints": ["web-secure"],
    }
)


@pytest.fixture
def probe_host(smoke_host: SmokeHost) -> Iterator[SmokeHost]:
    if smoke_host.run(f"test -e {PROBE_DIR}", check=False).returncode == 0:
        pytest.fail(f"{PROBE_DIR} already exists on the smoke VM; this test only runs on a host without it")
    put_route(smoke_host)
    yield smoke_host
    smoke_host.run(f"rm -rf {PROBE_DIR} {ROUTE} {ROUTE_TMP}")


def put_route(smoke_host: SmokeHost) -> None:
    """Write the route file atomically and let Traefik's file provider settle.

    Traefik generates a new default certificate whenever its TLS configuration
    changes; a route truncated and rewritten in place would briefly vanish and
    change the served leaf the HTTPS probe fingerprints.
    """

    smoke_host.run(f"cat > {ROUTE_TMP} && mv {ROUTE_TMP} {ROUTE} && sleep 3", input=ROUTE_TEXT)


def runner(smoke_host: SmokeHost) -> SubprocessRunner:
    return ssh_runner(
        SshTarget(
            hostname=smoke_host.hostname,
            port=smoke_host.port,
            user=smoke_host.user,
            key=smoke_host.key,
            known_hosts_file=smoke_host.known_hosts,
            strict_host_key_checking="yes",
            options=(("IdentitiesOnly", "yes"),),
        )
    )


def install(smoke_host: SmokeHost, cfg: TraefikHealthProbesConfig) -> SshRun:
    return run_deploy_ssh(deploy_traefik_health_probes, cfg, host_name=smoke_host.name, host_data=smoke_host.host_data)


def test_capture_install_verify(probe_host: SmokeHost) -> None:
    ssh = runner(probe_host)

    baseline = capture_traefik_health_probes(ssh, SPEC)

    https, http = baseline.observations
    assert (https.exit, https.status) == (60, "000")
    assert https.tls_sha256 is not None
    assert (http.exit, http.status) == (0, "404")
    assert baseline.dynamic[ROUTE.rsplit("/", 1)[1]] == hashlib.sha256(ROUTE_TEXT.encode()).hexdigest()
    # Read-only: nothing installed, no capture directory left behind.
    assert probe_host.run(f"test -e {PROBE_DIR}", check=False).returncode != 0
    assert probe_host.out(f"ls -d /tmp/{CAPTURE_PREFIX}* 2>/dev/null || true") == ""

    cfg = TraefikHealthProbesConfig(baseline=baseline)
    first = install(probe_host, cfg)
    TIMINGS["traefik probes install"] = first.seconds
    assert first.succeeded, first.error
    assert first.mutating_changed_ops != []
    second = install(probe_host, cfg)
    assert second.succeeded, second.error
    assert second.mutating_changed_ops == []

    assert probe_host.out(f"stat -c '%U:%G %a' {PROBE_DIR} {PROGRAM_PATH} {CHECKS_PATH}").splitlines() == [
        "root:root 700",
        "root:root 755",
        "root:root 600",
    ]
    assert probe_host.out(f"sha256sum {PROGRAM_PATH}").split()[0] == PROGRAM_SHA256
    assert probe_host.out(f"cat {CHECKS_PATH}") == config_json(baseline)

    commands = verify_traefik_health_probes(ssh)
    assert commands == probe_commands()

    # The transaction engine runs the argv as it is (the shebang picks /usr/bin/python3).
    for key in ("baseline_probe", "acceptance_probe", "cleanup_probe"):
        argv = " ".join(getattr(commands, key).argv)
        result = probe_host.run(argv, check=False)
        assert result.returncode == 0, (key, result.stderr)
    assert json.loads(probe_host.out(" ".join(commands.baseline_probe.argv))) == {
        "ingress_checks": 2,
        "baseline_preserved": True,
    }
    assert json.loads(probe_host.out(" ".join(commands.cleanup_probe.argv)))["dynamic_verified"] is True

    # A changed permanent route fails verification; putting it back passes again.
    probe_host.run(f"echo '# changed' >> {ROUTE} && sleep 3")
    with pytest.raises(ProbeError, match=r"^verify: permanent routing changed$"):
        verify_traefik_health_probes(ssh)
    put_route(probe_host)
    assert verify_traefik_health_probes(ssh) == commands

    # A changed served result is reported without the probe's host name.
    probe_host.run(f'sed -i \'s/"status": "404"/"status": "200"/\' {CHECKS_PATH}')
    with pytest.raises(ProbeError, match=r"^verify: ingress changed$"):
        verify_traefik_health_probes(ssh)
    assert install(probe_host, cfg).mutating_changed_ops == [
        "Traefik health probes | Install the captured private acceptance baseline"
    ]

    # A tampered or non-executable program is refused before anything runs; a redeploy repairs it.
    for mode, reason in (("0775", "writable by group or others"), ("0644", "is not executable")):
        probe_host.run(f"chmod {mode} {PROGRAM_PATH}")
        with pytest.raises(ProbeError, match=reason):
            verify_traefik_health_probes(ssh)
        repaired = install(probe_host, cfg)
        assert repaired.succeeded, repaired.error
        assert repaired.mutating_changed_ops == ["Traefik health probes | Install the read-only acceptance program"]
    assert verify_traefik_health_probes(ssh) == commands


def test_empty_probe_list_is_refused_on_the_host(probe_host: SmokeHost) -> None:
    probe_host.run("mkdir -p /root/ops-deploy-probes-smoke")
    try:
        probe_host.run("cat > /root/ops-deploy-probes-smoke/empty.json", input='{"probes": [], "entrypoints": ["w"]}')
        program = base64.encodebytes(PROGRAM).decode()
        probe_host.run("base64 -d > /root/ops-deploy-probes-smoke/health.py", input=program)
        result = probe_host.run(
            "/usr/bin/python3 /root/ops-deploy-probes-smoke/health.py capture /root/ops-deploy-probes-smoke/empty.json",
            check=False,
        )
        assert result.returncode != 0
        assert "At least one explicit ingress probe is required" in result.stderr
    finally:
        probe_host.run("rm -rf /root/ops-deploy-probes-smoke")
