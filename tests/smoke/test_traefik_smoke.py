"""Traefik on the smoke VM: install, upgrade, converged run, backup, restore, removal.

The VM's own Traefik (``smoke/provision.sh``) serves the service smokes, so
the test saves its binary, ``/etc/traefik`` and unit first and puts them back
afterwards. A stand-in ``lighttpd.service`` (a vendor unit running ``sleep``)
plays the conflicting distro web server.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from ops_deploy.infra import (
    TraefikBackupConfig,
    TraefikDeployConfig,
    TraefikRemoveConfig,
    TraefikRestoreConfig,
    deploy_traefik,
    deploy_traefik_backup,
    deploy_traefik_remove,
    deploy_traefik_restore,
)
from ops_deploy.infra.traefik_deploy import render_logrotate, render_static, render_unit
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

# Published release checksums (traefik_v<version>_checksums.txt).
CHECKSUMS = {
    ("3.7.13", "arm64"): "9155048abd64c59000d2f3c07dc6d6919bc6be9b618e6a554bc3808338aaf8b8",
    ("3.7.13", "amd64"): "52cd039a34258dd61c617a95d69252bc6bcae27c520f338186c31c7fef8f6394",
    ("3.7.14", "arm64"): "e5a2d0620cecc01dbc3d8da739db0671fdc030ef1c3b2d90d54f3baaa25d85d3",
    ("3.7.14", "amd64"): "d08641f5de2dd3788097bddab1ce4b29c10a0b788566970db707fa5c94c71f15",
}
SAVED = "/root/ops-deploy-traefik-smoke.tgz"
FAKE_WEB = "/usr/lib/systemd/system/lighttpd.service"
BACKUPS = "/opt/backups/traefik-smoke"
FAKE_UNIT = "[Service]\\nExecStart=/bin/sleep infinity\\n[Install]\\nWantedBy=multi-user.target\\n"


def deploy(smoke_host: SmokeHost, label: str, fn: Any, cfg: Any) -> SshRun:
    run = run_deploy_ssh(fn, cfg, host_name=smoke_host.name, host_data=smoke_host.host_data)
    TIMINGS[label] = run.seconds
    assert run.succeeded, run.error
    return run


def config(smoke_host: SmokeHost, version: str) -> TraefikDeployConfig:
    arch = {"aarch64": "arm64", "x86_64": "amd64"}[smoke_host.out("uname -m")]
    return TraefikDeployConfig(
        version=version,
        checksum=f"sha256:{CHECKSUMS[version, arch]}",
        letsencrypt_email="smoke@example.org",
        alias_policy={"web": "delete", "web-secure": "delete", "traefik": "delete"},
    )


@pytest.fixture
def provisioned_traefik(smoke_host: SmokeHost) -> Iterator[None]:
    rules = smoke_host.out("ufw show added 2>/dev/null || true")
    smoke_host.run(
        f"tar -czPf {SAVED} /usr/local/bin/traefik /etc/traefik /etc/systemd/system/traefik.service"
        f" && printf '{FAKE_UNIT}' > {FAKE_WEB}"
        " && systemctl daemon-reload && systemctl enable --now lighttpd.service"
    )
    yield
    for port in (80, 443):
        if f"ufw allow {port}/tcp" not in rules:
            smoke_host.run(f"ufw delete allow {port}/tcp", check=False)
    smoke_host.run(
        "systemctl stop traefik.service; systemctl unmask lighttpd.service; systemctl disable lighttpd.service;"
        f" rm -rf {FAKE_WEB} /etc/traefik /var/log/traefik /etc/logrotate.d/traefik {BACKUPS}"
        f" && tar -xzPf {SAVED} && rm -f {SAVED}"
        " && systemctl daemon-reload && systemctl reset-failed lighttpd.service 2>/dev/null;"
        " systemctl enable traefik.service && systemctl restart traefik.service",
        check=False,
    )
    assert smoke_host.out("systemctl is-active traefik.service") == "active"
    assert "traefik.yml" in smoke_host.out("systemctl cat traefik.service")


def test_traefik_lifecycle(smoke_host: SmokeHost, provisioned_traefik: None) -> None:
    old, new = config(smoke_host, "3.7.13"), config(smoke_host, "3.7.14")

    first = deploy(smoke_host, "traefik install 3.7.13", deploy_traefik, old)
    assert "Traefik | Check the installed Traefik is 3.7.13" in first.mutating_changed_ops
    assert smoke_host.out("traefik version | awk '/^Version:/ {print $2}'") == "3.7.13"
    upgrade = deploy(smoke_host, "traefik upgrade 3.7.14", deploy_traefik, new)
    assert upgrade.mutating_changed_ops == [
        "Traefik | Install Traefik 3.7.14",
        "Traefik | Check the installed Traefik is 3.7.14",
        "Traefik | Restart Traefik for the new configuration",
    ]
    pid = smoke_host.out("systemctl show -p MainPID --value traefik")
    second = deploy(smoke_host, "traefik second run", deploy_traefik, new)

    assert second.mutating_changed_ops == []
    assert smoke_host.out("systemctl show -p MainPID --value traefik") == pid
    # The running process is the new binary with the role's config and unit.
    assert smoke_host.out(f"readlink /proc/{pid}/exe") == "/usr/local/bin/traefik"
    assert smoke_host.run("cat /etc/traefik/traefik.toml").stdout == render_static(new)
    assert smoke_host.run("cat /etc/systemd/system/traefik.service").stdout == render_unit(new)
    assert smoke_host.out("stat -c '%U %a' /etc/traefik/acme /etc/traefik/acme/acme.json").splitlines() == [
        "root 700",
        "root 600",
    ]
    # HTTP redirects to HTTPS; the dashboard and metrics answer on their ports.
    redirect = "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: smoke.example' http://127.0.0.1/x"
    assert smoke_host.out(redirect) == "301 https://smoke.example/x"
    assert smoke_host.out("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/metrics") == "200"
    assert smoke_host.out("systemctl is-enabled lighttpd.service || true") == "masked"
    assert smoke_host.out("systemctl is-active lighttpd.service || true") == "inactive"
    # A forced rotation: logrotate accepts the file, Traefik reopens access.log on SIGUSR1
    # (requests after the rotation land in the fresh file) and keeps running. The access
    # log is buffered (100 lines) and the HTTP redirect is not logged, so each round sends
    # enough unrouted requests (404) to flush it.
    assert smoke_host.run("cat /etc/logrotate.d/traefik").stdout == render_logrotate(new)
    flush = "for i in $(seq 120); do curl -s -o /dev/null http://127.0.0.1:8090/nope; done; sleep 2"
    smoke_host.run(flush)
    smoke_host.run("logrotate -f /etc/logrotate.d/traefik")
    smoke_host.run(flush)
    assert smoke_host.out("test -s /var/log/traefik/access.log.1 && echo rotated") == "rotated"
    assert smoke_host.out("test -s /var/log/traefik/access.log && echo reopened") == "reopened"
    assert smoke_host.out("systemctl show -p MainPID --value traefik") == pid

    # Backup with ACME state, then restore it over a damaged store.
    smoke_host.run("printf '{\"smoke\": true}' > /etc/traefik/acme/acme.json")
    smoke_host.run("printf 'http: {}\\n' > /etc/traefik/dynamic/backup-route.yml")
    backup = TraefikBackupConfig(root=BACKUPS, include_acme=True, fetch_local=False, prefix="smoke")
    deploy(smoke_host, "traefik backup", deploy_traefik_backup, backup)
    listing = smoke_host.out(f"tar -tzf {BACKUPS}/smoke-*.tar.gz | sort").splitlines()
    relative = {entry.partition("/")[2] for entry in listing}
    outside_dynamic = {entry for entry in relative if entry == "dynamic/" or not entry.startswith("dynamic/")}
    assert outside_dynamic == {"", "acme/", "acme/acme.json", "dynamic/", "metadata.yml"}
    assert "dynamic/backup-route.yml" in relative
    assert smoke_host.out(f"stat -c '%U:%G %a' {BACKUPS}/smoke-*/dynamic") == "root:root 700"
    # This lifecycle smoke still restores ACME only, never archived routes.
    smoke_host.run("echo damaged > /etc/traefik/acme/acme.json && chmod 644 /etc/traefik/acme/acme.json")
    deploy(smoke_host, "traefik restore", deploy_traefik_restore, TraefikRestoreConfig(root=BACKUPS, include_acme=True))
    assert smoke_host.out("cat /etc/traefik/acme/acme.json") == '{"smoke": true}'
    assert smoke_host.out("stat -c '%U %a' /etc/traefik/acme/acme.json") == "root 600"
    assert smoke_host.out("test -e /tmp/traefik-restore && echo left || echo gone") == "gone"

    # Removal keeps routes and certificates; a second removal changes nothing.
    smoke_host.run("echo 'http: {}' > /etc/traefik/dynamic/smoke-route.yml")
    removal = TraefikRemoveConfig(confirm=True)
    deploy(smoke_host, "traefik remove", deploy_traefik_remove, removal)
    assert deploy(smoke_host, "traefik remove again", deploy_traefik_remove, removal).changed_ops == []
    assert smoke_host.out("systemctl is-active traefik.service || true") == "inactive"
    gone = "/usr/local/bin/traefik /etc/traefik/traefik.toml /etc/systemd/system/traefik.service /var/log/traefik"
    assert smoke_host.out(f"ls -d {gone} 2>/dev/null || true") == ""
    assert smoke_host.out("cat /etc/traefik/acme/acme.json") == '{"smoke": true}'
    assert smoke_host.out("ls /etc/traefik/dynamic") != ""
