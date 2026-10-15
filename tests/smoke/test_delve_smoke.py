"""Deploy delve to the smoke target twice: real end state, then a converged rerun.

Needs the Delve backend source (the podcast repo's ``apps/delve-backend``):
``DELVE_SOURCE_PATH``, else ``$PROJECTS_ROOT/podcast/apps/delve-backend``, and a
Go toolchain. The binary is built twice; identical bytes are part of the test.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.delve import DelveConfig, build_delved, deploy_delve
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "delve.example.invalid"


def delve_source() -> Path | None:
    configured = os.environ.get("DELVE_SOURCE_PATH")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "podcast" / "apps" / "delve-backend" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: DelveConfig
    secrets: SecretValues
    first: SshRun
    second: SshRun
    rebuilt: SshRun
    changed: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    source = delve_source()
    if source is None or not (source / "cmd" / "delved").is_dir():
        pytest.skip("no delve backend source (set DELVE_SOURCE_PATH or PROJECTS_ROOT)")
    build = tmp_path_factory.mktemp("delve")
    goarch: Literal["amd64", "arm64"] = "arm64" if smoke_host.out("uname -m") == "aarch64" else "amd64"
    ref = SecretRef("secrets/smoke/delve.yml")
    cfg = DelveConfig(
        binary_path=build_delved(source, build / "delved-1", goarch=goarch),
        secrets=ref,
        public_url=f"https://{HOST}",
        traefik_host=HOST,
        apple_client_id="org.example.player",
        storekit_root_certs_path="/etc/delve/apple-storekit-root-certs.pem",
        storekit_bundle_id="org.example.player",
        storekit_product_ids="org.example.player.pro.monthly",
        admin_emails="ops@example.invalid",
        profile_legacy_reregister=True,
        apple_signin_legacy_no_nonce=True,
    )
    values = SecretValues(
        ref,
        {"session_secret": f"smoke-session-{secrets.token_hex(16)}", "dogfood_token": f"smoke-{secrets.token_hex(8)}"},
    )
    rebuilt_cfg = cfg.model_copy(update={"binary_path": build_delved(source, build / "delved-2", goarch=goarch)})
    # Different bytes (a marker past the ELF payload; it still runs) replace the running binary.
    other = build / "delved-other"
    other.write_bytes(cfg.binary_path.read_bytes() + b"\0smoke-other-build\0")
    changed_cfg = cfg.model_copy(update={"binary_path": other})
    runs = []
    for label, config in (("first", cfg), ("second", cfg), ("rebuilt", rebuilt_cfg), ("changed", changed_cfg)):
        run = run_deploy_ssh(deploy_delve, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"delve {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, *runs)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write delve.env") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_rebuilt_unchanged_source_is_a_noop(deployed: Deployed) -> None:
    assert deployed.rebuilt.mutating_changed_ops == []


def test_new_binary_replaces_the_running_one_and_restarts(deployed: Deployed) -> None:
    assert deployed.changed.mutating_changed_ops == [
        "Deploy delve | Install delved",
        "Deploy delve | Restart delve.service",
    ]


def test_service_runs_and_timer_stays_off(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active delve") == "active"
    assert smoke_host.out("systemctl is-enabled delve") == "enabled"
    assert smoke_host.run("systemctl is-enabled delve-discovery-collect.timer", check=False).stdout.strip() == (
        "disabled"
    )
    assert smoke_host.run("systemctl is-active delve-discovery-collect.timer", check=False).stdout.strip() == (
        "inactive"
    )


def test_layout_and_permissions(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(
        "stat -c '%a %U %G %n' /opt/delve /opt/delve/delved /etc/delve /etc/delve/delve.env "
        "/etc/delve/apple-storekit-root-certs.pem /var/lib/delve"
    )
    assert listing.splitlines() == [
        "755 root root /opt/delve",
        "755 root root /opt/delve/delved",
        "750 root delve /etc/delve",
        "640 root delve /etc/delve/delve.env",
        "644 root delve /etc/delve/apple-storekit-root-certs.pem",
        "750 delve delve /var/lib/delve",
    ]
    assert smoke_host.out("test -f /var/lib/delve/delve.db && echo yes") == "yes"
    assert smoke_host.out("getent passwd delve | cut -d: -f6,7") == "/var/lib/delve:/usr/sbin/nologin"


def test_traefik_routes_to_delve(smoke_host: SmokeHost, deployed: Deployed) -> None:
    body = smoke_host.out(f"curl -ksS --resolve {HOST}:443:127.0.0.1 https://{HOST}/health")
    assert '"ok"' in body


def test_no_secret_on_disk_outside_the_env_file(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /etc /opt/delve --exclude=delve.env || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
