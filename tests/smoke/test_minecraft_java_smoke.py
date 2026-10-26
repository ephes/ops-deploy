"""Real Forge first deploy, converged run, normal update and stopped-state preservation.

Run only against an isolated smoke VM: MINECRAFT_FORGE_SMOKE=1 just smoke
 tests/smoke/test_minecraft_java_smoke.py. This test enables UFW on that fixture.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.minecraft_java import MinecraftJavaConfig, deploy_minecraft_java
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import SmokeHost

pytestmark = pytest.mark.skipif(os.environ.get("MINECRAFT_FORGE_SMOKE") != "1", reason="isolated Forge fixture opt-in")


@pytest.fixture(autouse=True)
def cleanup_fixture(smoke_host: SmokeHost) -> Iterator[None]:
    try:
        yield
    finally:
        smoke_host.run("systemctl disable --now minecraft-fixture 2>/dev/null || true; ufw disable", check=False)


def test_forge_start_update_repeat_and_stopped_preservation(smoke_host: SmokeHost) -> None:
    smoke_host.run(
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw && "
        "ufw allow 22/tcp && ufw --force enable"
    )
    cfg = MinecraftJavaConfig(
        secrets=SecretRef("fixture/minecraft.yml"),
        eula_agreed=True,
        service_name="minecraft-fixture",
        user="mcfixture",
        group="mcfixture",
        home="/opt/minecraft-fixture",
        site_path="/opt/minecraft-fixture/server",
        loader_mode="forge",
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1-47.4.0/forge-1.20.1-47.4.0-installer.jar",
        forge_installer_sha256="f3f57465e2cbdc328193f77ba7f0c94cb64405f31ed556753d9275e8bdc06e2c",
        firewall_allowed_networks=("192.0.2.0/24",),
        memory_min="512M",
        memory_max="1536M",
        startup_timeout=300,
        world_name="fixture-world",
        view_distance=2,
        simulation_distance=2,
    )
    assert cfg.secrets is not None
    values = SecretValues(cfg.secrets, {"rcon_password": "fixture-rcon-password"})

    receipt: dict[str, object] = {"forge_version": cfg.forge_version, "phases": {}}
    phases: dict[str, object] = {}
    receipt["phases"] = phases

    def record() -> None:
        if destination := os.environ.get("MINECRAFT_SMOKE_RECEIPT"):
            Path(destination).write_text(json.dumps(receipt, indent=2) + "\n")

    def deploy(config: MinecraftJavaConfig, label: str) -> SshRun:
        run = run_deploy_ssh(
            deploy_minecraft_java, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        phases[label] = {
            "succeeded": run.succeeded,
            "seconds": run.seconds,
            "mutating_changed_ops": run.mutating_changed_ops,
            "operations": [
                {"name": op.name, "changed": op.changed, "succeeded": op.succeeded, "read_only": op.read_only}
                for op in run.ops
            ],
        }
        record()
        assert run.succeeded, (run.error, [op for op in run.ops if not op.succeeded])
        return run

    first = deploy(cfg, "first")
    assert first.mutating_changed_ops
    pid = smoke_host.out("systemctl show -p MainPID --value minecraft-fixture")
    repeat = deploy(cfg, "repeat")
    assert repeat.mutating_changed_ops == []
    assert smoke_host.out("systemctl show -p MainPID --value minecraft-fixture") == pid
    sentinel = str(cfg.site_path / cfg.world_name / "cutover-preserved.txt")
    smoke_host.run(f"printf retained > {sentinel}; chown mcfixture:mcfixture {sentinel}")
    updated = cfg.model_copy(update={"max_players": 23})
    change = deploy(updated, "update")
    assert any("Restart minecraft-fixture" in op for op in change.mutating_changed_ops)
    assert smoke_host.out(f"cat {sentinel}") == "retained"
    assert smoke_host.out("systemctl show -p MainPID --value minecraft-fixture") != pid
    assert deploy(updated, "update-repeat").mutating_changed_ops == []
    stopped = updated.model_copy(update={"service_state": "stopped"})
    deploy(stopped, "stop")
    assert smoke_host.out("systemctl is-enabled minecraft-fixture") == "enabled"
    before = smoke_host.out(f"find {cfg.site_path / cfg.world_name} -type f -exec sha256sum {{}} + | sort")
    smoke_host.run("ufw disable")
    assert deploy(stopped, "stopped-repeat").mutating_changed_ops == []
    after = smoke_host.out(f"find {cfg.site_path / cfg.world_name} -type f -exec sha256sum {{}} + | sort")
    assert before == after
    assert smoke_host.out("ufw status") == "Status: inactive"
    receipt.update(
        world_hashes_preserved=True, repeat_pid_preserved=True, update_restarted=True, stopped_ufw_inactive=True
    )
    record()
