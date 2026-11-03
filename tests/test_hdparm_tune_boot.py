"""The hdparm_tune boot oneshot: role-byte parity, enable-only rollout, removal."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.hdparm_tune import HdparmDevice, HdparmTuneConfig, deploy_hdparm_tune
from ops_deploy.infra.hdparm_tune.render import render_block, render_boot
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

ORACLE = json.loads((Path(__file__).parent / "parity/hdparm_boot_apply.json").read_text())
TEMPLATES = Path(__file__).parents[1] / "src/ops_deploy/infra/hdparm_tune/templates"
SCRIPT = "/usr/local/sbin/hdparm-tune-apply"
UNIT = "/etc/systemd/system/hdparm-tune.service"
SERVICE = "hdparm-tune.service"


def policy(**fields: Any) -> HdparmTuneConfig:
    devices = (
        HdparmDevice(device="/dev/disk/by-id/owned-a", apm=127, spindown_time=241),
        HdparmDevice(device="/dev/disk/by-id/owned-b", apm=127, spindown_time=241),
    )
    return HdparmTuneConfig(**{"devices": devices, "apply_now": True, **fields})


def host(cfg: HdparmTuneConfig, *, script: bool = False, unit: bool = False, enabled: bool = False) -> dict[str, Any]:
    """Systemd Ubuntu host with hdparm installed and a current hdparm.conf block."""

    responses: dict[str, Any] = {
        "Owned hdparm block reconciliation": ['{"state": "current", "physical_state": "not_queried"}'],
        **fakehost.UBUNTU,
        **fakehost.deb_installed("hdparm"),
        **fakehost.service(SERVICE, running=False, enabled=enabled),
        **fakehost.directory("/usr/local/sbin"),
        **fakehost.directory("/etc/systemd/system"),
    }
    if script:
        responses.update(fakehost.file(SCRIPT, render_boot(cfg, "script"), mode="-rwxr-xr-x"))
    if unit:
        responses.update(fakehost.file(UNIT, render_boot(cfg, "unit")))
    return responses


def never_wakes_a_disk(commands: list[str]) -> None:
    for command in commands:
        assert "hdparm -" not in command
        assert not any(f"systemctl {verb}" in command for verb in ("start", "restart", "reload-or", "try-restart"))


@pytest.mark.parametrize("case", ORACLE["cases"])
def test_boot_resources_match_the_actual_ansible_rendering(case: dict[str, Any]) -> None:
    cfg = HdparmTuneConfig.model_validate(case["inputs"])
    assert render_boot(cfg, "script") == case["outputs"]["script"]
    assert render_boot(cfg, "unit") == case["outputs"]["unit"]


def test_vendored_templates_match_the_reviewed_role() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if library is None:
        pytest.skip("OPS_LIBRARY_PATH not set")
    source = Path(library) / "roles/hdparm_tune/templates"
    for path in source.glob("hdparm-tune*.j2"):
        assert (TEMPLATES / path.name).read_bytes() == path.read_bytes()


def test_role_defaults() -> None:
    cfg = HdparmTuneConfig()
    assert (cfg.apply_on_boot, cfg.boot_service_name, cfg.boot_script_path, cfg.boot_device_wait_sec) == (
        True,
        SERVICE,
        SCRIPT,
        60,
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"boot_service_name": "hdparm-tune.timer"},
        {"boot_service_name": "../owned.service"},
        {"boot_service_name": ".service"},
        {"boot_script_path": "relative"},
        {"boot_script_path": "/usr/local/sbin/"},
        {"boot_script_path": "/usr/../owned"},
        {"boot_script_path": "/usr/./owned"},
        {"boot_script_path": "/"},
        {"boot_device_wait_sec": -1},
        {"boot_device_wait_sec": True},
        {"apply_on_boot": "yes"},
    ],
)
def test_invalid_boot_settings_refuse(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HdparmTuneConfig(**fields)


def test_fresh_host_installs_and_enables_the_unit_without_starting_it() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_hdparm_tune, cfg, responses=host(cfg))

    assert run.succeeded, run.error
    assert run.written(SCRIPT) == render_boot(cfg, "script").encode()
    assert run.written(UNIT) == render_boot(cfg, "unit").encode()
    commands = run.executed_commands
    assert "systemctl daemon-reload" in commands
    assert "systemctl enable hdparm-tune.service" in commands
    assert commands.index("systemctl daemon-reload") < commands.index("systemctl enable hdparm-tune.service")
    assert any(f"chmod 755 {SCRIPT}" in command for command in commands)
    assert any(f"chmod 644 {UNIT}" in command for command in commands)
    never_wakes_a_disk(commands)
    # The unchanged hdparm.conf block applies nothing now, despite apply_now.
    assert not any("Owned hdparm block reconciliation" in command for command in commands)


def test_second_run_is_a_noop() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_hdparm_tune, cfg, responses=host(cfg, script=True, unit=True, enabled=True))

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []


def test_changed_script_only_reinstalls_the_script() -> None:
    cfg = policy()
    responses = host(cfg, unit=True, enabled=True)
    responses.update(fakehost.file(SCRIPT, "#!/bin/bash\nexit 0\n", mode="-rwxr-xr-x"))
    run = run_deploy_fake(deploy_hdparm_tune, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.written_paths == [SCRIPT]
    assert "systemctl daemon-reload" not in run.executed_commands
    never_wakes_a_disk(run.executed_commands)


@pytest.mark.parametrize("cfg", [policy(apply_on_boot=False), HdparmTuneConfig()])
def test_opt_out_or_no_devices_disables_and_removes_unit_and_script(cfg: HdparmTuneConfig) -> None:
    responses = host(policy(), script=True, unit=True, enabled=True)
    run = run_deploy_fake(deploy_hdparm_tune, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.written_paths == []
    commands = run.executed_commands
    assert commands.index("systemctl disable hdparm-tune.service") < next(
        n for n, command in enumerate(commands) if f"rm -f {UNIT}" in command
    )
    assert any(f"rm -f {SCRIPT}" in command for command in commands)
    assert commands[-1] == "systemctl daemon-reload"
    never_wakes_a_disk(commands)


def test_opt_out_on_a_host_without_the_unit_changes_nothing() -> None:
    cfg = policy(apply_on_boot=False)
    run = run_deploy_fake(deploy_hdparm_tune, cfg, responses=host(cfg))

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert not any("systemctl" in command for command in run.fact_commands if SERVICE in command)


def test_boot_unit_needs_systemd() -> None:
    cfg = policy()
    responses = {**host(cfg), "cat /proc/1/comm": ["init"]}
    run = run_deploy_fake(deploy_hdparm_tune, cfg, responses=responses)

    assert not run.succeeded
    assert "systemd" in str(run.error)


def block_device() -> str | None:
    """Any block device node of this machine; the fake hdparm never opens it."""

    for path in sorted(Path("/dev").iterdir()):
        try:
            if stat.S_ISBLK(path.stat().st_mode) and re.fullmatch(r"[A-Za-z0-9_.+/-]+", str(path)):
                return str(path)
        except OSError:
            continue
    return None


def run_boot_script(tmp_path: Path, cfg: HdparmTuneConfig) -> tuple[subprocess.CompletedProcess[str], Path]:
    calls = tmp_path / "calls"
    (tmp_path / "hdparm").write_text(f'#!/bin/sh\necho "$@" >> {calls}\n')
    (tmp_path / "hdparm").chmod(0o755)
    script = tmp_path / "apply"
    script.write_text(render_boot(cfg, "script"))
    result = subprocess.run(
        ["bash", str(script)],
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    return result, calls


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_boot_script_applies_each_present_device_once(tmp_path: Path) -> None:
    device = block_device()
    if device is None:
        pytest.skip("no block device node on this machine")
    cfg = HdparmTuneConfig(devices=(HdparmDevice(device=device, apm=127, acoustic_management=128, spindown_time=241),))
    result, calls = run_boot_script(tmp_path, cfg)
    assert result.returncode == 0, result.stderr
    assert calls.read_text() == f"-B 127 -M 128 -S 241 {device}\n"
    assert result.stdout == f"hdparm-tune: applied -B 127 -M 128 -S 241 to {device}\n"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_boot_script_reports_a_missing_device_and_still_applies_the_rest(tmp_path: Path) -> None:
    cfg = HdparmTuneConfig(
        devices=(
            HdparmDevice(device="/dev/owned-missing-hdparm-disk", apm=127),
            HdparmDevice(device="/dev/null", spindown_time=241),
        ),
        boot_device_wait_sec=0,
    )
    result, calls = run_boot_script(tmp_path, cfg)
    assert result.returncode == 1
    assert "/dev/owned-missing-hdparm-disk not found after 0s" in result.stderr
    # /dev/null is a character device, not a block device: also reported, never passed to hdparm.
    assert "/dev/null not found after 0s" in result.stderr
    assert not calls.exists()


def test_block_rendering_is_unchanged_by_boot_settings() -> None:
    assert render_block(policy(apply_on_boot=False, boot_device_wait_sec=1)) == render_block(policy())
