from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import SystemdUnitMasksConfig, UnitMask, deploy_systemd_unit_masks
from ops_deploy.testing import run_deploy_fake
from tests.fakehost import LINUX
from tests.test_base_headless_mode import SYSTEMD, units


def run(cfg: SystemdUnitMasksConfig, *states: tuple[str, str, str]) -> Any:
    return run_deploy_fake(deploy_systemd_unit_masks, cfg, responses={**SYSTEMD, **units(*states)})


def test_stops_masks_and_resets_a_running_unit() -> None:
    cfg = SystemdUnitMasksConfig(units=(UnitMask(unit="openipmi.service", reason="no BMC"),))

    result = run(cfg, ("loaded", "active", "enabled"))

    assert result.succeeded, result.error
    assert result.executed_commands == [
        "systemctl stop openipmi.service || true",
        "systemctl mask openipmi.service",
        "systemctl reset-failed openipmi.service 2>/dev/null || true",
    ]
    assert result.changed_ops == ["systemd unit masks | Mask openipmi.service (no BMC)"]


def test_masked_failed_unit_only_gets_its_failed_state_cleared() -> None:
    cfg = SystemdUnitMasksConfig(units=(UnitMask(unit="openipmi.service"),))

    result = run(cfg, ("masked", "failed", "masked"))

    assert result.executed_commands == ["systemctl reset-failed openipmi.service"]


def test_converged_host_changes_nothing() -> None:
    cfg = SystemdUnitMasksConfig(units=(UnitMask(unit="a.service"),), unmask=("b.timer",))

    # Order of the fact: unmask list first, then masks.
    result = run(cfg, ("loaded", "inactive", "enabled"), ("masked", "inactive", "masked"))

    assert result.succeeded, result.error
    assert result.changed_ops == []


def test_unmasks_a_unit_no_longer_listed() -> None:
    cfg = SystemdUnitMasksConfig(unmask=("b.timer",))

    result = run(cfg, ("masked", "inactive", "masked"))

    assert result.executed_commands == ["systemctl unmask b.timer"]


def test_options_off_only_mask() -> None:
    cfg = SystemdUnitMasksConfig(units=(UnitMask(unit="a.service"),), stop_now=False, reset_failed=False)

    result = run(cfg, ("loaded", "failed", "enabled"))

    assert result.executed_commands == ["systemctl mask a.service"]


def test_no_units_gathers_no_unit_facts() -> None:
    result = run_deploy_fake(deploy_systemd_unit_masks, SystemdUnitMasksConfig(), responses=SYSTEMD)

    assert result.succeeded, result.error
    assert not any("for unit in" in command for command in result.fact_commands)


def test_refuses_non_systemd_host() -> None:
    result = run_deploy_fake(deploy_systemd_unit_masks, SystemdUnitMasksConfig(), responses=LINUX)

    assert "requires a systemd-managed host" in str(result.error)


@pytest.mark.parametrize("unit", ["openipmi", "", "a b.service", "x.service;reboot"])
def test_rejects_units_without_a_type_suffix_or_with_odd_characters(unit: str) -> None:
    with pytest.raises(ValidationError):
        UnitMask(unit=unit)


def test_rejects_a_unit_in_both_lists() -> None:
    with pytest.raises(ValidationError, match="both masked and unmasked"):
        SystemdUnitMasksConfig(units=(UnitMask(unit="a.service"),), unmask=("a.service",))


def test_runtime_mask_gets_a_persistent_mask() -> None:
    cfg = SystemdUnitMasksConfig(units=(UnitMask(unit="a.service"),))

    result = run(cfg, ("masked", "inactive", "masked-runtime"))

    assert result.executed_commands == ["systemctl mask a.service"]
