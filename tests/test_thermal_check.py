"""thermal_monitoring's check-only deploy: the Nyxmon check of an endpoint another host serves."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services._nyxmon_json_metrics import check_command
from ops_deploy.services.thermal_monitoring import PASSWORD_KEY, ThermalCheckConfig, deploy_thermal_check
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.test_thermal_monitoring import CHECK, PASSWORD, SECRETS

P = "Thermal endpoint check | "
UPSERT = f"{P}Upsert Nyxmon check Example Thermal Freshness"
PROBE = " probe /home/nyxmon/site/db.sqlite3 example-host "

CFG = ThermalCheckConfig.model_validate({"secrets": "secrets/fixture.yml", "nyxmon_check": CHECK})


def run(responses: dict[str, Any], cfg: ThermalCheckConfig = CFG, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_thermal_check, cfg, SECRETS, responses=responses)
    assert result.succeeded is ok, result.error
    return result


def converged(cfg: ThermalCheckConfig = CFG) -> dict[str, Any]:
    login = PASSWORD if cfg.nyxmon_check.auth_username is not None else None
    return {**fakehost.UBUNTU, PROBE: [f"check {cfg.nyxmon_check.digest(login)}"]}


def test_a_converged_check_plans_only_the_privacy_check() -> None:
    result = run(converged())

    assert result.mutating_changed_ops == []
    assert [op.name for op in result.ops if op.changed] == [
        f"{P}Require a private Nyxmon database for Example Thermal Freshness"
    ]
    assert result.uploads == []
    assert result.stdin == []


def test_a_missing_check_is_upserted_with_the_password_on_stdin_only() -> None:
    result = run({**converged(), PROBE: ["check absent"]})

    assert result.mutating_changed_ops == [UPSERT]
    (upsert,) = [(c, s) for c, s in result.stdin if " apply " in c]
    assert json.loads(upsert[1]) == {"check_interval": 300, "data": CFG.nyxmon_check.desired_data(PASSWORD)}
    assert PASSWORD not in result.all_text()


def test_a_failing_probe_upserts_and_probes_again() -> None:
    result = run({**converged(), PROBE: [FAILED]})

    assert result.mutating_changed_ops == [UPSERT]
    assert result.ops[-1].read_only


def test_nothing_but_the_check_happens_on_the_host() -> None:
    result = run({**converged(), PROBE: ["check 0123"]})

    assert all("nyxmon" in c or "db.sqlite3" in c for c in result.executed_commands)
    assert not any(c.startswith(("apt", "systemctl", "useradd")) for c in result.executed_commands)


def test_a_non_private_database_stops_before_the_upsert() -> None:
    guard = check_command(CFG.nyxmon_check, "guard")
    result = run({**converged(), guard: {"success": False}, PROBE: [FAILED]}, ok=False)

    assert not any(" apply " in c for c in result.executed_commands)


NO_LOGIN = ThermalCheckConfig.model_validate(
    {"secrets": "secrets/fixture.yml", "nyxmon_check": {k: v for k, v in CHECK.items() if k != "auth_username"}}
)


@pytest.mark.parametrize("cfg", [CFG, NO_LOGIN], ids=["with login", "without login"])
@pytest.mark.parametrize("password", ["", "CHANGE_ME", "two\nlines"])
def test_unusable_passwords_are_refused(password: str, cfg: ThermalCheckConfig) -> None:
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: password})
    result = run_deploy_fake(deploy_thermal_check, cfg, secrets, responses=converged(cfg))

    assert not result.succeeded
    assert result.ops == []


def test_a_check_without_login_stores_no_password() -> None:
    result = run({**converged(NO_LOGIN), PROBE: ["check absent"]}, NO_LOGIN)

    (upsert,) = [(c, s) for c, s in result.stdin if " apply " in c]
    assert "auth" not in json.loads(upsert[1])["data"]
    assert PASSWORD not in upsert[1]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"nyxmon_check": {**CHECK, "user": "other"}}, "this Nyxmon"),
        ({"nyxmon_check": {**CHECK, "db_path": "/srv/nyxmon/db.sqlite3"}}, "this Nyxmon"),
        ({"nyxmon_check": {**CHECK, "db_path": "/home/nyxmon/site/db.sqlite3.bak"}}, "this Nyxmon"),
        ({"nyxmon_check": None}, "nyxmon_check"),
        ({"secrets": None}, "secrets file"),
    ],
)
def test_bad_configs_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        ThermalCheckConfig.model_validate({"secrets": "secrets/fixture.yml", "nyxmon_check": CHECK, **changes})
