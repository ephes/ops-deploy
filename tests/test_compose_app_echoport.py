"""compose_app's Echoport part: the target's checks, the upsert step, the host secrets after a restore."""

from __future__ import annotations

import base64
import json
from pathlib import PurePosixPath
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.compose_app import ComposeAppConfig, Echoport, deploy_compose_app
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.compose_app_fixtures import APIKEY, SITE, converged, stack_config, values

PREFIX = "Deploy vpnstack | "
UPSERT = f"{PREFIX}Upsert Echoport backup target vpnstack"
CHECK_PROBE = "if test -e /home/echoport/site/manage.py; then"
SECRET_PROBE = "' secrets-probe )"
FIX = f"{PREFIX}Set host secrets back to root 0600"
DB = f"{SITE}/vpn/state.db"
TARGET = Echoport(
    name="vpnstack",
    description="VPN stack state",
    db_path=DB,
    backup_files=(f"{SITE}/vpn/servers.json", APIKEY),
    schedule="30 3 * * *",
)


def config(**changes: Any) -> ComposeAppConfig:
    return stack_config(echoport=Echoport.model_validate({**TARGET.model_dump(), **changes}))


def deploy(cfg: ComposeAppConfig, secrets: SecretValues, **facts: Any) -> FakeRun:
    responses = {
        **converged(cfg, secrets),
        CHECK_PROBE: ["unchanged"],
        SECRET_PROBE: [f"secret {APIKEY} same"],
        **facts,
    }
    run = run_deploy_fake(deploy_compose_app, cfg, secrets, responses=responses)
    assert run.succeeded, run.error
    return run


def test_a_registered_target_changes_nothing() -> None:
    cfg = config()
    run = deploy(cfg, values(cfg))

    assert run.mutating_changed_ops == []
    probe = next(c for c in run.fact_commands if CHECK_PROBE in c)
    assert '"mode": "check"' in probe
    assert "runuser -u echoport -- env HOME=/home/echoport .venv/bin/python manage.py shell -c" in probe


def test_a_pending_target_is_upserted_with_the_app_defaults() -> None:
    cfg = config()
    run = deploy(cfg, values(cfg), **{CHECK_PROBE: ["pending"]})

    assert run.mutating_changed_ops == [UPSERT]
    apply = next(c for c in run.executed_commands if '"mode": "apply"' in c)
    for fragment in (
        '"service_name": "vpnstack.service"',
        '"restore_owner": "vpnstack:vpnstack"',
        f'"db_path": "{DB}"',
        f'"backup_files": ["{SITE}/vpn/servers.json", "{APIKEY}"]',
        '"schedule": "30 3 * * *"',
        '"schedule_policy": "keep"',
    ):
        assert fragment in apply
    assert apply.endswith("</dev/null")
    assert any("Echoport must be deployed on this host before vpnstack" in c for c in run.executed_commands)


def test_explicit_unit_owner_and_schedule_policy() -> None:
    cfg = config(service_name="other.service", restore_owner="vpnstack:media", update_schedule=True)
    run = deploy(cfg, values(cfg), **{CHECK_PROBE: ["pending"]})

    apply = next(c for c in run.executed_commands if '"mode": "apply"' in c)
    for fragment in (
        '"service_name": "other.service"',
        '"restore_owner": "vpnstack:media"',
        '"schedule_policy": "set"',
    ):
        assert fragment in apply


def test_a_restored_host_secret_goes_back_to_root() -> None:
    cfg = config()
    run = deploy(cfg, values(cfg), **{SECRET_PROBE: [f"secret {APIKEY} differs"]})

    assert run.mutating_changed_ops == [FIX]
    command, stdin = run.stdin[-1]
    assert command.endswith(" secrets-apply")
    assert json.loads(base64.b64decode(stdin)) == {"paths": [APIKEY]}


def test_a_failed_owner_probe_runs_the_repair() -> None:
    cfg = config()
    run = deploy(cfg, values(cfg), **{SECRET_PROBE: [FAILED]})

    assert FIX in run.mutating_changed_ops


def test_missing_or_root_owned_secrets_need_no_repair() -> None:
    cfg = config()
    run = deploy(cfg, values(cfg), **{SECRET_PROBE: [f"secret {APIKEY} missing"]})
    assert run.mutating_changed_ops == []


def test_host_secrets_inside_a_backed_up_directory_are_repaired_too() -> None:
    cfg = config(db_path=None, backup_files=(SITE,))
    assert cfg.echoport_secret_paths == (PurePosixPath(APIKEY),)

    run = deploy(cfg, values(cfg), **{SECRET_PROBE: [f"secret {APIKEY} differs"]})
    assert run.mutating_changed_ops == [FIX]


def test_without_host_secrets_there_is_no_owner_probe() -> None:
    cfg = config(backup_files=(f"{SITE}/vpn/servers.json",))
    run = deploy(cfg, values(cfg))

    assert not any(SECRET_PROBE in c for c in run.fact_commands)


def test_a_failing_check_probe_applies_and_probes_again() -> None:
    cfg = config()
    run = deploy(cfg, values(cfg), **{CHECK_PROBE: [FAILED]})

    assert UPSERT in run.mutating_changed_ops
    assert run.op(f"{PREFIX}Probe again: {UPSERT.removeprefix(PREFIX)}").read_only


def test_no_target_no_echoport() -> None:
    cfg = stack_config()
    run = run_deploy_fake(deploy_compose_app, cfg, values(cfg), responses=converged(cfg, values(cfg)))

    assert run.succeeded, run.error
    assert not any("echoport" in c for c in run.executed_commands + run.fact_commands)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"db_path": None, "backup_files": ()}, "needs a db_path or backup_files"),
        ({"backup_files": (f"{SITE}/vpn/state.db",)}, "echoport paths repeat"),
        ({"backup_files": (f"{SITE}/state.db",)}, "echoport basenames repeat state.db"),
        ({"backup_files": (f"{SITE}/manifest.json",)}, "manifest.json is the archive's own file"),
        ({"backup_files": (f"{SITE}/vpn",)}, "state.db is inside /home/vpnstack/site/vpn"),
        ({"backup_files": (f"{SITE}/vpn/state.db-wal",)}, "come from the online backup"),
        ({"db_path": "/srv/crypt/vpnstack/client/state.db"}, "outside /home/"),
        ({"backup_files": ("/home/other/secret",)}, "neither a declared directory of the app nor its host secret"),
        ({"restore_owner": "vpnstack"}, "restore_owner"),
        ({"schedule": "@daily"}, "schedule"),
        ({"service_name": "vpnstack"}, "service_name"),
    ],
)
def test_target_checks(changes: dict[str, Any], message: str) -> None:
    data = TARGET.model_dump(mode="json")
    data.update({k: list(v) if isinstance(v, tuple) else v for k, v in changes.items()})
    with pytest.raises((ConfigValidationError, ValueError), match=message):
        stack_config(echoport=data)
