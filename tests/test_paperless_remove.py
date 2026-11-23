"""The paperless_remove port; synthetic units, paths, accounts and databases only."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.paperless import PaperlessRemoveConfig, remove_paperless
from ops_deploy.services.paperless.commands import host_command
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

UNITS = ("paperless", "paperless-worker", "paperless-scheduler", "paperless-consumer")
ROUTE = "/etc/traefik/dynamic/paperless.yml"
SSHD = "/etc/ssh/sshd_config.d/sftp-scanner.conf"
SITE = "/home/paperless/site"
STORAGE = "/mnt/cryptdata/paperless"
FSTAB_HELPER = host_command("scanner_fstab_absent")
FSTAB_LINE = "/mnt/cryptdata/paperless/consume /srv/sftp-scanner/inbox none bind 0 0"
# What `just remove-one paperless` passes besides the confirmation and the
# three names the role never reads (ops-control justfiles/remove.just).
RECIPE = (
    "remove_site_root",
    "remove_virtualenv",
    "remove_current_symlink",
    "remove_temp_dir",
    "remove_media_dir",
    "remove_data_dir",
    "remove_consume_dir",
    "remove_export_dir",
    "remove_backup_dir",
    "remove_tmp_dir",
    "remove_postgres_database",
    "remove_postgres_user",
    "remove_user",
    "remove_group",
    "remove_scanner_user",
    "remove_sftp_chroot",
)


def full(**values: Any) -> PaperlessRemoveConfig:
    return PaperlessRemoveConfig.model_validate({"confirm": True, **dict.fromkeys(RECIPE, True), **values})


def test_defaults() -> None:
    assert PaperlessRemoveConfig().model_dump(mode="json") == {
        "confirm": False,
        "external_storage_root": "/mnt/cryptdata/paperless",
        "group": "paperless",
        "home_path": "/home/paperless",
        "postgres_become_user": "postgres",
        "postgres_database": "paperless",
        "postgres_user": "paperless",
        "remove_backup_dir": False,
        "remove_consume_dir": False,
        "remove_current_symlink": True,
        "remove_data_dir": False,
        "remove_export_dir": False,
        "remove_group": False,
        "remove_media_dir": False,
        "remove_postgres_database": False,
        "remove_postgres_user": False,
        "remove_scanner_config": True,
        "remove_scanner_user": False,
        "remove_service_units": True,
        "remove_sftp_chroot": False,
        "remove_site_root": True,
        "remove_temp_dir": True,
        "remove_tmp_dir": False,
        "remove_traefik_config": True,
        "remove_user": False,
        "remove_virtualenv": True,
        "scanner_sshd_config_path": "/etc/ssh/sshd_config.d/sftp-scanner.conf",
        "scanner_username": "scanner",
        "service_units": ["paperless", "paperless-worker", "paperless-scheduler", "paperless-consumer"],
        "sftp_chroot_dir": "/srv/sftp-scanner",
        "site_root": "/home/paperless/site",
        "systemd_unit_dir": "/etc/systemd/system",
        "temp_dir": "/tmp/paperless",
        "traefik_config_path": "/etc/traefik/dynamic/paperless.yml",
        "username": "paperless",
    }


def test_derived_defaults_follow_the_given_names() -> None:
    cfg = PaperlessRemoveConfig(username="ppl", remove_site_root=False)
    assert (cfg.home_path, cfg.site_root) == ("/home/ppl", "/home/ppl/site")
    assert cfg.remove_virtualenv is cfg.remove_current_symlink is False
    explicit = PaperlessRemoveConfig(remove_site_root=False, remove_virtualenv=True)
    assert explicit.remove_virtualenv is True
    assert explicit.remove_current_symlink is False


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_paperless, PaperlessRemoveConfig(**dict.fromkeys(RECIPE, True)))
    assert not run.succeeded
    assert "not confirmed" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize(
    "values",
    [
        {"site_root": "/"},
        {"site_root": "/home"},
        {"external_storage_root": "/mnt/cryptdata"},
        {"sftp_chroot_dir": "/srv"},
        {"temp_dir": "/tmp"},
        {"temp_dir": "/tmp/../etc"},
        {"username": "root"},
        {"scanner_username": "root"},
        {"postgres_database": 'x"; drop'},
    ],
)
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        full(**values)


def psql(sql: str) -> str:
    return f"runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -d postgres -c '{sql}'"


def host(
    *, present: bool = True, mounted: bool = True, database: str = "present", fstab_line: bool | None = None
) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    if present:
        for unit in UNITS:
            paths.update(fakehost.file(f"/etc/systemd/system/{unit}.service", "unit"))
        for path in (ROUTE, SSHD, f"{SITE}/.env"):
            paths.update(fakehost.file(path, "x"))
        for path in (
            SITE,
            f"{SITE}/.venv",
            "/tmp/paperless",
            *(f"{STORAGE}/{name}" for name in ("media", "data", "consume", "export", "backup", "tmp")),
            "/srv/sftp-scanner",
        ):
            paths.update(fakehost.directory(path, user="paperless"))
        paths.update(fakehost.symlink(f"{SITE}/paperless-ngx", f"{SITE}/paperless-ngx-3.5.1"))
        paths.update(fakehost.accounts({"paperless": "/home/paperless", "scanner": "/srv/sftp-scanner"}))
    probe = {"success": True, "enabled": present, "active": "active" if present else "inactive"}
    probe["load"] = "loaded" if present else "not-found"
    return {
        **fakehost.LINUX,
        "import json, subprocess, sys": [json.dumps(probe)],
        "mountpoint -q /srv/sftp-scanner/inbox": ["mounted"] if mounted and present else [],
        FSTAB_HELPER: [json.dumps({"change": present if fstab_line is None else fstab_line})],
        "from pg_database where": [database] if present and database else [],
        "from pg_roles where": [database] if present and database else [],
        **paths,
    }


def test_the_recipes_removal_follows_the_role_order() -> None:
    run = run_deploy_fake(remove_paperless, full(), responses=host())
    assert run.succeeded, run.error
    commands = [command for command in run.executed_commands if "import json, subprocess" not in command]
    stops = [f"systemctl {verb} {unit}" for unit in UNITS for verb in ("disable", "stop")]
    assert commands[: len(stops)] == stops
    rest = commands[len(stops) :]
    assert rest[:5] == [f"rm -rf /etc/systemd/system/{unit}.service" for unit in UNITS] + ["systemctl daemon-reload"]
    guard = rest.index(route_guard_command())
    assert rest[guard + 1] == f"rm -rf {ROUTE}"
    removed = [command.removeprefix("rm -rf ") for command in rest[guard + 1 :] if command.startswith("rm -rf ")]
    assert removed == [
        ROUTE,
        SSHD,
        SITE,
        f"{SITE}/.venv",
        f"{SITE}/paperless-ngx",
        f"{SITE}/.env",
        "/tmp/paperless",
        *(f"{STORAGE}/{name}" for name in ("media", "data", "consume", "export", "backup", "tmp")),
        "/srv/sftp-scanner",
    ]
    tail = rest[rest.index("rm -rf /srv/sftp-scanner") - 2 :]
    assert tail == [
        "umount /srv/sftp-scanner/inbox",
        FSTAB_HELPER,
        "rm -rf /srv/sftp-scanner",
        "userdel -r paperless",
        "groupdel paperless",
        "userdel -r scanner",
        psql('DROP DATABASE "paperless"'),
        psql('DROP ROLE "paperless"'),
    ]
    # The storage root, sshd and Traefik are not touched.
    assert f"rm -rf {STORAGE}" not in commands
    assert not any("sshd" in command and "systemctl" in command for command in commands)
    assert not any("traefik" in command and "systemctl" in command for command in commands)
    # The fstab line goes after the unmount, as one helper run with the exact fields on stdin.
    # (pyinfra evaluates the operation while planning and again while executing.)
    payloads = [json.loads(data) for text, data in run.stdin if FSTAB_HELPER in text]
    source, target = f"{STORAGE}/consume", "/srv/sftp-scanner/inbox"
    assert {p["source"] for p in payloads} == {source}
    assert {p["target"] for p in payloads} == {target}
    applied = [json.loads(data) for text, data in run.stdin if text == FSTAB_HELPER]
    assert [p["apply"] for p in applied] == [True]
    # The plan (--dry) lists it by its line.
    assert f"Remove Paperless-ngx | Remove the /etc/fstab line '{FSTAB_LINE}'" in run.planned_changes


def test_role_defaults_keep_data_accounts_and_databases() -> None:
    run = run_deploy_fake(remove_paperless, PaperlessRemoveConfig(confirm=True), responses=host())
    assert run.succeeded, run.error
    removed = [c.removeprefix("rm -rf ") for c in run.executed_commands if c.startswith("rm -rf ")]
    assert removed == [
        *(f"/etc/systemd/system/{unit}.service" for unit in UNITS),
        ROUTE,
        SSHD,
        SITE,
        f"{SITE}/.venv",
        f"{SITE}/paperless-ngx",
        f"{SITE}/.env",
        "/tmp/paperless",
    ]
    commands = "\n".join(run.executed_commands)
    for kept in ("userdel", "groupdel", "umount", "psql", STORAGE, FSTAB_HELPER):
        assert kept not in commands
    # Without remove_sftp_chroot the fstab line is not even inspected.
    assert not any(FSTAB_HELPER in event.value for event in run.events)


def test_kept_site_root_keeps_the_home_on_userdel() -> None:
    run = run_deploy_fake(remove_paperless, full(remove_site_root=False), responses=host())
    assert run.succeeded, run.error
    assert "userdel paperless" in run.executed_commands
    assert f"rm -rf {SITE}" not in run.executed_commands
    assert f"rm -rf {SITE}/.env" not in run.executed_commands


def test_a_removed_install_changes_only_the_unconditional_reload() -> None:
    run = run_deploy_fake(remove_paperless, full(), responses=host(present=False))
    assert run.error is None
    # The systemd tasks fail on absent units; the role ignores that.
    assert run.executed_commands == ["systemctl daemon-reload"]


def test_an_unmounted_inbox_is_not_unmounted() -> None:
    run = run_deploy_fake(remove_paperless, full(), responses=host(mounted=False))
    assert run.succeeded, run.error
    assert not any(command.startswith("umount") for command in run.executed_commands)


def test_unreadable_postgres_state_fails_the_drop() -> None:
    responses = host()
    responses["from pg_database where"] = ["", "ops-deploy-probe-failed"]
    run = run_deploy_fake(remove_paperless, full(), responses=responses)
    assert not run.succeeded
    assert any(event.kind == "function" and "_unreadable" in event.value for event in run.events)
    assert psql('DROP DATABASE "paperless"') not in run.executed_commands


def test_a_failed_userdel_stops_the_removal() -> None:
    responses = {"userdel -r paperless": {"success": False}, **host()}
    run = run_deploy_fake(remove_paperless, full(), responses=responses)
    assert not run.succeeded
    commands = "\n".join(run.executed_commands)
    assert "groupdel" not in commands
    assert "psql" not in commands


def test_an_absent_fstab_line_plans_no_change() -> None:
    run = run_deploy_fake(remove_paperless, full(), responses=host(fstab_line=False))
    assert run.succeeded, run.error
    assert FSTAB_HELPER not in run.executed_commands
    assert not any("fstab" in name for name in run.planned_changes)
    assert {json.loads(data)["apply"] for text, data in run.stdin if FSTAB_HELPER in text} == {False}
    assert "rm -rf /srv/sftp-scanner" in run.executed_commands


def test_the_fstab_line_follows_the_storage_and_chroot_names() -> None:
    cfg = full(external_storage_root="/mnt/vault/ppl", sftp_chroot_dir="/srv/scan")
    assert cfg.scanner_fstab_line == "/mnt/vault/ppl/consume /srv/scan/inbox none bind 0 0"
    run = run_deploy_fake(remove_paperless, cfg, responses=host())
    assert run.succeeded, run.error
    payloads = [json.loads(data) for text, data in run.stdin if FSTAB_HELPER in text]
    assert {(p["source"], p["target"]) for p in payloads} == {("/mnt/vault/ppl/consume", "/srv/scan/inbox")}


@pytest.mark.parametrize("answer", [["", "ops-deploy-probe-failed"], ["not json"], ['{"change": "yes"}']])
def test_an_unreadable_fstab_answer_stops_before_any_change(answer: list[str]) -> None:
    run = run_deploy_fake(remove_paperless, full(), responses={**host(), FSTAB_HELPER: answer})
    assert not run.succeeded
    assert "fstab line inspection failed" in str(run.error)
    # Refused while planning: nothing ran.
    assert not run.executed_commands
