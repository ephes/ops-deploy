"""Traefik backup, restore and removal against the fake connector."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.infra import (
    TraefikBackupConfig,
    TraefikRemoveConfig,
    TraefikRestoreConfig,
    deploy_traefik_backup,
    deploy_traefik_remove,
    deploy_traefik_restore,
)
from ops_deploy.infra.traefik_backup import _dynamic_tree_check
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

STAMP = "20261014T120000"
ENROLLED = {"test -e /var/lib/traefik-transactions": ["enrolled"]}


def backup(cfg: TraefikBackupConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    base = {"date +%Y%m%dT%H%M%S": [STAMP], "stat -c %a ": ["700"]}
    base[_dynamic_tree_check(cfg.dynamic_dir) + " && echo yes"] = ["yes"]

    def download(_self: FakeConnector, _source: str, destination: str, **_kwargs: Any) -> bool:
        Path(destination).write_bytes(b"synthetic downloaded archive")
        Path(destination).chmod(0o644)
        return True

    with patch.object(FakeConnector, "get_file", download):
        return run_deploy_fake(deploy_traefik_backup, cfg, responses={**base, **(responses or {})})


def test_backup_without_acme_writes_metadata_and_archive(tmp_path: Path) -> None:
    local = tmp_path / "backups"
    result = backup(TraefikBackupConfig(local_dir=local))

    assert result.succeeded, result.error
    assert result.upload("/opt/backups/traefik/manual-20261014T120000/metadata.yml") == (
        b"timestamp: 20261014T120000\nacme_path: /etc/traefik/acme/acme.json\n"
        b"include_acme: false\ndynamic_dir: /etc/traefik/dynamic\ninclude_dynamic: true\n"
    )
    assert not any("acme.json" in command and "install" in command for command in result.executed_commands)
    assert (
        "(umask 077 && tar -czf /opt/backups/traefik/manual-20261014T120000.tar.gz "
        "-C /opt/backups/traefik -- manual-20261014T120000 "
        "&& chmod 0600 /opt/backups/traefik/manual-20261014T120000.tar.gz)"
    ) in result.executed_commands
    assert "Traefik backup | Fetch the backup archive" in result.changed_ops
    assert local.is_dir()
    assert local.stat().st_mode & 0o777 == 0o700
    assert (local / "manual-20261014T120000.tar.gz").stat().st_mode & 0o777 == 0o600


def test_backup_with_acme_copies_it_root_only() -> None:
    cfg = TraefikBackupConfig(include_acme=True, fetch_local=False, prefix="pre-update")

    result = backup(cfg, {"test -e /etc/traefik/acme/acme.json": ["yes"]})

    assert result.succeeded, result.error
    assert (
        "install -o root -g root -m 0600 /etc/traefik/acme/acme.json "
        "/opt/backups/traefik/pre-update-20261014T120000/acme/acme.json"
    ) in result.executed_commands
    assert "Traefik backup | Fetch the backup archive" not in result.changed_ops


def test_backup_with_missing_acme_is_refused() -> None:
    result = backup(TraefikBackupConfig(include_acme=True))

    assert "ACME state file not found" in str(result.error)
    assert result.executed_commands == []


def test_backup_is_allowed_on_transaction_managed_hosts() -> None:
    assert backup(TraefikBackupConfig(fetch_local=False), ENROLLED).succeeded


def restore(cfg: TraefikRestoreConfig, responses: dict[str, Any]) -> FakeRun:
    return run_deploy_fake(deploy_traefik_restore, cfg, responses=responses)


LATEST = {"find /opt/backups/traefik -maxdepth 1": ["1760000000.5 /opt/backups/traefik/manual-2.tar.gz"]}


def test_restore_of_latest_archive_puts_acme_back() -> None:
    result = restore(TraefikRestoreConfig(include_acme=True), LATEST)

    assert result.succeeded, result.error
    (script,) = result.executed_commands
    assert script.startswith(
        "set -e; rm -rf /tmp/traefik-restore; mkdir -m 0700 /tmp/traefik-restore; "
        "tar -xzf /opt/backups/traefik/manual-2.tar.gz -C /tmp/traefik-restore; "
    )
    assert 'install -o root -g root -m 0600 "$payload"/acme/acme.json /etc/traefik/acme/acme.json' in script
    assert script.endswith("rm -rf /tmp/traefik-restore")


def test_restore_without_acme_restores_nothing() -> None:
    result = restore(TraefikRestoreConfig(), LATEST)

    assert result.succeeded, result.error
    assert "acme.json" not in result.executed_commands[0]


def test_restore_of_named_archive_must_exist() -> None:
    cfg = TraefikRestoreConfig(archive="manual-1.tar.gz")

    assert "archive not found: /opt/backups/traefik/manual-1.tar.gz" in str(restore(cfg, {}).error)
    found = restore(cfg, {"test -e /opt/backups/traefik/manual-1.tar.gz": ["yes"]})
    assert "tar -xzf /opt/backups/traefik/manual-1.tar.gz" in found.executed_commands[0]


def test_restore_without_archives_is_refused() -> None:
    assert "no Traefik backup archives" in str(restore(TraefikRestoreConfig(), {}).error)


@pytest.mark.parametrize("enrolled", [True, False])
def test_restore_refuses_transaction_managed_hosts(enrolled: bool) -> None:
    cfg = TraefikRestoreConfig(transaction_required=not enrolled)

    result = restore(cfg, {**LATEST, **(ENROLLED if enrolled else {})})

    assert "guarded Traefik transaction workflow" in str(result.error)
    assert result.executed_commands == []


def installed(**extra: Any) -> dict[str, Any]:
    present = (
        "/usr/local/bin/traefik",
        "/etc/traefik/traefik.toml",
        "/etc/traefik/dynamic",
        "/etc/traefik/acme",
        "/etc/traefik",
        "/var/log/traefik",
    )
    return {
        "cat /proc/1/comm": ["systemd"],
        "for unit in traefik.service": [
            "Id=traefik.service",
            "LoadState=loaded",
            "ActiveState=active",
            "UnitFileState=enabled",
            "---",
        ],
        **fakehost.file("/etc/systemd/system/traefik.service", "[Unit]\n"),
        "test -e /etc/systemd/system/traefik.service &&": ["yes"],
        **{f"test -e {path} &&": ["yes"] for path in present},
        "test -e /etc/logrotate.d/traefik &&": ["yes"],
        "find /etc/traefik -mindepth 1": [
            "/etc/traefik/traefik.toml",
            "/etc/traefik/dynamic",
            "/etc/traefik/acme",
        ],
        "command -v ufw": ["/usr/sbin/ufw"],
        "ufw show added": ["ufw allow 80/tcp", "ufw allow 443/tcp"],
        "find /tmp -mindepth 1": ["/tmp/traefik-restore"],
        **extra,
    }


CONFIRMED = TraefikRemoveConfig(confirm=True)


def remove(cfg: TraefikRemoveConfig, responses: dict[str, Any]) -> FakeRun:
    return run_deploy_fake(deploy_traefik_remove, cfg, responses=responses)


def test_removal_keeps_routes_and_certificates_by_default() -> None:
    result = remove(CONFIRMED, installed())

    assert result.succeeded, result.error
    assert result.executed_commands == [
        "systemctl stop traefik.service || true",
        "systemctl disable traefik.service || true",
        "rm -f /etc/systemd/system/traefik.service",
        "systemctl daemon-reload",
        "rm -rf /usr/local/bin/traefik",
        "rm -rf /etc/traefik/traefik.toml",
        "rm -rf /var/log/traefik",
        "rm -rf /etc/logrotate.d/traefik",
        "ufw delete allow 80/tcp",
        "ufw delete allow 443/tcp",
        "rm -rf /tmp/traefik-restore",
    ]


def test_complete_removal_takes_everything() -> None:
    result = remove(CONFIRMED.model_copy(update={"force_complete": True}), installed())

    assert result.succeeded, result.error
    commands = result.executed_commands
    for path in ("/etc/traefik/dynamic", "/etc/traefik/acme", "/etc/traefik"):
        assert f"rm -rf {path}" in commands
    assert commands.index("rm -rf /etc/traefik/acme") < commands.index("rm -rf /etc/traefik")


def test_config_dir_with_other_files_is_kept() -> None:
    cfg = CONFIRMED.model_copy(update={"force_complete": True})
    listing = {"find /etc/traefik -mindepth 1": ["/etc/traefik/dynamic", "/etc/traefik/extra.toml", "/etc/traefik/.x"]}

    result = remove(cfg, installed(**listing))

    assert "rm -rf /etc/traefik" not in result.executed_commands


def test_hidden_entries_do_not_keep_the_config_dir() -> None:
    cfg = CONFIRMED.model_copy(update={"force_complete": True})
    listing = {"find /etc/traefik -mindepth 1": ["/etc/traefik/traefik.toml", "/etc/traefik/.keep"]}

    assert "rm -rf /etc/traefik" in remove(cfg, installed(**listing)).executed_commands


def test_second_removal_changes_nothing() -> None:
    gone = {
        "cat /proc/1/comm": ["systemd"],
        "for unit in traefik.service": ["Id=traefik.service", "LoadState=not-found", "ActiveState=inactive", "---"],
        "command -v ufw": ["/usr/sbin/ufw"],
    }

    result = remove(CONFIRMED, gone)

    assert result.succeeded, result.error
    assert result.changed_ops == []


def test_removal_needs_confirmation() -> None:
    result = remove(TraefikRemoveConfig(), installed())

    assert "removal not confirmed" in str(result.error)
    assert result.executed_commands == []


@pytest.mark.parametrize("enrolled", [True, False])
def test_removal_refuses_transaction_managed_hosts(enrolled: bool) -> None:
    cfg = CONFIRMED.model_copy(update={"transaction_required": not enrolled})
    responses = ENROLLED if enrolled else {}

    result = remove(cfg, {**responses, **installed()})

    assert "guarded Traefik transaction workflow" in str(result.error)
    assert result.executed_commands == []
