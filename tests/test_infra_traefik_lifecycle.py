"""Traefik backup, restore and removal against the fake connector."""

import json
import shlex
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
from ops_deploy.infra.traefik_backup import _canonical, _dynamic_tree_check, _resolved_paths
from ops_deploy.infra.traefik_lifecycle_state import NAMES_SCRIPT, PATH_SCRIPT
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

STAMP = "20261014T120000"
ENROLLED = {"test -e /var/lib/traefik-transactions": ["enrolled"]}


def backup(cfg: TraefikBackupConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    base = {"date +%Y%m%dT%H%M%S": [STAMP], "stat -c %a ": ["700"]}
    base[_dynamic_tree_check(cfg.dynamic_dir) + " && echo yes"] = ["yes"]
    base[_resolved_paths(cfg.root, cfg.dynamic_dir)] = [_canonical(cfg.root), _canonical(cfg.dynamic_dir)]

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
    from ops_deploy.infra.traefik_backup import RESTORE_SCRIPT

    command = shlex.join(["python3", "-I", "-c", RESTORE_SCRIPT]) + " validate"
    selected = None
    if cfg.archive == "latest" and responses.get("find /opt/backups/traefik -maxdepth 1"):
        selected = "/opt/backups/traefik/manual-2.tar.gz"
    elif cfg.archive != "latest":
        candidate = cfg.archive if cfg.archive.startswith("/") else cfg.root + "/" + cfg.archive
        if responses.get("test -e " + candidate):
            selected = candidate
    metadata = {
        shlex.join(["python3", "-I", "-c", PATH_SCRIPT, "/var/lib/traefik-transactions"]): [
            json.dumps(
                {"mode": 0o40700, "uid": 0, "gid": 0}
                if responses.get("test -e /var/lib/traefik-transactions")
                else None
            )
        ],
        command: [json.dumps({"valid": True, "archive": selected})] if selected else ["ops-deploy-probe-failed"],
    }
    return run_deploy_fake(deploy_traefik_restore, cfg, responses={**responses, **metadata})


LATEST = {"find /opt/backups/traefik -maxdepth 1": ["1760000000.5 /opt/backups/traefik/manual-2.tar.gz"]}


def test_restore_of_latest_archive_puts_acme_back() -> None:
    result = restore(TraefikRestoreConfig(include_acme=True), LATEST)

    assert result.succeeded, result.error
    (script,) = result.executed_commands
    assert script.endswith(" apply")
    # Real archive validation/publication and strict repeat are exercised by
    # test_traefik_restore_host against synthetic filesystem state.
    payload = json.loads(result.stdin[-1][1])
    assert payload["archive"] == "/opt/backups/traefik/manual-2.tar.gz"
    assert payload["include_acme"] is True


def test_restore_without_acme_restores_nothing() -> None:
    result = restore(TraefikRestoreConfig(), LATEST)

    assert result.succeeded, result.error
    assert json.loads(result.stdin[-1][1])["include_acme"] is False


def test_restore_of_named_archive_must_exist() -> None:
    cfg = TraefikRestoreConfig(archive="manual-1.tar.gz")

    assert "validation failed before mutation" in str(restore(cfg, {}).error)
    found = restore(cfg, {"test -e /opt/backups/traefik/manual-1.tar.gz": ["yes"]})
    assert json.loads(found.stdin[-1][1])["archive"] == "/opt/backups/traefik/manual-1.tar.gz"


def test_restore_without_archives_is_refused() -> None:
    assert "validation failed before mutation" in str(restore(TraefikRestoreConfig(), {}).error)


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
    # Explicit metadata answers replace the legacy test-e/find answers. Unknown
    # product queries still receive no answer and must refuse, never mean absent.
    metadata: dict[str, Any] = {}
    paths = [
        "/var/lib/traefik-transactions",
        cfg.binary_path,
        cfg.config_dir,
        cfg.log_dir,
        cfg.static_config or f"{cfg.config_dir}/traefik.toml",
        cfg.dynamic_dir or f"{cfg.config_dir}/dynamic",
        cfg.acme_dir or f"{cfg.config_dir}/acme",
        f"/etc/systemd/system/{cfg.service_name}.service",
        "/etc/logrotate.d/traefik",
    ]
    for path in paths:
        present = any(k.startswith(f"test -e {path}") and v for k, v in responses.items())
        value = {"uid": 0, "gid": 0, "mode": 0o100600} if present else None
        metadata[shlex.join(["python3", "-I", "-c", PATH_SCRIPT, path])] = [json.dumps(value)]
    for path in [cfg.config_dir, "/tmp"]:
        listed = responses.get(f"find {path} -mindepth 1", [])
        metadata[shlex.join(["python3", "-I", "-c", NAMES_SCRIPT, path])] = [
            json.dumps([Path(name).name for name in listed])
        ]
    return run_deploy_fake(deploy_traefik_remove, cfg, responses={**responses, **metadata})


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
        "ufw delete allow 80/tcp || true",
        "ufw delete allow 443/tcp || true",
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


def test_optional_restore_mount_is_checked_with_bash_before_archive_validation() -> None:
    from ops_deploy.services._lifecycle.local_backup import mount_check

    cfg = TraefikRestoreConfig(required_mount="/owned-mount", staging_dir="/owned-mount/stage", dry_run=True)
    assert cfg.required_mount is not None
    command = shlex.join(["bash", "-c", mount_check(cfg.required_mount, cfg.staging_dir)])
    result = restore(cfg, {**LATEST, command: ["mounted"]})
    assert result.succeeded, result.error
    assert not result.uploads
    assert all(op.read_only for op in result.ops)
    assert any(command in event.value for event in result.events if event.kind == "fact")
    refused = restore(cfg, {**LATEST, command: ["ops-deploy-probe-failed"]})
    assert not refused.succeeded
    assert "required restore mount is unavailable" in str(refused.error)
    assert not refused.executed_commands
    assert not refused.uploads


@pytest.mark.parametrize("archive", ["../elsewhere.tar.gz", "child/../../elsewhere.zip"])
def test_relative_restore_archive_must_stay_below_root(archive: str) -> None:
    with pytest.raises(ValueError, match="below the backup root"):
        TraefikRestoreConfig(archive=archive)


@pytest.mark.parametrize(
    "path", ["/usr/local/bin", "/usr/bin", "/bin", "/sbin", "/usr/sbin", "/etc/systemd", "/etc/systemd/system"]
)
def test_traefik_remove_refuses_shared_executable_and_unit_roots(path: str) -> None:
    with pytest.raises(ValueError, match="declared Traefik resource"):
        TraefikRemoveConfig(confirm=True, binary_path=path)


def test_service_name_keeps_original_literal_unit_file_suffix_contract() -> None:
    # Original role writes {{ traefik_service_name }}.service literally even
    # when an operator supplied an existing suffix; systemctl normalizes control.
    cfg = TraefikRemoveConfig(confirm=True, service_name="custom.service")
    result = remove(
        cfg,
        {
            "cat /proc/1/comm": ["systemd"],
            "for unit in custom.service": [
                "Id=custom.service",
                "LoadState=loaded",
                "ActiveState=active",
                "UnitFileState=enabled",
                "---",
            ],
            **fakehost.file("/etc/systemd/system/custom.service.service", "owned unit"),
        },
    )
    assert result.succeeded, result.error
    assert "systemctl stop custom.service || true" in result.executed_commands
    assert "rm -f /etc/systemd/system/custom.service.service" in result.executed_commands


def test_literal_spaced_lifecycle_paths_keep_other_validation_and_backup_contracts() -> None:
    restore_cfg = TraefikRestoreConfig(
        root="/custom archives",
        archive="chosen archive.tar.gz",
        required_mount="/custom disk",
        staging_dir="/custom disk/restore stage",
        acme_path="/custom live/acme state.json",
        acme_dir="/custom live",
    )
    assert restore_cfg.root == "/custom archives"
    assert restore_cfg.archive == "chosen archive.tar.gz"
    assert restore_cfg.staging_dir == "/custom disk/restore stage"
    remove_cfg = TraefikRemoveConfig(
        confirm=True, binary_path="/custom bin/traefik", config_dir="/custom config", log_dir="/custom logs"
    )
    assert remove_cfg.binary_path == "/custom bin/traefik"
    for archive in ["../chosen archive.tar.gz", "chosen;command.tar.gz", "chosen\narchive.tar.gz"]:
        with pytest.raises(ValueError, match="validation error"):
            TraefikRestoreConfig(archive=archive)
    # The established deployment/backup shared path policy is unchanged.
    with pytest.raises(ValueError, match="validation error"):
        TraefikBackupConfig(root="/custom archives")
