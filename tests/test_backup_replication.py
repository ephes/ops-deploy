"""Exact original backup resources, explicit policy and bounded trust/key admission."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import struct
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.backup import (
    MailReplicationConfig,
    MinioArchiveConfig,
    SnapshotRetention,
    SyncoidConfig,
    SyncoidJob,
    UsbDrive,
    UsbReplicationConfig,
)
from ops_deploy.infra.backup.config import BackupConfig
from ops_deploy.infra.backup.render import render

ROOT = Path(__file__).parents[1]


def helper(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "owned_" + name, ROOT / "src/ops_deploy/infra/files" / ("backup_" + name + ".py")
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def jobs() -> tuple[SyncoidJob, ...]:
    return (SyncoidJob(source="fast/data", target="tank/data"),)


@pytest.mark.parametrize("model", [SyncoidConfig, UsbReplicationConfig, MinioArchiveConfig, MailReplicationConfig])
def test_disabled_original_policy_needs_no_secret_or_runtime_config(model: Any) -> None:
    assert not model(enabled=False).enabled


@pytest.mark.parametrize(
    "changes",
    [
        {"recursive": "true"},
        {"no_rollback": 1},
        {"extra_args": ['--sendoptions="bad"']},
        {"source": "fast/data;bad"},
        {"target": "fast/data"},
    ],
)
def test_ambiguous_or_untyped_replication_flags_refuse(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SyncoidJob.model_validate({"source": "fast/data", "target": "tank/data", **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"anchor_mode": "bookmark"},
        {
            "devices": [
                {"name": "same", "device": "/dev/disk/by-id/a"},
                {"name": "same", "device": "/dev/disk/by-id/b"},
            ],
            "anchor_mode": "bookmark",
        },
        {"devices": [{"name": "a", "device": "/dev/disk/by-id/a"}, {"name": "b", "device": "/dev/disk/by-id/b"}]},
        {"bookmark_prune_prefixes": []},
        {"spindown_enabled": True},
    ],
)
def test_original_usb_rotation_invariants_are_retained(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UsbReplicationConfig.model_validate(
            {
                "pool": "vault",
                "device": "/dev/disk/by-id/single",
                "jobs": [job.model_dump() for job in jobs()],
                **changes,
            }
        )


def test_exact_three_policy_defaults_and_raw_rollback_switch() -> None:
    local = SyncoidConfig(jobs=jobs())
    usb = UsbReplicationConfig(pool="vault", device="/dev/disk/by-id/owned", jobs=jobs())
    mail = MailReplicationConfig(source_host="owned.example")
    archive = MinioArchiveConfig(source_host="owned.example")
    assert local.default_args == ("--no-rollback",)
    assert local.on_calendar == "02:00"
    assert usb.on_calendar == "Sun 04:00"
    assert usb.anchor_mode == "sync_snapshot"
    assert mail.snapshot_keep == 30
    assert mail.on_calendar == "04:00"
    assert archive.on_calendar == "05:00"
    assert not archive.rsync_delete
    assert not archive.require_archives
    assert "--delete" in mail.vmail_rsync_extra_args
    assert "--delete" not in mail.stage_rsync_extra_args
    assert not any("private_key" in name or name == "key" for name in type(mail).model_fields)


@pytest.mark.parametrize(
    "changes",
    [
        {"on_calendar": "01:00\nExecStart=bad"},
        {"source_host": "owned;bad"},
        {"source_path": "/a/../b"},
        {"rsync_extra_args": ["--rsh=$(bad)"]},
        {"spindown_enabled": True},
    ],
)
def test_template_or_path_ambiguity_refuses_before_operations(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MinioArchiveConfig.model_validate({"source_host": "owned.example", **changes})


def test_retention_keeps_original_days_and_managed_prefix_contract() -> None:
    policy = SnapshotRetention(
        source="tank/timemachine",
        target="vault/timemachine",
        keep_days=60,
        prefixes=("autosnap_", "syncoid_fractal_", "syncoid_usb_"),
    )
    assert policy.keep_days == 60
    with pytest.raises(ValidationError):
        SnapshotRetention(source="tank/timemachine", target="vault/timemachine", keep_days=0, prefixes=())


def public_key(kind: str = "ssh-ed25519", payload: bytes = b"public-synthetic-only") -> str:
    return base64.b64encode(struct.pack(">I", len(kind)) + kind.encode() + payload).decode()


def test_known_hosts_fresh_rotation_preserves_unrelated_rows_and_alias_keys() -> None:
    module = helper("known_hosts")
    old = public_key(payload=b"old-public-only")
    new = public_key(payload=b"new-public-only")
    original = (
        "# keep exact\nother ssh-ed25519 "
        + old
        + " other-comment\nowned,alias ssh-ed25519 "
        + old
        + " shared-comment\nowned ssh-rsa "
        + public_key("ssh-rsa")
        + " keep-type\n"
    )
    updated = module.candidate(original, "owned", {("ssh-ed25519", new)})
    assert "# keep exact\nother ssh-ed25519 " + old + " other-comment\n" in updated
    assert "alias ssh-ed25519 " + old + " shared-comment\n" in updated
    assert "owned ssh-rsa " + public_key("ssh-rsa") + " keep-type\n" in updated
    assert updated.endswith("owned ssh-ed25519 " + new + "\n")
    assert module.candidate(updated, "owned", {("ssh-ed25519", new)}) == updated


def test_current_hashed_host_keeps_every_existing_byte() -> None:
    module = helper("known_hosts")
    salt = b"owned-public-hash-salt"
    host = "owned.example"
    key = public_key()
    name = (
        "|1|"
        + base64.b64encode(salt).decode()
        + "|"
        + base64.b64encode(hmac.digest(salt, host.encode(), "sha1")).decode()
    )
    original = "# untouched\n" + name + " ssh-ed25519 " + key + " existing-comment\n"
    assert module.candidate(original, host, {("ssh-ed25519", key)}) == original


def test_explicit_target_revocation_is_not_erased_by_keyscan() -> None:
    module = helper("known_hosts")
    key = public_key()
    with pytest.raises(ValueError, match="marked target"):
        module.candidate("@revoked owned ssh-ed25519 " + key + "\n", "owned", {("ssh-ed25519", key)})


def test_secret_path_symlink_refuses_before_content_read(tmp_path: Path) -> None:
    module = helper("secret")
    target = tmp_path / "real"
    target.write_text("synthetic-only")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="linked"):
        module.admit(link)


def test_every_typed_resource_matches_actual_original_ansible_rendering() -> None:
    oracle = json.loads((Path(__file__).parent / "parity/backup_templates.json").read_text())
    models: dict[str, type[BackupConfig]] = {
        "zfs_syncoid_replication": SyncoidConfig,
        "zfs_usb_replication": UsbReplicationConfig,
        "minio_offsite_replication": MinioArchiveConfig,
        "mail_offsite_replication": MailReplicationConfig,
    }
    for role, model in models.items():
        cfg = model.model_validate(oracle["inputs"][role])
        for relative, digest in oracle["source_sha256"].items():
            if not relative.startswith("roles/" + role + "/"):
                continue
            path = Path(relative)
            resource = path.name.removesuffix(".j2")
            assert render(cfg, resource) == oracle["resources"][resource], resource
            assert (
                hashlib.sha256((ROOT / "src/ops_deploy/infra/backup/templates" / path.name).read_bytes()).hexdigest()
                == digest
            )


def test_selected_backup_sources_match_cf3_without_rebaselining_global_parity() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("explicit selected-role cf3 proof requires paired OPS_LIBRARY_PATH")
    oracle = json.loads((Path(__file__).parent / "parity/backup_sources.json").read_text())
    for relative, digest in oracle["resources"].items():
        assert hashlib.sha256((Path(library) / relative).read_bytes()).hexdigest() == digest, relative
        if "/files/" in relative:
            assert (ROOT / "src/ops_deploy/infra/files" / Path(relative).name).read_bytes() == (
                Path(library) / relative
            ).read_bytes()


def test_source_inline_resources_match_actual_original_ansible_rendering() -> None:
    from ops_deploy.infra.backup.render import ENV
    from ops_deploy.infra.backup.source import BackupSourceConfig, source_render

    oracle = json.loads((Path(__file__).parent / "parity/backup_source_templates.json").read_text())
    cfg = BackupSourceConfig.model_validate(oracle["inputs"])
    for name, expected in oracle["resources"].items():
        actual = (
            ENV.get_template(name + ".j2").render() if name == "mail-restore-allow.sh" else source_render(cfg, name)
        )
        assert actual == expected, name
        assert (
            hashlib.sha256((ROOT / "src/ops_deploy/infra/backup/templates" / (name + ".j2")).read_bytes()).hexdigest()
            == oracle["source_sha256"][name]
        )


def test_original_USB_by_id_colon_paths_are_valid_operational_devices() -> None:
    cfg = UsbReplicationConfig(
        pool="vault",
        devices=(
            UsbDrive(name="a", device="/dev/disk/by-id/usb-owned-0:0"),
            UsbDrive(name="b", device="/dev/disk/by-id/usb-owned2-0:0"),
        ),
        anchor_mode="bookmark",
        jobs=jobs(),
        spindown_enabled=True,
        spindown_pool="tank",
        spindown_devices=("/dev/disk/by-id/ata-owned", "/dev/disk/by-id/usb-owned-0:0"),
    )
    assert cfg.spindown_devices[-1].endswith("0:0")


def test_source_preparation_never_authorizes_keys_on_macmini(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import inspect

    from pydantic import SecretStr

    module = importlib.import_module("ops_deploy.infra.backup.source")
    writes = []
    monkeypatch.setattr(module, "require_linux", lambda _: None)
    monkeypatch.setattr(module.files, "directory", lambda **kw: writes.append(kw["path"]))
    monkeypatch.setattr(module.files, "put", lambda **kw: writes.append(kw["dest"]))

    def unauthorized(**kw: Any) -> None:
        pytest.fail("original backup source play never manages macmini authorized_keys")

    monkeypatch.setattr(module, "authorize", unauthorized)
    raw = SecretStr("ssh-ed25519 " + public_key() + " synthetic-comment")
    inspect.unwrap(module.deploy_backup_source)(
        cfg=module.BackupSourceConfig(mail_restore_host="owned.example"),
        minio_public_key=raw,
        mail_public_key=raw,
        mail_private_key=SecretStr("synthetic-private-only"),
        restore_client=False,
    )
    assert writes == [
        "/root/.ssh",
        "/usr/local/sbin/minio-offsite-rsync-allow.sh",
        "/usr/local/sbin/mail-backup-stage.sh",
        "/usr/local/sbin/mail-offsite-allow.sh",
    ]


def test_invalid_source_public_key_refuses_before_any_source_file_operation(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import inspect

    from pydantic import SecretStr
    from pyinfra.api import DeployError

    module = importlib.import_module("ops_deploy.infra.backup.source")

    def forbidden(**kw: Any) -> None:
        pytest.fail("invalid public source key reached file declaration")

    monkeypatch.setattr(module.files, "directory", forbidden)
    with pytest.raises(DeployError, match="public key is invalid"):
        inspect.unwrap(module.deploy_backup_source)(
            cfg=module.BackupSourceConfig(mail_enabled=False), minio_public_key=SecretStr("invalid-public-key")
        )


def test_restore_authorization_updates_only_selected_key_and_retains_unowned_bytes() -> None:
    module = helper("authorized_key")
    selected = public_key(payload=b"selected")
    other = public_key(payload=b"unowned")
    original = (
        '# exact comment\nfrom="192.0.2.1" ssh-ed25519 '
        + other
        + " other comment\nssh-ed25519 "
        + selected
        + " old selected comment\n"
    )
    request = {
        "key": "ssh-ed25519 " + selected + " source comment",
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    updated = module.candidate(original, request)
    assert updated.startswith('# exact comment\nfrom="192.0.2.1" ssh-ed25519 ' + other + " other comment\n")
    assert updated.endswith("ssh-ed25519 " + selected + " macmini mail offsite restore\n")
    assert "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding" in updated
    assert module.candidate(updated, request) == updated


def test_original_mail_key_filter_matches_actual_ansible_nonsecret_oracle() -> None:
    from pydantic import SecretStr

    from ops_deploy.infra.backup.common import mail_key_input

    oracle = json.loads((Path(__file__).parent / "parity/mail_key_format.json").read_text())
    for source, expected in oracle["results"].items():
        assert mail_key_input(SecretStr(source)).get_secret_value() == expected


def test_mail_private_key_filter_is_applied_by_actual_callers_only(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import inspect

    from pydantic import SecretStr

    source = SecretStr("public-synthetic-material\n")
    expected = source.get_secret_value() + "\n"
    for module_name, cfg, filtered in [
        ("mail", MailReplicationConfig(source_host="owned.example"), True),
        ("archive", MinioArchiveConfig(source_host="owned.example"), False),
    ]:
        module = importlib.import_module("ops_deploy.infra.backup." + module_name)
        seen: list[str] = []
        monkeypatch.setattr(module, "prerequisites", lambda cfg: None)
        monkeypatch.setattr(
            module, "prepare", lambda cfg, material, captured=seen: captured.append(material.get_secret_value())
        )
        monkeypatch.setattr(module, "resource", lambda *a: None)
        monkeypatch.setattr(module, "timer", lambda *a, **kw: None)
        monkeypatch.setattr(
            module.files if module_name == "mail" else importlib.import_module("pyinfra.operations.files"),
            "directory",
            lambda **kw: None,
        )
        function = module.deploy_mail_replication if module_name == "mail" else module.deploy_minio_archive
        inspect.unwrap(function)(cfg=cfg, key=source)
        assert seen == [expected if filtered else source.get_secret_value()]
    client = importlib.import_module("ops_deploy.infra.backup.source")
    seen = []
    monkeypatch.setattr(client, "require_linux", lambda _: None)
    monkeypatch.setattr(client, "private_key", lambda **kw: seen.append(kw["content"].get_secret_value()))
    monkeypatch.setattr(client, "known_host", lambda **kw: None)
    inspect.unwrap(client.deploy_backup_restore_client)(
        cfg=client.BackupSourceConfig(mail_restore_host="owned.example"), mail_private_key=source
    )
    assert seen == [expected]


def test_original_ordered_authorization_options_are_byte_current_and_comments_not_keys() -> None:
    module = helper("authorized_key")
    selected = public_key(payload=b"selected")
    other = public_key(payload=b"unrelated")
    options = (
        'no-X11-forwarding,no-agent-forwarding,command="/usr/local/sbin/mail-restore-allow.sh",'
        "no-user-rc,no-pty,no-port-forwarding"
    )
    untouched = "ssh-ed25519 " + other + " comment mentioning ssh-ed25519 " + selected + " must survive\n"
    current = options + " ssh-ed25519 " + selected + " macmini mail offsite restore\n"
    request = {
        "key": "ssh-ed25519 " + selected,
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    assert module.candidate(untouched + current, request) == untouched + current


def test_extra_or_duplicate_authorization_options_are_actual_policy_drift() -> None:
    module = helper("authorized_key")
    key = public_key()
    request = {
        "key": "ssh-ed25519 " + key,
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    desired = module.candidate("", request)
    for changed in (
        desired.replace("no-pty,", "no-pty,no-pty,"),
        desired.replace("no-pty,", 'from="192.0.2.1",no-pty,'),
    ):
        assert changed != desired
        assert module.candidate(changed, request) == desired


@pytest.mark.parametrize(
    "options",
    [
        'command="/usr/local/sbin/mail-restore-allow.sh,no-agent-forwarding",no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding',
        "command=/usr/local/sbin/mail-restore-allow.sh,no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding",
        "'command=/usr/local/sbin/mail-restore-allow.sh,no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding'",
    ],
)
def test_quote_boundary_drift_is_never_reported_as_current(options: str) -> None:
    module = helper("authorized_key")
    key = public_key()
    request = {
        "key": "ssh-ed25519 " + key,
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    malformed = options + " ssh-ed25519 " + key + " macmini mail offsite restore\n"
    desired = module.candidate("", request)
    assert malformed != desired
    assert module.candidate(malformed, request) == desired


def test_unrelated_free_comment_quotes_are_never_parsed_as_options() -> None:
    module = helper("authorized_key")
    selected = public_key(payload=b"selected")
    other = public_key(payload=b"other")
    original = "ssh-ed25519 " + other + " Owner's unrelated key with an unmatched quote\n"
    request = {
        "key": "ssh-ed25519 " + selected,
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    assert module.candidate(original, request).startswith(original)


def test_openssh_escaped_quote_identity_cannot_leave_weaker_selected_row() -> None:
    module = helper("authorized_key")
    key = public_key()
    request = {
        "key": "ssh-ed25519 " + key,
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    # OpenSSH skips only backslash-doublequote, not an escaped backslash.
    options = 'command="a' + "\\" * 2 + '" x",no-pty'
    weaker = options + " ssh-ed25519 " + key + ' c"\n'
    desired = module.candidate("", request)
    assert module.candidate(weaker, request) == desired
    assert module.candidate(weaker + desired, request) == desired
    other = public_key(payload=b"other")
    unrelated = options + " ssh-ed25519 " + other + " Owner's unrelated key\n"
    assert module.candidate(unrelated + desired, request) == unrelated + desired


@pytest.mark.parametrize("ending", ["\n", "\r\n", ""])
@pytest.mark.parametrize("options", ["", "no-pty "])
def test_commentless_selected_rows_are_replaced_not_left_before_canonical(ending: str, options: str) -> None:
    module = helper("authorized_key")
    key = public_key()
    request = {
        "key": "ssh-ed25519 " + key,
        "command": "/usr/local/sbin/mail-restore-allow.sh",
        "comment": "macmini mail offsite restore",
    }
    weaker = options + "ssh-ed25519 " + key + ending
    desired = module.candidate("", request)
    assert module.candidate(weaker, request) == desired
    if ending:
        assert module.candidate(weaker + desired, request) == desired
    assert module.candidate(desired, request) == desired
