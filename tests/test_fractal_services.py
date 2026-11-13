"""Bounded contracts for persistent disk policy and the Sanoid/Samba APIs."""

from __future__ import annotations

import importlib.util
import json
import os
from contextlib import nullcontext
from io import StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.infra.hdparm_tune import HdparmDevice, HdparmTuneConfig
from ops_deploy.infra.hdparm_tune.render import render_block
from ops_deploy.services._samba.deploy import secret_users
from ops_deploy.services.samba_share import SambaShare, SambaSharesConfig
from ops_deploy.services.samba_timemachine import SambaTimeMachineConfig
from ops_deploy.services.sanoid import SanoidConfig, SanoidDataset
from ops_deploy.services.sanoid.render import render

ROOT = Path(__file__).parents[1] / "src/ops_deploy"


def script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "infra/files" / (name + "_host.py"))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "fields", [dict(apm=0), dict(spindown_time=254), dict(acoustic_management=255), dict(apm=True)]
)
def test_hdparm_values_refuse_invalid_hardware_parameters(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HdparmDevice(device="/dev/disk/by-id/owned", **fields)


@pytest.mark.parametrize("path", ["/etc/passwd", "/dev/../etc/file", "/dev/disk/by-id/x\n-B255"])
def test_hdparm_device_refuses_nondevice_or_ambiguous_path(path: str) -> None:
    with pytest.raises(ValidationError):
        HdparmDevice(device=path, apm=127)


def disk_policy() -> HdparmTuneConfig:
    return HdparmTuneConfig(
        devices=(
            HdparmDevice(device="/dev/disk/by-id/owned-a", apm=127, spindown_time=241),
            HdparmDevice(device="/dev/disk/by-id/owned-b", apm=127, spindown_time=241),
        ),
        apply_now=True,
    )


def hdparm_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str, *, fail: bool = False
) -> tuple[Path, list[list[str]]]:
    module = script("hdparm_tune")
    path = tmp_path / "hdparm.conf"
    path.write_text(content)
    monkeypatch.setattr(module, "PATH", path)
    calls = []

    def execute(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)
        if fail:
            raise RuntimeError("owned injected application fault")

    monkeypatch.setattr(module.subprocess, "run", execute)
    # Our temporary file stays owned by the test user; never chown a real path.
    monkeypatch.setattr(module.os, "fchown", lambda *args: None)
    monkeypatch.setattr(module.os, "listxattr", lambda path: [], raising=False)
    request = {
        "devices": [row.model_dump() for row in disk_policy().devices],
        "block": render_block(disk_policy()),
        "apply_now": True,
    }
    monkeypatch.setattr(module.sys, "argv", ["owned", "apply"])
    monkeypatch.setattr(module.sys, "stdin", StringIO(json.dumps(request)))
    if fail:
        with pytest.raises(RuntimeError):
            module.main()
    else:
        module.main()
    return path, calls


def test_hdparm_repeat_never_queries_or_reasserts_hardware(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = script("hdparm_tune")
    original = "# keep\n" + module.BEGIN + "\n" + render_block(disk_policy()) + module.END + "\n# tail\n"
    path, calls = hdparm_run(monkeypatch, tmp_path, original)
    assert path.read_text() == original
    assert calls == []


def test_hdparm_changed_block_preserves_unowned_text_and_original_argument_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path, calls = hdparm_run(monkeypatch, tmp_path, "# keep\n")
    assert path.read_text().startswith("# keep\n")
    assert calls == [
        ["hdparm", "-B", "127", "/dev/disk/by-id/owned-a"],
        ["hdparm", "-B", "127", "/dev/disk/by-id/owned-b"],
        ["hdparm", "-S", "241", "/dev/disk/by-id/owned-a"],
        ["hdparm", "-S", "241", "/dev/disk/by-id/owned-b"],
    ]


def test_hdparm_failure_leaves_config_but_no_state_attestation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path, calls = hdparm_run(monkeypatch, tmp_path, "# keep\n", fail=True)
    assert render_block(disk_policy()) in path.read_text()
    assert len(calls) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["hdparm.conf"]


@pytest.mark.parametrize(
    "original", ["# BEGIN ANSIBLE MANAGED BLOCK: hdparm_tune\n", "# END ANSIBLE MANAGED BLOCK: hdparm_tune\n"]
)
def test_hdparm_ambiguous_marker_refuses(original: str) -> None:
    with pytest.raises(ValueError, match="ambiguous"):
        script("hdparm_tune").candidate(original, "owned\n")


def test_sanoid_skip_keeps_bare_template_reference_and_never_renders_skipped_dataset() -> None:
    cfg = SanoidConfig(
        templates={"owned": {"hourly": 2, "autosnap": "yes", "autoprune": "no"}},
        datasets=(
            SanoidDataset(name="owned/data", template="owned", autosnap="no"),
            SanoidDataset(name="owned/skip", sanoid_skip=True),
        ),
    )
    text = render(cfg, "sanoid.conf")
    assert "[template_owned]\n" in text
    assert "[owned/data]\nuse_template = owned\nautosnap = no\n" in text
    assert "owned/skip" not in text
    assert "--cron" in render(cfg, "sanoid-ops-library.service")
    assert "Persistent=true" in render(cfg, "sanoid-ops-library.timer")


@pytest.mark.parametrize(
    "changes",
    [
        dict(templates={}),
        dict(datasets=[]),
        dict(datasets=[{"name": "owned/data", "template": "unknown"}]),
        dict(on_calendar="hourly\nExecStart=bad"),
    ],
)
def test_sanoid_invalid_policy_refuses(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SanoidConfig.model_validate(
            {
                "templates": {"owned": {"hourly": 2}},
                "datasets": [{"name": "owned/data", "template": "owned"}],
                **changes,
            }
        )


def test_samba_preserves_unowned_globals_and_deduplicates_explicit_includes() -> None:
    module = script("samba_config")
    original = (
        "[global]\n  server string = keep\n  include = /etc/samba/unowned.conf\n\n[unowned]\n path = /owned/sentinel\n"
    )
    request = {
        "base": "UNUSED",
        "fragments": [{"path": "/etc/samba/smb.conf.d/a.conf"}, {"path": "/etc/samba/smb.conf.d/b.conf"}],
        "fruit": "# owned fruit\n",
    }
    updated = module.candidate(original, request)
    assert "  server string = keep\n  include = /etc/samba/unowned.conf\n" in updated
    assert "[unowned]\n path = /owned/sentinel\n" in updated
    assert module.candidate(updated, request) == updated
    assert updated.count("include = /etc/samba/smb.conf.d/a.conf") == 1
    assert updated.count(module.BEGIN) == 1


def secrets(rows: Any) -> SecretValues:
    return SecretValues(SecretRef("secrets/owned.yml"), {"users": json.dumps(rows)})


def test_secret_users_filters_unrelated_material_and_representations() -> None:
    marker = "synthetic-secret-value"
    value = secret_users(
        secrets([{"name": "owned", "password": marker}, {"name": "unused", "password": "unused-value"}]),
        ("owned",),
        strict=True,
    )
    assert marker not in repr(value)
    assert json.loads(value.get_secret_value()) == [{"name": "owned", "password": marker}]
    assert "unused-value" not in value.get_secret_value()


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [{"name": "owned", "password": "CHANGEME"}],
        [{"name": "owned", "password": "x\ny"}],
        [{"name": "owned", "password": "x"}, {"name": "owned", "password": "x"}],
    ],
)
def test_time_machine_secret_contract_refuses_without_echoing_values(rows: Any) -> None:
    with pytest.raises(ValueError, match="must cover") as error:
        secret_users(secrets(rows), ("owned",), strict=True)
    assert "CHANGEME" not in str(error.value)


def test_generic_existing_contract_allows_empty_password_until_missing_known() -> None:
    assert json.loads(secret_users(secrets([{"name": "owned"}]), ("owned",), strict=False).get_secret_value()) == [
        {"name": "owned", "password": ""}
    ]


def test_unix_names_and_metadata_options_refuse_injection() -> None:
    for field in ("force_user", "force_group", "path_owner", "path_group"):
        with pytest.raises(ValidationError):
            SambaShare.model_validate({"name": "owned", "path": "/owned", field: "bad\noption"})
    with pytest.raises(ValidationError):
        SambaShare(name="owned", path="/owned", path_mode="7777")
    with pytest.raises(ValidationError):
        SambaShare(name="owned", path="/owned", extra_options={"include": "/unowned"})
    with pytest.raises(ValidationError):
        SambaTimeMachineConfig(users=())
    with pytest.raises(ValidationError):
        SambaSharesConfig(shares=(SambaShare(name="same", path="/owned"), SambaShare(name="same", path="/other")))


def test_actual_ansible_template_oracle() -> None:
    from ops_deploy.services.samba_share.render import render as share_render
    from ops_deploy.services.samba_timemachine.render import fruit_block
    from ops_deploy.services.samba_timemachine.render import render as tm_render

    oracle = json.loads((Path(__file__).parent / "parity/fractal_services.json").read_text())
    inputs, expected = oracle["inputs"], oracle["outputs"]
    assert render_block(HdparmTuneConfig.model_validate(inputs["hdparm"])) == expected["hdparm"]
    cfg = SanoidConfig.model_validate(inputs["sanoid"])
    for resource in ("sanoid.conf", "sanoid-ops-library.service", "sanoid-ops-library.timer"):
        assert render(cfg, resource) == expected[resource]
    tm = SambaTimeMachineConfig.model_validate(inputs["tm"])
    for resource in ("smb.conf", "smb-timemachine.conf"):
        assert tm_render(tm, resource) == expected["tm/" + resource]
    assert fruit_block(tm) == expected["fruit"]
    shares = SambaSharesConfig.model_validate(inputs["shares"])
    for index, row in enumerate(shares.shares):
        assert share_render(shares, row, "smb-share.conf") == expected["share" + str(index)]
    assert share_render(shares, shares.shares[0], "smb.conf") == expected["share-base"]


def test_tm_primary_group_membership_does_not_reassert_usermod() -> None:
    from pyinfra.api import deploy

    from ops_deploy.services._samba.deploy import unix_users
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    @deploy("Owned Unix account")
    def owned() -> None:
        unix_users(("owned",), "owned")

    result = run_deploy_fake(
        owned, responses={**fakehost.LINUX, **fakehost.system_account("owned", "/owned", shell="/usr/sbin/nologin")}
    )
    assert result.succeeded, result.error
    assert result.executed_commands == []
    assert not any("/owned" in command and "chown" in command for command in result.fact_commands)


def test_new_samba_include_follows_later_globals_but_existing_include_is_never_moved() -> None:
    module = script("samba_config")
    original = (
        "[global]\n include = /etc/samba/old.conf\n workgroup = OWNED\n"
        " server min protocol = SMB3\n\n[unowned]\n path = /owned\n"
    )
    request = {"base": "UNUSED", "fragments": [{"path": "/etc/samba/new.conf"}], "fruit": None}
    updated = module.candidate(original, request)
    assert updated.index("include = /etc/samba/old.conf") < updated.index("workgroup = OWNED")
    assert updated.index("server min protocol = SMB3") < updated.index("include = /etc/samba/new.conf")
    assert updated.index("include = /etc/samba/new.conf") < updated.index("[unowned]")
    assert module.candidate(updated, request) == updated


def test_only_generated_include_relocated_for_a_missing_base() -> None:
    module = script("samba_config")
    base = "[global]\n include = /etc/samba/generated.conf\n workgroup = OWNED\n server min protocol = SMB3\n"
    request = {"base": base, "fragments": [{"path": "/etc/samba/generated.conf"}], "fruit": None}
    result = module.candidate(None, request)
    assert result.index("server min protocol = SMB3") < result.index("include = /etc/samba/generated.conf")
    assert result.count("include = /etc/samba/generated.conf") == 1
    assert module.candidate(result, request) == result
    # Existing source with the original buggy ordering remains byte-current.
    assert module.candidate(base, request) == base


def test_samba_ambiguous_global_or_fruit_marker_refuses() -> None:
    module = script("samba_config")
    request = {"base": "UNUSED", "fragments": [], "fruit": "owned\n"}
    with pytest.raises(ValueError, match="one global"):
        module.candidate("[global]\n[global]\n", request)
    with pytest.raises(ValueError, match="ambiguous managed fruit"):
        module.candidate("[global]\n" + module.BEGIN + "\n", request)


def samba_host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[ModuleType, list[list[str]]]:
    """The config helper against tmp_path: root ownership, testparm, systemd and port 445 faked."""
    module = script("samba_config")
    commands: list[list[str]] = []

    def write(path: Path, text: str, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run(argv: list[str]) -> str:
        commands.append(argv)
        return ""

    monkeypatch.setattr(module, "STATE", tmp_path / "state")
    monkeypatch.setattr(module, "write", write)
    monkeypatch.setattr(module, "matches", lambda path, text: module.read(path) == text)
    monkeypatch.setattr(module, "validate", lambda desired: None)
    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(
        module, "unit", lambda name: {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}
    )
    monkeypatch.setattr(module, "socket", SimpleNamespace(create_connection=lambda *args, **kwargs: nullcontext()))
    return module, commands


def samba_request(tmp_path: Path, share: str, *, base: str = "[global]\n") -> dict[str, Any]:
    config, snippet = tmp_path / "smb.conf", tmp_path / "owned.conf"
    if not config.exists():
        config.write_text(f"[global]\n   include = {snippet}\n")
        snippet.write_text("[owned]\n    path = /owned\n")
    return {
        "config": str(config),
        "base": base,
        "fragments": [{"path": str(snippet), "content": share}],
        "fruit": None,
        "service_enabled": True,
        "service_state": "started",
    }


def samba_apply_and_rollout(module: ModuleType, request: dict[str, Any]) -> str | None:
    module.configure(request, module.rows(request))
    debt: str | None = module.owed()
    assert module.rollout_pending(request)
    module.rollout(request)
    assert module.owed() is None
    # "restarted" is an explicit per-run choice and always pending.
    assert module.rollout_pending(request) == (request["service_state"] == "restarted")
    return debt


def test_samba_snippet_only_change_reloads_instead_of_restarting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n    veto files = /._*/.DS_Store/\n")
    assert samba_apply_and_rollout(module, request) == "reload"
    assert ["smbcontrol", "all", "reload-config"] in commands
    assert not any(argv[:2] == ["systemctl", "restart"] for argv in commands)
    assert "veto files" in (tmp_path / "owned.conf").read_text()


def test_samba_base_change_still_restarts_both_daemons(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n")
    request["fruit"] = "   vfs objects = fruit streams_xattr\n"
    assert samba_apply_and_rollout(module, request) == "restart"
    assert [argv for argv in commands if argv[0] == "systemctl"] == [
        ["systemctl", "restart", "smbd"],
        ["systemctl", "restart", "nmbd"],
    ]
    assert not any(argv[0] == "smbcontrol" for argv in commands)


def test_samba_recorded_restart_debt_is_never_downgraded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state/restart-owed.json").write_text(json.dumps(module.RESTART_DEBT))
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n    browseable = no\n")
    assert samba_apply_and_rollout(module, request) == "restart"
    assert ["systemctl", "restart", "smbd"] in commands
    assert not any(argv[0] == "smbcontrol" for argv in commands)


def test_samba_recorded_reload_debt_upgrades_to_restart_on_a_base_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state/restart-owed.json").write_text(json.dumps(module.RELOAD_DEBT))
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n")
    request["fruit"] = "   vfs objects = fruit streams_xattr\n"
    assert samba_apply_and_rollout(module, request) == "restart"
    assert ["systemctl", "restart", "smbd"] in commands
    assert ["systemctl", "restart", "nmbd"] in commands
    assert not any(argv[0] == "smbcontrol" for argv in commands)


def test_samba_reload_debt_with_stopped_service_sends_no_reload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n    browseable = no\n")
    request["service_state"] = "stopped"
    module.configure(request, module.rows(request))
    assert module.owed() == "reload"
    module.rollout(request)
    assert module.owed() is None
    assert ["systemctl", "stop", "smbd"] in commands
    assert not any(argv[0] == "smbcontrol" for argv in commands)


def test_samba_explicit_restarted_state_wins_over_a_reload_debt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n    browseable = no\n")
    request["service_state"] = "restarted"
    assert samba_apply_and_rollout(module, request) == "reload"
    assert ["systemctl", "restart", "nmbd"] in commands
    assert not any(argv[0] == "smbcontrol" for argv in commands)


def test_samba_unknown_debt_refuses(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module, commands = samba_host(monkeypatch, tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state/restart-owed.json").write_text(json.dumps({"units": ["smbd"], "action": "reload-config"}))
    request = samba_request(tmp_path, "[owned]\n    path = /owned\n    browseable = no\n")
    with pytest.raises(ValueError, match="unknown Samba restart debt"):
        module.configure(request, module.rows(request))
    with pytest.raises(ValueError, match="unknown Samba restart debt"):
        module.rollout_pending(request)
    assert commands == []
    assert "browseable" not in (tmp_path / "owned.conf").read_text()


@pytest.mark.parametrize("options", [{"unknown_hook": "ignored"}, {"hourly": -1}, {"autosnap": "maybe"}])
def test_unsupported_or_invalid_sanoid_native_policy_refuses(options: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SanoidConfig(templates={"owned": options}, datasets=(SanoidDataset(name="owned/data", template="owned"),))


@pytest.mark.parametrize("role", ["sanoid", "samba_timemachine", "samba_share"])
def test_vendored_source_resources_match_the_reviewed_role(role: str) -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if library is None:
        pytest.skip("OPS_LIBRARY_PATH not set")
    source = Path(library) / "roles" / role / "templates"
    for path in source.glob("*.j2"):
        assert (ROOT / "services" / role / "templates" / path.name).read_bytes() == path.read_bytes()


@pytest.mark.parametrize("broken", [None, b"invalid", bytes(68)])
def test_missing_or_corrupt_local_sid_refuses_without_native_generation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, broken: bytes | None
) -> None:
    import sys
    from types import SimpleNamespace

    module = script("samba_accounts")
    (tmp_path / "secrets.tdb").touch()
    requests = []

    class Database:
        def get(self, key: bytes) -> bytes | None:
            requests.append(key)
            return broken

        def close(self) -> None:
            pass

    def open_db(path: str, *, flags: int) -> Database:
        assert flags == os.O_RDONLY
        return Database()

    monkeypatch.setitem(sys.modules, "tdb", SimpleNamespace(Tdb=open_db))
    values = {"private dir": str(tmp_path), "netbios name": "owned"}
    with pytest.raises(ValueError, match="Samba identity"):
        module.identity(SimpleNamespace(get=values.get))
    assert requests == [b"SECRETS/SID/OWNED"]


def test_existing_public_sid_validates_without_requesting_credential_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import struct
    import sys
    from types import SimpleNamespace

    module = script("samba_accounts")
    (tmp_path / "secrets.tdb").touch()
    raw = bytes([1, 4]) + (5).to_bytes(6, "big") + struct.pack("<15I", 21, 123, 456, 789, *([0] * 11))

    class Database:
        def get(self, key: bytes) -> bytes:
            assert key == b"SECRETS/SID/OWNED"
            return raw

        def close(self) -> None:
            pass

    def open_db(path: str, *, flags: int) -> Database:
        assert flags == os.O_RDONLY
        return Database()

    monkeypatch.setitem(sys.modules, "tdb", SimpleNamespace(Tdb=open_db))
    values = {"private dir": str(tmp_path), "netbios name": "owned"}
    assert module.identity(SimpleNamespace(get=values.get)) == "S-1-5-21-123-456-789"


@pytest.mark.parametrize("key", ["in clude", "IN\tCLUDE", "co py", "con fig backend"])
def test_extra_options_cannot_smuggle_native_whitespace_aliases(key: str) -> None:
    with pytest.raises(ValidationError):
        SambaShare(name="owned", path="/owned", extra_options={key: "/not-an-owned-include"})


@pytest.mark.parametrize("name", ["global", "GLOBAL", "globals", "GLOBALS", "homes", "printers"])
def test_reserved_share_section_names_refuse(name: str) -> None:
    with pytest.raises(ValidationError):
        SambaShare(name=name, path="/owned")
    with pytest.raises(ValidationError):
        SambaTimeMachineConfig(share_name=name, users=("owned",))


def share_group_run(group_lines: list[str], *, by_name: list[str], by_gid: list[str]) -> Any:
    from pyinfra.api import deploy

    from ops_deploy.services.samba_share import SambaShareGroup
    from ops_deploy.services.samba_share.deploy import ensure_group
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    @deploy("Share group")
    def owned() -> None:
        ensure_group(SambaShareGroup(name="media", gid=965))

    return run_deploy_fake(
        owned,
        responses={
            **fakehost.LINUX,
            "getent group media;": by_name,
            "getent group 965;": by_gid,
            "cat /etc/group": ["root:x:0:", *group_lines],
        },
    )


def test_share_group_is_created_with_its_gid_when_missing() -> None:
    result = share_group_run([], by_name=[], by_gid=[])
    assert result.succeeded, result.error
    assert any("groupadd" in c and "-r" in c and "media" in c and "--gid 965" in c for c in result.executed_commands)


def test_existing_share_group_with_its_gid_is_left_alone() -> None:
    line = "media:x:965:"
    result = share_group_run([line], by_name=[line], by_gid=[line])
    assert result.succeeded, result.error
    assert result.executed_commands == []


@pytest.mark.parametrize(
    ("by_name", "by_gid"),
    [(["media:x:1001:"], []), ([], ["other:x:965:"]), (["media:x:1001:"], ["other:x:965:"])],
)
def test_share_group_refuses_a_taken_name_or_gid(by_name: list[str], by_gid: list[str]) -> None:
    result = share_group_run([*by_name, *by_gid], by_name=by_name, by_gid=by_gid)
    assert not result.succeeded
    assert "exists with another gid or name" in str(result.error)
    assert not any("groupadd" in c or "groupmod" in c for c in result.executed_commands)


def test_share_group_probe_failure_refuses() -> None:
    result = share_group_run([], by_name=["", "ops-deploy-probe-failed"], by_gid=[])
    assert not result.succeeded
    assert "Cannot read the Unix group media" in str(result.error)


def test_share_groups_refuse_duplicate_names_or_gids() -> None:
    from ops_deploy.services.samba_share import SambaShareGroup

    share = (SambaShare(name="owned", path="/owned"),)
    for groups in (
        (SambaShareGroup(name="media", gid=965), SambaShareGroup(name="media", gid=966)),
        (SambaShareGroup(name="media", gid=965), SambaShareGroup(name="other", gid=965)),
    ):
        with pytest.raises(ValidationError, match="duplicate Samba share group"):
            SambaSharesConfig(shares=share, groups=groups)
    with pytest.raises(ValidationError):
        SambaShareGroup(name="media", gid=0)


def test_share_batch_creates_groups_before_any_share_step(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyinfra.operations import files

    from ops_deploy.services._samba import deploy as common
    from ops_deploy.services.samba_share import SambaShareGroup
    from ops_deploy.services.samba_share import deploy as share_deploy
    from ops_deploy.testing import run_deploy_fake

    calls: list[str] = []
    monkeypatch.setattr(common, "prerequisites", lambda cfg: calls.append("prerequisites"))
    monkeypatch.setattr(common, "unix_users", lambda names, group: calls.append("users"))
    monkeypatch.setattr(share_deploy, "ensure_group", lambda group: calls.append(f"group {group.name}"))
    monkeypatch.setattr(files, "directory", lambda **kwargs: calls.append(f"root {kwargs['group']}"))
    monkeypatch.setattr(common, "configure", lambda **kwargs: calls.append("configure"))
    monkeypatch.setattr(common, "accounts", lambda **kwargs: calls.append("accounts"))
    monkeypatch.setattr(common, "rollout", lambda **kwargs: calls.append("rollout"))
    cfg = SambaSharesConfig(
        shares=(SambaShare(name="owned", path="/owned", path_group="media", force_group="media"),),
        groups=(SambaShareGroup(name="media", gid=965), SambaShareGroup(name="other", gid=966)),
    )

    result = run_deploy_fake(share_deploy.deploy_samba_shares, cfg)

    assert result.succeeded, result.error
    assert calls == [
        "prerequisites",
        "users",
        "group media",
        "group other",
        "root media",
        "configure",
        "accounts",
        "rollout",
    ]
