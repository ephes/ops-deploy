"""Bounded contracts for persistent disk policy and the Sanoid/Samba APIs."""

from __future__ import annotations

import importlib.util
import json
import os
from io import StringIO
from pathlib import Path
from types import ModuleType
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
