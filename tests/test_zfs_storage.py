"""Declared ZFS identity, failure ordering and exact selected-role semantics."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError
from pyinfra.api import DeployError

from ops_deploy.infra.zfs_storage import ZfsDatasetConfig, ZfsPoolConfig
from ops_deploy.infra.zfs_storage.deploy import pool_payload, render_unlock
from ops_deploy.infra.zfs_storage.size import comparable, size_to_bytes

ROOT = Path(__file__).parents[1]


def helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "owned_zfs_storage", ROOT / "src/ops_deploy/infra/files/zfs_storage.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pool(**values: Any) -> ZfsPoolConfig:
    return ZfsPoolConfig.model_validate(dict(name="owned", vdevs=["/owned/file"], allow_create=True, **values))


@pytest.mark.parametrize("size", ["1.1T", "5.75T", "0.03125G", "6400G", "1.00001KiB", "17", " 4 mib "])
def test_size_uses_original_decimal_binary_truncation(size: str) -> None:
    # Parsing the selected source filter's arithmetic must not use float/round().
    match = re.match(r"[0-9.]+", size.strip())
    assert match is not None
    number = match.group()
    unit = next((u for u in "TGMK" if u in size.upper()), "")
    expected = int(Decimal(number) * 1024 ** ({"": 0, "K": 1, "M": 2, "G": 3, "T": 4}[unit]))
    assert size_to_bytes(size) == expected


@pytest.mark.parametrize("value", ["-1G", "NaN", "1G; true", "1e3", "", "1.2.3T"])
def test_invalid_size_refuses(value: str) -> None:
    with pytest.raises(ValueError, match="invalid native ZFS size"):
        size_to_bytes(value)


def test_none_is_zero_only_for_original_size_properties() -> None:
    assert comparable("quota", "none") == "0"
    assert comparable("compression", "none") == "none"
    assert comparable("refreservation", "auto") == "auto"
    assert comparable("quota", "1.1T") == "1209462790553"


@pytest.mark.parametrize(
    "values",
    [
        dict(name="-owned"),
        dict(vdevs=["mirror"]),
        dict(vdevs=["/x/../dev"]),
        dict(vdevs=["/a\n-f"]),
        dict(keyfile_path="/root/../key"),
        dict(unlock_service_name="x\nExecStart=bad"),
        dict(filesystem_properties={"quota": float("inf")}),
        dict(properties={"invalid=value": "x"}),
    ],
)
def test_ambiguous_inputs_refuse_before_native_commands(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ZfsPoolConfig.model_validate({"name": "owned", "vdevs": ["/owned/file"], "allow_create": True, **values})


def test_original_allow_create_flag_remains_explicit_even_for_existing_pool() -> None:
    with pytest.raises(ValidationError, match="allow_create"):
        ZfsPoolConfig(name="owned", vdevs=("/owned/file",))
    assert ZfsPoolConfig(name="owned", vdevs=("/owned/file",), validate_only=True).validate_only


@pytest.mark.parametrize("value", [None, "", "CHANGEME", "short", "short\ninvalid"])
def test_invalid_key_never_enters_native_payload(value: str | None) -> None:
    with pytest.raises(DeployError):
        pool_payload(pool(), None if value is None else SecretStr(value))


def test_keys_are_separate_secret_inputs_and_exact_source_defaults_remain() -> None:
    cfg = pool()
    assert "credential" not in ZfsPoolConfig.model_fields
    assert "credential" not in cfg.model_dump()
    assert cfg.resolved_keyfile == "/root/.zfs-key-owned"
    assert cfg.resolved_unlock_unit == "zfs-unlock-owned"
    assert cfg.resolved_mountpoint == "/owned"
    assert cfg.ashift == 12
    assert not cfg.force_create
    assert not cfg.autotrim
    assert cfg.packages == ("zfsutils-linux",)
    assert "ExecStop=/sbin/zfs unload-key owned\n" in render_unlock(cfg)
    assert "Restart=" not in render_unlock(cfg)


def test_dataset_source_alias_and_creation_only_policy_are_retained() -> None:
    cfg = ZfsDatasetConfig(
        name="owned/mac",
        macos_compat=True,
        inherit_encryption=False,
        properties={"acltype": "nfs4", "atime": "on", "casesensitivity": "sensitive"},
    )
    assert cfg.effective_properties == {
        "xattr": "sa",
        "acltype": "nfsv4",
        "atime": "on",
        "casesensitivity": "sensitive",
    }
    # inherit_encryption is an unconsumed source flag; never silently add encryption=off.
    assert "encryption" not in cfg.effective_properties


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (1, "permission denied"),
        (1, "cannot open 'owned': I/O error"),
        (2, "cannot open 'owned': no such pool"),
        (1, "cannot open 'other': no such pool"),
    ],
)
def test_unknown_absence_or_tool_errors_never_mean_create(
    monkeypatch: pytest.MonkeyPatch, code: int, error: str
) -> None:
    module = helper()
    monkeypatch.setattr(
        module.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess([], code, b"", error.encode())
    )
    with pytest.raises(module.Refused, match="unknown"):
        module.exists("zpool", "owned")


def test_only_exact_native_absence_is_admitted(monkeypatch: pytest.MonkeyPatch) -> None:
    module = helper()
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 1, b"", b"cannot open 'owned': no such pool\n"),
    )
    assert module.exists("zpool", "owned") is False


def test_wrong_source_key_fails_before_any_key_or_property_write(monkeypatch: pytest.MonkeyPatch) -> None:
    module = helper()
    monkeypatch.setattr(module, "prerequisite", lambda _: None)
    monkeypatch.setattr(module.os, "stat", lambda _: type("Info", (), {"st_mode": 0o100600})())
    monkeypatch.setattr(module, "exists", lambda *a: True)
    monkeypatch.setattr(
        module,
        "properties",
        lambda kind, name, keys: {
            key: {
                "encryption": "aes-256-gcm",
                "encryptionroot": "owned",
                "keyformat": "passphrase",
                "autotrim": "off",
            }.get(key, "-")
            for key in keys
        },
    )

    def wrong(_: Any) -> None:
        raise module.Refused("wrong desired key")

    def forbidden(*args: Any) -> None:
        pytest.fail("a native mutation or key read/publication happened after wrong-key refusal")

    monkeypatch.setattr(module, "verify_key", wrong)
    for name in ("key_current", "publish_key", "create_pool", "run"):
        monkeypatch.setattr(module, name, forbidden)
    with pytest.raises(module.Refused, match="wrong desired"):
        module.pool_apply(pool_payload(pool(), SecretStr("synthetic-key-only")))


def test_declared_parent_can_defer_planning_but_never_actual_absent_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    module = helper()
    monkeypatch.setattr(module, "prerequisite", lambda _: None)
    monkeypatch.setattr(module, "exists", lambda *a: False)
    data = {"name": "owned/new", "planned_parent": "owned", "validate_only": False}
    assert module.dataset_state(data)["deferred_prerequisite"] == "declared parent pool creation"
    with pytest.raises(module.Refused, match="parent pool absent"):
        module.dataset_apply(data)
    with pytest.raises(module.Refused, match="parent pool absent"):
        module.dataset_state({**data, "planned_parent": "other"})


def test_unknown_property_response_refuses_before_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    module = helper()
    monkeypatch.setattr(module, "run", lambda *a: "quota\t0\nquota\t0\n")
    with pytest.raises(module.Refused, match="unexpected"):
        module.properties("zfs", "owned", ["quota"])


def test_selected_role_provenance_and_original_unlock_resource() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("explicit selected-role cf3 proof requires paired OPS_LIBRARY_PATH")
    oracle = json.loads((Path(__file__).parent / "parity/zfs_storage_sources.json").read_text())
    for relative, digest in oracle["resources"].items():
        assert hashlib.sha256((Path(library) / relative).read_bytes()).hexdigest() == digest, relative
    assert (ROOT / "src/ops_deploy/infra/zfs_storage/templates/zfs-unlock-pool.service.j2").read_bytes() == (
        Path(library) / "roles/zfs_pool_deploy/templates/zfs-unlock-pool.service.j2"
    ).read_bytes()


@pytest.mark.parametrize(
    "value", ["none", "NONE", "auto", "1.1T", "5.75T", "6400G", "0.03125G", " 1G ", "none ", "0", "invalid", 1234]
)
@pytest.mark.parametrize("name", ["quota", "refquota", "refreservation", "compression"])
def test_host_comparison_matches_public_comparison_on_identical_inputs(name: str, value: object) -> None:
    # The original task regex does not trim padded properties. Its standalone
    # size filter does trim: preserve those separate source boundaries.
    assert helper().compare(name, value) == comparable(name, value)


@pytest.mark.parametrize(
    "literal", ["synthetic-valid-source-key\n", "synthetic-valid-source-key\nretained-source-bytes"]
)
def test_original_literal_key_file_bytes_are_preserved_with_native_first_line_semantics(literal: str) -> None:
    value = pool_payload(pool(), SecretStr(literal))
    assert value["credential"] == literal
    assert helper().key_bytes(value) == literal.encode()
