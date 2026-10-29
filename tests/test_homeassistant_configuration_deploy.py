"""Actual SDK operations over isolated local files; no inventory/service actions."""

from __future__ import annotations

import grp
import os
import pwd
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops

from ops_deploy.services.homeassistant.configuration import ConfigurationPolicy
from ops_deploy.services.homeassistant.configuration_deploy import (
    ConfigurationChanges,
    UnifiSecretSource,
    configure_files,
)
from ops_deploy.services.homeassistant.configuration_render import ConfigurationValues, render_configuration
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from ops_deploy.testing.harness import collect_ops
from tests.test_homeassistant_configuration import DISCOVERY, MET, MONITOR, USER


def config(root: Path) -> HomeAssistantRuntimeConfig:
    cfg = HomeAssistantRuntimeConfig(
        user=pwd.getpwuid(os.getuid()).pw_name,
        group=grp.getgrgid(os.getgid()).gr_name,
        home=str(root),
        site_path=str(root),
        config_path=str(root / "config"),
    )
    return cfg.model_copy(update={"security": cfg.security.model_copy(update={"system_python": sys.executable})})


def execute(
    cfg: HomeAssistantRuntimeConfig,
    policy: ConfigurationPolicy,
    *,
    diff: bool = True,
    values: ConfigurationValues | None = None,
    **kwargs: Any,
) -> tuple[list[Any], ConfigurationChanges]:
    state = State(Inventory(([("@local", {})], {})), Config(DIFF=diff))
    results = []

    def deploy() -> None:
        results.append(configure_files(cfg, policy, values or ConfigurationValues(), **kwargs))

    try:
        connect_all(state)
        add_deploy(state, deploy)
        run_ops(state)
        operations = collect_ops(state, "@local")
        assert all(op.succeeded for op in operations)
        return operations, results[0]
    finally:
        disconnect_all(state)


def snapshot(root: Path) -> dict[str, tuple[bytes, tuple[int, ...]]]:
    result: dict[str, tuple[bytes, tuple[int, ...]]] = {}
    for path in sorted(root.iterdir()):
        s = path.lstat()
        result[path.name] = (
            path.read_bytes(),
            (s.st_mode, s.st_uid, s.st_gid, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns),
        )
    return result


@pytest.mark.parametrize("diff", [False, True])
def test_original_new_config_secrets_includes_then_whole_repeat(
    tmp_path: Path, diff: bool, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    policy = ConfigurationPolicy(
        manage_configuration=True, manage_secrets=True, manage_includes=True, remove_legacy_met_weather_yaml=True
    )
    token = "owned-private-unifi-771"
    ops, changes = execute(cfg, policy, diff=diff, unifi=UnifiSecretSource(explicit=SecretStr(token)))
    assert len([op for op in ops if op.changed and not op.read_only]) == 8
    assert changes.homeassistant_changed() is False
    assert token not in caplog.text
    before = snapshot(root)
    ops, changes = execute(cfg, policy, diff=diff, unifi=UnifiSecretSource(explicit=SecretStr(token)))
    assert not any(op.changed for op in ops)
    assert changes.homeassistant_changed() is False
    assert snapshot(root) == before


@pytest.mark.parametrize("overwrite", [False, True])
def test_actual_preexisting_replacement_notifications_and_overwrite_order(tmp_path: Path, overwrite: bool) -> None:
    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    path = root / "configuration.yaml"
    path.write_text(USER + MET + MONITOR + DISCOVERY)
    path.chmod(0o640)
    policy = ConfigurationPolicy(
        manage_configuration=True, overwrite_config=overwrite, remove_legacy_met_weather_yaml=True
    )
    ops, changes = execute(cfg, policy)
    assert path.read_text() == (
        render_configuration(cfg, ConfigurationValues()).get_secret_value() if overwrite else USER
    )
    assert changes.homeassistant_changed() is (not overwrite)
    assert len([op for op in ops if op.changed]) == (1 if overwrite else 3)
    assert len(list(root.glob("configuration.yaml.*~"))) == (1 if overwrite else 3)
    before = snapshot(root)
    repeated, changes = execute(cfg, policy)
    assert not any(op.changed for op in repeated)
    assert not changes.homeassistant_changed()
    assert snapshot(root) == before


def test_unmanaged_routes_have_no_host_or_secret_probe() -> None:
    result = run_deploy_fake(
        configure_files,
        HomeAssistantRuntimeConfig(),
        ConfigurationPolicy(),
        ConfigurationValues(),
        unifi=UnifiSecretSource(source="unknown"),
    )
    assert result.succeeded
    assert not result.events
    assert not result.ops


def test_actual_dry_plan_has_no_destination_effects(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    state = State(Inventory(([("@local", {})], {})), Config(DIFF=True))
    policy = ConfigurationPolicy(manage_configuration=True, manage_secrets=True, manage_includes=True)
    try:
        connect_all(state)
        add_deploy(
            state,
            configure_files,
            cfg,
            policy,
            ConfigurationValues(),
            unifi=UnifiSecretSource(explicit=SecretStr("owned-dry-only")),
        )
        local = state.inventory.get_host("@local")
        planned = [state.get_op_data_for_host(local, key).operation_meta for key in state.get_op_order()]
        assert sum(row.will_change for row in planned) == 8
        assert not any(row.is_complete() for row in planned)
        assert list(root.iterdir()) == []
    finally:
        disconnect_all(state)


@pytest.mark.parametrize("overwrite", [False, True])
def test_include_existing_and_broken_links_use_original_initial_stat(tmp_path: Path, overwrite: bool) -> None:
    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    path = root / "automations.yaml"
    path.symlink_to("missing")
    policy = ConfigurationPolicy(manage_includes=True, overwrite_config=overwrite)
    ops, changes = execute(cfg, policy, include_files=("automations.yaml",))
    assert len([op for op in ops if op.changed]) == int(overwrite)
    assert path.is_symlink() is (not overwrite)
    assert not changes.homeassistant_changed()
    assert not (root / "missing").exists()


def test_existing_broken_config_refuses_during_plan_before_secret_write(tmp_path: Path) -> None:
    from pyinfra.api.exceptions import PyinfraError

    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    path = root / "configuration.yaml"
    path.symlink_to("missing")
    policy = ConfigurationPolicy(manage_secrets=True, manage_configuration=True)
    with pytest.raises(PyinfraError):
        execute(cfg, policy, diff=False, unifi=UnifiSecretSource(explicit=SecretStr("owned-before-failure")))
    assert not (root / "secrets.yaml").exists()
    assert path.is_symlink()


def test_failure_introduced_after_plan_retains_actual_earlier_secret_write(tmp_path: Path) -> None:
    from pyinfra.api.exceptions import PyinfraError

    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    path = root / "configuration.yaml"
    path.write_text(USER + MET)
    policy = ConfigurationPolicy(manage_secrets=True, manage_configuration=True, remove_legacy_met_weather_yaml=True)
    state = State(Inventory(([("@local", {})], {})), Config())
    try:
        connect_all(state)
        add_deploy(
            state,
            configure_files,
            cfg,
            policy,
            ConfigurationValues(),
            unifi=UnifiSecretSource(explicit=SecretStr("owned-before-failure")),
        )
        # Owned fault occurs AFTER actual planning; original valid snapshot is
        # not rewritten in evidence or mistaken for a preexisting failure.
        path.unlink()
        path.symlink_to("missing")
        with pytest.raises(PyinfraError):
            run_ops(state)
        assert (root / "secrets.yaml").is_file()
        assert path.is_symlink()
        assert not (root / "missing").exists()
        assert not list(root.glob("*~"))
    finally:
        disconnect_all(state)


def test_deferred_predecessor_plan_never_guesses_credential_then_executes_real_check(tmp_path: Path) -> None:
    from pyinfra.api.exceptions import PyinfraError

    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    state = State(Inventory(([("@local", {})], {})), Config(DIFF=True))
    try:
        connect_all(state)
        add_deploy(
            state,
            configure_files,
            cfg,
            ConfigurationPolicy(manage_secrets=True),
            ConfigurationValues(),
            unifi=UnifiSecretSource(source="file", file=str(tmp_path / "missing")),
            deferred=True,
        )
        assert list(root.iterdir()) == []
        with pytest.raises(PyinfraError):
            run_ops(state)
        assert list(root.iterdir()) == []
    finally:
        disconnect_all(state)


def test_source_model_and_payload_repr_hide_declared_credentials() -> None:
    source = UnifiSecretSource(
        explicit=SecretStr("owned-explicit-private"), variable=SecretStr("owned-variable-private")
    )
    assert "owned-explicit-private" not in repr(source)
    assert "owned-variable-private" not in str(source.protected_payload())
