"""Original removal primitives; synthetic files/accounts/services only."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops

from ops_deploy.services.homeassistant.remove import SERVICE_PROBE, HomeAssistantRemoveConfig, remove_homeassistant
from ops_deploy.testing import run_deploy_fake
from ops_deploy.testing.harness import collect_ops
from tests import fakehost

module = importlib.import_module("ops_deploy.services.homeassistant.remove")
FLAGS = tuple(name for name in HomeAssistantRemoveConfig.model_fields if name.startswith("remove_"))


def selected(**values: Any) -> HomeAssistantRemoveConfig:
    return HomeAssistantRemoveConfig(**{"confirm_removal": True, **dict.fromkeys(FLAGS, False), **values})


@pytest.mark.parametrize("overrides", [{}, {"user": "owned", "service_name": "owned-ha"}, {"home": "/srv/owned"}])
def test_exact_original_defaults_and_dependent_paths(overrides: dict[str, Any]) -> None:
    root = Path(__file__).parent / "parity/homeassistant/remove"
    manifest = json.loads((root / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (root / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()
    cfg = HomeAssistantRemoveConfig(**overrides)
    context = {"homeassistant_" + k: v for k, v in cfg.model_dump().items()}
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    for name, value in yaml.safe_load((root / "defaults.yml").read_text()).items():
        field = name.removeprefix("homeassistant_")
        expected = overrides.get(field, env.from_string(value).render(**context) if isinstance(value, str) else value)
        assert getattr(cfg, field) == expected
    tasks = yaml.safe_load((root / "tasks.yml").read_text())
    assert tasks[2]["failed_when"] is False
    assert tasks[2]["ignore_errors"] is True
    assert tasks[-3]["ansible.builtin.user"]["remove"] == "{{ homeassistant_remove_site_dir | bool }}"


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_homeassistant, HomeAssistantRemoveConfig())
    assert not run.succeeded
    assert "confirm_removal" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize("path", ["/", "/srv/../home"])
def test_unsafe_root_or_traversal_paths_refused(path: str) -> None:
    with pytest.raises(ValueError, match="removal paths"):
        selected(site_path=path)


def service_response(*, enabled: bool = True, active: str = "active", load: str = "loaded") -> dict[str, Any]:
    return {"import json, subprocess, sys": [json.dumps(dict(success=True, enabled=enabled, active=active, load=load))]}


@pytest.mark.parametrize("failure", [None, "disable", "stop"])
def test_service_disable_precedes_stop_and_failure_only_skips_rest_of_that_task(failure: str | None) -> None:
    cfg = selected(remove_service=True, remove_traefik=True)
    responses = {
        **({"systemctl " + failure: {"success": False, "stderr": ["owned failure"]}} if failure else {}),
        **service_response(),
        **fakehost.LINUX,
        **fakehost.file(cfg.systemd_unit_path, "owned unit"),
        **fakehost.file(cfg.traefik_config_path, "owned route"),
    }
    run = run_deploy_fake(remove_homeassistant, cfg, responses=responses)
    assert run.error is None
    assert run.succeeded is (failure is None)
    commands = "\n".join(run.executed_commands)
    assert "systemctl disable homeassistant" in commands
    assert ("systemctl stop homeassistant" in commands) is (failure != "disable")
    if failure != "disable":
        assert commands.index("systemctl disable") < commands.index("systemctl stop")
    assert commands.index("systemctl disable") < commands.index("rm -rf " + cfg.systemd_unit_path)
    assert commands.index("rm -rf " + cfg.systemd_unit_path) < commands.index("systemctl daemon-reload")
    assert "rm -rf " + cfg.traefik_config_path in commands
    assert "matter" not in commands
    assert "otbr" not in commands


@pytest.mark.parametrize("active", ["active", "activating", "deactivating", "inactive", "failed"])
def test_original_stop_states_and_disabled_service(active: str) -> None:
    run = run_deploy_fake(
        remove_homeassistant,
        selected(remove_service=True),
        responses={**service_response(enabled=False, active=active), **fakehost.LINUX},
    )
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert "systemctl disable" not in commands
    assert ("systemctl stop" in commands) is (active in {"active", "activating", "deactivating"})
    assert "systemctl daemon-reload" in commands


@pytest.mark.parametrize("remove_home", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_user_removal_flag_and_fatal_user_failure(remove_home: bool, failure: bool) -> None:
    cfg = selected(remove_user=True, remove_group=True, remove_site_dir=remove_home)
    responses = {
        **({"userdel": {"success": False}} if failure else {}),
        **fakehost.LINUX,
        **fakehost.system_account(cfg.user, cfg.home),
    }
    run = run_deploy_fake(remove_homeassistant, cfg, responses=responses)
    assert run.succeeded is not failure
    commands = "\n".join(run.executed_commands)
    expected = "userdel " + ("-r " if remove_home else "") + "homeassistant"
    assert expected in commands
    assert ("groupdel homeassistant" in commands) is not failure


@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "absent"])
def test_actual_owned_leaf_removal_preserves_symlink_target_and_repeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    # Filesystem primitive only on this controller; no Linux/service/account claim.
    monkeypatch.setattr(module, "require_linux", lambda label: None)
    target = tmp_path / "retained"
    target.write_text("owned retained bytes")
    path = tmp_path / "selected"
    if kind == "file":
        path.write_text("owned selected bytes")
    elif kind == "directory":
        path.mkdir()
        (path / "child").write_text("owned selected bytes")
    elif kind == "symlink":
        path.symlink_to(target)
    cfg = selected(remove_config_dir=True, config_path=str(path))
    for repeat in (False, True):
        state = State(Inventory(([("@local", {})], {})), Config())
        try:
            connect_all(state)
            add_deploy(state, remove_homeassistant, cfg)
            if not repeat:
                assert os.path.lexists(path) is (kind != "absent")
            run_ops(state)
            ops = collect_ops(state, "@local")
            assert all(op.succeeded for op in ops)
            assert sum(op.changed for op in ops) == int(not repeat and kind != "absent")
            assert not os.path.lexists(path)
            assert target.read_text() == "owned retained bytes"
            assert sorted(p.name for p in tmp_path.iterdir()) == ["retained"]
        finally:
            disconnect_all(state)


@pytest.mark.parametrize(
    ("state", "exit_code", "expected"),
    [
        ("enabled", 0, True),
        ("static", 0, True),
        ("generated", 0, True),
        ("transient", 0, True),
        ("enabled-runtime", 0, False),
        ("indirect", 0, False),
        ("alias", 0, False),
        ("disabled", 1, False),
    ],
)
def test_probe_preserves_actual_original_is_enabled_exit_and_output_semantics(
    tmp_path: Path, state: str, exit_code: int, expected: bool
) -> None:
    fake = tmp_path / "systemctl"
    fake.write_text(
        f"#!{sys.executable}\nimport sys\nif sys.argv[1] == 'show':\n"
        " print('LoadState=loaded\\nActiveState=deactivating')\nelse:\n"
        f" print({state!r})\n sys.exit({exit_code})\n"
    )
    fake.chmod(0o700)
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", SERVICE_PROBE, "owned.service"],
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert json.loads(result.stdout) == {
        "success": True,
        "load": "loaded",
        "active": "deactivating",
        "enabled": expected,
    }


@pytest.mark.parametrize("flag", FLAGS)
def test_each_original_flag_selects_only_its_declared_resources(flag: str) -> None:
    cfg = selected(**{flag: True})
    expected = {
        "remove_service": ["rm -rf " + cfg.systemd_unit_path, "systemctl daemon-reload"],
        "remove_traefik": ["rm -rf " + cfg.traefik_config_path],
        "remove_udev_rule": ["rm -rf " + cfg.udev_rule_path],
        "remove_virtualenv": ["rm -rf " + cfg.virtualenv_path, "rm -rf " + cfg.virtualenv_link],
        "remove_site_dir": ["rm -rf " + cfg.site_path],
        "remove_config_dir": ["rm -rf " + cfg.config_path],
        "remove_data_dir": ["rm -rf " + cfg.data_path],
        "remove_logs_dir": ["rm -rf " + cfg.logs_path],
        "remove_bin_dir": ["rm -rf " + cfg.bin_path],
        "remove_user": ["userdel homeassistant"],
        "remove_group": ["groupdel homeassistant"],
    }
    responses = {
        **service_response(enabled=False, active="inactive"),
        **fakehost.LINUX,
        **fakehost.system_account(cfg.user, cfg.home),
    }
    for name, path in cfg.model_dump().items():
        if name.endswith(("_path", "_link")):
            responses.update(fakehost.file(path, "owned resource"))
    run = run_deploy_fake(remove_homeassistant, cfg, responses=responses)
    assert run.succeeded, run.error
    assert run.executed_commands == expected[flag]


def test_absent_unit_error_is_retained_but_later_path_removal_continues() -> None:
    cfg = selected(remove_service=True, remove_traefik=True)
    run = run_deploy_fake(
        remove_homeassistant,
        cfg,
        responses={
            **service_response(load="not-found"),
            **fakehost.LINUX,
            **fakehost.file(cfg.traefik_config_path, "owned route"),
        },
    )
    assert run.error is None
    assert not run.succeeded
    assert run.executed_commands == ["systemctl daemon-reload", "rm -rf " + cfg.traefik_config_path]


def test_no_selected_removal_flag_has_no_operations() -> None:
    run = run_deploy_fake(remove_homeassistant, selected(), responses=fakehost.LINUX)
    assert run.succeeded
    assert not run.ops
    assert not run.executed_commands
