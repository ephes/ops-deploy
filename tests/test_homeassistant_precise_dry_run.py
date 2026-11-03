"""A dry run (``--dry``) of the Home Assistant deploy lists only real changes.

A converged host plans no change; real drift is still listed; operations only
execution can decide are listed as conditional; execution is unchanged.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from collections.abc import Callable
from functools import partial
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.operations import files as file_ops
from pyinfra.operations import server

from ops_deploy.services.homeassistant import configuration_deploy
from ops_deploy.services.homeassistant.application import application_command
from ops_deploy.services.homeassistant.configuration import ConfigurationPolicy
from ops_deploy.services.homeassistant.configuration_deploy import configure_files
from ops_deploy.services.homeassistant.configuration_render import ConfigurationValues
from ops_deploy.services.homeassistant.python_runtime import configure_python_runtime
from ops_deploy.services.homeassistant.render import render_unit
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.services.homeassistant.services import ensure_service_states, write_units
from ops_deploy.testing import run_deploy_fake
from ops_deploy.testing.harness import collect_ops
from tests import fakehost
from tests.test_homeassistant_configuration import MET, USER
from tests.test_homeassistant_configuration_deploy import config
from tests.test_homeassistant_python_runtime import current, responses  # noqa: F401  (fixture)

module = importlib.import_module("ops_deploy.services.homeassistant.deploy")
SECRET = "owned-dry-run-secret-5521"
SECRETS_BODY = f"unifi_password: {SECRET}\n"
CONFIG_BODY = "# rendered configuration\n"


# --- configuration.yaml / secrets.yaml (real files over @local) ------------------------------------


def _renderer(kind: str, item: str | None, executing: bool) -> SecretStr:
    return SecretStr(SECRETS_BODY if kind == "secrets" else CONFIG_BODY)


def _plan(cfg: HomeAssistantRuntimeConfig, policy: ConfigurationPolicy) -> tuple[dict[str, bool], Any]:
    """Plan only (no execution), as ``--dry`` does; planned change per op name."""
    state = State(Inventory(([("@local", {})], {})), Config(DIFF=True))
    results: list[Any] = []
    try:
        connect_all(state)
        add_deploy(
            state,
            lambda: results.append(
                configure_files(cfg, policy, ConfigurationValues(), task_renderer=_renderer, deferred=False)
            ),
        )
        local = state.inventory.get_host("@local")
        planned: dict[str, bool] = {}
        for key in state.get_op_order():
            meta = state.get_op_data_for_host(local, key).operation_meta
            name = ", ".join(sorted(state.get_op_meta(key).names))
            planned[name] = planned.get(name, False) or bool(meta.will_change)
        with_state = results[0]
        notified = with_state.homeassistant_changed()
        return planned, notified
    finally:
        disconnect_all(state)


def _converged(tmp_path: Path) -> tuple[HomeAssistantRuntimeConfig, ConfigurationPolicy]:
    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    (root / "configuration.yaml").write_text(USER)
    secrets = root / "secrets.yaml"
    secrets.write_text(SECRETS_BODY)
    secrets.chmod(0o600)
    policy = ConfigurationPolicy(
        manage_configuration=True, manage_secrets=True, overwrite_config=False, remove_legacy_met_weather_yaml=True
    )
    return cfg, policy


def test_converged_configuration_and_secrets_plan_no_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cfg, policy = _converged(tmp_path)
    sent: list[tuple[bool, str]] = []
    from pyinfra import state

    from ops_deploy.services.homeassistant.transport import run_protected_command

    def spy(target: Any, command: Any, **kwargs: Any) -> Any:
        sent.append((bool(state.is_executing), "".join(kwargs.get("_stdin") or [])))
        return run_protected_command(target, command, **kwargs)

    monkeypatch.setattr(configuration_deploy, "run_protected_command", spy)
    planned, notified = _plan(cfg, policy)
    assert planned  # the template and the three replacements were planned ...
    assert not any(planned.values()), planned  # ... and none is a change
    assert notified is False  # so no Home Assistant restart is planned
    # The host compared the secrets file against a digest; no body travelled.
    checks = [json.loads(stdin) for executing, stdin in sent if not executing]
    secrets_check = [item for item in checks if item["path"].endswith("secrets.yaml")]
    assert secrets_check
    assert all("content" not in item and "content_sha256" in item for item in secrets_check)
    assert not any(SECRET in stdin for _, stdin in sent)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("drift", ["replace", "secrets", "secrets-mode"])
def test_configuration_drift_is_still_planned(tmp_path: Path, drift: str) -> None:
    cfg, policy = _converged(tmp_path)
    root = Path(cfg.config_path)
    if drift == "replace":
        (root / "configuration.yaml").write_text(USER + MET)
    elif drift == "secrets":
        (root / "secrets.yaml").write_text("unifi_password: stale\n")
    else:
        (root / "secrets.yaml").chmod(0o644)
    planned, notified = _plan(cfg, policy)
    changed = sorted(name for name, value in planned.items() if value)
    if drift == "replace":
        assert changed == ["Manage Home Assistant configuration.yaml (replace)"]
        assert notified is True
    else:
        assert changed == ["Manage Home Assistant secrets.yaml (template)"]
        assert notified is False


def test_digest_check_never_writes_and_matches_the_body_check(tmp_path: Path) -> None:
    helper = files("ops_deploy.services.homeassistant").joinpath("files/configuration_file.py")
    cfg = config(tmp_path)
    path = tmp_path / "secrets.yaml"
    path.write_text(SECRETS_BODY)
    path.chmod(0o600)
    base = {"kind": "template", "path": str(path), "user": cfg.user, "group": cfg.group, "mode": "0600"}

    def check(**extra: Any) -> dict[str, Any]:
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(helper)],
            input=json.dumps({**base, **extra}),
            text=True,
            capture_output=True,
        )
        assert SECRET not in result.stdout + result.stderr
        return dict(json.loads(result.stdout))

    import hashlib

    good = hashlib.sha256(SECRETS_BODY.encode()).hexdigest()
    assert check(action="check", content_sha256=good)["changed"] is False
    assert check(action="check", content_sha256="0" * 64)["changed"] is True
    assert check(action="check", content=SECRETS_BODY)["changed"] is False
    # A digest cannot be written: apply with a digest is refused untouched.
    before = path.stat()
    refused = check(action="apply", content_sha256="0" * 64)
    assert refused["success"] is False
    assert refused["effects_started"] is False
    assert path.read_text() == SECRETS_BODY
    assert path.stat().st_mtime_ns == before.st_mtime_ns


# --- Python runtime, venvs, applications and extras (fake host) ------------------------------------


EXTRAS_CURRENT = {"<ha-extra-packages>": ['{"success": true, "current": true}']}
EXTRAS_DRIFT = {"<ha-extra-packages>": ['{"success": true, "current": false}']}


def _runtime_cfg() -> HomeAssistantRuntimeConfig:
    return HomeAssistantRuntimeConfig(
        manage_matter_server=True,
        package_spec="homeassistant==2026.10.2",
        matter_server_package_spec="python-matter-server[server]==8.1.2",
        extra_package_specs=("owned-extra==1",),
    )


def test_pinned_runtime_plans_no_change_and_no_restart(current: list[tuple[str, str]]) -> None:  # noqa: F811
    cfg = _runtime_cfg()
    notified: list[tuple[bool, bool]] = []

    def deploy() -> None:
        changes = configure_python_runtime(cfg, deferred=False)
        notified.append((changes.homeassistant_changed(), changes.matter_changed()))

    run = run_deploy_fake(deploy, responses={**responses(cfg), **EXTRAS_CURRENT})
    assert run.succeeded, run.error
    assert run.planned_changes == []
    assert run.planned_conditional == []
    assert notified == [(False, False)]
    # Execution is unchanged: the extras install still runs (UV only audits).
    assert any("pip install" in command for command in run.executed_commands)
    assert application_command(cfg, "homeassistant") not in run.executed_commands


def test_runtime_drift_is_still_planned(current: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    from ops_deploy.services.homeassistant import application
    from ops_deploy.services.homeassistant.python_state import EnvironmentState

    cfg = _runtime_cfg()

    def observe(cfg: HomeAssistantRuntimeConfig, kind: str, phase: str) -> EnvironmentState:
        version = "8.1.2" if kind == "matter" else "2026.10.1"  # HA one release behind
        return EnvironmentState(
            True, "Python " + cfg.python_version, application_exists=True, installed_version=version
        )

    monkeypatch.setattr(application, "_observe", observe)
    run = run_deploy_fake(
        lambda: configure_python_runtime(cfg, deferred=False), responses={**responses(cfg), **EXTRAS_CURRENT}
    )
    assert run.succeeded, run.error
    # The upgrade, and the extras that follow it, are planned.
    assert run.planned_changes == [
        "Install Home Assistant application",
        "Resolve and install Home Assistant extra packages",
    ]
    run = run_deploy_fake(
        lambda: configure_python_runtime(cfg, deferred=False), responses={**responses(cfg), **EXTRAS_DRIFT}
    )
    assert "Resolve and install Home Assistant extra packages" in run.planned_changes


def test_deferred_runtime_keeps_unresolved_rows(current: list[tuple[str, str]]) -> None:  # noqa: F811
    cfg = _runtime_cfg()
    run = run_deploy_fake(
        lambda: configure_python_runtime(cfg, deferred=True), responses={**responses(cfg), **EXTRAS_CURRENT}
    )
    assert run.succeeded, run.error
    assert "Install Home Assistant requested Python" in run.planned_changes
    assert "Resolve and install Home Assistant extra packages" in run.planned_changes


def _owned_distribution(tmp_path: Path, name: str, version: str, requires: tuple[str, ...] = ()) -> None:
    info = tmp_path / f"{name}-{version}.dist-info"
    info.mkdir()
    lines = [f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"]
    lines += [f"Requires-Dist: {item}\n" for item in requires]
    (info / "METADATA").write_text("".join(lines))


@pytest.mark.parametrize(
    ("specs", "constraints", "expected"),
    [
        (["owned-a==1.0"], "", True),
        (["owned-a==1.0", "owned-b>=2"], "", True),
        (["owned-a==1.1"], "", False),
        (["owned-missing==1"], "", False),
        (["owned-c==1.0"], "", False),  # its dependency is missing
        (["owned-a==1.0"], "owned-b>=3\n", False),  # a dependency violates a constraint
        (["owned-a==1.0"], "owned-b>=2\n# comment\n", True),
        (["owned-a==1.0; python_version < '3'"], "", True),  # marker excludes it
        (["--pre"], "", False),
    ],
)
@pytest.mark.parametrize("duplicate", [False, True])
def test_extras_probe_program(
    tmp_path: Path, specs: list[str], constraints: str, expected: bool, duplicate: bool
) -> None:
    pytest.importorskip("packaging")
    expected = expected and not duplicate  # duplicate metadata: UV would reinstall
    site = tmp_path / "site"
    site.mkdir()
    _owned_distribution(site, "owned_a", "1.0", ("owned-b>=2", "owned-x; extra == 'never'"))
    _owned_distribution(site, "owned_b", "2.5")
    _owned_distribution(site, "owned_c", "1.0", ("owned-absent>=1",))
    constraint = tmp_path / "constraints.txt"
    constraint.write_text(constraints)
    program = files("ops_deploy.services.homeassistant").joinpath("files/extra_packages_observe.py")
    if duplicate:
        _owned_distribution(site, "Owned.A", "0.9")
    # The program runs with the service venv's Python (which has packaging).
    launcher = (
        f"import sys; sys.path[:0] = [{str(site)!r}]; "
        f"sys.argv = ['probe']; exec(compile(open({str(program)!r}).read(), 'probe', 'exec'))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", launcher],
        input=json.dumps({"specs": specs, "constraints": [str(constraint)]}),
        text=True,
        capture_output=True,
    )
    if specs == ["--pre"]:
        assert json.loads(result.stdout) in ({"success": True, "current": False}, {"success": False})
    else:
        assert json.loads(result.stdout) == {"success": True, "current": expected}, result.stderr


# --- service units, desired state and handlers (fake host) -----------------------------------------


def _unit_responses(cfg: HomeAssistantRuntimeConfig, *, matter_unit: str | None = None) -> dict[str, Any]:
    return {
        **fakehost.LINUX,
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.file(cfg.systemd_unit_path, render_unit(cfg, "homeassistant")),
        **fakehost.file(
            cfg.matter_server_systemd_unit_path,
            render_unit(cfg, "matter-server") if matter_unit is None else matter_unit,
        ),
        **fakehost.service(cfg.service_name + ".service"),
        **fakehost.service(cfg.matter_server_service_name + ".service"),
    }


@pytest.mark.parametrize("drift", [False, True])
def test_unchanged_matter_unit_plans_no_restart(drift: bool) -> None:
    cfg = HomeAssistantRuntimeConfig(manage_matter_server=True)

    def deploy() -> None:
        pending = module._PendingHandlers()
        units = write_units(cfg)
        pending.reload.append(units.reload_required)
        pending.homeassistant.append(units.homeassistant_changed)
        pending.matter.append(units.matter_changed)
        ensure_service_states(cfg)
        pending.flush(cfg)

    run = run_deploy_fake(deploy, responses=_unit_responses(cfg, matter_unit="stale\n" if drift else None))
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    if drift:
        assert run.planned_changes == ["Write Matter server service unit"]
        assert run.planned_conditional == ["Reload Home Assistant systemd units", "Restart Matter server after changes"]
        assert commands.count("restart matter-server.service") == 1
    else:
        assert run.planned_changes == []
        assert run.planned_conditional == []
        assert "restart matter-server.service" not in commands
    assert "restart homeassistant.service" not in commands
    # Execution keeps the original unconditional desired-state daemon reload.
    assert commands.count("systemctl daemon-reload") == 2 + int(drift)


@pytest.mark.parametrize("trigger", [False, True])
def test_udev_handlers_follow_the_planned_rule(trigger: bool) -> None:
    from ops_deploy.services.homeassistant.host_layout import run_udev_handlers

    def deploy() -> None:
        rule = server.shell(name="Owned rule", commands=["printf rule"] if trigger else [])
        run_udev_handlers(rule)

    run = run_deploy_fake(deploy, responses=fakehost.LINUX)
    assert run.succeeded, run.error
    expected = ["Reload Home Assistant udev rules", "Trigger Home Assistant tty udev"] if trigger else []
    assert run.planned_conditional == expected
    assert ("udevadm control --reload-rules" in run.executed_commands) is trigger


# --- whole-deploy composition: deferral, read-only checks and conditional rows ---------------------


def _stubbed(monkeypatch: pytest.MonkeyPatch, *, layout: bool, uv: bool, probes: bool) -> dict[str, bool]:
    from tests.test_homeassistant_deploy import stub_composition

    stub_composition(monkeypatch)
    seen: dict[str, bool] = {}

    def configure_layout(cfg: Any, *, task_renderer: Any = None, prerequisites: list[Any]) -> None:
        prerequisites.extend([SimpleNamespace(will_change=False), SimpleNamespace(will_change=layout)])

    def python(cfg: Any, **kwargs: Any) -> Any:
        seen["runtime"] = kwargs["deferred"]
        return SimpleNamespace(homeassistant_changed=lambda: False, matter_changed=lambda: False)

    def configuration(*args: Any, **kwargs: Any) -> Any:
        seen["configuration"] = kwargs["deferred"]
        return SimpleNamespace(homeassistant_changed=lambda: False)

    monkeypatch.setattr(module, "configure_layout", configure_layout)
    monkeypatch.setattr(module, "install_uv", lambda *args, **kwargs: uv)
    monkeypatch.setattr(module, "configure_python_runtime", python)
    monkeypatch.setattr(module, "configure_files", configuration)
    monkeypatch.setattr(module, "plan_probes", lambda: probes)
    return seen


@pytest.mark.parametrize(
    ("layout", "uv", "probes", "runtime", "configuration"),
    [
        (False, False, True, False, False),  # converged: inspect while planning
        (True, False, True, True, True),  # account/directories planned: defer both
        (False, True, True, True, False),  # UV planned: only UV users defer
        (False, False, False, True, True),  # ``-y``: unchanged unconditional deferral
    ],
)
def test_deploy_defers_only_while_a_prerequisite_is_planned(
    monkeypatch: pytest.MonkeyPatch, layout: bool, uv: bool, probes: bool, runtime: bool, configuration: bool
) -> None:
    from tests.test_homeassistant_deploy import selected

    seen = _stubbed(monkeypatch, layout=layout, uv=uv, probes=probes)
    module.deploy_homeassistant.__wrapped__(cfg=selected())
    assert seen == {"runtime": runtime, "configuration": configuration}


def _check(op: Callable[[], Any]) -> Any:
    return run_deploy_fake(op, responses={**fakehost.LINUX, **fakehost.deb_installed("owned-package")})


def test_read_only_checks_and_package_refresh_plan_no_change() -> None:
    cfg = HomeAssistantRuntimeConfig()
    run = _check(
        lambda: (
            module._system_packages(name="Install Home Assistant system packages", packages=["owned-package"]),
            module.application_check(cfg, ["/owned/hass", "--script", "check_config"], "Validate owned"),
        )
    )
    assert run.succeeded, run.error
    assert run.planned_changes == []
    assert run.planned_conditional == []
    commands = "\n".join(run.executed_commands)
    assert "apt-get update" in commands  # the refresh still runs on every apply
    assert "check_config" in commands
    missing = run_deploy_fake(
        lambda: module._system_packages(name="Install Home Assistant system packages", packages=["owned-missing"]),
        responses=fakehost.LINUX,
    )
    assert missing.planned_changes == ["Install Home Assistant system packages"]


def test_api_operations_are_conditional_not_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    from ops_deploy.services.homeassistant.area_registry import AreaResult, manage_area_registry
    from ops_deploy.services.homeassistant.integration_flows import ApiReadiness, HomeAssistantApiConfig

    api = HomeAssistantApiConfig(token="owned-deploy-token-with-at-least-32-characters")
    state = State(Inventory((["@fake"], {})), Config())
    try:
        connect_all(state)
        add_deploy(
            state,
            lambda: manage_area_registry(
                HomeAssistantRuntimeConfig(), api, ApiReadiness(), [{"name": "Room"}], AreaResult(), app_port=8123
            ),
        )
        planned = {op.name: op.planned for op in collect_ops(state, "@fake")}
    finally:
        disconnect_all(state)
    assert planned == {"Wait for Home Assistant API": None, "Reconcile Home Assistant area registry": "conditional"}


def test_layout_collects_its_prerequisites_and_plans_none_when_current() -> None:
    from ops_deploy.services.homeassistant.host_layout import configure_layout, directories

    cfg = HomeAssistantRuntimeConfig(enable_udev_rule=False)
    collected: list[Any] = []
    responses = {
        **fakehost.LINUX,
        "cat /etc/group": [f"{cfg.group}:x:1000:", "dialout:x:20:"],
        "cat /etc/passwd | cut": [f"{cfg.user}:x:1000:1000::{cfg.home}:/bin/bash|{cfg.user}|{cfg.user} dialout||!"],
        **{key: value for path in directories(cfg) for key, value in fakehost.directory(path, user=cfg.user).items()},
    }
    run = run_deploy_fake(lambda: configure_layout(cfg, prerequisites=collected), responses=responses)
    assert run.succeeded, run.error
    assert len(collected) == 1 + len(directories(cfg))
    assert run.planned_changes == []


def test_harness_planned_kinds() -> None:
    def deploy() -> None:
        server.shell(name="Owned change", commands=["true"])
        server.shell(name="Owned conditional", commands=["true"], _if=lambda: False)
        file_ops.directory(name="Owned current", path="/owned", present=True, _if=partial(bool, 1))

    run = run_deploy_fake(deploy, responses=fakehost.directory("/owned"))
    assert run.planned_changes == ["Owned change"]
    assert run.planned_conditional == ["Owned conditional"]
