"""Original OTBR desired/render/build trigger contracts; no hardware."""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from pyinfra.api.operation import OperationMeta

from ops_deploy.infra.otbr import OtbrConfig, deploy_otbr
from ops_deploy.infra.otbr.prepare import (
    build_effects,
    build_environment,
    build_record,
    render,
    resolved_interfaces,
    source_effect_map,
)

ROOT = Path(__file__).parent
PARITY = ROOT / "parity/otbr_deploy"


def config(**overrides: Any) -> OtbrConfig:
    return resolved_interfaces(OtbrConfig(rcp_device="/dev/owned-synthetic-rcp", infra_interface="owned0", **overrides))


def test_original_sources_and_templates_are_exact_snapshots() -> None:
    for name, digest in json.loads((PARITY / "SOURCE-HASHES.json").read_text()).items():
        assert hashlib.sha256((PARITY / name).read_bytes()).hexdigest() == digest
    for name in ["otbr-agent.defaults.j2", "99-otbr-zbt2.rules.j2"]:
        packaged = ROOT.parent / "src/ops_deploy/infra/otbr/templates" / name
        assert packaged.read_bytes() == (PARITY / "templates" / name).read_bytes()


def test_default_build_record_exact_original_order_and_custom_environment_replaces() -> None:
    cfg = config()
    expected = (
        "REST_API=1\nWEB_GUI=0\nOTBR_MDNS=openthread\nOTBR_DHCP6_PD_CLIENT=none\n"
        "BACKBONE_ROUTER=1\nBORDER_ROUTING=1\nNAT64=1\nDISCOVERY_PROXY=1\n"
        "FIREWALL=1\nINFRA_IF_NAME=owned0\nOTBR_OPTIONS=\n"
    )
    assert build_record(cfg) == expected
    assert build_environment(cfg) == dict(line.split("=", 1) for line in expected.splitlines())
    assert build_environment(config(build_env={"ONLY_THIS": "literal $ and spaces"})) == {
        "ONLY_THIS": "literal $ and spaces"
    }
    assert build_environment(config(build_env={})) == {}


@pytest.mark.parametrize(("rest", "noattach", "extra", "web"), list(itertools.product([False, True], repeat=4)))
def test_templates_preserve_original_literal_options(rest: bool, noattach: bool, extra: bool, web: bool) -> None:
    cfg = config(
        rest_api_enabled=rest,
        no_auto_attach=noattach,
        agent_extra_opts="--owned option" if extra else "",
        web_enabled=web,
    )
    options = "-I wpan0 -B owned0 spinel+hdlc+uart:///dev/owned-synthetic-rcp?uart-baudrate=460800"
    if rest:
        options += " --rest-listen-address 127.0.0.1 --rest-listen-port 8081"
    if extra:
        options += " --owned option"
    assert render(cfg, "otbr-agent.defaults.j2") == (
        "# Managed by Ansible - OTBR agent defaults\n"
        f'OTBR_AGENT_OPTS="{options}"\nOTBR_NO_AUTO_ATTACH={int(noattach)}\n'
    )
    rules = render(cfg, "99-otbr-zbt2.rules.j2")
    assert rules == "# Home Assistant Connect ZBT-2 (ESP32-S3 USB serial)\n" + "".join(
        f'SUBSYSTEM=="tty", ATTRS{{idVendor}}=="303a", ATTRS{{idProduct}}=="{pid}", GROUP="dialout", MODE="0660"\n'
        for pid in ["4001", "831a"]
    )


@pytest.mark.parametrize(
    ("source", "marker", "agent", "record", "forceboot", "forcebuild", "web", "restart", "started"),
    list(itertools.product([False, True], repeat=9)),
)
def test_original_build_and_handler_predicates(
    source: bool,
    marker: bool,
    agent: bool,
    record: bool,
    forceboot: bool,
    forcebuild: bool,
    web: bool,
    restart: bool,
    started: bool,
) -> None:
    cfg = config(
        force_bootstrap=forceboot,
        force_rebuild=forcebuild,
        web_enabled=web,
        restart_on_change=restart,
        service_state="started" if started else "stopped",
    )
    result = build_effects(cfg, source_changed=source, marker_exists=marker, agent_exists=agent, record_current=record)
    assert result.bootstrap == (forceboot or source or not marker)
    assert result.setup == (forcebuild or source or not record or not agent)
    assert result.publish_build_record == result.setup
    assert result.restart_agent_after_setup == (result.setup and restart and started)
    assert result.restart_web_after_setup == (result.setup and restart and started and web)


def test_fallback_and_validation_preserve_configured_interface() -> None:
    assert resolved_interfaces(OtbrConfig(rcp_device="/dev/owned"), "fallback0").infra_interface == "fallback0"
    assert (
        resolved_interfaces(
            OtbrConfig(rcp_device="/dev/owned", infra_interface="chosen0"), "fallback0"
        ).backbone_interface
        == "chosen0"
    )
    with pytest.raises(ValueError, match="infra_interface"):
        resolved_interfaces(OtbrConfig(rcp_device="/dev/owned"))
    with pytest.raises(ValidationError):
        OtbrConfig(rcp_device="CHANGEME")
    with pytest.raises(ValidationError):
        config(rest_listen_address="")
    with pytest.raises(ValidationError):
        config(build_env={"BAD=KEY": "no"})


def test_source_effect_map_does_not_mask_upstream_main() -> None:
    cfg = config()
    effects = build_effects(cfg, source_changed=True, marker_exists=True, agent_exists=True, record_current=True)
    value = source_effect_map(cfg, {"before": "a" * 40, "resolved": "b" * 40}, effects)
    assert value["installed_commit"] != value["resolved_commit"]
    assert value["setup"]
    assert value["bootstrap"]
    assert value["restart_agent_after_setup"]
    assert value["may_manage_prerequisite_packages"]
    assert value["may_install_original_os_apt_dependency"]
    assert value["may_update_apt_cache"]
    assert value["may_remove_bind"]
    assert value["may_purge_bind_packages"]
    assert value["udev_rule_managed"]
    assert value["source_ref_is_installed_mask"] is False


def test_invalidation_precedes_source_and_success_publication_follows_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    events: list[str] = []

    def record(**kwargs: Any) -> OperationMeta:
        events.append(kwargs["name"])
        return Mock(spec=OperationMeta, will_change=True)

    monkeypatch.setattr(module, "require_linux", lambda _: None)
    monkeypatch.setattr(module, "require_systemd", lambda _: None)
    monkeypatch.setattr(
        module, "source_plan", lambda _: {"changed": True, "before": "a" * 40, "resolved": "b" * 40, "kind": "branch"}
    )
    monkeypatch.setattr(module, "path_state", lambda _: {"mode": 0, "uid": 0, "gid": 0})
    monkeypatch.setattr(module, "host", Mock(get_fact=lambda *args, **kwargs: None))
    for operation in ["directory", "file", "put"]:
        monkeypatch.setattr(module.files, operation, record)
    monkeypatch.setattr(module.server, "shell", record)
    monkeypatch.setattr(module.systemd, "service", record)
    deploy_otbr._inner(config(manage_packages=False, remove_bind=False))
    index = events.index
    assert index("Invalidate OTBR bootstrap marker before selected attempt") < index(
        "Force-update original recursive OTBR source"
    )
    assert index("Invalidate OTBR build record before selected attempt") < index(
        "Force-update original recursive OTBR source"
    )
    assert (
        index("Run original OTBR bootstrap")
        < index("Mark successful OTBR bootstrap")
        < index("Build and install original OTBR")
    )
    assert index("Build and install original OTBR") < index("Record successful OTBR build settings")
    assert not any("web" in item for item in events)


@pytest.mark.parametrize(("backbone", "expected"), [(None, "owned0"), ("", ""), ("custom0", "custom0")])
def test_original_explicit_empty_backbone_is_distinct_from_unset(backbone: str | None, expected: str) -> None:
    cfg = config(backbone_interface=backbone)
    assert cfg.backbone_interface == expected
    assert f"-B {expected} spinel" in render(cfg, "otbr-agent.defaults.j2")


@pytest.mark.parametrize(
    "repo",
    ["http://example.invalid/otbr.git", "git://example.invalid/otbr.git", "/owned/local/mirror", "../relative-mirror"],
)
def test_original_repo_transports_and_local_mirrors_remain_configurable(repo: str) -> None:
    assert config(repo_url=repo).repo_url == repo


def test_original_package_pins_and_extended_udev_mode_are_retained() -> None:
    cfg = config(prereq_packages=("git=1:2.43.*",), bind_packages=("bind9=1:9.18.*",), udev_mode="01777")
    assert cfg.prereq_packages == ("git=1:2.43.*",)
    assert cfg.bind_packages == ("bind9=1:9.18.*",)
    assert 'MODE="01777"' in render(cfg, "99-otbr-zbt2.rules.j2")


def test_bind_service_presence_is_observed_inside_operation_after_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    installed = False

    def states(services: tuple[str, ...]) -> dict[str, dict[str, str]]:
        assert installed, "presence was observed before synthetic bootstrap"
        return {services[0]: {"LoadState": "loaded"}}

    monkeypatch.setattr(module, "unit_states", states)
    monkeypatch.setattr(module.systemd.service, "_inner", lambda **kwargs: iter([kwargs]))
    generator = module.stop_bind_services._inner(("owned-late-bind.service",))
    installed = True
    assert list(generator) == [{"service": "owned-late-bind.service", "running": False, "enabled": False}]


@pytest.mark.parametrize("field", ["repo_url", "repo_version"])
def test_git_options_are_refused_without_losing_original_transport_forms(field: str) -> None:
    with pytest.raises(ValidationError, match="Git options"):
        config(**{field: "--upload-pack=owned-never-executed"})


def test_selected_package_metadata_is_deferred_and_command_values_are_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import json
    import shlex

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    ready = False

    def selected(command: str, *, name: str, stdin: str) -> str:
        assert ready, "package state was inspected before earlier operations"
        assert shlex.split(command)[0] == "/usr/bin/python3"
        assert json.loads(stdin) == {"packages": ["owned=1.2.*"], "present": True, "purge": False}
        return json.dumps({"install": ["owned=1.2.4"], "purge": [], "noop": []})

    monkeypatch.setattr(module, "probe", selected)
    monkeypatch.setattr(module.server.shell, "_inner", lambda **kwargs: iter(kwargs["commands"]))
    deferred = module.original_packages._inner(packages=("owned=1.2.*",), present=True)
    ready = True
    (command,) = deferred
    assert shlex.split(command)[-3:] == ["install", "--", "owned=1.2.4"]


def test_unavailable_selected_package_metadata_refuses_before_package_command(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib

    from pyinfra.api import DeployError

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    monkeypatch.setattr(module, "probe", lambda *args, **kwargs: '{"error":"python-apt"}')
    with pytest.raises(DeployError, match="original OS python3-apt dependency"):
        list(module.original_packages._inner(packages=("owned",), present=True))


@pytest.mark.parametrize(
    ("payload", "message"),
    [('{"error":"candidate"}', "no selected OTBR package/version candidate"), (None, "selected metadata probe failed")],
)
def test_candidate_failure_is_distinct_from_missing_os_library(
    payload: str | None, message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from pyinfra.api import DeployError

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    monkeypatch.setattr(module, "probe", lambda *args, **kwargs: payload)
    with pytest.raises(DeployError, match=message):
        list(module.original_packages._inner(packages=("owned",), present=True))


def test_actual_sdk_prepare_defers_until_prerequisite_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib
    import shlex

    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.operation import add_op
    from pyinfra.api.operations import run_ops
    from pyinfra.operations import server

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    fixture = tmp_path / "selected-package-metadata.json"
    state = State(Inventory(([("@local", {})], {})), Config())
    from ops_deploy.helpers.probes import probe as original_probe

    phases: list[bool] = []

    def observe(command: str, **kwargs: Any) -> str | None:
        phases.append(state.is_executing)
        assert fixture.exists(), "selected metadata read before prerequisite execution"
        return original_probe(command, **kwargs)

    monkeypatch.setattr(module, "source_command", lambda *args, **kwargs: "cat " + shlex.quote(str(fixture)))
    monkeypatch.setattr(module, "probe", observe)
    connect_all(state)
    try:
        add_op(
            state,
            server.shell,
            name="Owned prerequisite publishes selected metadata",
            commands=[
                "printf %s "
                + shlex.quote('{"install":[],"purge":[],"noop":["owned"]}')
                + " > "
                + shlex.quote(str(fixture))
            ],
        )
        metas = add_op(state, module.original_packages, packages=("owned",), present=True, deferred=True)
        meta = next(iter(metas.values()))
        assert not fixture.exists()
        assert phases == []
        assert meta.will_change, "pending work must not be presented as a resolved noop"
        run_ops(state)
        assert phases == [True]
        assert not meta.did_change()
        assert not state.failed_hosts
    finally:
        disconnect_all(state)


@pytest.mark.parametrize("dependency_present", [False, True])
def test_dependency_bootstrap_cache_only_when_missing_and_selected_decisions_deferred(
    dependency_present: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    module = importlib.import_module("ops_deploy.infra.otbr.deploy")
    events: list[dict[str, Any]] = []

    def record(**kwargs: Any) -> OperationMeta:
        events.append(kwargs)
        return Mock(spec=OperationMeta, will_change=True)

    monkeypatch.setattr(module, "require_linux", lambda _: None)
    monkeypatch.setattr(module, "require_systemd", lambda _: None)
    monkeypatch.setattr(module, "source_plan", lambda _: {"changed": True})
    monkeypatch.setattr(module, "path_state", lambda _: None)
    monkeypatch.setattr(
        module,
        "host",
        Mock(
            get_fact=lambda fact, **kwargs: (
                {"python3-apt": {"owned"}}
                if fact is module.DebPackages and dependency_present
                else {}
                if fact is module.DebPackages
                else None
            )
        ),
    )
    for operation in ["directory", "file", "put"]:
        monkeypatch.setattr(module.files, operation, record)
    for operation in ["packages", "update"]:
        monkeypatch.setattr(module.apt, operation, record)
    monkeypatch.setattr(module, "original_packages", record)
    monkeypatch.setattr(module, "stop_bind_services", record)
    monkeypatch.setattr(module.server, "shell", record)
    monkeypatch.setattr(module.systemd, "service", record)
    deploy_otbr._inner(config())
    rows = {row["name"]: row for row in events}
    names = list(rows)
    assert rows["Ensure original APT module dependency"]["update"] is not dependency_present
    assert (
        names.index("Ensure original APT module dependency")
        < names.index("Update OTBR prerequisite package cache")
        < names.index("Install original OTBR prerequisite packages")
    )
    assert rows["Install original OTBR prerequisite packages"]["deferred"] is True
    assert rows["Purge original bind packages"]["deferred"] is True
