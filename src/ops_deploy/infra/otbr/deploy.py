"""Original OTBR checkout/build/config/service/udev sequence."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import Path
from typing import Any

from pyinfra import host, logger, state
from pyinfra.api import DeployError, deploy, operation
from pyinfra.api.command import StringCommand
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.files import File, FileContents
from pyinfra.facts.server import Command, Which
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.base._units import unit_states
from ops_deploy.helpers.probes import probe, stdin_arguments
from ops_deploy.infra.otbr.config import OtbrConfig
from ops_deploy.infra.otbr.prepare import build_effects, build_environment, build_record, render, resolved_interfaces

SOURCE_SCRIPT = (Path(__file__).parent.parent / "files/otbr_source_host.py").read_text()


def source_command(action: str, *, interpreter: str = "python3") -> str:
    encoded = base64.b64encode(SOURCE_SCRIPT.encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<otbr-source>','exec'))"
    return shlex.join([interpreter, "-I", "-B", "-c", loader, action])


def source_plan(cfg: OtbrConfig) -> dict[str, Any]:
    payload = {key: getattr(cfg, key) for key in ("repo_url", "repo_version", "install_dir")}
    if not host.get_fact(Which, command="git"):
        # A fresh host may acquire Git in the already-declared prerequisite
        # operation. Apply resolves then; setup/bootstrap are necessarily due.
        return {"before": None, "resolved": None, "kind": None, "changed": True, "git_missing": True}
    raw = probe(source_command("source-plan"), name="OTBR installed versus resolved source", stdin=json.dumps(payload))
    try:
        value = json.loads(raw) if raw is not None else None
    except ValueError:
        value = None
    if (
        not isinstance(value, dict)
        or type(value.get("changed")) is not bool
        or (
            not isinstance(value.get("resolved"), str)
            and not (value.get("kind") == "short-commit" and value.get("resolution_pending_git_fetch") is True)
        )
    ):
        raise DeployError("Cannot establish OTBR installed versus resolved source")
    return value


def path_state(path: str) -> dict[str, int] | None:
    raw = probe(source_command("path-state"), name="OTBR path metadata", stdin=json.dumps({"path": path}))
    try:
        value = json.loads(raw) if raw is not None else ...
    except (ValueError, TypeError):
        value = ...
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"mode", "uid", "gid"}
        or any(type(item) is not int for item in value.values())
    ):
        raise DeployError("Cannot establish OTBR path metadata")
    return value


@operation()
def stop_bind_services(services: tuple[str, ...]) -> Generator[Any, None, None]:
    # This is an operation body: inspect after source/bootstrap/setup, since
    # bootstrap itself can install/start BIND on the same first or update run.
    states = unit_states(services)
    for service in services:
        load = states[service].get("LoadState")
        if not load:
            raise DeployError("Cannot establish selected OTBR BIND service metadata")
        if load != "not-found":
            yield from systemd.service._inner(service=service, running=False, enabled=False)


@operation()
def original_packages(
    packages: tuple[str, ...], present: bool, purge: bool = False, deferred: bool = False
) -> Generator[Any, None, None]:
    if deferred and not state.is_executing:
        message = "OTBR selected package work unresolved until declared prerequisites and cache update execute"
        logger.warning(message)
        # Explicit pending work, never a resolved/noop plan. pyinfra regenerates
        # this body during execution and then probes post-prerequisite metadata.
        yield StringCommand(":", shlex.quote(message))
        return
    # Observe package/cache changes from earlier operations at execution time.
    raw = probe(
        source_command("packages-plan", interpreter="/usr/bin/python3"),
        name="Selected original OTBR APT metadata",
        stdin=json.dumps({"packages": packages, "present": present, "purge": purge}),
    )
    try:
        plan = json.loads(raw) if raw is not None else None
    except ValueError:
        plan = None
    if isinstance(plan, dict) and set(plan) == {"error"}:
        errors = {
            "python-apt": "the original OS python3-apt dependency cannot be imported",
            "candidate": "no selected OTBR package/version candidate is available",
            "metadata": "selected original OTBR APT metadata is unavailable",
        }
        reason = plan["error"] if isinstance(plan["error"], str) else "metadata"
        raise DeployError("Cannot establish original OTBR package metadata; " + errors.get(reason, errors["metadata"]))
    if (
        not isinstance(plan, dict)
        or set(plan) != {"install", "purge", "noop"}
        or any(
            not isinstance(value, list) or any(not isinstance(item, str) for item in value) for value in plan.values()
        )
    ):
        raise DeployError("Cannot establish original OTBR package metadata; selected metadata probe failed")
    for name in plan["noop"]:
        host.noop("Selected OTBR package already satisfies original state: " + name)
    for action, selected in [("install", plan["install"]), ("remove", plan["purge"])]:
        if not selected:
            continue
        argv = [
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "-q",
            "-y",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
        ]
        if action == "remove" and purge:
            argv.append("--purge")
        argv += [action, "--", *selected]
        yield from server.shell._inner(commands=[shlex.join(argv)])


def _build_command(cfg: OtbrConfig, script: str) -> str:
    return (
        "cd "
        + shlex.quote(cfg.install_dir)
        + " && "
        + shlex.join(
            ["env", *(key + "=" + value for key, value in build_environment(cfg).items()), "./script/" + script]
        )
    )


@deploy("Deploy OpenThread Border Router")
def deploy_otbr(cfg: OtbrConfig) -> None:
    require_linux("otbr")
    require_systemd("otbr")
    fallback = None
    if not cfg.infra_interface:
        fallback = host.get_fact(
            Command,
            command=(
                "ip -4 route get 8.8.8.8 | awk 'NR == 1 {for (i=1;i<=NF;i++) if ($i == \"dev\") {print $(i+1); exit}}'"
            ),
        )
    cfg = resolved_interfaces(cfg, fallback)
    if cfg.manage_packages:
        # The original Ansible apt module automatically installs this OS library.
        # Declare that dependency explicitly; selected metadata uses system Python.
        dependency_missing = not host.get_fact(DebPackages).get("python3-apt")
        apt.packages(name="Ensure original APT module dependency", packages=["python3-apt"], update=dependency_missing)
        apt.update(name="Update OTBR prerequisite package cache")
        original_packages(
            name="Install original OTBR prerequisite packages",
            packages=cfg.prereq_packages,
            present=True,
            deferred=True,
        )
    files.directory(name="Ensure OTBR install directory", path=cfg.install_dir, user="root", group="root", mode="0755")
    source = source_plan(cfg)
    marker = cfg.bootstrap_marker or cfg.install_dir + "/.otbr-bootstrap"
    record = cfg.build_config_path or cfg.install_dir + "/.otbr-build-config"
    previous = host.get_fact(FileContents, path=record)
    metadata = host.get_fact(File, path=record)
    current = bool(
        metadata
        and metadata.get("user") == "root"
        and metadata.get("group") == "root"
        and metadata.get("mode") == 644
        and previous is not None
        and "\n".join(previous) + "\n" == build_record(cfg)
    )
    effects = build_effects(
        cfg,
        source_changed=source["changed"],
        marker_exists=path_state(marker) is not None,
        agent_exists=path_state(cfg.agent_bin) is not None,
        record_current=current,
    )
    if effects.bootstrap:
        files.file(name="Invalidate OTBR bootstrap marker before selected attempt", path=marker, present=False)
    if effects.setup:
        # The eleven original settings lines do not identify the built commit.
        # Invalidate before Git/bootstrap/setup: failure after a source-only
        # advance must remain retryable even when the old binary still exists.
        files.file(name="Invalidate OTBR build record before selected attempt", path=record, present=False)
    payload = {key: getattr(cfg, key) for key in ("repo_url", "repo_version", "install_dir")}
    # The original normal role fetches even at the same commit. Keep that
    # visible source operation while deriving build triggers from actual change.
    source_payload = {**payload, "_source": None if source.get("git_missing") else source}
    server.shell(
        name="Force-update original recursive OTBR source",
        commands=[source_command("source-apply")],
        **stdin_arguments(json.dumps(source_payload)),
    )
    if effects.bootstrap:
        server.shell(name="Run original OTBR bootstrap", commands=[_build_command(cfg, "bootstrap")])
        server.shell(
            name="Mark successful OTBR bootstrap",
            commands=[
                "touch -- "
                + shlex.quote(marker)
                + " && chown root:root -- "
                + shlex.quote(marker)
                + " && chmod 0644 -- "
                + shlex.quote(marker)
            ],
        )
    setup = None
    if effects.setup:
        setup = server.shell(name="Build and install original OTBR", commands=[_build_command(cfg, "setup")])
        # Deliberate failed-build retry repair: publish only after successful
        # setup, so an old agent binary cannot hide the failed settings change.
        files.put(
            name="Record successful OTBR build settings",
            src=StringIO(build_record(cfg)),
            dest=record,
            user="root",
            group="root",
            mode="0644",
        )
    if cfg.remove_bind:
        stop_bind_services(name="Stop and disable original BIND services after bootstrap", services=cfg.bind_services)
        if cfg.manage_packages:
            original_packages(
                name="Purge original bind packages",
                packages=cfg.bind_packages,
                present=False,
                purge=True,
                deferred=True,
            )
    defaults = files.put(
        name="Render original OTBR agent defaults",
        src=StringIO(render(cfg, "otbr-agent.defaults.j2")),
        dest=cfg.agent_defaults_path,
        user="root",
        group="root",
        mode="0644",
    )
    rule = None
    if cfg.manage_udev:
        rule = files.put(
            name="Render original ZBT-2 udev rule",
            src=StringIO(render(cfg, "99-otbr-zbt2.rules.j2")),
            dest=cfg.udev_rule_path,
            user="root",
            group="root",
            mode="0644",
        )
    services = [(cfg.service_name, cfg.service_enabled)]
    if cfg.web_enabled:
        services.append((cfg.web_service_name, True))
    for service, enabled in services:
        systemd.service(
            name="Ensure original " + service + " state",
            service=service,
            enabled=enabled,
            running=cfg.service_state != "stopped",
            restarted=cfg.service_state == "restarted",
            reloaded=cfg.service_state == "reloaded",
            daemon_reload=True,
        )
    if cfg.restart_on_change and cfg.service_state == "started":
        changes = [defaults] + ([setup] if setup is not None else [])
        systemd.service(
            name="Original OTBR agent change handler",
            service=cfg.service_name,
            running=None,
            restarted=True,
            enabled=cfg.service_enabled,
            _if=any_changed(*changes),
        )
        if setup is not None and cfg.web_enabled:
            systemd.service(
                name="Original OTBR web build handler",
                service=cfg.web_service_name,
                running=None,
                restarted=True,
                enabled=True,
                _if=any_changed(setup),
            )
    if rule is not None:
        server.shell(
            name="Reload original udev rules", commands=["udevadm control --reload-rules"], _if=any_changed(rule)
        )
        server.shell(
            name="Trigger original tty udev rules",
            commands=["udevadm trigger --subsystem-match=tty"],
            _if=any_changed(rule),
        )
