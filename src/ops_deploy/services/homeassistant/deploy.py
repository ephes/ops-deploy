"""Original normal deployment composition, awaiting owned application qualification.

This preserves explicit managed refresh/resolution/canary/reload work; it does not
claim a zero-managed repeat or hardware proof. Per-host state lives in this call.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Any, Literal

from paramiko import SSHException
from pyinfra import host, logger
from pyinfra.api import DeployError, FunctionCommand, OperationError, State, StringCommand, deploy, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt

from ops_deploy.base._common import require_linux
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .area_registry import AreaResult, manage_area_registry
from .builtin_conversation import ConversationResult, install_builtin_helper, run_builtin_conversation
from .configuration_deploy import configure_files
from .custom_component import install_custom_component
from .custom_conversation import CustomConversationResult, run_custom_conversation
from .deploy_config import HomeAssistantDeployConfig
from .host_layout import configure_layout, run_udev_handlers
from .ingress import write_ingress
from .integration_flows import ApiReadiness, ensure_api_readiness, integrate, reset_api_readiness
from .legacy_conversation import inspect_legacy_conversation, remove_legacy_component
from .pipelines import PipelineResult, manage_pipelines
from .python_runtime import configure_python_runtime
from .runtime_config import HomeAssistantRuntimeConfig
from .security import security_preflight, verify_security, write_constraints
from .services import ensure_service_states, flush_service_handlers, write_units
from .trust import inspect_trust, verify_running_trust, write_managed_dropin
from .uv import install_uv


def _selection(cfg: HomeAssistantRuntimeConfig, kind: Literal["uv", "custom"]) -> dict[str, Any]:
    source = resources("ops_deploy.services.homeassistant").joinpath("files/deployment_observe.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-selection>','exec'))"
    )
    path = cfg.uv_path if kind == "uv" else cfg.config_path + "/.storage/core.config_entries"
    try:
        success, output = host.run_shell_command(
            StringCommand(shlex.join([cfg.security.system_python, "-I", "-B", "-c", launcher])),
            _stdin=StdinLines(json.dumps({"kind": kind, "path": path})),
            _get_pty=False,
            print_input=False,
            print_output=False,
            _timeout=90,
        )
    except (OSError, SSHException):
        raise DeployError("Home Assistant prerequisite/selection inspection failed") from None
    try:
        value = json.loads(str(output.stdout))
        key = "exists" if kind == "uv" else "count"
        expected = bool if kind == "uv" else int
        if not success or not isinstance(value, dict) or set(value) != {"success", key} or value["success"] is not True:
            raise ValueError
        if type(value[key]) is not expected or (kind == "custom" and value[key] < 0):
            raise ValueError
    except (ValueError, TypeError):
        raise DeployError("Home Assistant prerequisite/selection inspection failed") from None
    return value


def _checked_command(state: State, host: Host, command: str, label: str) -> None:
    # Original check_config/import commands can print configuration/model details.
    # Keep output host-local/controller transient only; emit no raw stdout/stderr.
    try:
        success, _ = host.run_shell_command(
            StringCommand(command),
            _get_pty=False,
            print_input=False,
            print_output=False,
            _timeout=3600,
        )
    except (OSError, SSHException):
        raise OperationError(label + " did not complete; remote activity may remain") from None
    if not success:
        raise OperationError(label + " failed; inspect protected service logs")


@operation()
def _application_check(command: str, label: str) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_checked_command, (command, label), {})


def application_check(
    cfg: HomeAssistantRuntimeConfig, argv: list[str], label: str, *, trust: bool = False
) -> OperationMeta:
    return mark_read_only(
        _application_check(
            name=label,
            command=_as_user(cfg.user, PurePosixPath(cfg.home), {"UV_SYSTEM_CERTS": "1"} if trust else {}, argv),
            label=label,
        )
    )


def _notice(state: State, host: Host) -> None:
    logger.info("Traefik watches Home Assistant dynamic configs automatically")


@operation()
def _traefik_notice() -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_notice, (), {})


def _any_pending(callbacks: tuple[Callable[[], bool], ...]) -> Callable[[], bool]:
    return lambda: any(callback() for callback in callbacks)


@dataclass
class _PendingHandlers:
    """Registration-time queue consumed once; callbacks evaluate completed results."""

    reload: list[Callable[[], bool]] = field(default_factory=list)
    homeassistant: list[Callable[[], bool]] = field(default_factory=list)
    matter: list[Callable[[], bool]] = field(default_factory=list)
    udev: OperationMeta | None = None
    ingress: OperationMeta | None = None

    def flush(self, cfg: HomeAssistantRuntimeConfig) -> None:
        reload, ha, matter = tuple(self.reload), tuple(self.homeassistant), tuple(self.matter)
        self.reload.clear()
        self.homeassistant.clear()
        self.matter.clear()
        if reload or ha or matter:
            flush_service_handlers(
                cfg,
                reload_required=_any_pending(reload),
                homeassistant_required=_any_pending(ha),
                matter_required=_any_pending(matter),
            )
        if self.udev is not None:
            run_udev_handlers(self.udev)
            self.udev = None
        if self.ingress is not None:
            mark_read_only(_traefik_notice(name="Home Assistant Traefik watcher notice", _if=self.ingress.did_change))
            self.ingress = None


@deploy("Home Assistant")
def deploy_homeassistant(*, cfg: HomeAssistantDeployConfig) -> None:
    """Register original normal deployment, without executing API/model calls in plan.

    Metadata prerequisites/selection are observed during registration like normal
    pyinfra facts. Named registry values never enter durable controller output.
    No real-radio, Thread rollback, model response or native claim is implied.
    """
    runtime = cfg.runtime
    require_linux("Home Assistant")
    if not _selection(runtime, "uv")["exists"]:
        raise DeployError("uv binary not found at " + runtime.uv_path + ". Install uv before running this role.")
    # Preserve original environment -> unit -> system-store admission order.
    security_preflight(runtime.model_copy(update={"uv_system_certs": False}))
    if runtime.uv_system_certs:
        inspect_trust(runtime, "preflight", allow_missing_unit=True)
        security_preflight(runtime.model_copy(update={"python_security_floor_enabled": False}))
    apt.packages(name="Install Home Assistant system packages", packages=list(cfg.additional_packages), update=True)
    pending = _PendingHandlers(udev=configure_layout(runtime))
    install_uv(runtime.uv, manage=runtime.manage_uv)
    write_constraints(runtime)
    readiness = ApiReadiness()
    rebuild = False
    if cfg.builtin_enabled:
        install_builtin_helper(runtime, cfg.builtin)
        initial_legacy = inspect_legacy_conversation(host, runtime)
        rebuild = initial_legacy.rebuild
        if initial_legacy.retire:
            ensure_api_readiness(runtime, cfg.api, readiness)
            run_builtin_conversation(
                name="Retire legacy Home Assistant conversation",
                runtime=runtime,
                api=cfg.api,
                config=cfg.builtin,
                action="retire",
                result=ConversationResult(),
            )
        remove_legacy_component(runtime)
    python = configure_python_runtime(runtime, llama_cpp_rebuild=rebuild, deferred=True)
    pending.homeassistant.append(python.homeassistant_changed)
    pending.matter.append(python.matter_changed)
    verify_security(runtime)
    values = cfg.values
    if not values.internal_url and cfg.api.default_ipv4 is not None:
        values = values.model_copy(update={"internal_url": f"http://{cfg.api.default_ipv4}:{values.app_port}"})
    configuration = configure_files(
        runtime,
        cfg.configuration,
        values,
        unifi=cfg.unifi,
        examples=cfg.secret_examples,
        include_files=cfg.include_files,
        deferred=True,
    )
    pending.homeassistant.append(configuration.homeassistant_changed)
    if cfg.builtin_enabled:
        application_check(
            runtime,
            [runtime.virtualenv_path + "/bin/hass", "--script", "check_config", "--config", runtime.config_path],
            "Validate upgraded Home Assistant configuration",
            trust=True,
        )
    units = write_units(runtime)
    pending.reload.append(units.reload_required)
    pending.homeassistant.append(units.homeassistant_changed)
    pending.matter.append(units.matter_changed)
    dropin = write_managed_dropin(runtime)
    if dropin is not None:
        pending.reload.append(dropin.did_change)
        pending.homeassistant.append(dropin.did_change)
    pending.ingress = write_ingress(cfg.ingress, rendered=cfg.ingress_rendered)
    ensure_service_states(runtime)
    if cfg.areas():
        manage_area_registry(runtime, cfg.api, readiness, cfg.areas(), AreaResult(), app_port=values.app_port)
    for selection in cfg.integrations():
        integrate(runtime, cfg.api, selection, readiness)
    custom_result = CustomConversationResult()
    builtin_result = ConversationResult()
    if cfg.custom.enabled:
        component = install_custom_component(runtime, cfg.custom_component, deferred=True)
        pending.homeassistant.append(component.homeassistant_changed)
        pending.flush(runtime)
        reset_api_readiness(readiness)
    if not cfg.builtin_enabled:
        count = _selection(runtime, "custom")["count"]
        if count > 1:
            raise DeployError(
                f"Expected at most one custom_conversation config entry but found {count}; role owns domain"
            )
        if cfg.custom.enabled or count:
            cfg.custom.validate_selected()
            ensure_api_readiness(runtime, cfg.api, readiness)
            application_check(
                runtime,
                [runtime.virtualenv_path + "/bin/python", "-c", "import aiohttp"],
                "Verify Custom Conversation aiohttp",
            )
            run_custom_conversation(
                name="Manage Home Assistant Custom Conversation",
                runtime=runtime,
                api=cfg.api,
                config=cfg.custom,
                result=custom_result,
            )
    if cfg.builtin_enabled or cfg.assist.builtin_selected():
        # This nested original task group has its OWN flush even when custom ran.
        pending.flush(runtime)
        reset_api_readiness(readiness)
        ensure_api_readiness(runtime, cfg.api, readiness)
        install_builtin_helper(runtime, cfg.builtin)
        run_builtin_conversation(
            name="Manage Home Assistant built-in conversation",
            runtime=runtime,
            api=cfg.api,
            config=cfg.builtin,
            action="ensure" if cfg.builtin_enabled else "disable",
            result=builtin_result,
        )
        if cfg.builtin_enabled:
            application_check(
                runtime,
                [
                    runtime.virtualenv_path + "/bin/python",
                    "-c",
                    "import importlib.metadata as m; assert not any(d.metadata['Name'].lower().replace('_', '-')"
                    ".startswith('litellm') for d in m.distributions()), 'LiteLLM remains installed'",
                ],
                "Verify LiteLLM is absent",
            )
    definitions = cfg.assist.definitions()
    if definitions or cfg.assist.manage_stt or cfg.assist.manage_tts:
        manage_pipelines(
            runtime,
            cfg.api,
            readiness,
            "list" if definitions else "voice",
            cfg.assist.payload(
                wyoming_host=cfg.wyoming_host, wyoming_port=cfg.wyoming_port, builtin_enabled=cfg.builtin_enabled
            ),
            PipelineResult(),
            app_port=values.app_port,
            builtin=builtin_result,
            custom=custom_result,
        )
    if runtime.manage_matter_server:
        pending.flush(runtime)
        application_check(
            runtime,
            [runtime.virtualenv_path + "/bin/python", "-c", "import homeassistant.components.matter.config_flow"],
            "Validate HA Matter import",
        )
        application_check(
            runtime,
            [
                runtime.matter_server_virtualenv_path + "/bin/python",
                "-c",
                "from matter_server.server.__main__ import main; "
                "from matter_server.common.custom_clusters import check_polled_attributes",
            ],
            "Validate Matter server imports",
        )
    pending.flush(runtime)
    verify_running_trust(runtime)
