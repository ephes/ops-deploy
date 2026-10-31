"""Original standalone UV trust maintenance, separate from normal deployment."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from importlib.resources import files

from pydantic import Field, SecretStr, StrictInt
from pyinfra.api import DeployError, FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import systemd

from ops_deploy.base._common import RoleConfig, require_linux
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines

from .runtime_config import HomeAssistantRuntimeConfig
from .security import security_preflight
from .transport import run_protected_command
from .trust import inspect_trust, verify_running_trust, write_managed_dropin


class HomeAssistantTrustMaintenanceConfig(RoleConfig):
    runtime: HomeAssistantRuntimeConfig = Field(default_factory=HomeAssistantRuntimeConfig)
    health_url: SecretStr = SecretStr("http://localhost:10020/manifest.json")
    health_retries: StrictInt = 60
    health_delay: StrictInt = 5


def health_command(cfg: HomeAssistantRuntimeConfig) -> str:
    root = files("ops_deploy.services.homeassistant").joinpath("files")
    transport = base64.b64encode(root.joinpath("integration_flow.py").read_bytes()).decode()
    health = base64.b64encode(root.joinpath("maintenance_health.py").read_bytes()).decode()
    # Reuse the already ported original URI transport/auth/redirect semantics.
    # Its __main__ guard never runs; only request_transport enters this check.
    script = (
        "import base64;uri={'__name__':'_ha_uri'};health={'__name__':'_ha_health'};"
        f"exec(compile(base64.b64decode({transport!r}),'<ha-uri>','exec'),uri);"
        f"exec(compile(base64.b64decode({health!r}),'<ha-health>','exec'),health);"
        "raise SystemExit(health['main'](uri['request_transport']))"
    )
    return shlex.join([cfg.security.system_python, "-I", "-B", "-c", script])


def _health(state: State, host: Host, command: str, payload: SecretStr, timeout: int) -> None:
    success, output = run_protected_command(
        host,
        StringCommand(command),
        _stdin=StdinLines(payload.get_secret_value()),
        _get_pty=False,
        _timeout=timeout,
    )
    try:
        report = json.loads(str(output.stdout))
        if (
            set(report) != {"success", "attempts"}
            or type(report["success"]) is not bool
            or type(report["attempts"]) is not int
            or report["attempts"] < 0
            or success is not report["success"]
        ):
            raise ValueError
    except (TypeError, ValueError, KeyError):
        raise OperationError("Home Assistant trust maintenance health returned an invalid status") from None
    if not success:
        raise OperationError(f"Home Assistant trust maintenance health failed after {report['attempts']} attempts")


@operation()
def _health_operation(command: str, payload: SecretStr, timeout: int) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_health, (command, payload, timeout), {})


def check_maintenance_health(cfg: HomeAssistantTrustMaintenanceConfig) -> OperationMeta:
    # Finite original retries including redirect/auth hops, with controller grace.
    budget = (max(0, cfg.health_retries) + 1) * (330 + max(0, cfg.health_delay)) + 30
    payload = SecretStr(
        json.dumps(
            {
                "url": cfg.health_url.get_secret_value(),
                "retries": cfg.health_retries,
                "delay": cfg.health_delay,
                "deadline_seconds": budget,
            }
        )
    )
    return mark_read_only(
        _health_operation(
            name="Wait for Home Assistant after trust maintenance",
            command=health_command(cfg.runtime),
            payload=payload,
            timeout=budget + 30,
        )
    )


def maintain_homeassistant_trust(cfg: HomeAssistantTrustMaintenanceConfig) -> None:
    """Existing unit/store admission, changed-only restart, health and running check.

    Planning observes original read-only admission but performs no HTTP check,
    drop-in write or restart. No packages, user data or normal deployment run.
    """
    runtime = cfg.runtime
    if not runtime.uv_system_certs:
        raise DeployError("Home Assistant UV system certificates must be enabled for maintenance")
    require_linux("Home Assistant trust maintenance")
    inspect_trust(runtime, "preflight")
    security_preflight(runtime.model_copy(update={"python_security_floor_enabled": False}))
    dropin = write_managed_dropin(runtime)
    assert dropin is not None
    systemd.service(
        name="Restart Home Assistant for changed trust drop-in",
        service=runtime.service_name,
        restarted=True,
        daemon_reload=True,
        _if=dropin.did_change,
    )
    check_maintenance_health(cfg)
    # The maintenance task always verifies, independently of normal desired state.
    verify_running_trust(runtime.model_copy(update={"service_state": "started"}))
