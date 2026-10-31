"""Actual SDK interpreter probes, only called inside the admitted owned guest."""

from __future__ import annotations

import json
import os
import traceback
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any
from unittest.mock import patch

from pyinfra import host
from pyinfra.api import Config, FunctionCommand, Host, Inventory, State, StringCommand, operation
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.operation import add_op
from pyinfra.api.operations import run_ops
from pyinfra.api.state import BaseStateCallback
from pyinfra.connectors.local import LocalConnector
from pyinfra.connectors.util import CommandOutput
from pyinfra.context import ctx_host, ctx_state

from ops_deploy.services.homeassistant import interpreter
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

from .fixture import EVIDENCE
from .frozen_interpreter import load
from .reviewed_transport import run_protected_command

LIMIT = 16384


def environment_keys() -> list[str]:
    return sorted(key for key in os.environ if key.startswith(("UV_", "XDG_")) or key == "VIRTUAL_ENV")


def probe(
    *, install: bool, frozen: bool = True, retries: int = 0, retry_hook: Callable[[], None] | None = None
) -> dict[str, Any]:
    """Observe real connector results; never replace the command's execution."""
    implementation = load() if frozen else interpreter
    cfg = HomeAssistantRuntimeConfig()
    state = State(Inventory(([("@local", {})], {})), Config())
    report: dict[str, Any] = {"cwd": os.getcwd(), "environment_keys": environment_keys(), "commands": []}
    report["retries"] = []
    progress: set[Host] = set()

    class RetryCallback(BaseStateCallback):
        @staticmethod
        def operation_host_retry(state: State, target: Any, key: str, attempt: int, maximum: int) -> None:
            report["retries"].append(attempt)
            if retry_hook is not None:
                retry_hook()

    state.add_callback_handler(RetryCallback())
    original = LocalConnector.run_shell_command

    def record(connector: Any, command: StringCommand, **kwargs: Any) -> tuple[bool, CommandOutput]:
        success, output = original(connector, command, **kwargs)
        report["commands"].append(
            {
                "argv_shell": command.get_raw_value(),
                "connector_argument_keys": sorted(kwargs),
                "success": success,
                "stdout": output.stdout[:LIMIT],
                "stderr": output.stderr[:LIMIT],
                "truncated": len(output.stdout) > LIMIT or len(output.stderr) > LIMIT,
            }
        )
        return success, output

    def query() -> None:
        report["operation_context_keys"] = sorted(host.current_op_global_arguments or {})
        report["find"] = implementation.find_python(cfg)
        success, output = run_protected_command(
            host, StringCommand(implementation.interpreter_command(cfg, "find")), _timeout=60
        )
        report["reviewed_find"] = output.stdout.strip() if success else None

    @operation()
    def queries() -> Generator[FunctionCommand, None, None]:
        yield FunctionCommand(query, (), {})

    error = None
    try:
        with patch.object(LocalConnector, "run_shell_command", record):
            connect_all(state)
            if install:
                add_op(
                    state,
                    implementation._install,
                    cfg=cfg,
                    deferred=True,
                    _timeout=600,
                    _retries=retries,
                    _retry_delay=0,
                    **({} if frozen else {"installed": progress}),
                )
            else:
                add_op(state, queries, _timeout=600)
            report["planned_changes"] = []
            for key in state.get_op_order():
                for target in state.inventory.iter_activated_hosts():
                    with ctx_state.use(state), ctx_host.use(target):
                        meta = state.get_op_data_for_host(target, key).operation_meta
                        report["planned_changes"].append(meta.will_change)
            report["planning_progress"] = sorted(item.name for item in progress)
            run_ops(state)
    except Exception:
        error = traceback.format_exc(limit=12)
    finally:
        report["error"] = error
        report["installed_hosts"] = sorted(item.name for item in progress)
        report["actual_host_keys"] = all(isinstance(item, Host) for item in progress)
        report["failed_hosts"] = sorted(item.name for item in state.failed_hosts)
        report["operations"] = []
        report["changes"] = []
        for key in state.get_op_order():
            for target in state.inventory.iter_activated_hosts():
                meta = state.get_op_data_for_host(target, key).operation_meta
                report["changes"].append(meta.did_change() if meta.is_complete() else None)
                report["operations"].append(
                    {
                        "complete": meta.is_complete(),
                        "executed": meta.executed,
                        "success": meta.did_succeed() if meta.is_complete() else None,
                    }
                )
        disconnect_all(state)
    return report


def main() -> None:
    # Child admission remains mandatory when invoked directly. The parent has
    # already created the account, so the fresh-home parent admission cannot run.
    assert os.getuid() == 0
    assert os.uname().machine == "x86_64"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert os.environ.get("HOMEASSISTANT_FIXTURE_CASE") == "current"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    owned = os.environ["HOMEASSISTANT_OWNED_ID"]
    assert Path("/etc/ops-homeassistant-owned-id").read_text().strip() == owned
    assert json.loads(Path("/var/tmp/homeassistant-owned-guest.json").read_text())["run"] == owned
    artifact = json.loads((EVIDENCE / "installed-artifact.json").read_text())
    assert artifact["implementation_sha"] == os.environ["IMPLEMENTATION_SHA"]
    assert artifact["machine_id"] == Path("/etc/machine-id").read_text().strip()
    # The parent admits ownership and applies a process-group deadline/output
    # bound. No application package, original role or private controller runs.
    from .interpreter_repair import exercise

    exercise()


if __name__ == "__main__":
    main()
