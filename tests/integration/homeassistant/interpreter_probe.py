"""Actual SDK interpreter probes, only called inside the admitted owned guest."""

from __future__ import annotations

import json
import os
import traceback
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import patch

from pyinfra import host
from pyinfra.api import Config, FunctionCommand, Inventory, State, StringCommand, operation
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.operation import add_op
from pyinfra.api.operations import run_ops
from pyinfra.connectors.local import LocalConnector
from pyinfra.connectors.util import CommandOutput

from ops_deploy.services.homeassistant.interpreter import _install, find_python, interpreter_command
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

from .fixture import EVIDENCE, write
from .reviewed_transport import run_protected_command

LIMIT = 16384


def environment_keys() -> list[str]:
    return sorted(key for key in os.environ if key.startswith(("UV_", "XDG_")) or key == "VIRTUAL_ENV")


def probe(*, install: bool) -> dict[str, Any]:
    """Observe real connector results; never replace the command's execution."""
    cfg = HomeAssistantRuntimeConfig()
    state = State(Inventory(([("@local", {})], {})), Config())
    report: dict[str, Any] = {"cwd": os.getcwd(), "environment_keys": environment_keys(), "commands": []}
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
        report["frozen_find"] = find_python(cfg)
        success, output = run_protected_command(host, StringCommand(interpreter_command(cfg, "find")), _timeout=60)
        report["reviewed_find"] = output.stdout.strip() if success else None

    @operation()
    def queries() -> Generator[FunctionCommand, None, None]:
        yield FunctionCommand(query, (), {})

    error = None
    try:
        with patch.object(LocalConnector, "run_shell_command", record):
            connect_all(state)
            if install:
                add_op(state, _install, cfg=cfg, deferred=True, _timeout=600)
            else:
                add_op(state, queries, _timeout=600)
            run_ops(state)
    except Exception:
        error = traceback.format_exc(limit=12)
    finally:
        report["error"] = error
        report["failed_hosts"] = sorted(item.name for item in state.failed_hosts)
        report["operations"] = []
        for key in state.get_op_order():
            for target in state.inventory.iter_activated_hosts():
                meta = state.get_op_data_for_host(target, key).operation_meta
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
    write("interpreter-sdk-query.json", probe(install=False))
    write("interpreter-sdk-install.json", probe(install=True))


if __name__ == "__main__":
    main()
