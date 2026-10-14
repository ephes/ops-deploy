"""Run a deploy for real over pyinfra's ssh connector (the smoke target).

The counterpart of :func:`ops_deploy.testing.run_deploy_fake` for one real
host: same per-operation results (:class:`DeployRun`), so a smoke test can
assert a converged second run with ``mutating_changed_ops == []``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops

from ops_deploy.testing.harness import DeployRun, collect_ops


@dataclass
class SshRun(DeployRun):
    """Results of one :func:`run_deploy_ssh` call; ``seconds`` is wall time."""

    seconds: float = 0.0


def run_deploy_ssh(
    deploy_fn: Callable[..., Any],
    *args: Any,
    host_name: str,
    host_data: Mapping[str, Any],
    **kwargs: Any,
) -> SshRun:
    """Connect to ``host_name`` over SSH, then plan and execute ``deploy_fn``.

    ``host_data`` holds pyinfra's ssh connector keys (``ssh_hostname``,
    ``ssh_port``, ``ssh_user``, ``ssh_key``, ``ssh_known_hosts_file``,
    ``ssh_strict_host_key_checking``); ``sync_tree`` reads the same keys.
    A connection or operation failure does not raise; check
    :attr:`DeployRun.succeeded` and :attr:`DeployRun.error`.
    """

    inventory = Inventory(([(host_name, dict(host_data))], {}))
    state = State(inventory, Config())
    run = SshRun()
    started = time.monotonic()
    try:
        connect_all(state)
        if not state.activated_hosts:
            raise PyinfraError(f"could not connect to {host_name}")
        add_deploy(state, deploy_fn, *args, **kwargs)
        run_ops(state)
    except PyinfraError as exc:
        run.error = exc
    finally:
        run.ops = collect_ops(state, host_name)
        disconnect_all(state)
        run.seconds = time.monotonic() - started
    return run
