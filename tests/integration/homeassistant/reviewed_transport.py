"""Protected HA commands with the SDK's original fact privilege precedence."""

from __future__ import annotations

from typing import Any

from pyinfra.api import Host, StringCommand
from pyinfra.api.arguments import CONNECTOR_ARGUMENT_KEYS, pop_global_arguments
from pyinfra.connectors.util import CommandOutput


def run_protected_command(target: Host, command: StringCommand, **overrides: Any) -> tuple[bool, CommandOutput]:
    """Use the active connector/context without exposing stdin/stdout in verbose mode.

    Match SDK fact resolution: explicit overrides, operation, deploy, host data,
    then config. Never toggle shared state logging or substitute an SSH identity.
    """
    if any(key not in CONNECTOR_ARGUMENT_KEYS for key in overrides):
        raise ValueError("unsupported protected Home Assistant connector override")
    context = dict(target.current_op_global_arguments or {})
    context.update(overrides)
    global_arguments, _ = pop_global_arguments(target.state, target, context)
    executor = {key: value for key, value in global_arguments.items() if key in CONNECTOR_ARGUMENT_KEYS}
    return target.run_shell_command(command, print_input=False, print_output=False, **executor)
