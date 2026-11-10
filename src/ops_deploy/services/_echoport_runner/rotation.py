"""A register playbook's own monthly token rotation timer (heis-production-backup's).

``register-heis-production-backup.yml`` installs, after its Echoport target,
a root-only helper that issues a new FastDeploy service token
(``issueservicetoken --origin systemd-token-rotation``) and stores it on the
target, a oneshot service that runs it and a monthly timer, then enables and
starts the timer. ``files/token_rotation/<name>/`` keeps the three ``copy``
contents of that playbook unchanged (``helper``, ``service``, ``timer``);
ops-control's tests compare them with the playbook.

The helper names the FastDeploy user that issues the token (the playbook's
``*_service_token_user``, read from SOPS, under ``no_log``), so it is written
with :func:`ops_deploy.ops.secret_file` (root ``0700``, content on stdin
only). The units are written as ``root:root 0644``. Unlike the playbook,
which reloads systemd on every run, systemd is reloaded only when a unit
changed, so a converged host gets no mutating operation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from importlib.resources import files
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from pyinfra.api import DeployError
from pyinfra.operations import systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.systemd import systemd_unit
from ops_deploy.ops import secret_file
from ops_deploy.services._echoport_runner.access import PlainPath
from ops_deploy.services._echoport_runner.render import render_text, text_names

PACKAGE = "ops_deploy.services._echoport_runner"
PARTS = ("helper", "service", "timer")
_NAME = r"^[a-z0-9][a-z0-9_-]*$"
_VARIABLE = re.compile(r"^[a-z_][a-z0-9_]*$")
# What the texts read that must be the target's and its token's values (in the
# playbook these are the same variables as the token include's).
Binding = Literal["target", "service", "fastdeploy_root", "fastdeploy_user", "days"]
BINDINGS: tuple[Binding, ...] = ("target", "service", "fastdeploy_root", "fastdeploy_user", "days")


def rotation_names() -> tuple[str, ...]:
    """The kept rotation text sets (``files/token_rotation/<name>/``), by name."""

    folder = files(PACKAGE).joinpath("files", "token_rotation")
    return tuple(sorted(entry.name for entry in folder.iterdir() if entry.is_dir()))


def rotation_texts(name: str) -> dict[str, str]:
    """The playbook's ``helper``, ``service`` and ``timer`` contents of ``name``, unchanged."""

    if name not in rotation_names():
        raise ValueError(f"{name!r} is not a kept token rotation")
    folder = files(PACKAGE).joinpath("files", "token_rotation", name)
    return {part: folder.joinpath(part).read_text() for part in PARTS}


class TokenRotation(RoleConfig):
    """The playbook's rotation helper, service and timer.

    ``name``: the kept texts; ``helper``: the helper's path; ``unit``: the
    service and timer name without suffix. ``variables`` are the names the
    texts read, resolved, except ``user_variable``: the FastDeploy token
    user, which the deploy passes as a secret. ``bindings`` names the
    variable that holds each of :data:`BINDINGS`; the registration checks
    them against its target and token.
    """

    name: Annotated[str, Field(pattern=_NAME)]
    helper: PlainPath
    unit: Annotated[str, Field(pattern=_NAME)]
    variables: Mapping[str, Any]
    user_variable: str
    bindings: Mapping[Binding, str]

    @model_validator(mode="after")
    def _complete(self) -> TokenRotation:
        texts = rotation_texts(self.name)
        names: set[str] = set()
        for text in texts.values():
            names |= text_names(text)
        problems = []
        if not _VARIABLE.match(self.user_variable) or self.user_variable in self.variables:
            problems.append("the token user is a variable name of its own, passed as a secret")
        if names != set(self.variables) | {self.user_variable}:
            problems.append(f"the texts read {sorted(names)}, given {sorted({*self.variables, self.user_variable})}")
        if set(self.bindings) != set(BINDINGS) or not set(self.bindings.values()) <= set(self.variables):
            problems.append(f"bindings name a variable for each of {', '.join(BINDINGS)}")
        if f"ExecStart={self.helper}\n" not in texts["service"]:
            problems.append(f"the service does not run {self.helper}")
        if f"Unit={self.unit}.service\n" not in texts["timer"]:
            problems.append(f"the timer does not start {self.unit}.service")
        if problems:
            raise ValueError("token rotation: " + "; ".join(problems))
        return self

    def bound(self, binding: Binding) -> Any:
        """The value of the variable bound to ``binding``."""

        return self.variables[self.bindings[binding]]

    def rendered(self, token_user: str) -> dict[str, str]:
        """The three files as the playbook's ``copy`` writes them, with the token user."""

        values = {**self.variables, self.user_variable: token_user}
        return {part: render_text(text, values) for part, text in rotation_texts(self.name).items()}


def install_token_rotation(cfg: TokenRotation, token_user: str) -> None:
    """The playbook's helper, units and the enabled, started timer (call inside a deploy)."""

    if not token_user.strip() or "\n" in token_user:
        raise DeployError("the FastDeploy token user is required (one line; value withheld)")
    texts = cfg.rendered(token_user)
    secret_file(
        name=f"Install the token rotation helper {cfg.helper}",
        path=cfg.helper,
        content=SecretContent(texts["helper"]),
        user="root",
        group="root",
        mode="0700",
    )
    units = [systemd_unit(f"{cfg.unit}.{part}", texts[part]) for part in ("service", "timer")]
    timer = f"{cfg.unit}.timer"
    systemd.daemon_reload(name=f"Reload systemd for {timer}", _if=any_changed(*units))
    systemd.service(name=f"Enable and start {timer}", service=timer, running=True, enabled=True)


__all__ = ["BINDINGS", "TokenRotation", "install_token_rotation", "rotation_names", "rotation_texts"]
