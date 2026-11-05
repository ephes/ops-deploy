"""A register playbook's own Echoport target script, with a check mode, and the FastDeploy token piped into it.

The class B playbooks (design note §3.4) upsert their Echoport target with a
script of their own on ``manage.py shell``'s stdin. The scripts differ from
the shared upsert (:mod:`ops_deploy.services._echoport`) and from each other
in scope, owned fields, save behaviour and refusals, so a port keeps its
playbook's script text and does not map it onto ``upsert_target``.
``files/runner_target.py`` runs such a script unchanged in a check mode (in a
rolled-back transaction; ``unchanged``, ``pending`` or the refusal) and in
apply mode, and
:func:`upsert_runner_target` / :func:`token_and_target` are the
probe-then-apply steps around it:

- while planning, the check runs; a refusal stops the deploy before any write;
  ``unchanged`` adds no operation;
- otherwise the script runs once (after a token is issued, when one is due) and
  the check runs again, which must then say ``unchanged``.

Where the playbook's script saves on every run, the port saves only when a
field differs, so a converged row keeps its ``updated_at`` and skips
Echoport's ``full_clean`` on that run.

The values reach the script in ``manage.py shell -c``'s argument (world-readable
while it runs), so they must never hold a secret; :class:`RunnerTarget` refuses
names that look like one. A token goes from ``issueservicetoken`` to the script
through a pipe on the host, never to the controller, a file or a command line;
the FastDeploy user name arrives on stdin.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from pyinfra.api import DeployError
from pyinfra.operations import server

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.probes import last_line, probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.ops import secret_stdin

PRELUDE = (Path(__file__).parent / "files" / "runner_target.py").read_text()
ECHOPORT_USER = "echoport"
ECHOPORT_SITE = PurePosixPath("/home/echoport/site")
# Value names that look like a credential; they must not travel in argv.
_SECRET_NAME = re.compile(r"(token|secret|password|passwd|credential|private)", re.IGNORECASE)
_TargetName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]


class ServiceToken(RoleConfig):
    """``common/fastdeploy_service_token.yml``'s inputs (without the user, a secret on stdin)."""

    targets: tuple[_TargetName, ...] = Field(min_length=1)
    service: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]
    origin: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")] = "echoport"
    days: int = Field(default=90, ge=1, le=90)
    renewal_days: int = Field(default=30, ge=1)
    force_rotate: bool = False
    fastdeploy_root: PurePosixPath = PurePosixPath("/home/fastdeploy/site")
    fastdeploy_user: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")] = "fastdeploy"
    fastdeploy_home: PurePosixPath = PurePosixPath("/home/fastdeploy")

    @model_validator(mode="after")
    def _window(self) -> ServiceToken:
        if self.renewal_days >= self.days:
            raise ValueError("the renewal window must be shorter than the token lifetime")
        return self


class RunnerTarget(RoleConfig):
    """One playbook target script: ``name`` (for messages), the script and the values it reads."""

    name: _TargetName
    script: str = Field(min_length=1)
    values: Mapping[str, Any]
    token: ServiceToken | None = None
    user: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")] = ECHOPORT_USER
    site: PurePosixPath = ECHOPORT_SITE

    @field_validator("values")
    @classmethod
    def _no_secrets(cls, values: Mapping[str, Any]) -> Mapping[str, Any]:
        def walk(value: Any, path: str) -> None:
            if isinstance(value, Mapping):
                for key, item in value.items():
                    if _SECRET_NAME.search(str(key)):
                        raise ValueError("target script values travel in argv and must not hold a secret")
                    walk(item, f"{path}.{key}")
            elif isinstance(value, list | tuple):
                for item in value:
                    walk(item, path)

        walk(values, "values")
        json.dumps(values)  # JSON only
        return values


def target_code(target: RunnerTarget, mode: Literal["check", "apply"]) -> str:
    """The prelude with ``PARAMS`` (mode, script, values, token settings) in front, for ``manage.py shell -c``."""

    params = {
        "mode": mode,
        "script": target.script,
        "values": target.values,
        "token": None if target.token is None else target.token.model_dump(include=_TOKEN_PARAMS),
    }
    # Base64: a script's text holds backslashes, which a fish login shell would halve in argv.
    data = base64.b64encode(json.dumps(params).encode()).decode()
    return f'import base64 as _b, json as _j\nPARAMS = _j.loads(_b.b64decode("{data}").decode())\n{PRELUDE}'


_TOKEN_PARAMS = {"targets", "service", "renewal_days", "force_rotate"}


def target_shell(target: RunnerTarget, mode: Literal["check", "apply"]) -> str:
    """``manage.py shell -c <target_code>`` in the site as the Echoport user (a subshell, so it may be piped into)."""

    run = _as_user(
        target.user, PurePosixPath("/home") / target.user, {}, [".venv/bin/python", "manage.py", "shell", "-c"]
    )
    return f"(cd {shlex.quote(str(target.site))} && {run} {shlex.quote(target_code(target, mode))})"


def _check_command(target: RunnerTarget) -> str:
    return when_present([target.site / "manage.py"], last_line(target_shell(target, "check")), otherwise="missing")


def _check(target: RunnerTarget) -> tuple[str, str | None]:
    check = _check_command(target)
    state = probe(check, name=f"Echoport backup target {target.name}")
    answer = (state or "").strip()
    if answer.startswith("refused:"):
        raise DeployError(f"Echoport backup target {target.name}: {answer}")
    if answer == "missing":
        raise DeployError(f"Echoport is not installed at {target.site}; register the runner after Echoport")
    return check, state


def upsert_runner_target(target: RunnerTarget) -> None:
    """Check, then run the script when the check does not say ``unchanged`` (no token step)."""

    if target.token is not None:
        raise ValueError("a target with a service token goes through token_and_target")
    check, state = _check(target)
    if (state or "").strip() == "unchanged":
        return
    server.shell(
        name=f"Upsert Echoport backup target {target.name}",
        commands=[
            f"out=$( {target_shell(target, 'apply')} </dev/null ) || exit 1; "
            '[ "$(printf "%s\\n" "$out" | tail -n 1)" = applied ] '
            "|| { echo 'the target script did not apply' >&2; exit 1; }"
        ],
    )
    verify_probe(check, name=f"Echoport backup target {target.name}", expect="unchanged")


def token_and_target(target: RunnerTarget, token_user: str) -> None:
    """The playbook's token include and its target script, as one remote script.

    A new token is issued only when the stored one is missing, undecodable,
    scoped to another service, a legacy token without ``jti`` or within the
    renewal window (or when forced), and only after the check passed.
    """

    token = target.token
    if token is None:
        raise ValueError("token_and_target needs a ServiceToken")
    if not token_user.strip() or "\n" in token_user:
        raise DeployError("the FastDeploy token user is required (one line; value withheld)")
    _, state = _check(target)
    if (state or "").strip() == "unchanged":
        return
    # FastDeploy's own CLI in-process with the user read from stdin, so the
    # name is in no process's arguments (``commands.py --user`` would put it there).
    call = (
        "import sys; sys.argv = ['commands.py', 'issueservicetoken', "
        f"'--service', {token.service!r}, '--user', sys.stdin.readline().strip(), "
        f"'--days', '{token.days}', '--origin', {token.origin!r}]; "
        "import commands; commands.cli()"
    )
    issue = _as_user(token.fastdeploy_user, token.fastdeploy_home, {}, [".venv/bin/python", "-c", call])
    jwt = "^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$"
    applied = (
        'out=$(printf "%s\\n" "$out" | tail -n 1); [ "$out" = applied ] '
        "|| { echo 'the target script did not apply' >&2; exit 1; }"
    )
    script = "\n".join(
        [
            "IFS= read -r fd_user",
            f"out=$( {target_shell(target, 'apply')} </dev/null) || exit 1",
            'last=$(printf "%s\\n" "$out" | tail -n 1)',
            'if [ "$last" = need-token ]; then',
            f"  token=$(cd {shlex.quote(str(token.fastdeploy_root))} && "
            f"printf '%s\\n' \"$fd_user\" | {issue} 2>/dev/null) "
            "|| { echo 'issueservicetoken failed (output withheld)' >&2; exit 1; }",
            f"  [ \"$(printf '%s\\n' \"$token\" | wc -l)\" -eq 1 ] && printf '%s\\n' \"$token\" | grep -Eq '{jwt}' "
            "|| { echo 'issueservicetoken did not print exactly one JWT (output withheld)' >&2; exit 1; }",
            f"  out=$(printf '%s\\n' \"$token\" | {target_shell(target, 'apply')}) || exit 1",
            "fi",
            applied,
        ]
    )
    secret_stdin(
        name=f"Issue or reuse the FastDeploy token and upsert the Echoport backup target {target.name}",
        command=f"sh -c {shlex.quote(script)}",
        content=SecretContent(f"{token_user}\n"),
    )
    # A forced rotation is done once the new token is stored: probe again without forcing.
    settled = target.model_copy(update={"token": token.model_copy(update={"force_rotate": False})})
    verify_probe(_check_command(settled), name=f"Echoport backup target {target.name}", expect="unchanged")


__all__ = [
    "PRELUDE",
    "RunnerTarget",
    "ServiceToken",
    "target_code",
    "target_shell",
    "token_and_target",
    "upsert_runner_target",
]
