"""Mail's restart-owed protocol around existing file and systemd primitives.

The marker precedes a known config change. Callers clear it only after native
validation and service health. Changed files can remain after a failure while
the old daemon keeps running; this does not provide transactional rollback.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.facts.server import Users
from pyinfra.operations import server

from ops_deploy.helpers.checks import mark_read_only


@dataclass(frozen=True)
class PreparedConfig:
    marker: str
    owed: bool
    operation: OperationMeta
    action: Literal["restart", "reload"] = "restart"


def prepare_configs(
    service: str, inputs: list[OperationMeta], *, action: Literal["restart", "reload"] = "restart"
) -> PreparedConfig:
    """Register BEFORE config writes, then populate inputs with those operations.

    The operation evaluates their real planned commands after registration,
    following the existing mailgun-relay restart-owed pattern. Include only
    configuration/runtime changes requiring this daemon's restart, never SQL
    catalog changes or probes.
    """
    if not re.fullmatch(r"[a-z][a-z0-9-]*", service):
        raise ValueError("invalid mail daemon name")
    parent = "/var/lib/ops-deploy/mail-core"
    if action not in {"restart", "reload"}:
        raise ValueError("invalid mail daemon action")
    marker = f"{parent}/{service}.{action}"
    owed = bool(host.get_fact(File, path=marker))
    operation = server.shell(
        name=f"Remember {service} {action} owed",
        commands=[f"install -d -o root -g root -m 0700 {parent} && install -o root -g root -m 0600 /dev/null {marker}"],
        _if=lambda: not owed and any(op.will_change for op in inputs),
    )
    return PreparedConfig(marker, owed, operation, action)


def finish_restart(prepared: PreparedConfig, *, changes: tuple[OperationMeta, ...] = ()) -> OperationMeta:
    """Call only after every owned validation and service health succeeded."""
    return server.shell(
        name=f"Clear {PurePosixPath(prepared.marker).stem} {prepared.action} owed",
        commands=["rm -f -- " + shlex.quote(prepared.marker)],
        _if=lambda: prepared.owed or prepared.operation.did_change() or any(meta.did_change() for meta in changes),
    )


def validate_native(argv: list[str], label: str, *, stdout_marker: str = "") -> OperationMeta:
    # Native readers only. Capture diagnostics too: parser errors can quote a
    # protected SQL connection line. No credentials or config content is logged.
    script = (
        "import subprocess,sys; p=subprocess.run(sys.argv[2:],capture_output=True); "
        "failed=p.returncode or sys.argv[1].encode() not in p.stdout; "
        "print('Mail native configuration validation failed',file=sys.stderr) if failed else None; "
        "sys.exit(bool(failed))"
    )
    return mark_read_only(
        server.shell(
            name=label,
            commands=[shlex.join(["python3", "-I", "-c", script, stdout_marker, *argv])],
        )
    )


def postfix_group_access(
    group: Literal["opendkim", "_rspamd"], *, postfix_package_pending: bool = False
) -> OperationMeta:
    """Append only the declared mail socket group; never synthesize a package user.

    Existing identities use the ordinary user primitive with home ownership
    disabled. A known planned Postfix package creation must be rechecked after
    apt, before applying its supplemental group. Missing existing identities
    are unknown state rather than permission to create a substitute account.
    """
    if group not in {"opendkim", "_rspamd"}:
        raise ValueError("unsupported Postfix socket-access group")
    if "postfix" in host.get_fact(Users):
        return server.user(
            name="Allow Postfix mail socket access",
            user="postfix",
            groups=[group],
            append=True,
            create_home=False,
            ensure_home=False,
        )
    if not postfix_package_pending:
        raise DeployError("Postfix package identity is missing; no substitute account created")
    script = """import grp,os,pwd,subprocess,sys
try:
    user=pwd.getpwnam('postfix');group=grp.getgrnam(sys.argv[1])
    if group.gr_gid not in os.getgrouplist(user.pw_name,user.pw_gid):
        parent='/var/lib/ops-deploy/mail-core';marker=parent+'/postfix.restart'
        subprocess.run(['install','-d','-o','root','-g','root','-m','0700',parent],check=True,capture_output=True)
        subprocess.run(['install','-o','root','-g','root','-m','0600','/dev/null',marker],check=True,capture_output=True)
        subprocess.run(['usermod','-a','-G',group.gr_name,user.pw_name],check=True,capture_output=True)
except Exception:
    print('Postfix package identity/group verification failed; no substitute account created',file=sys.stderr)
    sys.exit(1)
"""
    return server.shell(
        name="Recheck package-created Postfix socket access",
        commands=[shlex.join(["python3", "-I", "-c", script, group])],
    )
