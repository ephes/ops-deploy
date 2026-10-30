"""Managed application rail; no app invocation in facts or implicit source work."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from importlib.resources import files
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin
from ops_deploy.services.daybook_controls.deploy import DIRECT
from ops_deploy.services.daybook_sessions.render import render_template
from ops_deploy.services.daybook_weeknotes_controls import WeeknotesDisableConfig, disable_weeknotes_schedule

from .config import WeeknotesIdentityConfig


def template_values(cfg: WeeknotesIdentityConfig) -> dict[str, str]:
    return {
        "daybook_sessions_service_user": cfg.owner,
        "daybook_sessions_service_home": cfg.home,
        "daybook_sessions_checkout_path": cfg.checkout,
        "daybook_sessions_config_dir": cfg.config_dir,
        "daybook_sessions_uv_bin": cfg.uv_bin,
        "daybook_sessions_launchd_path": cfg.path,
        "daybook_weeknotes_reconcile_runtime_dir": cfg.runtime,
        "daybook_weeknotes_reconcile_state_path": cfg.state,
        "daybook_weeknotes_reconcile_env_file": cfg.env_file,
        "daybook_weeknotes_reconcile_env_checksum_file": cfg.env_checksum,
        "daybook_weeknotes_identity_helper_path": cfg.helper,
        "daybook_weeknotes_identity_launcher_path": cfg.launcher,
        "daybook_weeknotes_identity_seed_path": cfg.seed,
        "daybook_weeknotes_identity_plan_path": cfg.plan,
        "daybook_weeknotes_identity_attestation_path": cfg.attestation,
    }


def operator_payload(cfg: WeeknotesIdentityConfig, uid: int) -> dict[str, Any]:
    values = template_values(cfg)
    expected = {}
    for key, template in (("helper", "weeknotes-identity-ops.py.j2"), ("launcher", "weeknotes-identity-ops.sh.j2")):
        body = render_template(template, values).encode()
        expected[key] = {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
    return {**cfg.model_dump(mode="json"), "uid": uid, "expected_code": expected}


def operator_command() -> str:
    pieces = ["import base64,sys,types"]
    body = files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py").read_bytes()
    encoded = base64.b64encode(body).decode()
    pieces.append(
        "m=types.ModuleType('ops_identity_filesystem');sys.modules[m.__name__]=m;"
        f"exec(compile(base64.b64decode('{encoded}'),'<identity-filesystem>','exec'),m.__dict__)"
    )
    encoded = base64.b64encode(
        files("ops_deploy.services.daybook_weeknotes_identity").joinpath("files/identity_operator_host.py").read_bytes()
    ).decode()
    pieces.append(
        f"exec(compile(base64.b64decode('{encoded}'),'<identity-operator>','exec'),{{'__name__':'__main__'}})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces)])


@deploy("Explicit original Weeknotes identity operator")
def run_weeknotes_identity(cfg: WeeknotesIdentityConfig) -> None:
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Weeknotes identity operators require macOS")
    if host.get_fact(Command, command="/usr/bin/id -u", **DIRECT) != "0":
        raise DeployError("Weeknotes identity operator requires the original root connection")
    value = host.get_fact(Command, command=shlex.join(["/usr/bin/id", "-u", cfg.owner]), **DIRECT) or ""
    if not value.isdecimal() or int(value) <= 0:
        raise DeployError("Weeknotes identity owner uid is unavailable")
    # Production values were validated above. Disposable fixtures deliberately
    # substitute their owned paths/unique label in the validated declaration.
    timer = WeeknotesDisableConfig().model_copy(update={"label": cfg.scheduler_label, "plist": cfg.scheduler_plist})
    disable_weeknotes_schedule(cfg=timer)
    secret_stdin(
        name="Run selected original identity action; retain private output in target memory",
        command=operator_command(),
        content=SecretContent(json.dumps(operator_payload(cfg, int(value))) + "\n"),
        **DIRECT,
    )
