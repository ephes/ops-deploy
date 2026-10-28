"""Sessions resource-stage construction; private bodies only travel via stdin.

The complete controller and resource substage are public APIs undergoing owned
qualification. No inventory adapter is wired or engine switched by this module.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shlex
from collections.abc import Mapping
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin

from .config import PACKAGE, DaybookSessionsConfig
from .layout import layout
from .render import _resource_texts
from .source import inspect_sessions_source, install_sessions_source, source_payload

IDENTITY_MODULES = (
    "__init__",
    "cast_client",
    "weeknotes",
    "weeknotes_identity_migration",
    "weeknotes_reconcile",
    "weeknotes_authoring",
    "weeknotes_quotes",
    "composer",
    "archive_quote_sink",
    "weeknotes_privacy",
    "sessions",
    "token_http",
)


def resource_payload(cfg: DaybookSessionsConfig, secrets: Mapping[str, str], source: SourceTree) -> dict[str, Any]:
    """Build private expected resources; never log/serialize outside protected stdin.

    Rendering the requested epoch is not verification. The host must verify the
    bound installed helper/modules, exact seed intent, attestation and root proof
    before installing its environment or accepting a repeat.
    """
    source_data = source_payload(cfg, source)
    wanted_epoch = cfg.daybook_weeknotes_post_identity_epoch == "monday-after-v1"
    if cfg.daybook_weeknotes_reconcile_enabled and cfg.daybook_weeknotes_reconcile_launchd_retired and not wanted_epoch:
        raise ValueError("Retired Weeknotes requires its original verified identity epoch")
    rendered = _resource_texts(cfg, secrets, identity_verified=wanted_epoch)
    filesystem = layout(cfg)
    identity: dict[str, Any] = {"required": wanted_epoch}
    if cfg.daybook_weeknotes_reconcile_enabled:
        helper = next((row for row in rendered if row.path == cfg.daybook_weeknotes_identity_helper_path), None)
        if helper is None:
            raise ValueError("Weeknotes identity helper declaration is unavailable")
        paths = ["src/daybook/" + name + ".py" for name in IDENTITY_MODULES]
        if any(path not in source_data["source_hashes"] for path in paths):
            raise ValueError("Weeknotes identity source contract is unavailable")
        identity.update(
            helper_sha256=hashlib.sha256(helper.content.encode()).hexdigest(),
            module_hashes={path: source_data["source_hashes"][path] for path in paths},
            seed_intent={
                "schema_version": 1,
                "identity_epoch": "monday-after-v1",
                "moves": cfg.daybook_weeknotes_identity_seed_moves,
            },
            policy_environment={
                "DAYBOOK_WEEKNOTES_PUBLIC_REPOSITORIES_JSON": secrets["daybook_weeknotes_public_repositories_json"]
            },
        )
    declared_files = [
        {"path": row.path, "owner": row.owner, "group": row.group, "mode": row.mode, "content": row.content}
        for row in rendered
    ]
    written = {row["path"] for row in declared_files}
    if written & (set(filesystem.remove_files) | {row.path for row in filesystem.logs}):
        raise ValueError("Sessions resource declarations overlap")
    return {
        "source": source_data,
        "config": cfg.model_dump(mode="json"),
        "directories": [asdict(row) for row in filesystem.directories],
        "logs": [asdict(row) for row in filesystem.logs],
        "retired_timers": [asdict(row) for row in filesystem.retired_timers],
        "remove_files": list(filesystem.remove_files),
        "resources": declared_files,
        "identity": identity,
    }


def resource_command(action: str) -> str:
    if action not in {
        "status",
        "apply",
        "verify",
        "prerequisites-status",
        "prerequisites-apply",
        "prerequisites-verify",
        "classifier-probe",
        "directories-status",
        "directories-apply",
        "reconcile-status",
        "reconcile-quiesce",
    }:
        raise ValueError("Unsupported Sessions resource action")
    parts = ["import base64,json,re,sys,types"]
    for module, resource in (
        ("ops_sessions_resources", "resources_host.py"),
        ("ops_sessions_controls", "controls_host.py"),
        ("ops_sessions_launchd", "launchd_host.py"),
        ("ops_sessions_dependencies", "dependencies_host.py"),
        ("ops_sessions_resource_stage", "resource_stage.py"),
    ):
        encoded = base64.b64encode(files(PACKAGE).joinpath("files/" + resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    loader = base64.b64encode(files(PACKAGE).joinpath("files/identity_host.py").read_bytes()).decode()
    parts.append(f"loader=base64.b64decode('{loader}').decode()")
    parts.append(
        "\ntry:\n"
        " raw=sys.stdin.buffer.read(8*1024*1024+1)\n"
        " if len(raw)>8*1024*1024:raise ValueError()\n"
        " data=json.loads(raw)\n"
        " stage=sys.modules['ops_sessions_resource_stage']\n"
        " cfg=data['config'];action=sys.argv[1]\n"
        " controls=sys.modules['ops_sessions_controls'];resources=sys.modules['ops_sessions_resources']\n"
        " launchd=sys.modules['ops_sessions_launchd']\n"
        " if action.startswith('prerequisites-') or action=='classifier-probe':\n"
        "  if action=='prerequisites-verify':cfg={**cfg,'daybook_sessions_brew_update':False}\n"
        "  deps=sys.modules['ops_sessions_dependencies'].Dependencies(cfg)\n"
        "  result=deps.inspect() if action in {'prerequisites-status','prerequisites-verify'} else {'current':True}\n"
        "  if action=='prerequisites-apply':deps.apply()\n"
        "  if action=='classifier-probe':deps.probe()\n"
        "  if action=='prerequisites-verify' and not result['current']:raise ValueError()\n"
        " elif action.startswith('directories-'):\n"
        "  controls.preflight(data)\n"
        "  states=[resources.directory_matches(row) for row in data['directories']]\n"
        "  result={'current':all(states)}\n"
        "  if action=='directories-apply':\n"
        "   launchd.require_reconcile_quiescence(cfg)\n"
        "   for row in data['directories']:resources.ensure_directory(row)\n"
        "   controls.browser_access(cfg)\n"
        "   result={'current':True}\n"
        " elif action.startswith('reconcile-'):\n"
        "  if action=='reconcile-quiesce':launchd.quiesce_reconcile(cfg)\n"
        "  try:\n"
        "   launchd.require_reconcile_quiescence(cfg);result={'current':True}\n"
        "  except resources.ResourceError as error:\n"
        "   if str(error)!='sessions_reconcile_quiescence_required':raise\n"
        "   result={'current':False}\n"
        " else:\n"
        "  result=stage.apply(data,loader) if action=='apply' "
        "else stage.inspect(data,loader,planning=action!='verify')\n"
        " if sys.argv[1]=='verify' and not result['current']:raise ValueError()\n"
        " print(json.dumps(result,sort_keys=True))\n"
        "except Exception as error:\n"
        " reason=str(error) if isinstance(error,sys.modules['ops_sessions_resources'].ResourceError) "
        "and re.fullmatch('sessions_[a-z_]+',str(error)) else 'sessions_resources_failed'\n"
        " print(reason,file=sys.stderr)\n"
        " raise SystemExit(1) from None"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts), action])


def inspect_component(data: dict[str, Any], action: str) -> bool:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=resource_command(action), _stdin=stream, _get_pty=False)
    try:
        observed = json.loads(result or "")
        if set(observed) != {"current"} or type(observed["current"]) is not bool:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise DeployError("Sessions component inspection is unavailable") from None
    return bool(observed["current"])


def inspect_sessions_resources(data: dict[str, Any]) -> dict[str, bool]:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=resource_command("status"), _stdin=stream, _get_pty=False)
    try:
        observed = json.loads(result or "")
        if set(observed) != {"current", "identity_verified"} or any(type(v) is not bool for v in observed.values()):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise DeployError("Sessions resource inspection is unavailable") from None
    return {key: bool(observed[key]) for key in ("current", "identity_verified")}


@deploy("Install original Sessions configuration and timer resources")
def install_sessions_resources(cfg: DaybookSessionsConfig, secrets: Mapping[str, str], source: SourceTree) -> None:
    """Resource substage; source/Brew/classifier prerequisites are separate.

    It is not an inventory role or activation operation. Original declared
    enabled Sessions/classifier schedules still retain their explicit start
    flags; current Studio declarations retire both timers.
    """
    if not cfg.daybook_sessions_enabled:
        return
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Daybook Sessions supports Darwin targets only")
    data = resource_payload(cfg, secrets, source)
    state = inspect_sessions_resources(data)
    if not state["current"]:
        secret_stdin(
            name="Converge original Sessions configuration and timer resources",
            command=resource_command("apply"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    mark_read_only(
        secret_stdin(
            name="Verify Sessions resources with bound pure identity gate",
            command=resource_command("verify"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    )


@deploy("Deploy original Daybook Sessions source and resources")
def deploy_daybook_sessions(
    cfg: DaybookSessionsConfig, secrets: Mapping[str, str], source: SourceTree, bundle: Path
) -> None:
    """Full-role controller; inventory adoption awaits owned qualification.

    The immutable tree/bundle are the normal once-per-run Main resolution. This
    is never the Inbox runtime update's source dependency: that remains Inbox
    only. Separate legacy convergence preserves unrelated runtime source/PIDs.
    """
    if not cfg.daybook_sessions_enabled:
        return
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Daybook Sessions supports Darwin targets only")
    data = resource_payload(cfg, secrets, source)

    def managed(name: str, action: str, payload: dict[str, Any] | None = None) -> None:
        secret_stdin(
            name=name,
            command=resource_command(action),
            content=SecretContent(json.dumps(payload or data) + "\n"),
        )

    if not inspect_component(data, "reconcile-status"):
        managed("Quiesce exact original system Weeknotes reconcile before source/configuration", "reconcile-quiesce")
    if not inspect_component(data, "prerequisites-status"):
        managed("Converge original uv/Homebrew prerequisites without package upgrades", "prerequisites-apply")
    if not inspect_component(data, "directories-status"):
        managed("Prepare original Sessions directories before source convergence", "directories-apply")
    source_state = inspect_sessions_source(cfg, source)
    install_sessions_source(cfg=cfg, source=source, bundle=bundle)
    if cfg.daybook_archive_quote_classifier_enabled and cfg.daybook_archive_quote_classifier_probe_enabled:
        # Real external model invocation under the original profile, including
        # on repeats. It must never be called from a fact or labeled read-only.
        managed("Run original synthetic Archive classifier probe as managed application work", "classifier-probe")
    data["source_changed"] = not source_state["current"]
    resource_state = inspect_sessions_resources(data)
    if not resource_state["current"]:
        managed("Converge original Sessions configuration and requested timer state", "apply")
    mark_read_only(
        secret_stdin(
            name="Verify original Sessions resources after managed source/resource stages",
            command=resource_command("verify"),
            content=SecretContent(json.dumps({**data, "source_changed": False}) + "\n"),
        )
    )
    mark_read_only(
        secret_stdin(
            name="Verify original Sessions uv/Homebrew prerequisites without installation",
            command=resource_command("prerequisites-verify"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    )
