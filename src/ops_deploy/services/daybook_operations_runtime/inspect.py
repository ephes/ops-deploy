"""Local-only pure runtime observation via the normal pyinfra connector."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import plistlib
import shlex
import subprocess
from collections.abc import Mapping
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

from .config import DaybookRuntimeConfig
from .decision import InstalledRuntime
from .render import credential_text, render_resource
from .status import SourceStatus

SCRIPT = files("ops_deploy.services.daybook_operations_runtime").joinpath("files/runtime_state.py").read_bytes()


def daybook_code_manifest(source: SourceTree, revision: str) -> dict[str, str]:
    if source.commit != revision:
        raise ValueError("Runtime source must be the same once-resolved Main revision")
    environment = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}

    def git(*args: str) -> bytes:
        result = subprocess.run(
            ["/usr/bin/git", "--no-optional-locks", "-C", str(source.path), *args],
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise ValueError("Runtime controller source is unavailable")
        return result.stdout

    if (
        git("rev-parse", "HEAD").decode().strip() != source.commit
        or git("status", "--porcelain", "--untracked-files=all").strip()
    ):
        raise ValueError("Runtime controller source must be exact and clean")
    expected = {}
    for relative in git("ls-files", "-z").decode().split("\0"):
        if not (
            (relative.startswith("src/daybook/") and relative.endswith(".py"))
            or relative in {"uv.lock", "pyproject.toml", ".python-version"}
        ):
            continue
        path = source.path / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Runtime controller code manifest must contain regular files")
        expected[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not expected:
        raise ValueError("Runtime controller source has no package code")
    return expected


def source_manifest(source: SourceTree, cfg: DaybookRuntimeConfig) -> dict[str, str]:
    return daybook_code_manifest(source, cfg.revision)


def observation_payload(cfg: DaybookRuntimeConfig, secrets: Mapping[str, str], source: SourceTree) -> dict[str, Any]:
    credential = credential_text(secrets.get("executor_token", ""))
    owner, group = ("root", "wheel") if cfg.owner == "root" else (cfg.user, "staff")
    policy = render_resource(cfg, "policy.json.j2")
    plist = render_resource(cfg, "runtime.plist.j2")
    resources = [
        {"path": str(cfg.policy), "owner": owner, "group": group, "mode": 0o644, "content": policy},
        {"path": str(cfg.staged_plist), "owner": owner, "group": group, "mode": 0o644, "content": plist},
        {"path": str(cfg.plist), "owner": owner, "group": group, "mode": 0o644, "content": plist},
        {
            "path": str(cfg.credential),
            "owner": cfg.user,
            "group": "staff",
            "mode": 0o600,
            "content": credential,
        },
    ]
    return {
        **cfg.model_dump(mode="json"),
        "group": "staff",
        "checkout": str(Path(str(cfg.install_root)) / "daybook"),
        "source_hashes": source_manifest(source, cfg),
        "resources": resources,
        "expected_argv": plistlib.loads(plist.encode())["ProgramArguments"],
        "preserve_enabled": True,
    }


def observation_command(action: str = "status") -> str:
    if action not in {"status", "verify"}:
        raise ValueError("Unsupported pure runtime observation action")
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(SCRIPT).decode()
        + "'),'<daybook-runtime-observer>','exec'))"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", launcher, action])


def observe_daybook_runtime(
    cfg: DaybookRuntimeConfig, secrets: Mapping[str, str], source: SourceTree
) -> InstalledRuntime:
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    data = observation_payload(cfg, secrets, source)
    # Raw string _stdin is printed by verbose Fact completion. StringIO is the
    # existing stdin writer's supported in-memory stream: repr contains no body.
    # No secret enters command/argv/environment; never PTY.
    with io.StringIO(json.dumps(data) + "\n") as stream:
        output = host.get_fact(Command, command=observation_command(), _stdin=stream, _get_pty=False)
    try:
        state = json.loads(output or "")
        if any(type(state.get(key)) is not bool for key in ("enabled", "source_current", "resources_current")):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise DeployError("Pure local runtime observation is unavailable") from None
    return InstalledRuntime(state["enabled"], state["source_current"], state["resources_current"])


@deploy("Verify protected Daybook runtime without Journal or executor calls")
def verify_daybook_runtime(
    cfg: DaybookRuntimeConfig, secrets: Mapping[str, str], source: SourceTree, *, statuses: tuple[SourceStatus, ...]
) -> None:
    names = [status.binding for status in statuses]
    if len(names) != len(set(names)) or set(names) != set(cfg.status_sources):
        raise DeployError("Pure runtime monitor has missing or duplicate declared sources")
    if any(not status.enabled or status.needs_operator or status.expiry_pending for status in statuses):
        raise DeployError("Pure runtime monitor requires operator attention")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    data = observation_payload(cfg, secrets, source)
    mark_read_only(
        secret_stdin(
            name="Verify current Daybook code, profile, credentials and supervisor",
            command=observation_command("verify"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    )
