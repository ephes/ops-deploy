"""Pinned-major Python environment and change-gated original editable installs."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator

from pyinfra import state
from pyinfra.api import DeployError, StringCommand, operation

from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.python_security import SECURITY_FLOORS

from .commands import host_command
from .config import PaperlessConfig
from .operations import as_service


def constraints_text() -> str:
    return "".join(f"{name}>={'.'.join(map(str, floor))}\n" for name, floor in sorted(SECURITY_FLOORS.items()))


def interpreter_probe(cfg: PaperlessConfig) -> str:
    venv = shlex.quote(f"{cfg.site_root}/.venv")
    python = shlex.quote(f"{cfg.site_root}/.venv/bin/python")
    run = as_service(
        cfg,
        shlex.join(
            [f"{cfg.site_root}/.venv/bin/python", "-I", "-B", "-c", "import sys;print('%d.%d' % sys.version_info[:2])"]
        ),
    )
    script = (
        f"if [ -L {venv} ]; then echo unsafe; "
        f"elif [ ! -e {python} ] && [ ! -L {python} ]; then echo missing; "
        f"elif out=$({run} 2>/dev/null); then echo python=$out; else echo broken; fi"
    )
    return shlex.join(["sh", "-c", script])


def interpreter_state(cfg: PaperlessConfig) -> str:
    answer = probe(interpreter_probe(cfg), name="Paperless interpreter state")
    if answer == "python=3.14":
        return "current"
    if answer in {"missing", "broken"}:
        return answer
    if (
        answer is not None
        and answer.startswith("python=")
        and answer.removeprefix("python=").replace(".", "").isdigit()
    ):
        return "wrong-version"
    raise DeployError("Paperless interpreter inspection is unsafe or unknown")


@operation()
def ensure_venv(cfg: PaperlessConfig, deferred: bool = False) -> Generator[StringCommand, None, None]:
    if not (deferred and not state.is_executing) and interpreter_state(cfg) == "current":
        return
    yield StringCommand(
        as_service(
            cfg,
            shlex.join(
                [
                    cfg.uv_binary,
                    "venv",
                    "--clear",
                    "--python",
                    cfg.python_version,
                    f"{cfg.site_root}/.venv",
                ]
            ),
        )
    )


def package_state(cfg: PaperlessConfig) -> dict[str, bool]:
    command = as_service(cfg, host_command("runtime_state", interpreter=f"{cfg.site_root}/.venv/bin/python"))
    answer = probe(
        command,
        name="Paperless installed distribution metadata",
        stdin=json.dumps({"release_dir": f"{cfg.site_root}/paperless-ngx-v{cfg.version}"}),
    )
    try:
        value = json.loads(answer or "")
        if (
            not isinstance(value, dict)
            or set(value) != {"python", "application", "supporting"}
            or any(type(item) is not bool for item in value.values())
            or value["python"] is not True
        ):
            raise ValueError
    except ValueError:
        raise DeployError("Paperless runtime metadata inspection failed after interpreter preparation") from None
    if not dependencies_current(cfg):
        value["application"] = False
    return value


def dependencies_current(cfg: PaperlessConfig) -> bool:
    command = as_service(
        cfg,
        shlex.join([cfg.uv_binary, "pip", "check", "--python", f"{cfg.site_root}/.venv/bin/python"]),
    )
    # uv distinguishes dependency inconsistencies (1) from inspection failures
    # (2). Never export its package/path diagnostics into inventory logs.
    script = f"{command} >/dev/null 2>&1; rc=$?; case $rc in 0) echo current ;; 1) echo pending ;; *) exit 1 ;; esac"
    result = probe(shlex.join(["sh", "-c", script]), name="Paperless dependency consistency")
    if result not in {"current", "pending"}:
        raise DeployError("Paperless dependency inspection failed; refusing unknown package changes")
    return result == "current"


def install_commands(cfg: PaperlessConfig, *, application: bool, supporting: bool) -> tuple[str, ...]:
    base = [cfg.uv_binary, "pip", "install", "--python", f"{cfg.site_root}/.venv"]
    if cfg.python_security_floor_enabled:
        base += ["--constraint", f"{cfg.site_root}/.python-security-constraints.txt"]
    commands = []
    if application:
        commands.append(
            as_service(cfg, shlex.join([*base, "-e", f"{cfg.site_root}/paperless-ngx-v{cfg.version}[postgres]"]))
        )
    if supporting:
        commands.append(as_service(cfg, shlex.join([*base, "gunicorn", "whitenoise", "setproctitle"])))
        commands.append(as_service(cfg, shlex.join([*base, "--force-reinstall", "fido2==1.1.3"])))
    return tuple(commands)


@operation()
def install_packages(cfg: PaperlessConfig, deferred: bool = False) -> Generator[StringCommand, None, None]:
    if deferred and not state.is_executing:
        application = supporting = True
    else:
        actual = package_state(cfg)
        application = cfg.force_reinstall or not actual["application"]
        # Editable dependency resolution can replace fido2; the original
        # supporting/pinned install follows every application installation.
        supporting = application or not actual["supporting"]
    for command in install_commands(cfg, application=application, supporting=supporting):
        yield StringCommand(command)
