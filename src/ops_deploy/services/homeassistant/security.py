"""Original environment/system-store trust checks and install constraints.

Preflight runs before any deployment write. The post-install FunctionCommand
reads fresh reports at execution time, rather than reusing cached preflight
facts. The original inspector imports only certifi/pip, never Home Assistant.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from importlib.resources import files
from io import StringIO
from pathlib import PurePosixPath
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files as file_ops

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.python import _as_user

from .runtime_config import HomeAssistantRuntimeConfig
from .security_policy import python_security_constraints, python_security_report_violations


def _script(name: str) -> str:
    return files("ops_deploy.services.homeassistant").joinpath("files", name).read_text()


def environment_command(cfg: HomeAssistantRuntimeConfig, python: str) -> str:
    argv = [
        python,
        "-I",
        "-B",
        "-c",
        _script("inspect_python_security.py"),
        "--managed-base-prefix",
        cfg.security.managed_base_prefix,
    ]
    # -B only prevents bytecode cache writes; inspector and policy are the
    # original source. No application import or extra trust override is added.
    return _as_user(cfg.user, PurePosixPath(cfg.home), {}, argv) if cfg.security.become else shlex.join(argv)


def _read(target: Host, command: str, *, label: str = "Home Assistant trust inspection") -> str:
    success, output = target.run_shell_command(
        StringCommand(command),
        print_output=False,
        print_input=False,
        _timeout=60,
    )
    if not success:
        raise OperationError(f"{label}: inspection command failed")
    return str(output.stdout)


def _report(target: Host, command: str, *, label: str = "Home Assistant trust inspection") -> dict[str, Any]:
    try:
        value = json.loads(_read(target, command, label=label))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise OperationError("Home Assistant trust inspection returned no valid report") from None


def _present(target: Host, path: str, system_python: str) -> bool:
    source = """import os, sys
try:
    os.lstat(sys.argv[1])
except FileNotFoundError:
    print('absent')
else:
    print('present')
"""
    answer = _read(
        target, shlex.join([system_python, "-I", "-B", "-c", source, path]), label=f"Environment path {path}"
    ).strip()
    if answer not in {"absent", "present"}:
        raise OperationError("Home Assistant environment stat returned an invalid result")
    return answer == "present"


def _environments(target: Host, cfg: HomeAssistantRuntimeConfig, *, preflight: bool) -> None:
    policy = cfg.security
    for environment in cfg.python_security_environments:
        python = environment.path + "/bin/python"
        if preflight and not _present(target, python, policy.system_python):
            continue
        report = _report(target, environment_command(cfg, python), label=f"{environment.label} ({python})")
        problems = python_security_report_violations(
            report,
            policy.packages,
            [root.model_dump() for root in policy.distrusted_roots],
            policy.requires_python,
            policy.deferred,
            {"python_version": policy.expected_python_version} if policy.managed_base_prefix else None,
        )
        if problems:
            raise OperationError(f"{environment.label}: {'; '.join(problems)}")


def security_preflight(cfg: HomeAssistantRuntimeConfig) -> None:
    """Original first environment checks and system-store admission, before writes."""
    try:
        if cfg.python_security_floor_enabled:
            _environments(host, cfg, preflight=True)
        if cfg.uv_system_certs:
            policy = cfg.security
            report = _report(
                host,
                shlex.join(
                    [
                        policy.system_python,
                        "-I",
                        "-B",
                        "-c",
                        _script("inspect_ca_file.py"),
                        policy.system_store,
                        *policy.system_store_dirs,
                    ]
                ),
                label=f"System CA store {policy.system_store}",
            )
            fingerprints = report.get("fingerprints")
            if not isinstance(fingerprints, list) or not all(isinstance(value, str) for value in fingerprints):
                raise OperationError("Home Assistant system store returned invalid fingerprints")
            # Exact original selectattr policy compares configured fingerprints
            # with uppercased observed fingerprints (not label matching).
            observed = {value.upper() for value in fingerprints}
            hits = [root.name for root in policy.distrusted_roots if root.sha256 in observed]
            if hits:
                raise OperationError("System store still trusts " + ", ".join(hits))
    except (OperationError, ValueError) as exc:
        raise DeployError(str(exc)) from None


def write_constraints(cfg: HomeAssistantRuntimeConfig) -> OperationMeta | None:
    if not cfg.python_security_floor_enabled:
        return None
    return file_ops.put(
        name="Write Home Assistant Python security constraints",
        src=StringIO(python_security_constraints(cfg.security.packages)),
        dest=cfg.python_security_constraints_path,
        user=cfg.user,
        group=cfg.group,
        mode="0644",
    )


def _after_install(state: State, host: Host, cfg: HomeAssistantRuntimeConfig) -> None:
    # state/host parameter names intentionally use FunctionCommand's supported
    # execution callback contract; no stale host-fact cache is consulted.
    _environments(host, cfg, preflight=False)


@operation()
def _verify_after_install(cfg: HomeAssistantRuntimeConfig) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_after_install, (cfg,), {})


def verify_security(cfg: HomeAssistantRuntimeConfig) -> OperationMeta | None:
    if not cfg.python_security_floor_enabled:
        return None
    return mark_read_only(_verify_after_install(name="Verify Home Assistant environment trust floors", cfg=cfg))
