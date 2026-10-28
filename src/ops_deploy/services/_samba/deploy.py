"""Batched config, native missing-only accounts and one daemon rollout."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Users, Which
from pyinfra.operations import apt, server

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import StdinLines, probe

from .config import SambaBaseConfig

SCRIPTS = Path(__file__).parent.parent.parent / "infra/files"
ACCOUNT_SCRIPT = (SCRIPTS / "samba_accounts_host.py").read_text()
CONFIG_SCRIPT = (SCRIPTS / "samba_config_host.py").read_text()


def command(script: str, action: str) -> str:
    source = {"accounts": ACCOUNT_SCRIPT, "config": CONFIG_SCRIPT}[script]
    allowed = {"check", "apply"} if script == "accounts" else {"check", "apply", "rollout-check", "rollout"}
    if action not in allowed:
        raise ValueError("invalid Samba helper action")
    return shlex.join(["python3", "-I", "-c", source, action])


def secret_users(secrets: SecretValues | None, names: tuple[str, ...], *, strict: bool) -> SecretStr:
    """Validate before any operation, without interpolating secret values in errors."""
    if not names:
        return SecretStr("[]")
    try:
        rows = json.loads(secrets["users"]) if secrets is not None else None
        if not isinstance(rows, list):
            raise ValueError
        relevant = [row for row in rows if isinstance(row, dict) and row.get("name") in names]
        if len(relevant) != len(names) or {row["name"] for row in relevant} != set(names):
            raise ValueError
        result = []
        for row in relevant:
            password = row.get("password", "")
            if not isinstance(password, str) or any(c in password for c in "\r\n\0"):
                raise ValueError
            if strict and (not password or password == "CHANGEME"):
                raise ValueError
            result.append({"name": row["name"], "password": password})
        return SecretStr(json.dumps(result))
    except (ValueError, KeyError, TypeError):
        raise ValueError(
            "Samba secret users must cover the declared account names with valid password fields"
        ) from None


def prerequisites(cfg: SambaBaseConfig) -> None:
    require_linux("Samba")
    require_systemd("Samba")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("Samba requires Debian/Ubuntu apt")
    installed = host.get_fact(DebPackages)
    apt.packages(
        name="Ensure Samba native tools and VFS packages",
        packages=list(cfg.packages),
        update=any(pkg not in installed for pkg in cfg.packages),
        cache_time=3600,
    )


def unix_users(names: tuple[str, ...], group: str) -> None:
    existing = host.get_fact(Users)
    for name in names:
        groups = [] if existing.get(name, {}).get("group") == group else [group]
        server.user(
            name=f"Ensure Samba Unix account {name}",
            user=name,
            groups=groups,
            append=True,
            shell="/usr/sbin/nologin",
            create_home=False,
            ensure_home=False,
        )


@operation()
def configure(payload: str) -> Generator[StringCommand, None, None]:
    state = probe(command("config", "check"), name="Samba owned configuration", stdin=payload)
    if state == "current":
        host.noop("Samba owned configuration is current")
    elif state == "pending":
        yield StringCommand(
            command("config", "apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh"
        )
    else:
        raise DeployError("Samba configuration state is unknown; refusing changes")


@operation()
def accounts(config: str, names: tuple[str, ...], credentials: SecretStr) -> Generator[StringCommand, None, None]:
    if not names:
        host.noop("No Samba accounts were requested")
        return
    raw = probe(
        command("accounts", "check"),
        name="Samba native names/flags inventory",
        stdin=json.dumps({"config": config, "names": names}),
    )
    try:
        state = json.loads(raw or "null")
        if not isinstance(state, dict) or state.get("state") not in {"known", "prerequisites"}:
            raise ValueError
        missing = state["missing"]
        if not isinstance(missing, list) or not set(missing) <= set(names):
            raise ValueError
    except (TypeError, KeyError, ValueError):
        raise DeployError("Samba account inventory is unknown; no account creation admitted") from None
    if not missing:
        host.noop("Requested Samba accounts already exist; passwords and disabled flags untouched")
        return
    rows = [row for row in json.loads(credentials.get_secret_value()) if row["name"] in missing]
    if any(not row["password"] for row in rows):
        raise DeployError("A missing Samba account needs a nonempty password")
    payload = json.dumps({"config": config, "names": missing, "credentials": rows})
    yield StringCommand(
        command("accounts", "apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh"
    )


@operation()
def rollout(payload: str) -> Generator[StringCommand, None, None]:
    state = probe(command("config", "rollout-check"), name="Samba restart debt and service metadata", stdin=payload)
    if state == "current":
        host.noop("Samba daemons are current; no restart")
    elif state == "pending":
        yield StringCommand(
            command("config", "rollout"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh"
        )
    else:
        raise DeployError("Samba rollout state is unknown; refusing restart")


def request(cfg: SambaBaseConfig, *, base: str, fragments: list[dict[str, str]], fruit: str | None = None) -> str:
    body: dict[str, Any] = {
        "config": cfg.config_file,
        "base": base,
        "fragments": fragments,
        "fruit": fruit,
        "service_enabled": cfg.service_enabled,
        "service_state": cfg.service_state,
    }
    return json.dumps(body)
