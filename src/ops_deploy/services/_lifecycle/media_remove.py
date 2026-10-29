"""Bounded metadata and operations shared by the three original media removals."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator, Sequence
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

from pydantic import AfterValidator, Field
from pyinfra.api import DeployError, operation
from pyinfra.operations import server, systemd

from ops_deploy.base._common import RoleConfig, require_systemd
from ops_deploy.base._units import ACTIVE, ENABLED, unit_name, unit_states
from ops_deploy.helpers.probes import probe, stdin_arguments
from ops_deploy.helpers.traefik import guarded

SCRIPT = (Path(__file__).parent / "files/media_remove_host.py").read_text()
PACKAGES = ("jellyfin", "jellyfin-ffmpeg6", "jellyfin-ffmpeg5", "jellyfin-ffmpeg")
PROTECTED = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib/systemd",
        "/lib/systemd/system",
        "/media",
        "/mnt",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/local",
        "/usr/local/bin",
        "/var",
        "/var/cache",
        "/var/lib",
        "/var/log",
        "/etc/systemd",
        "/etc/systemd/system",
        "/usr/sbin",
        "/usr/share",
        "/usr/lib/systemd",
        "/usr/lib/systemd/system",
        "/lib64",
        "/var/tmp",
        "/var/spool",
        "/var/mail",
        "/var/www",
        "/var/opt",
        "/usr/local/sbin",
        "/usr/local/lib",
        "/run/systemd",
        "/etc/traefik",
        "/etc/traefik/dynamic",
        "/mnt/cryptdata",
        "/mnt/cryptdata/media",
        "/mnt/cryptdata/media/video",
    }
)


def bounded_path(value: str) -> str:
    path = PurePosixPath(value)
    canonical = "/" + str(path).lstrip("/")
    if ".." in path.parts or canonical in PROTECTED:
        raise ValueError("removal paths must identify a declared service resource")
    return canonical


ResourcePath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/ +\-]*$"), AfterValidator(bounded_path)]


def bounded_identity(value: str) -> str:
    if value == "root":
        raise ValueError("root cannot be a media service account")
    return value


Identity = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]*$", max_length=32), AfterValidator(bounded_identity)]
ServiceName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+$")]


class MediaRemoveConfig(RoleConfig):
    confirm: bool = False
    remove_user: bool = True
    remove_traefik_config: bool = True


def _command(action: str) -> str:
    return shlex.join(["python3", "-I", "-c", SCRIPT, action])


@operation()
def _remove_route(path: str) -> Generator[Any, None, None]:
    # The role's absent operation also removes directory/symlink entries.
    # Reuse the existing transaction guard around that literal operation.
    yield from guarded(server.shell._inner(commands=[f"rm -rf -- {shlex.quote(path)}"]))


def snapshot(paths: Sequence[str], user: str | None, group: str | None, packages: bool) -> dict[str, Any]:
    selected_paths = list(dict.fromkeys(paths))
    request = {"paths": selected_paths, "user": user, "group": group, "packages": packages}
    raw = probe(_command("inspect"), name="Selected media removal metadata", stdin=json.dumps(request))
    try:
        state = json.loads(raw) if raw is not None else None
    except ValueError:
        state = None
    if not isinstance(state, dict) or set(state) != {"paths", "user", "group", "packages"}:
        raise DeployError("Cannot establish selected media removal metadata")
    if not isinstance(state["paths"], dict) or set(state["paths"]) != set(selected_paths):
        raise DeployError("Selected media removal paths do not match")
    for metadata in state["paths"].values():
        if metadata is not None and (
            not isinstance(metadata, dict)
            or set(metadata) != {"mode", "uid", "gid"}
            or any(type(value) is not int or value < 0 for value in metadata.values())
        ):
            raise DeployError("Selected media path metadata is malformed")
    account = state["user"]
    if account is not None:
        if (
            not user
            or not isinstance(account, dict)
            or set(account) != {"uid", "gid", "home"}
            or type(account["uid"]) is not int
            or account["uid"] <= 0
            or type(account["gid"]) is not int
            or account["gid"] < 0
            or not isinstance(account["home"], str)
        ):
            raise DeployError("Selected media account metadata is malformed or protected")
        try:
            if not account["home"].startswith("/"):
                raise ValueError("account home is not absolute")
            bounded_path(account["home"])
        except ValueError:
            raise DeployError("Selected media account home is protected") from None
    group_id = state["group"]
    if group_id is not None and (not group or type(group_id) is not int or group_id <= 0):
        raise DeployError("Selected media group metadata is malformed or protected")
    selected = state["packages"]
    if not isinstance(selected, list) or any(p not in PACKAGES for p in selected) or (selected and not packages):
        raise DeployError("Selected media package metadata is malformed")
    return state


def remove_media(
    *,
    confirm: bool,
    label: str,
    service_name: str,
    unit_paths: Sequence[str],
    paths: Sequence[str],
    user: str | None,
    group: str | None,
    control_service: bool = True,
    packages: bool = False,
    traefik_path: str | None = None,
    reload_traefik: bool = False,
    defer_unit_reload: bool = False,
) -> None:
    if not confirm:
        raise DeployError(f"{label}: removal not confirmed; set confirm to proceed")
    require_systemd(label)
    control_unit = unit_name(service_name)
    unit = unit_states([control_unit])[control_unit] if control_service else None
    if unit is not None and (not unit.get("LoadState") or not unit.get("ActiveState")):
        raise DeployError("Cannot establish the selected media service metadata")
    state = snapshot([*unit_paths, *paths], user, group, packages)
    if unit is not None:
        if unit["ActiveState"] in ACTIVE:
            server.shell(name=f"Stop {service_name}", commands=[f"systemctl stop {shlex.quote(control_unit)} || true"])
        if unit.get("UnitFileState") in ENABLED:
            server.shell(
                name=f"Disable {service_name}", commands=[f"systemctl disable {shlex.quote(control_unit)} || true"]
            )
    removed_unit = False
    for path in dict.fromkeys(unit_paths):
        if state["paths"][path] is not None:
            server.shell(name=f"Remove {path}", commands=[f"rm -rf -- {shlex.quote(path)}"])
            removed_unit = True
    if removed_unit and not defer_unit_reload:
        systemd.daemon_reload(name="Reload systemd after removed media units")
    if state["packages"]:
        server.shell(
            name="Purge the original Jellyfin package set",
            commands=[
                shlex.join(
                    ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "purge", "--", *state["packages"]]
                )
            ],
        )
    for path in dict.fromkeys(paths):
        if state["paths"][path] is not None and path not in unit_paths:
            if path == traefik_path:
                _remove_route(name=f"Remove {path}", path=path)
            else:
                server.shell(name=f"Remove {path}", commands=[f"rm -rf -- {shlex.quote(path)}"])
    if state["user"] is not None or state["group"] is not None:
        payload = {"user": user, "group": group}
        server.shell(
            name="Remove the selected service account and group",
            commands=[_command("accounts")],
            **stdin_arguments(json.dumps(payload)),
        )
    if removed_unit and defer_unit_reload:
        systemd.daemon_reload(name="Reload systemd after removed media units")
    if reload_traefik and traefik_path is not None and state["paths"][traefik_path] is not None:
        server.shell(name="Reload Traefik after removed MeTube route", commands=["systemctl reload traefik || true"])
