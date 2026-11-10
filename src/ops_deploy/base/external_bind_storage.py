"""Bind mounts from an external filesystem at their original paths.

The persistent result of ops-library's ``host_storage_migrate`` tool after its
cutover: one ``.mount`` unit per relocated directory (bound from
``root/<path>`` and tied to the external mount), an ``.automount`` guard for
backup directories, drop-ins that make the container engines require their
bind mounts, and Docker's builder cache limit in ``daemon.json``. Byte for
byte what the tool writes, so a host it migrated shows no change.

Nothing is copied, mounted, started or restarted: the units are written,
systemd is reloaded and the units are enabled for the next boot. Moving data
is the tool's attended job.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import shlex
from io import StringIO

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux, require_systemd
from ops_deploy.base._units import ENABLED, unit_states

SYSTEMD = "/etc/systemd/system"
DAEMON_JSON = "/etc/docker/daemon.json"
_PLAIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_.")


class BindSource(RoleConfig):
    path: AbsolutePath
    # Backup directories: autofs keeps the path present when the bind mount
    # stops, so a root-run backup fails instead of writing underneath.
    automount: bool = False


class EngineBinds(RoleConfig):
    unit: str = Field(pattern=r"^[A-Za-z0-9_.@-]+\.service$")
    paths: tuple[AbsolutePath, ...] = Field(min_length=1)


class ExternalBindStorageConfig(RoleConfig):
    mount: AbsolutePath
    root: AbsolutePath
    sources: tuple[BindSource, ...] = Field(min_length=1)
    engines: tuple[EngineBinds, ...] = ()
    # Docker's builder garbage collection limit; None leaves daemon.json alone.
    # The deploy owns the whole file: do not combine with docker_install's
    # configure_daemon on the same host.
    docker_builder_gc_bytes: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _engine_paths_are_sources(self) -> ExternalBindStorageConfig:
        # The tool's validate(): normalized paths, a real mount, a root below it.
        named = [("mount", self.mount), ("root", self.root)]
        named += [("source", source.path) for source in self.sources]
        for what, path in named:
            if posixpath.normpath(path) != path or path == "/":
                raise ValueError(f"{what} {path!r} must be a normalized path other than /")
        paths = [source.path for source in self.sources]
        if len(set(paths)) != len(paths):
            raise ValueError("sources must be unique")
        paths_set = set(paths)
        for engine in self.engines:
            missing = [path for path in engine.paths if path not in paths_set]
            if missing:
                raise ValueError(f"{engine.unit} needs bind mounts that are not sources: {', '.join(missing)}")
        if not self.root.startswith(self.mount + "/"):
            raise ValueError("root must be below mount")
        return self


def escape_path(path: str) -> str:
    """``systemd-escape --path``."""

    trimmed = "/".join(part for part in path.split("/") if part)
    if not trimmed:
        return "-"
    escaped = []
    for index, char in enumerate(trimmed):
        if char == "/":
            escaped.append("-")
        elif char in _PLAIN and not (index == 0 and char == "."):
            escaped.append(char)
        else:
            escaped.extend(f"\\x{byte:02x}" for byte in char.encode())
    return "".join(escaped)


def mount_unit(path: str) -> str:
    return f"{escape_path(path)}.mount"


def unit_files(cfg: ExternalBindStorageConfig) -> dict[str, str]:
    """Path -> content, as the tool's ``unit_files`` writes them."""

    external = mount_unit(cfg.mount)
    result: dict[str, str] = {}
    for source in cfg.sources:
        name = mount_unit(source.path)
        result[f"{SYSTEMD}/{name}"] = (
            "[Unit]\nDescription=External bulk storage\n"
            f"RequiresMountsFor={cfg.mount}\n"
            f"BindsTo={external}\nAfter={external}\n"
            f"\n[Mount]\nWhat={cfg.root}{source.path}\nWhere={source.path}\nType=none\nOptions=bind\n"
            "\n[Install]\nWantedBy=local-fs.target\n"
        )
        if source.automount:
            result[f"{SYSTEMD}/{escape_path(source.path)}.automount"] = (
                "[Unit]\nDescription=Guard external backup storage access\n"
                f"\n[Automount]\nWhere={source.path}\nTimeoutIdleSec=0\n"
                "\n[Install]\nWantedBy=local-fs.target\n"
            )
    for engine in cfg.engines:
        units = " ".join(mount_unit(path) for path in engine.paths)
        result[f"{SYSTEMD}/{engine.unit}.d/90-host-storage.conf"] = (
            f"[Unit]\nRequires={units}\nAfter={units}\nBindsTo={units}\n"
        )
    return result


def enabled_units(cfg: ExternalBindStorageConfig) -> list[str]:
    """What boots the binds: the automount where there is one, else the mount."""

    return [
        f"{escape_path(source.path)}.automount" if source.automount else mount_unit(source.path)
        for source in cfg.sources
    ]


def daemon_json(gc_bytes: int) -> str:
    policy = {"all": True, "reservedSpace": "0B", "maxUsedSpace": str(gc_bytes)}
    return json.dumps({"builder": {"gc": {"enabled": True, "policy": [policy]}}}, indent=2) + "\n"


def installed(path: str, content: str, mode: int) -> bool:
    """Whether ``path`` holds exactly ``content`` as root with ``mode``.

    For names with a backslash (``\\x2d``): GNU ``sha256sum`` escapes them in its
    output, which pyinfra's hash facts cannot parse, so ``files.put`` would
    always see a difference. The hash is read from stdin instead.
    """

    info = host.get_fact(File, path=path)
    if not info or info.get("mode") != mode or info.get("user") != "root" or info.get("group") != "root":
        return False
    digest = output(f"sha256sum < {shlex.quote(path)}").split()
    return bool(digest) and digest[0] == hashlib.sha256(content.encode()).hexdigest()


@deploy("External bind storage")
def deploy_external_bind_storage(cfg: ExternalBindStorageConfig) -> None:
    require_linux("external_bind_storage")
    require_systemd("external_bind_storage")
    written: list[OperationMeta] = []
    for engine in cfg.engines:
        files.directory(
            name=f"Ensure {SYSTEMD}/{engine.unit}.d",
            path=f"{SYSTEMD}/{engine.unit}.d",
            user="root",
            group="root",
            mode="0700",
        )
    for path, content in unit_files(cfg).items():
        if "\\" in path and installed(path, content, 600):
            continue
        written.append(
            files.put(name=f"Install {path}", src=StringIO(content), dest=path, user="root", group="root", mode="0600")
        )
    systemd.daemon_reload(name="Reload systemd for the storage units", _if=any_changed(*written))
    for unit, state in unit_states(enabled_units(cfg)).items():
        if state.get("UnitFileState") not in ENABLED:
            server.shell(name=f"Enable {unit}", commands=[f"systemctl enable -- {shlex.quote(unit)}"])
    if cfg.docker_builder_gc_bytes is not None:
        files.directory(name="Ensure /etc/docker", path="/etc/docker", user="root", group="root", mode="0755")
        files.put(
            name=f"Docker builder cache limit in {DAEMON_JSON}",
            src=StringIO(daemon_json(cfg.docker_builder_gc_bytes)),
            dest=DAEMON_JSON,
            user="root",
            group="root",
            mode="0600",
        )
