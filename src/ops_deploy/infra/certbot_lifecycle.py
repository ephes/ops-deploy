"""Source-backed Certbot state backup/restore, including retained pre-restore trees."""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import stat
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, field_validator, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import RoleConfig, require_linux
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.infra.traefik_backup import _private_local_file as _traefik_private_local_file

FILES = Path(__file__).parent / "files"
HOST_SCRIPT = (
    "ARCHIVE_MEMBERS_SOURCE=" + repr((FILES / "certbot_archive_members.py").read_text()) + "\n"
    "PRESERVE_SOURCE="
    + repr((FILES / "certbot_preserve.py").read_text())
    + "\n"
    + (FILES / "certbot_lifecycle_host.py").read_text()
)
PathValue = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/ +\-]*$")]
Mode = Annotated[
    str,
    BeforeValidator(lambda value: format(value, "04o") if type(value) is int else value),
    Field(pattern=r"^0?[0-7]{3}$"),
]
Identity = Annotated[
    str,
    BeforeValidator(lambda value: str(value) if type(value) is int else value),
    Field(pattern=r"^(?:[a-z_][a-z0-9_-]*|[0-9]+)$"),
]


class CertbotPaths(RoleConfig):
    root: PathValue = "/opt/backups/certbot-dns"
    owner: Identity = "root"
    group: Identity = "root"
    dir_mode: Mode = "0700"
    archive_extension: Annotated[str, Field(pattern=r"^[A-Za-z0-9.]+$")] = "tar.gz"

    @field_validator("root")
    @classmethod
    def canonical_root(cls, value: str) -> str:
        return _bounded(value)


def _bounded(value: str, *, mutable: bool = True) -> str:
    path = PurePosixPath(value)
    canonical = "/" + str(path).lstrip("/")
    protected = {
        "/",
        "/etc",
        "/var",
        "/usr",
        "/home",
        "/root",
        "/tmp",
        "/opt",
        "/mnt",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/srv",
        "/media",
        "/var/lib",
        "/var/log",
        "/var/cache",
        "/var/tmp",
        "/var/spool",
        "/var/mail",
        "/usr/bin",
        "/usr/sbin",
        "/usr/share",
        "/usr/lib",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/lib",
        "/usr/local/sbin",
    }
    if ".." in path.parts or canonical in protected:
        raise ValueError("Certbot paths must identify a declared resource directory")
    if mutable and any(".pre-restore-" in part for part in path.parts):
        raise ValueError("Certbot must never mutate a retained pre-restore copy")
    return canonical


class CertbotDnsBackupConfig(CertbotPaths):
    src: PathValue = "/etc/letsencrypt"
    prefix: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")] = "manual"
    archive_format: Literal["gz", "bz2", "xz", "tar", "zip"] = "gz"
    create_archive: bool = True
    fetch_local: bool = True
    local_dir: Path | None = None
    local_dir_mode: Mode = "0700"

    @field_validator("local_dir")
    @classmethod
    def local_path(cls, value: Path | None) -> Path | None:
        return Path(_bounded(str(value.expanduser().absolute()))) if value is not None else None

    @field_validator("src")
    @classmethod
    def source_path(cls, value: str) -> str:
        return _bounded(value, mutable=False)

    @model_validator(mode="after")
    def separate_source(self) -> Self:
        root, source = PurePosixPath(self.root), PurePosixPath(self.src)
        if root == source or root.is_relative_to(source) or source.is_relative_to(root):
            raise ValueError("Certbot backup source and root must be disjoint")
        return self


class CertbotDnsRestoreConfig(CertbotPaths):
    archive: Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._/ +\-]+)$", min_length=1)]
    directory: PathValue = "/etc/letsencrypt"
    credentials_file: PathValue | Literal[""] = "/etc/letsencrypt/dns-credentials.ini"
    rfc2136_credentials_file: PathValue | Literal[""] = "/etc/letsencrypt/dns-rfc2136-credentials.ini"
    credentials_mode: Mode = "0600"
    dry_run: bool = False
    run_dry_renew: bool = True
    reload_postfix: bool = False

    @field_validator("directory")
    @classmethod
    def target_path(cls, value: str) -> str:
        return _bounded(value)

    @field_validator("archive", "credentials_file", "rfc2136_credentials_file")
    @classmethod
    def no_traversal(cls, value: str) -> str:
        if ".." in PurePosixPath(value).parts:
            raise ValueError("Certbot archive and credential paths cannot contain parent traversal")
        return value

    @field_validator("credentials_file", "rfc2136_credentials_file")
    @classmethod
    def keep_preserved_credentials(cls, value: str) -> str:
        if any(".pre-restore-" in part for part in PurePosixPath(value).parts):
            raise ValueError("Certbot must never change credentials in a retained pre-restore copy")
        return value


def _command(action: str) -> str:
    # Like the existing Traefik engine loader, encode trusted packaged source:
    # fish login shells otherwise alter backslash pairs in nested Python reprs.
    encoded = base64.b64encode(HOST_SCRIPT.encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<certbot-lifecycle>','exec'))"
    return shlex.join(["python3", "-I", "-c", loader, action])


def _validated(action: str, payload: dict[str, object]) -> dict[str, object]:
    raw = probe(_command(action), name="Certbot lifecycle validation before mutation", stdin=json.dumps(payload))
    try:
        value = json.loads(raw) if raw is not None else None
    except ValueError:
        value = None
    expected = (
        {"valid", "archive", "timestamp", "managed", "restrict"}
        if action == "backup-plan"
        else {"valid", "archive", "tops"}
    )
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("valid") is not True
        or not isinstance(value.get("archive"), str)
        or not value["archive"]
    ):
        raise DeployError("Certbot lifecycle validation failed before mutation")
    if action == "backup-plan":
        stamp = value["timestamp"]
        archive = f"{payload['root']}/{payload['prefix']}-{stamp}.{payload['archive_extension']}"
        if (
            not isinstance(stamp, str)
            or re.fullmatch(r"[0-9]{8}T[0-9]{6}", stamp) is None
            or type(value["managed"]) is not bool
            or (payload["create_archive"] and not value["managed"])
            or not isinstance(value["restrict"], list)
            or any(not isinstance(path, str) for path in value["restrict"])
            or value["archive"] != archive
        ):
            raise DeployError("Certbot backup plan metadata is malformed")
    elif value["tops"] != [PurePosixPath(str(payload["directory"])).name]:
        raise DeployError("Certbot archive top-level metadata is malformed")
    return value


def _local_dir_current(path: str, mode: str) -> bool:
    try:
        details = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(details.st_mode):
        raise DeployError("Certbot local backup directory must be a real directory")
    return stat.S_IMODE(details.st_mode) == int(mode, 8)


def _local_dir(path: str, mode: str) -> None:
    os.makedirs(path, mode=int(mode, 8), exist_ok=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(descriptor, int(mode, 8))
    finally:
        os.close(descriptor)


def _private_local_file(path: str) -> None:
    try:
        _traefik_private_local_file(path)
    except DeployError as error:
        raise DeployError("Certbot local archive destination must be a regular, singly-linked file") from error


def _prepare_local_archive(path: str) -> None:
    # files.get writes through the destination with the controller's umask.
    # Reserve a new 0600 file so an interrupted fetch cannot leave a 0644 partial.
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        _private_local_file(path)
    else:
        os.close(descriptor)


@deploy("Certbot state backup")
def deploy_certbot_dns_backup(cfg: CertbotDnsBackupConfig) -> None:
    require_linux("certbot_dns_backup")
    payload = cfg.model_dump(mode="json")
    checked = _validated("backup-plan", payload)
    if type(checked.get("managed")) is not bool or not isinstance(checked.get("timestamp"), str):
        raise DeployError("Certbot backup plan metadata is malformed")
    payload["_timestamp"] = checked["timestamp"]
    if checked["managed"]:
        server.shell(
            name="Create the original private Certbot state backup",
            commands=[_command("backup-apply")],
            **stdin_arguments(json.dumps(payload)),
        )
    if cfg.fetch_local:
        local = str(cfg.local_dir or Path.home() / "backups/certbot-dns")
        if not _local_dir_current(local, cfg.local_dir_mode):
            python.call(
                name="Ensure the Certbot local backup directory",
                function=_local_dir,
                path=local,
                mode=cfg.local_dir_mode,
            )
        if cfg.create_archive:
            archive = str(checked["archive"])
            destination = str(Path(local) / PurePosixPath(archive).name)
            python.call(
                name="Prepare the private local Certbot archive destination",
                function=_prepare_local_archive,
                path=destination,
            )
            files.get(name="Fetch the Certbot state archive", src=archive, dest=destination)
            python.call(
                name="Restrict the fetched Certbot archive to 0600", function=_private_local_file, path=destination
            )


@deploy("Certbot state restore")
def deploy_certbot_dns_restore(cfg: CertbotDnsRestoreConfig) -> None:
    require_linux("certbot_dns_restore")
    payload = cfg.model_dump(mode="json")
    checked = _validated("restore-validate", payload)
    payload["archive"] = checked["archive"]
    if cfg.dry_run:
        verify_probe(
            _command("restore-validate"),
            name="Certbot archive validation only; no publication or renewal",
            stdin=json.dumps(payload),
        )
    else:
        server.shell(
            name="Preserve and restore original Certbot state with optional renewal and mail reload",
            commands=[_command("restore-apply")],
            **stdin_arguments(json.dumps(payload)),
        )
