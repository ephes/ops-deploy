"""minio: MinIO object storage as a hardened systemd service, optionally behind Traefik.

Port of the ``minio_deploy`` Ansible role together with the steps of
ops-control's ``deploy-minio.yml`` that belong to MinIO itself: the port
preflight and, in place of the encrypted-volume play it imports first, a
read-only check that the data volume is mounted. The role's templates are
shipped unchanged and rendered the way Ansible renders them, so the env file,
unit and Traefik route are byte-identical (``tests/test_minio_parity.py``) and
Ansible and ops-deploy can take turns on one host without churn.

Unlike the role, steps that would change nothing are skipped: the binaries are
downloaded only when their sha256 differs, root's ``mc`` admin alias and the
buckets are probed first (read-only) and written only when they differ, and
the Traefik route keeps its bcrypt hash while it still verifies. The data
directories get the role's owner recursively, but not its recursive mode
(``0750`` on every object file of the store). Credentials reach the host on
stdin only: the env file through ``secret_file``, the admin alias through
``mc alias import`` (the role's ``mc alias set`` puts them on a command line).

:func:`backup_account` is the role's ``tasks_from: backup_account``: one
scoped MinIO user per backup target, managed through root's admin alias.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from functools import cache, partial
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal

import jinja2
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Sha256File
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.base._common import ensure_curl
from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    http_check,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    wait_port,
)
from ops_deploy.helpers.probes import probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES, Hostname
from ops_deploy.ops import secret_file, secret_stdin

FILES = Path(__file__).parent / "files"
# Shared with echoport, whose cleanup alias has a scoped account of its own.
MC_ALIAS_PROBE = (FILES / "mc_alias_probe.py").read_text()
MINIO_ACCOUNT = (FILES / "minio_account.py").read_text()
BUCKET_PROBE = (FILES / "bucket_probe.py").read_text()

CONFIG_DIR = PurePosixPath("/etc/minio")
ENV_FILE = PurePosixPath("/etc/default/minio")
UNIT = "minio.service"
# The role's internal ranges (minio_internal_ip_ranges): the helper's default
# without the last one.
INTERNAL_IP_RANGES = DEFAULT_INTERNAL_IP_RANGES[:5]
# ``mc anonymous set`` values the pinned mc accepts and reports back unchanged.
# The role also lists readonly and writeonly, which that mc refuses.
AnonymousPolicy = Literal["private", "public"]

# Rendered into the env file (double quotes) and the unit: no whitespace, quotes,
# ``$``, backticks or backslashes.
_PATH = r"^/[A-Za-z0-9._/-]+$"
_UNSAFE_IN_ENV = ('"', "\\", "\r", "\n")
Release = Annotated[
    str, Field(pattern=r"^RELEASE\.[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z(\.hotfix\.[0-9a-f]+)?$")
]
Checksum = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
Url = Annotated[str, Field(pattern=r"^https?://[^\s'\"$`\\]+$")]
Alias = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$")]
BucketName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_-]*)*$")]
BindHost = Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]+$")]


def _posix_path(value: PurePosixPath) -> PurePosixPath:
    if not re.match(_PATH, str(value)) or ".." in value.parts or value == PurePosixPath("/"):
        raise ValueError("paths must be absolute, below /, without '..' and of letters, digits and ._/-")
    return value


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Bucket(_Part):
    """One entry of the role's ``minio_buckets``."""

    name: BucketName
    # ``mc version enable``; false leaves versioning as it is (the role never suspends it).
    versioning: bool = False
    # ``mc anonymous set``; None leaves anonymous access as it is.
    policy: AnonymousPolicy | None = None


class MinioConfig(BaseServiceConfig):
    """The role's variables without the ``minio_`` prefix (defaults from its defaults/main.yml)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = ("root_user", "root_password")

    service_name: ServiceName = "minio"
    user: UnixUser = "minio"
    group: UnixUser = "minio"
    home: PurePosixPath = PurePosixPath("/home/minio")
    # The role has no site; this is the home, the unit's WorkingDirectory.
    site_path: PurePosixPath = PurePosixPath("/home/minio")
    bin_path: PurePosixPath = PurePosixPath("/usr/local/bin/minio")

    version: Release = "RELEASE.2025-10-15T17-29-55Z.hotfix.c392ab039"
    checksum: Checksum = "sha256:2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4"
    # None: the role's minio_download_url for ``version`` (release or hotfix track).
    download_url: Url | None = None

    data_dirs: tuple[PurePosixPath, ...] = (PurePosixPath("/var/lib/minio/data"),)
    # Mount points that must be mounted before anything changes (ops-control's
    # encrypted volume, which its playbook prepares in a play of its own).
    required_mounts: tuple[PurePosixPath, ...] = ()
    # The playbook's port preflight on the API and console ports.
    port_preflight: bool = False

    bind_host: BindHost = "127.0.0.1"
    api_port: int = Field(default=9001, ge=1, le=65535)
    console_port: int = Field(default=9002, ge=1, le=65535)

    expose_via_traefik: bool = False
    traefik_host: Hostname = "minio.home.example.com"
    # None: ``s3.<traefik_host>``, the role's default.
    traefik_api_host: Hostname | None = None
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    console_basic_auth_enabled: bool = True
    console_basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"
    internal_ip_ranges: tuple[Annotated[str, Field(pattern=r"^[0-9A-Fa-f.:]+/[0-9]{1,3}$")], ...] = INTERNAL_IP_RANGES

    systemd_restart: Literal["no", "on-success", "on-failure", "on-abnormal", "on-watchdog", "on-abort", "always"] = (
        "always"
    )
    healthcheck_timeout: int = Field(default=30, ge=1, le=600)
    systemd_memory_max: Annotated[str, Field(pattern=r"^([0-9]+[KMGT]?|[0-9]{1,2}%|infinity)?$")] = ""
    systemd_limit_nofile: int = Field(default=65536, ge=1)
    systemd_tasks_max: Annotated[str, Field(pattern=r"^([0-9]+|[0-9]{1,2}%|infinity)$")] = "infinity"

    bootstrap_with_mc: bool = False
    mc_version: Release = "RELEASE.2025-08-13T08-35-41Z"
    mc_checksum: Checksum = "sha256:01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
    # None: the role's minio_mc_download_url for ``mc_version``.
    mc_download_url: Url | None = None
    mc_bin_path: PurePosixPath = PurePosixPath("/usr/local/bin/mc")
    # Root's admin alias (minio_host_alias), which the backup accounts and other
    # deploys (echoport, archive) use.
    host_alias: Alias = "local"
    buckets: tuple[Bucket, ...] = ()

    @field_validator("home", "site_path", "bin_path", "mc_bin_path", "data_dirs", "required_mounts")
    @classmethod
    def _paths(cls, value: Any) -> Any:
        for path in value if isinstance(value, tuple) else (value,):
            _posix_path(path)
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> MinioConfig:
        if not self.data_dirs:
            raise ValueError("data_dirs must name at least one directory")
        if self.site_path != self.home:
            raise ValueError("site_path is the home (the unit's WorkingDirectory)")
        if self.api_port == self.console_port:
            raise ValueError("api_port and console_port must differ")
        if self.expose_via_traefik and self.traefik_host == "minio.home.example.com":
            raise ValueError("expose_via_traefik requires traefik_host")
        if len({bucket.name for bucket in self.buckets}) != len(self.buckets):
            raise ValueError("bucket names must be unique")
        if self.buckets and not self.bootstrap_with_mc:
            raise ValueError("buckets are created by the bootstrap; set bootstrap_with_mc")
        return self

    @property
    def api_host(self) -> str:
        return self.traefik_api_host or f"s3.{self.traefik_host}"

    @property
    def url(self) -> str:
        return f"http://{self.bind_host}:{self.api_port}"

    @property
    def basic_auth(self) -> bool:
        return self.expose_via_traefik and self.console_basic_auth_enabled

    @property
    def binary_url(self) -> str:
        if self.download_url:
            return self.download_url
        track = "hotfixes" if ".hotfix." in self.version else "release"
        nested = "/archive" if track == "hotfixes" else ""
        return f"https://dl.min.io/server/minio/{track}/linux-amd64/archive{nested}/minio.{self.version}"

    @property
    def mc_url(self) -> str:
        return self.mc_download_url or f"https://dl.min.io/client/mc/release/linux-amd64/archive/mc.{self.mc_version}"


def check_secrets(cfg: MinioConfig, secrets: SecretValues) -> None:
    """The role's credential asserts, naming keys only."""

    secrets.require(cfg.required_secret_keys)
    watched = list(cfg.required_secret_keys)
    if cfg.basic_auth:
        secrets.require(("console_basic_auth_password",))
        watched.append("console_basic_auth_password")
    weak = [key for key in watched if secrets[key] in ("", "CHANGEME")]
    if weak:
        raise ValueError(f"secrets are empty or placeholders: {', '.join(weak)}")
    # The env file quotes them in double quotes; the admin alias needs one line.
    unsafe = [key for key in cfg.required_secret_keys if any(char in secrets[key] for char in _UNSAFE_IN_ENV)]
    if unsafe:
        raise ValueError(f"secrets must not contain double quotes, backslashes or line breaks: {', '.join(unsafe)}")


@cache
def _templates() -> jinja2.Environment:
    # The role's own templates, rendered with the options of Ansible's
    # template module and the filters the policy template uses.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.minio", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = bool
    return env


def role_vars(cfg: MinioConfig, secrets: SecretValues) -> dict[str, Any]:
    """The role's variables, as ``deploy-minio.yml`` sets them (TLS and SSE off)."""

    return {
        "minio_user": cfg.user,
        "minio_group": cfg.group,
        "minio_home": str(cfg.home),
        "minio_bin_path": str(cfg.bin_path),
        "minio_env_file": str(ENV_FILE),
        "minio_config_dir": str(CONFIG_DIR),
        "minio_certs_dir": str(CONFIG_DIR / "certs"),
        "minio_data_dirs": [str(path) for path in cfg.data_dirs],
        "minio_bind_host": cfg.bind_host,
        "minio_api_port": cfg.api_port,
        "minio_console_port": cfg.console_port,
        "minio_tls_enable": False,
        "minio_sse_enabled": False,
        "minio_sse_master_key": "",
        "minio_root_user": secrets.get("root_user", ""),
        "minio_root_password": secrets.get("root_password", ""),
        "minio_systemd_restart": cfg.systemd_restart,
        "minio_systemd_limit_nofile": cfg.systemd_limit_nofile,
        "minio_systemd_tasks_max": cfg.systemd_tasks_max,
        "minio_systemd_memory_max": cfg.systemd_memory_max,
        "minio_traefik_host": cfg.traefik_host,
        "minio_traefik_api_host": cfg.api_host,
        "minio_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "minio_console_basic_auth_enabled": cfg.console_basic_auth_enabled,
        "minio_console_basic_auth_user": cfg.console_basic_auth_user,
        "minio_internal_ip_ranges": list(cfg.internal_ip_ranges),
    }


def render_role(template: str, cfg: MinioConfig, secrets: SecretValues, **extra: Any) -> str:
    return _templates().get_template(template).render(**{**role_vars(cfg, secrets), **extra})


def render_env(cfg: MinioConfig, secrets: SecretValues) -> SecretContent:
    """``/etc/default/minio`` (the role's ``minio.env.j2``)."""

    return SecretContent(render_role("minio.env.j2", cfg, secrets))


def render_unit(cfg: MinioConfig, secrets: SecretValues) -> str:
    return render_role("minio.service.j2", cfg, secrets)


def render_route(cfg: MinioConfig, secrets: SecretValues, auth_hash: str | None) -> str:
    """The role's ``traefik-minio.yml.j2``, with the password hash the helper resolved."""

    return render_role("traefik-minio.yml.j2", cfg, secrets, minio_console_basic_auth_password_hash=auth_hash or "")


def traefik_config(cfg: MinioConfig, secrets: SecretValues) -> TraefikRoute:
    """The route's file (``minio.yml``) and basic auth; the template draws both routers."""

    auth = None
    if cfg.console_basic_auth_enabled:
        auth = BasicAuth(user=cfg.console_basic_auth_user, password=SecretStr(secrets["console_basic_auth_password"]))
    return TraefikRoute(
        name="minio",
        host=cfg.traefik_host,
        app_port=cfg.console_port,
        app_host=cfg.bind_host,
        basic_auth=auth,
        internal_ip_ranges=cfg.internal_ip_ranges,
        cert_resolver=cfg.traefik_cert_resolver,
    )


# -- host steps -----------------------------------------------------------------


def _mounts(cfg: MinioConfig) -> None:
    """The volume the encrypted-volume play opens and mounts must be mounted (read-only)."""

    for mount in cfg.required_mounts:
        path = shlex.quote(str(mount))
        missing = shlex.quote(
            f"{mount} is not mounted; prepare the encrypted volume (deploy-encrypted-volume.yml) first"
        )
        mark_read_only(
            server.shell(
                name=f"Require {mount} to be mounted",
                commands=[f"mountpoint -q {path} || {{ echo {missing} >&2; exit 1; }}"],
            )
        )


def _port_preflight(cfg: MinioConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but MinIO may listen on its two ports.

    Like ``common/preflight_ports.yml`` with ``bind: loopback`` and the owner
    ``minio.service``: a TCP listener on a port at a loopback or wildcard
    address fails the deploy unless every process behind it runs in
    ``minio.service``. Read-only; runs before any change.
    """

    ports = " ".join(str(port) for port in (cfg.api_port, cfg.console_port))
    script = (
        f"for port in {ports}; do "
        'out=$(ss -Hltnp "sport = :$port") || exit 1; '
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        'case "${local%:*}" in 127.0.0.1|0.0.0.0|"[::1]"|"[::]"|"*"|"[::ffff:127.0.0.1]") ;; *) continue ;; esac; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        f"grep -qx '0::/system.slice/{UNIT}' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        '[ "$bad" = 0 ] || echo "port in use: $local $users" >&2; '
        'done; [ "$bad" = 0 ]; } || exit 1; done'
    )
    return mark_read_only(
        server.shell(
            name=f"Port preflight tcp/{cfg.api_port} tcp/{cfg.console_port}", commands=[f"sh -c {shlex.quote(script)}"]
        )
    )


def _data_dir(cfg: MinioConfig, path: PurePosixPath) -> None:
    """The role's data directory, owned by MinIO all the way down.

    The role's ``file`` with ``recurse`` also sets ``0750`` on every file below;
    MinIO writes objects ``0644``, so that rewrites the modes of every object
    added since the last run. Only the directory itself gets the mode here;
    ownership is set recursively, and only when something below has another
    owner or group.
    """

    files.directory(
        name=f"Create MinIO data directory {path}", path=str(path), user=cfg.user, group=cfg.group, mode="0750"
    )
    quoted = shlex.quote(str(path))
    # MinIO creates and removes temporary files below the data directory all
    # the time; one that vanishes during the walk is not an error.
    find = (
        f"find {quoted} -ignore_readdir_race ! -user {cfg.user} -printf x -quit -o ! -group {cfg.group} -printf x -quit"
    )
    # Before the user exists (a first deploy over kept data) everything needs it.
    check = when_present([path], f"if id -u {cfg.user} >/dev/null 2>&1; then {find}; else echo x; fi", otherwise="")
    found = probe(check, name=f"ownership below {path}")
    server.shell(
        name=f"Set ownership below {path}",
        commands=[f"chown -R {cfg.user}:{cfg.group} {quoted}"],
        _if=lambda: found is None or bool(found.strip()),
    )
    if found is None:
        verify_probe(check, name=f"ownership below {path}", expect="")


def _binary(name: str, url: str, checksum: str, dest: PurePosixPath) -> OperationMeta:
    """``get_url`` with a checksum: download only when ``dest`` has another sha256.

    The download is checked before it replaces ``dest``; it is staged next to
    it and renamed over it, so a running binary is never half-written. Owner
    and mode are reconciled either way, as ``get_url`` does.
    """

    sha256 = checksum.removeprefix("sha256:")
    current = host.get_fact(Sha256File, path=str(dest))
    if current != sha256:
        ensure_curl(f"minio ({name})")
    staged = shlex.quote(str(dest.with_name(f".{dest.name}.ops-deploy-new")))
    script = (
        "set -e; tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; "
        f'curl -fsSL --max-time 900 -o "$tmp/download" {shlex.quote(url)}; '
        f"echo {sha256}'  '\"$tmp/download\" | sha256sum -c --quiet -; "
        f'install -o root -g root -m 0755 "$tmp/download" {staged}; '
        f"mv -f {staged} {shlex.quote(str(dest))}"
    )
    installed = server.shell(name=f"Install {name} {dest}", commands=[script], _if=lambda: current != sha256)
    files.file(
        name=f"Set owner and mode of {dest}", path=str(dest), user="root", group="root", mode="0755", touch=False
    )
    return installed


def _alias_digest(url: str, access_key: str, secret_key: str) -> str:
    return hashlib.sha256("\n".join((url, access_key, secret_key)).encode()).hexdigest()


def _alias_listing(mc: PurePosixPath, alias: str, run_as: tuple[str, PurePosixPath] | None = None) -> str:
    """Strict probe: a digest of ``alias``'s stored URL and credentials, or ``none``."""

    argv = [str(mc), "--json", "alias", "list", alias]
    command = _as_user(*run_as, {}, argv) if run_as else shlex.join(argv)
    # mc reports a missing alias as JSON, which the probe reads as "none"; any
    # other failure of mc fails the probe.
    return f'out=$( {command} ); rc=$?; printf \'%s\\n\' "$out" | python3 -I -c {shlex.quote(MC_ALIAS_PROBE)} "$rc"'


def _admin_alias(cfg: MinioConfig, secrets: SecretValues) -> OperationMeta:
    """Root's admin alias (``mc alias set`` in the role), imported when it differs."""

    alias = cfg.host_alias
    wanted = {
        "url": cfg.url,
        "accessKey": secrets["root_user"],
        "secretKey": secrets["root_password"],
        "api": "s3v4",
        "path": "auto",
    }
    digest = _alias_digest(cfg.url, secrets["root_user"], secrets["root_password"])
    check = when_present([cfg.mc_bin_path], _alias_listing(cfg.mc_bin_path, alias), otherwise="none")
    stored = probe(check, name=f"mc alias {alias} of root")
    failed = shlex.quote(f"mc alias import {alias} failed; mc output is withheld (it can quote the credentials)")
    imported = secret_stdin(
        name=f"Configure root's mc alias {alias}",
        # ``alias import`` reads the JSON on stdin; ``alias set`` would put the
        # credentials in the host's process list.
        command=f"{shlex.join([str(cfg.mc_bin_path), 'alias', 'import', alias])} >/dev/null 2>&1 || "
        f"{{ echo {failed} >&2; exit 1; }}",
        content=SecretContent(json.dumps(wanted) + "\n"),
        _if=lambda: (stored or "").strip() != digest,
    )
    if stored is None:
        verify_probe(check, name=f"mc alias {alias} of root")
    return imported


def _buckets(cfg: MinioConfig) -> None:
    """The role's ``mc mb``, ``mc version enable`` and ``mc anonymous set`` per bucket, where needed."""

    mc, alias = str(cfg.mc_bin_path), cfg.host_alias
    spec = json.dumps(
        [{"name": b.name, "versioning": b.versioning, "anonymous": b.policy} for b in cfg.buckets],
        separators=(",", ":"),
    )
    check = when_present(
        [cfg.mc_bin_path], shlex.join(["python3", "-I", "-c", BUCKET_PROBE, mc, alias, spec]), otherwise="absent"
    )
    found = probe(check, name="MinIO buckets")
    absent = found is not None and found.strip() == "absent"
    try:
        parsed = None if found is None or absent else json.loads(found)
    except ValueError:
        parsed = None
    # Before mc is installed (or when the probe failed) every step runs; each
    # is idempotent (``mb --ignore-existing``). After a failed probe it runs
    # again after them.
    failed = not absent and not isinstance(parsed, dict)
    needed: dict[str, list[str]] = (
        parsed if isinstance(parsed, dict) else {b.name: ["mb", "version", "anonymous"] for b in cfg.buckets}
    )

    def wanted(bucket: str, step: str) -> bool:
        return step in needed.get(bucket, [])

    for bucket in cfg.buckets:
        target = f"{alias}/{bucket.name}"
        server.shell(
            name=f"Create MinIO bucket {bucket.name}",
            commands=[shlex.join([mc, "mb", target, "--ignore-existing"])],
            _if=partial(wanted, bucket.name, "mb"),
        )
        if bucket.versioning:
            server.shell(
                name=f"Enable versioning on MinIO bucket {bucket.name}",
                commands=[shlex.join([mc, "version", "enable", target])],
                _if=partial(wanted, bucket.name, "version"),
            )
        if bucket.policy is not None:
            server.shell(
                name=f"Set anonymous access {bucket.policy} on MinIO bucket {bucket.name}",
                commands=[shlex.join([mc, "anonymous", "set", bucket.policy, target])],
                _if=partial(wanted, bucket.name, "anonymous"),
            )
    if failed:
        verify_probe(check, name="MinIO buckets", expect="{}")


def _verify(cfg: MinioConfig) -> None:
    """The rest of the role's verify.yml: the admin alias and the buckets."""

    mc, alias = str(cfg.mc_bin_path), cfg.host_alias
    mark_read_only(
        server.shell(
            name=f"Verify mc alias {alias}",
            # Its output carries the secret key.
            commands=[f"{shlex.join([mc, 'alias', 'list', alias])} >/dev/null"],
        )
    )
    for bucket in cfg.buckets:
        mark_read_only(
            server.shell(
                name=f"Verify MinIO bucket {bucket.name}",
                commands=[f"{shlex.join([mc, 'ls', f'{alias}/{bucket.name}'])} >/dev/null"],
            )
        )


@deploy("Deploy minio")
def deploy_minio(cfg: MinioConfig, secrets: SecretValues) -> None:
    check_secrets(cfg, secrets)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg, secrets) if cfg.expose_via_traefik else None

    _mounts(cfg)
    if cfg.port_preflight:
        _port_preflight(cfg)

    system_user(cfg.user, group=cfg.group, home=cfg.home, shell="/usr/sbin/nologin", mode="0750")
    files.directory(name=f"Create {CONFIG_DIR}", path=str(CONFIG_DIR), user="root", group="root", mode="0755")
    for path in cfg.data_dirs:
        _data_dir(cfg, path)

    binary = _binary("MinIO", cfg.binary_url, cfg.checksum, cfg.bin_path)
    env = secret_file(
        name=f"Write {ENV_FILE}", path=ENV_FILE, content=env_content, mode="0600", user="root", group="root"
    )
    unit = systemd_unit(UNIT, render_unit(cfg, secrets))
    service_rollout(UNIT, units=[unit], restart_when=[binary, env])
    wait_port(cfg.api_port, host=cfg.bind_host, retries=cfg.healthcheck_timeout, name="Wait for the MinIO API port")
    wait_port(
        cfg.console_port, host=cfg.bind_host, retries=cfg.healthcheck_timeout, name="Wait for the MinIO console port"
    )
    # The role checks health last; the bootstrap below needs a MinIO that
    # answers (it may have been restarted just now, the role's handler only
    # restarts at the end).
    http_check(f"{cfg.url}/minio/health/live", retries=4, delay=5, name="Check MinIO health endpoint")

    if route is not None:
        # Traefik watches its dynamic directory; the role does not restart it.
        traefik_route(route, renderer=lambda _route, auth_hash: render_route(cfg, secrets, auth_hash), restart="none")

    if cfg.bootstrap_with_mc:
        _binary("mc", cfg.mc_url, cfg.mc_checksum, cfg.mc_bin_path)
        _admin_alias(cfg, secrets)
        _buckets(cfg)
        _verify(cfg)


# -- tasks_from: backup_account ---------------------------------------------------


class RunnerAlias(_Part):
    """The backup runner's ``mc`` alias for the account.

    ``common/backup_minio_account.yml`` imports it right after the account
    (``echoport_backup``'s ``tasks_from: minio_alias``). Here it also proves
    the account's secret: while the stored alias holds the configured secret
    and can list the account's keys with it, MinIO has that secret and the
    upsert is skipped.
    """

    name: Alias
    os_user: UnixUser = "root"
    home: PurePosixPath = PurePosixPath("/root")
    url: Url = "http://127.0.0.1:9001"

    @field_validator("home")
    @classmethod
    def _home(cls, value: PurePosixPath) -> PurePosixPath:
        return _posix_path(value)


class BackupAccount(_Part):
    """``minio_backup_account_*`` of the role's ``tasks_from: backup_account``.

    One MinIO user, ``bk-`` + 17 hex digits of the SHA-256 of ``name`` (MinIO
    allows 20 characters), that holds exactly the policy ``backup-<name>``:
    read, write and list below ``<bucket>/<prefix>/`` (or the whole bucket),
    never the admin API.
    """

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]
    bucket: BucketName = "backups"
    # Empty: the name, as the role's default ``[minio_backup_account_name]``.
    prefixes: tuple[Prefix, ...] = ()
    allow_put: bool = True
    allow_delete: bool = False
    whole_bucket: bool = False
    mc: PurePosixPath = PurePosixPath("/usr/local/bin/mc")
    admin_alias: Alias = "local"
    policy_dir: PurePosixPath = PurePosixPath("/etc/minio/policies")
    alias: RunnerAlias | None = None

    @field_validator("mc", "policy_dir")
    @classmethod
    def _path(cls, value: PurePosixPath) -> PurePosixPath:
        return _posix_path(value)

    @model_validator(mode="after")
    def _alias_is_not_the_admin_alias(self) -> BackupAccount:
        if self.alias is not None and self.alias.os_user == "root" and self.alias.name == self.admin_alias:
            raise ValueError("the runner alias must not be root's admin alias")
        return self

    @property
    def key_prefixes(self) -> tuple[str, ...]:
        return self.prefixes or (self.name,)

    @property
    def user(self) -> str:
        return "bk-" + hashlib.sha256(self.name.encode()).hexdigest()[:17]

    @property
    def policy(self) -> str:
        return f"backup-{self.name}"

    @property
    def policy_path(self) -> PurePosixPath:
        return self.policy_dir / f"{self.policy}.json"

    @property
    def listing(self) -> str:
        """What the account can list: its first prefix, or the whole bucket."""

        return self.bucket if self.whole_bucket else f"{self.bucket}/{self.key_prefixes[0]}/"


def render_policy(account: BackupAccount) -> str:
    """The account's policy (the role's ``backup-account-policy.json.j2``)."""

    return (
        _templates()
        .get_template("backup-account-policy.json.j2")
        .render(
            minio_backup_account_bucket=account.bucket,
            minio_backup_account_prefixes=list(account.key_prefixes),
            minio_backup_account_whole_bucket=account.whole_bucket,
            minio_backup_account_allow_put=account.allow_put,
            minio_backup_account_allow_delete=account.allow_delete,
        )
    )


def check_account_secret(secret: SecretStr) -> None:
    """The role's input check of the secret key; the value is never printed."""

    value = secret.get_secret_value()
    if not 32 <= len(value) <= 40 or value == "CHANGEME":
        raise ValueError("the backup account's secret key must be 32 to 40 characters and not CHANGEME")
    if "\r" in value or "\n" in value:
        raise ValueError("the backup account's secret key must be one line")


def backup_account(account: BackupAccount, secret: SecretStr) -> None:
    """Create or update ``account`` (the role's ``tasks_from: backup_account``) and its runner alias.

    Everything goes through root's admin alias (``account.admin_alias``) and
    the secret reaches ``mc`` on stdin. A read-only probe (the secret is not an
    argument) decides: the policy is created when its file changed or the
    server's copy is missing or differs, the user is attached when it does not
    hold the policy. ``mc admin user add`` (an upsert) runs when the user is
    missing or, as in the role, on every run unless ``account.alias`` proves
    the secret. A read-only check at the end is the role's last assert.
    """

    check_account_secret(secret)
    value = secret.get_secret_value()
    mc, admin = str(account.mc), account.admin_alias
    document = render_policy(account)

    def script(mode: str) -> str:
        return shlex.join(
            ["python3", "-I", "-c", MINIO_ACCOUNT, mode, mc, admin, account.policy, account.user, document]
        )

    state = probe(script("probe"), name=f"MinIO account {account.name}")
    found = dict(part.partition("=")[::2] for part in (state or "").split())
    runner = account.alias
    proven, stored, wanted = False, "", ""
    if runner is not None:
        run_as = (runner.os_user, runner.home)
        listing = when_present([runner.home], _alias_listing(account.mc, runner.name, run_as), otherwise="none")
        # A failed probe reads as a different alias: it is imported, then proven below.
        stored = (probe(listing, name=f"mc alias {runner.name} of {runner.os_user}") or "").strip()
        wanted = _alias_digest(runner.url, account.user, value)
        login = when_present([runner.home], f"{_runner_ls(account, runner)} >/dev/null && echo ok", otherwise="no")
        reachable = str(host.get_fact(Command, command=f"{login} 2>/dev/null || true") or "").strip() == "ok"
        proven = stored == wanted and reachable

    missing = shlex.quote(
        f"mc admin info {admin} failed: the admin alias is not configured for root on this host "
        "or MinIO is unreachable. Deploy MinIO with bootstrap_with_mc first."
    )
    mark_read_only(
        server.shell(
            name=f"Require the MinIO admin alias {admin} of root",
            commands=[f"{shlex.join([mc, 'admin', 'info', admin])} >/dev/null || {{ echo {missing} >&2; exit 1; }}"],
        )
    )
    files.directory(
        name="Create MinIO policy directory", path=str(account.policy_dir), user="root", group="root", mode="0750"
    )
    policy_file = files.put(
        name=f"Install MinIO policy {account.policy}",
        src=StringIO(document),
        dest=str(account.policy_path),
        user="root",
        group="root",
        mode="0640",
    )
    server.shell(
        name=f"Create or update MinIO policy {account.policy}",
        commands=[shlex.join([mc, "admin", "policy", "create", admin, account.policy, str(account.policy_path)])],
        _if=lambda: policy_file.did_change() or found.get("policy") != "ok",
    )
    failed = shlex.quote(
        f"mc admin user add for {account.user} failed; mc output is withheld (it can quote the secret)"
    )
    add = shlex.join([mc, "admin", "user", "add", admin])
    secret_stdin(
        name=f"Create or update MinIO user of {account.name}",
        # ``mc admin user add`` is an upsert; it reads the user and the secret from stdin.
        command=f"{add} >/dev/null 2>&1 || {{ echo {failed} >&2; exit 1; }}",
        content=SecretContent(f"{account.user}\n{value}\n"),
        _if=lambda: found.get("user") not in ("attached", "unattached") or not proven,
    )
    server.shell(
        name=f"Attach MinIO policy {account.policy}",
        commands=[shlex.join([mc, "admin", "policy", "attach", admin, account.policy, "--user", account.user])],
        _if=lambda: found.get("user") != "attached",
    )
    if runner is not None:
        _runner_alias(account, runner, value, stored, wanted)
    mark_read_only(server.shell(name=f"Verify MinIO account {account.name}", commands=[script("verify")]))


def _runner_ls(account: BackupAccount, runner: RunnerAlias) -> str:
    """``mc ls`` of what the account may list, as the runner with its alias."""

    argv = [str(account.mc), "ls", f"{runner.name}/{account.listing}"]
    return _as_user(runner.os_user, runner.home, {}, argv)


def _runner_alias(account: BackupAccount, runner: RunnerAlias, secret: str, stored: str, wanted: str) -> None:
    """The runner's alias, imported when it differs; then proof it reaches the account's keys."""

    alias = {"url": runner.url, "accessKey": account.user, "secretKey": secret, "api": "s3v4", "path": "auto"}
    mc_import = _as_user(runner.os_user, runner.home, {}, [str(account.mc), "alias", "import", runner.name])
    failed = shlex.quote(f"mc alias import {runner.name} failed for {runner.os_user}; mc output is withheld")
    # ``alias import`` opens its file itself; the user cannot reopen the
    # root-owned pipe on stdin, so the JSON goes through a private file in a
    # root-owned directory (nothing in it can be swapped for a link), removed
    # right after.
    script = (
        "set -e; d=$(mktemp -d); trap 'rm -rf \"$d\"' EXIT; "
        'chmod 0711 "$d"; umask 077; '
        f'cat > "$d/alias.json"; chown {runner.os_user} "$d/alias.json"; '
        f'{mc_import} "$d/alias.json" >/dev/null 2>&1 || {{ echo {failed} >&2; exit 1; }}'
    )
    secret_stdin(
        name=f"Configure mc alias {runner.name} of {runner.os_user}",
        # Not ``alias set``, which would put the credentials in the host's process list.
        command=script,
        content=SecretContent(json.dumps(alias)),
        _if=lambda: stored != wanted,
    )
    mark_read_only(
        server.shell(
            name=f"Verify mc alias {runner.name} reaches {account.listing}",
            commands=[f"{_runner_ls(account, runner)} >/dev/null"],
        )
    )


@deploy("Deploy MinIO backup account")
def deploy_backup_account(account: BackupAccount, secret: SecretStr) -> None:
    """:func:`backup_account` on its own, for a play on the MinIO host."""

    backup_account(account, secret)
