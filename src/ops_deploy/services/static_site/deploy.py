"""static_site: a generated, read-only site served by a tiny stdlib HTTP server.

Port of the ``static_site_deploy`` Ansible role. The controller validates the
publication source (regular files only, no symlinks, optional exact file
allowlist), syncs it to the host, and the host serves it from a hardened
systemd unit on loopback behind a Traefik route. The unit, the server script
and the route are byte-identical to the role's
(``tests/test_static_site_parity.py``), so Ansible and ops-deploy can take
turns on one host.

The HTTP server is the role's Python script or the pinned Rust
``metrics-httpd static`` (``httpd_impl``; the role's ``metrics_httpd_switch``,
see :mod:`ops_deploy.services._metrics_httpd`).
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Users
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.templates import render
from ops_deploy.helpers import TraefikRoute, mark_read_only, service_rollout, systemd_unit, traefik_route
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.ops import sync_tree
from ops_deploy.services import _metrics_httpd as metrics_httpd

TEMPLATE_PACKAGE = "ops_deploy.services.static_site"

SAFE_PATH = r"^/[A-Za-z0-9_./-]+$"
Token = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]


class StaticSiteSourceError(ValueError):
    """The publication source on the controller is missing or unsafe."""


class StaticSiteConfig(BaseServiceConfig, metrics_httpd.HttpdSwitchFields):
    """The ``static_site_deploy`` role's variables; ``httpd_*`` select its HTTP server (``static_site_impl``)."""

    # The role's defaults all follow ``service_name``: user, group, document
    # root and server script are filled in from it when not given.
    service_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")] = "static-site"
    user: UnixUser = "static-site"
    group: UnixUser | None = None
    # The document root on the host (the role's static_site_path).
    site_path: PurePosixPath = PurePosixPath("/srv/static-sites/static-site")
    # The generated site on the controller.
    source_path: Path
    required_files: tuple[Token, ...] = Field(default=("index.html", "report.md", "snapshot.json"), min_length=1)
    restrict_to_required_files: bool = False
    rsync_delete: bool = True
    # Readable by root and the service group only (0750/0640 instead of 0755/0644).
    private: bool = False
    python_path: PurePosixPath = PurePosixPath("/usr/bin/python3")
    server_path: PurePosixPath = PurePosixPath("/usr/local/libexec/static-site-httpd.py")
    bind_host: Literal["127.0.0.1"] = "127.0.0.1"
    port: int = Field(default=10061, ge=1024, le=65535)
    healthcheck_contains: str = ""
    traefik_enabled: bool = True
    traefik_host: Hostname | None = None
    traefik_entrypoints: tuple[Token, ...] = Field(default=("web-secure",), min_length=1)
    traefik_http_entrypoint: Token = "web"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    # When non-empty, an ipAllowList guards both routers (403 before any redirect).
    traefik_allowed_networks: tuple[str, ...] = ()
    verify_public: bool = False
    public_healthcheck_retries: int = Field(default=20, ge=1)
    public_healthcheck_delay: int = Field(default=3, ge=0)

    @model_validator(mode="before")
    @classmethod
    def _defaults_follow_service_name(cls, data: Any) -> Any:
        if isinstance(data, dict):
            name = data.get("service_name", "static-site")
            if isinstance(name, str):
                defaults = {
                    "user": name,
                    "site_path": f"/srv/static-sites/{name}",
                    "server_path": f"/usr/local/libexec/{name}-httpd.py",
                }
                return {**defaults, **data}
        return data

    @field_validator("site_path", "python_path", "server_path")
    @classmethod
    def _safe_path(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute() or ".." in value.parts or not re.match(SAFE_PATH, str(value)):
            raise ValueError("paths must be absolute and use only letters, digits, _ . / and -")
        return value

    @field_validator("source_path")
    @classmethod
    def _source_is_absolute(cls, value: Path) -> Path:
        # An absolute path of safe characters, as the role demands of it.
        if not value.is_absolute() or value == Path("/") or not re.match(SAFE_PATH, str(value)):
            raise ValueError("source_path must be an absolute path of letters, digits, _ . / and -, not /")
        return value

    @field_validator("traefik_allowed_networks")
    @classmethod
    def _cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            # Go's net.ParseCIDR (Traefik): a decimal prefix length, no scope, no host bits.
            address, _, prefix = item.partition("/")
            if item != item.strip() or item.count("/") != 1 or not (prefix.isascii() and prefix.isdigit()):
                raise ValueError("traefik_allowed_networks entries must be CIDR ranges")
            if "%" in address:
                raise ValueError("traefik_allowed_networks entries must be CIDR ranges")
            try:
                ipaddress.ip_network(item, strict=True)
            except ValueError:
                raise ValueError("traefik_allowed_networks entries must be CIDR ranges") from None
        return value

    @model_validator(mode="after")
    def _consistent(self) -> StaticSiteConfig:
        if self.traefik_enabled:
            if self.traefik_host is None or self.traefik_host == "static.example.com":
                raise ValueError("traefik_host must be a real hostname while traefik is enabled")
            if self.traefik_http_entrypoint in self.traefik_entrypoints:
                raise ValueError("traefik_http_entrypoint must not be one of traefik_entrypoints")
        return self

    @property
    def group_name(self) -> str:
        return self.group or self.user

    @property
    def allowed_networks_json(self) -> str:
        return json.dumps(list(self.traefik_allowed_networks))

    @property
    def dir_mode(self) -> str:
        return "0750" if self.private else "0755"

    @property
    def file_mode(self) -> str:
        return "0640" if self.private else "0644"


def validate_source(cfg: StaticSiteConfig) -> None:
    """The role's ``validate.yml`` checks of the controller-side source.

    A real directory, the required files as regular files, no symlinks, no
    special files; with ``restrict_to_required_files`` exactly the required
    files and nothing nested.
    """

    root = cfg.source_path
    if not root.is_dir() or root.is_symlink():
        raise StaticSiteSourceError(f"Static site source is missing, not a directory, or a symlink: {root}")
    for name in cfg.required_files:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise StaticSiteSourceError(f"Required static publication file is missing or unsafe: {name}")

    links = specials = 0
    files_found: list[Path] = []
    directories: list[Path] = []
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                if entry.is_symlink():
                    links += 1
                elif entry.is_dir(follow_symlinks=False):
                    directories.append(Path(entry.path))
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    files_found.append(Path(entry.path))
                else:
                    specials += 1
    if links:
        raise StaticSiteSourceError(
            "Static publication source contains symbolic links; refusing to follow or publish them."
        )
    if specials:
        raise StaticSiteSourceError(
            "Static publication source contains a socket, FIFO, device, or another unsupported entry; "
            "only regular files and directories are accepted."
        )
    if cfg.restrict_to_required_files and (
        directories
        or len(files_found) != len(cfg.required_files)
        or {path.name for path in files_found} - set(cfg.required_files)
    ):
        raise StaticSiteSourceError(
            "Strict static publication accepts only the configured required regular files at the source root; "
            "nested directories and extra files are refused."
        )


def render_server(cfg: StaticSiteConfig) -> str:
    return render(TEMPLATE_PACKAGE, "static-site-httpd.py.j2", cfg=cfg)


def render_unit(cfg: StaticSiteConfig) -> str:
    return render(TEMPLATE_PACKAGE, "static-site.service.j2", cfg=cfg)


def render_route(cfg: StaticSiteConfig) -> str:
    return render(TEMPLATE_PACKAGE, "static-site.traefik.yml.j2", cfg=cfg)


# The unit's [Service] lines besides Type, User, Group, ExecStart, Restart and
# RestartSec (templates/static-site.service.j2): the --check-config sandbox.
UNIT_SANDBOX = (
    "UMask=0027",
    "TasksMax=128",
    "MemoryMax=256M",
    "NoNewPrivileges=true",
    "PrivateDevices=true",
    "PrivateTmp=true",
    "ProtectClock=true",
    "ProtectControlGroups=true",
    "ProtectHome=true",
    "ProtectHostname=true",
    "ProtectKernelLogs=true",
    "ProtectKernelModules=true",
    "ProtectKernelTunables=true",
    "ProtectSystem=strict",
    "RestrictAddressFamilies=AF_UNIX AF_INET",
    "RestrictNamespaces=true",
    "RestrictRealtime=true",
    "RestrictSUIDSGID=true",
    "LockPersonality=true",
    "MemoryDenyWriteExecute=true",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
)


def httpd_endpoint(cfg: StaticSiteConfig) -> metrics_httpd.Endpoint:
    """The role's ``metrics_httpd_switch`` inputs: ``static --bind --port --root`` in the unit's sandbox."""

    return metrics_httpd.Endpoint(
        service_name=cfg.service_name,
        argv=("static", "--bind", cfg.bind_host, "--port", str(cfg.port), "--root", str(cfg.site_path)),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=(*UNIT_SANDBOX, f"ReadOnlyPaths={cfg.site_path}"),
        python_script=str(cfg.server_path),
        probe_bind=cfg.bind_host,
        probe_port=cfg.port,
        probe_path="/",
        probe_expect="static",
    )


def _service_account(cfg: StaticSiteConfig) -> None:
    """The role's user.yml: a system group and a no-login system user without a home directory.

    As in the role the home is the distribution default (``/home/<user>``) and
    is not created. An existing user is left alone apart from a warning.
    """

    group = cfg.group_name
    server.group(name=f"Ensure group {group}", group=group, system=True)
    existing = host.get_fact(Users).get(cfg.user)
    if existing is None:
        server.user(
            name=f"Ensure user {cfg.user}",
            user=cfg.user,
            group=group,
            home=f"/home/{cfg.user}",
            shell="/usr/sbin/nologin",
            system=True,
            ensure_home=False,
            create_home=False,
        )
    elif existing.get("group") != group or existing.get("shell") != "/usr/sbin/nologin":
        logger.warning(f"{host.name}: existing user {cfg.user} differs from the service account; left unchanged")


def _probe(cfg: StaticSiteConfig, url: str, *, retries: int, delay: int, label: str) -> OperationMeta:
    """Poll ``url`` on the target until it answers 200, then look for the health-check marker."""

    curl = "curl -sSL --max-redirs 10 --max-time 10 -o \"$body\" -w '%{http_code}'"
    marker = ""
    if cfg.healthcheck_contains:
        probe = "import sys; sys.exit(0 if sys.argv[2] in open(sys.argv[1], errors='replace').read() else 1)"
        marker = (
            f'python3 -c {shlex.quote(probe)} "$body" {shlex.quote(cfg.healthcheck_contains)} || '
            f"{{ echo {shlex.quote(label + ' did not contain the configured health-check marker.')} >&2; exit 1; }}"
        )
    script = (
        "body=$(mktemp) || exit 1; trap 'rm -f \"$body\"' EXIT; code=; "
        f"for i in $(seq 1 {retries}); do "
        f"code=$({curl} {shlex.quote(url)} 2>/dev/null); "
        f'[ "$code" = 200 ] && break; sleep {delay}; done; '
        f'[ "$code" = 200 ] || {{ echo "{label} answered ${{code:-nothing}}, expected 200" >&2; exit 1; }}; '
        f"{marker}"
    )
    return mark_read_only(server.shell(name=f"Check {label}", commands=[f"bash -c {shlex.quote(script)}"]))


def _private_modes_check(cfg: StaticSiteConfig) -> OperationMeta:
    script = (
        f"bad=$(find {shlex.quote(str(cfg.site_path))} -perm /o=rwx) || exit 1; "
        '[ -z "$bad" ] || { echo "Private static site has entries accessible to others:" >&2; '
        'echo "$bad" >&2; exit 1; }'
    )
    return mark_read_only(
        server.shell(name="Check private publication modes", commands=[f"bash -c {shlex.quote(script)}"])
    )


@deploy("Deploy static site")
def deploy_static_site(cfg: StaticSiteConfig, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    validate_source(cfg)
    group = cfg.group_name

    # Like the role (``synchronize``), this needs rsync on the host already: the
    # content sync plans against the host, so an install here would come too late.
    _service_account(cfg)
    for parent in dict.fromkeys((cfg.site_path.parent, cfg.server_path.parent)):
        files.directory(name=f"Ensure directory {parent}", path=str(parent), user="root", group="root", mode="0755")
    files.directory(
        name=f"Ensure document root {cfg.site_path}",
        path=str(cfg.site_path),
        user="root",
        group=group,
        mode=cfg.dir_mode,
    )

    # Root-owned and service-readable: group = the service group, modes as the role's rsync demands.
    sync_tree(
        name="Publish site content",
        src=cfg.source_path,
        dest=cfg.site_path,
        user="root",
        group=group,
        delete=cfg.rsync_delete,
        chmod=f"D{cfg.dir_mode},F{cfg.file_mode}",
        runner=rsync,
    )

    server_script = files.put(
        name="Install static HTTP server",
        src=io.StringIO(render_server(cfg)),
        dest=str(cfg.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    unit = systemd_unit(cfg.service_name, render_unit(cfg))
    # Python or the pinned Rust metrics-httpd (drop-in metrics-httpd-impl.conf).
    selection = metrics_httpd.select(httpd_endpoint(cfg), cfg)
    if cfg.traefik_enabled:
        assert cfg.traefik_host is not None
        route = TraefikRoute(
            name=cfg.service_name,
            host=cfg.traefik_host,
            app_port=cfg.port,
            app_host=cfg.bind_host,
            cert_resolver=cfg.traefik_cert_resolver,
        )
        # The role has no reload handler for the route; the file provider watches the directory.
        traefik_route(route, renderer=lambda _route, _hash: render_route(cfg), restart="none")
    service_rollout(cfg.service_name, units=[unit, selection.dropin], restart_when=[server_script])
    # The unit runs the selected server and answers 200 for /; then pin and prune.
    metrics_httpd.verify(selection)

    _probe(cfg, f"http://{cfg.bind_host}:{cfg.port}/", retries=10, delay=1, label="loopback static service")
    if cfg.traefik_enabled and cfg.verify_public:
        _probe(
            cfg,
            f"https://{cfg.traefik_host}/",
            retries=cfg.public_healthcheck_retries,
            delay=cfg.public_healthcheck_delay,
            label="public HTTPS route",
        )
    if cfg.private:
        _private_modes_check(cfg)
