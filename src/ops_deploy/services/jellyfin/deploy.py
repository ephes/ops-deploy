"""jellyfin: the Jellyfin media server from its upstream apt repository, behind Traefik.

Port of the ``jellyfin_deploy`` Ansible role (with its ``jellyfin_shared``
defaults). Deploy only: backup, restore and remove stay with the Ansible
roles. The role's Traefik template is shipped unchanged and rendered the way
Ansible's ``template`` module renders it, so the route is byte-identical to
the role's (``tests/test_jellyfin_parity.py``), and the deployed bcrypt hash
is kept while it still matches the password, as the role does since
ops-library 2.49.1. Jellyfin itself is never restarted (the role has no task
that notifies its restart handler) and Traefik neither (its file provider
watches the directory).

Unlike the role, nothing runs that would change nothing: the repository key
is downloaded only while the keyring is missing or ASCII-armored (the role
downloads it on every run), the apt cache is refreshed only before an
install or after a repository change, and the jellyfin-ffmpeg candidate is
picked while planning (or, when this run configures the repository, by the
install step itself). The repository's distribution, release and
architecture are configuration, not facts: the deploy refuses a host whose
os-release or architecture says otherwise.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
from functools import cache
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any

import jinja2
import yaml
from pydantic import AfterValidator, Field, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Sha1File
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import RoleConfig, output, require_linux
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers import BasicAuth, TraefikRoute, http_check, mark_read_only, traefik_route, wait_port
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.services.compose_app.config import plain_path

TEMPLATE_PACKAGE = "ops_deploy.services.jellyfin"
TEMPLATE = "jellyfin-traefik.yml.j2"
ROUTE_NAME = "jellyfin"
PLACEHOLDER = "CHANGEME"

# jellyfin_shared/defaults/main.yml
ROLE_MEDIA_DIRECTORIES = (
    "/mnt/cryptdata/media/video/movies",
    "/mnt/cryptdata/media/video/tv",
    "/mnt/cryptdata/media/video/youtube",
)
ROLE_INTERNAL_IP_RANGES = ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10", "fd7a:115c:a1e0::/48")
# The role's ``jellyfin_repo_family_map`` (keyed by os-release ID, which is
# Ansible's distribution in lower case for these two) and its fallback.
REPO_FAMILY = {"debian": "debian", "ubuntu": "ubuntu"}
REPO_FAMILY_DEFAULT = "debian"
# The role's ``jellyfin_repo_arch_map`` (keyed by ``uname -m``) and its fallback.
REPO_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
REPO_ARCH_DEFAULT = "amd64"
# The role's ffmpeg pick: the first candidate whose ``apt-cache policy`` has a candidate version.
_CANDIDATE = re.compile(r"Candidate:\s+(?!\(none\))")
# What counts as an installed bundled ffmpeg: any jellyfin-ffmpeg package (the
# jellyfin package depends on one, and the newer ones conflict with the older).
_FFMPEG = re.compile(r"jellyfin-ffmpeg[0-9]*")
DPKG_QUERY = "dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Provides}\\n'"
# Never remove a package to install another (a conflicting jellyfin-ffmpeg would remove jellyfin).
INSTALL_ARGS = "--no-remove -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
# Rendered unquoted into YAML lists and apt lines.
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MIDDLEWARE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.-]{0,127}$")
# Inside ClientIP(`...`) in a double-quoted YAML string.
_NETWORK = re.compile(r"^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$")

PlainPath = Annotated[PurePosixPath, AfterValidator(plain_path)]
PackageName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]{0,99}$")]
RepoWord = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
RepoUrl = Annotated[str, Field(pattern=rf"^https://{_LABEL}(\.{_LABEL})*(/[A-Za-z0-9._~-]+)*$")]
KeyUrl = Annotated[str, Field(pattern=rf"^https://{_LABEL}(\.{_LABEL})*(/[A-Za-z0-9._~-]+)+$")]
Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3,4}$")]


def _yaml_word(value: str, pattern: re.Pattern[str]) -> bool:
    """A plain word that YAML reads back as the same string (not ``true``, ``1``, ``null``)."""

    return bool(pattern.fullmatch(value)) and yaml.safe_load(value) == value


class JellyfinConfig(RoleConfig):
    """The ``jellyfin_*`` role variables the deploy uses, without the prefix (role defaults).

    ``repo_distro``, ``repo_release`` and ``repo_arch`` have no default: the
    role derives them from Ansible facts, here they are fixed per host and
    checked against the host while planning.
    """

    user: UnixUser = "jellyfin"
    group: UnixUser = "jellyfin"
    service_enabled: bool = True
    data_dir: PlainPath = PurePosixPath("/var/lib/jellyfin")
    config_dir: PlainPath = PurePosixPath("/etc/jellyfin")
    log_dir: PlainPath = PurePosixPath("/var/log/jellyfin")
    media_directories: tuple[PlainPath, ...] = tuple(PurePosixPath(p) for p in ROLE_MEDIA_DIRECTORIES)
    media_dir_owner: UnixUser = "root"
    media_dir_group: UnixUser = "root"
    media_dir_mode: Mode = "0755"
    create_media_dirs: bool = True
    # Not in the role: mount points the media directories must live on. The
    # deploy stops before any change when one is not mounted.
    mounts_required: tuple[PlainPath, ...] = ()
    http_port: int = Field(default=8096, ge=1, le=65535)

    configure_repo: bool = True
    repo_base: RepoUrl = "https://repo.jellyfin.org"
    repo_distro: RepoWord
    repo_release: RepoWord
    repo_component: RepoWord = "main"
    repo_arch: RepoWord
    # None: the role's ``<repo_base>/<repo_distro>/jellyfin_team.gpg.key``.
    repo_key_url: KeyUrl | None = None
    repo_keyring: PlainPath = PurePosixPath("/usr/share/keyrings/jellyfin-archive-keyring.gpg")
    repo_list_file: PlainPath = PurePosixPath("/etc/apt/sources.list.d/jellyfin.list")

    ffmpeg_candidates: tuple[PackageName, ...] = ("jellyfin-ffmpeg6", "jellyfin-ffmpeg5", "jellyfin-ffmpeg")
    packages_base: tuple[PackageName, ...] = ("jellyfin", "apache2-utils")

    traefik_enabled: bool = True
    traefik_host: Hostname = "media.example.com"
    traefik_entrypoints: tuple[str, ...] = ("web-secure",)
    traefik_cert_resolver: str = ""
    traefik_middlewares: tuple[str, ...] = ()
    internal_ip_ranges: tuple[str, ...] = ROLE_INTERNAL_IP_RANGES
    basic_auth_enabled: bool = True
    basic_auth_remove_header: bool = True

    healthcheck_enabled: bool = True
    # None: the role's ``http://127.0.0.1:<http_port>/``.
    healthcheck_url: str | None = None
    healthcheck_timeout: int = Field(default=60, ge=1, le=600)
    healthcheck_retries: int = Field(default=5, ge=1, le=100)
    healthcheck_expected_statuses: tuple[int, ...] = (200, 301, 302, 307, 308)

    @field_validator("media_directories")
    @classmethod
    def _media(cls, value: tuple[PurePosixPath, ...]) -> tuple[PurePosixPath, ...]:
        if not value:
            raise ValueError("media_directories must include at least one path")
        if len(set(value)) != len(value):
            raise ValueError("media_directories lists a path twice")
        return value

    @field_validator("traefik_entrypoints")
    @classmethod
    def _entrypoints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # An empty list would render ``entryPoints:`` as null: every entry point.
        if not value or not all(_yaml_word(item, _WORD) for item in value):
            raise ValueError("traefik_entrypoints must be one or more plain names")
        return value

    @field_validator("traefik_cert_resolver")
    @classmethod
    def _resolver(cls, value: str) -> str:
        if value and not _yaml_word(value, _WORD):
            raise ValueError("traefik_cert_resolver must be a plain name")
        return value

    @field_validator("traefik_middlewares")
    @classmethod
    def _middlewares(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(_yaml_word(item, _MIDDLEWARE) for item in value):
            raise ValueError("traefik_middlewares must be plain names (provider suffix allowed)")
        return value

    @field_validator("internal_ip_ranges")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("internal_ip_ranges must not be empty")
        for item in value:
            if not _NETWORK.fullmatch(item):
                raise ValueError("internal_ip_ranges must contain IP networks")
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
        return value

    @field_validator("healthcheck_url")
    @classmethod
    def _health_url(cls, value: str | None) -> str | None:
        # What ``http_check`` accepts (it echoes the URL in a message).
        if value is not None and not re.fullmatch(r"https?://[^\s'\"$`\\]+", value):
            raise ValueError("healthcheck_url must be an http(s) URL without whitespace, quotes, $, ` or \\")
        return value

    @field_validator("healthcheck_expected_statuses")
    @classmethod
    def _statuses(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or not all(100 <= code <= 599 for code in value):
            raise ValueError("healthcheck_expected_statuses must be HTTP status codes")
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> JellyfinConfig:
        names = (*self.packages_base, *self.ffmpeg_candidates)
        if not self.packages_base or len(set(names)) != len(names):
            raise ValueError("packages_base must not be empty, and no package may be listed twice")
        managed = {self.data_dir, self.config_dir, self.log_dir}
        if len(managed) != 3 or managed & set(self.media_directories):
            raise ValueError("data_dir, config_dir, log_dir and the media directories must be distinct")
        return self

    @property
    def key_url(self) -> str:
        return self.repo_key_url or f"{self.repo_base}/{self.repo_distro}/jellyfin_team.gpg.key"

    @property
    def health_url(self) -> str:
        return self.healthcheck_url or f"http://127.0.0.1:{self.http_port}/"


# -- rendering ---------------------------------------------------------------------


@cache
def _templates() -> jinja2.Environment:
    # Rendered like Ansible's template module (trim_blocks), for byte parity.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["bool"] = bool
    return env


def role_vars(cfg: JellyfinConfig, *, user: str, auth_hash: str) -> dict[str, Any]:
    """The role's variables the Traefik template reads."""

    return {
        "jellyfin_basic_auth_enabled": cfg.basic_auth_enabled,
        "jellyfin_traefik_host": cfg.traefik_host,
        "jellyfin_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "jellyfin_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "jellyfin_traefik_middlewares": list(cfg.traefik_middlewares),
        "jellyfin_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "jellyfin_basic_auth_user": user,
        "jellyfin_basic_auth_password_hash": auth_hash,
        "jellyfin_basic_auth_remove_header": cfg.basic_auth_remove_header,
        "jellyfin_http_port": cfg.http_port,
    }


def traefik_config(cfg: JellyfinConfig, basic_auth: BasicAuth | None) -> TraefikRoute:
    return TraefikRoute(
        name=ROUTE_NAME,
        title="Jellyfin",
        host=cfg.traefik_host,
        app_port=cfg.http_port,
        basic_auth=basic_auth if cfg.basic_auth_enabled else None,
        internal_ip_ranges=cfg.internal_ip_ranges,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_route(cfg: JellyfinConfig, route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's ``jellyfin-traefik.yml.j2``."""

    user = route.basic_auth.user if route.basic_auth else ""
    return _templates().get_template(TEMPLATE).render(**role_vars(cfg, user=user, auth_hash=auth_hash or ""))


def repository_line(cfg: JellyfinConfig) -> str:
    """The one line ``apt_repository`` keeps in the list file."""

    return (
        f"deb [signed-by={cfg.repo_keyring} arch={cfg.repo_arch}] {cfg.repo_base}/{cfg.repo_distro} "
        f"{cfg.repo_release} {cfg.repo_component}\n"
    )


def pick_ffmpeg(cfg: JellyfinConfig, policies: dict[str, str]) -> str | None:
    """The role's choice: the first candidate whose ``apt-cache policy`` names a candidate version."""

    return next((name for name in cfg.ffmpeg_candidates if _CANDIDATE.search(policies.get(name, ""))), None)


def ffmpeg_install_script(cfg: JellyfinConfig) -> str:
    """The pick and install while executing, after the base packages (and a new repository) are in place."""

    candidates = " ".join(shlex.quote(name) for name in cfg.ffmpeg_candidates)
    names = shlex.quote(f" {' '.join(cfg.ffmpeg_candidates)} ")
    return (
        # An installed jellyfin-ffmpeg (the one the jellyfin package depends on) satisfies the pick.
        "if dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 2>/dev/null | "
        f"awk -v names={names} "
        '\'$2 ~ /^.i/ && ($1 ~ /^jellyfin-ffmpeg[0-9]*$/ || index(names, " " $1 " ")) {found = 1} '
        "END {exit !found}'; then exit 0; fi; "
        f"for p in {candidates}; do "
        "if LC_ALL=C apt-cache policy \"$p\" 2>/dev/null | grep -E '^ *Candidate:' | grep -qv '(none)'; then "
        f'DEBIAN_FRONTEND=noninteractive apt-get install -y {INSTALL_ARGS} "$p"; exit $?; '
        "fi; done; "
        "echo 'No jellyfin-ffmpeg package available for this distro/arch; continuing without bundled ffmpeg.' >&2"
    )


def key_install_script(cfg: JellyfinConfig) -> str:
    """Download the armored key into a private directory, dearmor it and move it into place."""

    keyring = shlex.quote(str(cfg.repo_keyring))
    staged = shlex.quote(f"{cfg.repo_keyring}.ops-deploy-new")
    return (
        'set -e; tmp=$(mktemp -d); trap "rm -rf -- $tmp" EXIT; '
        f'curl -fsSL --max-time 120 -o "$tmp/key" {shlex.quote(cfg.key_url)}; '
        'gpg --batch --yes --dearmor -o "$tmp/keyring" "$tmp/key"; test -s "$tmp/keyring"; '
        f'install -o root -g root -m 0644 "$tmp/keyring" {staged}; mv -f {staged} {keyring}'
    )


# -- planning probes -------------------------------------------------------------------


def _check_host(cfg: JellyfinConfig) -> None:
    """The fixed repository settings must be what the role would derive from this host's facts."""

    found = output('. /etc/os-release && echo "$ID|${VERSION_CODENAME:-$UBUNTU_CODENAME}"').strip()
    distro_id, _, release = found.partition("|")
    machine = output("uname -m").strip()
    expected = (REPO_FAMILY.get(distro_id, REPO_FAMILY_DEFAULT), release, REPO_ARCH.get(machine, REPO_ARCH_DEFAULT))
    if not distro_id or not release or not machine:
        raise DeployError("jellyfin: cannot read the host's os-release and architecture")
    if expected != (cfg.repo_distro, cfg.repo_release, cfg.repo_arch):
        raise DeployError(
            f"jellyfin: the host is {'/'.join(expected)}, the config says "
            f"{cfg.repo_distro}/{cfg.repo_release}/{cfg.repo_arch}; update repo_distro, repo_release, repo_arch"
        )


def _keyring_state(cfg: JellyfinConfig) -> str:
    """``binary`` (a dearmored keyring, kept), ``armored`` or ``missing`` (both: install the key)."""

    keyring = shlex.quote(str(cfg.repo_keyring))
    state = output(
        f"if [ -s {keyring} ]; then if head -c 5 {keyring} | grep -q -- -----; then echo armored; "
        "else echo binary; fi; fi"
    ).strip()
    return state or "missing"


def _ffmpeg_policies(cfg: JellyfinConfig) -> dict[str, str]:
    """``apt-cache policy`` per candidate (read-only; unknown packages print nothing)."""

    script = "; ".join(
        f"echo {shlex.quote('>>' + name)}; LC_ALL=C apt-cache policy {shlex.quote(name)}"
        for name in cfg.ffmpeg_candidates
    )
    policies: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in output(f"{{ {script}; }}").splitlines():
        if line.startswith(">>"):
            current = policies.setdefault(line[2:], [])
        elif current is not None:
            current.append(line)
    return {name: "\n".join(lines) for name, lines in policies.items()}


# -- the role's task files ----------------------------------------------------------------


def _repository(cfg: JellyfinConfig) -> tuple[list[OperationMeta], bool]:
    """repo.yml: keyring and list file. Returns the operations and whether both were current while planning."""

    ops: list[OperationMeta] = []
    key_current = _keyring_state(cfg) == "binary"
    if not key_current:
        # Checked while planning, so a host without them fails before any change
        # (installing them here would need an apt refresh, which a broken key fails).
        tools = [tool for tool in ("curl", "gpg") if not host.get_fact(Which, command=tool)]
        if tools:
            raise DeployError(
                f"jellyfin: installing the repository key needs {' and '.join(tools)} on the host; "
                "install curl and gnupg first"
            )
        ops.append(server.shell(name="Install Jellyfin repository key", commands=[key_install_script(cfg)]))
    files.file(
        name="Set Jellyfin keyring permissions", path=str(cfg.repo_keyring), user="root", group="root", mode="0644"
    )
    line = repository_line(cfg)
    list_current = host.get_fact(Sha1File, path=str(cfg.repo_list_file)) == hashlib.sha1(line.encode()).hexdigest()
    ops.append(
        files.put(
            name="Configure Jellyfin apt repository",
            src=StringIO(line),
            dest=str(cfg.repo_list_file),
            user="root",
            group="root",
            mode="0644",
        )
    )
    return ops, key_current and list_current


def installed_packages() -> set[str]:
    """Installed packages and the names they provide (Ansible's ``apt`` counts a provider as present)."""

    have: set[str] = set()
    for line in output(DPKG_QUERY).splitlines():
        status, _, rest = line.partition("|")
        if status[1:2] != "i":  # the second letter is the package's state; ``i``: installed
            continue
        name, _, provides = rest.partition("|")
        have.add(name)
        have.update(item.split()[0] for item in provides.split(",") if item.strip())
    return have


def _packages(cfg: JellyfinConfig, repo_ops: list[OperationMeta], repo_current: bool) -> None:
    """packages.yml: the base packages and the first available jellyfin-ffmpeg.

    The ffmpeg pick is decided while planning only when the repository and
    the base packages are already in place; otherwise one step makes it after
    the base install. Either way an installed jellyfin-ffmpeg satisfies it.
    """

    have = installed_packages()
    missing = [name for name in cfg.packages_base if name not in have]
    decide_now = repo_current and not missing
    ffmpeg_present = any(_FFMPEG.fullmatch(name) or name in cfg.ffmpeg_candidates for name in have)
    if decide_now and not ffmpeg_present:
        ffmpeg = pick_ffmpeg(cfg, _ffmpeg_policies(cfg))
        if ffmpeg is None:
            logger.warning(
                f"{host.print_prefix}No jellyfin-ffmpeg package available for this distro/arch; "
                "continuing without bundled ffmpeg."
            )
        else:
            missing.append(ffmpeg)

    def refresh() -> bool:
        return bool(missing) or not repo_current or any(op.did_change() for op in repo_ops)

    apt.update(name="Update apt cache", _if=refresh)
    if missing:
        apt.packages(name="Install Jellyfin packages", packages=missing, extra_install_args="--no-remove")
    if not decide_now:
        server.shell(name="Install the first available Jellyfin ffmpeg package", commands=[ffmpeg_install_script(cfg)])


def _directory(path: PurePosixPath, *, user: str, group: str, mode: str) -> None:
    """Ansible's ``file`` with ``state: directory``: owner, group and exactly ``mode``.

    GNU ``chmod 1777`` keeps a directory's setgid bit and pyinfra skips a
    zero mode, so the mode is compared with ``stat`` while planning and set
    with ``chmod =<mode>``, which sets every bit, special ones included.
    """

    want = int(mode, 8)
    quoted = shlex.quote(str(path))
    current = output(f"stat -c %a {quoted}").strip()
    files.directory(name=f"Ensure {path}", path=str(path), user=user, group=group)
    if not re.fullmatch(r"[0-7]{1,4}", current) or int(current, 8) != want:
        server.shell(name=f"Set mode {want:04o} on {path}", commands=[f"chmod ={want:04o} {quoted}"])


def _directories(cfg: JellyfinConfig) -> None:
    """directories.yml."""

    for path in (cfg.data_dir, cfg.config_dir, cfg.log_dir):
        _directory(path, user=cfg.user, group=cfg.group, mode="0750")
    if cfg.create_media_dirs:
        for path in cfg.media_directories:
            _directory(path, user=cfg.media_dir_owner, group=cfg.media_dir_group, mode=cfg.media_dir_mode)


def check_basic_auth(cfg: JellyfinConfig, basic_auth: BasicAuth | None) -> None:
    """validate.yml's basic auth assertion; errors never quote the password."""

    wanted = cfg.traefik_enabled and cfg.basic_auth_enabled
    if wanted and basic_auth is None:
        raise ValueError("basic_auth is required when Traefik and basic auth are enabled")
    if not wanted and basic_auth is not None:
        raise ValueError("basic_auth given, but Traefik or basic auth is disabled")
    if basic_auth is not None and PLACEHOLDER in basic_auth.password.get_secret_value():
        raise ValueError("basic auth password must not be a placeholder")


@deploy("Deploy Jellyfin")
def deploy_jellyfin(cfg: JellyfinConfig, basic_auth: BasicAuth | None = None) -> None:
    check_basic_auth(cfg, basic_auth)
    require_linux("jellyfin")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("jellyfin needs a Debian-family host")
    if cfg.configure_repo:
        _check_host(cfg)
    for mount in cfg.mounts_required:
        quoted = shlex.quote(str(mount))
        mark_read_only(
            server.shell(
                name=f"Require the mount {mount}",
                commands=[
                    f"findmnt --mountpoint {quoted} >/dev/null || {{ echo {quoted}' is not mounted' >&2; exit 1; }}"
                ],
            )
        )

    repo_ops, repo_current = _repository(cfg) if cfg.configure_repo else ([], True)
    _packages(cfg, repo_ops, repo_current)
    _directories(cfg)

    if cfg.traefik_enabled:

        def renderer(route: TraefikRoute, auth_hash: str | None) -> str:
            return render_route(cfg, route, auth_hash)

        traefik_route(traefik_config(cfg, basic_auth), renderer=renderer, restart="none")

    systemd.service(
        name="Enable and start jellyfin.service",
        service="jellyfin.service",
        running=True,
        enabled=cfg.service_enabled,
    )

    if cfg.healthcheck_enabled:
        wait_port(cfg.http_port, retries=cfg.healthcheck_timeout, delay=1, name="Wait for Jellyfin port to be open")
        http_check(
            cfg.health_url,
            status=cfg.healthcheck_expected_statuses,
            retries=cfg.healthcheck_retries,
            delay=3,
            timeout=cfg.healthcheck_timeout,
            name="Perform Jellyfin HTTP health check",
        )
