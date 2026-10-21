"""FastDeploy: the FastAPI deploy platform with its Vue frontend, on PostgreSQL.

Port of the ``fastdeploy_deploy`` Ansible role, rsync method only. The env
and unit files are byte-identical to the role's
(``tests/test_fastdeploy_parity.py``), so Ansible and ops-deploy can take turns
on one host. Host-side state in the site directory (registered services,
env files, the venv, the built frontend) survives every sync
(``persistent_excludes``). Like the role, every deploy restarts the service
and then checks its DB-backed auth with a freshly minted token.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from datetime import date
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, FileContents
from pyinfra.facts.server import Command
from pyinfra.operations import apt, files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import (
    BasicAuth,
    HealthCheck,
    RedirectRegex,
    TraefikRoute,
    mark_read_only,
    postgres_database,
    service_rollout,
    systemd_unit,
    traefik_route,
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.traefik import _MIDDLEWARE, DEFAULT_INTERNAL_IP_RANGES, Hostname
from ops_deploy.ops import secret_file, secret_stdin, sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.fastdeploy"
FILES = Path(__file__).parent / "files"
# Files the role runs with FastDeploy's interpreter (``python -c``).
ENSURE_TOKEN_USER = (FILES / "ensure_token_user.py").read_text()
ROLLOUT_CHECK = (FILES / "rollout_check.py").read_text()

# No whitespace, quotes, ``$``, backticks or backslashes: rendered unquoted into .env.
Url = Annotated[str, Field(pattern=r"^(https?|wss?)://[^\s'\"$`\\]+$")]
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
TokenUser = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}$")]
Days = Annotated[int, Field(ge=1)]
# FastDeploy's RestorePolicy (src/deploy/config.py). None of these allow a
# quote: the JSON is rendered in single quotes.
RestoreService = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")]
RestorePrefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*/$")]
# validate_service_token_settings.yml: ISO 8601 with a UTC offset; "T" or a space.
_TIMESTAMP = (
    r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[T ]([01][0-9]|2[0-3]):[0-5][0-9]"
    r"(:[0-5][0-9]([.][0-9]+)?)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$"
)
_IP = r"^[0-9A-Fa-f.:]+$"
NODESOURCE_KEYRING = "/etc/apt/keyrings/nodesource.gpg"
NODESOURCE_URL = "https://deb.nodesource.com"
# Written next to the build output after a build; holds the digest of its inputs.
BUILD_STAMP = ".ops-deploy-build"


class RestorePolicy(BaseModel):
    """The bucket and key prefixes one FastDeploy service's Echoport restores may read."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")]
    # One runner service can serve several Echoport targets, each under its own prefix.
    prefixes: tuple[RestorePrefix, ...] = Field(min_length=1)


class FastdeployConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "secret_key",
        "initial_user_name",
        "initial_user_password_hash",
        "postgres_password",
        "basic_auth_password",
    )

    service_name: ServiceName = "fastdeploy"
    user: UnixUser = "fastdeploy"
    # Runs the registered services' deploy.sh through sudo (SUDO_USER); each
    # registered service installs its own narrow sudoers rule.
    deploy_user: UnixUser = "deploy"
    site_path: PurePosixPath = PurePosixPath("/home/fastdeploy/site")
    # A FastDeploy checkout, synced to the site root as a whole.
    source_path: Path
    # Never shipped (the role's fastdeploy_rsync_excludes).
    source_excludes: tuple[str, ...] = (
        ".vault_password",
        "*.pyc",
        ".env",
        "venv",
        "databases",
        "frontend/node_modules",
        "frontend/dist",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "htmlcov",
        "site",
        ".DS_Store",
    )
    # Host-side state in the site tree that --delete must never remove: what
    # the role creates there (bin, logs, the services directory registrations
    # write into, .env.shell) and the stale SQLite file of early deploys. The
    # env file, venv, node_modules, dist and databases are already excluded
    # above or by sync_tree itself.
    persistent_excludes: tuple[str, ...] = ("/.env.shell", "/bin/", "/logs/", "/services/", "/db.sqlite3")
    environment: Annotated[str, Field(pattern=r"^[a-z]+$")] = "production"
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    nodejs_version: int = Field(default=24, ge=18, le=99)
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=9999, ge=1024, le=65535)
    # Uvicorn's --forwarded-allow-ips: literal addresses only, never a wildcard or CIDR.
    forwarded_allow_ips: tuple[Annotated[str, Field(pattern=_IP)], ...] = ("127.0.0.1",)
    restart_on_failure: bool = True
    restart_sec: int = Field(default=5, ge=0)
    api_url: Url = "https://deploy.example.com"
    websocket_url: Url = "wss://deploy.example.com/deployments/ws"
    postgres_database: Identifier = "fastdeploy"
    postgres_user: Identifier = "fastdeploy"
    # The deploy manages the database through the local cluster's socket, so
    # DATABASE_URL must point at that same cluster.
    postgres_host: Literal["localhost", "127.0.0.1"] = "localhost"
    postgres_port: Literal[5432] = 5432
    # Empty: not rendered, FastDeploy's own defaults apply.
    legacy_service_tokens_accepted_until: Annotated[str, Field(pattern=rf"{_TIMESTAMP}|^$")] = ""
    service_token_max_expire_days: Days | None = None
    service_token_retention_days: Days | None = None
    # SERVICE_TOKEN_ADMIN_USERS: who may issue service tokens through the API
    # (also the web UI deploy button). With ``service_token_admin_initial_user``
    # the initial user (a secret) comes first. Empty: not rendered, FastDeploy
    # refuses API token issuance to everyone (403).
    service_token_admin_users: tuple[TokenUser, ...] = ()
    service_token_admin_initial_user: bool = False
    # RESTORE_POLICIES, keyed by FastDeploy service name. Empty: not rendered,
    # FastDeploy refuses every restore (422).
    restore_policies: dict[RestoreService, RestorePolicy] = Field(default_factory=dict)
    # Temporary bridge for legacy service tokens: FastDeploy users without a usable password.
    legacy_token_users: tuple[TokenUser, ...] = ()
    create_initial_user: bool = True
    sync_services: bool = True
    # After the restart every deploy does: wait for the port, check auth with a minted token.
    rollout_validation: bool = True
    rollout_validation_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")] = "/users/me"
    rollout_validation_user: TokenUser | None = None  # None: the initial user
    rollout_validation_token_ttl_seconds: int = Field(default=300, ge=30)
    rollout_validation_retries: int = Field(default=15, ge=1)
    rollout_validation_delay: int = Field(default=2, ge=0)
    traefik_host: Hostname = "deploy.example.com"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"

    @field_validator("source_path")
    @classmethod
    def _source_is_a_fastdeploy_checkout(cls, value: Path) -> Path:
        wanted = ("commands.py", "pyproject.toml", "uv.lock", "src/deploy", "frontend/package.json")
        missing = [p for p in wanted if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not a FastDeploy checkout (missing {', '.join(missing)})")
        return value

    @field_validator("legacy_service_tokens_accepted_until")
    @classmethod
    def _real_date(cls, value: str) -> str:
        if value:
            try:
                date.fromisoformat(value[:10])
            except ValueError:
                raise ValueError("legacy_service_tokens_accepted_until is not a real date") from None
        return value

    @model_validator(mode="after")
    def _proxies_given(self) -> Self:
        if not self.forwarded_allow_ips:
            raise ValueError("forwarded_allow_ips must list at least one address")
        return self

    @property
    def home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.user

    @property
    def deploy_home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.deploy_user

    @property
    def services_path(self) -> PurePosixPath:
        return self.site_path / "services"

    @property
    def libexec_path(self) -> PurePosixPath:
        """Root-owned home of the scripts FastDeploy runs through sudo (ops-library fastdeploy_runner)."""
        return PurePosixPath("/usr/local/libexec/fastdeploy")

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def frontend_path(self) -> PurePosixPath:
        return self.site_path / "frontend"

    @property
    def service_token_settings(self) -> bool:
        return (
            bool(self.legacy_service_tokens_accepted_until)
            or self.service_token_admins
            or any(days is not None for days in (self.service_token_max_expire_days, self.service_token_retention_days))
        )

    @property
    def service_token_admins(self) -> bool:
        return self.service_token_admin_initial_user or bool(self.service_token_admin_users)

    @property
    def build_env(self) -> dict[str, str]:
        """The role's frontend build environment."""

        return {
            "NODE_ENV": "production",
            "VITE_API_BASE_PROD": self.api_url,
            "VITE_WEBSOCKET_URL_PROD": self.websocket_url,
        }


def check_secrets(secrets: SecretValues) -> None:
    """The role's secret asserts, plus single-line values (they land in env files)."""

    secrets.require(FastdeployConfig.required_secret_keys)
    if any("\n" in value or "\r" in value for value in secrets.values()):
        raise ValueError("secret values must be single lines")
    placeholders = sorted(k for k, v in secrets.items() if "CHANGEME" in v)
    if placeholders:
        raise ValueError(f"secrets still hold placeholder values: {', '.join(placeholders)}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,254}", secrets["initial_user_name"]):
        raise ValueError("initial_user_name must be a plain user name")
    # Rendered into DATABASE_URL unencoded (as the role does): only URL-safe characters.
    if not re.fullmatch(r"[A-Za-z0-9._~-]+", secrets["postgres_password"]):
        raise ValueError("postgres_password may only use letters, digits and . _ ~ -")


def traefik_config(cfg: FastdeployConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title="FastDeploy",
        host=cfg.traefik_host,
        app_port=cfg.app_port,
        app_host=cfg.app_host,
        basic_auth=BasicAuth(
            user=secrets.get("basic_auth_user") or cfg.basic_auth_user,
            password=SecretStr(secrets["basic_auth_password"]),
        ),
        internal_ip_ranges=cfg.internal_ip_ranges,
        middlewares=cfg.traefik_middlewares,
        cert_resolver=cfg.traefik_cert_resolver,
        frame_options="SAMEORIGIN",
        redirect=RedirectRegex(regex="^(https?://[^/]+)/$", replacement="${1}/static/index.html"),
        health_check=HealthCheck(),
    )


def render_env(cfg: FastdeployConfig, secrets: SecretValues, *, shell: bool) -> SecretContent:
    """``.env`` (systemd ``EnvironmentFile`` and FastDeploy's settings) or, with ``shell``, ``.env.shell``."""

    admins = [secrets["initial_user_name"]] if cfg.service_token_admin_initial_user else []
    admins += cfg.service_token_admin_users
    policies = {name: policy.model_dump(mode="json") for name, policy in cfg.restore_policies.items()}
    return SecretContent(
        render(
            TEMPLATE_PACKAGE,
            "fastdeploy.env.j2",
            cfg=cfg,
            secrets=secrets,
            shell=shell,
            # The role's to_json(sort_keys=True, separators=(',', ':')).
            admin_users_json=_compact_json(admins) if admins else "",
            restore_policies_json=_compact_json(policies) if policies else "",
        )
    )


def _compact_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def frontend_digest(cfg: FastdeployConfig) -> str:
    """Digest of the build inputs: the frontend sources and the build environment.

    Covers every file under ``frontend/`` except dependencies, build output
    and Finder metadata, so it never misses a source change the sync ships.
    """

    root = cfg.source_path / "frontend"
    digest = hashlib.sha256(json.dumps(cfg.build_env, sort_keys=True).encode())
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] in ("node_modules", "dist") or path.name == ".DS_Store" or not path.is_file():
            continue
        digest.update(f"\0{relative.as_posix()}\0".encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _site_command(cfg: FastdeployConfig, script: str, env: dict[str, str] | None = None) -> str:
    """``script`` run by ``sh`` in the site directory as the service user."""

    shell = _as_user(cfg.user, cfg.home, env or {}, ["sh", "-c", script])
    return f"cd {shlex.quote(str(cfg.site_path))} && {shell}"


def _users_probe(cfg: FastdeployConfig) -> str:
    """SHA-256 digests of the FastDeploy user names in the database (names may be secret).

    Prints nothing while the database or its ``user`` table does not exist yet
    (first deploy); any other error fails the probe.
    """

    def psql(database: str, sql: str) -> str:
        return shlex.join(["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-d", database, "-c", sql])

    database = f"select 1 from pg_database where datname = '{cfg.postgres_database}'"
    table = "select to_regclass('public.\"user\"') is not null"
    names = "select encode(sha256(convert_to(name, 'UTF8')), 'hex') from \"user\""
    return (
        f'cd / && db=$( {psql("postgres", database)} ) || exit 1; [ "$db" = 1 ] || exit 0; '
        f't=$( {psql(cfg.postgres_database, table)} ) || exit 1; [ "$t" = t ] || exit 0; '
        f"{psql(cfg.postgres_database, names)}"
    )


def _digest(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


# createuser exits 0 even when it fails and prints the database error, which
# can quote the password hash: judge its output here and never show it.
_JUDGE = (
    'out=$({run} 2>&1); case "$out" in {ok}) exit 0;; esac; '
    'echo "{what} failed; output withheld because it can quote a password hash" >&2; exit 1'
)


def _initialize(cfg: FastdeployConfig, secrets: SecretValues, when_changed: list[OperationMeta]) -> None:
    """The role's initialize.yml: initial user, legacy token users, service sync."""

    check = _users_probe(cfg)
    found = probe(check, name="FastDeploy users")
    # A failed probe: create them (createuser accepts an existing user), then probe again.
    users = set((found or "").split())
    python = shlex.quote(str(cfg.venv_bin / "python"))
    env = {"PRODUCTION": "true", "COLUMNS": "1000"}
    if cfg.create_initial_user and _digest(secrets["initial_user_name"]) not in users:
        run = (
            "set -a; . ./.env.shell; set +a; IFS= read -r INITIAL_USER_NAME; IFS= read -r INITIAL_PASSWORD_HASH; "
            f"export INITIAL_USER_NAME INITIAL_PASSWORD_HASH; {python} commands.py createuser"
        )
        stdin = f"{secrets['initial_user_name']}\n{secrets['initial_user_password_hash']}\n"
        secret_stdin(
            name="Create initial FastDeploy user",
            command=_site_command(
                cfg, _JUDGE.format(run=run, ok='*created:*|*"duplicate key"*', what="createuser"), env
            ),
            content=SecretContent(stdin),
        )
    for name in cfg.legacy_token_users:
        if _digest(name) in users:
            continue
        run = f"{python} -c {shlex.quote(ENSURE_TOKEN_USER)}"
        ok = '*created:*|*"duplicate key"*|*"unique constraint"*'
        secret_stdin(
            name=f"Create legacy token user {name}",
            command=_site_command(cfg, _JUDGE.format(run=run, ok=ok, what=f"creating user {name}")),
            content=SecretContent(f"{name}\n"),
        )
    if found is None and (cfg.create_initial_user or cfg.legacy_token_users):
        verify_probe(check, name="FastDeploy users")
    if cfg.sync_services:
        server.shell(
            name="Sync services from filesystem",
            commands=[
                _site_command(cfg, f"set -a; . ./.env.shell; set +a; exec {python} commands.py syncservices", env)
            ],
            _if=lambda: any(meta.did_change() for meta in when_changed),
        )


def _nodejs(cfg: FastdeployConfig) -> None:
    """NodeSource's Node.js when ``node`` is missing or older than ``nodejs_version`` (the role's check)."""

    version = host.get_fact(Command, command="node --version 2>/dev/null || true") or ""
    match = re.match(r"^v([0-9]+)\.", version)
    if match and int(match[1]) >= cfg.nodejs_version:
        return
    apt.packages(name="Install NodeSource prerequisites", packages=["ca-certificates", "curl", "gnupg"], update=True)
    files.directory(name="Create /etc/apt/keyrings", path="/etc/apt/keyrings", mode="0755")
    if not host.get_fact(File, path=NODESOURCE_KEYRING):
        server.shell(
            name="Download NodeSource GPG key",
            commands=[
                f"curl -fsSL {NODESOURCE_URL}/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o {NODESOURCE_KEYRING}"
            ],
        )
    files.put(
        name="Add NodeSource repository",
        src=StringIO(
            f"deb [signed-by={NODESOURCE_KEYRING}] {NODESOURCE_URL}/node_{cfg.nodejs_version}.x nodistro main\n"
        ),
        dest="/etc/apt/sources.list.d/nodesource.list",
        mode="0644",
    )
    apt.packages(name="Install Node.js", packages=["nodejs"], latest=True, update=True)


def _frontend(cfg: FastdeployConfig) -> OperationMeta:
    """Build the frontend when its inputs differ from the last build's; returns the stamp write."""

    _nodejs(cfg)
    stamp_path = cfg.frontend_path / "dist" / BUILD_STAMP
    stamp = f"{frontend_digest(cfg)}\n"
    if host.get_fact(FileContents, path=str(stamp_path)) != stamp.splitlines():
        install = "npm ci" if (cfg.source_path / "frontend" / "package-lock.json").exists() else "npm install"
        frontend = shlex.quote(str(cfg.frontend_path))
        server.shell(
            name="Build frontend",
            commands=[
                f"cd {frontend} && {_as_user(cfg.user, cfg.home, {}, install.split())}",
                f"cd {frontend} && {_as_user(cfg.user, cfg.home, cfg.build_env, ['npm', 'run', 'build'])}",
            ],
        )
    return files.put(
        name="Record frontend build inputs",
        src=StringIO(stamp),
        dest=str(stamp_path),
        user=cfg.user,
        group=cfg.user,
        mode="0644",
    )


def _rollout_check(cfg: FastdeployConfig, secrets: SecretValues) -> OperationMeta:
    """Mint a token and check DB-backed auth with it (the role's rollout validation); read-only."""

    request = {
        "user": cfg.rollout_validation_user or secrets["initial_user_name"],
        "ttl_seconds": cfg.rollout_validation_token_ttl_seconds,
        "url": f"http://{cfg.app_host}:{cfg.app_port}{cfg.rollout_validation_path}",
        "retries": cfg.rollout_validation_retries,
        "delay": cfg.rollout_validation_delay,
    }
    python = shlex.quote(str(cfg.venv_bin / "python"))
    # Only the last line of the output (the verdict or the exception) is shown.
    run = (
        f'out=$({python} -c {shlex.quote(ROLLOUT_CHECK)} 2>&1); rc=$?; printf "%s\\n" "$out" | tail -n 1 >&2; exit $rc'
    )
    return mark_read_only(
        secret_stdin(
            name="Check FastDeploy auth with a minted token",
            command=_site_command(cfg, run),
            content=SecretContent(json.dumps(request) + "\n"),
        )
    )


def _accounts(cfg: FastdeployConfig) -> None:
    """The role's user.yml: deploy and service users, directories; the retired sudoers rule goes."""

    for group in (cfg.deploy_user, cfg.user):
        server.group(name=f"Ensure group {group}", group=group)
    # Like the role's ``user`` tasks: regular accounts, home created only for a new user.
    server.user(
        name=f"Ensure user {cfg.deploy_user}",
        user=cfg.deploy_user,
        group=cfg.deploy_user,
        groups=[cfg.user],
        append=True,
        shell="/bin/bash",
        home=str(cfg.deploy_home),
        create_home=True,
        ensure_home=False,
        comment="Deployment Service Account",
    )
    server.user(
        name=f"Ensure user {cfg.user}",
        user=cfg.user,
        group=cfg.user,
        shell="/bin/bash",
        home=str(cfg.home),
        create_home=True,
        ensure_home=False,
        comment="FastDeploy Service Account",
    )
    for path in (cfg.home, cfg.site_path, cfg.site_path / "bin", cfg.site_path / "logs"):
        files.directory(name=f"Ensure directory {path}", path=str(path), user=cfg.user, group=cfg.user, mode="0755")
    _runner_layout(cfg)
    # The old wildcard rule (``<user> ALL=(deploy) NOPASSWD: <services>/*/deploy.sh *``)
    # let FastDeploy run any script it writes into its own services directory;
    # like the role (ops-library 2.35.0), remove it.
    files.file(name="Remove the retired wildcard sudoers rule", path="/etc/sudoers.d/fastdeploy", present=False)


def _runner_layout(cfg: FastdeployConfig) -> None:
    """The role's runner_layout.yml (ops-library 2.49.0).

    FastDeploy only reads its services root, so it is root-owned. Hosts deployed
    by older role versions have a fastdeploy-owned tree below it, root-run
    backup scripts included: the owner becomes root and the service group
    becomes root (other groups, such as deploy, stay). The scripts sudo runs
    live in the root-owned libexec directory instead: fastdeploy owns the site
    around the services root and could rename it.
    """

    services = shlex.quote(str(cfg.services_path))
    group = shlex.quote(cfg.user)
    root = str(cfg.services_path)
    files.directory(name=f"Ensure directory {root}", path=root, user="root", group="root", mode="0755")
    not_root = f"find {services} -mindepth 1 ! -user root"
    service_group = f"find {services} -mindepth 1 -group {group}"
    leftovers = host.get_fact(Command, command=f"{{ {not_root} -print; {service_group} -print; }} 2>/dev/null || true")
    if leftovers:
        server.shell(
            name="Hand everything below the services root to root",
            commands=[f"{not_root} -exec chown -h root {{}} +", f"{service_group} -exec chgrp -h root {{}} +"],
        )
    for path in (cfg.libexec_path.parent, cfg.libexec_path):
        files.directory(name=f"Ensure directory {path}", path=str(path), user="root", group="root", mode="0755")


@deploy("Deploy fastdeploy")
def deploy_fastdeploy(
    cfg: FastdeployConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    check_secrets(secrets)
    env_content, shell_env = render_env(cfg, secrets, shell=False), render_env(cfg, secrets, shell=True)
    route = traefik_config(cfg, secrets)

    postgres_database(cfg.postgres_database, owner=cfg.postgres_user, password=SecretStr(secrets["postgres_password"]))
    _accounts(cfg)
    code = sync_tree(
        name="Sync FastDeploy source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=(*cfg.source_excludes, *cfg.persistent_excludes),
        runner=rsync,
        user=cfg.user,
        group=cfg.user,
    )
    for path, content in ((".env", env_content), (".env.shell", shell_env)):
        secret_file(
            name=f"Write {path}", path=cfg.site_path / path, content=content, mode="0600", user=cfg.user, group=cfg.user
        )
    # The role runs ``uv sync --frozen`` (all default groups) on every deploy;
    # here only after a source change or when the venv is missing.
    # A venv on another Python version is synced too; uv recreates it. The
    # venv belongs to the service user, so its interpreter runs as that user.
    version = "import sys; print(*sys.version_info[:2], sep='.')"
    probe = _as_user(cfg.user, cfg.home, {}, [str(cfg.venv_bin / "python"), "-c", version])
    venv_python = host.get_fact(Command, command=f"{probe} 2>/dev/null || true") or ""
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.python_version,
        args=("--frozen",),
        when_changed=[code] if venv_python.strip() in ("", cfg.python_version) else None,
    )
    _frontend(cfg)
    _initialize(cfg, secrets, [code, deps])

    unit = systemd_unit(cfg.service_name, render(TEMPLATE_PACKAGE, "fastdeploy.service.j2", cfg=cfg))
    # Traefik's file provider watches the dynamic directory; like the role
    # (ops-library 2.31.47), no Traefik restart.
    traefik_route(route, restart="none")
    # Every deploy is a rollout: the restart is unconditional, as in the role.
    service_rollout(cfg.service_name, units=[unit], always_restart=True)
    if cfg.rollout_validation:
        wait_port(
            cfg.app_port,
            host=cfg.app_host,
            retries=cfg.rollout_validation_retries * max(cfg.rollout_validation_delay, 1),
        )
        _rollout_check(cfg, secrets)
