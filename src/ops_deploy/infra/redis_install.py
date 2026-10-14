"""Redis from apt with a managed ``redis.conf`` (the ``redis_install`` role).

The password is a deploy argument, not part of the config, so the config can
be logged and compared freely. ``redis.conf`` holds it, so it is written with
:func:`~ops_deploy.ops.secret_file` and never shown in a diff. The data
directory is only created and its owner and mode set; nothing in it is
touched.
"""

from __future__ import annotations

import hashlib
import shlex
from collections.abc import Generator
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy, operation
from pyinfra.facts.server import Command, Which
from pyinfra.operations import apt, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.infra._common import apt_repository, codename, directory
from ops_deploy.infra.postgres_install import PackageName, RepoWord, Url
from ops_deploy.ops import secret_file, secret_stdin

MaxmemoryPolicy = Literal[
    "noeviction",
    "allkeys-lru",
    "volatile-lru",
    "allkeys-lfu",
    "volatile-lfu",
    "allkeys-random",
    "volatile-random",
    "volatile-ttl",
]


def _single_word(value: str) -> str:
    if not value or any(ch.isspace() or ch in "\"'" for ch in value):
        raise ValueError(f"not a single redis.conf word: {value!r}")
    return value


class RedisInstallConfig(RoleConfig):
    package_name: PackageName = "redis-server"
    add_official_repo: bool = False
    apt_repo: Url = "https://packages.redis.io/deb"
    # None: the host's release codename, as the role's ansible_distribution_release.
    apt_suite: RepoWord | None = None
    apt_components: tuple[RepoWord, ...] = ("main",)
    repo_key_url: Url = "https://packages.redis.io/gpg"
    repo_keyring_path: AbsolutePath = "/usr/share/keyrings/redis-official-archive-keyring.gpg"

    bind_addresses: tuple[str, ...] = Field(default=("127.0.0.1", "::1"), min_length=1)
    port: int = Field(default=6379, ge=1, le=65535)
    protected_mode: bool = True
    supervised_mode: Literal["systemd", "upstart", "auto", "no"] = "systemd"
    databases: int = Field(default=16, gt=0)
    requirepass_enabled: bool = False

    save_rules: tuple[str, ...] = ("900 1", "300 10", "60 10000")
    appendonly: bool = False
    appendfilename: str = Field(default="appendonly.aof", pattern=r"^[A-Za-z0-9._-]+$")
    appendfsync: Literal["always", "everysec", "no"] = "everysec"
    maxmemory: str = Field(default="0", pattern=r"^[0-9]+([kmgKMG]?[bB]?)?$")
    maxmemory_policy: MaxmemoryPolicy = "noeviction"
    tcp_backlog: int = Field(default=511, gt=0)
    timeout: int = Field(default=0, ge=0)
    tcp_keepalive: int = Field(default=300, ge=0)
    stop_writes_on_bgsave_error: bool = True
    loglevel: Literal["debug", "verbose", "notice", "warning", "nothing"] = "notice"
    log_dir: AbsolutePath = "/var/log/redis"
    # None: <log_dir>/redis-server.log.
    logfile: AbsolutePath | None = None

    # The role can try a candidate config in a throwaway redis-server first;
    # that is not ported (it is off in every inventory) and refused.
    validate_config: Literal[False] = False

    config_path: AbsolutePath = "/etc/redis/redis.conf"
    data_dir: AbsolutePath = "/var/lib/redis"
    user: UnixUser = "redis"
    group: UnixUser = "redis"
    service_name: str = Field(default="redis-server", pattern=r"^[A-Za-z0-9_.@-]+$")
    restart_on_change: bool = True
    # Address the final PING uses; None: the first bind address.
    check_host: str | None = None

    @field_validator("bind_addresses")
    @classmethod
    def _bind_words(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_single_word(item) for item in value)

    @field_validator("check_host")
    @classmethod
    def _check_word(cls, value: str | None) -> str | None:
        return None if value is None else _single_word(value)

    @field_validator("save_rules")
    @classmethod
    def _save_rules(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for rule in value:
            seconds, _, changes = rule.partition(" ")
            if not (seconds.isdigit() and changes.isdigit()):
                raise ValueError(f"save rule must be '<seconds> <changes>': {rule!r}")
        return value

    @property
    def log_path(self) -> str:
        return self.logfile or f"{self.log_dir}/redis-server.log"


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def render_config(cfg: RedisInstallConfig, password: SecretStr | None) -> str:
    """``redis.conf.j2`` from the role, byte for byte."""

    auth = (
        f"requirepass {password.get_secret_value()}\n"
        if cfg.requirepass_enabled and password is not None
        else "# requirepass disabled\n"
    )
    if cfg.maxmemory in ("0", "0b", "0B"):
        memory = "# maxmemory unlimited\n"
    else:
        memory = f"maxmemory {cfg.maxmemory}\nmaxmemory-policy {cfg.maxmemory_policy}\n"
    save = "".join(f"save {rule}\n" for rule in cfg.save_rules) if cfg.save_rules else 'save ""\n'
    return (
        "# Managed by Ansible (redis_install role)\n\n"
        f"port {cfg.port}\ntcp-backlog {cfg.tcp_backlog}\ntimeout {cfg.timeout}\ntcp-keepalive {cfg.tcp_keepalive}\n\n"
        f"bind {' '.join(cfg.bind_addresses)}\n\n"
        f"protected-mode {_yes(cfg.protected_mode)}\ndaemonize no\nsupervised {cfg.supervised_mode}\n"
        f"databases {cfg.databases}\n\n"
        f"{auth}\n"
        f"dir {cfg.data_dir}\n\n"
        f"{memory}\n"
        f"{save}\n"
        f'appendonly {_yes(cfg.appendonly)}\nappendfilename "{cfg.appendfilename}"\nappendfsync {cfg.appendfsync}\n\n'
        f'loglevel {cfg.loglevel}\nlogfile "{cfg.log_path}"\n'
        f"stop-writes-on-bgsave-error {_yes(cfg.stop_writes_on_bgsave_error)}\n"
    )


def _check_password(cfg: RedisInstallConfig, password: SecretStr | None) -> None:
    if not cfg.requirepass_enabled:
        return
    secret = password.get_secret_value() if password is not None else ""
    if not secret:
        raise DeployError("redis_install: a password is required when requirepass_enabled is set")
    if secret.lower() in ("changeme", "password"):
        raise DeployError("redis_install: the password must not be a placeholder")
    if any(ch.isspace() or ch in "\"'" for ch in secret) or not secret.isprintable():
        # It goes into redis.conf unquoted: whitespace ends the directive and
        # Redis's parser treats quotes specially.
        raise DeployError("redis_install: the password must not contain whitespace, quotes or control characters")


def _stale_probe(cfg: RedisInstallConfig) -> str:
    """Prints ``ping|<reply>``, ``conf|<mtime>`` and ``start|<epoch>``; no secret involved."""

    unit = shlex.quote(cfg.service_name)
    return (
        f"printf 'ping|%s\\n' \"$(redis-cli -p {cfg.port} PING 2>&1)\"; "
        f"printf 'conf|%s\\n' \"$(stat -c %Y {shlex.quote(cfg.config_path)} 2>/dev/null)\"; "
        f"started=$(systemctl show -p ActiveEnterTimestamp --value {unit}); "
        f'printf \'start|%s\\n\' "$(date -d "$started" +%s 2>/dev/null)"'
    )


def needs_restart(cfg: RedisInstallConfig, lines: list[str]) -> str | None:
    """Why the running server does not match ``redis.conf``, or None."""

    values = dict(line.partition("|")[::2] for line in lines)
    if cfg.requirepass_enabled and values.get("ping", "").strip() == "PONG":
        return "Redis answers without a password"
    conf, start = values.get("conf", ""), values.get("start", "")
    if cfg.restart_on_change and conf.isdigit() and start.isdigit() and int(conf) > int(start):
        return "redis.conf is newer than the running server"
    return None


@operation()
def _restart_if_stale(cfg: RedisInstallConfig) -> Generator[str, None, None]:
    # The role checks this after starting the service: the package starts
    # Redis with its own config before ours is written, and a run that changes
    # nothing would otherwise leave it so. The role also tries the configured
    # password; that needs the secret in a probe, so the config file time is
    # compared with the server's start time instead.
    reason = needs_restart(cfg, (host.get_fact(Command, command=_stale_probe(cfg)) or "").splitlines())
    if reason is None:
        host.noop(f"{cfg.service_name} runs the current configuration")
        return
    yield f"systemctl restart {shlex.quote(cfg.service_name)}"


def _ping(cfg: RedisInstallConfig, password: SecretStr | None) -> None:
    target = shlex.join(["redis-cli", "-h", cfg.check_host or cfg.bind_addresses[0], "-p", str(cfg.port), "PING"])
    check = f'[ "$({target})" = PONG ]'
    label = f"Check {cfg.service_name} answers PING"
    if cfg.requirepass_enabled and password is not None:
        command = f"IFS= read -r REDISCLI_AUTH && export REDISCLI_AUTH && {check}"
        mark_read_only(
            secret_stdin(name=label, command=command, content=SecretContent(password.get_secret_value() + "\n"))
        )
    else:
        mark_read_only(server.shell(name=label, commands=[check]))


@deploy("Redis")
def deploy_redis_install(cfg: RedisInstallConfig, password: SecretStr | None = None) -> None:
    """Install Redis, write ``redis.conf`` and keep the service running it."""

    require_linux("redis_install")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("redis_install needs a Debian-family host")
    _check_password(cfg, password)

    if cfg.add_official_repo:
        suite = cfg.apt_suite or codename()
        if not suite:
            raise DeployError("redis_install: cannot tell the host's release codename; set apt_suite")
        apt_repository(
            name="redis-official",
            key_url=cfg.repo_key_url,
            keyring=cfg.repo_keyring_path,
            uris=cfg.apt_repo,
            suites=(suite,),
            components=cfg.apt_components,
            dearmor=True,
        )
    # The role refreshes the cache on every run; an hour-old cache is enough here.
    apt.packages(
        name="Install Redis packages", packages=[cfg.package_name, "redis-tools"], update=True, cache_time=3600
    )

    for path, mode in ((cfg.data_dir, "0750"), (cfg.log_dir, "0755")):
        directory(path, user=cfg.user, group=cfg.group, mode=mode)
    config_dir = str(PurePosixPath(cfg.config_path).parent)
    directory(config_dir, user="root", group="root", mode="0755")

    rendered = render_config(cfg, password)
    content = SecretContent(rendered)
    config = shlex.quote(cfg.config_path)
    # The role keeps the replaced file (``backup: true``) under the same name pattern.
    current = output(f"sha256sum {config}").split(" ")[0]
    if current and current != hashlib.sha256(rendered.encode()).hexdigest():
        server.shell(
            name=f"Back up {cfg.config_path}",
            # Created private, then given the config's owner and mode: the
            # old file may hold the password and may be readable by others.
            commands=[
                f'b={config}."$$".$(date +%Y-%m-%d@%H:%M:%S)~ && (umask 077 && cp {config} "$b") '
                f'&& chown root:{shlex.quote(cfg.group)} "$b" && chmod 0640 "$b"'
            ],
        )
    written = secret_file(
        name=f"Write {cfg.config_path}",
        path=cfg.config_path,
        content=content,
        user="root",
        group=cfg.group,
        mode="0640",
    )
    # Earlier backups may hold the password too: root:<group> 0640, like the role.
    pattern = shlex.quote(f"{PurePosixPath(cfg.config_path).name}.*~")
    loose = output(
        f"find {shlex.quote(config_dir)} -maxdepth 1 -type f -name {pattern} "
        f"! \\( -user root -group {shlex.quote(cfg.group)} -perm 0640 \\)"
    ).split()
    if loose:
        quoted = " ".join(shlex.quote(path) for path in loose)
        server.shell(
            name="Restrict earlier Redis configuration backups",
            commands=[f"chown root:{shlex.quote(cfg.group)} {quoted}", f"chmod 0640 {quoted}"],
        )

    if cfg.restart_on_change:
        systemd.service(
            name=f"Restart {cfg.service_name} for the new configuration",
            service=cfg.service_name,
            restarted=True,
            _if=written.did_change,
        )
    systemd.service(name=f"Ensure {cfg.service_name}", service=cfg.service_name, running=True, enabled=True)
    _restart_if_stale(name=f"Restart {cfg.service_name} if it runs an older configuration", cfg=cfg)
    _ping(cfg, password)
