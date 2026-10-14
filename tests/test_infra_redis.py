"""``deploy_redis_install`` against the fake connector."""

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra import RedisInstallConfig, deploy_redis_install
from ops_deploy.infra.redis_install import needs_restart, render_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

PASSWORD = SecretStr("redis-fixture-password")
CFG = RedisInstallConfig(requirepass_enabled=True)
CONF = "/etc/redis/redis.conf"
NOAUTH = "(error) NOAUTH Authentication required."
WRITE = "Redis | Write /etc/redis/redis.conf"
PING = "Redis | Check redis-server answers PING"


def config_file(content: str, mode: str = "-rw-r-----", group: str = "redis") -> dict[str, Any]:
    return {**fakehost.file(CONF, content), **fakehost.stat(CONF, group=group, mode=mode)}


def converged(cfg: RedisInstallConfig = CFG, password: SecretStr | None = PASSWORD, **probe: str) -> dict[str, Any]:
    state = {"ping": NOAUTH, "conf": "1000", "start": "2000", **probe}
    return {
        **LINUX,
        "command -v apt-get": ["/usr/bin/apt-get"],
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("redis-server", "redis-tools"),
        **fakehost.stat("/var/lib/redis", user="redis", mode="drwxr-x---"),
        **fakehost.stat("/var/log/redis", user="redis", mode="drwxr-xr-x"),
        **fakehost.directory("/etc/redis"),
        **config_file(render_config(cfg, password)),
        **fakehost.service("redis-server.service"),
        "printf 'ping|%s": [f"{key}|{value}" for key, value in state.items()],
        "stat -c %a ": ["755"],
    }


def run(responses: dict[str, Any], cfg: RedisInstallConfig = CFG, password: SecretStr | None = PASSWORD) -> FakeRun:
    result = run_deploy_fake(deploy_redis_install, cfg, password, responses=responses)
    assert result.succeeded, result.error
    return result


def test_converged_host_changes_nothing_but_the_check() -> None:
    result = run(converged())

    assert result.mutating_changed_ops == []
    assert result.changed_ops == [PING]
    # The check reads the password from stdin; nothing else carries it.
    assert result.stdin == [(result.stdin[0][0], PASSWORD.get_secret_value() + "\n")]
    assert "REDISCLI_AUTH" in result.stdin[0][0]
    assert "redis-cli -h 127.0.0.1 -p 6379 PING" in result.stdin[0][0]
    assert PASSWORD.get_secret_value() not in result.all_text()


def test_changed_config_is_backed_up_written_and_applied() -> None:
    responses = converged()
    responses.update(config_file("# apt default\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [
        "Redis | Back up /etc/redis/redis.conf",
        WRITE,
        "Redis | Restart redis-server for the new configuration",
    ]
    backup = next(c for c in result.executed_commands if "umask 077" in c)
    assert backup == (
        'b=/etc/redis/redis.conf."$$".$(date +%Y-%m-%d@%H:%M:%S)~ && (umask 077 && cp /etc/redis/redis.conf "$b") '
        '&& chown root:redis "$b" && chmod 0640 "$b"'
    )
    # The file itself goes over stdin to the secret installer, never as an upload.
    assert result.uploaded_paths == []
    assert PASSWORD.get_secret_value() not in result.all_text()


def test_restart_can_be_turned_off() -> None:
    cfg = RedisInstallConfig(requirepass_enabled=True, restart_on_change=False)
    responses = converged(cfg)
    responses.update(config_file("# apt default\n"))

    result = run(responses, cfg)

    assert not any("restart" in command for command in result.executed_commands)


def test_server_answering_without_password_is_restarted() -> None:
    result = run(converged(ping="PONG"))

    assert result.mutating_changed_ops == ["Redis | Restart redis-server if it runs an older configuration"]
    assert "systemctl restart redis-server" in result.executed_commands


def test_config_newer_than_server_is_applied() -> None:
    result = run(converged(conf="3000"))

    assert result.mutating_changed_ops == ["Redis | Restart redis-server if it runs an older configuration"]


def test_needs_restart() -> None:
    cfg = RedisInstallConfig()
    assert needs_restart(cfg, ["ping|PONG", "conf|1", "start|2"]) is None
    assert needs_restart(cfg, ["ping|PONG", "conf|2", "start|2"]) is None
    assert needs_restart(cfg, ["ping|PONG", "conf|3", "start|2"]) == "redis.conf is newer than the running server"
    # Unknown times (stopped server, missing file) never trigger a restart.
    assert needs_restart(cfg, ["ping|", "conf|3", "start|"]) is None
    assert needs_restart(RedisInstallConfig(restart_on_change=False), ["conf|3", "start|2"]) is None
    assert needs_restart(CFG, ["ping|PONG", "conf|1", "start|2"]) == "Redis answers without a password"


def test_loose_backups_are_restricted() -> None:
    responses = converged()
    responses["find /etc/redis -maxdepth 1"] = ["/etc/redis/redis.conf.1.2025-01-01@00:00:00~"]

    result = run(responses)

    assert result.mutating_changed_ops == ["Redis | Restrict earlier Redis configuration backups"]
    assert "chmod 0640 '/etc/redis/redis.conf.1.2025-01-01@00:00:00~'" in result.executed_commands


def test_without_password() -> None:
    cfg = RedisInstallConfig(bind_addresses=("127.0.0.1",), check_host="::1")

    result = run(converged(cfg, None), cfg, None)

    assert result.mutating_changed_ops == []
    assert result.stdin == []
    assert "redis-cli -h ::1 -p 6379 PING" in "\n".join(result.executed_commands)


def test_fresh_host() -> None:
    result = run({**LINUX, "command -v apt-get": ["/usr/bin/apt-get"]})

    commands = "\n".join(result.executed_commands)
    assert "redis-server redis-tools" in commands
    assert "umask 077" not in commands  # nothing to back up yet
    # The package may create them setgid after planning; cleared after creation.
    assert commands.index("mkdir -p /etc/redis") < commands.index("chmod u-s,g-s,o-t /etc/redis")
    assert any(name == WRITE for name in result.changed_ops)


def test_official_repository() -> None:
    cfg = RedisInstallConfig(add_official_repo=True, apt_suite="noble")

    result = run({**LINUX, "command -v apt-get": ["/usr/bin/apt-get"]}, cfg, None)

    # Served armored, stored binary under .gpg (apt ignores an armored .gpg).
    assert any("| gpg --dearmor --yes -o" in c for c in result.executed_commands)
    assert result.upload("/etc/apt/sources.list.d/redis-official.sources").decode() == (
        "Components: main\nEnabled: yes\nX-Repolib-Name: redis-official\n"
        "Signed-By: /usr/share/keyrings/redis-official-archive-keyring.gpg\n"
        "Suites: noble\nTypes: deb\nURIs: https://packages.redis.io/deb\n"
    )


@pytest.mark.parametrize(
    ("password", "message"),
    [
        (None, "a password is required"),
        (SecretStr(""), "a password is required"),
        (SecretStr("ChangeMe"), "placeholder"),
        (SecretStr("two words"), "whitespace"),
        (SecretStr("line\nbreak"), "whitespace"),
        (SecretStr('quote"broken'), "quotes"),
        (SecretStr("'single'"), "quotes"),
    ],
)
def test_refuses_bad_passwords(password: SecretStr | None, message: str) -> None:
    result = run_deploy_fake(deploy_redis_install, CFG, password, responses=converged())

    assert not result.succeeded
    assert message in str(result.error)
    assert result.executed_commands == []


@pytest.mark.parametrize(
    "fields",
    [
        {"bind_addresses": ()},
        {"bind_addresses": ("127.0.0.1 0.0.0.0",)},
        {"port": 70000},
        {"databases": 0},
        {"maxmemory": "1 gb"},
        {"maxmemory_policy": "lru"},
        {"appendfsync": "sometimes"},
        {"tcp_backlog": 0},
        {"timeout": -1},
        {"save_rules": ("900",)},
        {"validate_config": True},
        {"unknown": 1},
    ],
)
def test_config_rejects(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RedisInstallConfig(**fields)


def test_setgid_directories_are_cleared_like_ansible() -> None:
    # The Ubuntu package creates /etc/redis setgid; Ansible's chmod clears it.
    # First match wins: the specific response goes before the generic one.
    responses = {"stat -c %a /etc/redis": ["2755"], **converged()}

    result = run(responses)

    assert "chmod u-s,g-s,o-t /etc/redis" in result.executed_commands
    assert result.mutating_changed_ops == ["Redis | Clear special mode bits on /etc/redis"]


def test_armored_official_key_is_converted_binary_left_alone() -> None:
    cfg = RedisInstallConfig(add_official_repo=True, apt_suite="noble")
    key = "/usr/share/keyrings/redis-official-archive-keyring.gpg"
    base = {**LINUX, "command -v apt-get": ["/usr/bin/apt-get"], **fakehost.file(key, "x")}

    armored = run({f"head -c 10 {key}": ["-----BEGIN"], **base}, cfg, None)
    assert any("gpg --dearmor" in c for c in armored.executed_commands)
    commands = armored.executed_commands
    assert any("gnupg" in c and "install" in c for c in commands)
    # The cache is refreshed only after the key is repaired (the broken key would fail it).
    dearmor = next(i for i, c in enumerate(commands) if "gpg --dearmor" in c)
    assert all("apt-get update" not in c for c in commands[:dearmor])
    assert any("apt-get update" in c for c in commands[dearmor:])

    fresh = run({**LINUX, "command -v apt-get": ["/usr/bin/apt-get"]}, cfg, None).executed_commands
    first = next(i for i, c in enumerate(fresh) if "gpg --dearmor" in c)
    assert any("apt-get update" in c for c in fresh[:first])  # a fresh host has no index yet

    sources = "/etc/apt/sources.list.d/redis-official.sources"
    missing_key = run({**LINUX, "command -v apt-get": ["/usr/bin/apt-get"], **fakehost.file(sources, "x")}, cfg, None)
    commands = missing_key.executed_commands
    first = next(i for i, c in enumerate(commands) if "gpg --dearmor" in c)
    assert all("apt-get update" not in c for c in commands[:first])

    binary = run({f"head -c 10 {key}": ["\x99\x01"], **base}, cfg, None)
    assert not any("gpg --dearmor" in c for c in binary.executed_commands)
