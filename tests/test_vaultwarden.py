"""Deploy-level scenarios for vaultwarden against the fake connector."""

import base64
import hashlib
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.vaultwarden import (
    VaultwardenConfig,
    deploy_vaultwarden,
    render_dropin,
    render_env,
    render_route,
)
from ops_deploy.services.vaultwarden.deploy import smtp_command, smtp_request, sources_line
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

ENV = "/etc/vaultwarden.env"
DROPIN = "/etc/systemd/system/vaultwarden.service.d/override.conf"
ROUTE = "/etc/traefik/dynamic/vaultwarden.yml"
KEYRING = "/etc/apt/keyrings/vaultwarden-deb-repo-keyring.gpg"
SOURCES = "/etc/apt/sources.list.d/vaultwarden.list"
DATA = "/var/lib/vaultwarden/data"
LOGS = "/var/log/vaultwarden"
ADMIN_TOKEN = "$argon2id$v=19$m=65540,t=3,p=4$vaultwarden-fixture-admin-token"
SMTP_USER = "vaultwarden-fixture-smtp-user"
SMTP_PASSWORD = "vaultwarden-fixture-smtp-password#1"
SECRET_VALUES = {"admin_token": ADMIN_TOKEN, "smtp_username": SMTP_USER, "smtp_password": SMTP_PASSWORD}
P = "Deploy Vaultwarden | "
READ_ONLY = [
    f"{P}Port preflight tcp/8000",
    f"{P}Read installed package versions",
    f"{P}Wait for Vaultwarden to be ready",
]
# The config.json check runs ``smtp_config_sync.py check`` (a substring of the fact command).
SMTP_CHECK = "' check )"


@pytest.fixture
def cfg() -> VaultwardenConfig:
    return VaultwardenConfig(
        domain="https://vault.example.com",
        secrets=SecretRef("secrets/prod/vaultwarden.yml"),
        smtp_host="localhost",
        smtp_from="vault@example.com",
        smtp_accept_invalid_certs=True,
        smtp_accept_invalid_hostnames=True,
        traefik_entrypoint="web-secure",
    )


def values(cfg: VaultwardenConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: VaultwardenConfig) -> SecretValues:
    return values(cfg)


def env_file(content: bytes) -> dict[str, Any]:
    """``/etc/vaultwarden.env`` as the role leaves it: root:vaultwarden 0640."""

    line = f"user=root group=vaultwarden mode=-rw-r----- atime=0 mtime=0 ctime=0 size=10 '{ENV}'"
    return {
        f"sha256sum {ENV} ": [f"{hashlib.sha256(content).hexdigest()}  {ENV}"],
        f"test -e {ENV} ||": [line],
    }


def converged(cfg: VaultwardenConfig, secrets: SecretValues, **drift: Any) -> dict[str, Any]:
    """Facts of a host where the role (or this deploy) left vaultwarden fully deployed."""

    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed(
            "apt-transport-https", "ca-certificates", "curl", "gnupg", "vaultwarden", "vaultwarden-web-vault"
        ),
        **fakehost.directory("/etc/apt/keyrings"),
        **fakehost.file(KEYRING, "binary keyring"),
        **fakehost.directory("/etc/apt/sources.list.d"),
        **fakehost.file(SOURCES, sources_line(cfg, "bookworm")),
        **fakehost.directory(DATA, user="vaultwarden", mode="drwxr-x---"),
        **fakehost.directory(LOGS, user="vaultwarden", mode="drwxr-x---"),
        f"stat -c %a {DATA}": ["750"],
        f"stat -c %a {LOGS}": ["750"],
        **env_file(render_env(cfg, secrets).reveal()),
        SMTP_CHECK: ["current"],
        **fakehost.directory("/etc/systemd/system/vaultwarden.service.d"),
        **fakehost.file(DROPIN, render_dropin(cfg)),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(ROUTE, render_route(cfg)),
        **fakehost.service("vaultwarden.service"),
    }
    # Drift replaces the converged value of the same fact command.
    responses.update(drift)
    return responses


def deploy(cfg: VaultwardenConfig, secrets: SecretValues, responses: dict[str, Any]) -> FakeRun:
    run = run_deploy_fake(deploy_vaultwarden, cfg, secrets, responses=responses)
    assert run.succeeded, run.error
    return run


def changed(*names: str) -> list[str]:
    return [f"{P}{name}" for name in names]


def assert_no_secret_leaks(run: FakeRun) -> None:
    text = run.all_text()
    for value in (ADMIN_TOKEN, SMTP_USER, SMTP_PASSWORD):
        assert value not in text
        for _, stdin in run.stdin:
            assert value not in stdin  # the env file travels base64-encoded


def test_first_run_installs_everything(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**fakehost.UBUNTU, SMTP_CHECK: ["absent"]})

    commands = run.executed_commands
    assert run.ops[0].name == f"{P}Port preflight tcp/8000"
    assert run.ops[0].read_only
    assert any("vaultwarden-deb.pages.dev/vaultwarden-deb-repo-keyring.gpg" in c for c in commands)
    assert run.upload(SOURCES).decode() == (
        f"deb [signed-by={KEYRING}] https://vaultwarden-deb.pages.dev bookworm main\n"
    )
    install = next(c for c in commands if c.endswith("install vaultwarden vaultwarden-web-vault"))
    update = [i for i, c in enumerate(commands) if c == "apt-get update"]
    assert update
    assert update[-1] < commands.index(install)
    assert run.upload(DROPIN).decode() == render_dropin(cfg)
    assert run.upload(ROUTE).decode() == render_route(cfg)
    order = [install, "systemctl daemon-reload", "systemctl start vaultwarden.service"]
    assert [commands.index(c) for c in order] == sorted(commands.index(c) for c in order)
    # Just started: no restart on top, and Traefik is never touched.
    assert "systemctl restart vaultwarden.service" not in commands
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    # config.json does not exist before the first start: nothing to sync.
    assert f"{P}Sync SMTP settings to config.json" not in run.changed_ops
    # The env file only on stdin (base64); every other file is a plain upload.
    assert ENV not in run.uploaded_paths
    env_stdin = [
        stdin for command, stdin in run.stdin if command.startswith("python3 -I -c") and " vaultwarden.env " in command
    ]
    assert base64.b64decode("".join(env_stdin)) == render_env(cfg, secrets).reveal()
    assert_no_secret_leaks(run)


def test_converged_host_gets_no_mutating_operation(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploaded_paths == []
    assert "systemctl restart vaultwarden.service" not in run.executed_commands
    assert_no_secret_leaks(run)


def test_second_run_is_idempotent(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    # The second run sees what the first one wrote (the converged facts) twice in a row.
    first = deploy(cfg, secrets, converged(cfg, secrets))
    second = deploy(cfg, secrets, converged(cfg, secrets))

    assert first.mutating_changed_ops == second.mutating_changed_ops == []


def test_changed_env_file_restarts_without_daemon_reload(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **env_file(b"old content\n")))

    assert run.mutating_changed_ops == changed(f"Deploy {ENV}", "Restart vaultwarden.service")
    assert "systemctl daemon-reload" not in run.executed_commands
    assert_no_secret_leaks(run)


def test_changed_dropin_reloads_systemd_and_restarts(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **fakehost.file(DROPIN, "[Service]\n")))

    assert run.mutating_changed_ops == changed(
        "Deploy systemd override for security hardening",
        "Reload systemd for vaultwarden.service",
        "Restart vaultwarden.service",
    )


def test_changed_route_is_rewritten_without_any_restart(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **fakehost.file(ROUTE, "http: {}\n")))

    assert run.mutating_changed_ops == changed("Write Traefik route vaultwarden")
    assert not any("systemctl" in c for c in run.executed_commands)


def test_pending_config_json_is_synced_on_the_host_and_restarts(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{SMTP_CHECK: ["pending"]}))

    assert run.mutating_changed_ops == changed("Sync SMTP settings to config.json", "Restart vaultwarden.service")
    apply = next(c for c in run.executed_commands if c.endswith(" apply"))
    assert apply == smtp_command("apply")
    # The request (non-secret settings) goes over stdin, never the command line.
    assert [stdin for command, stdin in run.stdin if command == apply] == [smtp_request(cfg)]
    assert "vault@example.com" not in apply


@pytest.mark.parametrize("state", ["absent", "current"])
def test_absent_or_current_config_json_is_left_alone(cfg: VaultwardenConfig, secrets: SecretValues, state: str) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{SMTP_CHECK: [state]}))

    assert run.mutating_changed_ops == []
    assert not any(c.endswith(" apply") for c in run.executed_commands)


def test_failed_config_json_probe_runs_the_sync_and_probes_again(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{SMTP_CHECK: ["", FAILED]}))

    assert f"{P}Sync SMTP settings to config.json" in run.mutating_changed_ops
    verify = run.op(f"{P}Probe again: vaultwarden config.json SMTP settings")
    assert verify.read_only


def test_without_smtp_host_config_json_is_not_probed(secrets: SecretValues) -> None:
    cfg = VaultwardenConfig(domain="https://vault.example.com", secrets=SecretRef("secrets/prod/vaultwarden.yml"))
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert not any(" check )" in c for c in run.fact_commands)
    assert run.mutating_changed_ops == []
    env = render_env(cfg, secrets).reveal().decode()
    assert "SMTP_HOST=" not in env.replace("# SMTP_HOST=", "")
    assert SMTP_PASSWORD not in env


def test_admin_panel_disabled_needs_no_token(cfg: VaultwardenConfig) -> None:
    secrets = values(cfg, admin_enabled="false", admin_token="")
    run = deploy(cfg, secrets, converged(cfg, secrets))

    env = render_env(cfg, secrets).reveal().decode()
    assert "# Admin panel disabled (vaultwarden_admin_enabled=False)" in env
    assert "\nADMIN_TOKEN=" not in env
    assert run.mutating_changed_ops == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"admin_token": ""}, "admin_token must be set"),
        ({"admin_token": "CHANGEME"}, "admin_token must be set"),
        ({"admin_enabled": "yes"}, "admin_enabled must be a boolean"),
        ({"smtp_password": "two\nlines"}, "smtp_password must be a single line"),
        ({"admin_token": "token\r"}, "admin_token must be a single line"),
    ],
)
def test_bad_secrets_fail_before_any_operation(cfg: VaultwardenConfig, changes: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message) as caught:
        run_deploy_fake(deploy_vaultwarden, cfg, values(cfg, **changes), responses={**fakehost.UBUNTU})

    assert "two" not in str(caught.value)


@pytest.mark.parametrize(("release", "suite"), [("noble", "bookworm"), ("jammy", "bookworm"), ("trixie", "trixie")])
def test_release_selects_the_repository_suite(
    cfg: VaultwardenConfig, secrets: SecretValues, release: str, suite: str
) -> None:
    run = deploy(cfg, secrets, {**fakehost.UBUNTU, ". /etc/os-release": [release]})

    assert run.upload(SOURCES).decode().endswith(f" {suite} main\n")


def test_unsupported_release_fails_before_any_operation(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = run_deploy_fake(
        deploy_vaultwarden, cfg, secrets, responses={**fakehost.UBUNTU, ". /etc/os-release": ["focal"]}
    )

    assert not run.succeeded
    assert isinstance(run.error, DeployError)
    assert "unsupported release 'focal'" in str(run.error)
    assert run.ops == []


def test_traefik_and_health_check_can_be_turned_off(secrets: SecretValues) -> None:
    cfg = VaultwardenConfig(
        domain="https://vault.example.com",
        secrets=SecretRef("secrets/prod/vaultwarden.yml"),
        traefik_enabled=False,
        healthcheck_enabled=False,
    )
    run = deploy(cfg, secrets, {**fakehost.UBUNTU})

    assert ROUTE not in run.uploaded_paths
    assert not any("/alive" in c for c in run.executed_commands)


def test_health_check_polls_alive_on_the_rocket_port(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    check = next(c for c in run.executed_commands if "/alive" in c)
    assert "http://127.0.0.1:8000/alive" in check
    assert "seq 1 6" in check


def test_port_preflight_allows_only_the_vaultwarden_unit(cfg: VaultwardenConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    preflight = run.executed_commands[0]
    assert "sport = :8000" in preflight
    assert "0::/system.slice/vaultwarden.service" in preflight


def preflight_script(cfg: VaultwardenConfig, secrets: SecretValues) -> str:
    run = deploy(cfg, secrets, converged(cfg, secrets))
    command = run.executed_commands[0]
    assert command.startswith("sh -c ")
    return shlex.split(command)[2]


@pytest.mark.parametrize(
    ("address", "listener", "refused"),
    [
        ("127.0.0.1", "127.0.0.1:8000", True),
        ("127.0.0.1", "0.0.0.0:8000", True),
        ("127.0.0.1", "[::]:8000", True),
        ("127.0.0.1", "127.0.0.2:8000", False),
        ("127.0.0.1", "192.0.2.7:8000", False),
        ("127.0.0.2", "127.0.0.2:8000", True),
        ("127.0.0.2", "[::ffff:127.0.0.2]:8000", True),
        ("0.0.0.0", "192.0.2.7:8000", True),
        ("0.0.0.0", "[2001:db8::7]:8000", True),
    ],
)
def test_port_preflight_refuses_a_foreign_listener_on_a_colliding_address(
    tmp_path: Path, secrets: SecretValues, address: str, listener: str, refused: bool
) -> None:
    # The generated sh script against a fake ``ss``; the process is not in
    # vaultwarden.service (no /proc/<pid>/cgroup naming it), so it is foreign.
    cfg = VaultwardenConfig(domain="https://vault.example.com", rocket_address=address)
    ss = tmp_path / "ss"
    ss.write_text(f"#!/bin/sh\necho 'LISTEN 0 4096 {listener} 0.0.0.0:* users:((\"python3\",pid=999999,fd=3))'\n")
    ss.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    result = subprocess.run(
        ["sh", "-c", preflight_script(cfg, secrets)], env=env, capture_output=True, text=True, check=False
    )

    assert (result.returncode != 0) is refused
    assert ("port in use" in result.stderr) is refused


@pytest.mark.parametrize("address", ["127.0.0.1", "127.0.0.2", "0.0.0.0"])
def test_port_preflight_passes_without_listener(tmp_path: Path, secrets: SecretValues, address: str) -> None:
    cfg = VaultwardenConfig(domain="https://vault.example.com", rocket_address=address)
    ss = tmp_path / "ss"
    ss.write_text("#!/bin/sh\nexit 0\n")
    ss.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    result = subprocess.run(["sh", "-c", preflight_script(cfg, secrets)], env=env, capture_output=True, check=False)

    assert result.returncode == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"domain": "vault.example.com"},
        {"domain": "https://vault.example.com:8443"},
        {"domain": "https://vault example.com"},
        {"domain": "https://müller.example"},
        {"rocket_address": "::1"},
        {"rocket_port": 0},
        {"traefik_entrypoint": "true"},
        {"traefik_entrypoint": "web secure"},
        {"traefik_certresolver": "le: x"},
        {"smtp_host": "localhost"},
        {"smtp_from_name": "two\nlines"},
        {"user": "vw"},
        {"site_path": "/srv/vaultwarden"},
        {"healthcheck_timeout": 4},
        {"apt_repo_url": "http://vaultwarden-deb.pages.dev"},
        {"unknown": 1},
    ],
)
def test_config_rejects_what_the_role_or_its_files_cannot_take(overrides: dict[str, Any]) -> None:
    fields: dict[str, Any] = {"domain": "https://vault.example.com", **overrides}
    with pytest.raises(ConfigValidationError):
        VaultwardenConfig(**fields)


def test_domain_with_a_path_routes_its_host_name() -> None:
    cfg = VaultwardenConfig(domain="https://vault.example.com/vw")

    assert cfg.hostname == "vault.example.com"
    assert "Host(`vault.example.com`)" in render_route(cfg)
