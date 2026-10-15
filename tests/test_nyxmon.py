"""Deploy-level scenarios for nyxmon against the fake connector."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers.traefik import hash_password, render_route
from ops_deploy.services.nyxmon import NyxmonConfig, deploy_nyxmon
from ops_deploy.services.nyxmon.deploy import SQLITE_PRIVACY, TEMPLATE_PACKAGE, render_env, traefik_config
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.nyxmon_fixtures import SOURCE_FILES, make_source

SITE = "/home/nyxmon/site"
SECRET_VALUES = {
    "django_secret_key": "nyxmon-fixture-django-key",
    "telegram_bot_token": "123456:nyxmon-fixture-bot-token",
    "telegram_chat_id": "-100555000111",
    "basic_auth_password": "nyxmon-fixture-password",
    "opsgate_submit_token": "nyxmon-fixture-opsgate-token-0123",
}
UNITS = {
    "nyxmon": "/etc/systemd/system/nyxmon.service",
    "nyxmon-monitor": "/etc/systemd/system/nyxmon-monitor.service",
}
ROUTE = "/etc/traefik/dynamic/nyxmon.yml"
SQLITE_PROBE = f"test -f {SITE}/db.sqlite3 || echo missing"
UV_SYNC = (
    f"cd {SITE} && runuser -u nyxmon -- env HOME=/home/nyxmon UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --frozen --no-dev --no-default-groups --python 3.13"
)
OPSGATE = "http://studio.example:8711"
ITEMIZED_CHANGE = [">f.st...... views.py"]
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])


@pytest.fixture
def cfg(tmp_path: Path) -> NyxmonConfig:
    return NyxmonConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/nyxmon.yml"),
        opsgate_submit_base_url=OPSGATE,
    )


def values(cfg: NyxmonConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: NyxmonConfig) -> SecretValues:
    return values(cfg)


def converged(cfg: NyxmonConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where nyxmon is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets, shell=False).reveal().decode(),
        f"{SITE}/.env.shell": render_env(cfg, secrets, shell=True).reveal().decode(),
        UNITS["nyxmon"]: render(TEMPLATE_PACKAGE, "nyxmon.service.j2", cfg=cfg),
        UNITS["nyxmon-monitor"]: render(TEMPLATE_PACKAGE, "nyxmon-monitor.service.j2", cfg=cfg),
        ROUTE: render_route(traefik_config(cfg, secrets), _HASH),
        **{f"{SITE}/{name}": SOURCE_FILES[name] for name in ("pyproject.toml", "uv.lock", "README.md")},
        **{f"{unit}.d/sqlite-privacy.conf": SQLITE_PRIVACY for unit in UNITS.values()},
    }
    content.update(drift)
    responses: dict[str, Any] = {**fakehost.LINUX, **fakehost.system_account("nyxmon", "/home/nyxmon")}
    for path in ("", "/site", "/site/cache", "/logs", "/site/src", "/site/src/nyxmon", "/site/src/nyxboard"):
        responses.update(fakehost.directory(f"/home/nyxmon{path}", user="nyxmon"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic", *(f"{unit}.d" for unit in UNITS.values())):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        private = path.endswith((".env", ".env.shell"))
        owner = "nyxmon" if path.startswith(SITE) else "root"
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    responses[f"test -e {SITE}/venv ||"] = [
        f"user=nyxmon group=nyxmon mode=lrwxrwxrwx atime=0 mtime=0 ctime=0 size=10 '{SITE}/venv' -> '{SITE}/.venv'"
    ]
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("nyxmon.service", "nyxmon-monitor.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX, SQLITE_PROBE: ["missing"]}


def deploy(
    cfg: NyxmonConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_nyxmon, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


READ_ONLY = [
    "Deploy nyxmon | Wait for port 127.0.0.1:10017",
    "Deploy nyxmon | Check http://127.0.0.1:10017/",
    "Deploy nyxmon | Check nyxmon-monitor runs the Python agent",
    "Deploy nyxmon | Check nyxmon-monitor OpsGate settings",
]
AGENT_DROPIN = "/etc/systemd/system/nyxmon-monitor.service.d/agent-impl.conf"


def test_first_run_installs_everything(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/nyxmon -s /bin/bash -g nyxmon -r -M nyxmon" in commands
    assert UV_SYNC in commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index("systemctl start nyxmon.service")
    assert commands.index("systemctl start nyxmon.service") < commands.index("systemctl start nyxmon-monitor.service")
    assert "systemctl restart nyxmon.service" not in commands
    assert any("chmod 0600" in c for c in commands)
    # Both env files go over stdin via secret_file, never as uploads.
    assert len(run.stdin) == 2
    assert not any(path.endswith((".env", ".env.shell")) for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY


def test_second_run_changes_nothing_mutating(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any(c.startswith(("systemctl", "cd ", "find ")) for c in run.executed_commands)


def test_code_change_migrates_and_restarts_both_without_uv_sync(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Sync Django source",
        "Deploy nyxmon | Sync src/nyxmon",
        "Deploy nyxmon | Sync src/nyxboard",
        "Deploy nyxmon | uv sync /home/nyxmon/site",
        "Deploy nyxmon | manage.py migrate --noinput",
        "Deploy nyxmon | manage.py collectstatic --noinput",
        "Deploy nyxmon | Restart nyxmon.service",
        "Deploy nyxmon | Restart nyxmon-monitor.service",
    ]
    assert "systemctl daemon-reload" not in run.executed_commands


def test_django_sync_protects_host_state(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    django = next(call for call in rsync.calls if "--dry-run" not in call and f"{SITE}/" in call[-1])
    assert "--delete" in django
    assert django[-2].endswith("/src/django/")
    protected: tuple[str, ...] = ("db.sqlite3*", "*.sqlite3", "cache", ".env*", "/.env.shell", "media/")
    protected += ("staticfiles/", "/src/", "/venv")
    for pattern in (*protected, "/pyproject.toml", "/uv.lock", "/README.md", ".vault_password"):
        assert f"--exclude={pattern}" in django


def test_lockfile_change_syncs_dependencies(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/uv.lock": "version = 0\n"}))

    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Copy uv.lock",
        "Deploy nyxmon | uv sync /home/nyxmon/site",
        "Deploy nyxmon | manage.py migrate --noinput",
        "Deploy nyxmon | manage.py collectstatic --noinput",
        "Deploy nyxmon | Restart nyxmon.service",
        "Deploy nyxmon | Restart nyxmon-monitor.service",
    ]


def test_secret_rotation_rewrites_env_and_restarts_both(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, telegram_bot_token="654321:rotated-fixture-token")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Write .env",
        "Deploy nyxmon | Write .env.shell",
        "Deploy nyxmon | Restart nyxmon.service",
        "Deploy nyxmon | Restart nyxmon-monitor.service",
    ]
    assert "rotated-fixture-token" not in run.all_text()


def test_basic_auth_rotation_only_touches_traefik(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_password="rotated-fixture-password"), converged(cfg, secrets))

    # Traefik's file provider loads the new route; no restart (ops-library 2.31.47).
    assert run.mutating_changed_ops == ["Deploy nyxmon | Write Traefik route nyxmon"]
    assert not any("traefik" in command for command in run.executed_commands if command.startswith("systemctl"))


def test_rust_agent_dropin_is_removed_and_the_monitor_restarted(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    dropin = "[Service]\nExecStart=\nExecStart=/opt/nyxmon-agent/0.1.0/nyxmon-agent --db x\n"
    responses = {**converged(cfg, secrets), **fakehost.file(AGENT_DROPIN, dropin)}

    run = deploy(cfg, secrets, responses)

    # The role's agent_rust.yml with nyxmon_agent_impl: python.
    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Select the Python agent for nyxmon-monitor",
        "Deploy nyxmon | Reload systemd for nyxmon-monitor.service",
        "Deploy nyxmon | Restart nyxmon-monitor.service",
    ]
    assert f"rm -f {AGENT_DROPIN}" in run.executed_commands


def test_agent_check_wants_the_venv_start_agent(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    check = next(c for c in run.executed_commands if "start-agent" in c and "MainPID" in c)
    assert f"grep -qxF {SITE}/.venv/bin/start-agent" in check
    assert "/opt/nyxmon-agent/*) exit 1" in check


@pytest.mark.parametrize("entry", ["model_validate_json", "model_validate_strings"])
def test_agent_defaults_validate_from_text(tmp_path: Path, entry: str) -> None:
    data = {"source_path": str(make_source(tmp_path)), "secrets": {"path": "secrets/prod/nyxmon.yml"}}
    text = json.dumps(data) if entry == "model_validate_json" else data

    cfg = getattr(NyxmonConfig, entry)(text)

    assert (cfg.agent_impl, cfg.agent_rust_install_root) == ("python", "/opt/nyxmon-agent")


def test_rust_agent_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="agent_impl"):
        NyxmonConfig(source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), agent_impl="rust")


def test_basic_auth_user_from_secrets_wins(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_user="ops"), converged(cfg, secrets))

    assert "ops:$2y$05$" in run.upload(ROUTE).decode()


def test_monitor_unit_change_reloads_and_restarts_only_the_monitor(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{UNITS["nyxmon-monitor"]: "[Unit]\n"}))

    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Install systemd unit nyxmon-monitor.service",
        "Deploy nyxmon | Reload systemd for nyxmon-monitor.service",
        "Deploy nyxmon | Restart nyxmon-monitor.service",
    ]


def test_missing_umask_dropin_restarts_its_service(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets, **{f"{UNITS['nyxmon']}.d/sqlite-privacy.conf": "[Service]\n"})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy nyxmon | SQLite umask for nyxmon",
        "Deploy nyxmon | Reload systemd for nyxmon.service",
        "Deploy nyxmon | Restart nyxmon.service",
    ]


def test_exposed_database_is_restricted(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), SQLITE_PROBE: [f"{SITE}/db.sqlite3-wal"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy nyxmon | Restrict SQLite database and sidecars"]
    fix = next(c for c in run.executed_commands if "chown -h nyxmon:nyxmon" in c)
    assert '|| ! test -e "$f" || exit 1' in fix  # a vanished journal is not a failure


def test_opsgate_disabled_skips_token_and_check(tmp_path: Path) -> None:
    cfg = NyxmonConfig(source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/nyxmon.yml"))
    required = {k: SECRET_VALUES[k] for k in cfg.required_secret_keys}
    secrets = SecretValues(SecretRef("secrets/prod/nyxmon.yml"), required)

    run = deploy(cfg, secrets)

    assert READ_ONLY[-1] not in [op.name for op in run.ops]
    assert "OPSGATE" not in render_env(cfg, secrets, shell=False).reveal().decode()


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: NyxmonConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="rotated-fixture-django-key") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-django-key"):
        assert value not in text


def test_env_files_ride_on_stdin_only(cfg: NyxmonConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    for command, payload in run.stdin:
        assert SECRET_VALUES["django_secret_key"] not in command
        assert SECRET_VALUES["django_secret_key"].encode() in base64.b64decode("".join(payload.split()))


def test_short_opsgate_token_fails_before_any_operation(cfg: NyxmonConfig) -> None:
    with pytest.raises(ValueError, match="opsgate_submit_token must have") as excinfo:
        run_deploy_fake(deploy_nyxmon, cfg, values(cfg, opsgate_submit_token="short-token"), responses=first_host())
    assert "short-token" not in str(excinfo.value)


def test_multiline_secret_is_rejected(cfg: NyxmonConfig) -> None:
    with pytest.raises(ValueError, match="single lines"):
        run_deploy_fake(deploy_nyxmon, cfg, values(cfg, telegram_chat_id="1\nEVIL=1"), responses=first_host())


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("django_secret_key", "CHANGEME"),
        ("basic_auth_password", "xCHANGEMEx"),
        ("telegram_bot_token", "development-token"),
    ],
)
def test_placeholder_secret_is_rejected(cfg: NyxmonConfig, key: str, value: str) -> None:
    with pytest.raises(ValueError, match=f"placeholder values: {key}"):
        run_deploy_fake(deploy_nyxmon, cfg, values(cfg, **{key: value}), responses=first_host())


def test_middlewares_match_the_route_helper(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError):
        NyxmonConfig(
            source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), traefik_middlewares=("rate.limit@file",)
        )


def test_missing_secret_key_fails(cfg: NyxmonConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="telegram_bot_token"):
        run_deploy_fake(deploy_nyxmon, cfg, SecretValues(cfg.secrets, {"django_secret_key": "x"}))


def test_source_must_be_a_nyxmon_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a nyxmon checkout"):
        NyxmonConfig(source_path=tmp_path, secrets=SecretRef("secrets/prod/nyxmon.yml"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"notify_consecutive_failures": 0},
        {"notify_repeat_interval_seconds": 59},
        {"check_batch_size": 101},
        {"processing_lease_seconds": 599},
        {"opsgate_submit_base_url": "http://x y"},
    ],
)
def test_role_validations(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        NyxmonConfig(source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/nyxmon.yml"), **overrides)
