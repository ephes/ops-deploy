"""Deploy-level scenarios for weeknotes.home against the fake connector."""

import base64
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.helpers.postgres import scram_verifier, state_command
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.weeknotes_home import WeeknotesHomeConfig, deploy_weeknotes_home
from ops_deploy.services.weeknotes_home.deploy import (
    nyxmon_checks,
    render,
    render_env,
    render_route,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.weeknotes_home_fixtures import make_source

HOME = "/home/weeknotes-home"
SITE = f"{HOME}/site"
SERVICE_DIR = f"{SITE}/services/weeknotes_home"
UNIT = "/etc/systemd/system/weeknotes-home.service"
ROUTE = "/etc/traefik/dynamic/weeknotes-home.yml"
ENV = f"{SITE}/.env.weeknotes-home"
FD_CONFIG = "/home/fastdeploy/site/services/weeknotes-home-backup/config.json"
FD_SERVICE = {"name": "weeknotes-home-backup", "cwd": "/tmp", "deploy_script": "deploy.sh"}
SALT = b"fixture-salt-16b"
SECRET_VALUES = {
    "django_secret_key": "weeknotes-fixture-django-secret-0123",
    "postgres_password": "weeknotes-fixture-pg-password",
    "api_token": "weeknotes-fixture-api-token-0123456789abcdef",
    "basic_auth_password": "weeknotes-fixture-basic-pw",
    "fastdeploy_token_user": "fixture-fastdeploy-operator",
}
ITEMIZED_CHANGE = [">f.st...... src/daybook/views.py"]
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])
READ_ONLY = [
    "Deploy weeknotes-home | Port preflight tcp/10062",
    "Deploy weeknotes-home | Check http://127.0.0.1:10062/healthz",
]
WIRING_READ_ONLY = [
    "Deploy weeknotes-home | Check Echoport installation",
    "Deploy weeknotes-home | Check FastDeploy backup service registration",
    "Deploy weeknotes-home | Check Nyxmon installation",
]
ECHOPORT_PROBE = "test -f /home/echoport/site/manage.py &&"
NYXMON_PROBE = "test -f /home/nyxmon/site/db.sqlite3 &&"
SERVICE_ROW_PROBE = "psql -XAtq -d fastdeploy -c"
MIGRATE_CHECK = "manage.py migrate --check"
STATIC_CHECK = "manage.py collectstatic --noinput --dry-run"


@pytest.fixture
def cfg(tmp_path: Path) -> WeeknotesHomeConfig:
    return WeeknotesHomeConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/weeknotes_home.yml"),
        traefik_host="weeknotes.example.com",
        django_allowed_hosts=("127.0.0.1", "localhost", "weeknotes.example.com"),
        django_csrf_trusted_origins=("https://weeknotes.example.com",),
        cast_base_url="https://cast.example.com",
        operations_wiring=True,
    )


def values(cfg: WeeknotesHomeConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: WeeknotesHomeConfig) -> SecretValues:
    return values(cfg)


def postgres_state(password: str, *, login: str = "true", owner: str = "weeknotes_home") -> list[str]:
    verifier = scram_verifier(password, salt=SALT)
    salt_spec = verifier.split("$")[1]
    digest = hashlib.sha256(verifier.encode()).hexdigest()
    return [f"role|{login}|{salt_spec}|{digest}", f"db|{owner}", f"schema|{owner}"]


def converged(cfg: WeeknotesHomeConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where weeknotes.home and its wiring are fully deployed."""

    content = {
        ENV: render_env(cfg, secrets).reveal().decode(),
        UNIT: render("weeknotes-home.service.j2", cfg=cfg),
        ROUTE: render_route(cfg, traefik_config(cfg, secrets), _HASH),
        FD_CONFIG: json.dumps(FD_SERVICE, indent=2) + "\n",
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("weeknotes-home", HOME, shell="/bin/bash"),
        state_command("weeknotes_home", "weeknotes_home", "postgres"): postgres_state(secrets["postgres_password"]),
        MIGRATE_CHECK: ["current"],
        STATIC_CHECK: ["current"],
        ECHOPORT_PROBE: ["unchanged"],
        NYXMON_PROBE: ["changed=false"],
        SERVICE_ROW_PROBE: [json.dumps(FD_SERVICE)],
    }
    for path in ("", "/site", "/site/cache/weeknotes-home", "/site/static/weeknotes-home"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="weeknotes-home"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "weeknotes-home" if path.startswith(SITE) else "root"
        mode = "-rw-------" if path == ENV else "-rw-r--r--"
        responses.update(fakehost.file(path, text, user=owner, mode=mode))
    responses.update(fakehost.venv(f"{SITE}/.venv-weeknotes-home"))
    for unit in ("weeknotes-home.service", "traefik.service", "postgresql.service"):
        responses.update(fakehost.service(unit))
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: WeeknotesHomeConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_weeknotes_home,
        cfg,
        secrets,
        rsync=rsync or RecordingRsyncRunner(),
        responses=responses or first_host(),
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/weeknotes-home -s /bin/bash -g weeknotes-home -r -M weeknotes-home" in commands
    sync = next(c for c in commands if "uv sync" in c)
    migrate = next(c for c in commands if "migrate --noinput" in c)
    collect = next(c for c in commands if "collectstatic --noinput" in c)
    assert "--frozen --group weeknotes-home --python 3.14" in sync
    assert f"UV_PROJECT_ENVIRONMENT={SITE}/.venv-weeknotes-home" in sync
    assert commands.index(sync) < commands.index(migrate) < commands.index(collect)
    assert commands.index(collect) < commands.index("systemctl start weeknotes-home.service")
    assert "systemctl restart weeknotes-home.service" not in commands
    # The env file goes over stdin; so do the role and database statements.
    assert not any(path.endswith(".env.weeknotes-home") for path in run.uploaded_paths)
    assert {op.name for op in run.ops if op.read_only} == {*READ_ONLY, *WIRING_READ_ONLY}
    assert any("CREATE ROLE" in sql for _, sql in run.stdin)


def test_second_run_changes_nothing_mutating(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert set(run.changed_ops) == {*READ_ONLY, *WIRING_READ_ONLY}
    assert run.uploads == []
    assert run.stdin == []


def test_code_change_syncs_migrates_collects_and_restarts(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy weeknotes-home | Sync daybook source",
        "Deploy weeknotes-home | uv sync /home/weeknotes-home/site",
        "Deploy weeknotes-home | Run weeknotes-home migrations",
        "Deploy weeknotes-home | Collect weeknotes-home static files",
        "Deploy weeknotes-home | Restart weeknotes-home.service",
    ]


def test_sync_protects_host_state(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" in real
    assert real[-1].endswith(f"{SITE}/")
    for pattern in (
        "/cache",
        "/static",
        "/.env.weeknotes-home",
        "/.venv-weeknotes-home",
        ".git",
        ".envrc",
        "/src/daybook.egg-info",
    ):
        assert f"--exclude={pattern}" in real


def test_env_change_rewrites_env_runs_django_and_restarts(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_secret_key="rotated-fixture-django-secret-0123")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy weeknotes-home | Write .env.weeknotes-home",
        "Deploy weeknotes-home | Run weeknotes-home migrations",
        "Deploy weeknotes-home | Collect weeknotes-home static files",
        "Deploy weeknotes-home | Restart weeknotes-home.service",
    ]
    assert "rotated-fixture-django-secret" not in run.all_text()


def test_postgres_password_rotation_updates_role_and_env(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, postgres_password="rotated-fixture-pg-password")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops[0] == "Deploy weeknotes-home | Ensure PostgreSQL role weeknotes_home"
    assert "Deploy weeknotes-home | Write .env.weeknotes-home" in run.mutating_changed_ops
    sql = next(s for _, s in run.stdin if s.startswith("ALTER ROLE"))
    assert "SCRAM-SHA-256$4096:" in sql
    assert "rotated-fixture-pg-password" not in run.all_text() + sql


def test_basic_auth_rotation_only_touches_traefik(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_password="rotated-fixture-password"), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy weeknotes-home | Write Traefik route weeknotes-home",
        "Deploy weeknotes-home | Restart Traefik for weeknotes-home",
    ]


def test_unapplied_migrations_are_retried_without_a_code_change(
    cfg: WeeknotesHomeConfig, secrets: SecretValues
) -> None:
    responses = {**converged(cfg, secrets), MIGRATE_CHECK: []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy weeknotes-home | Run weeknotes-home migrations",
        "Deploy weeknotes-home | Restart weeknotes-home.service",
    ]


def test_static_files_to_copy_are_collected_without_a_code_change(
    cfg: WeeknotesHomeConfig, secrets: SecretValues
) -> None:
    responses = {**converged(cfg, secrets), STATIC_CHECK: []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy weeknotes-home | Collect weeknotes-home static files"]


def test_django_commands_read_secrets_from_the_env_file(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    migrate = next(c for c in run.executed_commands if "migrate --noinput" in c)
    assert f"cd {SERVICE_DIR} &&" in migrate
    assert "runuser -u weeknotes-home --" in migrate
    assert ENV in migrate
    for secret in SECRET_VALUES.values():
        assert secret not in migrate


def test_unit_runs_gunicorn_from_the_service_directory(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    unit = render("weeknotes-home.service.j2", cfg=cfg)

    assert f"WorkingDirectory={SERVICE_DIR}\n" in unit
    assert f"ExecStart={SITE}/.venv-weeknotes-home/bin/gunicorn" in unit
    assert "--bind 127.0.0.1:10062" in unit


# -- operations wiring -----------------------------------------------------------


def test_wiring_drift_is_applied(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    responses = {
        **converged(cfg, secrets),
        ECHOPORT_PROBE: ["pending"],
        NYXMON_PROBE: ["changed=true"],
        SERVICE_ROW_PROBE: [json.dumps({**FD_SERVICE, "cwd": "/elsewhere"})],
    }

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy weeknotes-home | Sync FastDeploy service row for the backup service",
        "Deploy weeknotes-home | Issue or reuse the FastDeploy token and upsert the Echoport backup target",
        "Deploy weeknotes-home | Upsert Nyxmon checks",
    ]
    sql = next(s for _, s in run.stdin if s.startswith("INSERT INTO service"))
    assert "'weeknotes-home-backup'" in sql
    assert '"cwd": "/tmp"' in sql
    assert "ON CONFLICT (name) DO UPDATE" in sql


def test_token_is_issued_and_piped_to_echoport_only_when_needed(
    cfg: WeeknotesHomeConfig, secrets: SecretValues
) -> None:
    responses = {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"]}

    run = deploy(cfg, secrets, responses)

    command, stdin = next((c, s) for c, s in run.stdin if "issueservicetoken" in c)
    assert stdin == SECRET_VALUES["fastdeploy_token_user"] + "\n"
    # The user name is on stdin and expanded on the host, never in the command.
    assert SECRET_VALUES["fastdeploy_token_user"] not in command
    # FastDeploy's CLI is called in-process; the name is in no argument list.
    assert "sys.stdin.readline().strip()" in command
    assert '--user "$fd_user"' not in command
    assert '"$fd_user" |' in command
    assert "weeknotes-home-backup" in command
    assert "--days" in command
    assert "--origin" in command
    # First pass finds out whether a token is needed; the second one stores it.
    assert command.count(".venv/bin/python manage.py shell -c") == 2
    assert "need-token" in command
    assert "2>/dev/null" in command
    assert '"mode": "apply"' in command
    assert '"restore_owner": "weeknotes-home:weeknotes-home"' in command
    assert '"schedule": "10 4 * * *"' in command
    assert '"legacy_name": "weeknotes-home"' in command
    assert '"name": "weeknotes_home"' in command


def test_wiring_scripts_are_valid_shell(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"], NYXMON_PROBE: ["changed=true"]}

    run = deploy(cfg, secrets, responses)

    scripts = [c for c, _ in run.stdin if "issueservicetoken" in c]
    scripts += [c for c in run.executed_commands if "NYXMON_MODE" in c or "migrate" in c]
    scripts += [c for c in run.fact_commands if "manage.py shell" in c]
    assert len(scripts) >= 4
    for script in scripts:
        checked = subprocess.run(["sh", "-n", "-c", script], capture_output=True, text=True, check=False)
        assert checked.returncode == 0, checked.stderr


def test_converged_wiring_issues_no_token(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert not any("issueservicetoken" in c for c in run.executed_commands)
    assert not any("manage.py shell" in c or ("nyxmon" in c and "python3" in c) for c in run.executed_commands)


def test_nyxmon_checks_match_the_playbook_shape(cfg: WeeknotesHomeConfig) -> None:
    local, backup = nyxmon_checks(cfg)

    assert local["url"] == "http://127.0.0.1:10062/healthz"
    assert local["data"] == {"timeout": 5, "retries": 2, "retry_delay": 2}
    assert backup["url"] == "http://127.0.0.1:10018/api/health/"
    assert backup["data"]["checks"][0]["path"] == "$.targets_by_name.weeknotes_home.status"
    assert backup["data"]["notification_suppression"]["active_if"][0]["value"] == 0.5
    assert backup["data"]["notification_suppression"]["reason"] == "echoport_backup_window_active"


def test_wiring_is_optional(tmp_path: Path) -> None:
    cfg = WeeknotesHomeConfig(source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/weeknotes_home.yml"))
    secrets = values(cfg)
    secrets_without_user = SecretValues(secrets.ref, {k: v for k, v in secrets.items() if k != "fastdeploy_token_user"})

    run = deploy(cfg, secrets_without_user)

    assert not any("echoport" in c or "nyxmon" in c for c in run.executed_commands + run.fact_commands)


def test_wiring_needs_the_fastdeploy_user(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    without = SecretValues(secrets.ref, {k: v for k, v in secrets.items() if k != "fastdeploy_token_user"})

    with pytest.raises(KeyError, match="fastdeploy_token_user"):
        run_deploy_fake(deploy_weeknotes_home, cfg, without, rsync=RecordingRsyncRunner(), responses=first_host())


@pytest.mark.parametrize("path", ["/home/echoport/site/manage.py", FD_CONFIG, "/home/nyxmon/site/db.sqlite3"])
def test_missing_dependency_fails_the_run(cfg: WeeknotesHomeConfig, secrets: SecretValues, path: str) -> None:
    responses = {f"test -f {path} ||": {"success": False}, **converged(cfg, secrets)}

    run = run_deploy_fake(deploy_weeknotes_home, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded


# -- secrets ---------------------------------------------------------------------


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated", "drift"])
def test_secrets_never_recorded(cfg: WeeknotesHomeConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    if scenario == "drift":
        responses = {**(responses or {}), ECHOPORT_PROBE: ["pending"]}
    used = values(cfg, django_secret_key="rotated-fixture-django-secret-0123") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-django"):
        assert value not in text


def test_secrets_ride_on_stdin_only(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"]}, None)

    for command, _ in run.stdin:
        for value in SECRET_VALUES.values():
            assert value not in command
    payloads = []
    for _, payload in run.stdin:
        try:
            payloads.append(base64.b64decode("".join(payload.split()), validate=True).decode())
        except ValueError:
            payloads.append(payload)
    assert SECRET_VALUES["fastdeploy_token_user"] in "\n".join(payloads)


def test_env_secrets_reach_the_host_only_through_stdin(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    joined = ""
    for _, payload in run.stdin:
        try:
            joined += base64.b64decode("".join(payload.split()), validate=True).decode(errors="replace")
        except ValueError:
            continue
    for key in ("django_secret_key", "api_token", "postgres_password"):
        assert SECRET_VALUES[key] in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "too-short"}, "django_secret_key"),
        ({"django_secret_key": "CHANGEME-CHANGEME-CHANGEME"}, "django_secret_key"),
        ({"postgres_password": "CHANGEME"}, "postgres_password"),
        ({"postgres_password": "pässword"}, "postgres_password"),
        ({"api_token": "short"}, "api_token"),
        ({"api_token": "CHANGEME" * 5}, "api_token"),
        ({"api_token": "a" * 31}, "api_token"),
        ({"api_token": "a" * 40 + "!"}, "api_token"),
        ({"basic_auth_password": "CHANGEME"}, "basic_auth_password"),
        ({"basic_auth_password": "tab\there"}, "basic_auth_password"),
        ({"django_secret_key": "weeknotes-fixture-django-secret\nX=1"}, "single lines"),
        ({"api_token": ""}, "api_token"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(
    cfg: WeeknotesHomeConfig, changes: dict[str, str], match: str
) -> None:
    with pytest.raises((ValueError, KeyError), match=match) as excinfo:
        run_deploy_fake(deploy_weeknotes_home, cfg, values(cfg, **changes), responses=first_host())
    assert "weeknotes-fixture" not in str(excinfo.value)


# -- config and guards -----------------------------------------------------------


def test_source_must_be_a_daybook_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a daybook checkout"):
        WeeknotesHomeConfig(source_path=tmp_path, secrets=SecretRef("secrets/prod/weeknotes_home.yml"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"django_allowed_hosts": ("a b",)},
        {"echoport_target_schedule": "10 4 * * *; rm"},
        {"traefik_middlewares": ("rate.limit@file",)},
        {"internal_ip_ranges": ("8.8.8.0/24",)},
        {"internal_ip_ranges": ("10.0.0.1/8",)},
        {"internal_ip_ranges": ()},
        {"internal_ip_ranges": ("0.0.0.0/0",)},
        {"internal_ip_ranges": ("fe80::/10",)},
        {"fastdeploy_token_days": 91},
        {"fastdeploy_token_rotate_days": 90},
        {"echoport_legacy_target_name": "weeknotes_home"},
        {"postgres_host": "db.example.com"},
        {"basic_auth_user": "ad min"},
        {"app_port": 80},
    ],
)
def test_config_validation(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        WeeknotesHomeConfig(
            source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/weeknotes_home.yml"), **overrides
        )


def test_port_collision_stops_before_any_change(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    responses = {**first_host(), "ss -Hltnp": {"success": False, "stderr": "port in use"}}

    run = run_deploy_fake(deploy_weeknotes_home, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert len(run.executed_commands) == 1
    assert "0::/system.slice/weeknotes-home.service" in run.executed_commands[0]
