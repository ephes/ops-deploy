"""Deploy-level scenarios for work_app against the fake connector."""

import base64
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.work_app import WorkAppConfig, deploy_work_app
from ops_deploy.services.work_app.deploy import render, render_env, render_route, traefik_config
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.work_app_fixtures import SOURCE_FILES, make_source

HOME = "/home/work"
SITE = f"{HOME}/site"
DB = f"{SITE}/db.sqlite3"
UNIT = "/etc/systemd/system/work-app.service"
ROUTE = "/etc/traefik/dynamic/work-app.yml"
SECRET_KEY = "work-fixture-django-secret-key-" + "0123456789" * 3
SECRET_VALUES = {"django_secret_key": SECRET_KEY, "basic_auth_password": "work-fixture-basic-pw"}
UV_SYNC = (
    f"cd {SITE} && runuser -u work -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --frozen --no-dev --no-install-project --python 3.14"
)
ITEMIZED_CHANGE = [">f.st...... src/config/views.py"]
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])
READ_ONLY = [
    "Deploy work_app | Port preflight tcp/10011",
    "Deploy work_app | Check http://127.0.0.1:10011/accounts/login/",
]
ECHOPORT_PROBE = "if test -e /home/echoport/site/manage.py; then"
NYXMON_PROBE = "if test -e /home/nyxmon/site/manage.py; then"


@pytest.fixture
def cfg(tmp_path: Path) -> WorkAppConfig:
    return WorkAppConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/work_app.yml"),
        traefik_host="work.example.com",
        django_allowed_hosts=("127.0.0.1", "localhost", "work.example.com"),
        django_csrf_trusted_origins=("https://work.example.com",),
        echoport_target="work_app",
        nyxmon_check=True,
    )


def values(cfg: WorkAppConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: WorkAppConfig) -> SecretValues:
    return values(cfg)


def converged(cfg: WorkAppConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where work_app and its wiring are fully deployed."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets).reveal().decode(),
        UNIT: render("work-app.service.j2", cfg=cfg),
        ROUTE: render_route(traefik_config(cfg, secrets), _HASH),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("work", HOME, shell="/usr/sbin/nologin"),
        ECHOPORT_PROBE: ["unchanged"],
        NYXMON_PROBE: ["unchanged"],
        "migrate --check": ["current"],
        "sync --frozen --no-dev --no-install-project --check": ["current"],
        "find /home/work/site/staticfiles -mindepth 1": ["present"],
        "work/site/.venv/bin/python --version": ["Python 3.14.2"],
    }
    for path in ("", "/site", "/site/staticfiles"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="work", mode="drwxr-x---"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "work" if path.startswith(SITE) else "root"
        private = path == f"{SITE}/.env"
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    for name in ("manage.py", "pyproject.toml", "uv.lock"):
        responses.update(fakehost.file(f"{SITE}/{name}", SOURCE_FILES[name], user="work"))
    responses.update(fakehost.file(DB, "sqlite", user="work", mode="-rw-------"))
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("work-app.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: WorkAppConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_work_app, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/work -s /usr/sbin/nologin -g work -r -M work" in commands
    migrate = next(c for c in commands if "manage.py migrate --noinput" in c)
    collect = next(c for c in commands if "manage.py collectstatic --noinput" in c)
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index(collect)
    assert commands.index(collect) < commands.index("systemctl start work-app.service")
    assert "systemctl restart work-app.service" not in commands
    # Only .env goes over stdin; the top-level files are plain uploads.
    assert len(run.stdin) == 1
    assert {f"{SITE}/manage.py", f"{SITE}/pyproject.toml", f"{SITE}/uv.lock"} <= set(run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    upsert = [c for c in commands if "manage.py shell -c" in c]
    assert len(upsert) == 2
    assert all('"mode": "apply"' in c for c in upsert)


def test_second_run_changes_nothing_mutating(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.stdin == []
    assert run.uploads == []


def test_code_change_syncs_migrates_collects_and_restarts(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"/src/": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy work_app | Sync work_app src/",
        "Deploy work_app | uv sync /home/work/site",
        "Deploy work_app | Run work_app migrations",
        "Deploy work_app | Collect static files",
        "Deploy work_app | Restart work-app.service",
    ]


def test_each_directory_is_synced_with_its_own_delete_and_the_roles_excludes(
    cfg: WorkAppConfig, secrets: SecretValues
) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = [call for call in rsync.calls if "--dry-run" not in call]
    assert [call[-1].rpartition(":")[2] for call in real] == [f"{SITE}/src/", f"{SITE}/ledger/"]
    for call in real:
        assert "--delete" in call
        for pattern in (".env", "*.sqlite3", "*.sqlite3-*", "__pycache__", ".venv", ".git", ".vault_password"):
            assert f"--exclude={pattern}" in call
        assert "--chown=work:work" in call


def test_top_level_file_change_restarts_without_a_sync(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    responses.update(fakehost.file(f"{SITE}/uv.lock", "version = 0\n", user="work"))

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy work_app | Copy uv.lock",
        "Deploy work_app | uv sync /home/work/site",
        "Deploy work_app | Run work_app migrations",
        "Deploy work_app | Collect static files",
        "Deploy work_app | Restart work-app.service",
    ]


def test_env_change_rewrites_env_and_restarts(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_secret_key="r" * 60)

    run = deploy(cfg, rotated, converged(cfg, secrets))

    # A new .env may point at another database, so migrations run again.
    assert run.mutating_changed_ops == [
        "Deploy work_app | Write .env",
        "Deploy work_app | Run work_app migrations",
        "Deploy work_app | Collect static files",
        "Deploy work_app | Restart work-app.service",
    ]
    assert "r" * 60 not in run.all_text()


def test_basic_auth_rotation_only_touches_the_route(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_password="rotated-fixture-password"), converged(cfg, secrets))

    # The role has no Traefik restart handler: the file provider watches the file.
    assert run.mutating_changed_ops == ["Deploy work_app | Write Traefik route work-app"]
    assert not any("traefik" in c and "restart" in c for c in run.executed_commands)


def test_unapplied_migrations_are_retried_without_a_code_change(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "migrate --check": []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy work_app | Run work_app migrations",
        "Deploy work_app | Restart work-app.service",
    ]


def test_failed_uv_sync_is_retried_without_a_source_change(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "sync --frozen --no-dev --no-install-project --check": []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy work_app | uv sync /home/work/site",
        "Deploy work_app | Run work_app migrations",
        "Deploy work_app | Collect static files",
        "Deploy work_app | Restart work-app.service",
    ]


def test_files_newer_than_the_service_restart_it(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "ExecMainStartTimestamp": ["stale"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy work_app | Service started before the deployed files",
        "Deploy work_app | Restart work-app.service",
    ]
    probe = next(c for c in run.fact_commands if "ExecMainStartTimestamp" in c)
    assert "__pycache__" in probe


def test_env_change_runs_migrations(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, django_secret_key="r" * 60), converged(cfg, secrets))

    assert "Deploy work_app | Run work_app migrations" in run.mutating_changed_ops


def test_migration_check_never_touches_a_missing_database(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    # A first run: the probe tests for the database and .env before asking Django.
    run = deploy(cfg, secrets)

    probe = next(c for c in run.fact_commands if "migrate --check" in c)
    assert probe.index("test -e /home/work/site/db.sqlite3") < probe.index("migrate --check")


def test_empty_static_root_is_collected(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "find /home/work/site/staticfiles -mindepth 1": []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy work_app | Collect static files",
        "Deploy work_app | Restart work-app.service",
    ]


def test_outdated_venv_is_removed_and_rebuilt(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {
        **converged(cfg, secrets),
        **fakehost.directory(f"{SITE}/.venv", user="work"),
        "work/site/.venv/bin/python --version": ["Python 3.12.3"],
    }

    run = deploy(cfg, secrets, responses)

    assert "Deploy work_app | Remove outdated venv /home/work/site/.venv" in run.mutating_changed_ops
    assert "Deploy work_app | uv sync /home/work/site" in run.mutating_changed_ops
    assert f"rm -rf {SITE}/.venv" in run.executed_commands


def test_database_permissions_are_restricted(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), **fakehost.file(DB, "sqlite", user="work", mode="-rw-r--r--")}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy work_app | Restrict database permissions"]


def test_wiring_drift_is_applied(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"], NYXMON_PROBE: ["pending"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy work_app | Upsert Echoport backup target",
        "Deploy work_app | Upsert Nyxmon health check",
    ]
    echoport = next(c for c in run.executed_commands if "/home/echoport/site" in c and "manage.py shell" in c)
    assert '"schedule": "10 2 * * *"' in echoport
    assert '"restore_owner": "work:work"' in echoport
    assert '"service_name": "work-app.service"' in echoport
    nyxmon = next(c for c in run.executed_commands if "/home/nyxmon/site" in c and "manage.py shell" in c)
    assert "http://127.0.0.1:10011/healthz" in nyxmon
    assert "Work app login page" in nyxmon


def test_wiring_is_optional(tmp_path: Path) -> None:
    cfg = WorkAppConfig(source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/work_app.yml"))

    run = deploy(cfg, values(cfg))

    assert not any("echoport" in c or "nyxmon" in c for c in run.executed_commands + run.fact_commands)


def test_wiring_refuses_a_host_without_the_target_app(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"]}

    run = deploy(cfg, secrets, responses)

    apply = next(c for c in run.executed_commands if "Echoport must be deployed" in c)
    assert apply.index("test -f /home/echoport/site/manage.py") < apply.index("exit 1")


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: WorkAppConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="r" * 60) if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (SECRET_KEY, SECRET_VALUES["basic_auth_password"], "r" * 60):
        assert value not in text


def test_env_rides_on_stdin_only(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    for command, _ in run.stdin:
        assert SECRET_KEY not in command
    joined = "\n".join(base64.b64decode("".join(payload.split())).decode() for _, payload in run.stdin)
    assert f"DJANGO_SECRET_KEY={SECRET_KEY}" in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "too-short"}, "django_secret_key"),
        ({"django_secret_key": "CHANGEME" + "x" * 60}, "django_secret_key"),
        ({"django_secret_key": "has spaces " + "x" * 60}, "django_secret_key"),
        ({"django_secret_key": "dollar$" + "x" * 60}, "django_secret_key"),
        ({"basic_auth_password": "CHANGEME"}, "basic_auth_password"),
        ({"basic_auth_password": "x\nY=1"}, "single lines"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: WorkAppConfig, changes: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_work_app, cfg, values(cfg, **changes), responses=first_host())
    assert "work-fixture" not in str(excinfo.value)


def test_missing_secret_key_names_only_the_key(cfg: WorkAppConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="django_secret_key"):
        run_deploy_fake(
            deploy_work_app,
            cfg,
            SecretValues(cfg.secrets, {"basic_auth_password": "x"}),
            responses=first_host(),
        )


def test_source_must_be_a_work_ledger_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a work-ledger checkout"):
        WorkAppConfig(source_path=tmp_path, secrets=SecretRef("secrets/prod/work_app.yml"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"django_allowed_hosts": ("a b",)},
        {"django_allowed_hosts": ()},
        {"django_csrf_trusted_origins": ("https://a;rm",)},
        {"evidence_base_url": "https://a/$(x)"},
        {"echoport_schedule": "10 2 * * *; rm"},
        {"traefik_middlewares": ("rate.limit@file",)},
        {"healthcheck_path": "login"},
    ],
)
def test_config_validation(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        WorkAppConfig(source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), **overrides)


def test_port_collision_stops_before_any_change(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**first_host(), "ss -Hltnp": {"success": False, "stderr": "port in use"}}

    run = run_deploy_fake(deploy_work_app, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert len(run.executed_commands) == 1
    assert "0::/system.slice/work-app.service" in run.executed_commands[0]


def test_failed_health_check_fails_the_deploy(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "curl -sS": {"success": False}}
    # the check loops in a single shell command; a failing command fails the op
    run = run_deploy_fake(deploy_work_app, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded


def test_a_failing_migrations_probe_runs_migrate_and_probes_again(cfg: WorkAppConfig, secrets: SecretValues) -> None:
    # The probe crashed (not "pending"): the step runs, then the probe must pass.
    responses = {**converged(cfg, secrets), "migrate --check": [FAILED]}

    run = deploy(cfg, secrets, responses)

    assert run.succeeded
    assert "Deploy work_app | Run work_app migrations" in run.mutating_changed_ops
    verify = run.op("Deploy work_app | Probe again: work_app migrations")
    assert verify.changed
    assert verify.read_only
    assert any("migrate --check --plan" in c and "probe still fails" in c for c in run.executed_commands)
