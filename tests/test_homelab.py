"""Deploy-level scenarios for homelab against the fake connector."""

import base64
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.base import UvInstallConfig
from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.homelab import HomelabConfig, deploy_homelab
from ops_deploy.services.homelab.deploy import (
    DEFAULT_SERVICES_CHECK,
    render_env,
    render_route,
    render_unit,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.homelab_fixtures import SOURCE_FILES, make_source

HOME = "/home/homelab"
SITE = f"{HOME}/site"
DB = f"{SITE}/db.sqlite3"
UNIT = "/etc/systemd/system/homelab.service"
ROUTE = "/etc/traefik/dynamic/homelab.yml"
SECRET_KEY = "homelab-fixture-django-secret-key-0123456789"
SECRET_VALUES = {"django_secret_key": SECRET_KEY, "basic_auth_password": "homelab-fixture-basic-pw"}
AS_HOMELAB = f"cd {SITE} && runuser -u homelab -- env HOME={HOME}"
UV_VENV = f"{AS_HOMELAB} /usr/local/bin/uv venv --python 3.14 {SITE}/.venv"
UV_SYNC = f"{AS_HOMELAB} VIRTUAL_ENV={SITE}/.venv /usr/local/bin/uv sync --frozen"
ITEMIZED_CHANGE = [">f.st...... src/config/urls.py"]
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])
P = "Deploy homelab | "
READ_ONLY = [f"{P}Require /usr/local/bin/uv"]
# Probe commands (substrings of the fact commands).
VENV_VERSION = f"{SITE}/.venv/bin/python --version"
VENV_LINK = f"[ -e {SITE}/venv ]"
VENV_PRESENT = f"[ -e {SITE}/.venv ]"
OWNERSHIP = f"find {SITE} \\( ! -user homelab"
DEPS = "uv sync --frozen --check"
MIGRATIONS = "migrate --check --plan"
DB_MODE = f"stat -c '%U:%G %a' {DB}"
STATIC = "collectstatic --noinput --dry-run"
SERVICES = "manage.py shell -c"


@pytest.fixture
def cfg(tmp_path: Path) -> HomelabConfig:
    return HomelabConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/homelab.yml"),
        traefik_host="home.example.com",
        django_allowed_hosts="127.0.0.1,home.example.com",
    )


def values(cfg: HomelabConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: HomelabConfig) -> SecretValues:
    return values(cfg)


def converged(cfg: HomelabConfig, secrets: SecretValues, **drift: Any) -> dict[str, Any]:
    """Facts of a host where homelab is fully deployed."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets).reveal().decode(),
        UNIT: render_unit(cfg),
        ROUTE: render_route(cfg, traefik_config(cfg, secrets), _HASH),
    }
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("homelab", HOME),
        VENV_VERSION: ["Python 3.14.2"],
        VENV_LINK: ["present"],
        DEPS: ["current"],
        MIGRATIONS: ["current"],
        DB_MODE: ["homelab:homelab 644"],
        STATIC: ["current"],
        SERVICES: ["current"],
    }
    for path in ("", "/site", "/site/staticfiles", "/site/cache", "/site/media/services", "/site/media/services/logos"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="homelab"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "homelab" if path.startswith(SITE) else "root"
        private = path == f"{SITE}/.env"
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    for name in ("manage.py", "pyproject.toml", "uv.lock"):
        mode = "-rwxr-xr-x" if name == "manage.py" else "-rw-r--r--"
        responses.update(fakehost.file(f"{SITE}/{name}", SOURCE_FILES[name], user="homelab", mode=mode))
    responses.update(fakehost.service("homelab.service"))
    responses.update(drift)
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: HomelabConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_homelab, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


def changed(*names: str) -> list[str]:
    return [f"{P}{name}" for name in names]


def test_first_run_installs_everything(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/homelab -s /bin/bash -g homelab -r -M homelab" in commands
    migrate = next(c for c in commands if "manage.py migrate --noinput" in c)
    db_mode = next(c for c in commands if f"chmod 0644 {DB}" in c)
    collect = next(c for c in commands if "manage.py collectstatic --noinput'" in c)
    services = next(c for c in commands if "manage.py add_default_services" in c)
    order = [UV_VENV, UV_SYNC, migrate, db_mode, collect, services, "systemctl start homelab.service"]
    assert [commands.index(c) for c in order] == sorted(commands.index(c) for c in order)
    assert "systemctl restart homelab.service" not in commands
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    # Only .env goes over stdin; the top-level files and the route are plain uploads.
    assert len(run.stdin) == 1
    assert {f"{SITE}/manage.py", f"{SITE}/pyproject.toml", f"{SITE}/uv.lock", UNIT, ROUTE} <= set(run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    assert f"{P}Create venv symlink to .venv" in run.mutating_changed_ops


def test_second_run_changes_nothing_mutating(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    # The deployed hash is kept: no route rewrite, and Traefik is never restarted.
    assert not any("traefik" in c for c in run.executed_commands)


def test_code_change_syncs_and_reruns_the_django_steps(cfg: HomelabConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == changed(
        "Sync homelab src",
        "Install dependencies with uv sync",
        "Run Django migrations",
        "Collect static files",
        "Add default services with logos",
        "Restart homelab.service",
    )


def test_sync_adds_src_without_delete_and_with_the_roles_excludes(cfg: HomelabConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" not in real
    assert real[-2] == f"{cfg.source_path}/src/"
    assert real[-1].endswith(f"{SITE}/src/")
    assert "--chown=homelab:homelab" in real
    for pattern in ("__pycache__", "*.pyc", ".pytest_cache", ".coverage", "htmlcov", ".mypy_cache"):
        assert f"--exclude={pattern}" in real


def test_media_is_synced_without_delete_and_restarts_nothing(tmp_path: Path) -> None:
    cfg = HomelabConfig(source_path=make_source(tmp_path, media=True), secrets=SecretRef("secrets/prod/homelab.yml"))
    secrets = values(cfg)
    rsync = RecordingRsyncRunner(responses={"media/ ": [">f+++++++++ services/logos/app.png"]})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == changed("Sync homelab media")
    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert real[-2:] == [f"{cfg.source_path}/media/", real[-1]]
    assert real[-1].endswith(f"{SITE}/media/")
    assert "--delete" not in real
    assert "--exclude=.gitkeep" in real


def test_no_media_in_the_checkout_syncs_none(cfg: HomelabConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner()

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert all("/media/" not in " ".join(call) for call in rsync.calls)


def test_top_level_file_change_reinstalls_and_restarts(cfg: HomelabConfig, secrets: SecretValues) -> None:
    drift = fakehost.file(f"{SITE}/uv.lock", "version = 0\n", user="homelab")

    run = deploy(cfg, secrets, converged(cfg, secrets, **drift))

    assert run.mutating_changed_ops == changed(
        "Copy uv.lock to site directory",
        "Install dependencies with uv sync",
        "Run Django migrations",
        "Collect static files",
        "Restart homelab.service",
    )


def test_env_change_rewrites_env_and_restarts(cfg: HomelabConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_secret_key="rotated-homelab-fixture-secret-key-0123")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == changed(
        "Create environment file for Django",
        "Run Django migrations",
        "Collect static files",
        "Restart homelab.service",
    )


def test_basic_auth_rotation_only_touches_the_route(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_password="rotated-fixture-pw"), converged(cfg, secrets))

    assert run.mutating_changed_ops == changed("Write Traefik route homelab")
    assert not any("traefik" in c and "systemctl" in c for c in run.executed_commands)


def test_basic_auth_user_comes_from_the_secret(cfg: HomelabConfig, secrets: SecretValues) -> None:
    route = render_route(cfg, traefik_config(cfg, values(cfg, basic_auth_user="ops")), _HASH)

    assert f'          - "ops:{_HASH}"' in route.splitlines()


@pytest.mark.parametrize("version", ["Python 3.12.3", ""])
def test_outdated_or_broken_venv_is_removed_and_rebuilt(
    cfg: HomelabConfig, secrets: SecretValues, version: str
) -> None:
    drift = {VENV_VERSION: [version] if version else [], VENV_PRESENT: ["present"]}

    run = deploy(cfg, secrets, converged(cfg, secrets, **drift))

    assert run.mutating_changed_ops == changed(
        f"Remove broken or outdated venv {SITE}/.venv",
        "Create virtual environment using uv",
        "Install dependencies with uv sync",
        "Run Django migrations",
        "Collect static files",
        "Restart homelab.service",
    )
    commands = run.executed_commands
    assert commands.index(f"rm -rf -- {SITE}/.venv") < commands.index(UV_VENV) < commands.index(UV_SYNC)


def test_missing_venv_is_created_without_a_removal(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{VENV_VERSION: []}))

    assert f"{P}Remove broken or outdated venv {SITE}/.venv" not in run.changed_ops
    assert f"{P}Create virtual environment using uv" in run.mutating_changed_ops


def test_missing_venv_link_is_created_alone(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{VENV_LINK: []}))

    assert run.mutating_changed_ops == changed("Create venv symlink to .venv")
    assert any(c.startswith(f"ln -s .venv {SITE}/venv") for c in run.executed_commands)


def test_foreign_ownership_is_fixed_alone(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{OWNERSHIP: [f"{SITE}/media"]}))

    assert run.mutating_changed_ops == changed("Set ownership for synced files")
    assert any("-exec chown -h homelab:homelab {} +" in c for c in run.executed_commands)


def test_database_mode_is_set_to_the_roles_0644(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{DB_MODE: ["homelab:homelab 600"]}))

    assert run.mutating_changed_ops == changed("Fix database permissions")
    assert any(f"chown homelab:homelab {DB} && chmod 0644 {DB}" in c for c in run.executed_commands)


def test_pending_default_services_run_alone(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{SERVICES: ["pending"]}))

    assert run.mutating_changed_ops == changed("Add default services with logos")


def test_pending_static_files_are_collected_alone(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{STATIC: ["pending"]}))

    assert run.mutating_changed_ops == changed("Collect static files")


def test_unapplied_migrations_are_retried_and_restart(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{MIGRATIONS: ["pending"]}))

    assert run.mutating_changed_ops == changed("Run Django migrations", "Restart homelab.service")


def test_failed_uv_sync_is_retried_without_a_source_change(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{DEPS: ["pending"]}))

    assert run.mutating_changed_ops == changed(
        "Install dependencies with uv sync",
        "Run Django migrations",
        "Collect static files",
        "Restart homelab.service",
    )


@pytest.mark.parametrize(
    ("probe_key", "name"), [(SERVICES, "homelab default services"), (MIGRATIONS, "homelab migrations")]
)
def test_a_failing_probe_runs_its_step_and_probes_again(
    cfg: HomelabConfig, secrets: SecretValues, probe_key: str, name: str
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{probe_key: [FAILED]}))

    verify = run.op(f"{P}Probe again: {name}")
    assert verify.changed
    assert verify.read_only
    assert any("probe still fails" in c and probe_key in c for c in run.executed_commands)


def test_default_services_probe_is_read_only_by_construction(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    probe = next(c for c in run.fact_commands if SERVICES in c)
    assert "FileSystemStorage._save = refuse" in probe
    assert "execute_wrapper(refuse_writes)" in probe
    assert "transaction.set_rollback(True)" in probe
    # The code is an argument of bash, never interpolated into the script.
    assert 'manage.py shell -c "$1"' in probe
    assert "\\" not in DEFAULT_SERVICES_CHECK


def test_uv_install_runs_only_when_configured(tmp_path: Path) -> None:
    cfg = HomelabConfig(
        source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/homelab.yml"), uv=UvInstallConfig()
    )
    secrets = values(cfg)
    responses = {
        **converged(cfg, secrets),
        **fakehost.directory("/usr/local/bin"),
        "/usr/local/bin/uv --version": ["uv 0.14.1 (abc 2026-10-01)"],
        **fakehost.stat("/usr/local/bin/uvx"),
        "uname -m": ["x86_64"],
        "command -v curl": ["/usr/bin/curl"],
    }

    run = deploy(cfg, secrets, responses)

    # The role's pinned uv replaces another version, then the deploy itself is converged.
    assert run.mutating_changed_ops == changed("Install uv | Install uv 0.13.4 to /usr/local/bin")


def test_uv_already_pinned_is_left_alone(tmp_path: Path) -> None:
    cfg = HomelabConfig(
        source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/homelab.yml"), uv=UvInstallConfig()
    )
    secrets = values(cfg)
    responses = {
        **converged(cfg, secrets),
        **fakehost.directory("/usr/local/bin"),
        "/usr/local/bin/uv --version": ["uv 0.13.4 (abc 2026-09-01)"],
        **fakehost.stat("/usr/local/bin/uvx"),
    }

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == []


def test_missing_uv_fails_before_the_venv(cfg: HomelabConfig, secrets: SecretValues) -> None:
    responses = {**first_host(), "test -x /usr/local/bin/uv ||": {"success": False, "stderr": "uv is required"}}

    run = run_deploy_fake(deploy_homelab, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert UV_VENV not in run.executed_commands
    assert not any("manage.py migrate" in c for c in run.executed_commands)


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: HomelabConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    rotated = "r" * 60
    used = values(cfg, django_secret_key=rotated, basic_auth_password=rotated) if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (SECRET_KEY, SECRET_VALUES["basic_auth_password"], rotated):
        assert value not in text


def test_env_rides_on_stdin_only(cfg: HomelabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    for command, _ in run.stdin:
        assert SECRET_KEY not in command
    joined = "\n".join(base64.b64decode("".join(payload.split())).decode() for _, payload in run.stdin)
    assert f"DJANGO_SECRET_KEY={SECRET_KEY}" in joined.splitlines()


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "CHANGEME"}, "django_secret_key"),
        ({"django_secret_key": "has spaces-0123456789"}, "django_secret_key"),
        ({"django_secret_key": "dollar$HOME-0123456789"}, "django_secret_key"),
        ({"django_secret_key": "paren(s)-0123456789"}, "django_secret_key"),
        ({"django_secret_key": "amp&ersand-0123456789"}, "django_secret_key"),
        ({"basic_auth_password": "CHANGEME"}, "basic_auth_password"),
        ({"basic_auth_password": "x\nY=1"}, "single lines"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: HomelabConfig, changes: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_homelab, cfg, values(cfg, **changes), responses=first_host())
    assert "homelab-fixture" not in str(excinfo.value)


def test_missing_secret_key_names_only_the_key(cfg: HomelabConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="django_secret_key"):
        run_deploy_fake(
            deploy_homelab, cfg, SecretValues(cfg.secrets, {"basic_auth_password": "x"}), responses=first_host()
        )


@pytest.mark.parametrize("missing", ["src", "manage.py", "pyproject.toml", "uv.lock"])
def test_source_must_be_a_homelab_checkout(tmp_path: Path, missing: str) -> None:
    source = make_source(tmp_path)
    target = source / missing
    if target.is_dir():
        for path in sorted(target.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        target.rmdir()
    else:
        target.unlink()

    with pytest.raises(ConfigValidationError, match=f"missing {missing}"):
        HomelabConfig(source_path=source, secrets=SecretRef("secrets/prod/homelab.yml"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"django_allowed_hosts": "a b"},
        {"django_allowed_hosts": "a;rm"},
        {"django_admin_url": "$(x)/"},
        {"service_name": "home", "user": "homelab"},
        {"uv": UvInstallConfig(install_dir="/opt/bin")},
        {"uv_path": "/usr/local/bin/uvx"},
        {"site_path": "/home/home lab/site"},
        {"media_subdirs": ("../etc",)},
        {"internal_ip_ranges": ("not-a-network",)},
        {"traefik_host": "home example"},
    ],
)
def test_config_validation(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        HomelabConfig(source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), **overrides)
