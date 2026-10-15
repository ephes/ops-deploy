"""Deploy-level scenarios for heis against the fake connector."""

import base64
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.services.heis import HeisConfig, deploy_heis
from ops_deploy.services.heis.deploy import (
    _admin_stamp,
    _digest,
    render,
    render_env,
    render_route,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.heis_fixtures import make_source

HOME = "/home/heis"
SITE = f"{HOME}/site"
UNIT = "/etc/systemd/system/heis.service"
ROUTE = "/etc/traefik/dynamic/heis.traefik.yml"
STAMP = f"{HOME}/.ops-deploy-admin"
FQDN = "heis.example.com"
SECRET_VALUES = {
    "django_secret_key": "heis-fixture-django-key-0123456789",
    "django_admin_url": "heis-fixture-admin-url/",
    "admin_username": "fixture-admin",
    "admin_email": "admin@heis.example",
    "admin_password": "heis-fixture-admin-pw",
}
UV_SYNC = (
    f"cd {SITE} && runuser -u heis -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --frozen --no-dev --python 3.13"
)
ITEMIZED_CHANGE = [">f.st...... apps/heis/views.py"]
ADMIN_PROBE = "select username, email, is_staff"
RECONCILERS = [
    "Deploy heis | Ensure default Wagtail pages exist",
    "Deploy heis | Seed homepage content",
    "Deploy heis | Seed subpage content and chrome defaults",
]
CONTENT = [
    "Deploy heis | Mark content reconciliation pending",
    *RECONCILERS,
    "Deploy heis | Clear content reconciliation marker",
]
READ_ONLY = [
    "Deploy heis | Wait for port 127.0.0.1:10020",
    "Deploy heis | Check http://127.0.0.1:10020/",
]


@pytest.fixture
def cfg(tmp_path: Path) -> HeisConfig:
    return HeisConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/heis.yml"),
        fqdn=FQDN,
        traefik_host_rule=f"Host(`{FQDN}`) || Host(`www.{FQDN}`)",
    )


def values(cfg: HeisConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: HeisConfig) -> SecretValues:
    return values(cfg)


def admin_rows(secrets: SecretValues) -> list[str]:
    name, email = secrets["admin_username"], secrets["admin_email"]
    return [f"A {_digest(name, 1, 1, 1)}", f"B {_digest(name, email)}"]


def converged(cfg: HeisConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where heis is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets).reveal().decode(),
        f"{SITE}/gunicorn.sh": render("gunicorn.sh.j2", cfg=cfg),
        f"{HOME}/.config/fish/config.fish": render("user_config.fish.j2", cfg=cfg),
        UNIT: render("heis.service.j2", cfg=cfg),
        ROUTE: render_route(cfg),
        STAMP: _admin_stamp(cfg, secrets),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("heis", HOME, shell="/usr/bin/fish"),
        ADMIN_PROBE: admin_rows(secrets),
        "migrate --check": ["current"],
        "--python 3.13 --dry-run": ["current"],
        "staticfiles.json": ["present"],
        **fakehost.deb_installed("fish", "rsync", "sqlite3"),
    }
    for path in ("", "/site", "/site/cache", "/.config/fish"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="heis"))
    # Live hosts have ~/.config as heis:root; the deploy leaves it alone.
    responses.update(fakehost.stat(f"{HOME}/.config", user="heis", group="root", mode="drwxr-xr-x"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "heis" if path.startswith(HOME) and path != STAMP else "root"
        private = "-rw-------" if path in (f"{SITE}/.env", STAMP) else "-rw-r--r--"
        responses.update(
            fakehost.file(path, text, user=owner, mode="-rwxr-xr-x" if path.endswith("gunicorn.sh") else private)
        )
    responses[f"test -e {SITE}/venv ||"] = [
        f"user=heis group=heis mode=lrwxrwxrwx atime=0 mtime=0 ctime=0 size=10 '{SITE}/venv' -> '{SITE}/.venv'"
    ]
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("heis.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: HeisConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_heis, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: HeisConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/heis -s /usr/bin/fish -g heis -r -M heis" in commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    pages = next(c for c in commands if "manage.py setup_default_pages --hostname heis.example.com --port 443" in c)
    home = next(c for c in commands if "manage.py seed_home_content" in c)
    subpages = next(c for c in commands if "manage.py seed_subpages_content" in c)
    static = next(c for c in commands if "manage.py collectstatic --noinput" in c)
    ensure = next(c for c in commands if "manage.py ensure_superuser" in c)
    order = [UV_SYNC, migrate, pages, home, subpages, static, ensure]
    assert [commands.index(c) for c in order] == sorted(commands.index(c) for c in order)
    install = next(c for c in commands if "apt-get" in c and "install" in c)
    assert all(p in install for p in ("fish", "rsync", "sqlite3"))
    assert commands.index(install) < commands.index("useradd -d /home/heis -s /usr/bin/fish -g heis -r -M heis")
    assert commands.index(ensure) < commands.index("systemctl start heis.service")
    assert "systemctl restart heis.service" not in commands
    assert "mkdir -p /home/heis/.config" in commands
    assert "chown heis:heis /home/heis/.config" in commands
    # .env, the superuser environment and the stamp go over stdin, never as uploads.
    assert len(run.stdin) == 3
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    assert run.upload(ROUTE).decode() == render_route(cfg)
    assert run.upload(f"{SITE}/gunicorn.sh").decode() == render("gunicorn.sh.j2", cfg=cfg)
    assert ROUTE in run.uploaded_paths
    assert not any("/etc/traefik/dynamic/heis.yml" in p for p in run.uploaded_paths)


def test_second_run_changes_nothing_mutating(cfg: HeisConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any(c.startswith(("systemctl", "cd ", "find ", "chown")) for c in run.executed_commands)


def test_code_change_syncs_migrates_and_restarts(cfg: HeisConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy heis | Sync heis source",
        "Deploy heis | uv sync /home/heis/site",
        "Deploy heis | Run heis migrations",
        *CONTENT,
        "Deploy heis | Collect static files",
        "Deploy heis | Restart heis.service",
    ]
    # The role's migrations and collectstatic do not restart; the code change does.


def test_sync_never_deletes_and_protects_host_state(cfg: HeisConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" not in real
    assert "--chown=heis:heis" in real
    assert real[-1].endswith(f"{SITE}/")
    for pattern in (
        "db.sqlite3",
        "*.sqlite3",
        "media",
        "backups",
        ".venv",
        "venv",
        ".git",
        "heis-buehne-bilder.zip",
        "/.env",
        "/staticfiles",
        "/cache",
    ):
        assert f"--exclude={pattern}" in real


def test_env_change_rewrites_env_and_restarts(cfg: HeisConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_secret_key="rotated-fixture-django-key-0123456789")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    # The stamp is keyed by the Django secret, so the admin is ensured once more.
    assert run.mutating_changed_ops == [
        "Deploy heis | Write .env",
        "Deploy heis | Ensure heis admin user",
        "Deploy heis | Record heis admin user",
        "Deploy heis | Restart heis.service",
    ]
    assert "rotated-fixture-django-key" not in run.all_text()


def test_admin_password_change_only_ensures_the_admin(cfg: HeisConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, admin_password="rotated-fixture-admin-pw"), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy heis | Ensure heis admin user",
        "Deploy heis | Record heis admin user",
    ]
    assert "rotated-fixture-admin-pw" not in run.all_text()


@pytest.mark.parametrize("missing", [0, 1], ids=["not a superuser", "other email"])
def test_account_drift_is_ensured(cfg: HeisConfig, secrets: SecretValues, missing: int) -> None:
    rows = admin_rows(secrets)
    del rows[missing]
    responses = {**converged(cfg, secrets), ADMIN_PROBE: rows}

    run = deploy(cfg, secrets, responses)

    # The stamp still matches, so it is not rewritten.
    assert run.mutating_changed_ops == ["Deploy heis | Ensure heis admin user"]


def test_unapplied_migrations_are_retried_without_a_code_change(cfg: HeisConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "migrate --check": []}

    run = deploy(cfg, secrets, responses)

    # No restart: the role does not restart after migrations either.
    assert run.mutating_changed_ops == ["Deploy heis | Run heis migrations", *CONTENT]


def test_stale_environment_is_synced_without_a_code_change(cfg: HeisConfig, secrets: SecretValues) -> None:
    # An earlier run stopped after the source sync, or python_version changed.
    run = deploy(cfg, secrets, {**converged(cfg, secrets), "--python 3.13 --dry-run": []})

    assert run.mutating_changed_ops == [
        "Deploy heis | uv sync /home/heis/site",
        "Deploy heis | Run heis migrations",
        *CONTENT,
        "Deploy heis | Collect static files",
        "Deploy heis | Restart heis.service",
    ]


def test_missing_static_manifest_collects_again(cfg: HeisConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**converged(cfg, secrets), "staticfiles.json": []})

    assert run.mutating_changed_ops == ["Deploy heis | Collect static files"]


def test_wrong_ownership_is_repaired(cfg: HeisConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "-print -quit": [f"{SITE}/media/x.jpg"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy heis | Set ownership of the site tree"]
    assert f"chown -hR heis:heis {SITE}" in run.executed_commands


def test_launcher_and_unit_changes_restart(cfg: HeisConfig, secrets: SecretValues) -> None:
    launcher = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/gunicorn.sh": "#!/bin/sh\n"}))
    unit = deploy(cfg, secrets, converged(cfg, secrets, **{UNIT: "[Unit]\n"}))

    assert launcher.mutating_changed_ops == [
        "Deploy heis | Write gunicorn.sh",
        "Deploy heis | Restart heis.service",
    ]
    assert unit.mutating_changed_ops == [
        "Deploy heis | Install systemd unit heis.service",
        "Deploy heis | Reload systemd for heis.service",
        "Deploy heis | Restart heis.service",
    ]


def test_route_change_does_not_restart_traefik(cfg: HeisConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert run.mutating_changed_ops == ["Deploy heis | Write Traefik route heis"]
    assert not any("traefik" in c for c in run.executed_commands if c.startswith("systemctl"))


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: HeisConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="rotated-fixture-django-key-0123456789") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-django-key"):
        assert value not in text
    assert _admin_stamp(cfg, used).strip() not in text


def test_secrets_ride_on_stdin_only(cfg: HeisConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    payloads = []
    for command, payload in run.stdin:
        assert all(value not in command for value in SECRET_VALUES.values())
        try:
            payloads.append(base64.b64decode("".join(payload.split())).decode())
        except ValueError:
            payloads.append(payload)
    joined = "\n".join(payloads)
    assert SECRET_VALUES["django_secret_key"] in joined
    assert "ADMIN_PASSWORD=heis-fixture-admin-pw" in joined
    assert "ADMIN_USERNAME=fixture-admin" in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "CHANGEME"}, "django_secret_key"),
        ({"django_secret_key": "key\nX=1"}, "single lines"),
        ({"django_admin_url": "CHANGEME"}, "django_admin_url"),
        ({"admin_username": "CHANGEME"}, "admin_username"),
        ({"admin_password": "CHANGE_ME"}, "admin_password"),
        ({"admin_email": "a@b\nX=1"}, "single lines"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: HeisConfig, changes: dict[str, str], match: str) -> None:
    run_target = values(cfg, **changes)
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_heis, cfg, run_target, responses=first_host())
    assert "heis-fixture" not in str(excinfo.value)


@pytest.mark.parametrize("key", ["django_admin_url", "admin_username", "admin_email", "admin_password"])
def test_admin_secrets_are_required(cfg: HeisConfig, key: str) -> None:
    with pytest.raises(MissingSecretKeysError, match=key):
        run_deploy_fake(deploy_heis, cfg, values(cfg, **{key: ""}), responses=first_host())


def test_source_must_be_a_heis_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a heis checkout"):
        HeisConfig(source_path=tmp_path, secrets=SecretRef("x.yml"), fqdn=FQDN, traefik_host_rule="Host(`a.b`)")


@pytest.mark.parametrize(
    "overrides",
    [
        {"traefik_host_rule": 'Host("a.b")'},
        {"traefik_host_rule": "Host(`a`)\nx: y"},
        {"fqdn": "not a host"},
        {"django_allowed_hosts": "a b"},
        {"traefik_tls_host_rule": 'Host("a.b")'},
        {"traefik_canonical_redirect_regex": "^x$"},
        {"traefik_canonical_redirect_regex": "it's", "traefik_canonical_redirect_replacement": "y"},
        {"wagtailadmin_base_url": "ftp://x"},
        {"app_port": 80},
        {"python_version": "python3.13"},
    ],
)
def test_config_validation(tmp_path: Path, overrides: dict[str, Any]) -> None:
    base: dict[str, Any] = {"fqdn": FQDN, "traefik_host_rule": f"Host(`{FQDN}`)"}
    with pytest.raises(ConfigValidationError):
        HeisConfig(source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), **{**base, **overrides})


def test_production_switches_skip_the_content_reconcilers(cfg: HeisConfig, secrets: SecretValues) -> None:
    prod = cfg.model_copy(update={"setup_default_pages": False, "seed_content": False})

    first = deploy(prod, secrets)
    code = deploy(
        prod, secrets, converged(prod, secrets), rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})
    )

    for run in (first, code):
        assert not any(op.name in CONTENT for op in run.ops)
        assert not any("setup_default_pages" in c or "seed_" in c for c in run.executed_commands)


def test_each_switch_is_independent(cfg: HeisConfig, secrets: SecretValues) -> None:
    pages_only = deploy(cfg.model_copy(update={"seed_content": False}), secrets)
    seed_only = deploy(cfg.model_copy(update={"setup_default_pages": False}), secrets)

    assert [op.name for op in pages_only.ops if op.name in RECONCILERS] == RECONCILERS[:1]
    assert [op.name for op in seed_only.ops if op.name in RECONCILERS] == RECONCILERS[1:]


def test_failed_reconciliation_is_retried(cfg: HeisConfig, secrets: SecretValues) -> None:
    # An earlier run stopped between marking and clearing.
    responses = {**converged(cfg, secrets), ".ops-deploy-content-pending": ["pending"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == CONTENT
    assert f"touch {HOME}/.ops-deploy-content-pending" in run.executed_commands
    assert f"rm -f {HOME}/.ops-deploy-content-pending" in run.executed_commands


def test_env_quotes_like_the_role(cfg: HeisConfig, secrets: SecretValues) -> None:
    env = (
        render_env(cfg.model_copy(update={"serve_media": True}), values(cfg, django_secret_key="a b$c'd"))
        .reveal()
        .decode()
    )

    assert "DJANGO_SECRET_KEY='a b$c'\"'\"'d'\n" in env
    assert "DJANGO_ADMIN_URL=heis-fixture-admin-url/\n" in env
    assert "DJANGO_SERVE_MEDIA=True\n" in env
    assert f"WAGTAILADMIN_BASE_URL=https://{FQDN}\n" in env


def test_route_file_is_named_after_the_user(cfg: HeisConfig) -> None:
    assert str(traefik_config(cfg).path) == ROUTE
