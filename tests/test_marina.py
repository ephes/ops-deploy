"""Deploy-level scenarios for marina against the fake connector."""

import base64
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.marina import MarinaConfig, deploy_marina
from ops_deploy.services.marina.deploy import (
    _admin_stamp,
    _digest,
    render,
    render_env,
    render_route,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.marina_fixtures import make_source

HOME = "/home/marina"
SITE = f"{HOME}/site"
UNIT = "/etc/systemd/system/marina.service"
ROUTE = "/etc/traefik/dynamic/marina.traefik.yml"
STAMP = f"{HOME}/.ops-deploy-admin"
FQDN = "marina.example.com"
SECRET_VALUES = {
    "django_secret_key": "marina-fixture-django-key-0123456789",
    "admin_username": "fixture-admin",
    "admin_email": "admin@marina.example",
    "admin_password": "marina-fixture-admin-pw",
}
UV_SYNC = (
    f"cd {SITE} && runuser -u marina -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --frozen --no-dev --python 3.13"
)
ITEMIZED_CHANGE = [">f.st...... apps/marina/views.py"]
ADMIN_PROBE = "select username, email, is_staff"
READ_ONLY = [
    "Deploy marina | Wait for port 127.0.0.1:10019",
    "Deploy marina | Check http://127.0.0.1:10019/",
]


@pytest.fixture
def cfg(tmp_path: Path) -> MarinaConfig:
    return MarinaConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/marina.yml"),
        fqdn=FQDN,
        traefik_host_rule=f"Host(`{FQDN}`) || Host(`www.{FQDN}`)",
    )


def values(cfg: MarinaConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: MarinaConfig) -> SecretValues:
    return values(cfg)


def admin_rows(secrets: SecretValues) -> list[str]:
    name, email = secrets["admin_username"], secrets["admin_email"]
    return [f"A {_digest(name, 1, 1, 1)}", f"B {_digest(name, email)}"]


def converged(cfg: MarinaConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where marina is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets).reveal().decode(),
        f"{SITE}/gunicorn.sh": render("gunicorn.sh.j2", cfg=cfg),
        f"{HOME}/.config/fish/config.fish": render("user_config.fish.j2", cfg=cfg),
        UNIT: render("marina.service.j2", cfg=cfg),
        ROUTE: render_route(cfg),
        STAMP: _admin_stamp(cfg, secrets),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("marina", HOME, shell="/usr/bin/fish"),
        ADMIN_PROBE: admin_rows(secrets),
        "migrate --check": ["current"],
        "--python 3.13 --dry-run": ["current"],
        "staticfiles.json": ["present"],
    }
    for path in ("", "/site", "/site/cache", "/.config/fish"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="marina"))
    # Live hosts have ~/.config as marina:root; the deploy leaves it alone.
    responses.update(fakehost.stat(f"{HOME}/.config", user="marina", group="root", mode="drwxr-xr-x"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "marina" if path.startswith(HOME) and path != STAMP else "root"
        private = "-rw-------" if path in (f"{SITE}/.env", STAMP) else "-rw-r--r--"
        responses.update(
            fakehost.file(path, text, user=owner, mode="-rwxr-xr-x" if path.endswith("gunicorn.sh") else private)
        )
    responses[f"test -e {SITE}/venv ||"] = [
        f"user=marina group=marina mode=lrwxrwxrwx atime=0 mtime=0 ctime=0 size=10 '{SITE}/venv' -> '{SITE}/.venv'"
    ]
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("marina.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: MarinaConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_marina, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: MarinaConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/marina -s /usr/bin/fish -g marina -r -M marina" in commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    static = next(c for c in commands if "manage.py collectstatic --noinput" in c)
    ensure = next(c for c in commands if "manage.py ensure_superuser" in c)
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index(static) < commands.index(ensure)
    assert commands.index(ensure) < commands.index("systemctl start marina.service")
    assert "systemctl restart marina.service" not in commands
    assert "mkdir -p /home/marina/.config" in commands
    assert "chown marina:marina /home/marina/.config" in commands
    # .env, the superuser environment and the stamp go over stdin, never as uploads.
    assert len(run.stdin) == 3
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    assert run.upload(ROUTE).decode() == render_route(cfg)
    assert run.upload(f"{SITE}/gunicorn.sh").decode() == render("gunicorn.sh.j2", cfg=cfg)
    assert ROUTE in run.uploaded_paths
    assert not any("/etc/traefik/dynamic/marina.yml" in p for p in run.uploaded_paths)


def test_second_run_changes_nothing_mutating(cfg: MarinaConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any(c.startswith(("systemctl", "cd ", "find ", "chown")) for c in run.executed_commands)


def test_code_change_syncs_migrates_and_restarts(cfg: MarinaConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy marina | Sync marina source",
        "Deploy marina | uv sync /home/marina/site",
        "Deploy marina | Run marina migrations",
        "Deploy marina | Collect static files",
        "Deploy marina | Restart marina.service",
    ]
    # The role's migrations and collectstatic do not restart; the code change does.


def test_sync_never_deletes_and_protects_host_state(cfg: MarinaConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" not in real
    assert "--chown=marina:marina" in real
    assert real[-1].endswith(f"{SITE}/")
    for pattern in ("db.sqlite3", "*.sqlite3", "media", "backups", ".venv", ".git", "/.env", "/staticfiles", "/cache"):
        assert f"--exclude={pattern}" in real


def test_env_change_rewrites_env_and_restarts(cfg: MarinaConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_secret_key="rotated-fixture-django-key-0123456789")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    # The stamp is keyed by the Django secret, so the admin is ensured once more.
    assert run.mutating_changed_ops == [
        "Deploy marina | Write .env",
        "Deploy marina | Ensure marina admin user",
        "Deploy marina | Record marina admin user",
        "Deploy marina | Restart marina.service",
    ]
    assert "rotated-fixture-django-key" not in run.all_text()


def test_admin_password_change_only_ensures_the_admin(cfg: MarinaConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, admin_password="rotated-fixture-admin-pw"), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy marina | Ensure marina admin user",
        "Deploy marina | Record marina admin user",
    ]
    assert "rotated-fixture-admin-pw" not in run.all_text()


@pytest.mark.parametrize("missing", [0, 1], ids=["not a superuser", "other email"])
def test_account_drift_is_ensured(cfg: MarinaConfig, secrets: SecretValues, missing: int) -> None:
    rows = admin_rows(secrets)
    del rows[missing]
    responses = {**converged(cfg, secrets), ADMIN_PROBE: rows}

    run = deploy(cfg, secrets, responses)

    # The stamp still matches, so it is not rewritten.
    assert run.mutating_changed_ops == ["Deploy marina | Ensure marina admin user"]


def test_unapplied_migrations_are_retried_without_a_code_change(cfg: MarinaConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "migrate --check": []}

    run = deploy(cfg, secrets, responses)

    # No restart: the role does not restart after migrations either.
    assert run.mutating_changed_ops == ["Deploy marina | Run marina migrations"]


def test_stale_environment_is_synced_without_a_code_change(cfg: MarinaConfig, secrets: SecretValues) -> None:
    # An earlier run stopped after the source sync, or python_version changed.
    run = deploy(cfg, secrets, {**converged(cfg, secrets), "--python 3.13 --dry-run": []})

    assert run.mutating_changed_ops == [
        "Deploy marina | uv sync /home/marina/site",
        "Deploy marina | Run marina migrations",
        "Deploy marina | Collect static files",
        "Deploy marina | Restart marina.service",
    ]


def test_missing_static_manifest_collects_again(cfg: MarinaConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**converged(cfg, secrets), "staticfiles.json": []})

    assert run.mutating_changed_ops == ["Deploy marina | Collect static files"]


def test_wrong_ownership_is_repaired(cfg: MarinaConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "-print -quit": [f"{SITE}/media/x.jpg"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy marina | Set ownership of the site tree"]
    assert f"chown -hR marina:marina {SITE}" in run.executed_commands


def test_launcher_and_unit_changes_restart(cfg: MarinaConfig, secrets: SecretValues) -> None:
    launcher = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/gunicorn.sh": "#!/bin/sh\n"}))
    unit = deploy(cfg, secrets, converged(cfg, secrets, **{UNIT: "[Unit]\n"}))

    assert launcher.mutating_changed_ops == [
        "Deploy marina | Write gunicorn.sh",
        "Deploy marina | Restart marina.service",
    ]
    assert unit.mutating_changed_ops == [
        "Deploy marina | Install systemd unit marina.service",
        "Deploy marina | Reload systemd for marina.service",
        "Deploy marina | Restart marina.service",
    ]


def test_route_change_does_not_restart_traefik(cfg: MarinaConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert run.mutating_changed_ops == ["Deploy marina | Write Traefik route marina"]
    assert not any("traefik" in c for c in run.executed_commands if c.startswith("systemctl"))


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: MarinaConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="rotated-fixture-django-key-0123456789") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-django-key"):
        assert value not in text
    assert _admin_stamp(cfg, used).strip() not in text


def test_secrets_ride_on_stdin_only(cfg: MarinaConfig, secrets: SecretValues) -> None:
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
    assert "ADMIN_PASSWORD=marina-fixture-admin-pw" in joined
    assert "ADMIN_USERNAME=fixture-admin" in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "CHANGEME"}, "django_secret_key"),
        ({"django_secret_key": "key-with-$dollar-0123456789"}, "django_secret_key may only use"),
        ({"django_secret_key": "key with space"}, "django_secret_key may only use"),
        ({"django_secret_key": "key\nX=1"}, "django_secret_key may only use"),
        ({"admin_email": "a@b\nX=1"}, "single lines"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: MarinaConfig, changes: dict[str, str], match: str) -> None:
    run_target = values(cfg, **changes)
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_marina, cfg, run_target, responses=first_host())
    assert "marina-fixture" not in str(excinfo.value)


@pytest.mark.parametrize("key", ["admin_username", "admin_email", "admin_password"])
def test_admin_secrets_are_required(cfg: MarinaConfig, key: str) -> None:
    with pytest.raises(MissingSecretKeysError, match=key):
        run_deploy_fake(deploy_marina, cfg, values(cfg, **{key: ""}), responses=first_host())


def test_source_must_be_a_marina_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a marina checkout"):
        MarinaConfig(source_path=tmp_path, secrets=SecretRef("x.yml"), fqdn=FQDN, traefik_host_rule="Host(`a.b`)")


@pytest.mark.parametrize(
    "overrides",
    [
        {"traefik_host_rule": 'Host("a.b")'},
        {"traefik_host_rule": "Host(`a`)\nx: y"},
        {"fqdn": "not a host"},
        {"django_allowed_hosts": "a b"},
        {"django_admin_url": "admin/ x"},
        {"app_port": 80},
        {"python_version": "python3.13"},
    ],
)
def test_config_validation(tmp_path: Path, overrides: dict[str, Any]) -> None:
    base: dict[str, Any] = {"fqdn": FQDN, "traefik_host_rule": f"Host(`{FQDN}`)"}
    with pytest.raises(ConfigValidationError):
        MarinaConfig(source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), **{**base, **overrides})


def test_hardening_is_rendered_only_when_enabled(cfg: MarinaConfig, secrets: SecretValues) -> None:
    hardened = cfg.model_copy(update={"systemd_hardening": True})

    run = deploy(hardened, secrets, converged(cfg, secrets))

    unit = run.upload(UNIT).decode()
    assert "ProtectSystem=strict" in unit
    assert f"ReadWritePaths={SITE} {SITE}/cache" in unit
    assert "ProtectSystem" not in render("marina.service.j2", cfg=cfg)


def test_route_file_is_named_after_the_user(cfg: MarinaConfig) -> None:
    assert str(traefik_config(cfg).path) == ROUTE


def test_a_failing_migrations_probe_runs_migrate_and_probes_again(cfg: MarinaConfig, secrets: SecretValues) -> None:
    # The probe crashed (not "pending"): the step runs, then the probe must pass.
    responses = {**converged(cfg, secrets), "migrate --check": [FAILED]}

    run = deploy(cfg, secrets, responses)

    assert run.succeeded
    assert "Deploy marina | Run marina migrations" in run.mutating_changed_ops
    verify = run.op("Deploy marina | Probe again: marina migrations")
    assert verify.changed
    assert verify.read_only
    assert any("migrate --check --plan" in c and "probe still fails" in c for c in run.executed_commands)
