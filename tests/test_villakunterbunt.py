"""Deploy-level scenarios for villakunterbunt against the fake connector."""

import base64
import os
import shlex
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.villakunterbunt import VillakunterbuntConfig, deploy_villakunterbunt
from ops_deploy.services.villakunterbunt.deploy import (
    BUILD_STAMP,
    CSRF_CHECK,
    MEDIA_MOVE,
    PENDING,
    LegacyGuard,
    UrlCheck,
    code_lines,
    legacy_guard_script,
    media_move_script,
    purge_script,
    quiesced_script,
    render,
    render_env,
    render_route,
    url_check_script,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.test_remote_shell_execution import LOGIN_SHELLS, run_remote
from tests.villakunterbunt_fixtures import MIDDLEWARE_PROD, make_source

HOME = "/home/villakunterbunt"
SITE = f"{HOME}/site"
DATA = f"{HOME}/data"
VENV = f"{SITE}/django/.venv"
UNITS = "/etc/systemd/system"
ROUTE = "/etc/traefik/dynamic/villakunterbunt.traefik.yml"
FQDN = "villakunterbunt.staging.example.com"
MAILGUN = "https://mailgun.example.org/v3"
SECRET_VALUES = {
    "django_secret_key": "fixture-django-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz",
    "bootstrap_admin_password": "fixture-bootstrap-password",
    "django_admin_url_path": "/fixture-django-admin/",
    "wagtail_admin_url_path": "/fixture-wagtail-admin/",
    "django_mailgun_api_key": "fixture-mailgun-api-key",
    "mailgun_api_url": MAILGUN,
    "mailgun_sender_domain": "mg.fixture.example",
    "django_default_from_email": "Villa <villa@fixture.example>",
    "django_server_email": "Server <server@fixture.example>",
    "django_email_subject_prefix": "[Fixture] ",
}
# Values that must never show up in commands, op arguments or uploads.
SECRET_ONLY = [v for k, v in SECRET_VALUES.items() if k not in ("mailgun_api_url",)]
ITEMIZED_CHANGE = [">f.st...... django/app/views.py"]
STAMP = f"NODE_ENV=production WAGTAIL_BASE_URL=http://127.0.0.1:10025 NEXT_PUBLIC_FQDN={FQDN}"
BASE = f"https://{FQDN}"
PUBLIC_CHECKS = [
    f"Check {BASE}/",
    f"Check {BASE}/members",
    f"Check {BASE}/preview/",
    f"Check the CSRF origin of {BASE}",
]
READ_ONLY = [
    f"Deploy villakunterbunt | {name}"
    for name in (
        "Require Node.js and uv",
        "Check purged public files are absent",
        "Check no legacy code is served",
        "Wait for port 127.0.0.1:10025",
        "Check http://127.0.0.1:10025/",
        "Wait for port 127.0.0.1:10026",
        "Check http://127.0.0.1:10026/cms/login",
        *PUBLIC_CHECKS,
    )
]
V = "Deploy villakunterbunt | "
MARK_SOURCE = f"{V}Mark the source change pending"
CLEAR = f"{V}Clear the pending markers"
RESTART_DJANGO = f"{V}Restart villakunterbunt-django.service"
RESTART_NEXT = f"{V}Restart villakunterbunt-next.service"
BUILD = f"{V}Build the Next.js app (npm ci, next build)"
# Everything a source change runs after the sync.
SOURCE_STEPS = [
    f"{V}Mark villakunterbunt-django for a restart and collectstatic (dependencies)",
    f"{V}uv sync /home/villakunterbunt/site/django",
    f"{V}Run migrations",
    f"{V}Collect static files",
    f"{V}Import content",
    BUILD,
    f"{V}Remove purged public files",
    RESTART_DJANGO,
    RESTART_NEXT,
    CLEAR,
]
LEFT = "ls -1A | grep"


@pytest.fixture
def cfg(tmp_path: Path) -> VillakunterbuntConfig:
    return make_cfg(make_source(tmp_path))


# An application shaped like the real one, with made-up names.
APP: dict[str, Any] = {
    "next_path_prefixes": ("/cms", "/_next"),
    "middleware_from": "middleware.prod.ts",
    "content_import_command": "import_content",
    "private_media_moves": ("documents",),
    "purged_public_dirs": ("uploads",),
    "legacy_guard": LegacyGuard(tokens=("jwtVerify",), dirs=("*/app/admin",), search=("nextjs/.next/standalone",)),
    "next_check_path": "/cms/login",
    "csrf_check_path": "/cms-api/session/",
    "public_checks": (
        UrlCheck(path="/", retries=10, delay=6),
        UrlCheck(path="/members", status=302, follow=False),
        UrlCheck(path="/preview/", contains=('name="robots"', "noindex")),
    ),
    "refused_admin_url_paths": ("/hidden-admin/", "/wagtail-admin/"),
    "reserved_admin_url_paths": ("/static/", "/media/"),
    "extra_source_excludes": ("/tests",),
}


def make_cfg(source: Path, **overrides: Any) -> VillakunterbuntConfig:
    return VillakunterbuntConfig(
        source_path=source,
        secrets=SecretRef("secrets/staging/villakunterbunt.yml"),
        fqdn=FQDN,
        mailgun_api_url=MAILGUN,
        bootstrap_admin_email="admin@fixture.example",
        **{**APP, **overrides},
    )


def values(cfg: VillakunterbuntConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: VillakunterbuntConfig) -> SecretValues:
    return values(cfg)


def converged(cfg: VillakunterbuntConfig, secrets: SecretValues, **drift: Any) -> dict[str, Any]:
    """Facts of staging after a deploy; ``drift`` overrides file content (by path) or probe answers."""

    content = {
        f"{SITE}/gunicorn.sh": render("gunicorn.sh.j2", cfg=cfg),
        f"{SITE}/next.sh": render("next.sh.j2", cfg=cfg),
        f"{SITE}/nextjs/middleware.ts": MIDDLEWARE_PROD,
        f"{HOME}/.config/fish/config.fish": render("user_config.fish.j2", cfg=cfg),
        f"{UNITS}/villakunterbunt-django.service": render("django.service.j2", cfg=cfg),
        f"{UNITS}/villakunterbunt-next.service": render("next.service.j2", cfg=cfg),
        ROUTE: render_route(cfg),
    }
    env = render_env(cfg, secrets)
    content.update({k: v for k, v in drift.items() if k.startswith("/")})
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("villakunterbunt", HOME, shell="/usr/bin/fish"),
        "sync --locked --no-dev --dry-run": ["current"],
        "migrate --check": ["current"],
        "staticfiles.json": ["present"],
        "auth_user where username": ["present"],
        "bootstrap-admin-password-applied && echo present": ["present"],
        f"{BUILD_STAMP} 2>/dev/null": [STAMP, "built"],
        **fakehost.venv(VENV),
    }
    responses.update({k: v for k, v in drift.items() if not k.startswith("/")})
    for path in ("", "/site", "/site/nextjs", "/site/cache", "/.config/fish"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="villakunterbunt"))
    for path in ("/data", "/data/media", "/data/private_media"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="villakunterbunt", mode="drwxr-x---"))
    # The playbook leaves ~/.config and the files it renders with group root.
    responses.update(fakehost.stat(f"{HOME}/.config", user="villakunterbunt", group="root", mode="drwxr-xr-x"))
    for path in (UNITS, "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "villakunterbunt" if path.startswith(HOME) else "root"
        mode = "-rwxr-xr-x" if path.endswith(".sh") else "-rw-r--r--"
        responses.update(fakehost.file(path, text, user=owner, mode=mode))
    responses.update(fakehost.file(f"{SITE}/.env", env.reveal().decode(), user="villakunterbunt", mode="-rw-------"))
    for unit in ("villakunterbunt-django.service", "villakunterbunt-next.service"):
        responses.update(fakehost.service(unit))
    return responses


def deploy(
    cfg: VillakunterbuntConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_villakunterbunt,
        cfg,
        secrets,
        rsync=rsync or RecordingRsyncRunner(),
        responses=responses or {**fakehost.LINUX},
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    # A new host has no documents marker yet.
    first = {**fakehost.LINUX, "then echo pending; fi": ["pending"]}
    run = deploy(cfg, secrets, first, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/villakunterbunt -s /usr/bin/fish -g villakunterbunt -r -M villakunterbunt" in commands
    order = [
        next(i for i, c in enumerate(commands) if marker in c)
        for marker in (
            "legacy-documents-migrated",
            f"touch {SITE}/{PENDING}",
            "uv sync --locked --no-dev",
            "manage.py migrate --noinput",
            "manage.py collectstatic --noinput --clear",
            "manage.py import_content",
            "manage.py createsuperuser --noinput --username admin --email admin@fixture.example",
            "manage.py shell -c",
            "npm ci --no-audit --no-fund",
            "systemctl start villakunterbunt-django.service",
            "systemctl start villakunterbunt-next.service",
            f"rm -f {PENDING} ",
        )
    ]
    assert order == sorted(order)
    assert not any(c.startswith("systemctl restart") for c in commands)
    # .env, the superuser password and the bootstrap password: stdin only.
    assert len(run.stdin) == 3
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert run.upload(ROUTE).decode() == render_route(cfg)
    assert run.upload(f"{SITE}/nextjs/middleware.ts").decode() == MIDDLEWARE_PROD
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    for path in (DATA, f"{DATA}/media", f"{DATA}/private_media"):
        assert f"chmod 750 {path}" in commands


def test_second_run_changes_nothing_mutating(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []


def test_code_change_runs_every_source_step_and_restarts_both(
    cfg: VillakunterbuntConfig, secrets: SecretValues
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=RecordingRsyncRunner({"--dry-run": ITEMIZED_CHANGE}))

    assert run.mutating_changed_ops == [MARK_SOURCE, f"{V}Sync the source", *SOURCE_STEPS]
    build = next(c for c in run.executed_commands if "npm ci" in c)
    assert f"rm -f {BUILD_STAMP}" in build
    assert "env NODE_ENV=production WAGTAIL_BASE_URL=http://127.0.0.1:10025" in build
    assert f"NEXT_PUBLIC_FQDN={FQDN} npm run build" in build
    assert f"> {BUILD_STAMP}" in build


def test_a_run_that_stopped_after_the_sync_is_repeated(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    # The sync went through, something later failed: the marker is still there.
    run = deploy(cfg, secrets, converged(cfg, secrets, **{LEFT: [PENDING]}))

    assert run.mutating_changed_ops == [MARK_SOURCE, *SOURCE_STEPS]


def test_middleware_drift_counts_as_a_source_change(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    drift = {f"{SITE}/nextjs/middleware.ts": "import { jwtVerify } from 'jose';\n"}

    run = deploy(cfg, secrets, converged(cfg, secrets, **drift))

    assert run.mutating_changed_ops == [
        MARK_SOURCE,
        f"{V}Install nextjs/middleware.prod.ts as nextjs/middleware.ts",
        *SOURCE_STEPS,
    ]


@pytest.mark.parametrize(
    ("unit", "restart"), [("villakunterbunt-django", RESTART_DJANGO), ("villakunterbunt-next", RESTART_NEXT)]
)
def test_a_restart_left_by_a_failed_run_is_repeated(
    cfg: VillakunterbuntConfig, secrets: SecretValues, unit: str, restart: str
) -> None:
    # An earlier run changed what the unit reads (perhaps its unit file), then
    # failed before or at its restart: systemd is reloaded and the unit restarted.
    run = deploy(cfg, secrets, converged(cfg, secrets, **{LEFT: [f".ops-deploy-restart-{unit}"]}))

    assert run.mutating_changed_ops == [
        f"{V}Mark {unit} for a restart",
        f"{V}Reload systemd for {unit}.service",
        restart,
        CLEAR,
    ]
    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index(f"systemctl restart {unit}.service")


def test_collectstatic_owed_by_a_failed_run_is_repeated(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    # New dependencies were installed, then the run failed before collectstatic.
    run = deploy(cfg, secrets, converged(cfg, secrets, **{LEFT: [".ops-deploy-collectstatic"]}))

    assert run.mutating_changed_ops == [f"{V}Collect static files", RESTART_DJANGO, CLEAR]


def test_dependency_changes_owe_collectstatic(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"sync --locked --no-dev --dry-run": ["pending"]}))

    mark = next(c for c in run.executed_commands if c.startswith("touch ") and "collectstatic" in c)
    assert mark == f"touch {SITE}/.ops-deploy-restart-villakunterbunt-django {SITE}/.ops-deploy-collectstatic"


def test_markers_are_written_before_the_changes(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_mailgun_api_key="rotated-fixture-mailgun-key")
    run = deploy(cfg, rotated, converged(cfg, secrets), rsync=RecordingRsyncRunner({"--dry-run": ITEMIZED_CHANGE}))

    names = run.mutating_changed_ops
    assert names.index(MARK_SOURCE) < names.index(f"{V}Sync the source")
    assert names.index(f"{V}Mark villakunterbunt-django for a restart") < names.index(f"{V}Write .env")
    assert names[-1] == CLEAR
    clear = run.executed_commands[-1]
    assert clear == (
        f"cd {SITE} && rm -f {PENDING} .ops-deploy-collectstatic .ops-deploy-restart-villakunterbunt-django "
        ".ops-deploy-restart-villakunterbunt-next"
    )


def test_sync_deletes_but_protects_host_state(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" in real
    assert "--chown=villakunterbunt:villakunterbunt" in real
    assert real[-1].endswith(f"{SITE}/")
    for pattern in (
        "/nextjs/public/uploads/***",
        "/django/staticfiles",
        "node_modules",
        ".venv",
        ".next",
        "/tests",
        "/.env",
        "/gunicorn.sh",
        "/next.sh",
        "/cache",
        "/nextjs/middleware.ts",
        ".ops-deploy-*",
    ):
        assert f"--exclude={pattern}" in real


def test_env_change_rewrites_env_and_restarts_django_only(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, django_mailgun_api_key="rotated-fixture-mailgun-key")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        f"{V}Mark villakunterbunt-django for a restart",
        f"{V}Write .env",
        f"{V}Reload systemd for villakunterbunt-django.service",
        RESTART_DJANGO,
        CLEAR,
    ]
    assert "rotated-fixture-mailgun-key" not in run.all_text()


@pytest.mark.parametrize("answer", [["other stamp", "built"], [STAMP], []], ids=["env", "no build", "no stamp"])
def test_stale_build_is_rebuilt(cfg: VillakunterbuntConfig, secrets: SecretValues, answer: list[str]) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{BUILD_STAMP} 2>/dev/null": answer}))

    assert run.mutating_changed_ops == [BUILD, f"{V}Remove purged public files", RESTART_NEXT, CLEAR]
    assert next(c for c in run.executed_commands if "npm ci" in c).startswith(
        f"touch {SITE}/.ops-deploy-restart-villakunterbunt-next && "
    )


def test_build_url_change_rebuilds_and_rewrites(tmp_path: Path, secrets: SecretValues) -> None:
    old = make_cfg(make_source(tmp_path))
    new = old.model_copy(update={"django_port": 10030})

    run = deploy(new, secrets, converged(old, secrets))

    assert BUILD in run.mutating_changed_ops
    assert "Deploy villakunterbunt | Write next.sh" in run.mutating_changed_ops
    assert "Deploy villakunterbunt | Restart villakunterbunt-next.service" in run.mutating_changed_ops
    assert "Deploy villakunterbunt | Restart villakunterbunt-django.service" in run.mutating_changed_ops


def test_unapplied_migrations_and_missing_static_are_repaired(
    cfg: VillakunterbuntConfig, secrets: SecretValues
) -> None:
    migrations = deploy(cfg, secrets, converged(cfg, secrets, **{"migrate --check": []}))
    static = deploy(cfg, secrets, converged(cfg, secrets, **{"staticfiles.json": []}))

    assert migrations.mutating_changed_ops == ["Deploy villakunterbunt | Run migrations"]
    assert static.mutating_changed_ops == [f"{V}Collect static files", RESTART_DJANGO, CLEAR]


def test_stale_environment_is_synced(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"sync --locked --no-dev --dry-run": ["pending"]}))

    assert run.mutating_changed_ops == [
        f"{V}Mark villakunterbunt-django for a restart and collectstatic (dependencies)",
        f"{V}uv sync /home/villakunterbunt/site/django",
        f"{V}Run migrations",
        f"{V}Collect static files",
        RESTART_DJANGO,
        CLEAR,
    ]


def test_failed_dependency_probe_syncs_and_probes_again(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"sync --locked --no-dev --dry-run": [FAILED]}))

    names = [op.name for op in run.ops]
    sync = names.index("Deploy villakunterbunt | uv sync /home/villakunterbunt/site/django")
    again = names.index("Deploy villakunterbunt | Probe again: villakunterbunt dependencies")
    assert sync < again
    assert run.op("Deploy villakunterbunt | Probe again: villakunterbunt dependencies").read_only


def test_missing_bootstrap_admin_is_created(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"auth_user where username": ["absent"]}))

    assert run.mutating_changed_ops == ["Deploy villakunterbunt | Create the bootstrap admin"]
    [(command, payload)] = run.stdin
    assert "DJANGO_SUPERUSER_PASSWORD=fixture-bootstrap-password" in payload
    assert "fixture-bootstrap-password" not in command


def test_bootstrap_password_is_set_once(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"bootstrap-admin-password-applied && echo present": []}))

    assert run.mutating_changed_ops == ["Deploy villakunterbunt | Set the bootstrap admin password (first deploy only)"]
    [(command, payload)] = run.stdin
    assert f"touch {DATA}/.bootstrap-admin-password-applied" in command
    assert "BOOTSTRAP_ADMIN_PASSWORD=fixture-bootstrap-password" in payload


def test_legacy_documents_and_uploads_are_moved_and_removed(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    drift = {"then echo pending; fi": ["pending"], "! -name .gitkeep \\) -print -quit": ["nextjs/public/uploads/a"]}

    run = deploy(cfg, secrets, converged(cfg, secrets, **drift))

    assert run.mutating_changed_ops == [
        "Deploy villakunterbunt | Move media/documents into private storage",
        "Deploy villakunterbunt | Remove purged public files",
    ]
    move = next(c for c in run.executed_commands if "legacy-documents-migrated" in c)
    # Both units stand still while files move, and run again afterwards.
    assert move.startswith("running=$(for u in villakunterbunt-next.service villakunterbunt-django.service;")
    assert 'if [ -n "$loaded" ] && ! systemctl stop $loaded;' in move


def test_launcher_unit_and_route_changes(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    launcher = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/next.sh": "#!/bin/sh\n"}))
    unit = deploy(cfg, secrets, converged(cfg, secrets, **{f"{UNITS}/villakunterbunt-django.service": "[Unit]\n"}))
    route = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert launcher.mutating_changed_ops == [
        f"{V}Mark villakunterbunt-next for a restart",
        f"{V}Write next.sh",
        f"{V}Reload systemd for villakunterbunt-next.service",
        RESTART_NEXT,
        CLEAR,
    ]
    assert unit.mutating_changed_ops == [
        f"{V}Mark villakunterbunt-django for a restart",
        f"{V}Install systemd unit villakunterbunt-django.service",
        f"{V}Reload systemd for villakunterbunt-django.service",
        RESTART_DJANGO,
        CLEAR,
    ]
    # The playbook relies on Traefik's file watch; nothing is restarted.
    assert route.mutating_changed_ops == ["Deploy villakunterbunt | Write Traefik route villakunterbunt"]


def test_public_checks_can_be_skipped(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg.model_copy(update={"skip_public_smoke_checks": True}), secrets, converged(cfg, secrets))

    assert run.changed_ops == [name for name in READ_ONLY if name.split(" | ")[1] not in PUBLIC_CHECKS]


def test_extra_hosts_are_checked_too(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(make_source(tmp_path), extra_django_allowed_hosts=("www.villakunterbunt.example.com",))

    run = deploy(cfg, secrets)

    assert "Deploy villakunterbunt | Check https://www.villakunterbunt.example.com/members" in run.changed_ops


@pytest.mark.parametrize("scenario", ["first", "converged", "code change"])
def test_secrets_never_recorded(cfg: VillakunterbuntConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    rsync = RecordingRsyncRunner({"--dry-run": ITEMIZED_CHANGE} if scenario == "code change" else {})

    run = deploy(cfg, secrets, responses, rsync=rsync)

    text = run.all_text() + repr(run.ops)
    for value in SECRET_ONLY:
        assert value not in text


def test_secrets_ride_on_stdin_only(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    payloads = []
    for command, payload in run.stdin:
        assert all(value not in command for value in SECRET_ONLY)
        try:
            payloads.append(base64.b64decode("".join(payload.split())).decode())
        except ValueError:
            payloads.append(payload)
    joined = "\n".join(payloads)
    assert f"DJANGO_SECRET_KEY='{SECRET_VALUES['django_secret_key']}'" in joined
    assert "BOOTSTRAP_ADMIN_PASSWORD=fixture-bootstrap-password" in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "too-short"}, "django_secret_key must have at least 50"),
        ({"bootstrap_admin_password": "CHANGEME-later"}, "bootstrap_admin_password"),
        ({"django_mailgun_api_key": "CHANGEME"}, "django_mailgun_api_key"),
        ({"mailgun_api_url": "https://other.example.org/v3"}, "mailgun_api_url"),
        ({"django_admin_url_path": "/hidden-admin/"}, "django_admin_url_path must not be the default"),
        ({"wagtail_admin_url_path": "wagtail-admin"}, "wagtail_admin_url_path must not be the default"),
        ({"django_admin_url_path": "/cms/admin/"}, "reserved prefix"),
        ({"wagtail_admin_url_path": "_next"}, "reserved prefix"),
        ({"wagtail_admin_url_path": "static/x"}, "reserved prefix"),
        ({"wagtail_admin_url_path": "fixture-django-admin"}, "must differ"),
        ({"django_admin_url_path": "/"}, "django_admin_url_path must be a URL path"),
        ({"django_admin_url_path": "/a'b/"}, "django_admin_url_path must be a URL path"),
        ({"django_server_email": "a@b\nX=1"}, "single lines"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(
    cfg: VillakunterbuntConfig, changes: dict[str, str], match: str
) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_villakunterbunt, cfg, values(cfg, **changes), responses={**fakehost.LINUX})

    for value in changes.values():
        if len(value) > 3:
            assert value not in str(excinfo.value)


def test_missing_secret_keys_fail(cfg: VillakunterbuntConfig) -> None:
    assert cfg.secrets is not None
    partial = SecretValues(cfg.secrets, {"django_secret_key": SECRET_VALUES["django_secret_key"]})

    with pytest.raises(MissingSecretKeysError):
        run_deploy_fake(deploy_villakunterbunt, cfg, partial, responses={**fakehost.LINUX})


def test_source_must_have_both_apps(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a Django plus Next"):
        make_cfg(tmp_path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"purged_public_dirs": ("..",)},
        {"purged_public_dirs": (".",)},
        {"private_media_moves": ("../x",)},
        {"middleware_from": "../middleware.ts"},
        {"legacy_guard": {"search": ("nextjs/../..",)}},
        {"next_path_prefixes": ("/cms/",)},
        {"next_path_prefixes": ("/",)},
        {"next_path_prefixes": ()},
    ],
)
def test_unsafe_names_and_prefixes_are_refused(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises((ConfigValidationError, ValueError)):
        make_cfg(make_source(tmp_path), **overrides)


def test_middleware_must_exist_in_the_source(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="middleware_from"):
        make_cfg(make_source(tmp_path), middleware_from="missing.ts")


def test_generic_defaults_have_no_application_steps(tmp_path: Path, secrets: SecretValues) -> None:
    bare = VillakunterbuntConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/staging/villakunterbunt.yml"),
        fqdn=FQDN,
        mailgun_api_url=MAILGUN,
        bootstrap_admin_email="admin@fixture.example",
    )

    run = deploy(bare, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    names = " ".join(op.name for op in run.ops)
    for absent in ("middleware", "Import content", "private storage", "purged", "legacy code", "CSRF"):
        assert absent not in names
    assert f"Check {BASE}/" in names
    assert "Path(`/_next`) || PathPrefix(`/_next/`))" in render_route(bare)


def test_config_defaults_mirror_the_playbook(cfg: VillakunterbuntConfig) -> None:
    assert (cfg.django_port, cfg.next_port, cfg.gunicorn_workers) == (10025, 10026, 3)
    assert cfg.allowed_hosts == f"{FQDN},localhost,127.0.0.1"
    assert cfg.csrf_trusted_origins == f"https://{FQDN}"
    assert cfg.host_rule == f"Host(`{FQDN}`)"
    assert str(cfg.sqlite_path) == f"{DATA}/db.sqlite3"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("planted", "fails"),
    [
        ({}, False),
        # Under node_modules: unrelated dependency internals are ignored.
        ({"nextjs/.next/standalone/node_modules/jose/index.js": "jwtVerify"}, False),
        ({"nextjs/.next/standalone/nextjs/server.js": "jwtVerify(token)"}, True),
        ({"nextjs/app/api/admin/route.ts": "export {}"}, True),
        ({"nextjs/app/page.ts": "cookies.get('admin_session')"}, True),
        # A forbidden token on a line that also names node_modules still counts.
        ({"nextjs/.next/standalone/nextjs/chunk.js": "require('./node_modules/jose');jwtVerify(t)"}, True),
        # Dependencies are not the app: their directories do not count.
        ({"nextjs/.next/standalone/node_modules/x/app/api/admin/index.js": "x"}, False),
        # Tokens are fixed strings: the dot matches only a dot.
        ({"nextjs/app/x.ts": "legacyXauth"}, False),
        ({"nextjs/app/x.ts": "legacy.auth"}, True),
    ],
)
def test_legacy_guard_runs_in_real_shells(
    tmp_path: Path, login_shell: str, planted: dict[str, str], fails: bool
) -> None:
    for name, text in {"nextjs/app/page.tsx": "export default 1", **planted}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    guard = LegacyGuard(
        tokens=("jwtVerify", "admin_session", "legacy.auth"),
        dirs=("*/app/api/admin",),
        search=("nextjs/.next/standalone", "nextjs/app"),
    )

    result = run_remote(f"cd {tmp_path} && {legacy_guard_script(guard)}", login_shell, os.environ["PATH"])

    assert (result.returncode != 0) == fails, result.stderr
    assert ("Legacy code found" in result.stderr) == fails


RECORD = f"{SITE}/.ops-deploy-source"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def from_git(cfg: VillakunterbuntConfig, commit: str = COMMIT) -> VillakunterbuntConfig:
    return VillakunterbuntConfig.model_validate({**cfg.model_dump(), "source_commit": commit})


def test_git_source_records_its_commit_once(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    recorded = {**converged(cfg, secrets), **fakehost.file(RECORD, f"{COMMIT}\n", user="villakunterbunt")}

    first = deploy(from_git(cfg), secrets, converged(cfg, secrets))
    again = deploy(from_git(cfg), secrets, recorded)
    local = deploy(cfg, secrets, recorded)

    # Recording restarts nothing; the same commit again is a no-op.
    assert first.mutating_changed_ops == [f"{V}Record the deployed commit"]
    assert first.upload(RECORD).decode() == f"{COMMIT}\n"
    assert again.mutating_changed_ops == []
    assert local.mutating_changed_ops == [f"{V}Forget the deployed commit (local source)"]


def test_the_record_comes_after_the_health_checks(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    run = deploy(from_git(cfg), secrets, rsync=RecordingRsyncRunner({"--dry-run": ITEMIZED_CHANGE}))

    names = [op.name for op in run.ops]
    assert names.index(READ_ONLY[-1]) < names.index(f"{V}Record the deployed commit") < names.index(CLEAR)


@pytest.mark.parametrize("commit", ["abc1234", "0123456789ABCDEF0123456789ABCDEF01234567", "main"])
def test_source_commit_must_be_a_full_commit(cfg: VillakunterbuntConfig, commit: str) -> None:
    with pytest.raises(ConfigValidationError, match="source_commit"):
        from_git(cfg, commit)


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("get", "post", "fails"),
    [
        ('{"csrfToken": "t"}', "400", False),
        ('{"csrfToken": "t"}', "403", True),
        # A broken session endpoint fails even though the POST answers 400.
        ("FAIL", "400", True),
        ("not json", "400", True),
        ('{"csrfToken": ""}', "400", True),
    ],
)
def test_csrf_check_runs_in_real_shells(tmp_path: Path, login_shell: str, get: str, post: str, fails: bool) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # GET (-c jar): prints ``get`` or fails; POST (--data): prints ``post`` as the status.
    curl.write_text(
        "#!/bin/sh\n"
        'case " $* " in *" --data "*) printf %s "$POST" ;; *) [ "$GET" = FAIL ] && exit 22; echo "$GET" ;; esac\n'
    )
    curl.chmod(0o755)
    command = f"base=https://villakunterbunt.example.com; path=/cms-api/session/; {CSRF_CHECK}"

    result = run_remote(command, login_shell, f"{bin_dir}:{os.environ['PATH']}", GET=get, POST=post)

    assert (result.returncode != 0) == fails, result.stderr


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("check", "code", "body", "ok"),
    [
        (UrlCheck(path="/"), "200", "x", True),
        (UrlCheck(path="/"), "500", "x", False),
        (UrlCheck(path="/m", status=302, follow=False), "302", "", True),
        (
            UrlCheck(path="/p/", contains=('name="robots"', "noindex")),
            "200",
            '<meta name="robots" content="noindex">',
            True,
        ),
        (UrlCheck(path="/p/", contains=('name="robots"', "noindex")), "200", "<meta>", False),
    ],
)
def test_url_check_runs_in_real_shells(
    tmp_path: Path, login_shell: str, check: UrlCheck, code: str, body: str, ok: bool
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # Writes $BODY to the -o file and prints $CODE; records whether -L was given.
    curl.write_text(
        "#!/bin/sh\n"
        'out=; prev=; for a in "$@"; do [ "$prev" = -o ] && out=$a; [ "$a" = -L ] && touch "$MARK"; prev=$a; done\n'
        'printf %s "$BODY" > "$out"; printf %s "$CODE"\n'
    )
    curl.chmod(0o755)
    mark = tmp_path / "followed"
    script = url_check_script("https://example.com" + check.path, check.model_copy(update={"delay": 0}))

    result = run_remote(
        f"sh -c {shlex.quote(script)}",
        login_shell,
        f"{bin_dir}:{os.environ['PATH']}",
        BODY=body,
        CODE=code,
        MARK=str(mark),
    )

    assert (result.returncode == 0) == ok, result.stderr
    assert mark.exists() == check.follow


def test_launcher_comment_changes_do_not_restart(cfg: VillakunterbuntConfig, secrets: SecretValues) -> None:
    deployed = render("next.sh.j2", cfg=cfg).replace("# The Django URL", "# An older comment\n# The Django URL")
    assert code_lines(deployed.splitlines()) == code_lines(render("next.sh.j2", cfg=cfg).splitlines())

    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/next.sh": deployed}))

    assert run.mutating_changed_ops == [f"{V}Write next.sh"]


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_url_check_retries_until_the_content_is_there(tmp_path: Path, login_shell: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # The first answer is a warming page; the second one has the content.
    curl.write_text(
        "#!/bin/sh\n"
        'out=; prev=; for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done\n'
        'n=$(cat "$COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$COUNT"\n'
        '[ $n -ge 2 ] && printf %s "--ready" > "$out" || printf %s warming > "$out"; printf 200\n'
    )
    curl.chmod(0o755)
    check = UrlCheck(path="/", contains=("--ready",), retries=3, delay=0)
    script = url_check_script("https://example.com/", check)

    result = run_remote(
        f"sh -c {shlex.quote(script)}", login_shell, f"{bin_dir}:{os.environ['PATH']}", COUNT=str(tmp_path / "n")
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "n").read_text().strip() == "2"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_url_check_refuses_an_incomplete_transfer(tmp_path: Path, login_shell: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # Status 200 and part of the body, then a timeout (curl exits 28).
    curl.write_text(
        "#!/bin/sh\n"
        'out=; prev=; for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done\n'
        'printf %s noindex > "$out"; printf 200; exit 28\n'
    )
    curl.chmod(0o755)
    script = url_check_script("https://example.com/", UrlCheck(path="/", contains=("noindex",), retries=2, delay=0))

    result = run_remote(f"sh -c {shlex.quote(script)}", login_shell, f"{bin_dir}:{os.environ['PATH']}")

    assert result.returncode != 0


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_purge_removes_files_and_symlinks(tmp_path: Path, login_shell: str) -> None:
    private = tmp_path / "private"
    private.mkdir()
    (private / "doc.pdf").write_text("private")
    public = tmp_path / "nextjs/public"
    (public / "uploads").mkdir(parents=True)
    (public / "uploads/.gitkeep").write_text("")
    (public / "uploads/a.pdf").write_text("old")
    (public / "uploads/link.pdf").symlink_to(private / "doc.pdf")
    (public / "uploads/nested").mkdir()
    (public / "uploads/nested/.gitkeep").symlink_to(private)
    (public / "linked").symlink_to(private)
    dirs = ["nextjs/public/uploads", "nextjs/public/linked", "nextjs/public/missing"]

    found = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-print -quit')}", login_shell, os.environ["PATH"])
    purged = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-delete')}", login_shell, os.environ["PATH"])
    again = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-print -quit')}", login_shell, os.environ["PATH"])

    assert found.stdout.strip()
    assert purged.returncode == 0, purged.stderr
    assert again.stdout.strip() == ""
    assert sorted(p.name for p in (public / "uploads").iterdir()) == [".gitkeep", "nested"]
    assert list((public / "uploads/nested").iterdir()) == []
    assert not (public / "linked").exists()
    assert not (public / "linked").is_symlink()
    assert (private / "doc.pdf").read_text() == "private"


def _media(tmp_path: Path) -> tuple[Path, Path, Path]:
    src, dst = tmp_path / "media/documents", tmp_path / "private_media/documents"
    (src / "sub").mkdir(parents=True)
    (src / "sub/a.pdf").write_text("from media")
    (dst / "sub").mkdir(parents=True)
    (dst / "sub/b.pdf").write_text("only private")
    return src, dst, tmp_path / "private_media/.legacy-documents-migrated"


def _move(src: Path, dst: Path, marker: Path, login_shell: str) -> Any:
    script = media_move_script(str(src), str(dst), shlex.quote(str(marker)))
    return run_remote(f"sh -c {shlex.quote(script)}", login_shell, os.environ["PATH"])


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_media_move_moves_and_keeps_private_files(tmp_path: Path, login_shell: str) -> None:
    src, dst, marker = _media(tmp_path)
    (dst / "sub/same.pdf").write_text("same")
    (src / "sub/same.pdf").write_text("same")

    result = _move(src, dst, marker, login_shell)

    assert result.returncode == 0, result.stderr
    assert not src.exists()
    assert marker.exists()
    assert (dst / "sub/a.pdf").read_text() == "from media"
    assert (dst / "sub/b.pdf").read_text() == "only private"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize("case", ["different content", "dangling link", "link to the source", "source link"])
def test_media_move_keeps_the_source_on_a_conflict(tmp_path: Path, login_shell: str, case: str) -> None:
    src, dst, marker = _media(tmp_path)
    if case == "different content":
        (dst / "sub/a.pdf").write_text("other content")
    elif case == "dangling link":
        (dst / "sub/a.pdf").symlink_to(tmp_path / "nowhere")
    elif case == "link to the source":
        (dst / "sub/a.pdf").symlink_to(src / "sub/a.pdf")
    else:
        (src / "sub/c.pdf").symlink_to(tmp_path / "elsewhere")

    result = _move(src, dst, marker, login_shell)

    assert result.returncode != 0
    assert "not moving" in result.stderr
    assert (src / "sub/a.pdf").read_text() == "from media"
    assert not marker.exists()


def test_media_move_keeps_a_file_written_during_the_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, dst, _ = _media(tmp_path)
    real_walk = os.walk
    calls = []

    def walk(top: str) -> Any:
        calls.append(top)
        entries = list(real_walk(top))
        yield from entries
        if len(calls) == 3:
            # An upload lands after the verification pass listed the directory.
            (src / "sub/new.pdf").write_text("uploaded meanwhile")

    monkeypatch.setattr(os, "walk", walk)
    monkeypatch.setattr("sys.argv", ["-c", str(src), str(dst)])

    exec(compile(MEDIA_MOVE, "media_move", "exec"), {"__name__": "__main__"})

    assert len(calls) == 3
    assert (src / "sub/new.pdf").read_text() == "uploaded meanwhile"
    assert not (src / "sub/a.pdf").exists()
    assert (dst / "sub/a.pdf").read_text() == "from media"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("states", "stop_fails", "command_fails", "ran", "started"),
    [
        ({"a": "active", "b": "active"}, False, False, True, "a b"),
        # Waiting for its automatic restart: stopped too, and started again.
        ({"a": "inactive", "b": "activating"}, False, False, True, "b"),
        ({"a": "inactive", "b": "inactive"}, False, False, True, ""),
        ({"a": "active", "b": "active"}, False, True, True, "a b"),
        ({"a": "active", "b": "active"}, True, False, False, "a b"),
        # A first deploy: the units are not installed, nothing to stop.
        ({"a": "inactive", "b": "inactive", "not-found": "a b"}, True, False, True, ""),
        # Masked but still running: stopped like any other unit; it cannot
        # start again, which fails the step.
        ({"a": "active", "b": "active", "masked": "a b", "start fails": "1"}, False, False, True, "a b"),
    ],
)
def test_quiesced_script_runs_in_real_shells(
    tmp_path: Path,
    login_shell: str,
    states: dict[str, str],
    stop_fails: bool,
    command_fails: bool,
    ran: bool,
    started: str,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "log"
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        'echo "$*" >> "$LOG"\n'
        'case "$1" in is-active) eval "echo \\$STATE_$2"; exit 0 ;; stop) [ -n "$STOP_FAILS" ] && exit 1 ;; '
        'start) [ -n "$START_FAILS" ] && exit 1 ;; esac\n'
        '[ "$1" = show ] && { eval "echo \\${LOAD_$5:-loaded}"; exit 0; }\n'
        "exit 0\n"
    )
    systemctl.chmod(0o755)
    command = f"echo ran >> {log}" + ("; exit 3" if command_fails else "")
    env = {"LOG": str(log), "STATE_a": states["a"], "STATE_b": states["b"], "STOP_FAILS": "1" if stop_fails else ""}
    env.update({f"LOAD_{u}": "not-found" for u in states.get("not-found", "").split()})
    env.update({f"LOAD_{u}": "masked" for u in states.get("masked", "").split()})
    env["START_FAILS"] = states.get("start fails", "")

    result = run_remote(quiesced_script(("a", "b"), command), login_shell, f"{bin_dir}:{os.environ['PATH']}", **env)

    lines = log.read_text().splitlines()
    assert ("ran" in lines) == ran
    starts = [line for line in lines if line.startswith("start")]
    assert starts == ([f"start {started}"] if started else [])
    stops = [line for line in lines if line.startswith("stop")]
    assert stops == ([] if states.get("not-found") else ["stop a b"])
    if ran and stops:
        assert lines.index("stop a b") < lines.index("ran")
    expected = 1 if stop_fails and not states.get("not-found") else 3 if command_fails else 0
    if states.get("start fails") and expected == 0:
        expected = 1
    assert result.returncode == expected, result.stderr
