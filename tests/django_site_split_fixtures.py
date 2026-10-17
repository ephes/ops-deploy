"""A django_site with a Next.js standalone frontend (a Django app in ``django/``, Next.js in ``nextjs/``).

Made-up names throughout; the shape is the one ops-control's split site uses:
data outside the site, ``.env`` and the cache at the site root, a bootstrap
admin, a content import on source changes, the strict sandbox, public and
CSRF checks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.django_site import (
    AppSpec,
    BootstrapSuperuser,
    Checks,
    DjangoSiteConfig,
    EnvEntry,
    EnvLiteral,
    EnvSpec,
    Joined,
    LegacyGuard,
    LocalMedia,
    ManageStep,
    NextStandalone,
    PathSecrets,
    Route,
    Secret,
    SourceSpec,
    SqliteDb,
    StepGroup,
    Steps,
    UrlCheck,
)
from ops_deploy.services.django_site.render import render, render_env
from tests import fakehost

USER = "splitsite"
HOME = f"/home/{USER}"
SITE = f"{HOME}/site"
DATA = f"{HOME}/data"
VENV = f"{SITE}/django/.venv"
ENV = f"{SITE}/.env"
LAUNCHER = f"{SITE}/gunicorn.sh"
NEXT_SH = f"{SITE}/next.sh"
MIDDLEWARE = f"{SITE}/nextjs/middleware.ts"
FISH = f"{HOME}/.config/fish/config.fish"
UNITS = "/etc/systemd/system"
UNIT = f"{UNITS}/{USER}-django.service"
NEXT_UNIT = f"{UNITS}/{USER}-next.service"
ROUTE = f"/etc/traefik/dynamic/{USER}.traefik.yml"
FQDN = "split.staging.example.com"
MAILGUN = "https://mailgun.example.org/v3"
DJANGO_PORT, NEXT_PORT = 10041, 10042
DJANGO_URL = f"http://127.0.0.1:{DJANGO_PORT}"
STAMP = f"NODE_ENV=production WAGTAIL_BASE_URL={DJANGO_URL} NEXT_PUBLIC_FQDN={FQDN}"
SECRET_VALUES = {
    "django_secret_key": "fixture-django-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz",
    "bootstrap_admin_password": "fixture-bootstrap-password",
    "django_admin_url_path": "/fixture-django-admin/",
    "wagtail_admin_url_path": "/fixture-wagtail-admin/",
    "django_mailgun_api_key": "fixture-mailgun-api-key",
    "mailgun_api_url": MAILGUN,
    "mailgun_sender_domain": "mg.fixture.example",
    "django_default_from_email": "Split <split@fixture.example>",
    "django_server_email": "Server <server@fixture.example>",
    "django_email_subject_prefix": "[Fixture] ",
}
# Values that must never show up in commands, op arguments or uploads.
SECRET_ONLY = [v for k, v in SECRET_VALUES.items() if k != "mailgun_api_url"]
MIDDLEWARE_PROD = "export function middleware() {}\n"
SOURCE_FILES = {
    "package.json": '{"name": "app"}\n',
    "package-lock.json": "{}\n",
    "nextjs/middleware.ts": "import { jwtVerify } from 'jose';\n",
    "nextjs/middleware.prod.ts": MIDDLEWARE_PROD,
    "nextjs/content/home.json": "{}\n",
    "django/manage.py": "# manage\n",
    "django/pyproject.toml": "[project]\nname = 'app'\n",
    "django/uv.lock": "version = 1\n",
    "django/config/wsgi.py": "application = None\n",
}
EXCLUDES = ("/.git", ".venv", "/tests")


def make_source(root: Path) -> Path:
    source = root / "app"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source


def _secret(key: str) -> Secret:
    return Secret(secret=key)


def env_extra() -> tuple[EnvEntry, ...]:
    """The split site's ``.env`` after the base keys, in its order."""

    values: list[tuple[str, Any]] = [
        ("DJANGO_DEPLOY_ENVIRONMENT", "staging"),
        ("DJANGO_CSRF_TRUSTED_ORIGINS", f"https://{FQDN}"),
        ("DJANGO_MEDIA_ROOT", f"{DATA}/media"),
        ("DJANGO_PRIVATE_MEDIA_ROOT", f"{DATA}/private_media"),
        ("DJANGO_HEALTHCHECK_FORCE_FAILURE_FILE", f"{DATA}/healthcheck.force_fail"),
        ("DATABASE_ENGINE", "django.db.backends.sqlite3"),
        ("DATABASE_NAME", f"{DATA}/db.sqlite3"),
        ("DJANGO_ADMIN_URL_PATH", _secret("django_admin_url_path")),
        ("WAGTAIL_ADMIN_URL_PATH", _secret("wagtail_admin_url_path")),
        (
            "WAGTAILADMIN_BASE_URL",
            Joined(parts=(f"https://{FQDN}/", Secret(secret="wagtail_admin_url_path", strip="/"))),
        ),
        ("DJANGO_EMAIL_BACKEND", "anymail.backends.mailgun.EmailBackend"),
        ("MAILGUN_API_URL", Secret(secret="mailgun_api_url", equals=MAILGUN)),
        ("MAILGUN_SENDER_DOMAIN", _secret("mailgun_sender_domain")),
        ("DJANGO_MAILGUN_API_KEY", _secret("django_mailgun_api_key")),
        ("DJANGO_DEFAULT_FROM_EMAIL", _secret("django_default_from_email")),
        ("DJANGO_SERVER_EMAIL", _secret("django_server_email")),
        ("DJANGO_EMAIL_SUBJECT_PREFIX", _secret("django_email_subject_prefix")),
    ]
    return tuple(EnvEntry(key=key, value=value) for key, value in values)


def split_config(source: Path, **changes: Any) -> DjangoSiteConfig:
    values: dict[str, Any] = {
        "service_name": USER,
        "title": "Split site",
        "unit": f"{USER}-django",
        "user": USER,
        "home": HOME,
        "site_path": SITE,
        "shell": "/usr/bin/fish",
        "fish": True,
        "secrets": SecretRef(f"secrets/staging/{USER}.yml"),
        "source": SourceSpec(
            path=source,
            excludes=EXCLUDES,
            delete=True,
            required_files=("manage.py", "pyproject.toml", "uv.lock"),
        ),
        "app": AppSpec(
            app_dir="django",
            env_dir="",
            settings_module="config.settings.production",
            port=DJANGO_PORT,
            workers=3,
            uv_args=("--locked", "--no-dev"),
        ),
        "database": SqliteDb(path=f"{DATA}/db.sqlite3"),
        "media": LocalMedia(root=f"{DATA}/media", private_root=f"{DATA}/private_media"),
        "env": EnvSpec(
            secret_key=Secret(secret="django_secret_key", min_length=50),
            allowed_hosts=f"{FQDN},localhost,127.0.0.1",
            extra=env_extra(),
            url_paths=PathSecrets(
                secrets=(_secret("django_admin_url_path"), _secret("wagtail_admin_url_path")),
                refused=("/hidden-admin/", "/wagtail-admin/"),
                reserved=("/static/", "/media/"),
            ),
        ),
        "steps": Steps(
            migrate_args=("--noinput",),
            collectstatic_args=("--noinput", "--clear"),
            restart_after_collectstatic=True,
            extra=(
                StepGroup(
                    name="content import",
                    steps=(ManageStep(name="Import content", argv=("import_content",)),),
                    triggers=frozenset({"source"}),
                ),
            ),
        ),
        "admin": BootstrapSuperuser(email="admin@fixture.example"),
        "frontend": NextStandalone(
            unit=f"{USER}-next",
            port=NEXT_PORT,
            app_dir="nextjs",
            router="cms",
            path_prefixes=("/cms", "/_next"),
            build_env=(
                EnvLiteral(key="WAGTAIL_BASE_URL", value=DJANGO_URL),
                EnvLiteral(key="NEXT_PUBLIC_FQDN", value=FQDN),
            ),
            runtime_env=(EnvLiteral(key="DJANGO_BASE_URL", value=DJANGO_URL),),
            middleware_from="middleware.prod.ts",
            purged_public_dirs=("uploads",),
            legacy_guard=LegacyGuard(tokens=("jwtVerify",), dirs=("*/app/admin",), search=("nextjs/.next/standalone",)),
            check_path="/cms/login",
        ),
        "route": Route(
            fqdn=FQDN,
            name=USER,
            host_rule=f"Host(`{FQDN}`)",
            backend="127.0.0.1",
            public_reason="Public website; the editors log in",
        ),
        "checks": Checks(
            public=(
                UrlCheck(path="/", retries=10, delay=6),
                UrlCheck(path="/members", status=302, follow=False),
                UrlCheck(path="/preview/", contains=('name="robots"', "noindex")),
            ),
            csrf_path="/cms-api/session/",
        ),
        "hardening": "strict",
    }
    values.update(changes)
    return DjangoSiteConfig(**values)


def values(cfg: DjangoSiteConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


def files(cfg: DjangoSiteConfig, secrets: SecretValues) -> dict[str, str]:
    """The files django_site writes for the split site, by host path."""

    return {
        ENV: render_env(cfg, secrets).reveal().decode(),
        LAUNCHER: render("gunicorn.sh.j2", cfg),
        NEXT_SH: render("next.sh.j2", cfg),
        MIDDLEWARE: MIDDLEWARE_PROD,
        FISH: render("config.fish.j2", cfg),
        UNIT: render("unit.service.j2", cfg),
        NEXT_UNIT: render("unit.service.j2", cfg, frontend_unit=True),
        ROUTE: render("route.traefik.yml.j2", cfg),
    }


def deployed(content: dict[str, str], **drift: Any) -> dict[str, Any]:
    """Facts of a host where the split site is fully deployed with ``content``.

    ``drift`` overrides file content (keys starting with ``/``) or fact answers.
    """

    content = {**content, **{k: v for k, v in drift.items() if k.startswith("/")}}
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account(USER, HOME, shell="/usr/bin/fish"),
        "sync --locked --no-dev --dry-run": ["current"],
        "migrate --check": ["current"],
        "staticfiles.json": ["present"],
        "auth_user where username": ["present"],
        "bootstrap-admin-password-applied && echo present": ["present"],
        ".ops-deploy-next-build 2>/dev/null": [STAMP, "built"],
        **fakehost.venv(VENV),
    }
    for path in ("", "/site", "/site/nextjs", "/site/cache", "/.config/fish"):
        responses.update(fakehost.directory(f"{HOME}{path}", user=USER))
    for path in ("/data", "/data/media", "/data/private_media"):
        responses.update(fakehost.directory(f"{HOME}{path}", user=USER, mode="drwxr-x---"))
    responses.update(fakehost.stat(f"{HOME}/.config", user=USER, group="root", mode="drwxr-xr-x"))
    for path in (UNITS, "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = USER if path.startswith(HOME) else "root"
        mode = "-rwxr-xr-x" if path.endswith(".sh") else "-rw-------" if path == ENV else "-rw-r--r--"
        responses.update(fakehost.file(path, text, user=owner, mode=mode))
    responses[f"test -e {SITE}/django/venv ||"] = [
        f"user={USER} group={USER} mode=lrwxrwxrwx atime=0 mtime=0 ctime=0 size=10 '{SITE}/django/venv' -> '{VENV}'"
    ]
    for unit in (f"{USER}-django.service", f"{USER}-next.service"):
        responses.update(fakehost.service(unit))
    responses.update({k: v for k, v in drift.items() if not k.startswith("/")})
    return responses


def converged(cfg: DjangoSiteConfig, secrets: SecretValues, **drift: Any) -> dict[str, Any]:
    return deployed(files(cfg, secrets), **drift)
