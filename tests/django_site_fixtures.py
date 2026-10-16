"""A django_site config in marina's shape (marina runs on django_site), and the facts of a host where it is deployed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.django_site import (
    AppSpec,
    DjangoSiteConfig,
    EnsureSuperuser,
    EnvEntry,
    EnvSpec,
    ManageStep,
    Route,
    Secret,
    SourceSpec,
    StepGroup,
    Steps,
)
from ops_deploy.services.django_site.django import admin_stamp, digest
from ops_deploy.services.django_site.render import render, render_env
from ops_deploy.services.heis import HeisConfig
from tests import fakehost

HOME = "/home/marina"
SITE = f"{HOME}/site"
ENV = f"{SITE}/.env"
LAUNCHER = f"{SITE}/gunicorn.sh"
FISH = f"{HOME}/.config/fish/config.fish"
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
ADMIN_PROBE = "select username, email, is_staff"
REQUIRED = ("manage.py", "pyproject.toml", "uv.lock", "config/wsgi.py")
# marina's SiteSpec excludes (the marina_deploy role's list plus host-written files).
SOURCE_EXCLUDES = (
    ".vault_password",
    "db.sqlite3",
    "db.sqlite3-wal",
    "db.sqlite3-shm",
    "*.sqlite3",
    "*.sqlite3-wal",
    "*.sqlite3-shm",
    "media",
    "backups",
    ".venv",
    ".git",
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "/.env",
    "/staticfiles",
    "/cache",
)


def site_config(checkout: Path, **changes: Any) -> DjangoSiteConfig:
    """marina as a django_site: the values ops-control's SiteSpec sets."""

    values: dict[str, Any] = {
        "service_name": "marina",
        "title": "Marina",
        "user": "marina",
        "home": HOME,
        "site_path": SITE,
        "shell": "/usr/bin/fish",
        "fish": True,
        "secrets": SecretRef("secrets/prod/marina.yml"),
        "source": SourceSpec(path=checkout, excludes=SOURCE_EXCLUDES, required_files=REQUIRED),
        "app": AppSpec(settings_module="config.settings.production", port=10019, python="3.13"),
        "env": EnvSpec(admin_url="marina_admin/"),
        "admin": EnsureSuperuser(),
        "route": Route(
            fqdn=FQDN,
            host_rule=f"Host(`{FQDN}`) || Host(`www.{FQDN}`)",
            public_reason="Public portfolio website",
        ),
    }
    values.update(changes)
    return DjangoSiteConfig(**values)


def values(cfg: DjangoSiteConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


def admin_rows(secrets: SecretValues) -> list[str]:
    name, email = secrets["admin_username"], secrets["admin_email"]
    return [f"A {digest(name, 1, 1, 1)}", f"B {digest(name, email)}"]


def files(cfg: DjangoSiteConfig, secrets: SecretValues) -> dict[str, str]:
    """The canonical file set as django_site renders it, by host path."""

    assert cfg.admin is not None
    return {
        ENV: render_env(cfg, secrets).reveal().decode(),
        LAUNCHER: render("gunicorn.sh.j2", cfg),
        FISH: render("config.fish.j2", cfg),
        UNIT: render("unit.service.j2", cfg),
        ROUTE: render("route.traefik.yml.j2", cfg),
        STAMP: admin_stamp(cfg, cfg.admin, secrets),
    }


def deployed(content: dict[str, str], secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where marina is fully deployed with ``content``; ``drift`` overrides content by path."""

    content = {**content, **drift}
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
        private = "-rw-------" if path in (ENV, STAMP) else "-rw-r--r--"
        responses.update(fakehost.file(path, text, user=owner, mode="-rwxr-xr-x" if path == LAUNCHER else private))
    responses[f"test -e {SITE}/venv ||"] = [
        f"user=marina group=marina mode=lrwxrwxrwx atime=0 mtime=0 ctime=0 size=10 '{SITE}/venv' -> '{SITE}/.venv'"
    ]
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("marina.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def converged(cfg: DjangoSiteConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    return deployed(files(cfg, secrets), secrets, **drift)


HEIS_RECONCILERS = "content reconciliation"


def from_heis(cfg: HeisConfig) -> DjangoSiteConfig:
    """The django_site config that deploys what the heis module's ``cfg`` deploys (ops-control's HEIS SiteSpec)."""

    steps = []
    if cfg.setup_default_pages:
        steps.append(
            ManageStep(
                name="Ensure default Wagtail pages exist",
                argv=("setup_default_pages", "--hostname", cfg.fqdn, "--port", "443"),
            )
        )
    if cfg.seed_content:
        steps.append(ManageStep(name="Seed homepage content", argv=("seed_home_content",)))
        steps.append(ManageStep(name="Seed subpage content and chrome defaults", argv=("seed_subpages_content",)))
    groups = (
        (
            StepGroup(
                name=HEIS_RECONCILERS,
                steps=tuple(steps),
                marker=".ops-deploy-content-pending",
                after="migrate",
            ),
        )
        if steps
        else ()
    )
    return DjangoSiteConfig(
        service_name="heis",
        title="Heis",
        user="heis",
        home=cfg.home,
        site_path=cfg.site_path,
        shell="/usr/bin/fish",
        fish=True,
        apt_packages=("fish", "rsync", "sqlite3"),
        secrets=cfg.secrets,
        source=SourceSpec(
            path=cfg.source_path, commit=cfg.source_commit, excludes=cfg.source_excludes, required_files=REQUIRED
        ),
        app=AppSpec(
            settings_module=cfg.django_settings_module,
            port=cfg.app_port,
            workers=cfg.gunicorn_workers,
            timeout=cfg.gunicorn_timeout,
            python=cfg.python_version,
        ),
        env=EnvSpec(
            admin_url=Secret(secret="django_admin_url"),
            allowed_hosts=cfg.django_allowed_hosts,
            extra=(
                EnvEntry(key="DJANGO_SERVE_MEDIA", value="True" if cfg.serve_media else "False"),
                EnvEntry(key="WAGTAILADMIN_BASE_URL", value=cfg.admin_base_url),
            ),
        ),
        steps=Steps(extra=groups),
        admin=EnsureSuperuser(),
        route=Route(
            fqdn=cfg.fqdn,
            host_rule=cfg.traefik_host_rule,
            tls_host_rule=cfg.traefik_tls_host_rule,
            canonical_redirect_regex=cfg.traefik_canonical_redirect_regex,
            canonical_redirect_replacement=cfg.traefik_canonical_redirect_replacement,
            public_reason="Public website; the Wagtail admin has a login",
        ),
    )
