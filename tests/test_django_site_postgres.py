"""PostgreSQL/Wagtail paths, first-step resumption and secret transport."""

from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.helpers.postgres import state_command
from ops_deploy.services.django_site import (
    DjangoSiteConfig,
    EnvEntry,
    ManageStep,
    PostgresDb,
    Route,
    Secret,
    StepGroup,
    Steps,
)
from ops_deploy.services.django_site.render import render, render_env
from tests import fakehost
from tests.django_site_fixtures import site_config, values
from tests.marina_fixtures import make_source
from tests.test_django_site import deploy
from tests.test_postgres import stored


def config(tmp_path: Path, **changes: Any) -> DjangoSiteConfig:
    return site_config(
        make_source(tmp_path),
        admin=None,
        fish=False,
        database=PostgresDb(name="school-site", user="school-site"),
        **changes,
    )


def facts() -> dict[str, Any]:
    return {
        **fakehost.LINUX,
        "pg_isready": ["ready"],
        "migrate --check": ["current"],
        "--dry-run": ["current"],
        "staticfiles.json": ["present"],
        state_command("school-site", "school-site", "postgres"): [
            stored("fixture-password"),
            "db|school-site",
            "schema|school-site",
        ],
    }


def test_postgres_url_encodes_password_and_requires_its_secret(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    sec = values(cfg, postgres_password="a:b@c/d%?#")
    env = render_env(cfg, sec).reveal().decode()
    url = next(line.split("=", 1)[1].strip("'") for line in env.splitlines() if line.startswith("DATABASE_URL="))
    assert unquote(urlsplit(url).password or "") == sec["postgres_password"]
    assert cfg.required_secret_keys == ("postgres_password", "django_secret_key")
    assert "/db.sqlite3*" not in cfg.sync_excludes


def test_postgres_server_unavailable_fails_before_operations(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    with pytest.raises(ValueError, match="PostgreSQL is unavailable"):
        deploy(cfg, values(cfg, postgres_password="fixture-password"), {**fakehost.LINUX}, succeed=False)


def test_postgres_deploy_does_not_manage_server_or_probe_sqlite(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    run = deploy(cfg, values(cfg, postgres_password="fixture-password"), facts())
    commands = "\n".join(run.executed_commands)
    assert "systemctl start postgresql" not in commands
    assert "CREATE DATABASE" not in commands
    assert "sqlite3" not in commands


def test_first_step_secret_stdin_and_done_marker(tmp_path: Path) -> None:
    step = ManageStep(
        name="Bootstrap school",
        argv=("bootstrap", "--skip-env"),
        stdin_env=(EnvEntry(key="DJANGO_SUPERUSER_PASSWORD", value=Secret(secret="bootstrap_password")),),
    )
    group = StepGroup(name="bootstrap", steps=(step,), when="first", marker=".ops-deploy-bootstrap")
    cfg = config(tmp_path, steps=Steps(extra=(group,)))
    sec = values(cfg, postgres_password="fixture-password", bootstrap_password="synthetic-bootstrap-password")
    run = deploy(cfg, sec, facts())
    text = "\n".join(run.executed_commands)
    assert "synthetic-bootstrap-password" not in text
    assert ".ops-deploy-bootstrap-done" in text
    assert any("synthetic-bootstrap-password" in str(payload) for payload in run.stdin)
    again = deploy(cfg, sec, {**facts(), "test -e /var/lib/ops-deploy/marina/.ops-deploy-bootstrap-done": ["present"]})
    assert not any("manage.py bootstrap" in c for c in again.executed_commands)
    resumed = deploy(
        cfg,
        sec,
        {
            **facts(),
            "test -e /var/lib/ops-deploy/marina/.ops-deploy-bootstrap-done": ["present"],
            "test -e /var/lib/ops-deploy/marina/.ops-deploy-bootstrap &&": ["pending"],
        },
    )
    assert any("manage.py bootstrap" in c for c in resumed.executed_commands)


def test_first_requires_marker_and_rejects_completion_marker_collision(tmp_path: Path) -> None:
    for groups in [
        (StepGroup(name="first", steps=(ManageStep(name="Run", argv=("check",)),), when="first"),),
        (
            StepGroup(
                name="first", steps=(ManageStep(name="Run", argv=("check",)),), when="first", marker=".ops-deploy-x"
            ),
            StepGroup(name="second", steps=(ManageStep(name="Run", argv=("check",)),), marker=".ops-deploy-x-done"),
        ),
    ]:
        with pytest.raises(ConfigValidationError):
            config(tmp_path, steps=Steps(extra=groups))


def test_wagtail_names_security_headers_and_optional_tls(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        route=Route(
            fqdn="school.example.com",
            host_rule="Host(`school.example.com`)",
            wagtail=True,
            cert_resolver="",
            extra_middlewares=("marina-noindex@file",),
            noindex=True,
            public_reason="Public school site",
        ),
    )
    text = render("route.traefik.yml.j2", cfg)
    assert "marina-secure:" in text
    assert "marina-http:" in text
    assert "stsSeconds: 15552000" in text
    assert "tls: {}" in text
    assert "certResolver" not in text
    assert "marina-noindex@file" in text
    assert 'X-Robots-Tag: "noindex, nofollow, noarchive"' in render("noindex.traefik.yml.j2", cfg)


@pytest.mark.parametrize(
    "options",
    [
        {"tls_host_rule": "Host(`secure.example.com`)"},
        {
            "canonical_redirect_regex": "^https://old.example.com/(.*)",
            "canonical_redirect_replacement": "https://new.example.com/${1}",
        },
    ],
)
def test_wagtail_rejects_ignored_classic_route_fields(options: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="Wagtail"):
        Route(
            fqdn="school.example.com",
            host_rule="Host(`school.example.com`)",
            wagtail=True,
            public_reason="Public school",
            **options,
        )


def test_required_static_rejects_globs() -> None:
    with pytest.raises(ValueError, match="pattern"):
        Steps(required_static=("staticfiles/css/*.css",))


def test_noindex_is_written_before_referencing_route(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        route=Route(
            fqdn="school.example.com",
            host_rule="Host(`school.example.com`)",
            wagtail=True,
            noindex=True,
            extra_middlewares=("marina-noindex@file",),
            public_reason="Public school",
        ),
    )
    run = deploy(cfg, values(cfg, postgres_password="fixture-password"), facts())
    names = [op.name for op in run.ops]
    assert names.index("Deploy marina | Write noindex response middleware") < names.index(
        "Deploy marina | Write Traefik route marina"
    )
