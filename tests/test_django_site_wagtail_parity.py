"""Wagtail origin environment values and externally referenced route names."""

from io import StringIO
from pathlib import Path

import jinja2
import pytest
from dotenv import dotenv_values

from ops_deploy.services.django_site import EnvEntry, EnvSpec, Route
from ops_deploy.services.django_site.render import render, render_env
from tests.django_site_fixtures import values
from tests.hsts import hsts_headers
from tests.test_django_site_postgres import config

ORIGIN = Path(__file__).parent / "parity/ansible"


@pytest.mark.parametrize("storage", [False, True])
@pytest.mark.parametrize("sentry", [False, True])
@pytest.mark.parametrize("api_url", ["", "https://relay.example.com/v3"])
def test_wagtail_env_preserves_values(tmp_path: Path, storage: bool, sentry: bool, api_url: str) -> None:
    fields = {
        "DJANGO_MAILGUN_API_KEY": "fixture-mail-key",
        "MAILGUN_API_KEY": "fixture-mail-key",
        "MAILGUN_SENDER_DOMAIN": "mail.example.com",
        "MAILGUN_DOMAIN": "mail.example.com",
        "DJANGO_SERVER_EMAIL": "server@example.com",
        "EXTRA": 'value "quoted"',
    }
    if storage:
        fields.update(
            DJANGO_AWS_ACCESS_KEY_ID="fixture-id",
            DJANGO_AWS_SECRET_ACCESS_KEY="fixture-s3-secret",
            DJANGO_AWS_STORAGE_BUCKET_NAME="fixture-bucket",
            CLOUDFRONT_DOMAIN="cdn.example.com",
        )
    if sentry:
        fields.update(
            DJANGO_SENTRY_DSN="https://dsn.example.com",
            SENTRY_DSN="https://dsn.example.com",
            DJANGO_SENTRY_ENVIRONMENT="staging",
            SENTRY_ENVIRONMENT="staging",
        )
    if api_url:
        fields["MAILGUN_API_URL"] = api_url
    cfg = config(
        tmp_path,
        env=EnvSpec(admin_url="hidden_admin/", extra=tuple(EnvEntry(key=k, value=v) for k, v in fields.items())),
    )
    sec = values(cfg, postgres_password="fixture-password")
    context = {
        "wagtail_django_settings_module": cfg.app.settings_module,
        "wagtail_django_secret_key": sec["django_secret_key"],
        "wagtail_admin_url": "hidden_admin/",
        "wagtail_django_allowed_hosts": cfg.allowed_hosts,
        "wagtail_django_cache_location": str(cfg.cache_dir),
        "wagtail_postgres_user": "school-site",
        "wagtail_postgres_password": "fixture-password",
        "wagtail_postgres_host": "localhost",
        "wagtail_postgres_port": 5432,
        "wagtail_postgres_database": "school-site",
        "wagtail_require_object_storage": storage,
        "wagtail_require_sentry": sentry,
        "wagtail_mailgun_api_url": api_url,
        "wagtail_env_extra": {"EXTRA": fields["EXTRA"]},
        "wagtail_django_aws_access_key_id": "fixture-id",
        "wagtail_django_aws_secret_access_key": "fixture-s3-secret",
        "wagtail_django_aws_storage_bucket_name": "fixture-bucket",
        "wagtail_cloudfront_domain": "cdn.example.com",
        "wagtail_django_sentry_dsn": "https://dsn.example.com",
        "wagtail_django_sentry_environment": "staging",
        "wagtail_django_mailgun_api_key": "fixture-mail-key",
        "wagtail_mailgun_sender_domain": "mail.example.com",
        "wagtail_django_server_email": "server@example.com",
    }
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["bool"] = bool
    old = env.from_string((ORIGIN / "wagtail_deploy__wagtail.env.j2").read_text()).render(**context)
    assert dict(dotenv_values(stream=StringIO(old))) == dict(
        dotenv_values(stream=StringIO(render_env(cfg, sec).reveal().decode()))
    )


@pytest.mark.parametrize("resolver", ["", "letsencrypt"])
def test_route_matches_origin_except_comments(tmp_path: Path, resolver: str) -> None:
    cfg = config(
        tmp_path,
        route=Route(
            fqdn="school.example.com",
            host_rule="Host(`school.example.com`)",
            wagtail=True,
            cert_resolver=resolver,
            extra_middlewares=("school-noindex@file",),
            public_reason="Public school website",
        ),
    )
    context = dict(
        wagtail_service_name=cfg.unit_name,
        wagtail_traefik_host_rule=cfg.route.host_rule,
        wagtail_traefik_entrypoints=["web-secure"],
        wagtail_traefik_middlewares=["school-noindex@file"],
        wagtail_traefik_cert_resolver=resolver,
        wagtail_app_host="localhost",
        wagtail_app_port=cfg.app.port,
    )
    origin = (
        jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        .from_string((ORIGIN / "wagtail_deploy__wagtail.traefik.yml.j2").read_text())
        .render(**context)
    )

    def normalize(text: str) -> str:
        return "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))

    assert normalize(render("route.traefik.yml.j2", cfg)) == normalize(origin)


def test_wagtail_route_sends_hsts_without_preload(tmp_path: Path) -> None:
    route = Route(
        fqdn="school.example.com",
        host_rule="Host(`school.example.com`)",
        wagtail=True,
        public_reason="Public school website",
    )

    assert len(hsts_headers(render("route.traefik.yml.j2", config(tmp_path, route=route)))) == 1
