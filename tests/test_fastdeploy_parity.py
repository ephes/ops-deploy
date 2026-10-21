"""fastdeploy files are byte-identical to the fastdeploy_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``;
the vendored ``files/`` by ``test_ops_library_drift``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
switching the host between Ansible and ops-deploy rewrites none of them.
"""

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.fastdeploy import FastdeployConfig
from ops_deploy.services.fastdeploy.deploy import TEMPLATE_PACKAGE, render_env
from tests.fastdeploy_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
# Every character the role's shell quoting escapes, plus ones it must leave alone.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#'


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    # Ansible's to_json: json.dumps with the filter's keyword arguments.
    env.filters["to_json"] = lambda value, **kwargs: json.dumps(value, **kwargs)
    return env.get_template(f"fastdeploy_deploy__{template}").render(**variables)


def role_vars(cfg: FastdeployConfig, secrets: SecretValues, **extra: Any) -> dict[str, Any]:
    site = str(cfg.site_path)
    return {
        "fastdeploy_user": cfg.user,
        "fastdeploy_group": cfg.user,
        "fastdeploy_site_path": site,
        "fastdeploy_services_path": f"{site}/services",
        "fastdeploy_venv_bin": f"{site}/.venv/bin",
        "fastdeploy_environment": cfg.environment,
        "fastdeploy_api_url": cfg.api_url,
        "fastdeploy_postgres_user": cfg.postgres_user,
        "fastdeploy_postgres_password": secrets["postgres_password"],
        "fastdeploy_postgres_host": cfg.postgres_host,
        "fastdeploy_postgres_port": cfg.postgres_port,
        "fastdeploy_postgres_database": cfg.postgres_database,
        "fastdeploy_secret_key": secrets["secret_key"],
        "fastdeploy_legacy_service_tokens_accepted_until": cfg.legacy_service_tokens_accepted_until,
        # The role's "not set" is an empty string.
        "fastdeploy_service_token_max_expire_days": cfg.service_token_max_expire_days or "",
        "fastdeploy_service_token_retention_days": cfg.service_token_retention_days or "",
        # The playbook lists the initial user by name ("{{ ...initial_user_name }}").
        "fastdeploy_service_token_admin_users": (
            [secrets["initial_user_name"]] if cfg.service_token_admin_initial_user else []
        )
        + list(cfg.service_token_admin_users),
        "fastdeploy_restore_policies": {
            name: {"bucket": policy.bucket, "prefixes": list(policy.prefixes)}
            for name, policy in cfg.restore_policies.items()
        },
        "fastdeploy_app_port": cfg.app_port,
        "fastdeploy_app_host": cfg.app_host,
        "fastdeploy_forwarded_allow_ips": list(cfg.forwarded_allow_ips),
        "fastdeploy_service_restart_on_failure": cfg.restart_on_failure,
        "fastdeploy_service_restart_sec": cfg.restart_sec,
        **extra,
    }


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


def make(source: Path, **overrides: Any) -> tuple[FastdeployConfig, SecretValues]:
    cfg = FastdeployConfig(source_path=source, secrets=SecretRef("secrets/prod/fastdeploy.yml"), **overrides)
    assert cfg.secrets is not None
    values = {
        "secret_key": AWKWARD,
        "initial_user_name": "admin",
        "initial_user_password_hash": "$2b$12$fixturehash",
        "postgres_password": "pg-fixture-password",
        "basic_auth_password": "fixture-password",
    }
    return cfg, SecretValues(cfg.secrets, values)


CONFIGS: list[dict[str, Any]] = [
    {},
    {
        "api_url": "https://deploy.home.example",
        "legacy_service_tokens_accepted_until": "2026-10-31T00:00:00+00:00",
    },
    # A space instead of "T" (what an unquoted YAML timestamp becomes) is written with "T".
    {"legacy_service_tokens_accepted_until": "2026-10-31 00:00:00Z", "service_token_retention_days": 30},
    {"service_token_max_expire_days": 90},
    # Admin users and restore policies: compact JSON in single quotes, alone or together.
    {"service_token_admin_initial_user": True},
    {"service_token_admin_users": ("ops@example.com", "second")},
    {
        "legacy_service_tokens_accepted_until": "2026-10-31T00:00:00+00:00",
        "service_token_admin_initial_user": True,
        "service_token_admin_users": ("ops@example.com",),
        "restore_policies": {
            "weeknotes-home-backup": {"bucket": "backups", "prefixes": ("weeknotes_home/", "weeknotes-home/")},
            "echoport-backup": {"bucket": "backups", "prefixes": ("nyxmon/", "archive/")},
        },
    },
    {"restore_policies": {"svc.backup_1": {"bucket": "my.bucket-1", "prefixes": ("a/b/",)}}},
    {
        "restart_on_failure": False,
        "app_port": 10000,
        "site_path": "/srv/fd/site",
        "user": "fd",
        "forwarded_allow_ips": ("127.0.0.1", "::1"),
    },
]


@pytest.mark.parametrize("overrides", CONFIGS)
@pytest.mark.parametrize("shell", [False, True])
def test_env_matches_role(source: Path, overrides: dict[str, Any], shell: bool) -> None:
    cfg, secrets = make(source, **overrides)

    ours = render_env(cfg, secrets, shell=shell).reveal().decode()
    role = render_ansible("fastdeploy.env.j2", role_vars(cfg, secrets, task_shell_environment=shell))

    assert ours == role


@pytest.mark.parametrize("overrides", CONFIGS)
def test_unit_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, **overrides)

    template = "fastdeploy.service.j2"
    assert render(TEMPLATE_PACKAGE, template, cfg=cfg) == render_ansible(template, role_vars(cfg, secrets))


def test_shell_env_quotes_what_the_role_quotes(source: Path) -> None:
    cfg, secrets = make(source)

    shell = render_env(cfg, secrets, shell=True).reveal().decode()

    assert 'SECRET_KEY="k\\$y\\`with\\"quotes\\\\and(parens)&amp;#"' in shell.splitlines()


def test_admins_and_restore_policies_are_quoted_compact_json(source: Path) -> None:
    cfg, secrets = make(
        source,
        service_token_admin_initial_user=True,
        service_token_admin_users=("ops@example.com",),
        restore_policies={
            "weeknotes-home-backup": {"bucket": "backups", "prefixes": ("weeknotes_home/", "weeknotes-home/")},
            "echoport-backup": {"bucket": "backups", "prefixes": ("nyxmon/", "archive/")},
        },
    )

    for shell in (False, True):
        lines = render_env(cfg, secrets, shell=shell).reveal().decode().splitlines()

        assert lines[-6:] == [
            "",
            "# Service tokens",
            """SERVICE_TOKEN_ADMIN_USERS='["admin","ops@example.com"]'""",
            "",
            "# Restores",
            "RESTORE_POLICIES='"
            '{"echoport-backup":{"bucket":"backups","prefixes":["nyxmon/","archive/"]},'
            '"weeknotes-home-backup":{"bucket":"backups","prefixes":["weeknotes_home/","weeknotes-home/"]}}'
            "'",
        ]
