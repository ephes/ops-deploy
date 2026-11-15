"""FastDeploy's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/fastdeploy`` were recorded when these
renders still equalled the retired fastdeploy_deploy role's output;
identical bytes mean the next deploy rewrites nothing and restarts nothing
(see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.fastdeploy import FastdeployConfig
from ops_deploy.services.fastdeploy.deploy import TEMPLATE_PACKAGE, render_env
from tests.fastdeploy_fixtures import make_source
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "fastdeploy"
# Every character the env file's shell quoting escapes, plus ones it must leave alone.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#'


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


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    # Admin users and restore policies: compact JSON in single quotes.
    "tokens-policies": {
        "legacy_service_tokens_accepted_until": "2026-10-31T00:00:00+00:00",
        "service_token_admin_initial_user": True,
        "service_token_admin_users": ("ops@example.com",),
        "restore_policies": {
            "weeknotes-home-backup": {"bucket": "backups", "prefixes": ("weeknotes_home/", "weeknotes-home/")},
            "echoport-backup": {"bucket": "backups", "prefixes": ("nyxmon/", "archive/")},
        },
    },
    "custom-site": {
        "restart_on_failure": False,
        "app_port": 10000,
        "site_path": "/srv/fd/site",
        "user": "fd",
        "forwarded_allow_ips": ("127.0.0.1", "::1"),
    },
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(source: Path, case: str) -> None:
    cfg, secrets = make(source, **CASES[case])

    assert_golden(GOLDEN / case / "fastdeploy.env", render_env(cfg, secrets, shell=False).reveal().decode())
    assert_golden(GOLDEN / case / "fastdeploy.shell.env", render_env(cfg, secrets, shell=True).reveal().decode())
    assert_golden(GOLDEN / case / "fastdeploy.service", render(TEMPLATE_PACKAGE, "fastdeploy.service.j2", cfg=cfg))


def test_shell_env_quotes_shell_metacharacters(source: Path) -> None:
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
