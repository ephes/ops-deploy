"""echoport's host files stay byte for byte what hosts have (``tests/golden/echoport``).

The env file, the unit, the staging refresh script, the Traefik route and the
MinIO account policy are rendered from synthetic inputs (ops-control's literal
values) and compared with the recorded renders: identical bytes mean the next
deploy rewrites nothing and restarts nothing. See ``tests/goldens.py``.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.echoport import EchoportConfig
from ops_deploy.services.echoport.deploy import (
    MinioAccount,
    render_env,
    render_policy,
    render_role,
    render_route,
    traefik_config,
)
from tests.echoport_fixtures import make_source
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "echoport"
# Every character that could trip a template: ``$``, backticks, quotes, ampersands.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#0123456789'
DOMAIN = "echoport.home.example.invalid"
RANGES = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
    "fd50:3e45:c454:0::/64",
)
# A fixed bcrypt hash: hash_password salts randomly.
AUTH_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"
SECRETS = {
    "django_secret_key": AWKWARD,
    "fastdeploy_base_url": "https://deploy.example.invalid",
    "fastdeploy_service_token": "token-0123456789abcdef",
    "admin_username": "admin",
    "admin_password": "admin-password",
    "basic_auth_password": "basic-auth-password",
    "minio_access_key": "minio-root",
    "minio_secret_key": "minio-secret-0123",
}


def make(tmp_path: Path, secrets: dict[str, str], **overrides: Any) -> tuple[EchoportConfig, SecretValues]:
    ref = SecretRef("secrets/prod/echoport.yml")
    # ops-control's echoport_config(): the playbook's literal values.
    cfg = EchoportConfig(
        source_path=make_source(tmp_path),
        secrets=ref,
        traefik_host=DOMAIN,
        django_allowed_hosts=("127.0.0.1", DOMAIN),
        internal_ip_ranges=RANGES,
        minio_url="http://127.0.0.1:9001",
        staging_db_refresh_enabled=True,
        staging_db_refresh_targets=("homepage-production-db", "python-podcast-production-db"),
        **overrides,
    )
    return cfg, SecretValues(ref, secrets)


def test_env_file(tmp_path: Path) -> None:
    cfg, values = make(tmp_path, SECRETS)

    assert_golden(GOLDEN / "echoport.env", render_env(cfg, values).reveal().decode())


def test_env_file_with_timing_settings(tmp_path: Path) -> None:
    cfg, values = make(
        tmp_path,
        SECRETS,
        stale_run_grace_seconds=600,
        late_result_window_seconds=7200,
        health_overdue_grace_minutes=90,
        django_debug=True,
        workers=3,
        allowed_path_prefixes=("/srv/",),
    )

    text = render_env(cfg, values).reveal().decode()
    assert_golden(GOLDEN / "timing" / "echoport.env", text)
    assert "ECHOPORT_STALE_RUN_GRACE_SECONDS=600\n" in text
    assert "DJANGO_DEBUG=true\n" in text


@pytest.mark.parametrize("template", ["echoport.service.j2", "staging-db-refresh.sh.j2"])
def test_unit_and_script(tmp_path: Path, template: str) -> None:
    cfg, values = make(tmp_path, SECRETS)

    assert_golden(GOLDEN / template.removesuffix(".j2"), render_role(template, cfg, values))


@pytest.mark.parametrize(
    ("case", "overrides"),
    [("dual-router", {}), ("no-basic-auth", {"basic_auth_enabled": False})],
)
def test_route(tmp_path: Path, case: str, overrides: dict[str, Any]) -> None:
    cfg, values = make(tmp_path, SECRETS, **overrides)
    route = traefik_config(cfg, values)
    auth_hash = AUTH_HASH if cfg.basic_auth_enabled else None

    text = render_route(cfg, values, route, auth_hash)
    assert_golden(GOLDEN / case / "traefik-echoport.yml", text)
    assert (f'"admin:{AUTH_HASH}"' in text) is cfg.basic_auth_enabled


def test_account_policy() -> None:
    assert_golden(GOLDEN / "backup-account-policy.json", render_policy(MinioAccount()))


@pytest.mark.parametrize(
    ("allow_put", "allow_delete"), [(False, True), (True, False), (False, False)], ids=["retention", "put", "read"]
)
def test_account_policy_grants_only_what_the_account_needs(allow_put: bool, allow_delete: bool) -> None:
    statements = json.loads(render_policy(MinioAccount(allow_put=allow_put, allow_delete=allow_delete)))["Statement"]
    assert statements[1] == {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::backups"]}
    actions = [
        "s3:GetObject",
        "s3:GetObjectVersion",
        *(["s3:PutObject"] if allow_put else []),
        *(["s3:DeleteObject"] if allow_delete else []),
    ]
    assert statements[2] == {"Effect": "Allow", "Action": actions, "Resource": ["arn:aws:s3:::backups/*"]}


def test_account_user_is_the_playbooks_derived_name() -> None:
    # backup_minio_account_user: "bk-{{ (backup_minio_account_target | hash('sha256'))[:17] }}"
    assert MinioAccount().user == "bk-" + hashlib.sha256(b"echoport-retention").hexdigest()[:17]
    assert len(MinioAccount().user) == 20
    assert MinioAccount().policy == "backup-echoport-retention"
