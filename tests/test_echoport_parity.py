"""echoport files are byte-identical to the echoport_deploy role's output.

The deploy ships the role's templates unchanged; this renders the vendored
copies (``tests/parity/ansible/echoport_deploy__*``, checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
with the variables ``deploy-echoport.yml`` passes, the way Ansible's
``template`` module does, and compares with what the deploy writes.
"""

import hashlib
import json
import shlex
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
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

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/echoport/templates"
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


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["quote"] = shlex.quote  # what Ansible's ``quote`` filter is
    return env.get_template(f"echoport_deploy__{template}").render(**variables)


def playbook_vars(secrets: dict[str, str], **extra: Any) -> dict[str, Any]:
    """Role defaults overlaid with deploy-echoport.yml's role vars."""

    site = "/home/echoport/site"
    return {
        "echoport_user": "echoport",
        "echoport_group": "echoport",
        "echoport_home": "/home/echoport",
        "echoport_site_path": site,
        "echoport_venv_bin": f"{site}/.venv/bin",
        "echoport_cache_dir": f"{site}/cache",
        "echoport_app_host": "127.0.0.1",
        "echoport_app_port": 10018,
        "echoport_workers": 2,
        "echoport_allowed_path_prefixes": ["/home/", "/opt/", "/var/lib/", "/mnt/cryptdata/"],
        "echoport_stale_run_grace_seconds": "",
        "echoport_late_result_window_seconds": "",
        "echoport_health_overdue_grace_minutes": "",
        "echoport_django_settings_module": "config.settings.production",
        "echoport_django_allowed_hosts": f"127.0.0.1,{DOMAIN}",
        "echoport_django_secret_key": secrets["django_secret_key"],
        "echoport_django_debug": False,
        "echoport_fastdeploy_base_url": secrets["fastdeploy_base_url"],
        "echoport_fastdeploy_service_token": secrets["fastdeploy_service_token"],
        "echoport_minio_mc_path": "/usr/local/bin/mc",
        "echoport_minio_alias": "minio",
        "echoport_traefik_host": DOMAIN,
        "echoport_traefik_cert_resolver": "",
        "echoport_traefik_middlewares": [],
        "echoport_basic_auth_enabled": True,
        "echoport_basic_auth_user": "admin",
        "echoport_basic_auth_password_hash": hash_password(secrets["basic_auth_password"]),
        "echoport_internal_ip_ranges": list(RANGES),
        "echoport_staging_db_refresh_targets": ["homepage-production-db", "python-podcast-production-db"],
        "echoport_staging_db_refresh_triggered_by": "staging-refresh-scheduler",
        **extra,
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


def test_env_file_is_byte_identical(tmp_path: Path) -> None:
    cfg, values = make(tmp_path, SECRETS)

    assert render_env(cfg, values).reveal().decode() == render_ansible("echoport.env.j2", playbook_vars(SECRETS))


def test_env_file_with_timing_settings_is_byte_identical(tmp_path: Path) -> None:
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
    role = playbook_vars(
        SECRETS,
        echoport_stale_run_grace_seconds=600,
        echoport_late_result_window_seconds=7200,
        echoport_health_overdue_grace_minutes=90,
        echoport_django_debug=True,
        echoport_workers=3,
        echoport_allowed_path_prefixes=["/srv/"],
    )

    text = render_env(cfg, values).reveal().decode()
    assert text == render_ansible("echoport.env.j2", role)
    assert "ECHOPORT_STALE_RUN_GRACE_SECONDS=600\n" in text
    assert "DJANGO_DEBUG=true\n" in text


@pytest.mark.parametrize("template", ["echoport.service.j2", "staging-db-refresh.sh.j2"])
def test_unit_and_script_are_byte_identical(tmp_path: Path, template: str) -> None:
    cfg, values = make(tmp_path, SECRETS)

    assert render_role(template, cfg, values) == render_ansible(template, playbook_vars(SECRETS))


@pytest.mark.parametrize(
    ("overrides", "role"),
    [
        ({}, {}),
        (
            {"traefik_cert_resolver": "letsencrypt", "traefik_middlewares": ("rate-limit@file", "extra")},
            {
                "echoport_traefik_cert_resolver": "letsencrypt",
                "echoport_traefik_middlewares": ["rate-limit@file", "extra"],
            },
        ),
        ({"basic_auth_enabled": False}, {"echoport_basic_auth_enabled": False}),
    ],
    ids=["dual router", "resolver and middlewares", "no basic auth"],
)
def test_route_is_byte_identical(tmp_path: Path, overrides: dict[str, Any], role: dict[str, Any]) -> None:
    cfg, values = make(tmp_path, SECRETS, **overrides)
    route = traefik_config(cfg, values)
    auth_hash = hash_password(SECRETS["basic_auth_password"]) if cfg.basic_auth_enabled else None

    expected = render_ansible(
        "traefik-echoport.yml.j2", playbook_vars(SECRETS, echoport_basic_auth_password_hash=auth_hash or "", **role)
    )
    assert render_route(cfg, values, route, auth_hash) == expected
    if auth_hash:
        assert f'"admin:{auth_hash}"' in expected


@pytest.mark.parametrize(
    ("allow_put", "allow_delete"), [(False, True), (True, False), (False, False)], ids=["retention", "put", "read"]
)
def test_account_policy_is_byte_identical(allow_put: bool, allow_delete: bool) -> None:
    # deploy-echoport.yml's include of minio_deploy's backup_account (whole
    # bucket), rendered with Ansible's to_json and bool filters.
    account = MinioAccount(allow_put=allow_put, allow_delete=allow_delete)
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
    expected = env.get_template("minio_deploy__backup-account-policy.json.j2").render(
        minio_backup_account_bucket="backups",
        minio_backup_account_prefixes=["echoport-retention"],
        minio_backup_account_whole_bucket="true",
        minio_backup_account_allow_put=allow_put,
        minio_backup_account_allow_delete=allow_delete,
    )

    assert render_policy(account) == expected
    statements = json.loads(expected)["Statement"]
    assert statements[1] == {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::backups"]}
    actions = ["s3:GetObject", *(["s3:PutObject"] if allow_put else []), *(["s3:DeleteObject"] if allow_delete else [])]
    assert statements[2] == {"Effect": "Allow", "Action": actions, "Resource": ["arn:aws:s3:::backups/*"]}


def test_account_user_is_the_playbooks_derived_name() -> None:
    # backup_minio_account_user: "bk-{{ (backup_minio_account_target | hash('sha256'))[:17] }}"
    assert MinioAccount().user == "bk-" + hashlib.sha256(b"echoport-retention").hexdigest()[:17]
    assert len(MinioAccount().user) == 20
    assert MinioAccount().policy == "backup-echoport-retention"


def test_packaged_templates_are_the_role_templates() -> None:
    packaged = sorted(PACKAGED.glob("*.j2"))
    assert len(packaged) == 5
    for template in packaged:
        role = "minio_deploy" if template.name == "backup-account-policy.json.j2" else "echoport_deploy"
        assert template.read_text() == (VENDORED / f"{role}__{template.name}").read_text()
