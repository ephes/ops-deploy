"""minio files are byte-identical to the minio_deploy role's output.

The deploy ships the role's templates unchanged; this renders the vendored
copies (``tests/parity/ansible/minio_deploy__*``, checked against ops-library
by ``test_traefik_parity.test_vendored_templates_match_ops_library``) with the
role's defaults and the variables ``deploy-minio.yml`` passes, the way
Ansible's ``template`` module does, and compares with what the deploy writes.
"""

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.minio import BackupAccount, MinioConfig
from ops_deploy.services.minio.deploy import render_env, render_policy, render_route, render_unit

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/minio/templates"
SECRETS = {
    "root_user": "minio-root-user",
    # Characters a template could trip on (the env file quotes in double quotes).
    "root_password": "k$y`with'quotes&amp;#0123456789",
    "console_basic_auth_password": "console-basic-auth",
}
CONSOLE = "minio.home.example.invalid"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    # Ansible's to_json and bool filters, as the policy template uses them.
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = bool
    return env.get_template(f"minio_deploy__{template}").render(**variables)


def role_defaults(**extra: Any) -> dict[str, Any]:
    """The role's defaults/main.yml (the variables the templates read)."""

    return {
        "minio_user": "minio",
        "minio_group": "minio",
        "minio_home": "/home/minio",
        "minio_bin_path": "/usr/local/bin/minio",
        "minio_config_dir": "/etc/minio",
        "minio_env_file": "/etc/default/minio",
        "minio_certs_dir": "/etc/minio/certs",
        "minio_data_dirs": ["/var/lib/minio/data"],
        "minio_bind_host": "127.0.0.1",
        "minio_api_port": 9001,
        "minio_console_port": 9002,
        "minio_traefik_host": "minio.home.example.com",
        "minio_traefik_api_host": "s3.minio.home.example.com",
        "minio_traefik_cert_resolver": "",
        "minio_console_basic_auth_enabled": True,
        "minio_console_basic_auth_user": "admin",
        "minio_internal_ip_ranges": [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "100.64.0.0/10",
            "fd7a:115c:a1e0::/48",
        ],
        "minio_tls_enable": False,
        "minio_sse_enabled": False,
        "minio_sse_master_key": "",
        "minio_root_user": SECRETS["root_user"],
        "minio_root_password": SECRETS["root_password"],
        "minio_systemd_restart": "always",
        "minio_systemd_memory_max": "",
        "minio_systemd_limit_nofile": 65536,
        "minio_systemd_tasks_max": "infinity",
        **extra,
    }


def playbook_vars(**extra: Any) -> dict[str, Any]:
    """Role defaults overlaid with deploy-minio.yml's role vars."""

    playbook = {
        "minio_data_dirs": ["/mnt/cryptdata/minio/data"],
        "minio_traefik_host": CONSOLE,
        "minio_traefik_api_host": f"s3.{CONSOLE.removeprefix('minio.')}",
    }
    return role_defaults(**{**playbook, **extra})


def playbook_config(**overrides: Any) -> MinioConfig:
    # ops-control's minio_config(): the playbook's literal values.
    fields: dict[str, Any] = {
        "secrets": SecretRef("secrets/prod/minio.yml"),
        "data_dirs": ("/mnt/cryptdata/minio/data",),
        "expose_via_traefik": True,
        "traefik_host": CONSOLE,
        "traefik_api_host": f"s3.{CONSOLE.removeprefix('minio.')}",
        **overrides,
    }
    return MinioConfig(**fields)


def values(cfg: MinioConfig) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, SECRETS)


def test_packaged_templates_are_the_vendored_ones() -> None:
    for template in ("minio.env.j2", "minio.service.j2", "traefik-minio.yml.j2", "backup-account-policy.json.j2"):
        assert (PACKAGED / template).read_text() == (VENDORED / f"minio_deploy__{template}").read_text(), template


@pytest.mark.parametrize(
    ("overrides", "role"),
    [
        ({}, {}),
        (
            {"data_dirs": ("/srv/minio/a", "/srv/minio/b"), "bind_host": "100.64.0.7", "api_port": 9101},
            {
                "minio_data_dirs": ["/srv/minio/a", "/srv/minio/b"],
                "minio_bind_host": "100.64.0.7",
                "minio_api_port": 9101,
            },
        ),
    ],
    ids=["playbook", "two dirs, other bind"],
)
def test_env_file_is_byte_identical(overrides: dict[str, Any], role: dict[str, Any]) -> None:
    cfg = playbook_config(**overrides)

    assert render_env(cfg, values(cfg)).reveal().decode() == render_ansible("minio.env.j2", playbook_vars(**role))


def test_env_file_with_role_defaults_is_byte_identical() -> None:
    cfg = MinioConfig(secrets=SecretRef("secrets/prod/minio.yml"))

    assert render_env(cfg, values(cfg)).reveal().decode() == render_ansible("minio.env.j2", role_defaults())


@pytest.mark.parametrize(
    ("overrides", "role"),
    [
        ({}, {}),
        (
            {"systemd_memory_max": "2G", "systemd_restart": "on-failure", "systemd_tasks_max": "512"},
            {"minio_systemd_memory_max": "2G", "minio_systemd_restart": "on-failure", "minio_systemd_tasks_max": "512"},
        ),
    ],
    ids=["playbook", "limits"],
)
def test_unit_is_byte_identical(overrides: dict[str, Any], role: dict[str, Any]) -> None:
    cfg = playbook_config(**overrides)

    assert render_unit(cfg, values(cfg)) == render_ansible("minio.service.j2", playbook_vars(**role))


@pytest.mark.parametrize(
    ("overrides", "role"),
    [
        ({}, {}),
        ({"traefik_cert_resolver": "letsencrypt"}, {"minio_traefik_cert_resolver": "letsencrypt"}),
        ({"console_basic_auth_enabled": False}, {"minio_console_basic_auth_enabled": False}),
    ],
    ids=["dual router", "cert resolver", "no basic auth"],
)
def test_route_is_byte_identical(overrides: dict[str, Any], role: dict[str, Any]) -> None:
    cfg = playbook_config(**overrides)
    auth_hash = hash_password(SECRETS["console_basic_auth_password"]) if cfg.console_basic_auth_enabled else None
    variables = playbook_vars(**role)
    if auth_hash:
        variables["minio_console_basic_auth_password_hash"] = auth_hash

    expected = render_ansible("traefik-minio.yml.j2", variables)
    assert render_route(cfg, values(cfg), auth_hash) == expected
    if auth_hash:
        assert f'"admin:{auth_hash}"' in expected


@pytest.mark.parametrize(
    "account",
    [
        BackupAccount(name="delve"),
        BackupAccount(name="weeknotes_home", prefixes=("weeknotes_home", "weeknotes-home")),
        BackupAccount(name="echoport-retention", whole_bucket=True, allow_put=False, allow_delete=True),
        BackupAccount(name="reader", bucket="other-bucket", allow_put=False),
    ],
    ids=lambda account: account.name,
)
def test_account_policy_is_byte_identical(account: BackupAccount) -> None:
    # The role's defaults for tasks_from: backup_account, overlaid as
    # common/backup_minio_account.yml and deploy-echoport.yml pass them.
    expected = render_ansible(
        "backup-account-policy.json.j2",
        {
            "minio_backup_account_bucket": account.bucket,
            "minio_backup_account_prefixes": list(account.key_prefixes),
            "minio_backup_account_whole_bucket": account.whole_bucket,
            "minio_backup_account_allow_put": account.allow_put,
            "minio_backup_account_allow_delete": account.allow_delete,
        },
    )

    assert render_policy(account) == expected
    json.loads(expected)
