"""PostgreSQL and Redis config files are byte-identical to the roles' output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
switching a host between the tools rewrites nothing and restarts nothing.
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest
from pydantic import SecretStr

from ops_deploy.infra import PgHbaRule, PostgresInstallConfig, RedisInstallConfig
from ops_deploy.infra._common import deb822_sources
from ops_deploy.infra.postgres_install import render_conf_d, render_pg_hba
from ops_deploy.infra.redis_install import render_config

VENDORED = Path(__file__).parent / "parity" / "ansible"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(template).render(**variables)


POSTGRES_CONFIGS = {
    "defaults": PostgresInstallConfig(),
    "string listen, overrides": PostgresInstallConfig(
        listen_addresses="*",
        port=5433,
        config_overrides={"shared_buffers": "256MB", "Max_Connections": 200, "jit": False, "quote": "it's"},
    ),
    "several listen addresses, rules with extras": PostgresInstallConfig(
        listen_addresses=("localhost", "10.0.0.1"),
        pg_hba_rules=(
            PgHbaRule(type="local", database="all", user="postgres", auth_method="peer", comment="admin"),
            PgHbaRule(type="host", database="app", user="app", auth_method="md5"),
            PgHbaRule(
                type="hostssl",
                database="all",
                user="all",
                address="10.0.0.0/8",
                auth_method="cert",
                auth_options="clientcert=verify-full map=x",
            ),
        ),
    ),
}


def postgres_vars(cfg: PostgresInstallConfig) -> dict[str, Any]:
    listen = cfg.listen_addresses if isinstance(cfg.listen_addresses, str) else list(cfg.listen_addresses)
    rules = [{k: v for k, v in rule.model_dump().items() if v is not None} for rule in cfg.pg_hba_rules]
    for rule, original in zip(rules, cfg.pg_hba_rules, strict=True):
        # The role's default address applies only when none is given.
        if "address" not in original.model_fields_set:
            rule.pop("address")
    return {
        "postgres_install_listen_addresses": listen,
        "postgres_install_port": cfg.port,
        "postgres_install_config_overrides": dict(cfg.config_overrides),
        "postgres_install_pg_hba_rules": rules,
    }


@pytest.mark.parametrize("cfg", POSTGRES_CONFIGS.values(), ids=POSTGRES_CONFIGS.keys())
def test_postgres_files_match_the_role(cfg: PostgresInstallConfig) -> None:
    variables = postgres_vars(cfg)

    assert render_conf_d(cfg) == render_ansible("postgres_install__ops_postgresql.conf.j2", variables)
    assert render_pg_hba(cfg) == render_ansible("postgres_install__pg_hba.conf.j2", variables)


def test_default_pg_hba_is_what_macmini_has() -> None:
    # 208 bytes, as `ls -l /etc/postgresql/17/main/pg_hba.conf` shows on macmini.
    assert len(render_pg_hba(PostgresInstallConfig()).encode()) == 208
    assert len(render_conf_d(PostgresInstallConfig()).encode()) == 90


REDIS_CONFIGS = {
    "defaults": (RedisInstallConfig(), None),
    "password, memory limit, no save rules": (
        RedisInstallConfig(
            requirepass_enabled=True,
            maxmemory="256mb",
            maxmemory_policy="allkeys-lru",
            save_rules=(),
            appendonly=True,
            protected_mode=False,
            stop_writes_on_bgsave_error=False,
            bind_addresses=("127.0.0.1",),
            logfile="/var/log/redis/other.log",
        ),
        SecretStr("redis-fixture-password"),
    ),
    "zero bytes means unlimited": (RedisInstallConfig(maxmemory="0B"), None),
}


@pytest.mark.parametrize(("cfg", "password"), REDIS_CONFIGS.values(), ids=REDIS_CONFIGS.keys())
def test_redis_config_matches_the_role(cfg: RedisInstallConfig, password: SecretStr | None) -> None:
    variables = {
        f"redis_install_{key}": value
        for key, value in cfg.model_dump().items()
        if key not in ("logfile", "check_host", "validate_config")
    }
    variables.update(
        redis_install_bind_addresses=list(cfg.bind_addresses),
        redis_install_save_rules=list(cfg.save_rules),
        redis_install_logfile=cfg.log_path,
        redis_install_password=password.get_secret_value() if password else "",
    )

    assert render_config(cfg, password) == render_ansible("redis_install__redis.conf.j2", variables)


def test_deb822_sources_match_what_ansible_wrote_on_macmini() -> None:
    # /etc/apt/sources.list.d/postgresql.sources on macmini (deb822_repository).
    macmini = (
        "Components: main\n"
        "Enabled: yes\n"
        "X-Repolib-Name: postgresql\n"
        "Signed-By: /etc/apt/keyrings/postgresql.asc\n"
        "Suites: noble-pgdg\n"
        "Types: deb\n"
        "URIs: https://apt.postgresql.org/pub/repos/apt\n"
    )

    assert (
        deb822_sources(
            name="postgresql",
            uris="https://apt.postgresql.org/pub/repos/apt",
            suites=("noble-pgdg",),
            components=("main",),
            signed_by="/etc/apt/keyrings/postgresql.asc",
        )
        == macmini
    )
