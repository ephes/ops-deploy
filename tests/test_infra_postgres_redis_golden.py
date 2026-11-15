"""PostgreSQL and Redis config files stay byte for byte what hosts have.

The renders are recorded under ``tests/golden/postgres_install`` and
``tests/golden/redis_install`` (see ``tests/goldens.py``). Identical bytes
mean the next deploy rewrites nothing and restarts nothing.
"""

from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.infra import PgHbaRule, PostgresInstallConfig, RedisInstallConfig
from ops_deploy.infra._common import deb822_sources
from ops_deploy.infra.postgres_install import render_conf_d, render_pg_hba
from ops_deploy.infra.redis_install import render_config
from tests.goldens import assert_golden

POSTGRES_GOLDEN = Path(__file__).parent / "golden" / "postgres_install"
REDIS_GOLDEN = Path(__file__).parent / "golden" / "redis_install"


def slug(name: str) -> str:
    return name.replace(",", "").replace(" ", "-")


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


@pytest.mark.parametrize("name", POSTGRES_CONFIGS)
def test_postgres_files_are_golden(name: str) -> None:
    cfg = POSTGRES_CONFIGS[name]

    assert_golden(POSTGRES_GOLDEN / slug(name) / "ops_postgresql.conf", render_conf_d(cfg))
    assert_golden(POSTGRES_GOLDEN / slug(name) / "pg_hba.conf", render_pg_hba(cfg))


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


@pytest.mark.parametrize("name", REDIS_CONFIGS)
def test_redis_config_is_golden(name: str) -> None:
    cfg, password = REDIS_CONFIGS[name]

    assert_golden(REDIS_GOLDEN / slug(name) / "redis.conf", render_config(cfg, password))


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
