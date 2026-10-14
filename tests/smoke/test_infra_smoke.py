"""PostgreSQL and Redis on the smoke VM: real end state, data kept, converged second run.

The VM's PostgreSQL is shared with the service smokes; the deploy only brings
its configuration to the role's (which keeps local password logins working)
and adds a throwaway database. Redis is installed by the test and left
installed, with the smoke password removed again.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from ops_deploy.infra import (
    DatabaseSpec,
    ExtensionSpec,
    PostgresInstallConfig,
    RedisInstallConfig,
    deploy_postgres_install,
    deploy_redis_install,
)
from ops_deploy.infra.postgres_install import render_conf_d, render_pg_hba
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

DB = "opsdeploy_infra_smoke"
PG_PASSWORD = "infra-smoke-pg-password"
REDIS_PASSWORD = "infra-smoke-redis-password"


def deploy(smoke_host: SmokeHost, label: str, fn: Any, *args: Any, **kwargs: Any) -> SshRun:
    run = run_deploy_ssh(fn, *args, host_name=smoke_host.name, host_data=smoke_host.host_data, **kwargs)
    TIMINGS[label] = run.seconds
    assert run.succeeded, run.error
    return run


def psql(smoke_host: SmokeHost, sql: str, database: str = DB) -> str:
    return smoke_host.out(f"runuser -u postgres -- psql -XAtq -d {database} -c {shlex.quote(sql)}")


@pytest.fixture
def smoke_database(smoke_host: SmokeHost) -> Iterator[None]:
    yield
    smoke_host.run(f"runuser -u postgres -- dropdb --if-exists {DB}; runuser -u postgres -- dropuser --if-exists {DB}")


def test_postgres_install(smoke_host: SmokeHost, smoke_database: None) -> None:
    cfg = PostgresInstallConfig()
    spec = DatabaseSpec(name=DB, owner=DB, password=SecretStr(PG_PASSWORD))
    extensions = (ExtensionSpec(name="pg_trgm", database=DB),)

    deploy(smoke_host, "postgres first run", deploy_postgres_install, cfg, databases=(spec,), extensions=extensions)
    as_owner = f"PGPASSWORD={PG_PASSWORD} psql -XAtq -h 127.0.0.1 -U {DB} -d {DB} -c"
    smoke_host.run(f"{as_owner} 'create table marker (id int); insert into marker values (42)'")
    second = deploy(smoke_host, "postgres second run", deploy_postgres_install, cfg, (spec,), extensions)

    assert second.mutating_changed_ops == []
    conf = "/etc/postgresql/17/main"
    assert smoke_host.run(f"cat {conf}/conf.d/20-ops-library.conf").stdout == render_conf_d(cfg)
    assert smoke_host.run(f"cat {conf}/pg_hba.conf").stdout == render_pg_hba(cfg)
    assert psql(smoke_host, "select extname from pg_extension where extname = 'pg_trgm'") == "pg_trgm"
    login = f"{as_owner} 'select id from marker'"
    assert smoke_host.out(login) == "42"

    # A new password is set in place; the data stays.
    new = DatabaseSpec(name=DB, owner=DB, password=SecretStr(PG_PASSWORD + "-2"))
    third = deploy(smoke_host, "postgres password change", deploy_postgres_install, cfg, (new,), extensions)
    assert third.mutating_changed_ops == [f"PostgreSQL | Ensure PostgreSQL role {DB}"]
    assert smoke_host.out(login.replace(PG_PASSWORD, PG_PASSWORD + "-2")) == "42"


@pytest.fixture
def redis_reset(smoke_host: SmokeHost) -> Iterator[None]:
    yield
    # Leave Redis without the smoke password and without the smoke key.
    smoke_host.run(f"REDISCLI_AUTH={REDIS_PASSWORD} redis-cli DEL opsdeploy:smoke", check=False)
    deploy(smoke_host, "redis reset", deploy_redis_install, RedisInstallConfig())


def test_redis_install(smoke_host: SmokeHost, redis_reset: None) -> None:
    cfg = RedisInstallConfig(requirepass_enabled=True, check_host="::1")
    password = SecretStr(REDIS_PASSWORD)

    deploy(smoke_host, "redis first run", deploy_redis_install, cfg, password)
    auth = f"REDISCLI_AUTH={REDIS_PASSWORD} redis-cli"
    smoke_host.run(f"{auth} SET opsdeploy:smoke kept")
    second = deploy(smoke_host, "redis second run", deploy_redis_install, cfg, password)

    assert second.mutating_changed_ops == []
    assert "NOAUTH" in smoke_host.run("redis-cli PING", check=False).stdout
    assert smoke_host.out("stat -c '%U %G %a' /etc/redis/redis.conf /var/lib/redis").splitlines() == [
        "root redis 640",
        "redis redis 750",
    ]
    assert smoke_host.out("find /etc/redis -name 'redis.conf.*~' ! -perm 0640 ! -user root") == ""

    # A config written behind the server's back is picked up; the data survives.
    pid = smoke_host.out("systemctl show -p MainPID --value redis-server")
    smoke_host.run(f"{auth} SAVE")
    smoke_host.run("sleep 2 && touch /etc/redis/redis.conf")
    stale = deploy(smoke_host, "redis stale config", deploy_redis_install, cfg, password)
    assert stale.mutating_changed_ops == ["Redis | Restart redis-server if it runs an older configuration"]
    assert smoke_host.out("systemctl show -p MainPID --value redis-server") != pid
    assert smoke_host.out(f"{auth} GET opsdeploy:smoke") == "kept"
