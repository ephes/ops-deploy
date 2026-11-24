"""``deploy_postgres_install`` against the fake connector."""

import hashlib
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError
from pyinfra.api import DeployError

from ops_deploy.helpers.postgres import scram_verifier, state_command
from ops_deploy.infra import DatabaseSpec, ExtensionSpec, PostgresInstallConfig, deploy_postgres_install
from ops_deploy.infra._common import deb822_sources
from ops_deploy.infra.postgres_install import Cluster, clusters_named, refuse_other_major, render_conf_d, render_pg_hba
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

PASSWORD = "postgres-fixture-password"
# The cluster probe of deploy_postgres_install (postgres_install.cluster_probe).
PROBE = "command -v pg_lsclusters"
APP = DatabaseSpec(name="app", owner="app", password=SecretStr(PASSWORD))
CFG = PostgresInstallConfig()
CONF_DIR = "/etc/postgresql/17/main"
PACKAGES = ("postgresql-17", "postgresql-client-17", "postgresql-contrib-17", "libpq-dev", "python3-psycopg2")
SOURCES = deb822_sources(
    name="postgresql",
    uris="https://apt.postgresql.org/pub/repos/apt",
    suites=("noble-pgdg",),
    components=("main",),
    signed_by="/etc/apt/keyrings/postgresql.asc",
)


def stored_role(password: str) -> str:
    verifier = scram_verifier(password, salt=b"0123456789abcdef")
    return f"role|t|{verifier.split('$')[1]}|{hashlib.sha256(verifier.encode()).hexdigest()}"


def installed(*packages: str, provides: str = "") -> dict[str, Any]:
    return {"dpkg-query -W -f=": [f"ii |{name}|{provides}" for name in packages]}


def owned_by_postgres(path: str, content: str, mode: str) -> dict[str, Any]:
    return {**fakehost.file(path, content), **fakehost.stat(path, user="postgres", mode=mode)}


def converged(cfg: PostgresInstallConfig = CFG) -> dict[str, Any]:
    """A host the role has set up: every file, package, unit and the app database in place."""

    return {
        **LINUX,
        "command -v apt-get": ["/usr/bin/apt-get"],
        ". /etc/os-release": ["noble"],
        **fakehost.directory("/etc/apt/keyrings"),
        **fakehost.file("/etc/apt/keyrings/postgresql.asc", "key"),
        **fakehost.directory("/etc/apt/sources.list.d"),
        **fakehost.file("/etc/apt/sources.list.d/postgresql.sources", SOURCES),
        **fakehost.apt_cache_fresh(),
        **installed(*PACKAGES),
        **fakehost.directory(CONF_DIR, user="postgres"),
        **fakehost.directory(f"{CONF_DIR}/conf.d", user="postgres"),
        **owned_by_postgres(f"{CONF_DIR}/conf.d/20-ops-library.conf", render_conf_d(cfg), "-rw-r--r--"),
        **owned_by_postgres(f"{CONF_DIR}/pg_hba.conf", render_pg_hba(cfg), "-rw-r-----"),
        **fakehost.service("postgresql.service"),
        **fakehost.service("postgresql@17-main.service"),
        state_command("app", "app", "postgres"): [stored_role(PASSWORD), "db|app", "schema|app"],
        "pg_extension": ["1"],
        "stat -c %a ": ["755"],
        # The host's cluster on cfg's major and port.
        PROBE: [f"{cfg.version} {cfg.cluster_name} {cfg.port} online postgres /d /l", "PG_LSCLUSTERS_OK"],
    }


def run(responses: dict[str, Any], cfg: PostgresInstallConfig = CFG, **kwargs: Any) -> FakeRun:
    # Without a probe answer: a fresh host without PostgreSQL tooling.
    responses = {**responses, PROBE: responses.get(PROBE, ["PG_LSCLUSTERS_ABSENT"])}
    result = run_deploy_fake(deploy_postgres_install, cfg, responses=responses, **kwargs)
    assert result.succeeded, result.error
    return result


def test_converged_host_changes_nothing() -> None:
    result = run(converged(), databases=(APP,), extensions=(ExtensionSpec(name="unaccent", database="app"),))

    assert result.changed_ops == []
    assert result.stdin == []


def test_fresh_host_installs_configures_and_creates() -> None:
    responses = {**LINUX, "command -v apt-get": ["/usr/bin/apt-get"], ". /etc/os-release": ["noble"]}

    result = run(responses, databases=(APP,), extensions=(ExtensionSpec(name="uuid-ossp", database="app"),))

    assert result.uploaded_paths[:3] == [
        "/etc/apt/sources.list.d/postgresql.sources",
        f"{CONF_DIR}/conf.d/20-ops-library.conf",
        f"{CONF_DIR}/pg_hba.conf",
    ]
    assert result.upload("/etc/apt/sources.list.d/postgresql.sources").decode() == SOURCES
    commands = "\n".join(result.executed_commands)
    assert "apt-get update" in commands
    assert all(package in commands for package in PACKAGES)
    # Started after the config is written (a stopped server is started, not restarted).
    assert commands.index("pg_hba.conf") < commands.index("systemctl start postgresql.service")
    assert 'CREATE DATABASE "app" OWNER "app"' in commands
    assert 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"' in commands
    # The password only travels as a SCRAM verifier on stdin.
    assert PASSWORD not in result.all_text()
    assert all(PASSWORD not in text for _, text in result.stdin)


def test_changed_pg_hba_is_rewritten_and_restarts_once() -> None:
    responses = converged()
    responses.update(owned_by_postgres(f"{CONF_DIR}/pg_hba.conf", "local all all trust\n", "-rw-r-----"))

    result = run(responses, databases=(APP,))

    assert result.changed_ops == [
        "PostgreSQL | Render pg_hba.conf",
        "PostgreSQL | Restart postgresql for the new configuration",
    ]
    assert [c for c in result.executed_commands if "restart" in c] == ["systemctl restart postgresql.service"]


def test_existing_data_is_never_dropped_or_recreated() -> None:
    # A database owned by someone else, a role with another password: both
    # are altered in place, nothing is dropped.
    responses = converged()
    responses[state_command("app", "app", "postgres")] = [stored_role("old-password"), "db|postgres", "schema|postgres"]

    result = run(responses, databases=(APP,))

    commands = "\n".join(result.executed_commands + [text for _, text in result.stdin])
    assert 'ALTER DATABASE "app" OWNER TO "app"' in commands
    assert 'ALTER ROLE "app" WITH LOGIN PASSWORD' in commands
    for word in ("DROP", "CREATE DATABASE", "TRUNCATE", "DELETE", "pg_dropcluster", "pg_createcluster"):
        assert word not in commands


def test_unmanaged_files_are_left_alone() -> None:
    cfg = PostgresInstallConfig(manage_conf_d=False, manage_pg_hba=False)
    responses = converged(cfg)
    responses.update(owned_by_postgres(f"{CONF_DIR}/pg_hba.conf", "anything\n", "-rw-r-----"))

    result = run(responses, cfg)

    assert result.changed_ops == []
    assert not any("conf.d" in path or "pg_hba" in path for path in result.uploaded_paths)


def test_repository_off_removes_it_like_the_role() -> None:
    cfg = PostgresInstallConfig(use_pgdg_repo=False)

    result = run(converged(cfg), cfg)

    assert result.changed_ops == [
        "PostgreSQL | Remove /etc/apt/sources.list.d/postgresql.sources",
        "PostgreSQL | Remove /etc/apt/keyrings/postgresql.asc",
    ]


def test_explicit_packages_and_codename() -> None:
    cfg = PostgresInstallConfig(packages=("postgresql-16",), extra_packages=(), repo_codename="bookworm", version="16")
    responses = {**LINUX, "command -v apt-get": ["/usr/bin/apt-get"]}

    result = run(responses, cfg)

    assert "Suites: bookworm-pgdg\n" in result.upload("/etc/apt/sources.list.d/postgresql.sources").decode()
    installs = [c for c in result.executed_commands if "apt-get" in c and "install" in c]
    assert len(installs) == 1
    assert "postgresql-16" in installs[0]
    assert "libpq-dev" not in installs[0]
    assert "/etc/postgresql/16/main/pg_hba.conf" in result.uploaded_paths


def test_refuses_non_debian_and_unknown_codename() -> None:
    no_apt = run_deploy_fake(deploy_postgres_install, CFG, responses=LINUX)
    assert not no_apt.succeeded
    assert "Debian-family" in str(no_apt.error)

    unknown = run_deploy_fake(
        deploy_postgres_install,
        CFG,
        responses={**LINUX, "command -v apt-get": ["/usr/bin/apt-get"], PROBE: ["PG_LSCLUSTERS_ABSENT"]},
    )
    assert not unknown.succeeded
    assert "codename" in str(unknown.error)


def test_refuses_conflicting_database_lists() -> None:
    twice = run_deploy_fake(deploy_postgres_install, CFG, databases=(APP, APP), responses=converged())
    assert not twice.succeeded
    assert "listed twice" in str(twice.error)

    other = DatabaseSpec(name="other", owner="app", password=SecretStr("different"))
    clash = run_deploy_fake(deploy_postgres_install, CFG, databases=(APP, other), responses=converged())
    assert not clash.succeeded
    assert "two different passwords" in str(clash.error)
    assert PASSWORD not in str(clash.error)


@pytest.mark.parametrize(
    "fields",
    [
        {"version": "17.1"},
        {"cluster_name": "Main"},
        {"listen_addresses": ("localhost'; evil",)},
        {"config_overrides": {"work_mem": "1\nfsync = off"}},
        {"config_overrides": {"bad key": 1}},
        {"pg_hba_rules": ({"type": "local", "database": "all", "user": "a b", "auth_method": "peer"},)},
        {"pg_hba_rules": ({"type": "remote", "database": "all", "user": "all", "auth_method": "peer"},)},
        {"repo_url": "http://plain.example.com"},
        {"port": 0},
        {"unknown": True},
    ],
)
def test_config_rejects(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        PostgresInstallConfig(**fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"name": "App", "owner": "app", "password": "x"},
        {"name": "app", "owner": "a-b", "password": "x"},
        {"name": "app", "owner": "app", "password": ""},
        {"name": "app", "owner": "app", "password": "pässword"},
    ],
)
def test_database_spec_rejects(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as excinfo:
        DatabaseSpec(**fields)
    assert "pässword" not in str(excinfo.value)


def test_virtual_contrib_package_counts_as_installed() -> None:
    responses = converged()
    responses.update(
        installed(
            "postgresql-17",
            "postgresql-client-17",
            "libpq-dev",
            "python3-psycopg2",
            provides="postgresql-17-jit-llvm (= 19), postgresql-contrib-17",
        )
    )

    assert run(responses, databases=(APP,)).changed_ops == []
    responses["dpkg-query -W -f="] = ["ii |postgresql-17|", "rc |libpq-dev|"]
    result = run(responses)
    (install,) = [c for c in result.executed_commands if "apt-get" in c and "install" in c]
    assert "libpq-dev" in install
    assert "postgresql-17 " not in install + " "


def test_other_port_targets_that_cluster_and_disabled_stays_disabled() -> None:
    cfg = PostgresInstallConfig(port=5433, service_enabled=False)
    responses = {**LINUX, "command -v apt-get": ["/usr/bin/apt-get"], ". /etc/os-release": ["noble"]}

    result = run(responses, cfg, databases=(APP,), extensions=(ExtensionSpec(name="pg_trgm", database="app"),))

    sql = [c for c in result.executed_commands if "psql" in c] + [c for c, _ in result.stdin]
    assert sql
    assert all(" -p 5433" in c for c in sql)
    assert not any("systemctl enable" in c for c in result.executed_commands)


def test_unreachable_server_while_planning_is_planned_as_new() -> None:
    # The probe swallows errors (server stopped or not installed yet); creates
    # are planned, and a CREATE of something that exists would fail, not alter.
    assert state_command("app", "app", "postgres").endswith("2>/dev/null || true")


LISTING_17 = "17 main 5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log"
ROW_17_DOWN = "17 main 5433 down   postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log"
ROW_19 = "19 main 5432 online postgres /var/lib/postgresql/19/main /var/log/postgresql/postgresql-19-main.log"
ROW_19_EMPTY = "19 main 5433 online postgres /var/lib/postgresql/19/main /var/log/postgresql/postgresql-19-main.log"
OK = "PG_LSCLUSTERS_OK"


def probe(*rows: str) -> list[str]:
    return [*rows, OK]


def test_clusters_named_reads_the_probe() -> None:
    assert clusters_named("\n".join(probe(ROW_17_DOWN, ROW_19)), "main") == [
        Cluster("17", 5433, False),
        Cluster("19", 5432, True),
    ]
    assert clusters_named("\n".join(probe(ROW_19)), "other") == []
    assert clusters_named(OK, "main") == []
    assert clusters_named("PG_LSCLUSTERS_ABSENT", "main") == []
    assert clusters_named("9.6 main 5432 online postgres /d /l\n" + OK, "main") == [Cluster("9.6", 5432, True)]
    # Another cluster without a port does not block; listed directories are fine.
    assert clusters_named(f"16 old <unknown> down postgres /d /l\n{ROW_19}\n{OK}", "main") == [
        Cluster("19", 5432, True)
    ]
    assert clusters_named(f"{ROW_19}\n{OK}\nLEFTOVER /var/lib/postgresql/19/main", "main") == [
        Cluster("19", 5432, True)
    ]


@pytest.mark.parametrize(
    ("listing", "message"),
    [
        ("PG_LSCLUSTERS_FAILED", "pg_lsclusters failed"),
        ("", "pg_lsclusters failed"),
        ("19 mainPG_LSCLUSTERS_FAILED", "pg_lsclusters failed"),
        (f"19 main\n{OK}", "unexpected pg_lsclusters output"),
        ("PG_LSCLUSTERS_ABSENT\nLEFTOVER /etc/postgresql/17/main", "cluster directories remain"),
        (f"{OK}\nLEFTOVER /var/lib/postgresql/17/main", "does not list"),
        (f"19 main <unknown> down postgres /d /l\n{OK}", "has no port"),
    ],
)
def test_probe_failures_are_refused(listing: str, message: str) -> None:
    with pytest.raises(DeployError, match=message):
        clusters_named(listing, "main")


def test_existing_cluster_on_its_major_passes() -> None:
    result = run({**converged(), PROBE: probe(LISTING_17)}, databases=(APP,))

    assert result.changed_ops == []


def test_failing_probe_stops_before_any_change() -> None:
    result = run_deploy_fake(deploy_postgres_install, CFG, responses={**converged(), PROBE: ["PG_LSCLUSTERS_FAILED"]})

    assert not result.succeeded
    assert "pg_lsclusters failed" in str(result.error)
    assert not result.executed_commands


def test_version_without_its_cluster_is_refused_before_any_change() -> None:
    # 19 configured while the data is still in 17/main: would configure an empty 19/main.
    cfg = PostgresInstallConfig(version="19")
    result = run_deploy_fake(deploy_postgres_install, cfg, responses={**converged(), PROBE: probe(LISTING_17)})

    assert not result.succeeded
    assert "upgrade it with pg_upgradecluster" in str(result.error)
    assert not result.executed_commands


def test_old_major_of_an_upgrade_is_refused() -> None:
    # 17 configured after the upgrade to 19: would configure and start the stopped 17/main.
    result = run_deploy_fake(deploy_postgres_install, CFG, responses={**converged(), PROBE: probe(ROW_17_DOWN, ROW_19)})

    assert not result.succeeded
    assert "deploy version 19" in str(result.error)
    assert not result.executed_commands


@pytest.mark.parametrize(
    ("version", "clusters", "message"),
    [
        ("17", [Cluster("19", 5432, True)], "deploy version 19"),  # old cluster already dropped
        ("19", [Cluster("9.6", 5432, True)], "upgrade it with pg_upgradecluster"),
        # The packages' auto-created empty 19/main on 5433 beside the live 17/main.
        ("19", [Cluster("17", 5432, True), Cluster("19", 5433, True)], "finish the upgrade"),
        ("19", [Cluster("17", 5433, True), Cluster("19", 5432, True)], "finish the upgrade"),
        ("17", [Cluster("9.6", 5433, False), Cluster("17", 5432, True)], None),
        ("19", [Cluster("17", 5433, False), Cluster("19", 5432, True)], None),
    ],
)
def test_refuse_other_major(version: str, clusters: list[Cluster], message: str | None) -> None:
    cfg = PostgresInstallConfig(version=version)
    if message is None:
        refuse_other_major(cfg, clusters)
    else:
        with pytest.raises(DeployError, match=message):
            refuse_other_major(cfg, clusters)
