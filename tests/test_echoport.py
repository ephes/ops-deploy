"""Deploy-level scenarios for echoport against the fake connector."""

import hashlib
import json
import shlex
from pathlib import Path
from typing import Any

import bcrypt
import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.echoport import EchoportConfig, MinioAccount, NyxmonCheck, deploy_echoport
from ops_deploy.services.echoport.deploy import (
    _django_hash,
    admin_current,
    check_secrets,
    nyxmon_checks,
    render_env,
    render_policy,
    render_role,
    render_route,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.echoport_fixtures import make_source
from tests.hsts import hsts_headers

HOME = "/home/echoport"
SITE = f"{HOME}/site"
UNIT = "/etc/systemd/system/echoport.service"
ROUTE = "/etc/traefik/dynamic/echoport.yml"
REFRESH = f"{SITE}/staging-db-refresh.sh"
DOMAIN = "echoport.example.invalid"
SECRET_VALUES = {
    "django_secret_key": "echoport-fixture-django-key-0123456789",
    "fastdeploy_base_url": "https://deploy.example.invalid",
    "fastdeploy_service_token": "echoport-fixture-fd-token-0123",
    "admin_username": "echoport-fixture-admin",
    "admin_password": "echoport-fixture-admin-password",
    "admin_email": "admin@example.invalid",
    "basic_auth_password": "echoport-fixture-basic-pw",
    "minio_secret_key": "echoport-fixture-minio-secret-0123",
}
# The MinIO account of the cleanup alias (deploy-echoport.yml's echoport-retention).
ACCOUNT = MinioAccount()
ACCOUNT_USER = "bk-" + hashlib.sha256(b"echoport-retention").hexdigest()[:17]
POLICY_FILE = "/etc/minio/policies/backup-echoport-retention.json"
ACCOUNT_PROBE = " probe /usr/local/bin/mc local backup-echoport-retention "
ACCOUNT_LOGIN = "/usr/local/bin/mc ls minio/backups >/dev/null && echo ok"
# Without an account: the alias takes both credentials from the secrets.
ROOT_STYLE = {**SECRET_VALUES, "minio_access_key": "echoport-fixture-minio-user"}
UV_SYNC = (
    f"cd {SITE} && runuser -u echoport -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --frozen --no-dev --no-default-groups --python 3.13"
)
ITEMIZED_CHANGE = [">f.st...... config/settings/production.py"]
VENV_PROBE = "echo broken"
ADMIN_PROBE = "One line per staff"
MIGRATE_PROBE = "migrate --check"
STATIC_PROBE = "staticfiles/staticfiles.json"
OWNER_PROBE = "! -user echoport"
MC_PROBE = "alias list minio"
NYXMON_DB_PROBE = "test -f /home/nyxmon/site/db.sqlite3"
NYXMON_CHECK_PROBE = "NYXMON_APPLY=0"
CRONS = {
    "scheduled": "Echoport scheduled backups",
    "cleanup": "Echoport cleanup old backups",
    "staging": "Echoport staging DB refresh",
}
READ_ONLY = [
    "Deploy echoport | Require the MinIO admin alias local of root",
    "Deploy echoport | Verify MinIO account echoport-retention",
    "Deploy echoport | Verify the cleanup user can reach the MinIO bucket",
    "Deploy echoport | Check Echoport listens only on 127.0.0.1:10018",
]


def stdin_writes(run: FakeRun) -> list[tuple[str, str]]:
    """Stdin of every command but the Nyxmon check probe, which reads the check payload."""

    return [(command, text) for command, text in run.stdin if NYXMON_CHECK_PROBE not in command]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def admin_line(username: str, email: str, password: str, flags: str = "11") -> str:
    encoded = "pbkdf2_sha256$1000$fixturesalt"
    full = _django_hash(password, encoded)
    assert full is not None
    return f"{digest(username)} {digest(email)} {flags} {encoded} {digest(full)}"


def make_cfg(tmp_path: Path, **overrides: Any) -> EchoportConfig:
    fields: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": SecretRef("secrets/prod/echoport.yml"),
        "traefik_host": DOMAIN,
        "django_allowed_hosts": ("127.0.0.1", DOMAIN),
        "minio_url": "http://127.0.0.1:9001",
        "staging_db_refresh_enabled": True,
        "staging_db_refresh_targets": ("homepage-production-db",),
        "nyxmon": NyxmonCheck(),
        "minio_account": ACCOUNT,
        **overrides,
    }
    return EchoportConfig(**fields)


@pytest.fixture
def cfg(tmp_path: Path) -> EchoportConfig:
    return make_cfg(tmp_path)


def values(cfg: EchoportConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    base = SECRET_VALUES if cfg.minio_account is not None else ROOT_STYLE
    return SecretValues(cfg.secrets, {**base, **changes})


def route_text(cfg: EchoportConfig, secrets: SecretValues) -> str:
    return render_route(cfg, secrets, traefik_config(cfg, secrets), hash_password(secrets["basic_auth_password"]))


def converged(cfg: EchoportConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where echoport is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets).reveal().decode(),
        UNIT: render_role("echoport.service.j2", cfg, secrets),
        ROUTE: route_text(cfg, secrets),
        REFRESH: render_role("staging-db-refresh.sh.j2", cfg, secrets),
        f"{SITE}/pyproject.toml": (cfg.source_path / "pyproject.toml").read_text(),
        f"{SITE}/uv.lock": (cfg.source_path / "uv.lock").read_text(),
    }
    if cfg.minio_account is not None:
        content[POLICY_FILE] = render_policy(cfg.minio_account)
    content.update(drift)
    responses: dict[str, Any] = {**fakehost.LINUX, **fakehost.system_account("echoport", HOME)}
    for path in (HOME, SITE, f"{SITE}/cache", f"{HOME}/logs", f"{SITE}/src", f"{SITE}/src/backups"):
        responses.update(fakehost.directory(path, user="echoport"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.directory("/etc/minio/policies", mode="drwxr-x---"))
    for path, text in content.items():
        owner = "echoport" if path.startswith(SITE) else "root"
        mode = {f"{SITE}/.env": "-rw-------", REFRESH: "-rwxr-x---", POLICY_FILE: "-rw-r-----"}.get(path, "-rw-r--r--")
        responses.update(fakehost.file(path, text, user=owner, mode=mode))
    for log in ("scheduler", "cleanup", "staging-db-refresh"):
        responses.update(fakehost.file(f"{HOME}/logs/{log}.log", "", user="echoport", mode="-rw-r-----"))
    responses.update(fakehost.symlink(f"{SITE}/venv", f"{SITE}/.venv", user="echoport"))
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("echoport.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    responses[VENV_PROBE] = ["Python 3.13.5"]
    responses[MIGRATE_PROBE] = ["current"]
    responses[STATIC_PROBE] = ["present"]
    responses[ADMIN_PROBE] = [
        "3 objects imported automatically (use -v 2 for details).",
        admin_line(secrets["admin_username"], secrets.get("admin_email", ""), secrets["admin_password"]),
    ]
    for name in CRONS.values():
        responses[f'"name":"{name}"'] = ["unchanged"]
    access = ACCOUNT_USER if cfg.minio_account is not None else secrets["minio_access_key"]
    responses[MC_PROBE] = [digest("\n".join((cfg.minio_url, access, secrets["minio_secret_key"])))]
    responses[ACCOUNT_PROBE] = ["policy=ok user=attached"]
    responses[ACCOUNT_LOGIN] = ["ok"]
    responses[NYXMON_DB_PROBE] = ["present"]
    responses[NYXMON_CHECK_PROBE] = ["changed=false"]
    return responses


def deploy(
    cfg: EchoportConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_echoport, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or fakehost.LINUX
    )
    assert run.succeeded, run.error
    return run


def changed_names(run: FakeRun) -> set[str]:
    return {name.removeprefix("Deploy echoport | ") for name in run.mutating_changed_ops}


def cron_edits(run: FakeRun) -> list[str]:
    return [c for c in run.executed_commands if c.startswith("python3 -I -c ") and '"job"' in shlex.split(c)[-1]]


def test_first_run_installs_everything(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/echoport -s /bin/bash -g echoport -r -M echoport" in commands
    assert UV_SYNC in commands
    migrate = next(c for c in commands if "manage.py migrate --noinput" in c)
    collect = next(c for c in commands if "manage.py collectstatic --noinput" in c)
    admin = next(c for c in commands if "ensure_superuser" in c)
    start = commands.index("systemctl start echoport.service")
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index(collect) < commands.index(admin) < start
    assert "systemctl restart echoport.service" not in commands
    # Like the role's django_manage: python manage.py in the site root as the service user.
    assert migrate.startswith(f"cd {SITE} && runuser -u echoport -- env HOME={HOME} DJANGO_SETTINGS_MODULE=")
    assert f"exec {SITE}/.venv/bin/python manage.py migrate --noinput" in migrate
    # The env file, admin credentials, MinIO account and mc alias only travel on stdin.
    assert len(run.stdin) == 4
    stdin = dict(run.stdin)
    user_add = next(c for c in commands if "admin user add local" in c)
    assert stdin[user_add] == f"{ACCOUNT_USER}\n{SECRET_VALUES['minio_secret_key']}\n"
    # The account first, through root's admin alias, before anything else.
    account_ops = [
        "/usr/local/bin/mc admin info local",
        "/usr/local/bin/mc admin policy create local backup-echoport-retention " + POLICY_FILE,
        user_add,
        f"/usr/local/bin/mc admin policy attach local backup-echoport-retention --user {ACCOUNT_USER}",
    ]
    positions = [next(i for i, c in enumerate(commands) if c.startswith(op)) for op in account_ops]
    assert positions == sorted(positions)
    assert positions[-1] < commands.index("useradd -d /home/echoport -s /bin/bash -g echoport -r -M echoport")
    assert run.upload(POLICY_FILE).decode() == render_policy(ACCOUNT)
    assert stdin[admin] == (
        f"{SECRET_VALUES['admin_username']}\n{SECRET_VALUES['admin_email']}\n{SECRET_VALUES['admin_password']}\n"
    )
    alias = next(c for c in commands if "alias import minio" in c)
    assert json.loads(stdin[alias]) == {
        "url": "http://127.0.0.1:9001",
        "accessKey": ACCOUNT_USER,
        "secretKey": SECRET_VALUES["minio_secret_key"],
        "api": "s3v4",
        "path": "auto",
    }
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    uploaded = run.upload(ROUTE).decode()
    auth_hash = _hash_in(uploaded)
    assert bcrypt.checkpw(SECRET_VALUES["basic_auth_password"].encode(), auth_hash.encode())
    assert uploaded == render_route(cfg, secrets, traefik_config(cfg, secrets), auth_hash)


def _hash_in(route: str) -> str:
    line = next(line for line in route.splitlines() if line.strip().startswith('- "admin:'))
    return line.strip()[len('- "admin:') : -1]


def test_second_run_changes_nothing_mutating(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert stdin_writes(run) == []
    assert not any("rm -rf" in c or "chown" in c for c in run.executed_commands)


def test_code_change_syncs_deps_migrates_and_restarts(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    rsync = RecordingRsyncRunner(responses={f"{cfg.source_path}/src/django/": ITEMIZED_CHANGE})
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert changed_names(run) == {
        "Sync echoport source",
        f"uv sync {SITE}",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart echoport.service",
    }
    argv = next(a for a in rsync.calls if "--dry-run" not in a)
    assert argv[-1] == f"root@localhost:{SITE}/" or argv[-1].endswith(f":{SITE}/")
    assert "--delete" in argv
    assert "--chown=echoport:echoport" in argv
    for exclude in (
        "db.sqlite3",
        "db.sqlite3-*",
        "media/",
        "staticfiles/",
        "src/",
        "cache",
        "/.env",
        "/venv",
        "/uv.lock",
        "/staging-db-refresh.sh",
        "/pyproject.toml",
        ".venv",
    ):
        assert f"--exclude={exclude}" in argv, exclude


def test_package_sources_are_synced_below_the_site(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    rsync = RecordingRsyncRunner(responses={f"{cfg.source_path}/src/backups/": ITEMIZED_CHANGE})
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert changed_names(run) == {
        "Sync echoport src/backups/",
        f"uv sync {SITE}",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart echoport.service",
    }
    argv = next(a for a in rsync.calls if "--dry-run" not in a)
    assert argv[-1].endswith(f":{SITE}/src/backups/")
    assert "--exclude=src/" not in argv


def test_lockfile_change_resyncs_dependencies(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/uv.lock": "version = 0\n"}))

    assert changed_names(run) == {
        "Copy uv.lock from source",
        f"uv sync {SITE}",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart echoport.service",
    }


def test_secret_rotation_rewrites_env_and_restarts(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    rotated = values(cfg, django_secret_key="echoport-fixture-django-key-rotated-0123")
    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert changed_names(run) == {
        "Write .env",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart echoport.service",
    }


def test_admin_password_rotation_only_updates_the_admin(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, values(cfg, admin_password="echoport-fixture-new-password"), converged(cfg, secrets))

    assert changed_names(run) == {"Ensure Echoport admin user"}


def test_admin_without_email_does_not_enforce_one(cfg: EchoportConfig) -> None:
    secrets = SecretValues(cfg.secrets or SecretRef("secrets/prod/echoport.yml"), SECRET_VALUES)
    no_email = {k: v for k, v in SECRET_VALUES.items() if k != "admin_email"}
    bare = SecretValues(secrets.ref, no_email)
    responses = converged(cfg, bare)
    responses[ADMIN_PROBE] = [admin_line(bare["admin_username"], "someone@example.invalid", bare["admin_password"])]
    run = deploy(cfg, bare, responses)

    assert run.mutating_changed_ops == []


def test_unit_change_reloads_and_restarts(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{UNIT: "[Unit]\n"}))

    assert changed_names(run) == {
        "Install systemd unit echoport.service",
        "Reload systemd for echoport.service",
        "Restart echoport.service",
    }


def test_route_drift_restarts_traefik_only(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert changed_names(run) == {"Write Traefik route echoport", "Restart Traefik for echoport"}


def test_basic_auth_password_rotation_rehashes_the_route(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, values(cfg, basic_auth_password="echoport-fixture-new-basic-pw"), converged(cfg, secrets))

    assert changed_names(run) == {"Write Traefik route echoport", "Restart Traefik for echoport"}


def test_traefik_disabled_writes_no_route(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path, traefik_enabled=False)
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert not any("traefik" in name.lower() for name in run.changed_ops + [op.name for op in run.ops])
    assert run.mutating_changed_ops == []


@pytest.mark.parametrize("job", CRONS)
def test_cron_drift_rewrites_only_that_entry(cfg: EchoportConfig, job: str) -> None:
    secrets = values(cfg)
    responses = converged(cfg, secrets)
    responses[f'"name":"{CRONS[job]}"'] = ["pending"]
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {f"Cron job {CRONS[job]}: present"}
    [command] = cron_edits(run)
    params = json.loads(shlex.split(command)[-1])
    assert params["apply"] is True
    assert params["name"] == CRONS[job]
    assert params["state"] == "present"


def test_cron_jobs_match_the_roles_commands(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = converged(cfg, secrets)
    for name in CRONS.values():
        responses[f'"name":"{name}"'] = ["pending"]
    run = deploy(cfg, secrets, responses)

    jobs = [json.loads(shlex.split(c)[-1]) for c in cron_edits(run)]
    by_name = {job["name"]: job for job in jobs}
    scheduled = by_name[CRONS["scheduled"]]
    assert (scheduled["minute"], scheduled["hour"]) == ("*/5", "*")
    assert scheduled["job"] == (
        f"cd {SITE} && DJANGO_SETTINGS_MODULE=config.settings.production {SITE}/.venv/bin/python manage.py "
        f"run_scheduled_backups >> {HOME}/logs/scheduler.log 2>&1"
    )
    cleanup = by_name[CRONS["cleanup"]]
    assert (cleanup["minute"], cleanup["hour"]) == ("0", "3")
    assert cleanup["job"].endswith(f"manage.py cleanup_old_backups >> {HOME}/logs/cleanup.log 2>&1")
    staging = by_name[CRONS["staging"]]
    assert (staging["minute"], staging["hour"]) == ("20", "2")
    assert staging["job"] == f"cd {SITE} && {REFRESH} >> {HOME}/logs/staging-db-refresh.log 2>&1"


def test_disabled_jobs_are_removed_not_added(tmp_path: Path) -> None:
    cfg = make_cfg(
        tmp_path,
        scheduler_enabled=False,
        cleanup_enabled=False,
        minio_url="",
        staging_db_refresh_enabled=False,
        minio_account=None,
    )
    secrets = values(cfg)
    responses = converged(cfg, secrets)
    for name in CRONS.values():
        responses[f'"name":"{name}"'] = ["pending"]
    run = deploy(cfg, secrets, responses)

    assert {name for name in changed_names(run) if name.startswith("Cron job")} == {
        f"Cron job {name}: absent" for name in CRONS.values()
    }
    assert not any(path.endswith(".log") or path == REFRESH for path in run.uploaded_paths)
    assert not any("alias import" in c or "mc admin" in c for c in run.executed_commands)


def test_missing_log_files_and_staging_script_are_created(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = {k: v for k, v in converged(cfg, secrets).items() if "logs/" not in k and REFRESH not in k}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {
        "Ensure log file scheduler.log",
        "Ensure log file cleanup.log",
        "Ensure log file staging-db-refresh.log",
        "Install staging DB refresh helper script",
    }
    assert run.upload(REFRESH).decode() == render_role("staging-db-refresh.sh.j2", cfg, secrets)


@pytest.mark.parametrize("account", [True, False], ids=["scoped account", "secrets only"])
def test_mc_alias_is_set_when_it_differs(tmp_path: Path, account: bool) -> None:
    cfg = make_cfg(tmp_path, minio_account=ACCOUNT if account else None)
    secrets = values(cfg)
    for stored in (["none"], [digest("other")], []):
        run = deploy(cfg, secrets, {**converged(cfg, secrets), MC_PROBE: stored})

        # An alias without the secret does not prove the account holds it: upserted too.
        expected = {"Configure mc alias for the cleanup user"}
        if account:
            expected.add("Create or update MinIO user of echoport-retention")
        assert changed_names(run) == expected
        command, stdin = run.stdin[-1]
        # mc reads a private file the service user owns, not the root-owned stdin pipe.
        assert command.endswith(
            f'runuser -u echoport -- env HOME={HOME} /usr/local/bin/mc alias import minio "$d/alias.json"'
        )
        assert "chmod 0711" in command
        assert 'chown echoport "$d"' not in command
        assert "rm -rf" in command
        assert SECRET_VALUES["minio_secret_key"] not in command
        assert json.loads(stdin)["secretKey"] == SECRET_VALUES["minio_secret_key"]


def test_unreachable_bucket_fails_the_deploy(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), "mc ls minio/backups >/dev/null": {"success": False}}
    run = run_deploy_fake(deploy_echoport, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == READ_ONLY[2]


def test_pending_migration_runs_without_a_code_change(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), MIGRATE_PROBE: []})

    # A retry after a failed migrate must restart: the workers still run the old code.
    assert changed_names(run) == {
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart echoport.service",
    }


def test_missing_static_manifest_runs_collectstatic_only(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), STATIC_PROBE: []})

    assert changed_names(run) == {"manage.py collectstatic --noinput"}


@pytest.mark.parametrize("version", ["Python 3.12.3", "broken"])
def test_a_venv_on_the_wrong_python_is_rebuilt(cfg: EchoportConfig, version: str) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), VENV_PROBE: [version]})

    assert changed_names(run) == {
        f"Remove {SITE}/.venv unless it runs Python 3.13",
        f"uv sync {SITE}",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart echoport.service",
    }
    commands = run.executed_commands
    assert commands.index(f"rm -rf {SITE}/.venv") < commands.index(UV_SYNC)


def test_foreign_owned_files_are_chowned(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), OWNER_PROBE: [f"{SITE}/db.sqlite3"]})

    assert changed_names(run) == {f"Set ownership of {SITE}"}
    assert f"chown -R echoport:echoport {SITE}" in run.executed_commands


def test_nyxmon_check_is_upserted_when_it_differs(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), NYXMON_CHECK_PROBE: ["changed=true"]})

    assert changed_names(run) == {"Upsert Nyxmon Echoport json-metrics check"}
    command = run.executed_commands[-1]
    assert command.startswith("runuser -u nyxmon -- env HOME=/home/nyxmon ")
    assert "NYXMON_APPLY=1" in command
    assert "NYXMON_SERVICE_NAME=echoport" in command
    # The checks ride on stdin (probe and upsert), never on the command line.
    assert cfg.nyxmon is not None
    payload = json.dumps(nyxmon_checks(cfg.nyxmon), separators=(",", ":")) + "\n"
    assert dict(run.stdin)[command] == payload
    assert [text for c, text in run.stdin if NYXMON_CHECK_PROBE in c] == [payload]
    assert not any("NYXMON_CHECKS_JSON" in c or "freshness" in c for c in run.executed_commands + run.fact_commands)


def test_nyxmon_check_is_skipped_without_the_database(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), NYXMON_DB_PROBE: []})

    assert run.mutating_changed_ops == []
    assert not any(op.name.endswith("Nyxmon Echoport json-metrics check") for op in run.ops)


def test_nyxmon_check_payload_follows_the_playbook(cfg: EchoportConfig) -> None:
    assert cfg.nyxmon is not None
    [check] = nyxmon_checks(cfg.nyxmon)

    assert check["name"] == "Echoport backup freshness (homepage/python-podcast)"
    assert check["check_type"] == "json-metrics"
    assert check["check_interval"] == 300
    data = check["data"]
    assert data["url"] == "http://127.0.0.1:10018/api/health/"
    assert [c["path"] for c in data["checks"]] == [
        f"$.targets_by_name.{t}.status"
        for t in ("homepage-production-db", "python-podcast-production-db", "homepage-media", "python-podcast-media")
    ]
    assert {c["severity"] for c in data["checks"]} == {"critical"}
    suppression = data["notification_suppression"]
    assert suppression["reason"] == "echoport_backup_window_active"
    assert [c["value"] for c in suppression["active_if"]] == [0.5] * 4
    assert suppression["timeout"] == 3.0
    assert data["timeout"] == 10.0


def test_a_listener_check_failure_fails_the_deploy(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), "Echoport must listen only on": {"success": False}}
    run = run_deploy_fake(deploy_echoport, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == READ_ONLY[3]


def test_secrets_never_recorded(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = {**fakehost.LINUX, NYXMON_DB_PROBE: ["present"], NYXMON_CHECK_PROBE: ["changed=true"]}
    run = deploy(cfg, secrets, responses, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    text = run.all_text()
    assert ACCOUNT_USER in text
    for key, value in SECRET_VALUES.items():
        if key not in ("admin_username", "admin_email", "fastdeploy_base_url"):
            assert value not in text, key
    # The route holds only a bcrypt hash of the password.
    assert SECRET_VALUES["basic_auth_password"] not in text


def test_config_rejects_bad_values(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError):
        EchoportConfig(source_path=tmp_path)
    with pytest.raises(ConfigValidationError, match="not an echoport checkout"):
        make_cfg(tmp_path, source_path=tmp_path / "nothing")
    source = make_source(tmp_path / "ok")
    for bad in (
        {"app_host": "0.0.0.0"},
        {"site_path": "/srv/site"},
        {"cleanup_enabled": True, "minio_url": ""},
        {"rsync_additional_paths": ("src/missing/",)},
        {"rsync_additional_paths": (".",)},
        {"rsync_additional_paths": ("../",)},
        {"rsync_additional_paths": ("src/../",)},
        {"rsync_additional_paths": ("src",)},
        {"rsync_additional_paths": ("staticfiles/",)},
        {"rsync_additional_paths": ("/etc/",)},
        {"allowed_path_prefixes": ("relative/",)},
        {"python_version": "3"},
        {"django_settings_module": "config settings"},
    ):
        with pytest.raises(ConfigValidationError):
            EchoportConfig(
                **{
                    "source_path": source,
                    "secrets": SecretRef("secrets/prod/echoport.yml"),
                    "traefik_host": DOMAIN,
                    "minio_url": "http://127.0.0.1:9001",
                    **bad,
                }
            )


def test_missing_and_placeholder_secrets_are_refused(cfg: EchoportConfig) -> None:
    complete = values(cfg)
    check_secrets(cfg, complete)
    for key in ("django_secret_key", "fastdeploy_service_token", "basic_auth_password", "minio_secret_key"):
        partial = SecretValues(complete.ref, {k: v for k, v in SECRET_VALUES.items() if k != key})
        with pytest.raises(MissingSecretKeysError, match=key):
            check_secrets(cfg, partial)
    for change in (
        {"django_secret_key": "CHANGEME"},
        {"django_secret_key": "development-secret-key-change-in-production"},
        {"basic_auth_password": "CHANGEME"},
    ):
        with pytest.raises(ValueError, match=f"placeholders: {next(iter(change))}"):
            check_secrets(cfg, values(cfg, **change))
    with pytest.raises(ValueError, match="single lines"):
        check_secrets(cfg, values(cfg, django_secret_key="a\nb"))


def test_without_cleanup_and_basic_auth_those_secrets_are_not_required(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path, cleanup_enabled=False, basic_auth_enabled=False, minio_url="", minio_account=None)
    keys = {
        k: v
        for k, v in SECRET_VALUES.items()
        if k not in ("basic_auth_password", "minio_access_key", "minio_secret_key")
    }
    assert cfg.secrets is not None
    check_secrets(cfg, SecretValues(cfg.secrets, keys))


def test_admin_current() -> None:
    line = admin_line("admin", "a@example.invalid", "pw")
    assert admin_current(line, "admin", "a@example.invalid", "pw")
    assert admin_current(line, "admin", "", "pw")
    assert not admin_current(line, "admin", "a@example.invalid", "other")
    assert not admin_current(line, "admin", "b@example.invalid", "pw")
    assert not admin_current(line, "root", "a@example.invalid", "pw")
    assert not admin_current(admin_line("admin", "a", "pw", flags="10"), "admin", "a", "pw")
    other_hasher = f"{digest('admin')} {digest('')} 11 argon2$argon2id$v=19 {digest('x')}"
    assert not admin_current(other_hasher, "admin", "", "pw")
    assert not admin_current("", "admin", "", "pw")


def test_a_failing_migrations_probe_runs_migrate_and_probes_again(cfg: EchoportConfig) -> None:
    # The probe crashed (not "pending"): the step runs, then the probe must pass.
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), MIGRATE_PROBE: [FAILED]}

    run = deploy(cfg, secrets, responses)

    assert run.succeeded
    assert "Deploy echoport | manage.py migrate --noinput" in run.mutating_changed_ops
    verify = run.op("Deploy echoport | Probe again: Echoport migrations")
    assert verify.changed
    assert verify.read_only
    assert any("migrate --check --plan" in c and "probe still fails" in c for c in run.executed_commands)


# -- the scoped MinIO account (deploy-echoport.yml's backup_account include) ----


ACCOUNT_STEPS = {
    "policy": "Create or update MinIO policy backup-echoport-retention",
    "user": "Create or update MinIO user of echoport-retention",
    "attach": "Attach MinIO policy backup-echoport-retention",
}


@pytest.mark.parametrize(
    ("state", "steps"),
    [
        ("policy=differs user=attached", {"policy"}),
        ("policy=missing user=attached", {"policy"}),
        ("policy=ok user=unattached", {"attach"}),
        ("policy=ok user=missing", {"user", "attach"}),
        ("policy=missing user=missing", {"policy", "user", "attach"}),
    ],
)
def test_account_steps_run_only_for_what_differs(cfg: EchoportConfig, state: str, steps: set[str]) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), ACCOUNT_PROBE: [state]})

    assert changed_names(run) == {ACCOUNT_STEPS[step] for step in steps}
    assert all("minio-root" not in c and "MINIO_ROOT" not in c for c in run.executed_commands)


def test_policy_file_drift_reinstalls_and_recreates_the_policy(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{POLICY_FILE: "{}\n"}))

    assert changed_names(run) == {"Install MinIO policy backup-echoport-retention", ACCOUNT_STEPS["policy"]}
    assert run.upload(POLICY_FILE).decode() == render_policy(ACCOUNT)


def test_a_secret_the_alias_cannot_log_in_with_is_upserted(cfg: EchoportConfig) -> None:
    # The alias holds the configured secret but MinIO refuses it (changed by hand).
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), ACCOUNT_LOGIN: []})

    assert changed_names(run) == {ACCOUNT_STEPS["user"]}
    [(command, stdin)] = stdin_writes(run)
    assert command.startswith("/usr/local/bin/mc admin user add local >/dev/null 2>&1 || ")
    assert stdin == f"{ACCOUNT_USER}\n{SECRET_VALUES['minio_secret_key']}\n"


def test_secret_rotation_upserts_the_user_then_the_alias(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    rotated = values(cfg, minio_secret_key="echoport-fixture-minio-rotated-0123")
    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert changed_names(run) == {ACCOUNT_STEPS["user"], "Configure mc alias for the cleanup user"}
    commands = run.executed_commands
    user_add = next(i for i, c in enumerate(commands) if "admin user add local" in c)
    alias = next(i for i, c in enumerate(commands) if "alias import minio" in c)
    assert user_add < alias


def test_without_root_admin_alias_nothing_changes_on_minio(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = {
        **converged(cfg, secrets),
        "/usr/local/bin/mc admin info local": {"success": False},
        ACCOUNT_PROBE: ["policy=missing user=missing"],
    }
    run = run_deploy_fake(deploy_echoport, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == READ_ONLY[0]
    assert not any("mc admin policy" in c or "mc admin user" in c for c in run.executed_commands)
    assert stdin_writes(run) == []


def test_an_account_that_fails_verification_fails_the_deploy(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), " verify /usr/local/bin/mc local backup-": {"success": False}}
    run = run_deploy_fake(deploy_echoport, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == READ_ONLY[1]


def test_a_failing_account_probe_runs_every_account_step(cfg: EchoportConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), ACCOUNT_PROBE: [FAILED]})

    assert changed_names(run) == set(ACCOUNT_STEPS.values())
    assert run.op(READ_ONLY[1]).changed


def test_account_secrets_follow_the_roles_input_check(cfg: EchoportConfig) -> None:
    check_secrets(cfg, values(cfg))
    for short in ("x" * 31, "x" * 41):
        with pytest.raises(ValueError, match="32 to 40 characters"):
            check_secrets(cfg, values(cfg, minio_secret_key=short))
    # The access key is the derived account user; root credentials cannot slip in.
    with pytest.raises(ValueError, match="minio_access_key"):
        check_secrets(cfg, values(cfg, minio_access_key="minio-root-user"))
    with pytest.raises(ConfigValidationError, match="requires cleanup_enabled"):
        make_cfg(cfg.source_path.parent / "other", cleanup_enabled=False)


def test_route_sends_hsts_without_preload(cfg: EchoportConfig) -> None:
    assert len(hsts_headers(route_text(cfg, values(cfg)))) == 1
