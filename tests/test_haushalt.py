"""Deploy-level scenarios for haushalt against the fake connector (synthetic data only)."""

import base64
import getpass
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.services.haushalt import HaushaltConfig, RouteChecks, deploy_haushalt
from ops_deploy.services.haushalt.deploy import (
    RESTRICT_DATABASE,
    render_env,
    render_route,
    render_unit,
    upload_token_sha256,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.haushalt_fixtures import SOURCE_FILES, make_source
from tests.haushalt_legacy import LEGACY_ENV, LEGACY_ROUTE, LEGACY_UNIT

HOME = "/home/haushalt"
SITE = f"{HOME}/site"
DB = f"{HOME}/data/db.sqlite3"
UNIT = "/etc/systemd/system/haushalt.service"
ROUTE = "/etc/traefik/dynamic/haushalt.yml"
MARKER = "/var/lib/ops-deploy/haushalt/.ops-deploy-pending"
IDENTITY = "/var/lib/ops-deploy/haushalt/database-identity"
HOST = "haushalt.example.invalid"
SECRET_VALUES = {
    "django_secret_key": "haushalt-fixture-django-key-" + "0123456789" * 3,
    "upload_token": "haushalt-fixture-upload-token-0123456789abcdef",
}
UV_SYNC = (
    f"cd {SITE} && runuser -u haushalt -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={HOME}/venv "
    f"UV_PYTHON_INSTALL_DIR={HOME}/python /usr/local/bin/uv sync --frozen --only-group web "
    "--no-install-project --python 3.14"
)
UV_CHECK = "--no-install-project --python 3.14 --check"
MIGRATE_CHECK = "manage.py migrate --check"
ITEMIZED_CHANGE = [">f.st...... money/views.py"]
P = "Deploy haushalt service | "
READ_ONLY = [
    f"{P}Port preflight tcp/10067",
    f"{P}Refuse to replace a missing database",
    f"{P}Require gunicorn 23 or newer in /home/haushalt/venv",
    f"{P}Wait for port 127.0.0.1:10067",
    f"{P}Check http://127.0.0.1:10067/healthz",
]
NETWORKS = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")


def make_cfg(tmp_path: Path, **overrides: Any) -> HaushaltConfig:
    settings: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": SecretRef("secrets/prod/haushalt.yml"),
        "traefik_host": HOST,
        "allowed_networks": NETWORKS,
    }
    return HaushaltConfig(**{**settings, **overrides})


@pytest.fixture
def cfg(tmp_path: Path) -> HaushaltConfig:
    return make_cfg(tmp_path)


def values(cfg: HaushaltConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: HaushaltConfig) -> SecretValues:
    return values(cfg)


def converged(cfg: HaushaltConfig, secrets: SecretValues, **drift: str) -> dict[Any, Any]:
    """Facts of a host where haushalt is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{HOME}/haushalt.env": render_env(cfg, secrets).reveal().decode(),
        UNIT: render_unit(cfg),
        ROUTE: render_route(cfg),
        f"{SITE}/pyproject.toml": SOURCE_FILES["services/haushalt/pyproject.toml"],
        f"{SITE}/uv.lock": SOURCE_FILES["services/haushalt/uv.lock"],
        f"{SITE}/.python-version": SOURCE_FILES["services/haushalt/.python-version"],
    }
    content.update(drift)
    responses: dict[Any, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("haushalt", HOME, shell="/usr/sbin/nologin"),
    }
    for path in ("", "/site", "/data", "/static"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="haushalt", mode="drwx------"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        private = path.startswith(HOME)
        owner = "haushalt" if private else "root"
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    responses.update(fakehost.file(DB, "", user="haushalt", mode="-rw-------"))
    responses.update(fakehost.venv(f"{HOME}/venv"))
    responses["sys.version_info"] = ["3.14"]
    responses[UV_CHECK] = ["current"]
    responses[MIGRATE_CHECK] = ["current"]
    for unit in ("haushalt.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def deploy(
    cfg: HaushaltConfig,
    secrets: SecretValues,
    responses: dict[Any, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
    **kwargs: Any,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_haushalt,
        cfg,
        secrets,
        rsync=rsync or RecordingRsyncRunner(),
        responses=fakehost.LINUX if responses is None else responses,
        **kwargs,
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/haushalt -s /usr/sbin/nologin -g haushalt -r -M haushalt" in commands
    assert UV_SYNC in commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index("systemctl start haushalt.service")
    assert migrate.startswith(f"cd {SITE}/web && ")
    assert "collectstatic --noinput --clear" in migrate
    assert "umask 077;" in migrate
    assert "systemctl restart haushalt.service" not in commands
    assert any("chmod -R u+rwX,go-rwx" in c for c in commands)
    assert any(f"set -C; : > {DB}" in c for c in commands)
    assert sorted(path for path in run.uploaded_paths if path.startswith(SITE)) == [
        f"{SITE}/.python-version",
        f"{SITE}/pyproject.toml",
        f"{SITE}/uv.lock",
    ]
    # The environment file goes over stdin via secret_file, never as an upload.
    assert len(run.stdin) == 1
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    assert "systemctl restart traefik.service" not in commands


def test_second_run_changes_nothing_mutating(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any(c.startswith(("systemctl", "cd ", "find ", "chown")) for c in run.executed_commands)


def test_host_of_the_old_deploy_is_taken_over_in_place(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    """Against the old script's files: rewrite env, unit and route once, restart once, move nothing."""

    old_env = LEGACY_ENV.format(
        secret_key=SECRET_VALUES["django_secret_key"], token_sha256=upload_token_sha256(secrets)
    )
    responses = converged(cfg, secrets, **{f"{HOME}/haushalt.env": old_env, UNIT: LEGACY_UNIT, ROUTE: LEGACY_ROUTE})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}Write environment file",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Install systemd unit haushalt.service",
        f"{P}Write Traefik route haushalt",
        f"{P}Reload systemd for haushalt.service",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]
    # The environment's values are the old file's: only the header comment differs.
    ((_, payload),) = run.stdin
    new_env = base64.b64decode("".join(payload.split())).decode()
    assert new_env.splitlines()[1:] == old_env.splitlines()[1:]
    assert new_env.splitlines()[0] != old_env.splitlines()[0]
    # The unit: the header and gunicorn's --forwarder-headers= only.
    new_unit = run.upload(UNIT).decode().splitlines()
    old_unit = LEGACY_UNIT.splitlines()
    assert [i for i, (a, b) in enumerate(zip(new_unit, old_unit, strict=True)) if a != b] == [0, 14]
    assert new_unit[14] == old_unit[14].replace(" --access-logfile", " --forwarder-headers= --access-logfile")
    # The route: the same routers, services and allowlist, plus the edge-header middleware.
    new_route = yaml.safe_load(run.upload(ROUTE))["http"]
    old_route = yaml.safe_load(LEGACY_ROUTE)["http"]
    assert new_route["services"] == old_route["services"]
    secure = new_route["routers"]["haushalt-secure"]
    assert secure["middlewares"] == [*old_route["routers"]["haushalt-secure"]["middlewares"], "haushalt-edge-headers"]
    assert {k: v for k, v in secure.items() if k != "middlewares"} == {
        k: v for k, v in old_route["routers"]["haushalt-secure"].items() if k != "middlewares"
    }
    assert new_route["routers"]["haushalt-http"] == old_route["routers"]["haushalt-http"]
    assert set(new_route["middlewares"]) == {*old_route["middlewares"], "haushalt-edge-headers"}
    for name, middleware in old_route["middlewares"].items():
        assert new_route["middlewares"][name] == middleware
    # Nothing writes the database but its mode check and migrate.
    touching = [c for c in run.executed_commands if DB in c]
    # Only reads (the guard, the identity record and check) and migrate itself.
    allowed = ("chmod", "chown", "stat", "ls", "sh -c 'test ! -L", "install -d -o root", '[ "$(stat')
    reads = ("the database is missing",)
    assert [c for c in touching if not c.startswith(allowed) and not any(r in c for r in reads)] == []


def test_code_change_migrates_and_restarts_without_uv_sync(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}Sync web",
        f"{P}Own and privatize the synced tree",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]


def test_sync_ships_only_the_web_app_and_protects_host_state(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = [call for call in rsync.calls if "--dry-run" not in call]
    assert [call[-1].split(":", 1)[1] for call in real] == [f"{SITE}/web/"]
    assert real[0][-2].endswith("/daybook/services/haushalt/web/")
    for call in real:
        assert "--delete" in call
        assert "--chown=haushalt:haushalt" in call
        for pattern in ("*.sqlite3", "*.sqlite3-*", "staticfiles", ".env", "__pycache__", "*.pyc", ".DS_Store"):
            assert f"--exclude={pattern}" in call


def test_lockfile_change_syncs_dependencies(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/uv.lock": "version = 0\n"}))

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}Copy uv.lock",
        f"{P}uv sync /home/haushalt/site (web)",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]


def test_missing_venv_or_other_python_syncs_dependencies(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    responses["sys.version_info"] = ["3.13"]

    run = deploy(cfg, secrets, responses)

    assert f"{P}uv sync /home/haushalt/site (web)" in run.mutating_changed_ops
    del responses["sys.version_info"], responses[f"test -x {HOME}/venv/bin/python"]
    run = deploy(cfg, secrets, responses)
    assert UV_SYNC in run.executed_commands


def test_secret_rotation_rewrites_env_and_restarts(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, upload_token="rotated-fixture-upload-token-0123456789")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}Write environment file",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]
    assert "rotated-fixture-upload-token" not in run.all_text()


def test_allowlist_change_rewrites_the_route_without_a_restart(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path)
    narrower = make_cfg(tmp_path, allowed_networks=("100.64.0.0/10",))

    run = deploy(narrower, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == [f"{P}Write Traefik route haushalt"]
    assert '["100.64.0.0/10"]' in run.upload(ROUTE).decode()


def test_exposed_tree_is_privatized(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "! -type l -perm /077": [f"{SITE}/web/manage.py"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}Own and privatize the synced tree",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]


def test_exposed_database_is_restricted(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), **fakehost.file(DB, "", user="haushalt", mode="-rw-r--r--")}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [f"{P}Restrict the database"]


def test_missing_database_on_an_installed_host_fails_before_any_change(
    cfg: HaushaltConfig, secrets: SecretValues
) -> None:
    responses = converged(cfg, secrets)
    for key in [key for key in responses if isinstance(key, str) and DB in key]:
        del responses[key]
    responses[re.compile(r"is missing on an installed host")] = {"success": False}

    run = run_deploy_fake(deploy_haushalt, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == f"{P}Refuse to replace a missing database"
    # Only the read-only preflight and the guard ran.
    assert len(run.executed_commands) == 2
    assert "is missing on an installed host" in run.executed_commands[1]


def test_the_database_guard_allows_only_a_fresh_host(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    guard = next(c for c in run.executed_commands if "is missing on an installed host" in c)
    assert f"test -e {DB} || test ! -e {HOME}/haushalt.env ||" in guard
    assert f"test ! -L {DB} ||" in guard
    commands = run.executed_commands
    # A fresh host: the service user creates the empty database exclusively,
    # before the environment file that marks the host as installed.
    create = next(i for i, c in enumerate(commands) if f"set -C; : > {DB}" in c)
    assert commands[create].startswith("runuser -u haushalt -- ")
    env_write = next(i for i, (command, _) in enumerate(run.stdin) if "haushalt.env" in command)
    assert env_write == 0
    assert create < commands.index(run.stdin[0][0])
    # Nothing hands back a database that did not exist at plan time.
    assert not any(c.endswith(f" {DB} haushalt") for c in commands)
    assert f"test ! -e {DB} || test -f {DB} ||" in guard


def test_migrate_runs_between_recording_and_checking_the_database_identity(
    cfg: HaushaltConfig, secrets: SecretValues
) -> None:
    run = deploy(cfg, secrets)

    commands = run.executed_commands
    migrate = next(c for c in commands if "manage.py migrate --noinput" in c)
    assert migrate.index("the database is missing") < migrate.index("manage.py migrate --noinput")
    record = next(c for c in commands if c.endswith(f"mv -f {IDENTITY}.new {IDENTITY}"))
    assert record.startswith("install -d -o root -g root -m 0700 /var/lib/ops-deploy/haushalt && ")
    assert f"id=$(stat -c %d:%i {DB}) && " in record
    check = next(c for c in commands if "the database was replaced while migrate ran" in c)
    assert check.endswith(f"rm -f {IDENTITY}")
    assert commands.index(record) < commands.index(migrate) < commands.index(check)
    assert commands.index(check) < commands.index("systemctl start haushalt.service")
    guard = next(c for c in commands if "is missing on an installed host" in c)
    assert f"if test -e {IDENTITY}; then" in guard
    assert f"head -c 64 {IDENTITY}" in guard
    assert f"header=$(timeout 10 od -A n -t u1 -j 18 -N 2 {DB}) || exit 1;" in guard
    assert f"size=$(stat -c %s {DB}) || exit 1;" in guard
    assert "is not a rollback-journal database" in guard


def test_a_replaced_database_stops_the_run_before_the_restart(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses: dict[Any, Any] = {
        **converged(cfg, secrets, **{f"{HOME}/haushalt.env": "old\n"}),
        re.compile(r"the database was replaced while migrate ran"): {"success": False},
    }

    run = run_deploy_fake(deploy_haushalt, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == f"{P}Check the database identity"
    assert "systemctl restart haushalt.service" not in run.executed_commands
    assert f"rm -f {MARKER}" not in run.executed_commands


def test_a_restored_root_owned_database_is_handed_back_without_following_links(
    cfg: HaushaltConfig, secrets: SecretValues
) -> None:
    responses = {**converged(cfg, secrets), **fakehost.file(DB, "", user="root", mode="-rw-------")}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [f"{P}Restrict the database"]
    restrict = next(c for c in run.executed_commands if c.endswith(f" {DB} haushalt"))
    assert restrict.startswith("python3 -I -c ")
    assert restrict.endswith(f" {DB} haushalt")


def test_a_rollout_left_pending_is_finished(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    """A run that died after writing files: the next run reloads, migrates, restarts and clears the marker."""

    responses = {**converged(cfg, secrets), f"test -e {MARKER} && echo pending": ["pending"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Reload systemd to finish a pending rollout",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]
    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index("systemctl restart haushalt.service")
    assert commands[-1] == f"rm -f {MARKER}"


def test_the_marker_is_set_before_any_change_and_cleared_after_the_checks(
    cfg: HaushaltConfig, secrets: SecretValues
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/uv.lock": "version = 0\n"}))

    commands = run.executed_commands
    touch = next(i for i, c in enumerate(commands) if c.endswith(f"touch {MARKER}"))
    assert commands[touch].startswith("install -d -o root -g root -m 0700 /var/lib/ops-deploy/haushalt && ")
    assert touch < commands.index(UV_SYNC)
    assert all(not c.startswith(("cd ", "systemctl", "chown", "runuser")) for c in commands[:touch])
    assert MARKER not in run.uploaded_paths
    assert commands[-1] == f"rm -f {MARKER}"
    assert not any(c.startswith("rm -f") for c in commands[:-1])


def test_a_failed_check_keeps_the_marker(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses: dict[Any, Any] = {
        **converged(cfg, secrets, **{f"{HOME}/haushalt.env": "old\n"}),
        re.compile(r"healthz"): {"success": False},
    }

    run = run_deploy_fake(deploy_haushalt, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert any(c.endswith(f"touch {MARKER}") for c in run.executed_commands)
    assert f"rm -f {MARKER}" not in run.executed_commands


def test_port_in_use_by_another_process_fails_before_any_change(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses: dict[Any, Any] = {**converged(cfg, secrets), re.compile(r"^sh -c 'out=\$\(ss "): {"success": False}}

    run = run_deploy_fake(deploy_haushalt, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == f"{P}Port preflight tcp/10067"
    assert not any(c.startswith(("groupadd", "useradd", "systemctl")) for c in run.executed_commands)


def test_preflight_allows_the_service_itself(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    script = next(c for c in run.executed_commands if "ss -Hltnp" in c)
    assert "sport = :10067" in script
    assert "/system.slice/haushalt.service" in script
    assert run.executed_commands.index(script) == 0


def test_traefik_can_be_disabled(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, traefik_enabled=False, traefik_host=None, allowed_networks=())

    run = deploy(cfg, secrets)

    assert not any("Traefik" in op.name for op in run.ops)
    env = render_env(cfg, secrets).reveal().decode()
    assert "DJANGO_ALLOWED_HOSTS=127.0.0.1\n" in env
    assert "DJANGO_CSRF_TRUSTED_ORIGINS=\n" in env


def test_env_names_the_host_paths(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    env = render_env(cfg, secrets).reveal().decode()

    assert f"DJANGO_ALLOWED_HOSTS={HOST},127.0.0.1\n" in env
    assert f"DJANGO_CSRF_TRUSTED_ORIGINS=https://{HOST}\n" in env
    assert f"HAUSHALT_DATABASE_PATH={DB}\n" in env
    assert f"DJANGO_STATIC_ROOT={HOME}/static\n" in env
    assert f"HAUSHALT_UPLOAD_TOKEN_SHA256={upload_token_sha256(secrets)}\n" in env
    assert SECRET_VALUES["upload_token"] not in env


def test_route_checks(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, route_checks=RouteChecks(controller_login=True, refused_address="192.0.2.7"))
    urls: list[str] = []

    def fetch(url: str, verify: bool) -> tuple[int, str]:
        urls.append(f"{url} verify={verify}")
        return 302, f"https://{HOST}/login/?next=/"

    run = deploy(cfg, secrets, converged(cfg, secrets), fetch=fetch)

    assert urls == [f"https://{HOST}/ verify=True"]
    assert run.mutating_changed_ops == []
    refused = next(c for c in run.executed_commands if "192.0.2.7" in c)
    assert f"--resolve {HOST}:443:192.0.2.7" in refused
    assert f"{P}Check an anonymous request is sent to the login" in run.changed_ops


def test_anonymous_request_away_from_the_login_fails(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, route_checks=RouteChecks(controller_login=True, login_retries=2, login_delay=0))
    run = run_deploy_fake(
        deploy_haushalt,
        cfg,
        secrets,
        rsync=RecordingRsyncRunner(),
        responses=converged(cfg, secrets),
        fetch=lambda url, verify: (200, ""),
    )

    assert not run.succeeded


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: HaushaltConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="rotated-" + "9876543210" * 5) if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), upload_token_sha256(secrets), "rotated-" + "9876543210" * 5):
        assert value not in text


def test_env_rides_on_stdin_only(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    for command, payload in run.stdin:
        assert SECRET_VALUES["django_secret_key"] not in command
        decoded = base64.b64decode("".join(payload.split()))
        assert SECRET_VALUES["django_secret_key"].encode() in decoded
        assert upload_token_sha256(secrets).encode() in decoded
        assert SECRET_VALUES["upload_token"].encode() not in decoded


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("django_secret_key", "short", "django_secret_key needs"),
        ("django_secret_key", "x" * 49 + "!", "django_secret_key needs"),
        ("upload_token", "x" * 31, "upload_token needs"),
    ],
)
def test_secret_validations(cfg: HaushaltConfig, key: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message) as excinfo:
        run_deploy_fake(deploy_haushalt, cfg, values(cfg, **{key: value}), responses=fakehost.LINUX)
    assert value not in str(excinfo.value) or value == "short"


def test_missing_secret_key_fails(cfg: HaushaltConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="upload_token"):
        run_deploy_fake(deploy_haushalt, cfg, SecretValues(cfg.secrets, {"django_secret_key": "x"}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed_networks": ()},
        {"traefik_host": None},
        {"allowed_networks": ("not-a-network",)},
        {"allowed_networks": ("100.64.0.1",)},
        {"app_port": 80},
        {"traefik_host": "bad host"},
        {"python_version": "3.13"},
        {"traefik_enabled": False, "route_checks": RouteChecks(controller_login=True)},
    ],
)
def test_validations(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        make_cfg(tmp_path, **overrides)


@pytest.mark.parametrize("missing", ["services/haushalt/web/manage.py", "services/haushalt/.python-version"])
def test_source_must_be_a_daybook_checkout_with_haushalt(tmp_path: Path, missing: str) -> None:
    source = make_source(tmp_path)
    (source / missing).unlink()

    with pytest.raises(ConfigValidationError, match="not a daybook checkout with haushalt"):
        HaushaltConfig(source_path=source, secrets=SecretRef("secrets/prod/haushalt.yml"), traefik_enabled=False)


def test_unsynced_venv_is_synced_after_an_interrupted_run(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), UV_CHECK: []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        f"{P}Mark the rollout pending",
        f"{P}uv sync /home/haushalt/site (web)",
        f"{P}Record the database identity",
        f"{P}manage.py migrate and collectstatic",
        f"{P}Check the database identity",
        f"{P}Restart haushalt.service",
        f"{P}Clear the pending rollout",
    ]


def _restrict(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", RESTRICT_DATABASE, str(path), getpass.getuser()],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_restrict_hands_back_a_regular_file(tmp_path: Path) -> None:
    database = tmp_path.resolve() / "data" / "db.sqlite3"
    database.parent.mkdir()
    database.write_bytes(b"synthetic")
    database.chmod(0o644)

    assert _restrict(database).returncode == 0
    assert database.stat().st_mode & 0o777 == 0o600
    assert database.read_bytes() == b"synthetic"


def test_restrict_follows_no_link(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    target = root / "elsewhere"
    target.mkdir()
    victim = target / "db.sqlite3"
    victim.write_bytes(b"other")
    victim.chmod(0o644)
    # The file itself a link, and a directory on the way a link.
    (root / "data").mkdir()
    (root / "data" / "db.sqlite3").symlink_to(victim)
    (root / "linked").symlink_to(target)

    for path in (root / "data" / "db.sqlite3", root / "linked" / "db.sqlite3"):
        assert _restrict(path).returncode != 0
    assert victim.stat().st_mode & 0o777 == 0o644


def test_restrict_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path.resolve() / "db.sqlite3"
    os.mkfifo(fifo)

    result = _restrict(fifo)

    assert result.returncode != 0
    assert "not a regular file" in result.stderr


def test_no_probe_opens_the_database_while_planning(cfg: HaushaltConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    facts = [event.value for event in run.events if event.kind != "shell"]
    assert not any("manage.py" in fact for fact in facts)
    assert not any(DB in fact and "sqlite" in fact.lower().replace("db.sqlite3", "") for fact in facts)


@pytest.mark.parametrize(
    ("content", "accepted"),
    [
        (b"", True),
        (b"SQLite format 3\x00" + b"\x10\x00\x01\x01" + b"\x00" * 80, True),
        (b"SQLite format 3\x00" + b"\x10\x00\x02\x02" + b"\x00" * 80, False),
        (b"x" * 17, False),
        (b"SQLite format 3\x00" + b"\x10\x00\x01\x01", False),
    ],
    ids=["fresh-empty", "rollback-journal", "wal", "short", "truncated-header"],
)
def test_the_guard_reads_the_journal_mode(tmp_path: Path, content: bytes, accepted: bool) -> None:
    """The guard's own script, run by sh against real files (GNU stat/od emulated where missing)."""

    cfg = make_cfg(tmp_path)
    run = deploy(cfg, values(cfg))
    guard = next(c for c in run.executed_commands if "is missing on an installed host" in c)
    database = tmp_path / "db.sqlite3"
    database.write_bytes(content)
    script = guard.split("sh -c ", 1)[1]
    script = shlex.split(script)[0].replace(DB, str(database)).replace(IDENTITY, str(tmp_path / "none"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "stat").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = -c ] && [ "$2" = %s ]; then wc -c < "$3" | tr -d " "; exit; fi\n'
        'exec /usr/bin/stat "$@"\n'
    )
    (bin_dir / "stat").chmod(0o755)
    (bin_dir / "timeout").write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (bin_dir / "timeout").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}

    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env, timeout=30)

    assert (result.returncode == 0) is accepted, result.stderr
