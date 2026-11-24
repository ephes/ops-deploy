"""Deploy-level scenarios for chesslab against the fake connector."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.chesslab import ChesslabConfig, deploy_chesslab
from ops_deploy.services.chesslab.deploy import (
    _row_digest,
    _users_stamp,
    app_users,
    render,
    render_env,
    render_route,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.chesslab_fixtures import make_source
from tests.hsts import hsts_headers

HOME = "/home/chesslab"
SITE = f"{HOME}/site"
DB = f"{HOME}/data/chess.db"
UNIT = "/etc/systemd/system/chesslab.service"
ROUTE = "/etc/traefik/dynamic/chesslab.yml"
STAMP = f"{HOME}/.ops-deploy-users"
USERS = [
    {"username": "Trainer", "password": "chesslab-fixture-user-pw", "lichess_username": "Fixture_Owner"},
    {"username": "second", "password": "chesslab-fixture-pw-two", "owner": "other"},
]
SECRET_VALUES = {
    "session_secret": "chesslab-fixture-session-secret-0123",
    "users": json.dumps(USERS),
    "basic_auth_password": "chesslab-fixture-basic-pw",
}
# Every command in the site: root leaves its own directory (cd /) and the user enters the site.
ENTER = """sh -c 'cd "$1" && shift && exec "$@"' sh"""
UV_SYNC = (
    f"cd / && runuser -u chesslab -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    f"{ENTER} {SITE} /usr/local/bin/uv sync --frozen --no-dev --python 3.14"
)
# Substrings of the two probes of chesslab's own database, and of the bounded stamp read.
MIGRATE_PROBE = "check_unapplied=True"
USERS_PROBE = "sqlite3 -readonly"
STAMP_READ = "info.st_uid == 0"
REMOTE_RSYNC = (
    "--rsync-path=cd / && runuser -u chesslab -- "
    """sh -c 'test -d "$1" && test ! -L "$1" && shift && exec rsync "$@"' rsync /home/chesslab/site"""
)
ITEMIZED_CHANGE = [">f.st...... src/chesslab/views.py"]
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])
READ_ONLY = [
    "Deploy chesslab | Port preflight tcp/10019",
    "Deploy chesslab | Check the path to /home/chesslab",
    "Deploy chesslab | Check chesslab database",
    "Deploy chesslab | Verify chesslab certifi/pip trust",
    "Deploy chesslab | Check http://127.0.0.1:10019/healthz",
]
ECHOPORT_PROBE = "if test -e /home/echoport/site/manage.py; then"
NYXMON_PROBE = "if test -e /home/nyxmon/site/manage.py; then"


@pytest.fixture
def cfg(tmp_path: Path) -> ChesslabConfig:
    return ChesslabConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/chesslab.yml"),
        traefik_host="chess.example.com",
        django_allowed_hosts=("127.0.0.1", "localhost", "chess.example.com"),
        django_csrf_trusted_origins=("https://chess.example.com",),
        echoport_target="chesslab",
        nyxmon_check=True,
    )


def values(cfg: ChesslabConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: ChesslabConfig) -> SecretValues:
    return values(cfg)


def user_rows(secrets: SecretValues) -> list[str]:
    return [_row_digest(u.username, u.owner) for u in app_users(secrets)]


def converged(cfg: ChesslabConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where chesslab and its wiring are fully deployed."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets).reveal().decode(),
        UNIT: render("chesslab.service.j2", cfg=cfg),
        ROUTE: render_route(traefik_config(cfg, secrets), _HASH),
        STAMP: _users_stamp(cfg, secrets, app_users(secrets)),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("chesslab", HOME, shell="/usr/sbin/nologin"),
        **fakehost.deb_installed("python3", "python3-venv", "sqlite3", "rsync"),
        USERS_PROBE: user_rows(secrets),
        ECHOPORT_PROBE: ["unchanged"],
        NYXMON_PROBE: ["unchanged"],
        MIGRATE_PROBE: ["current"],
        STAMP_READ: content[STAMP].splitlines(),
    }
    for path in ("", "/site", "/data"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="chesslab"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "chesslab" if path.startswith(SITE) else "root"
        private = path in (f"{SITE}/.env", STAMP)
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("chesslab.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: ChesslabConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_chesslab, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/chesslab -s /usr/sbin/nologin -g chesslab -r -M chesslab" in commands
    db_check = next(c for c in commands if "test -f /home/chesslab/data/chess.db" in c)
    migrate = next(c for c in commands if "django migrate --noinput" in c)
    ensure = [c for c in commands if "ensure_admin" in c]
    assert commands.index(db_check) < commands.index(UV_SYNC) < commands.index(migrate)
    assert len(ensure) == 2
    assert commands.index(migrate) < commands.index(ensure[0]) < commands.index("systemctl start chesslab.service")
    assert "systemctl restart chesslab.service" not in commands
    # .env, the two users, migrate, the stamp and the route (it holds the basic-auth hash) all go over stdin.
    assert len(run.stdin) == 6
    assert ROUTE in [path for path, _ in run.secret_files]
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    upsert = [c for c in commands if "manage.py shell -c" in c]
    assert len(upsert) == 2
    assert all('"mode": "apply"' in c for c in upsert)


def test_second_run_changes_nothing_mutating(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []


def test_code_change_syncs_migrates_and_restarts(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy chesslab | Sync chesslab source",
        "Deploy chesslab | uv sync /home/chesslab/site",
        "Deploy chesslab | Run chesslab migrations",
        "Deploy chesslab | Restart chesslab.service",
    ]


def test_sync_protects_host_state(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" in real
    assert real[-1].endswith(f"{SITE}/")
    for pattern in (".env", "chess.db", "*.db", "*.db-*", ".venv", ".git"):
        assert f"--exclude={pattern}" in real


def test_env_change_rewrites_env_and_restarts(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, session_secret="rotated-fixture-session-secret-0123")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    # The stamp is keyed by the Django secret, so the users are ensured once more.
    assert run.mutating_changed_ops == [
        "Deploy chesslab | Write .env",
        "Deploy chesslab | Ensure chesslab app user",
        "Deploy chesslab | Ensure chesslab app user",
        "Deploy chesslab | Record chesslab app users",
        "Deploy chesslab | Restart chesslab.service",
    ]
    assert "rotated-fixture-session-secret" not in run.all_text()


def test_password_change_only_ensures_users(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    users = [{**USERS[0], "password": "rotated-fixture-user-pw"}, USERS[1]]

    run = deploy(cfg, values(cfg, users=json.dumps(users)), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy chesslab | Ensure chesslab app user",
        "Deploy chesslab | Ensure chesslab app user",
        "Deploy chesslab | Record chesslab app users",
    ]
    assert "rotated-fixture-user-pw" not in run.all_text()


def test_missing_user_in_database_is_ensured(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), USERS_PROBE: user_rows(secrets)[:1]}

    run = deploy(cfg, secrets, responses)

    assert "Deploy chesslab | Ensure chesslab app user" in run.mutating_changed_ops


def test_basic_auth_rotation_only_touches_traefik(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_password="rotated-fixture-password"), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy chesslab | Write Traefik route chesslab",
        "Deploy chesslab | Restart Traefik for chesslab",
    ]


def test_wiring_drift_is_applied(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy chesslab | Upsert Echoport backup target"]
    apply = next(c for c in run.executed_commands if "/home/echoport/site" in c and "manage.py shell" in c)
    assert '"schedule": "50 2 * * *"' in apply
    assert '"schedule_policy": "keep"' in apply


def test_wiring_is_optional(tmp_path: Path) -> None:
    cfg = ChesslabConfig(source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/chesslab.yml"))

    run = deploy(cfg, values(cfg))

    assert not any("echoport" in c or "nyxmon" in c for c in run.executed_commands + run.fact_commands)


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: ChesslabConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, session_secret="rotated-fixture-session-secret-0123") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    secret_texts = [SECRET_VALUES["session_secret"], SECRET_VALUES["basic_auth_password"], "rotated-fixture-session"]
    secret_texts += [u["password"] for u in USERS] + ["Trainer", "Fixture_Owner"]
    for value in secret_texts:
        assert value not in text
    stamp = _users_stamp(cfg, used, app_users(used)).strip()
    assert stamp not in text


def test_secrets_ride_on_stdin_only(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    payloads = []
    for command, payload in run.stdin:
        assert SECRET_VALUES["session_secret"] not in command
        try:
            payloads.append(base64.b64decode("".join(payload.split())).decode())
        except ValueError:
            payloads.append(payload)
    joined = "\n".join(payloads)
    assert SECRET_VALUES["session_secret"] in joined
    assert all(u["password"] in joined for u in USERS)


def test_secret_key_wins_over_session_secret(cfg: ChesslabConfig) -> None:
    secrets = values(cfg, secret_key="chesslab-fixture-secret-key-preferred")

    env = render_env(cfg, secrets).reveal().decode()

    assert 'CHESSLAB_SECRET_KEY="chesslab-fixture-secret-key-preferred"' in env.splitlines()


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"session_secret": "too-short"}, "secret_key"),
        ({"session_secret": "CHANGEME-CHANGEME-CHANGEME"}, "secret_key"),
        ({"basic_auth_password": "CHANGEME"}, "basic_auth_password"),
        ({"users": "[]"}, "non-empty list"),
        ({"users": "not json"}, "list of mappings"),
        ({"users": json.dumps([{"username": "x", "password": "y"}])}, "owner or lichess_username"),
        ({"users": json.dumps([{"username": "x", "password": "", "owner": "o"}])}, "owner or lichess_username"),
        ({"users": json.dumps([{"username": "", "password": "p", "owner": "o"}])}, "owner or lichess_username"),
        ({"users": json.dumps([{"username": "x", "password": "p", "owner": ""}])}, "owner or lichess_username"),
        ({"session_secret": "chesslab-fixture-session-secret\nX=1"}, "single lines"),
        ({"users": json.dumps([{"username": "x", "password": "p\nX=1", "owner": "o"}])}, "owner or lichess_username"),
        ({"users": json.dumps([{"username": "x\ny", "password": "p", "owner": "o"}])}, "owner or lichess_username"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: ChesslabConfig, changes: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_chesslab, cfg, values(cfg, **changes), responses=first_host())
    assert "chesslab-fixture" not in str(excinfo.value)


def test_missing_database_stops_before_the_site_changes(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**first_host(), "runuser -u chesslab -- env HOME=/home/chesslab test -f": {"success": False}}
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = run_deploy_fake(deploy_chesslab, cfg, secrets, rsync=rsync, responses=responses)

    assert not run.succeeded
    assert all("--dry-run" in call for call in rsync.calls)
    assert not any(c.startswith("cd /home/chesslab/site") for c in run.executed_commands)


def test_source_must_be_a_chesslab_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a chesslab checkout"):
        ChesslabConfig(source_path=tmp_path, secrets=SecretRef("secrets/prod/chesslab.yml"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"django_allowed_hosts": ("a b",)},
        {"limit": "ten"},
        {"echoport_schedule": "50 2 * * *; rm"},
        {"traefik_middlewares": ("rate.limit@file",)},
    ],
)
def test_config_validation(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        ChesslabConfig(source_path=make_source(tmp_path), secrets=SecretRef("x.yml"), **overrides)


def test_port_collision_stops_before_any_change(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**first_host(), "ss -Hltnp": {"success": False, "stderr": "port in use"}}

    run = run_deploy_fake(deploy_chesslab, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert len(run.executed_commands) == 1
    assert "0::/system.slice/chesslab.service" in run.executed_commands[0]


def test_unapplied_migrations_are_retried_without_a_code_change(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), MIGRATE_PROBE: []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy chesslab | Run chesslab migrations",
        "Deploy chesslab | Restart chesslab.service",
    ]


def test_user_names_never_reach_a_command_line(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    ensure = [c for c in run.executed_commands if "ensure_admin" in c]
    assert ensure
    assert not any("--username" in c for c in ensure)
    assert all("CHESSLAB_DEPLOY_USERNAME" in c for c in ensure)


@pytest.mark.parametrize("probe", [MIGRATE_PROBE, USERS_PROBE, ECHOPORT_PROBE, NYXMON_PROBE])
def test_a_failing_probe_stops_planning_and_nothing_runs(
    cfg: ChesslabConfig, secrets: SecretValues, probe: str
) -> None:
    # The probe crashed (not "pending"): scheduling the step it gates would turn
    # an unreadable database or neighbour into a write.
    responses = {**converged(cfg, secrets), probe: [FAILED]}

    run = run_deploy_fake(deploy_chesslab, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert "probe failed" in str(run.error)
    assert run.executed_commands == []
    assert run.stdin == []
    assert run.uploads == []


def test_pending_is_not_a_failure(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), MIGRATE_PROBE: ["pending"], ECHOPORT_PROBE: ["pending"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy chesslab | Run chesslab migrations",
        "Deploy chesslab | Restart chesslab.service",
        "Deploy chesslab | Upsert Echoport backup target",
    ]


def _root_enters(command: str) -> bool:
    """Root changes into a service's directory before it drops privileges."""

    return any(f"cd /home/{owner}" in command.split("runuser")[0] for owner in ("chesslab", "echoport", "nyxmon"))


@pytest.mark.parametrize("scenario", ["first", "converged", "drift"])
def test_root_never_enters_or_writes_a_service_directory(
    cfg: ChesslabConfig, secrets: SecretValues, scenario: str
) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    if scenario == "drift":
        assert responses is not None
        responses.update({MIGRATE_PROBE: ["pending"], ECHOPORT_PROBE: ["pending"], NYXMON_PROBE: ["pending"]})
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, responses, rsync=rsync)

    commands = run.executed_commands + run.fact_commands
    assert not [c for c in commands if _root_enters(c)]
    in_site = [c for c in run.executed_commands if "uv sync" in c or "django" in c or "manage.py shell" in c]
    assert in_site
    assert all(c.startswith("cd / && runuser -u ") for c in in_site)
    # The sync receives as the service user and sets no owner as root.
    assert rsync.calls
    assert all(REMOTE_RSYNC in call for call in rsync.calls)
    assert not any(arg.startswith("--chown") for call in rsync.calls for arg in call)
    # site and data are made by the user; root's mkdir/chown only ever names the home.
    made = [c for c in run.executed_commands if c.startswith(("mkdir", "chown", "chmod")) and HOME in c]
    assert all(c.split()[-1] == HOME for c in made), made
    if scenario == "first":
        assert f"cd / && runuser -u chesslab -- mkdir -p -m 0755 {SITE}" in run.executed_commands
        assert f"cd / && runuser -u chesslab -- mkdir -p -m 0755 {HOME}/data" in run.executed_commands


def test_database_probes_run_read_only_as_the_service_user(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    users = next(c for c in run.fact_commands if USERS_PROBE in c)
    assert "runuser -u chesslab -- env HOME=/home/chesslab sh -c" in users
    # Never the account's ~/.sqliterc.
    assert users.count("sqlite3 -readonly -init /dev/null") == users.count("sqlite3 -readonly") == 2
    migrations = next(c for c in run.fact_commands if MIGRATE_PROBE in c)
    assert "?mode=ro" in migrations
    assert '"uri": True' in migrations
    assert "PYTHONDONTWRITEBYTECODE=1" in migrations
    assert "cd / && runuser -u chesslab -- env HOME=/home/chesslab" in migrations
    assert not any("migrate --check" in c for c in run.fact_commands)


def test_stamp_is_read_without_following_or_blocking(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    read = next(c for c in run.fact_commands if STAMP_READ in c)
    assert read.startswith("python3 -I -c ")
    assert read.endswith(STAMP)
    assert "os.O_NOFOLLOW | os.O_NONBLOCK" in read
    assert "0o600" in read
    assert not any(c.startswith(f"cat {STAMP}") for c in run.fact_commands)


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        ("regular", "stamp\n"),
        ("wrong-mode", ""),
        ("symlink", ""),
        ("fifo", ""),
        ("missing", ""),
        ("too-large", ""),
    ],
)
def test_stamp_reader_accepts_only_a_small_private_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted: str, expected: str
) -> None:
    import os
    import subprocess
    import sys

    from ops_deploy.services.chesslab.deploy import _READ_STAMP

    stamp = tmp_path / "stamp"
    if planted in ("regular", "wrong-mode", "too-large"):
        stamp.write_text("stamp\n" if planted != "too-large" else "x" * 300)
        stamp.chmod(0o644 if planted == "wrong-mode" else 0o600)
    elif planted == "symlink":
        target = tmp_path / "target"
        target.write_text("stamp\n")
        target.chmod(0o600)
        stamp.symlink_to(target)
    elif planted == "fifo":
        os.mkfifo(stamp, 0o600)
    # The production stamp is root's; here the owner is whoever runs the tests.
    script = _READ_STAMP.replace("info.st_uid == 0", f"info.st_uid == {os.getuid()}")
    assert script != _READ_STAMP

    done = subprocess.run([sys.executable, "-I", "-c", script, str(stamp)], capture_output=True, text=True, timeout=20)

    assert (done.returncode, done.stdout, done.stderr) == (0, expected, "")


def verify_only(cfg: ChesslabConfig) -> ChesslabConfig:
    return cfg.model_copy(update={"verify_only": True})


def test_verify_only_queues_nothing_that_changes_a_converged_host(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner()

    run = deploy(verify_only(cfg), secrets, converged(cfg, secrets), rsync=rsync)

    # Only read-only operations exist in this run: nothing that a later re-evaluation could turn into a write.
    assert [op.name for op in run.ops if not op.read_only] == []
    assert [op.name for op in run.ops if op.read_only] == [
        "Deploy chesslab | Check the path to /home/chesslab",
        "Deploy chesslab | Audit ownership below the chesslab home",
        "Deploy chesslab | Show the identity of chesslab",
        "Deploy chesslab | Check chesslab database",
    ]
    assert run.uploads == []
    assert run.stdin == []
    assert run.function_calls == []
    assert rsync.calls
    assert all("--dry-run" in call and REMOTE_RSYNC in call for call in rsync.calls)
    assert "cd / && runuser -u chesslab -- env HOME=/home/chesslab id" in run.executed_commands
    audit = next(c for c in run.executed_commands if "-perm -2000" in c)
    assert audit.endswith(f"sh chesslab chesslab {SITE} {HOME}/data")
    assert 'find "$@" -xdev' in audit
    assert run.fish_unsafe_commands == []
    assert '! -user "$user" -o ! -group "$group" -o -type d -perm -2000' in audit
    # No neighbour is asked and no account, package, unit or route fact is needed.
    assert not any("echoport" in c or "nyxmon" in c for c in run.executed_commands + run.fact_commands)
    assert not any(word in c for c in run.executed_commands for word in ("systemctl", "apt-get", "useradd", "mkdir"))


@pytest.mark.parametrize(
    ("drift", "itemized", "message"),
    [
        ({}, ITEMIZED_CHANGE, "the source differs"),
        ({MIGRATE_PROBE: ["pending"]}, [], "migrations are not current"),
        ({USERS_PROBE: []}, [], "application users"),
        ({STAMP_READ: ["stale"]}, [], "application users"),
        ({STAMP_READ: []}, [], "application users"),
        ({f"test -x {SITE}/.venv/bin/python": []}, [], "no interpreter"),
        ({f"test -e {SITE} ||": []}, [], f"{SITE} is missing"),
        (fakehost.directory(f"{HOME}/data", user="chesslab", mode="drwx------"), [], f"{HOME}/data is not 0755"),
        (
            {"cat /etc/passwd | cut": ["root:x:0:0:root:/root:/bin/bash|root|root||!"]},
            [],
            "account chesslab does not exist",
        ),
    ],
)
def test_verify_only_stops_on_pending_work_without_acting(
    cfg: ChesslabConfig, secrets: SecretValues, drift: dict[str, Any], itemized: list[str], message: str
) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": itemized})
    responses = {**converged(cfg, secrets), **drift}

    run = run_deploy_fake(deploy_chesslab, verify_only(cfg), secrets, rsync=rsync, responses=responses)

    assert not run.succeeded
    assert "verify_only: chesslab is not converged" in str(run.error)
    assert message in str(run.error)
    assert run.executed_commands == []
    assert run.function_calls == []
    assert all("--dry-run" in call for call in rsync.calls)


@pytest.mark.parametrize("probe", [MIGRATE_PROBE, USERS_PROBE])
def test_verify_only_stops_on_a_failing_probe(cfg: ChesslabConfig, secrets: SecretValues, probe: str) -> None:
    responses = {**converged(cfg, secrets), probe: [FAILED]}

    run = run_deploy_fake(deploy_chesslab, verify_only(cfg), secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert "probe failed" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize(
    ("layout", "message"),
    [
        (fakehost.symlink(f"{HOME}/data", "/srv/elsewhere", user="chesslab"), "not a directory"),
        (fakehost.directory(SITE, user="root"), "belongs to root:root"),
    ],
)
def test_verify_only_refuses_what_a_deploy_refuses(
    cfg: ChesslabConfig, secrets: SecretValues, layout: dict[str, Any], message: str
) -> None:
    rsync = RecordingRsyncRunner()

    run = run_deploy_fake(
        deploy_chesslab, verify_only(cfg), secrets, rsync=rsync, responses={**converged(cfg, secrets), **layout}
    )

    assert not run.succeeded
    assert message in str(run.error)
    assert run.executed_commands == []
    assert rsync.calls == []


def test_verify_only_never_transfers_even_if_the_host_changes_while_it_runs(
    cfg: ChesslabConfig, secrets: SecretValues
) -> None:
    # No sync operation is queued, so there is nothing pyinfra could re-evaluate into a transfer.
    rsync = RecordingRsyncRunner()

    run = deploy(verify_only(cfg), secrets, converged(cfg, secrets), rsync=rsync)

    assert not any("Sync" in op.name for op in run.ops)
    assert len(rsync.calls) == 1
    assert "--dry-run" in rsync.calls[0]


@pytest.mark.parametrize("field", ["site_path", "data_path"])
def test_audit_refuses_a_path_a_shell_would_read(tmp_path: Path, field: str) -> None:
    cfg = ChesslabConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/chesslab.yml"),
        verify_only=True,
        **{field: "/home/chesslab/x; touch /root/pwned"},
    )

    run = run_deploy_fake(deploy_chesslab, cfg, values(cfg), rsync=RecordingRsyncRunner(), responses=first_host())

    assert not run.succeeded
    assert "plain normalized absolute path" in str(run.error)
    assert run.executed_commands == []


def test_first_deploy_with_a_provisioned_database_but_no_account_plans(
    cfg: ChesslabConfig, secrets: SecretValues
) -> None:
    # The database may be there before the account this run creates: runuser
    # cannot work yet, and that is "nothing there yet", not a failed probe.
    responses = {**first_host(), USERS_PROBE: [FAILED], MIGRATE_PROBE: [FAILED]}

    run = deploy(cfg, secrets, responses, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    assert not any(USERS_PROBE in c or MIGRATE_PROBE in c for c in run.fact_commands)
    assert len([c for c in run.executed_commands if "ensure_admin" in c]) == 2
    assert any("django migrate --noinput" in c for c in run.executed_commands)


def test_a_foreign_site_directory_is_not_repaired(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), **fakehost.directory(SITE, user="root")}

    run = run_deploy_fake(deploy_chesslab, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert "Root does not repair it" in str(run.error)
    assert run.executed_commands == []


def test_a_symlinked_site_is_refused(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), **fakehost.symlink(SITE, "/etc", user="chesslab")}
    rsync = RecordingRsyncRunner()

    run = run_deploy_fake(deploy_chesslab, cfg, secrets, rsync=rsync, responses=responses)

    assert not run.succeeded
    assert "not a directory" in str(run.error)
    assert run.executed_commands == []
    assert rsync.calls == []


def test_route_sends_hsts_without_preload(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    assert len(hsts_headers(render_route(traefik_config(cfg, secrets), _HASH))) == 1


def test_stale_lock_fails_before_any_operation(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    # certifi/pip below the security floor: refused on the controller, nothing planned or run.
    (cfg.source_path / "uv.lock").write_text('[[package]]\nname = "certifi"\nversion = "2026.7.22"\n')
    with pytest.raises(ValueError, match="security floor"):
        deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))


def test_env_omits_proxy_hops_by_default(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    # Off unless a host opts in after its proxy prerequisites are verified.
    assert cfg.trusted_proxy_hops == 0
    assert "CHESSLAB_TRUSTED_PROXY_HOPS" not in render_env(cfg, secrets).reveal().decode()


def test_env_renders_opted_in_proxy_hop(tmp_path: Path) -> None:
    cfg = ChesslabConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/chesslab.yml"),
        trusted_proxy_hops=1,
    )
    env = render_env(cfg, values(cfg)).reveal().decode().splitlines()
    assert 'CHESSLAB_TRUSTED_PROXY_HOPS="1"' in env
    assert env.index('CHESSLAB_TRUSTED_PROXY_HOPS="1"') == env.index('CHESSLAB_SECURE_COOKIES="true"') + 1


@pytest.mark.parametrize("hops", [-1, 2, True])
def test_proxy_hops_accepts_only_zero_or_one(tmp_path: Path, hops: Any) -> None:
    with pytest.raises((ConfigValidationError, ValueError)):
        ChesslabConfig(
            source_path=make_source(tmp_path),
            secrets=SecretRef("secrets/prod/chesslab.yml"),
            trusted_proxy_hops=hops,
        )
