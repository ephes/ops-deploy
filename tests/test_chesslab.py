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
UV_SYNC = (
    f"cd {SITE} && runuser -u chesslab -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --frozen --no-dev --python 3.14"
)
ITEMIZED_CHANGE = [">f.st...... src/chesslab/views.py"]
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])
READ_ONLY = [
    "Deploy chesslab | Port preflight tcp/10019",
    "Deploy chesslab | Check chesslab database",
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
        "sqlite3 -readonly": user_rows(secrets),
        ECHOPORT_PROBE: ["unchanged"],
        NYXMON_PROBE: ["unchanged"],
        "django migrate --check": ["current"],
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
    # .env, the two users, migrate and the stamp all go over stdin.
    assert len(run.stdin) == 5
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
    responses = {**converged(cfg, secrets), "sqlite3 -readonly": user_rows(secrets)[:1]}

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
    assert '"update_schedule": false' in apply


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
    responses = {**converged(cfg, secrets), "django migrate --check": []}

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


def test_a_failing_migrations_probe_runs_migrate_and_probes_again(cfg: ChesslabConfig, secrets: SecretValues) -> None:
    # The probe crashed (not "pending"): the step runs, then the probe must pass.
    responses = {**converged(cfg, secrets), "django migrate --check": [FAILED]}

    run = deploy(cfg, secrets, responses)

    assert run.succeeded
    assert "Deploy chesslab | Run chesslab migrations" in run.mutating_changed_ops
    verify = run.op("Deploy chesslab | Probe again: chesslab migrations")
    assert verify.changed
    assert verify.read_only
    assert any("migrate --check --plan" in c and "probe still fails" in c for c in run.executed_commands)
