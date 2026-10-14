"""Deploy-level scenarios for fastdeploy against the fake connector."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers.postgres import scram_verifier, state_command
from ops_deploy.helpers.traefik import hash_password, render_route
from ops_deploy.services.fastdeploy import FastdeployConfig, deploy_fastdeploy
from ops_deploy.services.fastdeploy.deploy import (
    BUILD_STAMP,
    TEMPLATE_PACKAGE,
    frontend_digest,
    render_env,
    traefik_config,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.fastdeploy_fixtures import make_source

SITE = "/home/fastdeploy/site"
SECRET_VALUES = {
    "secret_key": "fastdeploy-fixture-secret-key",
    "initial_user_name": "fixture-admin",
    "initial_user_password_hash": "$2b$12$fastdeployfixturehashvalue",
    "postgres_password": "fastdeploy-fixture-pg-password",
    "basic_auth_password": "fastdeploy-fixture-basic-auth",
}
LEGACY = ("credential-rotation", "ops-control")
UNIT = "/etc/systemd/system/fastdeploy.service"
ROUTE = "/etc/traefik/dynamic/fastdeploy.yml"
SUDOERS = "/etc/sudoers.d/fastdeploy"
STAMP = f"{SITE}/frontend/dist/{BUILD_STAMP}"
USERS_FACT = "runuser -u postgres -- psql -XAtq -d fastdeploy -c 'select encode(sha256"
PYTHON_PROBE = f"runuser -u fastdeploy -- env HOME=/home/fastdeploy {SITE}/.venv/bin/python -c"
ITEMIZED_CHANGE = [">f.st...... src/deploy/views.py"]
SALT = b"fixture-salt-16b"
_HASH = hash_password(SECRET_VALUES["basic_auth_password"])

READ_ONLY = [
    "Deploy fastdeploy | Wait for port 127.0.0.1:9999",
    "Deploy fastdeploy | Check FastDeploy auth with a minted token",
]
ALWAYS = ["Deploy fastdeploy | Restart fastdeploy.service"]


@pytest.fixture
def cfg(tmp_path: Path) -> FastdeployConfig:
    return FastdeployConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/fastdeploy.yml"),
        api_url="https://deploy.example.com",
        legacy_token_users=LEGACY,
        legacy_service_tokens_accepted_until="2026-10-31T00:00:00+00:00",
    )


def values(cfg: FastdeployConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: FastdeployConfig) -> SecretValues:
    return values(cfg)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def postgres_state(password: str, *, login: str = "true", owner: str = "fastdeploy") -> list[str]:
    verifier = scram_verifier(password, salt=SALT)
    salt_spec = verifier.split("$")[1]
    return [f"role|{login}|{salt_spec}|{digest(verifier)}", f"db|{owner}", f"schema|{owner}"]


def account(user: str, home: str, uid: int, *, groups: str = "", comment: str = "") -> str:
    return f"{user}:x:{uid}:{uid}:{comment}:{home}:/bin/bash|{user}|{groups}||!"


def converged(cfg: FastdeployConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where fastdeploy is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{SITE}/.env": render_env(cfg, secrets, shell=False).reveal().decode(),
        f"{SITE}/.env.shell": render_env(cfg, secrets, shell=True).reveal().decode(),
        UNIT: render(TEMPLATE_PACKAGE, "fastdeploy.service.j2", cfg=cfg),
        ROUTE: render_route(traefik_config(cfg, secrets), _HASH),
        SUDOERS: render(TEMPLATE_PACKAGE, "sudoers.j2", cfg=cfg),
        STAMP: f"{frontend_digest(cfg)}\n",
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        state_command("fastdeploy", "fastdeploy", "postgres"): postgres_state(secrets["postgres_password"]),
        USERS_FACT: [digest(name) for name in (secrets["initial_user_name"], *LEGACY, "someone-else")],
        "node --version": ["v24.13.1"],
        "cat /etc/group": ["root:x:0:", "deploy:x:1001:", "fastdeploy:x:1002:deploy"],
        "cat /etc/passwd | cut": [
            "root:x:0:0:root:/root:/bin/bash|root|root||!",
            account("deploy", "/home/deploy", 1001, groups="fastdeploy", comment="Deployment Service Account"),
            account("fastdeploy", "/home/fastdeploy", 1002, comment="FastDeploy Service Account"),
        ],
    }
    for path in ("", "/site", "/site/bin", "/site/logs", "/site/services", "/site/frontend/dist"):
        responses.update(fakehost.directory(f"/home/fastdeploy{path}", user="fastdeploy"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic", "/etc/sudoers.d"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = "fastdeploy" if path.startswith(SITE) else "root"
        mode = "-rw-r--r--"
        if path.endswith((".env", ".env.shell")):
            mode = "-rw-------"
        elif path == SUDOERS:
            mode = "-r--r-----"
        responses.update(fakehost.file(path, text, user=owner, mode=mode))
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    for unit in ("fastdeploy.service", "traefik.service", "postgresql.service"):
        responses.update(fakehost.service(unit))
    responses[PYTHON_PROBE] = ["3.14"]
    return responses


def first_host() -> dict[str, Any]:
    return {**fakehost.LINUX}


def deploy(
    cfg: FastdeployConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_fastdeploy, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or first_host()
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    psql = "runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -p 5432"
    create_db = f'{psql} -c \'CREATE DATABASE "fastdeploy" OWNER "fastdeploy"\''
    assert create_db in commands
    assert "useradd -d /home/deploy -s /bin/bash -g deploy -G fastdeploy -c 'Deployment Service Account' -m deploy" in (
        commands
    )
    uv = next(c for c in commands if "/usr/local/bin/uv sync --frozen --python 3.14" in c)
    build = next(c for c in commands if "npm run build" in c)
    createuser = next(c for c in commands if "commands.py createuser" in c)
    start = commands.index("systemctl start fastdeploy.service")
    assert commands.index(create_db) < commands.index(uv) < commands.index(build) < commands.index(createuser) < start
    assert start < commands.index("systemctl restart fastdeploy.service")
    assert "Deploy fastdeploy | Install Node.js" in run.mutating_changed_ops
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    # The env files go over stdin via secret_file, never as uploads.
    assert not any(path.endswith((".env", ".env.shell")) for path in run.uploaded_paths)


def test_second_run_only_restarts(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == ALWAYS
    assert run.changed_ops == [*ALWAYS, *READ_ONLY]
    assert run.uploads == []
    # Only the read-only auth check reads stdin.
    assert [command for command, _ in run.stdin] == [run.executed_commands[-1]]
    assert not any("npm" in c or "uv sync" in c or "psql" in c for c in run.executed_commands)


def test_code_change_syncs_deps_and_services_but_does_not_build(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | Sync FastDeploy source",
        "Deploy fastdeploy | uv sync /home/fastdeploy/site",
        "Deploy fastdeploy | Sync services from filesystem",
        *ALWAYS,
    ]


def test_frontend_change_rebuilds(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    (cfg.source_path / "frontend" / "src" / "main.ts").write_text("console.log('changed')\n")

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | Build frontend",
        "Deploy fastdeploy | Record frontend build inputs",
        *ALWAYS,
    ]
    build = [c for c in run.executed_commands if "npm" in c]
    assert build[0].endswith("npm ci")
    assert "NODE_ENV=production VITE_API_BASE_PROD=https://deploy.example.com" in build[1]
    assert run.upload(STAMP).decode() == f"{frontend_digest(cfg)}\n"


def test_build_url_change_rebuilds(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    moved = cfg.model_copy(update={"websocket_url": "wss://elsewhere.example.com/deployments/ws"})

    run = deploy(moved, secrets, converged(cfg, secrets))

    assert "Deploy fastdeploy | Build frontend" in run.mutating_changed_ops


def test_build_artifacts_do_not_count_as_frontend_changes(cfg: FastdeployConfig) -> None:
    before = frontend_digest(cfg)
    for path in ("node_modules/x/index.js", "dist/index.html", ".DS_Store"):
        target = cfg.source_path / "frontend" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("noise")

    assert frontend_digest(cfg) == before


def test_old_node_is_upgraded_from_nodesource(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "node --version": ["v22.11.0"]}

    run = deploy(cfg, secrets, responses)

    assert "Deploy fastdeploy | Install Node.js" in run.mutating_changed_ops
    repo = run.upload("/etc/apt/sources.list.d/nodesource.list").decode()
    assert (
        repo == "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main\n"
    )


def test_secret_rotation_rewrites_both_env_files(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, secret_key="rotated-fixture-secret-key")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | Write .env",
        "Deploy fastdeploy | Write .env.shell",
        *ALWAYS,
    ]
    assert "rotated-fixture-secret-key" not in run.all_text()


def test_postgres_password_rotation_updates_role_and_env(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, postgres_password="rotated-fixture-pg-password")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | Ensure PostgreSQL role fastdeploy",
        "Deploy fastdeploy | Write .env",
        "Deploy fastdeploy | Write .env.shell",
        *ALWAYS,
    ]
    sql = next(s for c, s in run.stdin if c == "runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -p 5432")
    assert sql.startswith('ALTER ROLE "fastdeploy" WITH LOGIN PASSWORD \'SCRAM-SHA-256$4096:')
    assert "rotated-fixture-pg-password" not in sql
    assert "rotated-fixture-pg-password" not in run.all_text()


def test_role_without_login_or_scram_password_is_fixed(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    for state in (
        postgres_state(secrets["postgres_password"], login="false"),
        ["role|true||", "db|fastdeploy", "schema|fastdeploy"],  # md5 or no password
    ):
        responses = {**converged(cfg, secrets), state_command("fastdeploy", "fastdeploy", "postgres"): state}

        run = deploy(cfg, secrets, responses)

        assert run.mutating_changed_ops == ["Deploy fastdeploy | Ensure PostgreSQL role fastdeploy", *ALWAYS]


def test_python_version_change_syncs_the_venv(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), PYTHON_PROBE: ["3.13"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | uv sync /home/fastdeploy/site",
        "Deploy fastdeploy | Sync services from filesystem",
        *ALWAYS,
    ]


def test_database_and_schema_owners_are_fixed(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    state = postgres_state(secrets["postgres_password"], owner="postgres")
    responses = {**converged(cfg, secrets), state_command("fastdeploy", "fastdeploy", "postgres"): state}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy fastdeploy | Ensure PostgreSQL database fastdeploy", *ALWAYS]
    assert any('ALTER DATABASE "fastdeploy" OWNER TO "fastdeploy"' in c for c in run.executed_commands)
    assert any("-d fastdeploy -c 'ALTER SCHEMA public OWNER TO \"fastdeploy\"'" in c for c in run.executed_commands)


def test_missing_legacy_user_is_created_from_stdin(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), USERS_FACT: [digest(SECRET_VALUES["initial_user_name"]), digest(LEGACY[0])]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy fastdeploy | Create legacy token user ops-control", *ALWAYS]
    command, payload = run.stdin[0]
    assert payload == "ops-control\n"
    assert "runuser -u fastdeploy" in command
    assert "output withheld" in command


def test_initial_user_name_and_hash_only_on_stdin(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), USERS_FACT: [digest(name) for name in LEGACY]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy fastdeploy | Create initial FastDeploy user", *ALWAYS]
    command, payload = run.stdin[0]
    assert payload == f"{SECRET_VALUES['initial_user_name']}\n{SECRET_VALUES['initial_user_password_hash']}\n"
    assert "createuser" in command
    assert "PRODUCTION=true" in command


def test_rollout_check_request_rides_on_stdin(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    command, payload = run.stdin[-1]
    assert json.loads(payload) == {
        "user": SECRET_VALUES["initial_user_name"],
        "ttl_seconds": 300,
        "url": "http://127.0.0.1:9999/users/me",
        "retries": 15,
        "delay": 2,
    }
    assert "create_access_token" in command
    assert "tail -n 1" in command


def test_basic_auth_rotation_only_touches_traefik(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, basic_auth_password="rotated-fixture-password"), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | Write Traefik route fastdeploy",
        "Deploy fastdeploy | Restart Traefik for fastdeploy",
        *ALWAYS,
    ]


def test_unit_change_reloads_systemd(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{UNIT: "[Unit]\n"}))

    assert run.mutating_changed_ops == [
        "Deploy fastdeploy | Install systemd unit fastdeploy.service",
        "Deploy fastdeploy | Reload systemd for fastdeploy.service",
        *ALWAYS,
    ]


def test_sudoers_rule_is_validated_before_it_goes_live(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{SUDOERS: "# stale\n"}))

    assert run.mutating_changed_ops == ["Deploy fastdeploy | Install sudoers rule fastdeploy", *ALWAYS]
    staged = "/etc/sudoers.d/.ops-deploy-fastdeploy"
    assert (
        run.upload(staged)
        .decode()
        .endswith("fastdeploy ALL=(deploy) NOPASSWD: /home/fastdeploy/site/services/*/deploy.sh *\n")
    )
    assert f"visudo -cqf {staged} && mv -f {staged} {SUDOERS} || {{ rm -f {staged}; exit 1; }}" in (
        run.executed_commands
    )


def test_sync_protects_host_state(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    sync = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" in sync
    assert sync[-1].endswith(f":{SITE}/")
    protected = ("/services/", "/.env.shell", "/bin/", "/logs/", "/db.sqlite3", ".env", "databases")
    for pattern in (*protected, "frontend/node_modules", "frontend/dist", ".git", ".venv", ".ops-deploy-*"):
        assert f"--exclude={pattern}" in sync


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: FastdeployConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, postgres_password="rotated-fixture-pg-password") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-pg-password"):
        assert value not in text


def test_env_files_ride_on_stdin_only(cfg: FastdeployConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    env_payloads = [payload for command, payload in run.stdin if command.startswith("python3 -I")]
    assert len(env_payloads) == 2
    for payload in env_payloads:
        assert SECRET_VALUES["postgres_password"].encode() in base64.b64decode("".join(payload.split()))


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("secret_key", "CHANGEME", "placeholder values: secret_key"),
        ("postgres_password", "xCHANGEMEx", "placeholder values: postgres_password"),
        ("initial_user_name", "a\nb", "single lines"),
        ("initial_user_name", "admin; rm", "plain user name"),
        ("postgres_password", "pässword", "letters, digits"),
        ("postgres_password", "fixture@password", "letters, digits"),
    ],
)
def test_bad_secret_fails_before_any_operation(cfg: FastdeployConfig, key: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message) as excinfo:
        run_deploy_fake(deploy_fastdeploy, cfg, values(cfg, **{key: value}), responses=first_host())
    if key != "initial_user_name":
        assert value not in str(excinfo.value)


def test_missing_secret_key_fails(cfg: FastdeployConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="postgres_password"):
        run_deploy_fake(deploy_fastdeploy, cfg, SecretValues(cfg.secrets, {"secret_key": "x"}))


def test_source_must_be_a_fastdeploy_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a FastDeploy checkout"):
        FastdeployConfig(source_path=tmp_path, secrets=SecretRef("secrets/prod/fastdeploy.yml"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"legacy_service_tokens_accepted_until": "2026-02-30T00:00:00+00:00"},
        {"legacy_service_tokens_accepted_until": "2026-10-31"},
        {"service_token_max_expire_days": 0},
        {"legacy_token_users": ("bad name",)},
        {"forwarded_allow_ips": ()},
        {"forwarded_allow_ips": ("*",)},
        {"forwarded_allow_ips": ("10.0.0.0/8",)},
        {"api_url": "https://x y"},
        {"postgres_user": "Fast-Deploy"},
        {"postgres_host": "db.example.com"},
        {"postgres_port": 5433},
    ],
)
def test_role_validations(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        FastdeployConfig(
            source_path=make_source(tmp_path), secrets=SecretRef("secrets/prod/fastdeploy.yml"), **overrides
        )
