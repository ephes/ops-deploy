"""Deploy-level scenarios for opaq_app against the fake connector."""

import re
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.opaq_app import EchoportTarget, NyxmonCheck, OpaqAppConfig, deploy_opaq_app
from ops_deploy.services.opaq_app.deploy import (
    TEMPLATE_PACKAGE,
    RouteChecks,
    render_env,
    render_route,
    upload_token_sha256,
)
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.opaq_app_fixtures import SOURCE_FILES, make_source

HOME = "/home/opaq-app"
SITE = f"{HOME}/site"
DB = f"{HOME}/data/db.sqlite3"
UNIT = "/etc/systemd/system/opaq-app.service"
ROUTE = "/etc/traefik/dynamic/opaq-app.yml"
HOST = "opaq.example.invalid"
SECRET_VALUES = {
    "django_secret_key": "opaq-fixture-django-key-" + "0123456789" * 3,
    "upload_token": "opaq-fixture-upload-token-0123456789abcdef",
}
UV_SYNC = (
    f"cd {SITE} && runuser -u opaq-app -- env HOME={HOME} UV_PROJECT_ENVIRONMENT={HOME}/venv "
    f"UV_PYTHON_INSTALL_DIR={HOME}/python /usr/local/bin/uv sync --frozen --only-group opaq-app "
    "--no-install-project --python 3.14"
)
UV_CHECK = "--no-install-project --python 3.14 --check"
MIGRATE_CHECK = "manage.py migrate --check"
ITEMIZED_CHANGE = [">f.st...... opaq_app/views.py"]
ECHOPORT_PROBE = re.compile(r'manage\.py shell -c .*"mode": "check"')
NYXMON_PROBE = re.compile(r'OPAQ_NYXMON=.*"apply":false')
READ_ONLY = [
    "Deploy opaq_app service | Port preflight tcp/10065",
    "Deploy opaq_app service | Wait for port 127.0.0.1:10065",
    "Deploy opaq_app service | Check http://127.0.0.1:10065/healthz",
]
NETWORKS = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")


def make_cfg(tmp_path: Path, **overrides: Any) -> OpaqAppConfig:
    settings: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": SecretRef("secrets/prod/opaq_app.yml"),
        "traefik_host": HOST,
        "allowed_networks": NETWORKS,
    }
    return OpaqAppConfig(**{**settings, **overrides})


@pytest.fixture
def cfg(tmp_path: Path) -> OpaqAppConfig:
    return make_cfg(tmp_path)


def values(cfg: OpaqAppConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: OpaqAppConfig) -> SecretValues:
    return values(cfg)


def converged(cfg: OpaqAppConfig, secrets: SecretValues, **drift: str) -> dict[Any, Any]:
    """Facts of a host where opaq_app is fully deployed; ``drift`` overrides file content by path."""

    content = {
        f"{HOME}/opaq-app.env": render_env(cfg, secrets).reveal().decode(),
        UNIT: render(TEMPLATE_PACKAGE, "opaq-app.service.j2", cfg=cfg),
        ROUTE: render_route(cfg),
        f"{SITE}/pyproject.toml": SOURCE_FILES["pyproject.toml"],
        f"{SITE}/uv.lock": SOURCE_FILES["uv.lock"],
    }
    content.update(drift)
    responses: dict[Any, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("opaq-app", HOME, shell="/usr/sbin/nologin"),
    }
    for path in ("", "/site", "/site/services", "/data", "/static"):
        responses.update(fakehost.directory(f"{HOME}{path}", user="opaq-app", mode="drwx------"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        private = path.startswith(HOME)
        owner = "opaq-app" if private else "root"
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    responses.update(fakehost.file(DB, "", user="opaq-app", mode="-rw-------"))
    responses.update(fakehost.venv(f"{HOME}/venv"))
    responses["sys.version_info"] = ["3.14"]
    responses[UV_CHECK] = ["current"]
    responses[MIGRATE_CHECK] = ["current"]
    for unit in ("opaq-app.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    responses["echo installed"] = ["installed"]
    responses[ECHOPORT_PROBE] = ["unchanged"]
    responses[NYXMON_PROBE] = ["unchanged"]
    return responses


def deploy(
    cfg: OpaqAppConfig,
    secrets: SecretValues,
    responses: dict[Any, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
    **kwargs: Any,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_opaq_app,
        cfg,
        secrets,
        rsync=rsync or RecordingRsyncRunner(),
        responses=fakehost.LINUX if responses is None else responses,
        **kwargs,
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/opaq-app -s /usr/sbin/nologin -g opaq-app -r -M opaq-app" in commands
    assert UV_SYNC in commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index("systemctl start opaq-app.service")
    assert "collectstatic --noinput --clear" in migrate
    assert "umask 077;" in migrate
    assert "systemctl restart opaq-app.service" not in commands
    assert any("chmod -R u+rwX,go-rwx" in c for c in commands)
    assert any("chmod 600" in c and DB in c for c in commands)
    # The environment file goes over stdin via secret_file, never as an upload.
    assert len(run.stdin) == 1
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    assert "reload traefik" not in " ".join(commands)
    assert "systemctl restart traefik.service" not in commands


def test_second_run_changes_nothing_mutating(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any(c.startswith(("systemctl", "cd ", "find ", "chown")) for c in run.executed_commands)


def test_code_change_migrates_and_restarts_without_uv_sync(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | Sync src",
        "Deploy opaq_app service | Sync services/opaq_app",
        "Deploy opaq_app service | Own and privatize the synced tree",
        "Deploy opaq_app service | manage.py migrate and collectstatic",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]


def test_sync_protects_host_state(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = [call for call in rsync.calls if "--dry-run" not in call]
    assert [call[-1].split(":", 1)[1] for call in real] == [f"{SITE}/src/", f"{SITE}/services/opaq_app/"]
    for call in real:
        assert "--delete" in call
        assert "--chown=opaq-app:opaq-app" in call
        for pattern in ("*.sqlite3", "*.sqlite3-*", "staticfiles", ".env", "__pycache__", "*.pyc", ".pytest_cache"):
            assert f"--exclude={pattern}" in call


def test_lockfile_change_syncs_dependencies(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{SITE}/uv.lock": "version = 0\n"}))

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | Copy uv.lock",
        "Deploy opaq_app service | uv sync /home/opaq-app/site (opaq-app)",
        "Deploy opaq_app service | manage.py migrate and collectstatic",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]


def test_missing_venv_or_other_python_syncs_dependencies(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    responses["sys.version_info"] = ["3.13"]

    run = deploy(cfg, secrets, responses)

    assert "Deploy opaq_app service | uv sync /home/opaq-app/site (opaq-app)" in run.mutating_changed_ops
    del responses["sys.version_info"], responses[f"test -x {HOME}/venv/bin/python"]
    run = deploy(cfg, secrets, responses)
    assert UV_SYNC in run.executed_commands


def test_secret_rotation_rewrites_env_and_restarts(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, upload_token="rotated-fixture-upload-token-0123456789")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | Write environment file",
        "Deploy opaq_app service | manage.py migrate and collectstatic",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]
    assert "rotated-fixture-upload-token" not in run.all_text()


def test_allowlist_change_rewrites_the_route_without_a_restart(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path)
    narrower = make_cfg(tmp_path, allowed_networks=("100.64.0.0/10",))

    run = deploy(narrower, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == ["Deploy opaq_app service | Write Traefik route opaq-app"]
    assert '["100.64.0.0/10"]' in run.upload(ROUTE).decode()


def test_unit_change_reloads_and_restarts(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{UNIT: "[Unit]\n"}))

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | Install systemd unit opaq-app.service",
        "Deploy opaq_app service | Reload systemd for opaq-app.service",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]


def test_exposed_tree_is_privatized(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "-perm /077": [f"{SITE}/src/daybook/__init__.py"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | Own and privatize the synced tree",
        "Deploy opaq_app service | manage.py migrate and collectstatic",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]


def test_exposed_database_is_restricted(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), **fakehost.file(DB, "", user="opaq-app", mode="-rw-r--r--")}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == ["Deploy opaq_app service | Restrict the database"]


def test_missing_database_is_created_by_migrate(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    for key in [key for key in responses if isinstance(key, str) and DB in key]:
        del responses[key]

    run = deploy(cfg, secrets, responses)

    assert "Deploy opaq_app service | manage.py migrate and collectstatic" in run.mutating_changed_ops
    commands = run.executed_commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    assert commands.index(migrate) < next(i for i, c in enumerate(commands) if "chmod 600" in c and DB in c)


def test_port_in_use_by_another_process_fails_before_any_change(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses: dict[Any, Any] = {**converged(cfg, secrets), re.compile(r"^sh -c 'out=\$\(ss "): {"success": False}}

    run = run_deploy_fake(deploy_opaq_app, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == "Deploy opaq_app service | Port preflight tcp/10065"
    assert not any(c.startswith(("groupadd", "useradd", "systemctl")) for c in run.executed_commands)


def test_preflight_allows_the_service_itself(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    script = next(c for c in run.executed_commands if "ss -Hltnp" in c)
    assert "sport = :10065" in script
    assert "/system.slice/opaq-app.service" in script
    assert run.executed_commands.index(script) == 0


def test_static_route_guard(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, refuse_while_exists="/etc/traefik/dynamic/opaq.yml")

    run = deploy(cfg, secrets)

    assert any("test ! -e /etc/traefik/dynamic/opaq.yml" in c for c in run.executed_commands)
    commands = run.executed_commands
    guard = commands.index(next(c for c in commands if "test ! -e" in c))
    assert guard < next(i for i, c in enumerate(commands) if c.startswith("groupadd"))


def test_traefik_can_be_disabled(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, traefik_enabled=False, traefik_host=None, allowed_networks=())

    run = deploy(cfg, secrets)

    assert not any("Traefik" in op.name for op in run.ops)
    assert "DJANGO_ALLOWED_HOSTS=127.0.0.1\n" in render_env(cfg, secrets).reveal().decode()
    assert "DJANGO_CSRF_TRUSTED_ORIGINS=\n" in render_env(cfg, secrets).reveal().decode()


def test_echoport_target_is_upserted_only_when_it_differs(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, echoport=EchoportTarget())
    responses: dict[Any, Any] = converged(cfg, secrets)

    assert deploy(cfg, secrets, responses).mutating_changed_ops == []

    responses[ECHOPORT_PROBE] = ["pending"]
    run = deploy(cfg, secrets, responses)
    assert run.mutating_changed_ops == ["Deploy opaq_app service | Upsert Echoport entry"]
    apply = run.executed_commands[-1]
    assert '"mode": "apply"' in apply
    for fragment in (
        '"name": "opaq_app"',
        f'"db_path": "{DB}"',
        '"schedule": "20 2 * * *"',
        '"schedule_policy": "set"',
    ):
        assert fragment in apply
    assert apply.startswith("cd /home/echoport/site && runuser -u echoport --")


def test_echoport_is_required_when_a_target_is_configured(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, echoport=EchoportTarget())
    responses: dict[Any, Any] = {**converged(cfg, secrets), "echo installed": []}
    responses[re.compile(r"^test -f /home/echoport/site/manage.py \|\|")] = {"success": False}

    run = run_deploy_fake(deploy_opaq_app, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == "Deploy opaq_app service | Require Echoport"
    assert not any('"mode": "apply"' in command for command in run.executed_commands)


def test_nyxmon_check_is_upserted_only_when_it_differs(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, nyxmon_check=NyxmonCheck())
    responses: dict[Any, Any] = converged(cfg, secrets)

    assert deploy(cfg, secrets, responses).mutating_changed_ops == []

    responses[NYXMON_PROBE] = ["pending"]
    run = deploy(cfg, secrets, responses)
    assert run.mutating_changed_ops == ["Deploy opaq_app service | Upsert Nyxmon entry"]
    apply = run.executed_commands[-1]
    assert "set -e; set -a; . /home/nyxmon/site/.env.shell; set +a;" in apply
    assert '"url":"http://127.0.0.1:10065/healthz"' in apply
    assert '"interval":300' in apply
    assert '"apply":true' in apply


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
    assert "Deploy opaq_app service | Check an anonymous request is sent to the login" in run.changed_ops


def test_anonymous_request_away_from_the_login_fails(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, route_checks=RouteChecks(controller_login=True, login_retries=2, login_delay=0))
    run = run_deploy_fake(
        deploy_opaq_app,
        cfg,
        secrets,
        rsync=RecordingRsyncRunner(),
        responses=converged(cfg, secrets),
        fetch=lambda url, verify: (200, ""),
    )

    assert not run.succeeded


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: OpaqAppConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="rotated-" + "9876543210" * 5) if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), upload_token_sha256(secrets), "rotated-" + "9876543210" * 5):
        assert value not in text


def test_env_rides_on_stdin_only(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    import base64

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
def test_role_secret_validations(cfg: OpaqAppConfig, key: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message) as excinfo:
        run_deploy_fake(deploy_opaq_app, cfg, values(cfg, **{key: value}), responses=fakehost.LINUX)
    assert value not in str(excinfo.value) or value == "short"


def test_missing_secret_key_fails(cfg: OpaqAppConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(KeyError, match="upload_token"):
        run_deploy_fake(deploy_opaq_app, cfg, SecretValues(cfg.secrets, {"django_secret_key": "x"}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed_networks": ()},
        {"traefik_host": None},
        {"allowed_networks": ("not-a-network",)},
        {"allowed_networks": ("100.64.0.1",)},
        {"app_port": 80},
        {"traefik_host": "bad host"},
        {"source_dirs": ("../etc",)},
        {"source_dirs": ("src", "missing")},
        {"traefik_enabled": False, "route_checks": RouteChecks(controller_login=True)},
    ],
)
def test_role_validations(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        make_cfg(tmp_path, **overrides)


def test_source_must_be_a_daybook_checkout(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a daybook checkout"):
        OpaqAppConfig(source_path=tmp_path, secrets=SecretRef("secrets/prod/opaq_app.yml"))


def test_unsynced_venv_is_synced_after_an_interrupted_run(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), UV_CHECK: []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | uv sync /home/opaq-app/site (opaq-app)",
        "Deploy opaq_app service | manage.py migrate and collectstatic",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]


def test_unapplied_migrations_are_applied_after_an_interrupted_run(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), MIGRATE_CHECK: []}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy opaq_app service | manage.py migrate and collectstatic",
        "Deploy opaq_app service | Restart opaq-app.service",
    ]


def test_controller_check_follows_verify_tls(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, route_checks=RouteChecks(controller_login=True, verify_tls=False))
    seen: list[bool] = []

    def fetch(url: str, verify: bool) -> tuple[int, str]:
        seen.append(verify)
        return 302, "/login/?next=/"

    deploy(cfg, secrets, converged(cfg, secrets), fetch=fetch)

    assert seen == [False]


def test_echoport_target_follows_the_service_and_user(tmp_path: Path, secrets: SecretValues) -> None:
    cfg = make_cfg(tmp_path, user="opaq", service_name="opaq", site_path="/home/opaq/site", echoport=EchoportTarget())
    responses = {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"]}

    run = deploy(cfg, secrets, responses)

    apply = next(c for c in run.executed_commands if '"mode": "apply"' in c)
    assert '"service_name": "opaq.service"' in apply
    assert '"restore_owner": "opaq:opaq"' in apply
    assert '"db_path": "/home/opaq/data/db.sqlite3"' in apply


def test_migration_probe_writes_no_bytecode(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    probe = next(event.value for event in run.events if MIGRATE_CHECK in event.value)
    assert "PYTHONDONTWRITEBYTECODE=1" in probe
    assert "umask 077" in probe


def test_a_failing_migrations_probe_runs_migrate_and_probes_again(cfg: OpaqAppConfig, secrets: SecretValues) -> None:
    # The probe crashed (not "pending"): the step runs, then the probe must pass.
    responses = {**converged(cfg, secrets), MIGRATE_CHECK: [FAILED]}

    run = deploy(cfg, secrets, responses)

    assert run.succeeded
    assert "Deploy opaq_app service | manage.py migrate and collectstatic" in run.mutating_changed_ops
    verify = run.op("Deploy opaq_app service | Probe again: opaq_app migrations")
    assert verify.changed
    assert verify.read_only
    assert any("migrate --check --plan" in c and "probe still fails" in c for c in run.executed_commands)
