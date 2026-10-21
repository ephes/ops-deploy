"""Deploy-level scenarios for graphyard core against the fake connector."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.graphyard import GraphyardConfig, MetricSpecs, deploy_graphyard_core
from ops_deploy.services.graphyard import core as core_module
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.graphyard_fixtures import (
    REF,
    SECRETS,
    SPECS,
    core_config,
    macmini_core_config,
    make_source,
    secrets_values,
)
from tests.test_infra_docker_vector import DOCKER_PACKAGES, docker_converged

PREFIX = "Deploy graphyard core | "
SITE = "/opt/apps/graphyard/site"
DB = f"{SITE}/src/django/db.sqlite3"
ENV = "/etc/graphyard/graphyard.env"
COMPOSE = "/opt/apps/graphyard/docker-compose.yml"
SPECS_FILE = "/etc/graphyard/metric-collection-specs.json"
RELEASES = "/etc/graphyard/inventory-releases.json"
UNITS = "/etc/systemd/system"
READ_ONLY = {
    "Check Docker and Compose",
    "Require the Grafana provisioning assets",
    "Wait for the InfluxDB API",
    "Verify Grafana InfluxDB v1 auth",
    "Require pyproject.toml in the site",
    "Require uv.lock in the site",
    "Require the InfluxDB container to be running",
    "Validate the release registry without fetching or changing the database",
    "Wait for the graphyard web port",
    "Query the Graphyard health endpoint",
    "Verify graphyard services are active",
    "Check graphyard-agent runs the Python agent",
}


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.fixture
def cfg(source: Path) -> GraphyardConfig:
    return macmini_core_config(source)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def as_file(
    path: str, text: str, *, user: str = "root", group: str = "root", mode: str = "-rw-r--r--"
) -> dict[str, Any]:
    return {**fakehost.file(path, text), **fakehost.stat(path, user=user, group=group, mode=mode)}


def specs_probe(rendered: str) -> list[str]:
    """What the specs probe prints for a database holding exactly ``rendered``'s specs (written independently)."""

    lines = []
    for spec in json.loads(rendered)["metric_collection_specs"]:
        state = [spec.get("enabled", True), spec["spec_type"], spec.get("interval_seconds", 60), spec.get("config", {})]
        lines.append(f"spec {digest(spec['name'])} {digest(json.dumps(state, sort_keys=True))}")
    return lines


def converged(cfg: GraphyardConfig, secrets: SecretValues | None = None, /, **drift: str) -> dict[str, Any]:
    """Facts of a host where graphyard core is fully deployed; ``drift`` overrides file content by path."""

    secrets = secrets or secrets_values()
    render = core_module.render
    files = {
        ENV: (render("graphyard.env.j2", cfg, secrets), "graphyard", "-rw-r-----"),
        COMPOSE: (render("docker-compose.yml.j2", cfg, secrets), "root", "-rw-r-----"),
        f"{UNITS}/graphyard-runtime.service": (render("graphyard-runtime.service.j2", cfg, secrets), "root", None),
        f"{UNITS}/graphyard-web.service": (render("graphyard-web.service.j2", cfg, secrets), "root", None),
        f"{UNITS}/graphyard-agent.service": (render("graphyard-agent.service.j2", cfg, secrets), "root", None),
    }
    if cfg.metric_specs is not None:
        files[SPECS_FILE] = (core_module.render_specs(cfg, secrets), "graphyard", "-rw-r-----")
    if cfg.inventory_release_sources is not None:
        files[RELEASES] = (core_module.render_releases(cfg.inventory_release_sources), "graphyard", "-rw-r-----")
        for kind in ("service", "timer"):
            text = render(f"inventory-releases.{kind}.j2", cfg, secrets)
            files[f"{UNITS}/graphyard-inventory-releases.{kind}"] = (text, "root", None)
    responses: dict[str, Any] = {
        # Probes first: the fake connector answers with the first key a command contains.
        "metric_collection_spec": [],
        "--dry-run 2>&1": ["current"],
        "collectstatic --noinput --dry-run": ["current"],
        "migrate --check --plan": ["current"],
        **docker_converged(),
        **fakehost.accounts({"graphyard": "/opt/apps/graphyard"}, ("docker",), shell="/bin/bash"),
        **fakehost.deb_installed(*DOCKER_PACKAGES, "rsync"),
        **fakehost.directory("/opt/apps/graphyard", user="graphyard"),
        **fakehost.directory(SITE, user="graphyard"),
        **fakehost.stat("/etc/graphyard", group="graphyard", mode="drwxr-x---"),
        **fakehost.directory("/var/lib/graphyard"),
        **fakehost.directory("/var/lib/graphyard/influxdb2", user="1000"),
        **fakehost.directory("/var/lib/graphyard/influxdb2-config", user="1000"),
        **fakehost.directory("/var/lib/graphyard/grafana", user="472"),
        **fakehost.directory(UNITS),
        "stat -c '%u %g %a' /var/lib/graphyard/influxdb2-config": ["1000 0 775"],
        "stat -c '%u %g %a' /var/lib/graphyard/influxdb2": ["1000 0 755"],
        "stat -c '%u %g %a' /var/lib/graphyard/grafana": ["472 472 755"],
        "docker network inspect graphyard-monitoring": ["present"],
        "influx v1 auth list": ["present"],
        "influx bucket list": ["0123abcd 15552000"],
        f"test -e {SITE}/.venv/bin/python": ["present"],
        f"test -e {DB}": ["present"],
        f"stat -c '%U:%G %a' {DB}": ["graphyard:graphyard 640"],
        "/usr/local/bin/uv --version": ["uv 0.13.4 (x86_64-unknown-linux-gnu)"],
        **fakehost.file("/usr/local/bin/uvx", "uvx"),
        **fakehost.directory("/usr/local/bin"),
    }
    for container, service in (("graphyard-influxdb", "influxdb"), ("graphyard-grafana", "grafana")):
        responses[f"{{{{ end }}}} @exists' {container}"] = [f"graphyard-runtime|{service} @exists"]
    if cfg.metric_specs is not None:
        responses["metric_collection_spec"] = specs_probe(core_module.render_specs(cfg, secrets))
    else:
        del responses["metric_collection_spec"]
    for unit in ("graphyard-runtime", "graphyard-web", "graphyard-agent"):
        responses.update(fakehost.service(f"{unit}.service"))
    responses.update(fakehost.service("graphyard-inventory-releases.timer"))
    for path, (text, group, mode) in files.items():
        responses.update(as_file(path, drift.get(path, text), group=group, mode=mode or "-rw-r--r--"))
    return responses


def deploy(
    cfg: GraphyardConfig,
    responses: dict[str, Any] | None = None,
    secrets: SecretValues | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_graphyard_core,
        cfg,
        secrets or secrets_values(),
        rsync or RecordingRsyncRunner(),
        responses=responses if responses is not None else fakehost.UBUNTU,
    )
    assert run.succeeded, (run.error, [op.name for op in run.ops if not op.succeeded])
    return run


AFTER_SITE_CHANGE = [
    "Sync runtime dependencies with uv",
    "Run Django migrations",
    "Collect static files",
    "Apply declarative metric collection specs",
    "Restart graphyard-web.service",
    "Restart graphyard-agent.service",
]


def mutating(run: FakeRun) -> list[str]:
    return [name.removeprefix(PREFIX) for name in run.mutating_changed_ops]


def assert_no_secret_leaks(run: FakeRun) -> None:
    text = run.all_text()
    for key, value in SECRETS.items():
        assert value not in text, f"{key} leaked"


def test_second_run_changes_nothing(cfg: GraphyardConfig) -> None:
    rsync = RecordingRsyncRunner()
    run = deploy(cfg, converged(cfg), rsync=rsync)

    assert mutating(run) == []
    assert {name.removeprefix(PREFIX) for name in run.changed_ops} <= READ_ONLY
    assert run.uploaded_paths == []
    assert [call for call in rsync.calls if "--dry-run" not in call] == []
    # Only the read-only check of Grafana's InfluxDB login reads a secret (on stdin).
    assert [command.rsplit(" ", 1)[1] for command, _ in run.stdin] == ["check"]
    assert_no_secret_leaks(run)


def test_first_run_installs_everything(cfg: GraphyardConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f+++++++++ pyproject.toml"]})
    run = deploy(cfg, rsync=rsync)
    commands = run.executed_commands
    ops = mutating(run)

    assert "groupadd -r graphyard" in commands
    assert any(c.startswith("useradd -d /opt/apps/graphyard -s /bin/bash -g graphyard") for c in commands)
    real = [call for call in rsync.calls if "--dry-run" not in call]
    assert len(real) == 1
    assert real[0][-1].endswith(f":{SITE}/")
    assert "--delete" in real[0]
    assert "--chown=graphyard:graphyard" in real[0]
    assert {f"--exclude={pattern}" for pattern in core_module.SOURCE_EXCLUDES} <= set(real[0])
    assert any("install docker-ce" in c for c in commands)
    assert "chown 1000:0 /var/lib/graphyard/influxdb2 && chmod 0755 /var/lib/graphyard/influxdb2" in commands
    assert (
        "chown 1000:0 /var/lib/graphyard/influxdb2-config && chmod 0775 /var/lib/graphyard/influxdb2-config" in commands
    )
    assert "chown 472:472 /var/lib/graphyard/grafana && chmod 0755 /var/lib/graphyard/grafana" in commands
    assert "docker network create graphyard-monitoring" in commands
    assert "systemctl start graphyard-runtime.service" in commands
    # Started by this run: no restart (and no container recreation) on top.
    assert "systemctl restart graphyard-runtime.service" not in commands
    assert "Create Grafana InfluxDB v1 auth when missing" in ops
    assert any("uv venv --python 3.12 /opt/apps/graphyard/site/.venv" in c for c in commands)
    assert any("uv sync --no-default-groups --no-dev" in c for c in commands)
    assert any("manage.py migrate --noinput" in c for c in commands)
    assert any("manage.py collectstatic --noinput" in c for c in commands)
    assert any(
        "apply_metric_collection_specs --file /etc/graphyard/metric-collection-specs.json --prune" in c
        for c in commands
    )
    assert any("influx bucket update --id" in c and "--retention 180d" in c for c in commands)
    assert run.upload(RELEASES).decode() == core_module.render_releases(cfg.inventory_release_sources or ())
    assert run.upload(f"{UNITS}/graphyard-web.service").decode() == core_module.render(
        "graphyard-web.service.j2", cfg, secrets_values()
    )
    assert "systemctl start graphyard-inventory-releases.timer" in commands
    assert "systemctl start graphyard-web.service" in commands
    assert "systemctl start graphyard-agent.service" in commands
    assert "systemctl restart graphyard-web.service" not in commands
    # Secret files are installed from stdin, never uploaded or put on a command line.
    assert ENV not in run.uploaded_paths
    assert COMPOSE not in run.uploaded_paths
    assert SPECS_FILE not in run.uploaded_paths
    installed = [command for command, _ in run.stdin if "python3 -I -c" in command]
    assert any(ENV.rsplit("/", 1)[1] in command for command in installed)
    assert_no_secret_leaks(run)


def test_compose_change_restarts_the_runtime_only(cfg: GraphyardConfig) -> None:
    run = deploy(cfg, converged(cfg, **{COMPOSE: "services: {}\n"}))

    assert mutating(run) == ["Render Graphyard compose file", "Restart graphyard-runtime.service"]
    assert_no_secret_leaks(run)


def test_runtime_unit_change_reloads_and_restarts(cfg: GraphyardConfig) -> None:
    run = deploy(cfg, converged(cfg, **{f"{UNITS}/graphyard-runtime.service": "[Unit]\n"}))

    assert mutating(run) == [
        "Install systemd unit graphyard-runtime.service",
        "Reload systemd for graphyard-runtime.service",
        "Restart graphyard-runtime.service",
    ]


def test_unmanaged_container_is_removed_and_the_runtime_restarted(cfg: GraphyardConfig) -> None:
    responses = converged(cfg)
    responses["{{ end }} @exists' graphyard-grafana"] = [" @exists"]

    run = deploy(cfg, responses)

    assert mutating(run) == [
        "Remove unmanaged container graphyard-grafana before the Compose takeover",
        "Restart graphyard-runtime.service",
    ]
    assert "docker rm -f graphyard-grafana" in run.executed_commands


def test_unmanaged_containers_stay_when_the_migration_is_off(source: Path) -> None:
    cfg = macmini_core_config(source, runtime={"migrate_unmanaged_containers": False})
    responses = converged(cfg)
    responses["{{ end }} @exists' graphyard-grafana"] = ["other|grafana @exists"]

    assert mutating(deploy(cfg, responses)) == []


def test_source_change_syncs_installs_migrates_and_restarts_the_app(cfg: GraphyardConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... src/graphyard/views.py"]})
    run = deploy(cfg, converged(cfg), rsync=rsync)

    assert mutating(run) == [
        "Sync Graphyard source",
        "Sync runtime dependencies with uv",
        "Run Django migrations",
        "Collect static files",
        "Apply declarative metric collection specs",
        "Restart graphyard-web.service",
        "Restart graphyard-agent.service",
    ]
    assert "systemctl restart graphyard-runtime.service" not in run.executed_commands


def test_wrong_owners_are_fixed_but_logyards_files_are_left_alone(cfg: GraphyardConfig) -> None:
    """The shared Grafana tree: Graphyard owns it except Logyard's datasource file and dashboards."""

    responses = converged(cfg)
    responses[f"find {SITE} "] = [f"{SITE}/deploy/grafana/provisioning/dashboards-json"]

    run = deploy(cfg, responses)

    assert mutating(run) == ["Ensure ownership for synced files", *AFTER_SITE_CHANGE]
    chown = next(c for c in run.executed_commands if c.startswith(f"find {SITE} "))
    assert (
        f"\\( -path {SITE}/deploy/grafana/provisioning/datasources/logyard.yaml "
        f"-o -path {SITE}/deploy/grafana/dashboards/logyard \\) -prune -o" in chown
    )
    assert chown.endswith("-exec chown -h graphyard:graphyard {} +")
    probe = next(c for c in run.fact_commands if c.startswith(f"find {SITE} "))
    assert "-prune -o" in probe


def test_dashboards_mount_point_is_never_deleted_by_the_sync(cfg: GraphyardConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... README.md"]})
    deploy(cfg, converged(cfg), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--exclude=deploy/grafana/provisioning/dashboards-json/" in real


def test_env_change_rewrites_it_migrates_and_restarts_web_and_agent(source: Path) -> None:
    cfg = macmini_core_config(source)
    new = macmini_core_config(source, django={"allowed_hosts": ("127.0.0.1", "new.example.invalid")})

    run = deploy(new, converged(cfg))

    # New settings may need migrations or static files the old ones did not (the role runs both always).
    assert mutating(run) == [
        "Render Graphyard environment file",
        "Run Django migrations",
        "Collect static files",
        "Apply declarative metric collection specs",
        "Restart graphyard-web.service",
        "Restart graphyard-agent.service",
    ]


def test_missing_static_files_are_collected(cfg: GraphyardConfig) -> None:
    responses = converged(cfg)
    responses["collectstatic --noinput --dry-run"] = ["pending"]

    run = deploy(cfg, responses)

    assert mutating(run) == ["Collect static files"]


def test_pending_migration_runs_migrate_only(cfg: GraphyardConfig) -> None:
    responses = converged(cfg)
    responses["migrate --check --plan"] = ["pending"]

    assert mutating(deploy(cfg, responses)) == ["Run Django migrations", "Apply declarative metric collection specs"]


def test_retention_drift_updates_the_bucket(cfg: GraphyardConfig) -> None:
    responses = converged(cfg)
    responses["influx bucket list"] = ["0123abcd 0"]

    run = deploy(cfg, responses)

    assert mutating(run) == ["Update bucket retention when it drifts"]
    assert any("influx bucket update --id" in c for c in run.executed_commands)


def test_retention_left_alone_when_not_applied(source: Path) -> None:
    cfg = macmini_core_config(source, influx={"retention_apply": False})
    responses = converged(cfg)
    responses["influx bucket list"] = ["0123abcd 0"]

    run = deploy(cfg, responses)

    assert mutating(run) == []
    assert not any("influx bucket" in c for c in run.executed_commands)


def test_missing_grafana_influx_login_is_created(cfg: GraphyardConfig) -> None:
    responses = converged(cfg)
    responses["influx v1 auth list"] = ["missing"]

    run = deploy(cfg, responses)

    assert mutating(run) == ["Create Grafana InfluxDB v1 auth when missing"]
    create, stdin = next(
        (command, stdin) for command, stdin in run.stdin if "/private/legacy/authorizations" in command
    )
    assert stdin == f"{SECRETS['influx_token']}\n{SECRETS['grafana_influx_password']}\n"
    assert SECRETS["grafana_influx_password"] not in create
    assert create.endswith("http://127.0.0.1:8086 graphyard graphyard grafana ensure")
    assert_no_secret_leaks(run)


def test_metric_spec_drift_applies_the_specs(cfg: GraphyardConfig) -> None:
    responses = converged(cfg)
    responses["metric_collection_spec"] = responses["metric_collection_spec"][1:]

    assert mutating(deploy(cfg, responses)) == ["Apply declarative metric collection specs"]


def test_changed_spec_secret_rewrites_and_applies(cfg: GraphyardConfig) -> None:
    old = converged(cfg)
    secrets = secrets_values(nyxmon_storage_metrics_password="graphyard-fixture-rotated")

    run = deploy(cfg, old, secrets=secrets)

    assert mutating(run) == ["Render declarative metric collection specs", "Apply declarative metric collection specs"]


def test_specs_current_compares_like_the_command() -> None:
    rendered = json.dumps(
        {
            "metric_collection_specs": [
                {"name": " a ", "spec_type": "http_json_metric", "config": {"url": "x"}},
                {"name": "b", "spec_type": "http_page_probe", "enabled": False, "interval_seconds": 30},
            ]
        }
    )

    def row(name: str, state: list[Any]) -> str:
        return f"spec {digest(name)} {digest(json.dumps(state, sort_keys=True))}"

    stored = [row("a", [True, "http_json_metric", 60, {"url": "x"}]), row("b", [False, "http_page_probe", 30, {}])]
    extra = row("c", [True, "http_page_probe", 60, {}])

    assert core_module.specs_current("\n".join(stored), rendered, prune=True)
    assert core_module.specs_current("\n".join([*stored, extra]), rendered, prune=False)
    assert not core_module.specs_current("\n".join([*stored, extra]), rendered, prune=True)
    assert not core_module.specs_current(stored[0], rendered, prune=False)


def test_without_a_runtime_there_is_no_docker(source: Path) -> None:
    cfg = core_config(source, runtime=None)
    secrets = SecretValues(REF, {k: v for k, v in SECRETS.items() if not k.startswith("grafana")})

    run = deploy(cfg, secrets=secrets)

    assert not any("docker" in c for c in run.executed_commands)
    assert "Requires=" not in run.upload(f"{UNITS}/graphyard-web.service").decode()


def test_release_refresh_off_stops_an_installed_timer(source: Path) -> None:
    cfg = macmini_core_config(source, inventory_release_sources=None)
    responses = converged(cfg)
    responses.update(fakehost.stat(f"{UNITS}/graphyard-inventory-releases.timer"))
    responses["test -e /etc/systemd/system/graphyard-inventory-releases.timer"] = ["present"]

    run = deploy(cfg, responses)

    assert "systemctl stop graphyard-inventory-releases.timer" in run.executed_commands
    assert "systemctl disable graphyard-inventory-releases.timer" in run.executed_commands


def test_skip_django_manage_runs_no_management_command(source: Path) -> None:
    cfg = macmini_core_config(source, skip_django_manage=True)
    responses = converged(cfg)
    responses["migrate --check --plan"] = ["pending"]

    run = deploy(cfg, responses)

    # The agent check reads the agent's argv (``manage.py start_agent``); it runs nothing.
    assert not any("manage.py" in c for c in run.executed_commands if "/proc/$pid/cmdline" not in c)


def test_resolve_specs_fills_the_playbooks_references() -> None:
    resolved = core_module.resolve_specs(SPECS, secrets_values())

    assert resolved[0]["config"]["access_token"] == SECRETS["homeassistant_api_token"]
    assert resolved[1]["config"]["basic_password"] == SECRETS["nyxmon_storage_metrics_password"]
    assert "basic_password_secret_ref" not in resolved[1]["config"]
    assert resolved[2]["config"]["password"] == SECRETS["homeassistant_unifi_password"]
    assert resolved[3] == SPECS[3]
    # An explicit token or password is kept; the reference is still dropped.
    kept = core_module.resolve_specs(
        [{"spec_type": "http_json_metric", "config": {"basic_password": "x", "basic_password_secret_ref": "y"}}],
        secrets_values(),
    )
    assert kept[0]["config"] == {"basic_password": "x"}


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        (
            {"name": "s", "spec_type": "http_json_metric", "config": {"basic_password_secret_ref": "other"}},
            "unsupported basic_password_secret_ref",
        ),
        ({"name": "s", "spec_type": "home_assistant_sensor", "config": {}}, "homeassistant_api_token"),
    ],
)
def test_resolve_specs_refuses_unknown_or_missing_secrets(spec: dict[str, Any], message: str) -> None:
    secrets = SecretValues(REF, {k: v for k, v in SECRETS.items() if k != "homeassistant_api_token"})

    with pytest.raises(ValueError, match=message):
        core_module.resolve_specs([spec], secrets)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"django_secret_key": "CHANGEME"}, "django_secret_key"),
        ({"influx_token": "replace-me"}, "influx_token"),
        ({"grafana_admin_password": ""}, "grafana_admin_password"),
        ({"inventory_monitor_token": "short"}, "inventory_monitor_token"),
        ({"grafana_influx_password": "a\nb"}, "single lines"),
        ({"django_secret_key": "synthetic-secret(key)"}, "env file unquoted"),
        ({"influx_token": "a b"}, "env file unquoted"),
        ({"django_secret_key": "x$HOME"}, "env file unquoted"),
    ],
)
def test_secrets_are_checked_before_any_connection(cfg: GraphyardConfig, changes: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        core_module.check_secrets(cfg, secrets_values(**changes))


def test_inventory_monitor_token_must_be_present_but_may_be_empty(cfg: GraphyardConfig) -> None:
    core_module.check_secrets(cfg, secrets_values(inventory_monitor_token=""))
    secrets = SecretValues(REF, {k: v for k, v in SECRETS.items() if k != "inventory_monitor_token"})
    with pytest.raises(ValueError, match="inventory_monitor_token"):
        core_module.check_secrets(cfg, secrets)


@pytest.mark.parametrize(
    "changes",
    [
        {"influx": {"bucket_retention": "6 months"}},
        {"metric_specs": MetricSpecs(prune=True)},
        {"web_service_name": "graphyard-agent"},
        {"source_excludes": ("--delete-excluded",)},
        {"django": {"allowed_hosts": ("a b",)}},
        {"site_path": "relative"},
    ],
)
def test_config_rejects_bad_inputs(source: Path, changes: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        core_config(source, **changes)


def test_source_must_be_a_graphyard_tree(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(ConfigValidationError, match="not a Graphyard tree"):
        core_config(tmp_path / "empty")


def test_duration_seconds_follows_to_time_unit() -> None:
    assert core_module.duration_seconds("180d") == 15552000
    assert core_module.duration_seconds("0s") == 0
    assert core_module.duration_seconds("2w") == 1209600


def test_runtime_replacement_ca_store_rendering(source: Path) -> None:
    cfg = macmini_core_config(source)
    assert cfg.runtime is not None
    protected = cfg.model_copy(
        update={"runtime": cfg.runtime.model_copy(update={"ca_store_root": Path("/var/lib/managed-container-ca")})}
    )
    text = core_module.render("docker-compose.yml.j2", protected, secrets_values())
    assert text.count("create_host_path: false") == 2
    assert text.count("SSL_CERT_FILE") == 2
    assert text.count("SSL_CERT_DIR") == 2
    assert "/graphyard-influxdb" in text
    assert "/graphyard-grafana" in text


def test_runtime_rejects_relative_ca_store() -> None:
    from pydantic import ValidationError

    from ops_deploy.services.graphyard.core import Runtime

    with pytest.raises(ValidationError):
        Runtime(ca_store_root=Path("relative"))


def test_missing_prepared_runtime_ca_store_aborts_before_service_changes(source: Path) -> None:
    import re

    cfg = macmini_core_config(source)
    assert cfg.runtime is not None
    protected = cfg.model_copy(
        update={"runtime": cfg.runtime.model_copy(update={"ca_store_root": Path("/var/lib/managed-container-ca")})}
    )
    responses: dict[Any, Any] = dict(fakehost.UBUNTU)
    responses[re.compile(r"test -s /var/lib/managed-container-ca/.*")] = {"success": False}
    runner = RecordingRsyncRunner()
    run = run_deploy_fake(deploy_graphyard_core, protected, secrets_values(), runner, responses=responses)
    assert not run.succeeded
    assert not run.op(PREFIX + "Require prepared CA store /var/lib/managed-container-ca/graphyard-influxdb").succeeded
    assert not run.mutating_changed_ops
    assert all("--dry-run" in call for call in runner.calls)
