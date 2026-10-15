"""Deploy-level scenarios for logyard core against the fake connector."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import MissingSecretKeysError, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.logyard import (
    GrafanaWiring,
    HealthEndpoint,
    LogyardConfig,
    Loki,
    NyxmonChecks,
    ReadyChecks,
    deploy_logyard_core,
)
from ops_deploy.services.logyard import core as core_module
from ops_deploy.services.logyard.core import HEALTH_SCRIPT, nyxmon_checks, nyxmon_checks_current
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.logyard_fixtures import (
    DASHBOARD,
    EXTRA_DASHBOARD,
    PASSWORD,
    core_config,
    make_source,
    secrets_values,
)
from tests.test_infra_docker_vector import docker_converged

PREFIX = "Deploy logyard core | "
TARGET = "/opt/apps/graphyard/site/deploy/grafana/dashboards/logyard"
DB = "/home/nyxmon/site/db.sqlite3"
READ_ONLY = [
    PREFIX + "Check Docker and Compose",
    PREFIX + "Require the Graphyard Grafana container",
    PREFIX + "Wait for Loki /ready",
    PREFIX + "Wait for the Logyard health endpoint",
]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


@pytest.fixture
def cfg(source: Path) -> LogyardConfig:
    return core_config(source)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def nyxmon_probe(cfg: LogyardConfig, password: str = PASSWORD, *, interval: int | None = None) -> list[str]:
    """What ``nyxmon_checks.py probe`` prints on a database holding the checks (written independently)."""

    lines = ["service present"]
    for check in nyxmon_checks(cfg.nyxmon, password):
        data = json.dumps(check["data"], sort_keys=True)
        state = json.dumps([check["check_type"], check["url"], interval or check["check_interval"], data])
        lines.append(f"check {digest(check['name'])} {digest(state)}")
    return lines


def converged(cfg: LogyardConfig, **drift: str) -> dict[str, Any]:
    """Facts of a host where logyard core is fully deployed; ``drift`` overrides file content by path."""

    health = cfg.health
    content = {
        str(cfg.config_path): core_module.render_loki_config(cfg),
        str(cfg.compose_path): core_module.render_compose(cfg),
        f"/etc/systemd/system/{cfg.service_name}.service": core_module.render_service_unit(cfg),
    }
    if cfg.grafana is not None:
        content[str(cfg.grafana.datasource_path)] = core_module.render_datasource(cfg)
        content[f"{TARGET}/logyard-home.json"] = DASHBOARD
        content[f"{TARGET}/extra/more.json"] = EXTRA_DASHBOARD
    if health is not None:
        content[str(health.script_path)] = HEALTH_SCRIPT
        content[f"/etc/systemd/system/{health.service_name}.service"] = core_module.render_health_unit(cfg)
    content.update(drift)

    responses: dict[str, Any] = {
        **docker_converged(cfg.docker),
        **fakehost.accounts({"logyard": "/opt/apps/logyard"}, ("docker",)),
        **fakehost.deb_installed(*cfg.docker.prerequisite_packages, *cfg.docker.packages, "rsync"),
        **fakehost.directory("/opt/apps/logyard", user="logyard"),
        **fakehost.directory("/opt/apps/logyard/site", user="logyard"),
        **fakehost.directory("/etc/logyard"),
        **fakehost.directory("/var/lib/logyard/loki", user="10001"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.service(f"{cfg.service_name}.service"),
        "stat -c '%u %g %a' /var/lib/logyard/loki": ["10001 10001 755"],
        "docker network inspect graphyard-monitoring": ["present"],
        "stat -c %a ": ["755"],
        f"test -f {DB}": ["present"],
        "runuser -u nyxmon": nyxmon_probe(cfg),
    }
    if cfg.grafana is not None:
        responses.update(
            {
                "docker inspect --format '{{.State.Running}}'": ["true"],
                "docker inspect --format '{{json .NetworkSettings.Networks}}'": ['{"graphyard-monitoring": {}}'],
            }
        )
        for path in (
            "/opt/apps/graphyard/site/deploy/grafana/provisioning/datasources",
            "/opt/apps/graphyard/site/deploy/grafana/dashboards",
            TARGET,
            f"{TARGET}/extra",
        ):
            responses.update(fakehost.directory(path))
    if health is not None:
        responses.update(fakehost.service(f"{health.service_name}.service"))
    for path, text in content.items():
        executable = path == str(health.script_path) if health else False
        responses.update(fakehost.file(path, text, mode="-rwxr-xr-x" if executable else "-rw-r--r--"))
    return responses


def deploy(
    cfg: LogyardConfig,
    responses: dict[str, Any] | None = None,
    secrets: SecretValues | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_logyard_core,
        cfg,
        secrets or secrets_values(),
        rsync or RecordingRsyncRunner(),
        responses=responses if responses is not None else fakehost.UBUNTU,
    )
    assert run.succeeded, (run.error, [op.name for op in run.ops if not op.succeeded])
    return run


def test_first_run_installs_everything(cfg: LogyardConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f+++++++++ README.md"]})
    run = deploy(cfg, rsync=rsync)
    commands = run.executed_commands

    # Docker first, then the user, directories, source and runtime.
    assert any("install docker-ce" in c for c in commands)
    assert "groupadd -r logyard" in commands
    assert "useradd -d /opt/apps/logyard -s /usr/sbin/nologin -g logyard -r -M logyard" in commands
    assert "chown logyard:logyard /opt/apps/logyard" in commands
    assert "mkdir -p /var/lib/logyard/loki" in commands
    assert "chown 10001:10001 /var/lib/logyard/loki && chmod 0755 /var/lib/logyard/loki" in commands
    real = [call for call in rsync.calls if "--dry-run" not in call]
    assert len(real) == 1
    assert f"{cfg.source_path}/" in real[0]
    assert real[0][-1].endswith(":/opt/apps/logyard/site/")
    assert "--chown=logyard:logyard" in real[0]
    assert "--delete" in real[0]
    assert {"--exclude=.vault_password", "--exclude=.git/", "--exclude=__pycache__/", "--exclude=*.pyc"} <= set(real[0])
    assert "docker network create graphyard-monitoring" in commands
    assert run.upload("/etc/logyard/loki-config.yml").decode() == core_module.render_loki_config(cfg)
    assert run.upload("/opt/apps/logyard/docker-compose.yml").decode() == core_module.render_compose(cfg)
    assert run.upload("/etc/systemd/system/logyard.service").decode() == core_module.render_service_unit(cfg)
    assert "systemctl start logyard.service" in commands
    # Started by this run: no restart on top.
    assert "systemctl restart logyard.service" not in commands
    assert "docker network connect graphyard-monitoring graphyard-grafana" in commands
    assert run.upload("/opt/apps/graphyard/site/deploy/grafana/provisioning/datasources/logyard.yaml").decode() == (
        core_module.render_datasource(cfg)
    )
    assert run.upload(f"{TARGET}/logyard-home.json").decode() == DASHBOARD
    assert run.upload(f"{TARGET}/extra/more.json").decode() == EXTRA_DASHBOARD
    assert run.upload("/usr/local/bin/logyard_health_httpd.py").decode() == HEALTH_SCRIPT
    assert "systemctl start logyard-health-endpoint.service" in commands
    assert "docker restart graphyard-grafana" in commands
    # The checks come last; the database exists on the fixture host only when it says so.
    assert run.stdin == []


def test_second_run_changes_nothing(cfg: LogyardConfig) -> None:
    rsync = RecordingRsyncRunner()
    run = deploy(cfg, converged(cfg), rsync=rsync)

    assert run.mutating_changed_ops == []
    assert [op for op in run.changed_ops if op not in READ_ONLY] == []
    assert run.uploaded_paths == []
    assert run.stdin == []
    assert [call for call in rsync.calls if "--dry-run" not in call] == []


def test_loki_config_change_restarts_logyard_only(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg, **{str(cfg.config_path): "auth_enabled: true\n"}))

    assert run.mutating_changed_ops == [PREFIX + "Render Loki config", PREFIX + "Restart logyard.service"]
    assert "systemctl restart logyard.service" in run.executed_commands
    assert not any("docker restart" in c for c in run.executed_commands)


def test_new_retention_rewrites_the_config_and_restarts(source: Path) -> None:
    old, new = core_config(source), core_config(source, loki=Loki(retention_period="720h"))

    run = deploy(new, converged(old))

    assert run.mutating_changed_ops == [PREFIX + "Render Loki config", PREFIX + "Restart logyard.service"]
    assert "retention_period: 720h" in run.upload("/etc/logyard/loki-config.yml").decode()


def test_unit_change_reloads_systemd_and_restarts(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg, **{"/etc/systemd/system/logyard.service": "[Service]\n"}))

    assert sorted(run.mutating_changed_ops) == [
        PREFIX + "Install systemd unit logyard.service",
        PREFIX + "Reload systemd for logyard.service",
        PREFIX + "Restart logyard.service",
    ]


def test_changed_dashboard_is_put_and_restarts_grafana(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg, **{f"{TARGET}/logyard-home.json": "{}\n"}))

    assert run.mutating_changed_ops == [
        PREFIX + "Copy Logyard dashboard logyard-home.json",
        PREFIX + "Restart Graphyard Grafana",
    ]
    assert run.uploaded_paths == [f"{TARGET}/logyard-home.json"]
    assert "docker restart graphyard-grafana" in run.executed_commands
    assert "systemctl restart logyard.service" not in run.executed_commands


def test_changed_datasource_restarts_grafana(cfg: LogyardConfig) -> None:
    path = str(cfg.grafana.datasource_path)  # type: ignore[union-attr]

    run = deploy(cfg, converged(cfg, **{path: "apiVersion: 1\n"}))

    assert run.mutating_changed_ops == [
        PREFIX + "Render Logyard datasource provisioning file",
        PREFIX + "Restart Graphyard Grafana",
    ]


def test_grafana_not_on_the_logyard_network_is_connected_and_restarted(cfg: LogyardConfig) -> None:
    responses = converged(cfg)
    responses["docker inspect --format '{{json .NetworkSettings.Networks}}'"] = ['{"bridge": {}}']

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [
        PREFIX + "Connect Graphyard Grafana to the Logyard network",
        PREFIX + "Restart Graphyard Grafana",
    ]


def test_stopped_grafana_is_started(cfg: LogyardConfig) -> None:
    responses = converged(cfg)
    responses["docker inspect --format '{{.State.Running}}'"] = ["false"]

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [PREFIX + "Start Graphyard Grafana"]
    assert "docker start graphyard-grafana" in run.executed_commands


def test_wrongly_owned_dashboard_files_are_fixed_and_restart_grafana(cfg: LogyardConfig) -> None:
    responses = converged(cfg)
    find = f"find {TARGET} -type f"
    responses[find] = [f"{TARGET}/stale.json"]

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [
        PREFIX + "Make Logyard dashboard files root-owned 0644",
        PREFIX + "Restart Graphyard Grafana",
    ]
    assert any("-exec chown root:root {} + -exec chmod 0644 {} +" in c for c in run.executed_commands)


def test_wrongly_owned_dashboard_directories_are_fixed(cfg: LogyardConfig) -> None:
    responses = converged(cfg)
    responses[f"find {TARGET} -type d"] = [f"{TARGET}/old"]

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [
        PREFIX + "Make Logyard dashboard directories root-owned 0755",
        PREFIX + "Restart Graphyard Grafana",
    ]


def test_health_script_change_restarts_only_the_endpoint(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg, **{"/usr/local/bin/logyard_health_httpd.py": "#!/bin/sh\n"}))

    assert run.mutating_changed_ops == [
        PREFIX + "Install Logyard health endpoint script",
        PREFIX + "Restart logyard-health-endpoint.service",
    ]


def test_source_change_syncs_without_restarting_anything(cfg: LogyardConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... docs/operational-assumptions.md"]})

    run = deploy(cfg, converged(cfg), rsync=rsync)

    assert run.mutating_changed_ops == [PREFIX + "Sync Logyard source"]


def test_missing_grafana_container_fails_the_deploy(cfg: LogyardConfig) -> None:
    # The probes tolerate a missing container; the "require" step does not.
    missing: dict[Any, Any] = {
        re.compile(r"State\.Running\}\}' \S+ >/dev/null"): {"success": False, "stderr": "No such object"}
    }
    responses = {**missing, **converged(cfg)}

    run = run_deploy_fake(deploy_logyard_core, cfg, secrets_values(), RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    assert PREFIX + "Require the Graphyard Grafana container" in [op.name for op in run.ops if not op.succeeded]
    assert not any("docker restart" in c for c in run.executed_commands)


def test_grafana_wiring_can_be_turned_off(source: Path) -> None:
    cfg = core_config(source, grafana=None)

    run = deploy(cfg, converged(cfg))

    assert run.mutating_changed_ops == []
    assert not any("graphyard" in c for c in run.executed_commands)


def test_health_endpoint_and_checks_can_be_turned_off(source: Path) -> None:
    cfg = core_config(source, health=None, ready_checks=None)

    run = deploy(cfg, converged(cfg))

    assert run.mutating_changed_ops == []
    assert [op for op in run.changed_ops if op.endswith(("/ready", "health endpoint"))] == []
    assert not any("logyard-health" in c for c in run.executed_commands)


def test_readiness_checks_poll_loki_and_the_endpoint(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg))

    scripts = [c for c in run.executed_commands if "seq 1 18" in c]
    assert len(scripts) == 2
    assert "http://127.0.0.1:3101/ready" in scripts[0]
    assert "http://127.0.0.1:9105/.well-known/logyard" in scripts[1]
    assert "sleep 5" in scripts[0]


def test_custom_ready_checks(source: Path) -> None:
    cfg = core_config(source, ready_checks=ReadyChecks(retries=3, delay_seconds=1))

    run = deploy(cfg, converged(cfg))

    assert len([c for c in run.executed_commands if "seq 1 3)" in c]) == 2


# -- Nyxmon -----------------------------------------------------------------------


def test_nyxmon_checks_are_the_playbooks(cfg: LogyardConfig) -> None:
    checks = nyxmon_checks(cfg.nyxmon, "pw")

    assert [check["name"] for check in checks] == [
        "Logyard API Health (JSON Metrics)",
        "Logyard Ingest Freshness (JSON Metrics)",
        "Logyard Vector Producer (JSON Metrics)",
    ]
    first = checks[0]
    assert first["check_type"] == "json-metrics"
    assert first["url"] == "http://127.0.0.1:9105/.well-known/logyard"
    assert first["check_interval"] == 60
    assert first["data"]["notification_suppression"] == {
        "url": "http://macmini:9106/.well-known/os-apt-maintenance",
        "timeout": 3.0,
        "reason": "macmini_os_apt_maintenance",
        "status_path": "$.last_status",
        "active_statuses": ["running"],
        "finished_epoch_path": "$.last_run_finished_epoch",
        "active_for_seconds": 900,
        "auth": {"username": "nyxmon", "password": "pw"},
    }
    assert checks[2]["data"]["checks"][1] == {
        "path": "$.units.vector.active_state",
        "op": "==",
        "value": "active",
        "severity": "critical",
    }


def test_current_checks_are_recognised_by_digest(cfg: LogyardConfig) -> None:
    checks = nyxmon_checks(cfg.nyxmon, PASSWORD)
    probe = "\n".join(nyxmon_probe(cfg))

    assert nyxmon_checks_current(probe, checks)
    assert not nyxmon_checks_current("service absent", checks)
    assert not nyxmon_checks_current("\n".join(nyxmon_probe(cfg, interval=5)), checks)
    assert not nyxmon_checks_current(
        "\n".join(nyxmon_probe(cfg, "other-password")), nyxmon_checks(cfg.nyxmon, PASSWORD)
    )
    assert not nyxmon_checks_current("\n".join(nyxmon_probe(cfg)[:-1]), checks)


def test_drifted_nyxmon_check_is_upserted_with_the_password_on_stdin(cfg: LogyardConfig) -> None:
    responses = converged(cfg)
    responses["runuser -u nyxmon"] = nyxmon_probe(cfg, interval=5)

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [PREFIX + "Upsert Nyxmon Logyard json-metrics checks"]
    ((command, stdin),) = run.stdin
    assert command.startswith("runuser -u nyxmon -- env ")
    assert "'NYXMON_SERVICE_NAME=Logyard (macmini)'" in command
    assert command.rstrip().endswith("apply >/dev/null")
    assert json.loads(stdin) == nyxmon_checks(cfg.nyxmon, PASSWORD)
    # The password is only ever on stdin.
    assert PASSWORD not in run.all_text()


def test_new_password_is_upserted(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg), secrets_values(nyxmon_storage_metrics_password="rotated-fixture-password"))

    assert run.mutating_changed_ops == [PREFIX + "Upsert Nyxmon Logyard json-metrics checks"]
    assert "rotated-fixture-password" not in run.all_text()
    assert "rotated-fixture-password" in run.stdin[0][1]


def test_missing_nyxmon_database_skips_the_checks(cfg: LogyardConfig) -> None:
    responses = converged(cfg)
    del responses[f"test -f {DB}"]

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == []
    assert run.stdin == []
    assert not any("nyxmon" in c for c in run.executed_commands)


def test_nyxmon_probe_script_runs_isolated_as_the_nyxmon_user(cfg: LogyardConfig) -> None:
    run = deploy(cfg, converged(cfg))

    probes = [c for c in run.fact_commands if c.startswith("( runuser -u nyxmon")]
    assert probes
    assert "python3 -I -c" in probes[0]
    # Strict: a failing probe is reported, not read as "not current".
    assert probes[0].rstrip().endswith(" probe ) || { echo; echo ops-deploy-probe-failed; }")


# -- secrets and config -----------------------------------------------------------------


def test_missing_secret_fails_before_any_operation(cfg: LogyardConfig) -> None:
    assert cfg.secrets is not None
    with pytest.raises(MissingSecretKeysError, match="nyxmon_storage_metrics_password"):
        run_deploy_fake(deploy_logyard_core, cfg, SecretValues(cfg.secrets, {}), RecordingRsyncRunner())


def test_multiline_secret_is_refused(cfg: LogyardConfig) -> None:
    with pytest.raises(ValueError, match="single line"):
        run_deploy_fake(
            deploy_logyard_core, cfg, secrets_values(nyxmon_storage_metrics_password="a\nb"), RecordingRsyncRunner()
        )


def test_config_needs_the_secrets_file(source: Path) -> None:
    with pytest.raises(ConfigValidationError, match="nyxmon_storage_metrics_password"):
        LogyardConfig(
            source_path=source,
            nyxmon=NyxmonChecks(suppression_url="http://macmini:9106/x", suppression_reason="macmini"),
        )


def test_config_rejects_bad_inputs(source: Path, tmp_path: Path) -> None:
    core_config(source)
    empty = tmp_path / "empty"
    empty.mkdir()
    for bad in (
        {"source_path": empty},
        {"source_path": tmp_path / "missing"},
        {"source_path": source / "README.md"},
        {"home": "opt/logyard"},
        {"site_path": "/opt/../etc"},
        {"docker_network_name": "net work"},
        {"loki": {"image": "Grafana Loki"}},
        {"source_excludes": ("--delete",)},
        {"health": {"service_name": "logyard"}},
        {"user": "Root"},
    ):
        with pytest.raises(ConfigValidationError):
            core_config(source, **bad)


@pytest.mark.parametrize(
    "bad",
    [
        {"port": 0},
        {"path": "no-slash"},
        {"selector": "a\nb"},
        {"selector": "100%"},
        {"selector": "back\\slash"},
        {"units": ({"id": "a.b", "unit": "a.service"},)},
        {"units": ({"id": "a"},)},
        {"bind_host": "localhost; rm"},
    ],
)
def test_health_endpoint_rejects_bad_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HealthEndpoint(**bad)


def test_grafana_and_loki_reject_bad_inputs() -> None:
    for model, bad in (
        (GrafanaWiring, {"datasource_uid": "has space"}),
        (GrafanaWiring, {"datasource_path": "relative/logyard.yaml"}),
        (Loki, {"retention_period": "forever"}),
        (Loki, {"data_owner": "root"}),
        (Loki, {"data_dir": "/var/lib/../x"}),
        (Loki, {"schema_from": "yesterday"}),
    ):
        with pytest.raises(ValidationError):
            model(**bad)


def test_relative_source_path_is_made_absolute(source: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(source.parent)

    cfg = core_config(source, source_path=Path("logyard"))

    assert cfg.source_path == source


def test_a_failing_nyxmon_probe_upserts_and_probes_again(cfg: LogyardConfig) -> None:
    responses = {**converged(cfg), "runuser -u nyxmon": [FAILED]}

    run = deploy(cfg, responses)

    assert any(name.endswith("| Upsert Nyxmon Logyard json-metrics checks") for name in run.mutating_changed_ops)
    assert any(name.endswith("| Probe again: Nyxmon Logyard checks") for name in run.changed_ops)
