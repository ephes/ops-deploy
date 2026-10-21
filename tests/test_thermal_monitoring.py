"""thermal_monitoring: role template parity, config validation and the deploy's plans on the fake connector."""

from __future__ import annotations

import base64
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services import _nyxmon_json_metrics as json_metrics
from ops_deploy.services._nyxmon_json_metrics import check_command
from ops_deploy.services.thermal_monitoring import (
    PASSWORD_KEY,
    ThermalMonitoringConfig,
    deploy_thermal_monitoring,
)
from ops_deploy.services.thermal_monitoring import deploy as thermal
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.metrics_httpd_fixtures import verify_op, without_switch

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/thermal_monitoring/templates"
PASSWORD = "fixture-endpoint-password"
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: PASSWORD})
TAILSCALE_IP = "100.64.0.7"
URL = "http://host.example.invalid:9104/.well-known/thermal"

SYSFS: list[dict[str, Any]] = [
    {
        "id": "cpu_package",
        "source_entity_id": "sysfs:coretemp:package_id_0",
        "value_path_glob": "/sys/devices/platform/coretemp.0/hwmon/*/temp1_input",
        "sensor_label": "cpu_package",
        "sensor_class": "cpu",
        "metric_kind": "temperature",
        "unit": "celsius",
        "scale": 0.001,
    },
    {
        "id": "fan1",
        "source_entity_id": "sysfs:example:fan1",
        "value_path_glob": "/sys/class/hwmon/hwmon9/fan1_input",
        "sensor_label": "fan1",
        "sensor_class": "fan",
        "metric_kind": "fan",
        "unit": "rpm",
    },
]
LM: list[dict[str, Any]] = [
    {
        "id": "cpu_tctl",
        "source_entity_id": "lm_sensors:k10temp:Tctl",
        "chip_name_regex": "^k10temp-",
        "feature_name": "Tctl",
        "value_key": "temp1_input",
        "sensor_label": "cpu_tctl",
        "sensor_class": "cpu",
    },
    {
        "id": "nvme_boot",
        "source_entity_id": "lm_sensors:nvme:Composite",
        "device_path": "/dev/disk/by-id/nvme-Example_SSD_0001",
        "feature_name": "Composite",
        "value_key": "temp1_input",
    },
]
IPMI: list[dict[str, Any]] = [
    {
        "id": "TEMP_CPU",
        "sensor_name": "TEMP_CPU",
        "source_entity_id": "ipmi:TEMP_CPU",
        "sensor_label": "TEMP_CPU",
        "sensor_class": "cpu",
    }
]
RULES: list[dict[str, Any]] = [
    {"path": "$.meta.age_seconds", "op": ">=", "value": 0, "severity": "warning"},
    {"path": "$.meta.age_seconds", "op": "<", "value": 600, "severity": "warning"},
]
CHECK: dict[str, Any] = {
    "service_name": "example-host",
    "name": "Example Thermal Freshness",
    "check_interval": 300,
    "auth_username": "nyxmon",
    "data": {"url": URL, "timeout": 10.0, "retries": 1, "retry_delay": 2.0, "checks": RULES},
}


def make_cfg(**changes: Any) -> ThermalMonitoringConfig:
    fields: dict[str, Any] = {
        "auth_user": "nyxmon",
        "secrets": "secrets/fixture.yml",
        "timer_on_boot_sec": 75,
        "timer_randomized_delay_sec": 15,
        "exporter": {"packages": ["python3"], "sysfs_sensors": SYSFS},
        "nyxmon_check": CHECK,
    }
    return ThermalMonitoringConfig.model_validate({**fields, **changes})


CFG = make_cfg()


# -- parity with the roles' templates -----------------------------------------------


def render_ansible(role: str, template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["to_json"] = json.dumps
    return env.get_template(f"{role}__{template}").render(**variables)


# thermal_metrics_exporter/defaults/main.yml (the template's variables)
EXPORTER_DEFAULTS: dict[str, Any] = {
    "thermal_metrics_exporter_lm_sensors": [],
    "thermal_metrics_exporter_sysfs_sensors": [],
    "thermal_metrics_exporter_ipmi_sensors": [],
}
# thermal_metrics_endpoint/defaults/main.yml, the derived paths resolved
ENDPOINT_DEFAULTS: dict[str, Any] = {
    "thermal_metrics_endpoint_user": "metrics",
    "thermal_metrics_endpoint_group": "metrics",
    "thermal_metrics_endpoint_bind": "127.0.0.1",
    "thermal_metrics_endpoint_port": 9104,
    "thermal_metrics_endpoint_path": "/.well-known/thermal",
    "thermal_metrics_endpoint_data_dir": "/var/lib/thermal-metrics",
    "thermal_metrics_endpoint_json_path": "/var/lib/thermal-metrics/thermal.json",
    "thermal_metrics_endpoint_server_path": "/usr/local/bin/thermal_metrics_httpd.py",
    "thermal_metrics_endpoint_htpasswd_path": "/etc/thermal-metrics-endpoint/htpasswd",
    "thermal_metrics_endpoint_exporter_path": "/usr/local/bin/thermal-metrics-exporter",
    "thermal_metrics_endpoint_timer_interval": 300,
    "thermal_metrics_endpoint_timer_name": "thermal-metrics-collector",
    "thermal_metrics_endpoint_timer_on_boot_sec": 30,
    "thermal_metrics_endpoint_timer_on_calendar": "*:0/5",
    "thermal_metrics_endpoint_timer_accuracy_sec": 10,
    "thermal_metrics_endpoint_timer_randomized_delay_sec": 30,
}
# (config fields, role variables overriding the defaults), written out independently of role_vars().
VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "defaults": ({"auth_user": "nyxmon", "secrets": "secrets/fixture.yml"}, {}),
    "the monitoring play": (
        {
            "auth_user": "nyxmon",
            "secrets": "secrets/fixture.yml",
            "timer_on_boot_sec": 75,
            "timer_randomized_delay_sec": 15,
            "exporter": {"packages": ["python3"], "sysfs_sensors": SYSFS},
        },
        {
            "thermal_metrics_exporter_sysfs_sensors": SYSFS,
            "thermal_metrics_endpoint_timer_on_boot_sec": 75,
            "thermal_metrics_endpoint_timer_randomized_delay_sec": 15,
        },
    ),
    "everything": (
        {
            "auth_user": "monitor",
            "secrets": "secrets/fixture.yml",
            "service_name": "thermal-x",
            "user": "thermo",
            "group": "thermgrp",
            "site_path": "/srv/thermal",
            "port": 9200,
            "path": "/x/thermal",
            "server_path": "/opt/thermal/httpd.py",
            "htpasswd_dir": "/etc/thermal-x",
            "timer_name": "thermal-x-collector",
            "timer_interval": 120,
            "timer_on_boot_sec": 5,
            "timer_on_calendar": "*:0/2",
            "timer_accuracy_sec": 1,
            "timer_randomized_delay_sec": 0,
            "exporter": {
                "bin_path": "/opt/thermal/exporter",
                "lm_sensors": LM,
                "sysfs_sensors": SYSFS,
                "ipmi_sensors": IPMI,
            },
        },
        {
            "thermal_metrics_exporter_lm_sensors": LM,
            "thermal_metrics_exporter_sysfs_sensors": SYSFS,
            "thermal_metrics_exporter_ipmi_sensors": IPMI,
            "thermal_metrics_endpoint_user": "thermo",
            "thermal_metrics_endpoint_group": "thermgrp",
            "thermal_metrics_endpoint_port": 9200,
            "thermal_metrics_endpoint_path": "/x/thermal",
            "thermal_metrics_endpoint_data_dir": "/srv/thermal",
            "thermal_metrics_endpoint_json_path": "/srv/thermal/thermal.json",
            "thermal_metrics_endpoint_server_path": "/opt/thermal/httpd.py",
            "thermal_metrics_endpoint_htpasswd_path": "/etc/thermal-x/htpasswd",
            "thermal_metrics_endpoint_exporter_path": "/opt/thermal/exporter",
            "thermal_metrics_endpoint_timer_interval": 120,
            "thermal_metrics_endpoint_timer_on_boot_sec": 5,
            "thermal_metrics_endpoint_timer_on_calendar": "*:0/2",
            "thermal_metrics_endpoint_timer_accuracy_sec": 1,
            "thermal_metrics_endpoint_timer_randomized_delay_sec": 0,
        },
    ),
}
TEMPLATES: dict[tuple[str, str], Callable[[ThermalMonitoringConfig], str]] = {
    ("thermal_metrics_exporter", "thermal-metrics-exporter.py.j2"): lambda cfg: thermal.render_exporter(cfg),
    ("thermal_metrics_endpoint", "thermal_metrics_httpd.py.j2"): lambda cfg: thermal.render_httpd(cfg),
    ("thermal_metrics_endpoint", "thermal-metrics-collector.service.j2"): thermal.render_collector_service,
    ("thermal_metrics_endpoint", "thermal-metrics-collector.timer.j2"): thermal.render_collector_timer,
    ("thermal_metrics_endpoint", "thermal-metrics-endpoint.service.j2"): lambda cfg: thermal.render_endpoint_unit(
        cfg, "127.0.0.1"
    ),
}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("template", TEMPLATES, ids=lambda key: key[1])
def test_files_are_the_roles_templates_rendered(template: tuple[str, str], variant: str) -> None:
    fields, overrides = VARIANTS[variant]
    cfg = ThermalMonitoringConfig.model_validate(fields)

    expected = render_ansible(*template, {**EXPORTER_DEFAULTS, **ENDPOINT_DEFAULTS, **overrides})
    assert TEMPLATES[template](cfg) == expected


@pytest.mark.parametrize("template", sorted(p.name for p in PACKAGED.glob("*.j2")))
def test_shipped_templates_are_the_vendored_role_templates(template: str) -> None:
    role = "thermal_metrics_exporter" if template.startswith("thermal-metrics-exporter") else "thermal_metrics_endpoint"
    assert (PACKAGED / template).read_bytes() == (VENDORED / f"{role}__{template}").read_bytes()


def test_the_exporter_reads_back_the_sensor_lists_with_their_types() -> None:
    cfg = make_cfg(exporter={"lm_sensors": LM, "sysfs_sensors": SYSFS, "ipmi_sensors": IPMI})
    namespace: dict[str, Any] = {"__name__": "thermal_exporter"}

    exec(compile(thermal.render_exporter(cfg), "exporter", "exec"), namespace)

    assert namespace["LM_SENSORS"] == LM
    assert namespace["SYSFS_SENSORS"] == SYSFS
    assert type(namespace["SYSFS_SENSORS"][0]["scale"]) is float
    assert namespace["IPMI_SENSORS"] == IPMI


def test_the_endpoint_binds_to_the_given_address() -> None:
    unit = thermal.render_endpoint_unit(CFG, TAILSCALE_IP)

    assert f"  --bind {TAILSCALE_IP} \\\n" in unit


# -- config ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"auth_user": "CHANGE_ME"}, "placeholder"),
        ({"auth_user": "a:b"}, "auth_user"),
        ({"auth_user": ""}, "auth_user"),
        ({"bind": "0.0.0.0.0"}, "bind"),
        ({"bind": "::1"}, "bind"),
        ({"port": 0}, "port"),
        ({"path": "thermal"}, "path"),
        ({"path": "/a b"}, "path"),
        ({"site_path": "/var/lib/a b"}, "site_path"),
        ({"server_path": "relative.py"}, "server_path"),
        ({"timer_name": "-x"}, "timer_name"),
        ({"timer_interval": 0}, "timer_interval"),
        ({"timer_interval": "300"}, "timer_interval"),
        ({"timer_on_calendar": "*:0/5\nExecStart=/bin/sh"}, "timer_on_calendar"),
        ({"packages": ["Bad Package"]}, "packages"),
        ({"exporter": {"bin_path": "/usr/local/bin/x y"}}, "bin_path"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "id": "a-b"}]}}, "id"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "value_path_glob": "sys/x"}]}}, "absolute"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "scale": "0.001"}]}}, "scale"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "scale": float("inf")}]}}, "finite"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "scale": True}]}}, "scale"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "sensor_label": "a'''b"}]}}, "single quotes"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "unit": "a\nb"}]}}, "control"),
        ({"exporter": {"sysfs_sensors": [{**SYSFS[0], "extra": 1}]}}, "extra"),
        ({"exporter": {"sysfs_sensors": [{"id": "x", "source_entity_id": "y"}]}}, "value_path_glob"),
        ({"exporter": {"lm_sensors": [{**LM[0], "chip_name_regex": None}]}}, "chip_name_regex"),
        ({"exporter": {"lm_sensors": [{**LM[1], "device_path": "dev/nvme0"}]}}, "chip_name_regex"),
        ({"exporter": {"lm_sensors": [{**LM[0], "feature_name": ""}]}}, "feature_name"),
        ({"exporter": {"ipmi_sensors": [{"id": "x", "source_entity_id": "y"}]}}, "sensor_name"),
        ({"nyxmon_check": {**CHECK, "auth_username": "someone-else"}}, "auth_user"),
        ({"nyxmon_check": {**CHECK, "data": {**CHECK["data"], "checks": []}}}, "checks"),
        ({"nyxmon_check": {**CHECK, "data": {k: v for k, v in CHECK["data"].items() if k != "url"}}}, "url"),
        ({"nyxmon_check": {**CHECK, "data": {**CHECK["data"], "url": "ftp://x.example.invalid/"}}}, "url"),
        ({"nyxmon_check": {**CHECK, "data": {**CHECK["data"], "auth": {"username": "x"}}}}, "auth"),
        ({"nyxmon_check": {**CHECK, "data": {**CHECK["data"], "timeout": float("nan")}}}, "NaN"),
        ({"nyxmon_check": {**CHECK, "check_interval": 0}}, "check_interval"),
        ({"nyxmon_check": {**CHECK, "name": "a\\b"}}, "name"),
        ({"nyxmon_check": {**CHECK, "service_name": " "}}, "service_name"),
        ({"nyxmon_check": {**CHECK, "db_path": "/home/nyxmon/../db"}}, "db_path"),
    ],
)
def test_bad_configs_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        make_cfg(**changes)


def test_the_password_comes_from_a_secrets_file() -> None:
    with pytest.raises(ConfigValidationError, match="secrets file"):
        make_cfg(secrets=None)


def test_errors_never_echo_the_input() -> None:
    with pytest.raises(ConfigValidationError) as caught:
        make_cfg(exporter={"sysfs_sensors": [{**SYSFS[0], "sensor_label": "secret-looking'"}]})

    assert "secret-looking" not in str(caught.value)


def test_a_check_without_auth_needs_no_password() -> None:
    cfg = make_cfg(nyxmon_check={k: v for k, v in CHECK.items() if k != "auth_username"})

    assert cfg.nyxmon_check is not None
    assert "auth" not in cfg.nyxmon_check.desired_data(None)
    with pytest.raises(ValueError, match="password"):
        cfg.nyxmon_check.desired_data(PASSWORD)


def test_the_check_data_keeps_every_json_type() -> None:
    assert CFG.nyxmon_check is not None
    stored = json.dumps(CFG.nyxmon_check.desired_data(PASSWORD), sort_keys=True)

    assert '"timeout": 10.0' in stored
    assert '"retries": 1,' in stored
    assert '"value": 0}' in stored
    assert json.loads(stored)["auth"] == {"username": "nyxmon", "password": PASSWORD}


# -- the deploy's plans ------------------------------------------------------------------

EXPORTER = "/usr/local/bin/thermal-metrics-exporter"
HTTPD = "/usr/local/bin/thermal_metrics_httpd.py"
HTPASSWD = "/etc/thermal-metrics-endpoint/htpasswd"
UNITS = "/etc/systemd/system"
COLLECTOR = "thermal-metrics-collector.service"
TIMER = "thermal-metrics-collector.timer"
ENDPOINT = "thermal-metrics-endpoint.service"
TIMER_SHOW = f"systemctl show {TIMER} --property=NextElapseUSecRealtime --property=NextElapseUSecMonotonic"
ARMED = ["NextElapseUSecRealtime=Tue 2026-10-20 15:00:00 CEST", "NextElapseUSecMonotonic=infinity"]
UNARMED = ["NextElapseUSecMonotonic=infinity", "NextElapseUSecRealtime=n/a"]
JSON_PROBE = "if test -e /var/lib/thermal-metrics/thermal.json"
NYXMON_PROBE = " probe /home/nyxmon/site/db.sqlite3 example-host "
HASH = hash_password(PASSWORD)

P = "Thermal monitoring | "
RUN_COLLECTOR = f"{P}Run {COLLECTOR} once"
REARM = f"{P}Re-arm {TIMER}, which elapsed without a next trigger"
UPSERT = f"{P}Upsert Nyxmon check Example Thermal Freshness"


def htpasswd(content: str, *, group: str = "metrics", mode: str = "-rw-r-----") -> dict[str, Any]:
    return {**fakehost.file(HTPASSWD, content), **fakehost.stat(HTPASSWD, group=group, mode=mode)}


def converged(cfg: ThermalMonitoringConfig = CFG) -> dict[str, Any]:
    check = cfg.nyxmon_check
    return {
        **fakehost.UBUNTU,
        "tailscale ip --4": [TAILSCALE_IP],
        JSON_PROBE: ["present"],
        TIMER_SHOW: ARMED,
        NYXMON_PROBE: [f"check {check.digest(PASSWORD)}"] if check else {"success": False},
        **fakehost.deb_installed("python3", "apache2-utils"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory(UNITS),
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.stat("/var/lib/thermal-metrics", group="metrics", mode="drwxr-x---"),
        **fakehost.stat("/etc/thermal-metrics-endpoint", group="metrics", mode="drwxr-x---"),
        **fakehost.file(EXPORTER, thermal.render_exporter(cfg), mode="-rwxr-xr-x"),
        **fakehost.file(HTTPD, thermal.render_httpd(cfg), mode="-rwxr-xr-x"),
        **htpasswd(f"nyxmon:{HASH}\n"),
        **fakehost.file(f"{UNITS}/{COLLECTOR}", thermal.render_collector_service(cfg)),
        **fakehost.file(f"{UNITS}/{TIMER}", thermal.render_collector_timer(cfg)),
        **fakehost.file(f"{UNITS}/{ENDPOINT}", thermal.render_endpoint_unit(cfg, TAILSCALE_IP)),
        **fakehost.service(TIMER),
        **fakehost.service(ENDPOINT),
    }


def run(responses: dict[str, Any], cfg: ThermalMonitoringConfig = CFG, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_thermal_monitoring, cfg, SECRETS, responses=responses)
    assert result.succeeded is ok, result.error
    return result


def test_converged_host_plans_only_read_only_checks() -> None:
    result = run(converged())

    assert result.mutating_changed_ops == []
    assert [op.name for op in result.ops if op.changed] == [
        f"{P}Require an armed {TIMER}",
        verify_op(P, "thermal-metrics-endpoint"),
        f"{P}Require a private Nyxmon database for Example Thermal Freshness",
    ]
    assert not any("restart" in c or "systemctl start" in c for c in result.executed_commands)
    assert result.uploads == []
    assert without_switch(result.stdin) == []


FRESH = {**fakehost.UBUNTU, "tailscale ip --4": [TAILSCALE_IP], NYXMON_PROBE: ["service absent"]}


def test_fresh_host_installs_everything_once() -> None:
    result = run(FRESH)

    assert result.mutating_changed_ops == [
        f"{P}Install the thermal exporter packages",
        f"{P}Install {EXPORTER}",
        f"{P}Install the thermal endpoint packages",
        f"{P}Ensure group metrics",
        f"{P}Ensure user metrics",
        f"{P}Ensure /var/lib/thermal-metrics",
        f"{P}Ensure /etc/thermal-metrics-endpoint",
        f"{P}Install {HTTPD}",
        f"{P}Write {HTPASSWD}",
        f"{P}Install systemd unit {COLLECTOR}",
        f"{P}Install systemd unit {TIMER}",
        f"{P}Install systemd unit {ENDPOINT}",
        f"{P}Reload systemd for the thermal metrics units",
        RUN_COLLECTOR,
        f"{P}Enable {TIMER}",
        f"{P}Start {TIMER}",
        f"{P}Enable {ENDPOINT}",
        f"{P}Start {ENDPOINT}",
        UPSERT,
    ]
    commands = result.executed_commands
    assert f"systemctl start {COLLECTOR}" in commands
    assert not any(c.startswith("systemctl restart") for c in commands)
    assert not any("apt-get update" in c for c in commands)
    assert any("useradd" in c and "-s /usr/sbin/nologin" in c and "-m" not in c.split() for c in commands)
    assert result.upload(EXPORTER).decode() == thermal.render_exporter(CFG)
    assert result.upload(f"{UNITS}/{ENDPOINT}").decode() == thermal.render_endpoint_unit(CFG, TAILSCALE_IP)


def test_a_failing_nyxmon_probe_upserts_and_probes_again() -> None:
    result = run({**converged(), NYXMON_PROBE: [FAILED]})

    assert result.mutating_changed_ops == [UPSERT]
    assert result.ops[-1].name == f"{P}Probe again: Nyxmon check Example Thermal Freshness"
    assert result.ops[-1].read_only


def test_the_htpasswd_entry_is_written_privately_from_stdin() -> None:
    result = run(FRESH)

    (install,) = [(c, s) for c, s in result.stdin if HTPASSWD.rsplit("/", 1)[0] in c]
    command, payload = install
    assert " 0640 root metrics" in command
    entry = base64.b64decode(payload).decode()
    user, _, hashed = entry.rstrip("\n").partition(":")
    assert user == "nyxmon"
    assert entry.endswith("\n")
    assert hashed.startswith("$2y$05$")
    assert thermal.credentials_verify([entry.rstrip("\n")], "nyxmon", PASSWORD)


def test_the_password_never_appears_outside_stdin() -> None:
    for responses in (converged(), FRESH, {**converged(), NYXMON_PROBE: ["check absent"]}):
        result = run(responses)
        assert PASSWORD not in result.all_text()


def test_the_check_data_travels_only_on_the_upserts_stdin() -> None:
    result = run({**converged(), NYXMON_PROBE: ["check absent"]})

    assert result.mutating_changed_ops == [UPSERT]
    (upsert,) = [(c, s) for c, s in result.stdin if " apply " in c]
    command, payload = upsert
    assert command.startswith("runuser -u nyxmon -- python3 -I -c ")
    assert command.endswith(" apply /home/nyxmon/site/db.sqlite3 example-host 'Example Thermal Freshness'")
    assert "env " not in command.split(" -c ")[0]
    assert URL not in command
    assert json.loads(payload) == {"check_interval": 300, "data": CFG.nyxmon_check.desired_data(PASSWORD)}  # type: ignore[union-attr]


def test_the_upsert_retries_like_the_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json_metrics, "RETRY_DELAY", 0)
    assert json_metrics.RETRIES == 7
    responses = {
        **converged(),
        NYXMON_PROBE: ["check absent"],
        " apply /home/nyxmon/site/db.sqlite3": {"success": False},
    }

    result = run(responses, ok=False)

    applies = [c for c in result.executed_commands if " apply /home/nyxmon/site/db.sqlite3" in c]
    assert len(applies) == 8


def test_a_changed_password_rewrites_the_htpasswd_and_restarts_only_the_endpoint() -> None:
    responses = converged()
    responses.update(htpasswd(f"nyxmon:{hash_password('old-password')}\n"))
    responses[NYXMON_PROBE] = ["check 0000"]

    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Write {HTPASSWD}", f"{P}Restart {ENDPOINT}", UPSERT]
    assert f"systemctl restart {ENDPOINT}" in result.executed_commands


@pytest.mark.parametrize(
    "content",
    [
        "",
        "other:$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6\n",
        "nyxmon:$apr1$abcdefgh$0123456789abcdefghijkl\n",
        "nyxmon:$2y$00$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6\n",
    ],
    ids=["empty", "other user", "not bcrypt", "malformed bcrypt"],
)
def test_an_htpasswd_that_does_not_verify_is_regenerated(content: str) -> None:
    responses = converged()
    responses.update(htpasswd(content))

    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Write {HTPASSWD}", f"{P}Restart {ENDPOINT}"]


def test_a_verifying_htpasswd_is_kept_whatever_its_other_lines() -> None:
    responses = converged()
    responses.update(htpasswd(f"someone:x\nnyxmon:{HASH}"))

    assert run(responses).mutating_changed_ops == []


@pytest.mark.parametrize(
    ("group", "mode"), [("root", "-rw-r-----"), ("metrics", "-rw-rw-rw-"), ("metrics", "-rw-------")]
)
def test_a_verifying_htpasswd_gets_its_owner_and_mode_back_without_a_rewrite(group: str, mode: str) -> None:
    responses = converged()
    responses.update(htpasswd(f"nyxmon:{HASH}\n", group=group, mode=mode))

    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Ensure owner and mode of {HTPASSWD}"]
    assert without_switch(result.stdin) == []
    assert set(result.executed_commands) & {f"chmod 640 {HTPASSWD}", f"chown root:metrics {HTPASSWD}"}


def test_exporter_drift_rewrites_it_and_runs_the_collector_once() -> None:
    responses = converged()
    responses.update(fakehost.file(EXPORTER, "#!/usr/bin/env python3\n", mode="-rwxr-xr-x"))

    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Install {EXPORTER}", RUN_COLLECTOR]
    assert not any("restart" in c for c in result.executed_commands)


def test_httpd_drift_restarts_the_endpoint_only() -> None:
    responses = converged()
    responses.update(fakehost.file(HTTPD, "old\n", mode="-rwxr-xr-x"))

    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Install {HTTPD}", f"{P}Restart {ENDPOINT}"]


def test_timer_unit_drift_reloads_and_restarts_the_timer_only() -> None:
    responses = converged()
    responses.update(fakehost.file(f"{UNITS}/{TIMER}", "[Timer]\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [
        f"{P}Install systemd unit {TIMER}",
        f"{P}Reload systemd for the thermal metrics units",
        f"{P}Restart {TIMER}",
    ]


def test_collector_unit_drift_reloads_and_runs_the_collector_without_restarts() -> None:
    responses = converged()
    responses.update(fakehost.file(f"{UNITS}/{COLLECTOR}", "[Service]\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [
        f"{P}Install systemd unit {COLLECTOR}",
        f"{P}Reload systemd for the thermal metrics units",
        RUN_COLLECTOR,
    ]


def test_a_new_tailscale_address_rewrites_the_unit_and_restarts_the_endpoint() -> None:
    result = run({**converged(), "tailscale ip --4": ["100.64.0.8"]})

    assert result.mutating_changed_ops == [
        f"{P}Install systemd unit {ENDPOINT}",
        f"{P}Reload systemd for the thermal metrics units",
        f"{P}Restart {ENDPOINT}",
    ]
    assert "--bind 100.64.0.8 " in result.upload(f"{UNITS}/{ENDPOINT}").decode()


def test_a_missing_metrics_file_runs_the_collector_once() -> None:
    result = run({**converged(), JSON_PROBE: ["absent"]})

    assert result.mutating_changed_ops == [RUN_COLLECTOR]


@pytest.mark.parametrize("answer", [UNARMED, [FAILED], ["NextElapseUSecRealtime=", "NextElapseUSecMonotonic=0"]])
def test_an_unarmed_timer_is_re_armed(answer: list[str]) -> None:
    result = run({**converged(), TIMER_SHOW: answer})

    assert result.mutating_changed_ops == [REARM]
    assert f"systemctl restart {TIMER}" in result.executed_commands


def test_a_timer_this_run_restarts_is_not_re_armed_again() -> None:
    responses = {**converged(), TIMER_SHOW: UNARMED}
    responses.update(fakehost.file(f"{UNITS}/{TIMER}", "[Timer]\n"))

    result = run(responses)

    assert REARM not in result.mutating_changed_ops
    assert result.executed_commands.count(f"systemctl restart {TIMER}") == 1


def test_a_timer_that_stays_unarmed_fails_the_run() -> None:
    # First match wins: the failing re-read before the planning probe's (shorter) command.
    result = run({"--property=SubState": {"success": False}, **converged()}, ok=False)

    assert result.op(f"{P}Require an armed {TIMER}").succeeded is False


def test_the_armed_check_reads_like_the_role() -> None:
    assert thermal.timer_armed("\n".join(ARMED))
    assert thermal.timer_armed("NextElapseUSecMonotonic=1d 2h")
    assert not thermal.timer_armed("\n".join(UNARMED))
    assert not thermal.timer_armed("NextElapseUSecRealtime=  N/A \nNextElapseUSecMonotonic=0")
    assert not thermal.timer_armed("")


@pytest.mark.parametrize("answer", [[], ["100.64.0.7", "100.64.0.8"], ["fd7a::1"], ["not-an-ip"], [FAILED]])
def test_without_a_tailscale_ipv4_address_nothing_happens(answer: list[str]) -> None:
    result = run({**converged(), "tailscale ip --4": answer}, ok=False)

    assert result.ops == []
    assert "Tailscale" in str(result.error)


def test_an_explicit_bind_needs_no_tailscale() -> None:
    cfg = make_cfg(bind="127.0.0.1")
    responses = converged(cfg)
    responses.update(fakehost.file(f"{UNITS}/{ENDPOINT}", thermal.render_endpoint_unit(cfg, "127.0.0.1")))
    responses["tailscale ip --4"] = {"success": False}

    result = run(responses, cfg)

    assert result.mutating_changed_ops == []
    assert not any("tailscale" in c for c in result.fact_commands)


@pytest.mark.parametrize(
    "password", ["", "CHANGE_ME", "two\nlines", "carriage\rreturn", "nul\x00byte-password", "tab\tpassword", "x" * 73]
)
def test_unusable_passwords_are_refused_before_any_operation(password: str) -> None:
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: password})

    result = run_deploy_fake(deploy_thermal_monitoring, CFG, secrets, responses=converged())

    assert not result.succeeded
    assert result.ops == []
    if len(password) > 9:
        assert password not in str(result.error)


def test_a_private_database_is_required_before_the_upsert() -> None:
    guard = check_command(CFG.nyxmon_check, "guard")  # type: ignore[arg-type]
    responses = {**converged(), guard: {"success": False}, NYXMON_PROBE: [FAILED]}

    result = run(responses, ok=False)

    assert not any(" apply /home/nyxmon/site/db.sqlite3" in c for c in result.executed_commands)


def test_a_drifted_check_is_upserted() -> None:
    result = run({**converged(), NYXMON_PROBE: ["check 0123"]})

    assert result.mutating_changed_ops == [UPSERT]


def test_without_a_nyxmon_check_nyxmon_is_not_touched() -> None:
    cfg = make_cfg(nyxmon_check=None)

    result = run(converged(cfg), cfg)

    assert result.mutating_changed_ops == []
    assert not any("nyxmon" in c for c in result.executed_commands + result.fact_commands)


def test_converged_commands_are_valid_shell() -> None:
    result = run(FRESH)
    for command in result.executed_commands + result.fact_commands:
        checked = subprocess.run(["sh", "-n", "-c", command], capture_output=True, text=True, check=False)
        assert checked.returncode == 0, checked.stderr
