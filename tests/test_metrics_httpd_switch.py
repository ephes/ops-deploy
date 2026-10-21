"""services._metrics_httpd: the pyinfra side of ops-library's metrics_httpd_switch (PLAN.md 7.2, 7.4; S5e).

- the drop-in template and the argv/sandbox/probe rules are ops-library's
  (vendored byte for byte; with ``OPS_LIBRARY_PATH`` the drift tests compare
  them, and the renders of the three ports must equal the role's goldens and
  the inputs the roles hand to the switch);
- the plans of select/verify against the fake connector, for both
  implementations and the failure paths;
- the per-service inputs (argv, sandbox, probe) and their place in each deploy;
- ``files/verify_host.py`` run locally against a fake ``systemctl``, a fake
  ``/proc`` and a local HTTP server.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shlex
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import jinja2
import pytest
import yaml
from pyinfra.api import DeployError, deploy

from ops_deploy.core import ConfigValidationError
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services import _metrics_httpd as switch
from ops_deploy.services._metrics_httpd import Endpoint, HttpdSwitchFields, rules
from ops_deploy.services.logyard import HealthEndpoint
from ops_deploy.services.logyard import core as logyard_core
from ops_deploy.services.static_site import StaticSiteConfig
from ops_deploy.services.static_site import deploy as static_site
from ops_deploy.services.thermal_monitoring import deploy as thermal
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.logyard_fixtures import core_config, make_source
from tests.metrics_httpd_fixtures import BINARY, ROOT, SHA, VERSION, installed, verify_op
from tests.static_site_fixtures import make_source as make_site
from tests.test_logyard import PREFIX as LOGYARD_P
from tests.test_logyard import converged as logyard_converged
from tests.test_logyard import deploy as logyard_deploy
from tests.test_static_site import converged as static_converged
from tests.test_static_site import deploy as static_deploy
from tests.test_thermal_monitoring import TAILSCALE_IP as THERMAL_TS
from tests.test_thermal_monitoring import P as THERMAL_P
from tests.test_thermal_monitoring import converged as thermal_converged
from tests.test_thermal_monitoring import make_cfg as thermal_make_cfg
from tests.test_thermal_monitoring import run as thermal_run

OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
PACKAGE = Path(__file__).parents[1] / "src/ops_deploy"
VENDORED = Path(__file__).parent / "parity" / "ansible" / "metrics_httpd_switch__metrics-httpd-impl.conf.j2"
PY = "/usr/bin/python3 -I -"
P = "Switch | "
UNIT = "demo-endpoint"
DROPIN = f"/etc/systemd/system/{UNIT}.service.d/metrics-httpd-impl.conf"
ENDPOINT = Endpoint(
    service_name=UNIT,
    argv=(
        *("json-file", "--bind", "100.64.0.7", "--port", "9104", "--path", "/.well-known/demo"),
        *("--json-path", "/var/lib/demo/demo.json", "--htpasswd-file", "/etc/demo/htpasswd"),
        *("--realm", "demo-metrics", "--server-name", "demo-metrics-httpd/0.1"),
    ),
    user="metrics",
    group="metrics",
    sandbox=("NoNewPrivileges=yes", "ProtectSystem=strict", "ReadOnlyPaths=/var/lib/demo"),
    python_script="/usr/local/bin/demo_httpd.py",
    probe_bind="100.64.0.7",
    probe_port=9104,
    probe_path="/.well-known/demo",
    probe_realm="demo-metrics",
    ip_address_allow=("localhost", "100.64.0.0/10"),
)
PYTHON = HttpdSwitchFields()
PYTHON_PINNED = HttpdSwitchFields(httpd_rust_version=VERSION, httpd_rust_sha256=SHA)
RUST = HttpdSwitchFields(httpd_impl="rust", httpd_rust_version=VERSION, httpd_rust_sha256=SHA)
PIN_CHECK = f"pin --name metrics-httpd --root {ROOT} --consumer {UNIT}"
LIVE = f"systemctl show --property=MainPID --value {UNIT}"


def render_ansible(binary: str, argv: list[str]) -> str:
    """The vendored role template as Ansible's ``template`` module renders it."""

    env = jinja2.Environment(undefined=jinja2.StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
    template = env.from_string(VENDORED.read_text())
    return template.render(metrics_httpd_impl_binary=binary, metrics_httpd_impl_argv=argv)


def run(fields: HttpdSwitchFields, responses: dict[str, Any] | None = None, endpoint: Endpoint = ENDPOINT) -> FakeRun:
    @deploy("Switch")
    def body() -> None:
        switch.verify(switch.select(endpoint, fields))

    return run_deploy_fake(body, responses={**fakehost.LINUX, **(responses or {})})


def argv_of(result: FakeRun, marker: str) -> list[str]:
    (command,) = [c for c in result.executed_commands if marker in c]
    return shlex.split(command)


def ran(result: FakeRun, marker: str) -> bool:
    return any(marker in c for c in result.executed_commands)


# -- vendored template and rules ---------------------------------------------------------


def test_packaged_template_is_the_vendored_role_template() -> None:
    packaged = PACKAGE / "services/_metrics_httpd/templates/metrics-httpd-impl.conf.j2"
    assert packaged.read_bytes() == VENDORED.read_bytes()


@pytest.mark.parametrize(
    "argv",
    [
        ["logyard-health"],
        ["static", "--bind", "127.0.0.1", "--port", "10061", "--root", "/srv/x/site"],
        ["json-file", "--missing-message", "Metrics file not found - collector timer may not have run yet"],
        ["json-file", "--realm", "it's", "--x", "a;b", "--y", "plain"],
    ],
    ids=lambda argv: argv[0] + str(len(argv)),
)
def test_drop_in_is_rendered_as_the_role_renders_it(argv: list[str]) -> None:
    assert switch.render_dropin(BINARY, tuple(argv)) == render_ansible(BINARY, argv)


def test_drop_in_quotes_words_with_spaces_quotes_or_semicolons() -> None:
    rendered = switch.render_dropin(BINARY, ("json-file", "--missing-message", "not found", "--x", "a;b"))

    assert rendered == (
        "# Managed by ops-library metrics_httpd_switch: selects the Rust metrics-httpd.\n"
        "# Remove this file (daemon-reload, restart) to fall back to Python.\n"
        "[Service]\n"
        "ExecStart=\n"
        f'ExecStart={BINARY} json-file --missing-message "not found" --x "a;b"\n'
    )


def test_release_grammar_is_the_vendored_rust_release_decisions() -> None:
    namespace: dict[str, Any] = {}
    exec(  # the vendored ops-library filter (text), as the host script uses it
        (PACKAGE / "helpers/templates/rust_release.py.txt").read_text(), namespace
    )
    assert switch.VERSION_RE.pattern == namespace["VERSION_RE"].pattern
    assert switch.SHA256_RE.pattern == namespace["SHA256_RE"].pattern
    assert switch.CONSUMER_RE.pattern == namespace["CONSUMER_RE"].pattern


def test_rules_reject_what_systemd_would_interpret() -> None:
    assert rules.metrics_httpd_argv_problems(list(ENDPOINT.argv)) == []
    for bad in ("100%", "$HOME", 'a"b', "a\\b", "a\nb", ""):
        assert rules.metrics_httpd_argv_problems(["json-file", "--realm", bad]), bad
    assert rules.metrics_httpd_argv_problems(["json-file", "--check-config"])
    assert rules.metrics_httpd_argv_problems(["serve"])
    assert rules.metrics_httpd_sandbox_problems(["User=root"])


# -- config fields -------------------------------------------------------------------------


def test_python_is_the_default_and_needs_no_release() -> None:
    assert PYTHON.httpd_impl == "python"
    assert HttpdSwitchFields(httpd_rust_version="not a version").httpd_rust_version == "not a version"


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"httpd_impl": "rust"}, "needs httpd_rust_version"),
        ({"httpd_impl": "rust", "httpd_rust_version": "v0.1.0", "httpd_rust_sha256": SHA}, "needs httpd_rust_ver"),
        ({"httpd_impl": "rust", "httpd_rust_version": VERSION}, "needs httpd_rust_sha256"),
        ({"httpd_impl": "rust", "httpd_rust_version": VERSION, "httpd_rust_sha256": SHA.upper()}, "sha256"),
    ],
)
def test_rust_needs_a_release_version_and_sha256(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message) as error:
        thermal.ThermalMonitoringConfig.model_validate({"auth_user": "nyxmon", "secrets": "s.yml", **fields})
    assert "v0.1.0" not in str(error.value)


def test_impl_is_python_or_rust() -> None:
    with pytest.raises(ConfigValidationError, match="httpd_impl"):
        thermal.ThermalMonitoringConfig.model_validate({"auth_user": "nyxmon", "secrets": "s.yml", "httpd_impl": "go"})


# -- select and verify on the fake connector ---------------------------------------------


def test_python_without_a_release_only_checks_the_unit() -> None:
    result = run(PYTHON)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert [op.name for op in result.ops if op.changed] == [verify_op(P, UNIT)]
    (verify,) = result.executed_commands
    assert shlex.split(verify) == [
        *PY.split(),
        *("--unit", UNIT, "--impl", "python", "--python-script", "/usr/local/bin/demo_httpd.py"),
        *("--host", "100.64.0.7", "--port", "9104", "--path", "/.well-known/demo"),
        *("--expect", "unauthorized", "--timeout", "5", "--realm", "demo-metrics"),
        *("--retries", "15", "--delay", "2"),
    ]
    assert dict(result.stdin)[verify] == switch.VERIFY_SCRIPT
    assert result.op(verify_op(P, UNIT)).read_only
    # The pin is removed (none here) and old versions pruned, both planned by probes.
    assert any(f"{PIN_CHECK} --absent --check" in c for c in result.fact_commands)
    assert any("prune --name metrics-httpd" in c and "--check" in c for c in result.fact_commands)


def test_python_with_an_installed_release_validates_and_checks_it_read_only() -> None:
    result = run(PYTHON_PINNED, installed())

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert [op.name for op in result.ops if op.changed] == [
        f"{P}Validate metrics-httpd {VERSION}",
        f"{P}Check the metrics-httpd {VERSION} configuration of {UNIT}",
        verify_op(P, UNIT),
    ]
    assert argv_of(result, "--check-config") == [
        *("systemd-run", "--wait", "--pipe", "--collect", "--quiet"),
        *("--property=User=metrics", "--property=Group=metrics"),
        *("--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict"),
        "--property=ReadOnlyPaths=/var/lib/demo",
        BINARY,
        *ENDPOINT.argv,
        "--check-config",
    ]
    # A validated release is no change: prune runs only when its probe asks for it.
    assert not ran(result, "prune --name")


def test_python_installs_a_new_release_soft_and_prunes_after_it() -> None:
    result = run(PYTHON_PINNED)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == [
        f"{P}Install metrics-httpd {VERSION}",
        f"{P}Prune old metrics-httpd versions",
    ]
    install = argv_of(result, "install --name")
    assert install[-1] == "--soft"
    assert install[install.index("--validate-user") + 1] == "metrics"
    assert ran(result, "--check-config")
    assert not ran(result, DROPIN)
    prune = argv_of(result, "prune --name")
    assert "--protect" not in prune


def test_python_keeps_going_when_the_release_refuses_the_configuration() -> None:
    result = run(PYTHON_PINNED, {**installed(), "--check-config": {"success": False, "stderr": ["bad htpasswd"]}})

    assert result.error is None
    check = result.op(f"{P}Check the metrics-httpd {VERSION} configuration of {UNIT}")
    assert not check.succeeded
    # Ignored, as the role's warning: the unit is still verified on Python.
    assert ran(result, "--impl python")


def test_python_skips_the_check_after_a_failed_soft_install() -> None:
    result = run(PYTHON_PINNED, {"install --name metrics-httpd": {"stdout": ["failed bad archive"]}})

    assert result.succeeded, result.error
    assert not ran(result, "--check-config")
    assert not ran(result, "prune --name")
    assert ran(result, "--impl python")


@pytest.mark.parametrize(
    "fields",
    [
        HttpdSwitchFields(httpd_rust_version="0.1", httpd_rust_sha256=SHA),
        HttpdSwitchFields(httpd_rust_version=VERSION),
        HttpdSwitchFields(httpd_rust_version=VERSION, httpd_rust_sha256="abc"),
    ],
)
def test_python_with_a_malformed_pin_warns_and_installs_nothing(
    fields: HttpdSwitchFields, caplog: pytest.LogCaptureFixture
) -> None:
    result = run(fields)

    assert result.succeeded, result.error
    assert not ran(result, "install --name")
    assert not ran(result, "--check-config")
    assert "release pin is not a version with a 64-hex sha256" in caplog.text


def test_python_with_inputs_rust_would_refuse_warns_and_skips_the_check(caplog: pytest.LogCaptureFixture) -> None:
    endpoint = Endpoint(**{**ENDPOINT.__dict__, "argv": (*ENDPOINT.argv, "--realm", "100%")})
    result = run(PYTHON_PINNED, installed(), endpoint)

    assert result.succeeded, result.error
    assert not ran(result, "--check-config")
    assert "stays on Python, but a switch to Rust would be refused" in caplog.text
    assert "which systemd would interpret" in caplog.text


def test_rust_refuses_inputs_it_cannot_run_before_any_operation() -> None:
    endpoint = Endpoint(**{**ENDPOINT.__dict__, "sandbox": ("User=root",)})
    result = run(RUST, endpoint=endpoint)

    assert isinstance(result.error, DeployError)
    assert "impl rust for demo-endpoint refused, nothing switched" in str(result.error)
    assert "sets User; use validate_user/validate_group" in str(result.error)
    assert result.executed_commands == []


def test_a_unit_name_that_is_no_pin_consumer_is_refused() -> None:
    endpoint = Endpoint(**{**ENDPOINT.__dict__, "service_name": "Demo.Endpoint"})
    result = run(PYTHON, endpoint=endpoint)

    assert isinstance(result.error, DeployError)
    assert "not usable as a pin consumer" in str(result.error)
    assert result.executed_commands == []


def rust_responses(**extra: Any) -> dict[str, Any]:
    return {f"{PIN_CHECK} --version {VERSION} --check": [f"change {ROOT}/.pins/{UNIT}"], **extra}


def test_rust_installs_checks_selects_verifies_pins_and_prunes_in_that_order() -> None:
    result = run(RUST, rust_responses())

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == [
        f"{P}Install metrics-httpd {VERSION}",
        f"{P}Ensure /etc/systemd/system/{UNIT}.service.d",
        f"{P}Select the Rust HTTP server for {UNIT}",
        f"{P}Pin metrics-httpd for {UNIT}",
        f"{P}Prune old metrics-httpd versions",
    ]
    names = [op.name for op in result.ops]
    assert names.index(f"{P}Check the metrics-httpd {VERSION} configuration of {UNIT}") < names.index(
        f"{P}Select the Rust HTTP server for {UNIT}"
    )
    assert names.index(f"{P}Select the Rust HTTP server for {UNIT}") < names.index(verify_op(P, UNIT, "rust"))
    install = argv_of(result, "install --name")
    assert "--soft" not in install
    assert result.upload(DROPIN).decode() == switch.render_dropin(BINARY, ENDPOINT.argv)
    verify = argv_of(result, "--impl rust")
    assert verify[verify.index("--binary") + 1] == BINARY
    assert "--python-script" not in verify
    assert argv_of(result, f"{PIN_CHECK} --version")[-2:] == ["--version", VERSION]
    prune = argv_of(result, "prune --name")
    assert prune[prune.index("--protect") :] == ["--protect", BINARY]


def test_rust_stops_before_the_switch_when_the_release_refuses_the_configuration() -> None:
    result = run(RUST, rust_responses(**{"--check-config": {"success": False, "stderr": ["bad"]}}))

    assert not result.succeeded
    assert DROPIN not in result.uploaded_paths
    assert not ran(result, "--impl rust")
    assert not ran(result, f"{PIN_CHECK} --version")
    assert not ran(result, "prune --name")


def test_rust_stops_before_pinning_when_the_unit_does_not_run_it() -> None:
    result = run(RUST, rust_responses(**{"--impl rust": {"success": False, "stderr": ["does not run"]}}))

    assert not result.succeeded
    assert not ran(result, f"{PIN_CHECK} --version")
    assert not ran(result, "prune --name")


def test_converged_rust_changes_nothing() -> None:
    responses = {
        **installed(),
        **fakehost.file(DROPIN, switch.render_dropin(BINARY, ENDPOINT.argv)),
        **fakehost.directory(f"/etc/systemd/system/{UNIT}.service.d"),
        LIVE: [BINARY],
    }
    result = run(RUST, responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert result.uploaded_paths == []


def test_switch_back_to_python_removes_the_drop_in_unpins_and_protects_the_last_rust_binary() -> None:
    other = f"{ROOT}/0.0.9/metrics-httpd"
    responses = {
        **installed(),
        **fakehost.file(DROPIN, switch.render_dropin(other, ENDPOINT.argv)),
        LIVE: [other],
        f"{PIN_CHECK} --absent --check": [f"change {ROOT}/.pins/{UNIT}"],
    }
    result = run(PYTHON_PINNED, responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == [
        f"{P}Select the Python HTTP server for {UNIT}",
        f"{P}Pin metrics-httpd for {UNIT}",
        f"{P}Prune old metrics-httpd versions",
    ]
    names = [op.name for op in result.ops]
    assert names.index(f"{P}Select the Python HTTP server for {UNIT}") < names.index(f"{P}Validate metrics-httpd 0.1.0")
    assert any(c.startswith("rm -f") and DROPIN in c for c in result.executed_commands)
    assert argv_of(result, f"{PIN_CHECK} --absent")[-1] == "--absent"
    prune = argv_of(result, "prune --name")
    # The binary the drop-in named before this run, once (it is also the live executable).
    assert prune[prune.index("--protect") :] == ["--protect", other]


def test_an_unreadable_live_state_blocks_the_prune() -> None:
    result = run(PYTHON_PINNED, {LIVE: [FAILED]})

    assert result.succeeded, result.error
    assert "--live-state-unknown" in argv_of(result, "prune --name")


@pytest.mark.parametrize(
    ("bind", "allow", "host"),
    [("0.0.0.0", ("any",), "127.0.0.1"), ("::", ("any",), "::1"), ("127.0.0.1", ("localhost",), "127.0.0.1")],
)
def test_the_probe_address(bind: str, allow: tuple[str, ...], host: str) -> None:
    endpoint = Endpoint(**{**ENDPOINT.__dict__, "probe_bind": bind, "ip_address_allow": allow})
    command = shlex.split(switch.verify_command(switch.Selection(endpoint, "python", "", None, None, "", "", False)))  # type: ignore[arg-type]

    assert command[command.index("--host") + 1] == host


@pytest.mark.parametrize(
    ("bind", "allow"), [("100.64.0.7", ("localhost",)), ("localhost", ("any",)), ("10.0.0.1", ("100.64.0.0/10",))]
)
def test_a_probe_the_ip_filter_would_drop_is_skipped(
    bind: str, allow: tuple[str, ...], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO")
    endpoint = Endpoint(**{**ENDPOINT.__dict__, "probe_bind": bind, "ip_address_allow": allow})
    result = run(PYTHON, endpoint=endpoint)

    assert result.succeeded, result.error
    verify = argv_of(result, "--impl python")
    assert "--no-probe" in verify
    assert "--host" not in verify
    assert f"Skipping the HTTP probe of {UNIT}" in caplog.text


def test_the_drop_in_names_the_binary_it_selected() -> None:
    assert switch.before_binary(switch.render_dropin(BINARY, ("static",)).splitlines()) == BINARY
    assert switch.before_binary(["[Service]", "ExecStart=", "ExecStart=/a b", "ExecStart=/c d"]) == "/c"
    assert switch.before_binary(None) == ""
    assert switch.before_binary(["ExecStart="]) == ""


# -- the three ports ----------------------------------------------------------------------

TS = "100.64.0.10"


def thermal_cfg(**changes: Any) -> thermal.ThermalMonitoringConfig:
    return thermal.ThermalMonitoringConfig.model_validate({"auth_user": "nyxmon", "secrets": "s.yml", **changes})


def static_cfg(tmp_path: Path, **changes: Any) -> StaticSiteConfig:
    return StaticSiteConfig(source_path=make_site(tmp_path), traefik_host="static.test.example", **changes)


def service_lines(unit: str) -> list[str]:
    """The ``[Service]`` lines of a unit without identity, command and restart policy."""

    lines: list[str] = []
    section = ""
    for line in unit.splitlines():
        if line.startswith("["):
            section = line
        elif (
            section == "[Service]"
            and "=" in line
            and not line.startswith("#")
            and line.split("=", 1)[0] not in ("Type", "User", "Group", "ExecStart", "Restart", "RestartSec")
        ):
            lines.append(line)
    return lines


def test_thermal_inputs_mirror_its_unit() -> None:
    cfg = thermal_cfg()
    endpoint = thermal.httpd_endpoint(cfg, TS)

    assert endpoint.argv == (
        *("json-file", "--bind", TS, "--port", "9104", "--path", "/.well-known/thermal"),
        *("--json-path", "/var/lib/thermal-metrics/thermal.json"),
        *("--htpasswd-file", "/etc/thermal-metrics-endpoint/htpasswd"),
        *("--realm", "thermal-metrics", "--server-name", "thermal-metrics-httpd/0.1"),
    )
    unit = thermal.render_endpoint_unit(cfg, TS)
    assert "IPAddressAllow=localhost\nIPAddressAllow=100.64.0.0/10\n" in unit
    assert endpoint.ip_address_allow == ("localhost", "100.64.0.0/10")
    assert f"ReadOnlyPaths={cfg.site_path}\n" in unit
    assert (endpoint.user, endpoint.group, endpoint.python_script) == ("metrics", "metrics", str(cfg.server_path))
    assert switch.problems(endpoint) == []


def test_static_site_sandbox_is_its_units_service_lines(tmp_path: Path) -> None:
    cfg = static_cfg(tmp_path, service_name="benchmarks-static", site_path="/srv/benchmarks-static/site")
    endpoint = static_site.httpd_endpoint(cfg)

    assert list(endpoint.sandbox) == service_lines(static_site.render_unit(cfg))
    assert endpoint.argv == (
        "static",
        "--bind",
        "127.0.0.1",
        "--port",
        "10061",
        "--root",
        "/srv/benchmarks-static/site",
    )
    assert (endpoint.probe_expect, endpoint.probe_path, endpoint.ip_address_allow) == ("static", "/", ("any",))
    assert switch.problems(endpoint) == []


def test_logyard_sandbox_is_its_units_environment(tmp_path: Path) -> None:
    cfg = core_config(make_source(tmp_path))
    health = HealthEndpoint(
        selector='{host="macmini",source_type="journald"}', units=({"id": "vector", "unit": "vector.service"},)
    )
    cfg = cfg.model_copy(update={"health": health})
    endpoint = logyard_core.health_httpd_endpoint(cfg, health)

    environment = [line for line in service_lines(logyard_core.render_health_unit(cfg)) if line != "Type=simple"]
    assert list(endpoint.sandbox) == environment
    assert len(environment) == 10
    assert 'Environment="LOGYARD_HEALTH_SELECTOR={host=\\"macmini\\",source_type=\\"journald\\"}"' in environment
    assert endpoint.argv == ("logyard-health",)
    # Loki /ready and two queries (10 s each), systemctl per unit (5 s), 5 s on top.
    assert endpoint.probe_timeout == 10 * 3 + 5 * 1 + 5
    assert (endpoint.user, endpoint.group, endpoint.probe_expect) == ("logyard", "logyard", "logyard-health")
    assert switch.problems(endpoint) == []


def thermal_rust() -> thermal.ThermalMonitoringConfig:
    return thermal_make_cfg(httpd_impl="rust", httpd_rust_version=VERSION, httpd_rust_sha256=SHA)


def test_thermal_switch_to_rust_on_a_converged_host_restarts_only_the_endpoint() -> None:
    cfg = thermal_rust()
    pin = f"pin --name metrics-httpd --root {ROOT} --consumer thermal-metrics-endpoint --version {VERSION} --check"
    result = thermal_run({**thermal_converged(cfg), pin: [f"change {ROOT}/.pins/thermal-metrics-endpoint"]}, cfg)

    unit = "thermal-metrics-endpoint"
    assert result.mutating_changed_ops == [
        f"{THERMAL_P}Install metrics-httpd {VERSION}",
        f"{THERMAL_P}Ensure /etc/systemd/system/{unit}.service.d",
        f"{THERMAL_P}Select the Rust HTTP server for {unit}",
        f"{THERMAL_P}Reload systemd for the thermal metrics units",
        f"{THERMAL_P}Restart {unit}.service",
        f"{THERMAL_P}Pin metrics-httpd for {unit}",
        f"{THERMAL_P}Prune old metrics-httpd versions",
    ]
    dropin = f"/etc/systemd/system/{unit}.service.d/metrics-httpd-impl.conf"
    assert result.upload(dropin).decode() == switch.render_dropin(BINARY, thermal.httpd_endpoint(cfg, THERMAL_TS).argv)
    names = [op.name for op in result.ops]
    assert names.index(f"{THERMAL_P}Restart {unit}.service") < names.index(verify_op(THERMAL_P, unit, "rust"))
    assert names.index(verify_op(THERMAL_P, unit, "rust")) < names.index(f"{THERMAL_P}Pin metrics-httpd for {unit}")
    check = argv_of(result, "--check-config")
    assert check[check.index("--property=User=metrics") : check.index(BINARY)] == [
        *("--property=User=metrics", "--property=Group=metrics", "--property=NoNewPrivileges=yes"),
        *("--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes"),
        "--property=ReadOnlyPaths=/var/lib/thermal-metrics",
    ]


def test_thermal_converged_on_rust_changes_nothing() -> None:
    cfg = thermal_rust()
    unit = "thermal-metrics-endpoint"
    dropin = f"/etc/systemd/system/{unit}.service.d/metrics-httpd-impl.conf"
    responses = {
        **thermal_converged(cfg),
        **installed(),
        **fakehost.directory(f"/etc/systemd/system/{unit}.service.d"),
        **fakehost.file(dropin, switch.render_dropin(BINARY, thermal.httpd_endpoint(cfg, THERMAL_TS).argv)),
    }
    result = thermal_run(responses, cfg)

    assert result.mutating_changed_ops == []
    assert not any("restart" in c for c in result.executed_commands)


def test_static_site_switch_to_rust_reloads_and_restarts_for_the_drop_in(tmp_path: Path) -> None:
    cfg = static_cfg(tmp_path, httpd_impl="rust", httpd_rust_version=VERSION, httpd_rust_sha256=SHA)
    result = static_deploy(cfg, static_converged(cfg))

    prefix = "Deploy static site | "
    assert result.mutating_changed_ops == [
        f"{prefix}Install metrics-httpd {VERSION}",
        f"{prefix}Ensure /etc/systemd/system/static-site.service.d",
        f"{prefix}Select the Rust HTTP server for static-site",
        f"{prefix}Reload systemd for static-site.service",
        f"{prefix}Restart static-site.service",
        f"{prefix}Prune old metrics-httpd versions",
    ]
    dropin = "/etc/systemd/system/static-site.service.d/metrics-httpd-impl.conf"
    assert result.upload(dropin).decode() == switch.render_dropin(BINARY, static_site.httpd_endpoint(cfg).argv)
    names = [op.name for op in result.ops]
    assert names.index(verify_op(prefix, "static-site", "rust")) < names.index(f"{prefix}Check loopback static service")


def test_logyard_switch_to_rust_checks_the_health_endpoint_in_its_environment(tmp_path: Path) -> None:
    base = core_config(make_source(tmp_path))
    health = HealthEndpoint(httpd_impl="rust", httpd_rust_version=VERSION, httpd_rust_sha256=SHA)
    cfg = base.model_copy(update={"health": health})
    result = logyard_deploy(cfg, logyard_converged(cfg))

    unit = "logyard-health-endpoint"
    assert result.mutating_changed_ops == [
        f"{LOGYARD_P}Install metrics-httpd {VERSION}",
        f"{LOGYARD_P}Ensure /etc/systemd/system/{unit}.service.d",
        f"{LOGYARD_P}Select the Rust HTTP server for {unit}",
        f"{LOGYARD_P}Reload systemd for {unit}.service",
        f"{LOGYARD_P}Restart {unit}.service",
        f"{LOGYARD_P}Prune old metrics-httpd versions",
    ]
    environment = [f"--property={line}" for line in logyard_core.health_httpd_endpoint(cfg, health).sandbox]
    assert argv_of(result, "--check-config") == [
        *("systemd-run", "--wait", "--pipe", "--collect", "--quiet"),
        *("--property=User=logyard", "--property=Group=logyard", *environment),
        *(BINARY, "logyard-health", "--check-config"),
    ]
    dropin = f"/etc/systemd/system/{unit}.service.d/metrics-httpd-impl.conf"
    assert result.upload(dropin).decode() == switch.render_dropin(BINARY, ("logyard-health",))
    verify = argv_of(result, "--impl rust")
    assert verify[verify.index("--expect") :][:4] == ["--expect", "logyard-health", "--timeout", "35"]


# -- against ops-library ------------------------------------------------------------------


def golden(role: str) -> str:
    assert OPS_LIBRARY is not None
    return Path(OPS_LIBRARY, "tests/fixtures/metrics_httpd_switch", role, "metrics-httpd-impl.conf").read_text()


@needs_ops_library
def test_drop_ins_are_the_roles_goldens(tmp_path: Path) -> None:
    assert switch.render_dropin(BINARY, thermal.httpd_endpoint(thermal_cfg(), TS).argv) == golden(
        "thermal_metrics_endpoint"
    )
    assert switch.render_dropin(BINARY, static_site.httpd_endpoint(static_cfg(tmp_path)).argv) == golden(
        "static_site_deploy"
    )
    cfg = core_config(make_source(tmp_path))
    assert cfg.health is not None
    assert switch.render_dropin(BINARY, logyard_core.health_httpd_endpoint(cfg, cfg.health).argv) == golden(
        "logyard_deploy"
    )


def role_switch_inputs(role: str, tasks: str, context: dict[str, Any]) -> dict[str, Any]:
    """The ``metrics_httpd_switch_*`` vars a role's switch block sets, rendered with ``context``."""

    assert OPS_LIBRARY is not None
    library = Path(OPS_LIBRARY)
    defaults = yaml.safe_load((library / "roles/metrics_httpd_switch/defaults/main.yml").read_text())
    (block,) = [
        task
        for task in yaml.safe_load((library / "roles" / role / "tasks" / tasks).read_text())
        if "metrics_httpd_switch_impl" in (task.get("vars") or {})
    ]
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["string"] = str

    def render(value: Any) -> Any:
        if isinstance(value, list):
            return [render(item) for item in value]
        if not isinstance(value, str):
            return value
        bare = re.fullmatch(r"\{\{\s*(\w+)\s*\}\}", value.strip())
        if bare and isinstance(context.get(bare.group(1)), list):
            return context[bare.group(1)]
        return env.from_string(value).render(**context)

    names = (
        "argv",
        "unit_sandbox",
        "validate_user",
        "validate_group",
        "service_name",
        "python_script",
        "probe_bind",
        "probe_port",
        "probe_path",
        "probe_expect",
        "probe_realm",
        "probe_timeout",
        "ip_address_allow",
    )
    found = {}
    for name in names:
        key = f"metrics_httpd_switch_{name}"
        found[name] = render(block["vars"].get(key, defaults.get(key)))
    return found


def endpoint_inputs(endpoint: Endpoint) -> dict[str, Any]:
    return {
        "argv": list(endpoint.argv),
        "unit_sandbox": list(endpoint.sandbox),
        "validate_user": endpoint.user,
        "validate_group": endpoint.group,
        "service_name": endpoint.service_name,
        "python_script": endpoint.python_script,
        "probe_bind": endpoint.probe_bind,
        "probe_port": str(endpoint.probe_port),
        "probe_path": endpoint.probe_path,
        "probe_expect": endpoint.probe_expect,
        "probe_realm": endpoint.probe_realm,
        "probe_timeout": str(endpoint.probe_timeout),
        "ip_address_allow": list(endpoint.ip_address_allow),
    }


def normalised(inputs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        key: [str(v) for v in value] if isinstance(value, list) else str(value or "").strip()
        for key, value in inputs.items()
    }
    out["probe_timeout"] = str(int(float(out["probe_timeout"])))
    return out


@needs_ops_library
def test_thermal_inputs_are_the_roles() -> None:
    cfg = thermal_cfg()
    context = {
        **thermal.role_vars(cfg, TS),
        "thermal_metrics_endpoint_impl": "python",
        "thermal_metrics_endpoint_service_name": cfg.service_name,
    }
    role = role_switch_inputs("thermal_metrics_endpoint", "main.yml", context)
    assert normalised(role) == normalised(endpoint_inputs(thermal.httpd_endpoint(cfg, TS)))


@needs_ops_library
def test_static_site_inputs_are_the_roles(tmp_path: Path) -> None:
    cfg = static_cfg(tmp_path, service_name="benchmarks-static", site_path="/srv/benchmarks-static/site")
    context = {
        "static_site_impl": "python",
        "static_site_systemd_unit_name": cfg.service_name,
        "static_site_user": cfg.user,
        "static_site_group": cfg.group_name,
        "static_site_bind_host": cfg.bind_host,
        "static_site_port": cfg.port,
        "static_site_path": str(cfg.site_path),
        "static_site_server_path": str(cfg.server_path),
    }
    role = role_switch_inputs("static_site_deploy", "main.yml", context)
    assert normalised(role) == normalised(endpoint_inputs(static_site.httpd_endpoint(cfg)))


@needs_ops_library
def test_logyard_inputs_are_the_roles(tmp_path: Path) -> None:
    health = HealthEndpoint(units=({"id": "vector", "unit": "vector.service"},))
    cfg = core_config(make_source(tmp_path)).model_copy(update={"health": health})
    endpoint = logyard_core.health_httpd_endpoint(cfg, health)
    variables = logyard_core.role_vars(cfg)
    context = {
        **variables,
        "logyard_health_impl": "python",
        "logyard_health_service_name": health.service_name,
        "logyard_user": cfg.user,
        "logyard_group": cfg.group,
        # The role reads these lines from its rendered unit (set_fact before select).
        "_logyard_health_unit_environment": re.findall(r"(?m)^Environment=.*$", logyard_core.render_health_unit(cfg)),
    }
    role = role_switch_inputs("logyard_deploy", "health_endpoint.yml", context)
    assert normalised(role) == normalised(endpoint_inputs(endpoint))
    # The role reads that fact with the same expression from the same unit template.
    assert OPS_LIBRARY is not None
    tasks = Path(OPS_LIBRARY, "roles/logyard_deploy/tasks/health_endpoint.yml").read_text()
    assert "lookup('ansible.builtin.template', 'logyard-health-endpoint.service.j2')" in tasks
    assert "regex_findall('(?m)^Environment=.*$')" in tasks


# -- files/verify_host.py ----------------------------------------------------------------


class Answer(http.server.BaseHTTPRequestHandler):
    status = 401
    headers_out: ClassVar[dict[str, str]] = {"WWW-Authenticate": 'Basic realm="demo-metrics"'}
    body = b""

    def do_GET(self) -> None:
        self.send_response(self.status)
        for key, value in self.headers_out.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def server() -> Iterator[Callable[..., int]]:
    servers: list[http.server.HTTPServer] = []

    def start(status: int, headers: dict[str, str] | None = None, body: bytes = b"") -> int:
        handler = type("Handler", (Answer,), {"status": status, "headers_out": headers or {}, "body": body})
        httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return int(httpd.server_address[1])

    yield start
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


class FakeHost:
    """A fake ``systemctl`` and ``/proc`` for one unit's main process (pid 4242)."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.proc = base / "proc"
        self.binary = base / "opt/metrics-httpd/0.1.0/metrics-httpd"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text("#!/bin/sh\n")
        self.systemctl = base / "systemctl"
        self.unit("active", "4242")

    def unit(self, state: str, pid: str) -> None:
        self.systemctl.write_text(
            f'#!/bin/sh\ncase "$1" in is-active) echo {state} ;; show) echo {pid} ;; *) exit 1 ;; esac\n'
        )
        self.systemctl.chmod(0o755)

    def process(self, exe: Path | str, *words: str) -> None:
        directory = self.proc / "4242"
        directory.mkdir(parents=True, exist_ok=True)
        if (directory / "exe").is_symlink():
            (directory / "exe").unlink()
        (directory / "exe").symlink_to(exe)
        (directory / "cmdline").write_bytes(b"\0".join(w.encode() for w in words) + b"\0")

    def verify(self, *args: str) -> subprocess.CompletedProcess[str]:
        argv = [sys.executable, "-I", "-", "--unit", "demo", "--systemctl", str(self.systemctl)]
        argv += ["--proc-root", str(self.proc), "--retries", "1", "--delay", "0", *args]
        env = {**os.environ, "HOME": str(self.base)}
        return subprocess.run(
            argv, input=switch.VERIFY_SCRIPT, capture_output=True, text=True, timeout=60, check=False, env=env
        )


@pytest.fixture
def fake(tmp_path: Path) -> FakeHost:
    return FakeHost(tmp_path)


def probe_args(port: int, expect: str = "unauthorized", realm: str = "demo-metrics") -> list[str]:
    args = ["--host", "127.0.0.1", "--port", str(port), "--path", "/x", "--expect", expect, "--timeout", "5"]
    return args + (["--realm", realm] if expect == "unauthorized" else [])


def test_verify_rust_by_its_executable_and_a_401_with_the_realm(fake: FakeHost, server: Callable[..., int]) -> None:
    port = server(401, {"WWW-Authenticate": 'Basic realm="demo-metrics"'})
    fake.process(fake.binary, str(fake.binary), "json-file")

    result = fake.verify("--impl", "rust", "--binary", str(fake.binary), *probe_args(port))

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("ok demo runs impl rust")


def test_verify_rust_accepts_the_resolved_binary(fake: FakeHost) -> None:
    link = fake.base / "opt/current"
    link.symlink_to(fake.binary.parent)
    fake.process(os.path.realpath(fake.binary))

    result = fake.verify("--impl", "rust", "--binary", str(link / "metrics-httpd"), "--no-probe")

    assert result.returncode == 0, result.stderr
    assert "probe skipped" in result.stdout


def test_verify_rust_refuses_another_executable(fake: FakeHost) -> None:
    fake.process("/usr/bin/python3.12", "/usr/bin/python3", "/usr/local/bin/demo.py")

    result = fake.verify("--impl", "rust", "--binary", str(fake.binary), "--no-probe")

    assert result.returncode == 1
    assert "does not run the selected implementation (impl rust" in result.stderr
    assert "exe=/usr/bin/python3.12" in result.stderr


def test_verify_python_by_its_script_word(fake: FakeHost) -> None:
    fake.process("/usr/bin/python3.12", "/usr/bin/python3", "/usr/local/bin/demo.py", "--port", "9104")

    assert fake.verify("--impl", "python", "--python-script", "/usr/local/bin/demo.py", "--no-probe").returncode == 0
    wrong = fake.verify("--impl", "python", "--python-script", "/usr/local/bin/other.py", "--no-probe")
    assert wrong.returncode == 1
    assert "a command line with /usr/local/bin/other.py" in wrong.stderr


@pytest.mark.parametrize(("state", "pid"), [("failed", "4242"), ("active", "0"), ("activating", "")])
def test_verify_needs_an_active_unit_with_a_main_process(fake: FakeHost, state: str, pid: str) -> None:
    fake.process("/usr/bin/python3.12", "/usr/bin/python3", "/usr/local/bin/demo.py")
    fake.unit(state, pid)

    result = fake.verify("--impl", "python", "--python-script", "/usr/local/bin/demo.py", "--no-probe")

    assert result.returncode == 1
    assert f"state={state} pid={pid}" in result.stderr


@pytest.mark.parametrize(
    ("status", "headers", "body", "expect", "ok"),
    [
        (401, {"WWW-Authenticate": 'Basic realm="demo-metrics"'}, b"", "unauthorized", True),
        (401, {"WWW-Authenticate": 'Basic realm="other"'}, b"", "unauthorized", False),
        (401, {}, b"", "unauthorized", False),
        (200, {}, b"{}", "unauthorized", False),
        (200, {}, json.dumps({"status": "ok"}).encode(), "logyard-health", True),
        (200, {}, json.dumps({"loki": {}}).encode(), "logyard-health", False),
        (200, {}, b"[1]", "logyard-health", False),
        (200, {}, b"not json", "logyard-health", False),
        (503, {}, json.dumps({"status": "critical"}).encode(), "logyard-health", False),
        (200, {}, b"<html></html>", "static", True),
        (301, {"Location": "/x/"}, b"", "static", False),
        (404, {}, b"", "static", False),
    ],
)
def test_verify_probe_answers(
    fake: FakeHost,
    server: Callable[..., int],
    status: int,
    headers: dict[str, str],
    body: bytes,
    expect: str,
    ok: bool,
) -> None:
    port = server(status, headers, body)
    fake.process("/usr/bin/python3.12", "/usr/bin/python3", "/usr/local/bin/demo.py")

    result = fake.verify("--impl", "python", "--python-script", "/usr/local/bin/demo.py", *probe_args(port, expect))

    assert result.returncode == (0 if ok else 1), result.stderr
    if not ok:
        assert f"answered status {status}" in result.stderr
        assert "Nothing was pinned or pruned." in result.stderr


def test_verify_reports_an_endpoint_that_does_not_answer(fake: FakeHost, server: Callable[..., int]) -> None:
    port = server(200)
    fake.process("/usr/bin/python3.12", "/usr/bin/python3", "/usr/local/bin/demo.py")

    result = fake.verify("--impl", "python", "--python-script", "/usr/local/bin/demo.py", *probe_args(port + 1))

    assert result.returncode == 1
    assert "ConnectionRefusedError" in result.stderr or "answered" in result.stderr


def test_verify_sends_no_credentials(fake: FakeHost) -> None:
    seen: list[str | None] = []

    class Recorder(Answer):
        def do_GET(self) -> None:
            seen.append(self.headers.get("Authorization"))
            super().do_GET()

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        fake.process("/usr/bin/python3.12", "/usr/bin/python3", "/usr/local/bin/demo.py")
        # A login for every host in the HOME the script runs with: never used.
        (fake.base / ".netrc").write_text("default login user password fixture\n")
        result = fake.verify(
            "--impl", "python", "--python-script", "/usr/local/bin/demo.py", *probe_args(httpd.server_address[1])
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert result.returncode == 0, result.stderr
    assert seen == [None]
