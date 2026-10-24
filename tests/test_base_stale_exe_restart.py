"""``deploy_stale_exe_restart`` against the fake connector, and its rendered files."""

from __future__ import annotations

import base64
import importlib.util
import json
import shlex
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.api import DeployError

from ops_deploy.base import StaleExeRestartConfig, deploy_stale_exe_restart
from ops_deploy.base.stale_exe_restart import (
    APT_HOOK,
    CONFIG_PATH,
    HOST_SCRIPT,
    SCRIPT_PATH,
    render_apt_hook,
    render_config,
    render_service,
    render_timer,
    report_command,
    report_lines,
)
from ops_deploy.helpers.probes import FAILED
from ops_deploy.testing import FakeRun, fish_unsafe, run_deploy_fake
from tests import fakehost
from tests.fakehost import UBUNTU

P = "Stale binary restart | "
SERVICE_PATH = "/etc/systemd/system/stale-exe-restart.service"
TIMER_PATH = "/etc/systemd/system/stale-exe-restart.timer"
NGINX: dict[str, Any] = {
    "unit": "web-nginx.service",
    "binary": "/usr/sbin/nginx",
    "package": "nginx",
    "test": "nginx",
    "expected_argv": ["/usr/sbin/nginx", "-c", "/etc/web/nginx.conf", "-g", "daemon off;"],
    "http_probe": {
        "url": "http://127.0.0.1:10044/health",
        "headers": {"Host": "web.example.org", "X-Forwarded-Proto": "https"},
    },
}
CFG = StaleExeRestartConfig.model_validate({"units": [NGINX]})
PROBE = "report --config-b64"
FRESH = [
    P + "Ensure /usr/local/libexec/ops-deploy",
    P + f"Install {SCRIPT_PATH}",
    P + "Ensure /etc/ops-deploy",
    P + f"Write {CONFIG_PATH}",
    P + "Install systemd unit stale-exe-restart.service",
    P + "Install systemd unit stale-exe-restart.timer",
    P + "Reload systemd for the stale-exe-restart units",
    P + "Enable and start stale-exe-restart.timer",
    P + f"Write {APT_HOOK}",
]
CHECK = P + "Check the installed stale-exe-restart"
CHECK_COMMAND = f"/usr/bin/python3 -I {SCRIPT_PATH} report >/dev/null"


def report(
    *rows: dict[str, Any], others: list[dict[str, Any]] | None = None, skipped: int = 0, unreadable: int = 0
) -> str:
    return json.dumps(
        {
            "schema": 1,
            "mode": "report",
            "result": "ok",
            "attention": [],
            "units": list(rows) or [{"unit": "web-nginx.service", "status": "current"}],
            "report_only": others or [],
            "foreign_namespace_pids": skipped,
            "unreadable_pids": unreadable,
            "attempts": {},
        }
    )


def converged(cfg: StaleExeRestartConfig = CFG, **extra: Any) -> dict[str, Any]:
    return {
        PROBE: [report()],
        **extra,
        **UBUNTU,
        **fakehost.directory("/usr/local/libexec/ops-deploy"),
        **fakehost.file(SCRIPT_PATH, HOST_SCRIPT, mode="-rwxr-xr-x"),
        **fakehost.directory("/etc/ops-deploy"),
        **fakehost.file(CONFIG_PATH, render_config(cfg)),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.file(SERVICE_PATH, render_service()),
        **fakehost.file(TIMER_PATH, render_timer()),
        **fakehost.service("stale-exe-restart.timer"),
        **fakehost.directory("/etc/apt/apt.conf.d"),
        **fakehost.file(APT_HOOK, render_apt_hook()),
    }


def run(responses: dict[str, Any], cfg: StaleExeRestartConfig = CFG, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_stale_exe_restart, cfg, responses=responses)
    assert result.succeeded is ok, result.error
    return result


def never_touches_consumers(result: FakeRun) -> None:
    for command in result.executed_commands:
        assert not command.startswith(("systemctl restart", "systemctl reload", "systemctl stop")), command
        assert "stale-exe-restart.service" not in command or "start" not in command.split(), command


# -- the deploy ------------------------------------------------------------------------------


def test_fresh_host_installs_everything_and_restarts_nothing() -> None:
    result = run({PROBE: [report()], **UBUNTU})

    assert result.mutating_changed_ops == FRESH
    assert result.op(CHECK).read_only
    commands = result.executed_commands
    assert "systemctl daemon-reload" in commands
    assert "systemctl start stale-exe-restart.timer" in commands
    assert "systemctl enable stale-exe-restart.timer" in commands
    assert commands[-1] == CHECK_COMMAND
    never_touches_consumers(result)
    assert set(result.uploaded_paths) == {SCRIPT_PATH, CONFIG_PATH, SERVICE_PATH, TIMER_PATH, APT_HOOK}
    assert result.upload(SCRIPT_PATH).decode() == HOST_SCRIPT
    assert result.upload(CONFIG_PATH).decode() == render_config(CFG)
    assert result.upload(APT_HOOK).decode() == render_apt_hook()
    assert any("chmod 755" in c and SCRIPT_PATH in c for c in commands)
    assert any("chmod 644" in c and CONFIG_PATH in c for c in commands)
    assert any("chown root:root" in c and APT_HOOK in c for c in commands)
    # The hook is written last, after the units and the timer it queues.
    assert result.mutating_changed_ops[-1] == P + f"Write {APT_HOOK}"


def test_converged_host_changes_nothing() -> None:
    result = run(converged())

    assert result.mutating_changed_ops == []
    assert result.executed_commands == [CHECK_COMMAND]


def test_the_plan_runs_the_packaged_program_read_only_on_stdin() -> None:
    result = run(converged())

    facts = [command for command in result.fact_commands if PROBE in command]
    assert len(facts) == 1
    assert report_command(CFG) in facts[0]
    stdin = [text for command, text in result.stdin if PROBE in command]
    assert stdin == [HOST_SCRIPT]
    encoded = shlex.split(report_command(CFG))[5]
    assert base64.b64decode(encoded).decode() == render_config(CFG)
    assert not fish_unsafe(report_command(CFG))


def test_allowlist_change_rewrites_only_the_config() -> None:
    other = StaleExeRestartConfig.model_validate({"units": [{**NGINX, "http_probe": None}]})
    result = run(converged(CFG), other)

    assert result.mutating_changed_ops == [P + f"Write {CONFIG_PATH}"]
    never_touches_consumers(result)


def test_unit_drift_reloads_systemd_without_starting_anything_else() -> None:
    responses = converged()
    responses.update(fakehost.file(SERVICE_PATH, render_service().replace("50min", "10min")))

    result = run(responses)

    assert result.mutating_changed_ops == [
        P + "Install systemd unit stale-exe-restart.service",
        P + "Reload systemd for the stale-exe-restart units",
    ]
    never_touches_consumers(result)


def test_stopped_timer_is_started_and_enabled() -> None:
    responses = converged()
    responses.update(fakehost.service("stale-exe-restart.timer", running=False, enabled=False))

    result = run(responses)

    assert result.mutating_changed_ops == [P + "Enable and start stale-exe-restart.timer"]
    assert result.executed_commands[:2] == [
        "systemctl start stale-exe-restart.timer",
        "systemctl enable stale-exe-restart.timer",
    ]


def test_empty_allowlist_installs_a_report_only_timer() -> None:
    empty = StaleExeRestartConfig()
    result = run({PROBE: [report({"unit": "-", "status": "current"})], **UBUNTU}, empty)

    assert result.mutating_changed_ops == FRESH
    assert json.loads(result.upload(CONFIG_PATH)) == {"schema": 1, "units": []}


@pytest.mark.parametrize(
    "answer",
    [["partial output", "", FAILED], ["not json"], [json.dumps({"units": []})]],
    ids=["probe-failed", "not-json", "incomplete"],
)
def test_a_failed_or_unreadable_report_fails_before_any_change(answer: list[str]) -> None:
    result = run({PROBE: answer, **UBUNTU}, ok=False)

    assert "stale_exe_restart" in str(result.error)
    assert result.executed_commands == []
    assert result.uploaded_paths == []


def test_non_debian_host_is_refused() -> None:
    responses = {**UBUNTU, PROBE: [report()]}
    responses.pop("command -v apt-get")

    result = run(responses, ok=False)

    assert "Debian-family" in str(result.error)
    assert result.executed_commands == []


def test_host_without_systemd_is_refused() -> None:
    result = run({**UBUNTU, PROBE: [report()], "cat /proc/1/comm": ["init"]}, ok=False)

    assert "systemd" in str(result.error)
    assert result.executed_commands == []


# -- report lines ---------------------------------------------------------------------------


def test_report_lines_name_what_the_timer_would_do() -> None:
    answer = report(
        {"unit": "web-nginx.service", "status": "stale", "action": "test_and_restart"},
        {"unit": "api-nginx.service", "status": "current", "ready": True},
        others=[
            {"unit": "mongod.service", "stale_exe": ["/usr/bin/mongod"], "deleted_libs": []},
            {"unit": "ssh.service", "stale_exe": [], "deleted_libs": ["libcrypto.so.3"]},
        ],
        skipped=5,
        unreadable=2,
    )

    assert report_lines(answer) == [
        "web-nginx.service: stale; the next timer run tests and restarts it",
        "api-nginx.service: current",
        "report only (never restarted): 1 unit(s) with a replaced executable (mongod.service), "
        "1 with deleted libraries (ssh.service); 5 process(es) in other mount namespaces (path comparison skipped); "
        "2 process(es) NOT READABLE",
    ]
    assert report_lines(report())[-1].endswith("0 process(es) in other mount namespaces (path comparison skipped)")


@pytest.mark.parametrize(
    "row",
    [
        {"unit": "web-nginx.service", "status": "not_loaded"},
        {"unit": "web-nginx.service", "status": "refused", "reason": "ExecStart is [], not the approved argv"},
        {"unit": "web-nginx.service", "status": "error", "reason": "OSError"},
        {"unit": "web-nginx.service", "status": "current", "ready": False, "reason": "a restart would be refused: x"},
        {"unit": "web-nginx.service", "status": "inactive", "ready": False, "reason": "a restart would be refused: x"},
    ],
    ids=["not-loaded", "refused", "error", "current-unfit", "inactive-unfit"],
)
def test_an_allowlist_that_does_not_fit_fails_before_any_change(row: dict[str, Any]) -> None:
    with pytest.raises(DeployError, match=r"the allowlist does not fit the host: web-nginx\.service: "):
        report_lines(report(row))

    result = run({PROBE: [report(row)], **UBUNTU}, ok=False)
    assert "does not fit the host" in str(result.error)
    assert result.executed_commands == []
    assert result.uploaded_paths == []


def test_a_damaged_state_file_fails_before_any_change() -> None:
    answer = json.loads(report())
    answer["state_error"] = "/var/lib/ops-deploy/stale-exe-restart/state.json is not JSON"

    result = run({PROBE: [json.dumps(answer)], **UBUNTU}, ok=False)

    assert "state.json is not JSON; check it, then repair or remove it" in str(result.error)
    assert result.executed_commands == []


def test_operational_states_do_not_block_the_deploy() -> None:
    for row in (
        {"unit": "web-nginx.service", "status": "stale_no_retry", "reason": "one restart already attempted"},
        {"unit": "web-nginx.service", "status": "inactive", "ready": True},
        {"unit": "web-nginx.service", "status": "stale", "action": "test_and_restart"},
        {"unit": "web-nginx.service", "status": "changing", "reason": "the unit is reloading"},
    ):
        assert report_lines(report(row))[0].startswith("web-nginx.service: ")


# -- rendered files -----------------------------------------------------------------------------


def _host_program() -> Any:
    path = Path(__file__).parents[1] / "src" / "ops_deploy" / "base" / "files" / "stale_exe_restart.py"
    spec = importlib.util.spec_from_file_location("stale_exe_restart_rendered", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rendered_config_is_what_the_host_program_reads() -> None:
    program = _host_program()

    entries = program.parse_config(render_config(CFG))

    assert entries == [{**NGINX, "http_probe": {**NGINX["http_probe"], "status": 200}}]
    assert program.parse_config(render_config(StaleExeRestartConfig())) == []
    assert render_config(CFG).endswith("}\n")


def test_service_runs_the_program_once_without_restart_policy() -> None:
    text = render_service()

    assert "Type=oneshot\n" in text
    assert f"ExecStart=/usr/bin/python3 -I {SCRIPT_PATH} run\n" in text
    assert f"ConditionPathExists={CONFIG_PATH}\n" in text
    assert "StateDirectory=ops-deploy/stale-exe-restart\n" in text
    assert "StartLimitIntervalSec=0\n" in text
    assert "\nRestart=" not in text
    assert "[Install]" not in text


def test_timer_is_hourly_and_persistent() -> None:
    text = render_timer()

    assert "OnCalendar=hourly\n" in text
    assert "Persistent=true\n" in text
    assert "RandomizedDelaySec=5min\n" in text
    assert text.endswith("[Install]\nWantedBy=timers.target\n")


def test_apt_hook_only_queues_the_oneshot_and_never_fails_apt() -> None:
    assert render_apt_hook().splitlines()[-1] == (
        'DPkg::Post-Invoke { "if [ -d /run/systemd/system ] && [ -e /etc/systemd/system/stale-exe-restart.service ]; '
        'then systemctl --no-block start stale-exe-restart.service || true; fi"; };'
    )


# -- config validation ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"unit": "web-nginx"},
        {"unit": "-x.service"},
        {"binary": "/usr/sbin/../sbin/nginx"},
        {"binary": "nginx"},
        {"package": "Nginx"},
        {"test": "apache"},
        {"expected_argv": "/usr/sbin/nginx -c /etc/web/nginx.conf"},
        {"expected_argv": []},
        {"expected_argv": ["/usr/bin/nginx"]},
        {"expected_argv": ["/usr/sbin/nginx", "a\nb"]},
        {"http_probe": {"url": "https://127.0.0.1:443/"}},
        {"http_probe": {"url": "http://192.0.2.1:80/"}},
        {"http_probe": {"url": "http://127.0.0.1/"}},
        {"http_probe": {"url": "http://127.0.0.1:80/ x"}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "status": True}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "status": 600}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "headers": {"Host": "a\r\nX: b"}}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "headers": {"Bad Name": "x"}}},
    ],
)
def test_config_refuses(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        StaleExeRestartConfig.model_validate({"units": [{**NGINX, **change}]})


def test_config_refuses_duplicates_and_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        StaleExeRestartConfig.model_validate({"units": [NGINX, NGINX]})
    with pytest.raises(ValidationError):
        StaleExeRestartConfig.model_validate({"units": [], "restart_everything": True})
