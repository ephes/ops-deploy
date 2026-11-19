"""The Logyard Vector remap, run through ``vector test`` with journald-shaped events.

Covers the level taken from the application's own output (JSON, logfmt,
gunicorn, OpenThread) over journald's PRIORITY, the per-service floors that
keep Loki's own logs and OTBR's chatter out of Loki, and the service label
normalisation (Docker containers, login sessions, transient units). Skipped
where no ``vector`` binary is installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.logyard import vector
from tests.logyard_fixtures import vector_config

VECTOR = shutil.which("vector")


def local_confinement() -> bool:
    """The confinement decision a deploy would make for the local Vector."""

    assert VECTOR is not None
    version = subprocess.run([VECTOR, "--version"], capture_output=True, text=True, timeout=30, check=False).stdout
    return vector.supports_confinement(version, True)


pytestmark = pytest.mark.skipif(VECTOR is None, reason="no vector binary")


def event(message: str, *, unit: str = "", priority: str = "6", identifier: str = "", **fields: str) -> dict[str, str]:
    return {
        "message": message,
        "_SYSTEMD_UNIT": unit,
        "SYSLOG_IDENTIFIER": identifier,
        "PRIORITY": priority,
        **fields,
    }


def kept(name: str, log: dict[str, str], *, level: str, service: str) -> dict[str, Any]:
    check = f"assert_eq!(.level, {json.dumps(level)}); assert_eq!(.service, {json.dumps(service)})"
    return {
        "name": name,
        "inputs": [{"insert_at": "normalize_logs", "type": "log", "log_fields": log}],
        "outputs": [{"extract_from": "normalize_logs", "conditions": [{"type": "vrl", "source": check}]}],
    }


def dropped(name: str, log: dict[str, str]) -> dict[str, Any]:
    return {
        "name": name,
        "inputs": [{"insert_at": "normalize_logs", "type": "log", "log_fields": log}],
        "no_outputs_from": ["normalize_logs"],
    }


def loki(message: str) -> dict[str, str]:
    return event(
        message,
        unit="docker.service",
        priority="3",
        identifier="logyard-loki",
        CONTAINER_NAME="logyard-loki",
    )


def otbr(message: str) -> dict[str, str]:
    return event(message, unit="otbr-agent.service", identifier="otbr-agent")


CASES: list[dict[str, Any]] = [
    # Loki's own logs: Docker's journald driver files stderr as PRIORITY 3.
    dropped("loki info query log", loki('level=info ts=2026-11-19T10:57:15Z caller=metrics.go:409 msg="x"')),
    dropped("loki debug", loki("level=debug ts=2026-11-19T10:57:15Z msg=y")),
    kept("loki warning", loki("level=warn ts=2026-11-19T10:57:15Z msg=z"), level="warning", service="logyard-loki"),
    kept("loki error", loki("level=error ts=2026-11-19T10:57:15Z msg=z"), level="error", service="logyard-loki"),
    kept(
        "dockerd itself stays docker",
        event("Container failed to exit", unit="docker.service", priority="4", identifier="dockerd"),
        level="warning",
        service="docker",
    ),
    kept(
        "another container under journald",
        event(
            "plain output",
            unit="docker.service",
            priority="3",
            identifier="web-1",
            CONTAINER_NAME="web-1",
        ),
        level="error",
        service="web-1",
    ),
    # JSON bodies.
    kept(
        "rustfs json ERROR on stdout",
        event('{"timestamp":"x","level":"ERROR","message":"Replication failed"}', unit="rustfs.service"),
        level="error",
        service="rustfs",
    ),
    kept(
        "json WARN",
        event('{"level":"WARN","message":"slow"}', unit="rustfs.service"),
        level="warning",
        service="rustfs",
    ),
    kept(
        "json severity",
        event('{"severity":"critical","msg":"x"}', unit="app.service"),
        level="critical",
        service="app",
    ),
    kept(
        "pino numeric error",
        event('{"level":50,"msg":"x"}', unit="mastodon-streaming.service"),
        level="error",
        service="mastodon-streaming",
    ),
    kept(
        "pino numeric info on stderr",
        event('{"level":30,"msg":"x"}', unit="mastodon-streaming.service", priority="3"),
        level="info",
        service="mastodon-streaming",
    ),
    kept(
        "json without a level keeps PRIORITY",
        event('{"msg":"x"}', unit="app.service", priority="4"),
        level="warning",
        service="app",
    ),
    kept(
        "broken json keeps PRIORITY",
        event("{not json", unit="app.service", priority="3"),
        level="error",
        service="app",
    ),
    # logfmt bodies.
    kept(
        "gotosocial logfmt ERROR",
        event('timestamp="19/11/2026 11:57:34.246" func=x level=ERROR method=GET', unit="gotosocial.service"),
        level="error",
        service="gotosocial",
    ),
    kept(
        "logfmt quoted level",
        event('ts=1 level="warning" msg=x', unit="app.service", priority="3"),
        level="warning",
        service="app",
    ),
    kept(
        "unknown level word keeps PRIORITY",
        event("battery level=low now", unit="upower.service", priority="4"),
        level="warning",
        service="upower",
    ),
    kept(
        "level= inside a word is not logfmt",
        event("loglevel=debug requested", unit="app.service", priority="3"),
        level="error",
        service="app",
    ),
    # gunicorn.
    kept(
        "gunicorn ERROR on stdout",
        event("[2026-11-19 05:15:13 +0100] [353435] [ERROR] Control server error", unit="homepage.service"),
        level="error",
        service="homepage",
    ),
    kept(
        "gunicorn INFO on stderr",
        event("[2026-11-19 05:15:13 +0100] [353435] [INFO] Booting worker", unit="homepage.service", priority="3"),
        level="info",
        service="homepage",
    ),
    # OpenThread.
    dropped("otbr info", otbr("2d.16:49:00.639 [I] DataPollHandlr: Rx data poll, src:0x2003")),
    dropped("otbr debug", otbr("2d.16:49:00.639 [D] Mle-----------: x")),
    kept(
        "otbr note",
        otbr("2d.16:49:00.639 [N] Mle-----------: Role child -> router"),
        level="notice",
        service="otbr-agent",
    ),
    kept(
        "otbr warning",
        otbr("2d.16:49:00.639 [W] Mac-----------: Frame tx failed"),
        level="warning",
        service="otbr-agent",
    ),
    kept("otbr critical", otbr("2d.16:49:00.639 [C] Platform------: x"), level="critical", service="otbr-agent"),
    kept(
        "otbr plain syslog line keeps PRIORITY",
        event("Thread is up", unit="otbr-agent.service", identifier="otbr-agent", priority="5"),
        level="notice",
        service="otbr-agent",
    ),
    kept(
        "bracket letter elsewhere is not OpenThread",
        event("2d.16:49:00.639 [I] something", unit="other.service", identifier="other", priority="3"),
        level="error",
        service="other",
    ),
    # Review counterexamples: prefix formats before logfmt, top-level keys only.
    kept(
        "otbr warning mentioning level=info",
        otbr("2d.16:49:00.639 [W] Settings-----: stored level=info"),
        level="warning",
        service="otbr-agent",
    ),
    kept(
        "quoted msg does not hide the top-level level",
        event('ts=1 msg="retry with level=info" level=error', unit="app.service"),
        level="error",
        service="app",
    ),
    kept(
        "quoted msg alone does not set the level",
        event('ts=1 msg="level=error in text"', unit="app.service", priority="5"),
        level="notice",
        service="app",
    ),
    kept(
        "gunicorn line mentioning level=debug",
        event("[2026-11-19 05:15:13 +0100] [1] [ERROR] bad level=debug", unit="homepage.service"),
        level="error",
        service="homepage",
    ),
    kept(
        "indented json",
        event('  {"level":"ERROR","msg":"x"}', unit="app.service"),
        level="error",
        service="app",
    ),
    kept(
        "unknown json level falls back to severity",
        event('{"level":"unclassified","severity":"error"}', unit="app.service"),
        level="error",
        service="app",
    ),
    kept(
        "non-pino number keeps PRIORITY",
        event('{"level":3,"msg":"x"}', unit="app.service", priority="3"),
        level="error",
        service="app",
    ),
    kept(
        "container names are kept verbatim",
        event("x", unit="docker.service", priority="3", identifier="api", CONTAINER_NAME="api.service"),
        level="error",
        service="api.service",
    ),
    kept(
        "container named like a transient unit",
        event("x", unit="docker.service", priority="3", identifier="r", CONTAINER_NAME="run-u1"),
        level="error",
        service="run-u1",
    ),
    kept(
        "ordinary run- unit keeps its name", event("x", unit="run-backup.service"), level="info", service="run-backup"
    ),
    kept(
        "tab-separated logfmt keeps quoted text quoted",
        loki('ts=1\tmsg="retry with level=debug later"\tcaller=x'),
        level="error",
        service="logyard-loki",
    ),
    kept(
        "logfmt key with @",
        event("@timestamp=2026-11-19T10:57:15Z level=error msg=hello", unit="app.service"),
        level="error",
        service="app",
    ),
    kept(
        "hex-looking ordinary unit keeps its name", event("x", unit="run-red.service"), level="info", service="run-red"
    ),
    kept("systemd 257 transient unit", event("x", unit="run-p935-i12345.service"), level="info", service="run"),
    kept("logind c-session", event("x", unit="session-c1.scope"), level="info", service="session"),
    # PRIORITY fallback and service names.
    kept("plain stderr line", event("boom", unit="app.service", priority="3"), level="error", service="app"),
    kept("plain notice", event("hello", unit="app.service", priority="5"), level="notice", service="app"),
    kept("login session", event("x", unit="session-5072.scope", priority="6"), level="info", service="session"),
    kept("transient run unit", event("x", unit="run-u19023.service", priority="6"), level="info", service="run"),
    kept(
        "transient run scope",
        event("x", unit="run-r0f3a9c0d1e2f3a4b5c6d7e8f9a0b1c2d.scope", priority="6"),
        level="info",
        service="run",
    ),
    kept(
        "user manager keeps its name",
        event("x", unit="user@1000.service", priority="6"),
        level="info",
        service="user@1000",
    ),
    kept(
        "sessionless name keeps it", event("x", unit="session-cleanup.service"), level="info", service="session-cleanup"
    ),
    kept("identifier when no unit", event("x", identifier="kernel", priority="4"), level="warning", service="kernel"),
]


def run_vector_test(tmp_path: Path, fragment: str, cases: list[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
    config = tmp_path / "logyard.yaml"
    config.write_text(fragment)
    tests = tmp_path / "tests.yaml"
    tests.write_text(json.dumps({"tests": cases}))
    assert VECTOR is not None
    return subprocess.run(
        [VECTOR, "test", str(config), str(tests)], capture_output=True, text=True, timeout=120, check=False
    )


def test_remap_levels_floors_and_service_names(tmp_path: Path) -> None:
    result = run_vector_test(tmp_path, vector.render_fragment(vector_config(), local_confinement()), CASES)

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert output.count("... passed") == len(CASES), output


def test_floors_follow_the_configuration(tmp_path: Path) -> None:
    cfg = vector_config(min_levels={"app": "error", "mnt-team\\x2ddata": "warning"})
    cases = [
        kept("loki info is shipped without its floor", loki("level=info msg=x"), level="info", service="logyard-loki"),
        kept(
            "otbr info is shipped without its floor",
            otbr("1d.00:00:00.000 [I] x: y"),
            level="info",
            service="otbr-agent",
        ),
        dropped("app warning below its floor", event("careful", unit="app.service", priority="4")),
        kept("app error at its floor", event("boom", unit="app.service", priority="3"), level="error", service="app"),
        dropped("escaped unit name floor", event("x", unit="mnt-team\\x2ddata.mount", priority="6")),
    ]

    result = run_vector_test(tmp_path, vector.render_fragment(cfg, local_confinement()), cases)

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert output.count("... passed") == len(cases), output


def test_min_levels_reject_unknown_levels_and_label_values() -> None:
    with pytest.raises(ValueError, match="literal_error"):
        vector_config(min_levels={"app": "verbose"})
    with pytest.raises(ValueError, match="string_pattern_mismatch"):
        vector_config(min_levels={'app"} ; abort': "info"})
