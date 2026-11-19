"""obs_daily: config, rendered files, evidence pack, status endpoint, hand-over point and the deploy plan."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.services.obs_daily import (
    ObsDailyConfig,
    deploy_obs_daily,
    render_config,
    render_pack_service,
    render_pack_timer,
    render_status_service,
)
from ops_deploy.services.obs_daily import deploy as od
from ops_deploy.testing import FakeRun, fish_unsafe, run_deploy_fake
from tests import fakehost

FILES = Path(od.__file__).parent / "files"
SENDER = FILES / "obs_daily_send.py"
NOW = 1_795_000_000.0  # 2026-11-18 11:06:40 UTC
DAY = 86400
NS = 1_000_000_000


def cfg(**changes: Any) -> ObsDailyConfig:
    return ObsDailyConfig.model_validate(
        {"sleeping_hosts": ["atlas"], "tls_hosts": ["example.org", "mail.example.org:993"], **changes}
    )


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, FILES / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _ctl_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctl, "LOCK", str(tmp_path / "ctl.lock"))
    monkeypatch.setattr(ctl, "LAUNCHD_LOCK", str(tmp_path / "launchd.lock"))


pack = load("obs_pack")
status_mod = load("obs_status")
ctl = load("obs_ctl")


# -- config ----------------------------------------------------------------------------------------


def test_defaults() -> None:
    config = cfg()

    assert (config.pack_unit, config.status_unit, config.user, str(config.site_path)) == (
        "obs-daily-pack",
        "obs-daily-status",
        "nyxmon",
        "/var/lib/obs-daily",
    )
    assert config.loki_exclude_lines == ('"syslog_identifier":"logyard-loki"',)
    assert config.status_url == "http://127.0.0.1:9123/.well-known/obs-daily"
    assert config.on_calendar == "*-*-* 06:30:00"
    assert config.ctl_command("pack") == (
        "/usr/bin/python3 -I /usr/local/lib/obs-daily/obs_ctl.py --config /etc/obs-daily/config.json pack"
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"sleeping_hosts": ["a", "a"]}, "distinct"),
        ({"tls_hosts": ["bad host"]}, "tls_hosts"),
        ({"status_listen": "0.0.0.0:9123"}, "status_listen"),
        ({"loki_url": "http://loki.example:3100"}, "loki_url"),
        ({"backfill_days": 10, "signature_retention_days": 10}, "backfill_days"),
        ({"loki_exclude_lines": ["a\nb"]}, "loki_exclude_lines"),
        ({"lib_dir": "/var/lib/obs-daily/bin"}, "must not overlap"),
        ({"config_dir": "//etc/obs-daily"}, "single slash"),
        ({"config_dir": "/home/nyxmon/site/conf"}, "must not overlap"),
    ],
)
def test_bad_configs_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises((ConfigValidationError, ValueError), match=message):
        cfg(**changes)


def test_the_rendered_config_is_what_all_three_scripts_load(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(render_config(cfg()))

    config = pack.load_config(str(path))

    assert config["state_dir"] == "/var/lib/obs-daily"
    assert config["influx"]["token_file"] == "/etc/obs-daily/influx-token"
    assert config["nyxmon_db"] == "/home/nyxmon/site/db.sqlite3"
    assert config["sender"] == {
        "user": "nyxmon",
        "python": "/home/nyxmon/site/.venv/bin/python",
        "script": "/usr/local/lib/obs-daily/obs_daily_send.py",
        "env_file": "/home/nyxmon/site/.env",
        "cwd": "/home/nyxmon/site",
    }
    assert {"status_listen", "loop_window_seconds", "loop_events", "cache_seconds"} <= set(config)


def test_the_units_run_as_nyxmon_read_only_except_the_state() -> None:
    service = render_pack_service(cfg()).splitlines()
    for line in (
        "Type=oneshot",
        "User=nyxmon",
        "UMask=0027",
        "ExecStart=/usr/bin/python3 -I /usr/local/lib/obs-daily/obs_pack.py --config /etc/obs-daily/config.json",
        "TimeoutStartSec=3600",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=/var/lib/obs-daily",
        "NoNewPrivileges=yes",
    ):
        assert line in service
    assert not any(line.startswith("Restart=") for line in service)
    timer = render_pack_timer(cfg(on_calendar="Mon *-*-* 06:00:00")).splitlines()
    assert "OnCalendar=Mon *-*-* 06:00:00" in timer
    assert "Persistent=true" in timer
    endpoint = render_status_service(cfg()).splitlines()
    assert (
        "ExecStart=/usr/bin/python3 -I /usr/local/lib/obs-daily/obs_status.py --config /etc/obs-daily/config.json"
        in endpoint
    )
    assert "ProtectSystem=strict" in endpoint
    assert not any(line.startswith("ReadWritePaths") for line in endpoint)


def test_commands_shipped_as_arguments_are_fish_safe() -> None:
    assert "\\" not in od.TOKEN_SCRIPT
    for command in (od.token_command(cfg(), "check"), od.sender_check_command(cfg()), od.status_probe_command(cfg())):
        assert not fish_unsafe(command), command
    assert od.token_command(cfg(), "check").endswith(
        "check http://127.0.0.1:8086 graphyard graphyard graphyard-influxdb /etc/obs-daily/influx-token nyxmon "
        "'obs-daily read-only /etc/obs-daily/influx-token'"
    )


# -- templates -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "template"),
    [
        (
            "Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2",
            "Failed password for <id> user <id> from <ip> port # ssh#",
        ),
        ("mail for someone@example.org bounced", "mail for <email> bounced"),
        ("delivery to someone@example.org failed", "delivery to <email> failed"),
        ("login token=abc123def password: hunter2 done", "login <id> password: <redacted> done"),
        ("cannot open /srv/data/x-17.json: No such file", "cannot open <path>: No such file"),
        ("GET https://peer.example/api/v1/x?id=7 failed", "GET <url> failed"),
        ("10.0.0.1 - - [18/Nov/2026 14:09:20] Request timed out", "<ip> - - [<time>] Request timed out"),
        ("Time jumped backwards, rotating.", "Time jumped backwards, rotating."),
        (
            '{"timestamp":"2026-11-18T10:00:00Z","level":"ERROR","event":"replication_failed","bucket":"b",'
            '"object":"x/y.json","error":"Access Denied"}',
            "timestamp=<v> level=ERROR event=replication_failed bucket=b object=<v> error=Access Denied",
        ),
        (
            "level=ERROR method=GET url=https://x.example/a attempt=3 requestID=7e9ya1g msg=boom",
            "level=ERROR method=GET url=<v> attempt=<v> requestID=<v> msg=boom",
        ),
        ("worker 9f86d081884c7d659a2feaa0c55ad015 died", "worker <hex> died"),
        ("Payment from customer Erika Mustermann failed", "Payment from <id> Erika Mustermann failed"),
        ("Authorization: Bearer abc.def.ghi rejected", "Authorization: <redacted> <redacted> rejected"),
        ("api key ab12cd34ef56gh78ij90kl12 invalid", "api key <hex> invalid"),
        ("AccessDenied: Access Denied", "AccessDenied: Access Denied"),
        ('{"msg":"login failed","password":"correct horse battery"}', "msg=login <id> password=<redacted>"),
        ('password="correct horse battery" rejected', "password=<redacted> rejected"),
        ("Cookie: sid=abc; theme=dark; other=1", "Cookie: <redacted>"),
        ("api_key='correct horse battery' sent", "api_key=<v> sent"),
        ("credential=hunter2 used", "credential=<redacted> used"),
        ('password="ab\\"cd ef" rejected', "password=<redacted> rejected"),
        ("Cookie: sid=abc;\n theme=secretvalue", "Cookie: <redacted>"),
    ],
)
def test_templates_mask_what_varies_and_what_identifies(line: str, template: str) -> None:
    assert pack.mask(line) == template


def test_templates_never_carry_addresses_or_mail() -> None:
    text = pack.mask("user bob@example.org from 2001:db8::1 and 192.0.2.4:8080 at 2026-11-18T10:00:00.123Z")
    for leak in ("bob", "example.org", "2001", "192.0.2.4", "10:00"):
        assert leak not in text


# -- the pack against stub APIs --------------------------------------------------------------------


class Loki:
    """Answers by query substring; records every call."""

    def __init__(self) -> None:
        self.volume: dict[float, dict[str, dict[str, float]]] = {}  # end -> host -> service -> count
        self.problem: dict[str, list[tuple[float, str]]] = {}  # host -> [(epoch, raw line)]
        self.restarts: dict[str, list[tuple[float, str]]] = {}
        self.untrusted: dict[str, dict[str, float]] = {}
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, path: str, params: dict[str, str]) -> Any:
        self.calls.append((path, params))
        query = params.get("query", "")
        assert (
            "!= " + json.dumps('"syslog_identifier":"logyard-loki"') in query
            or path.startswith("label")
            or ("[1h]" in query)
        )
        if path.startswith("label/host"):
            return sorted({*self.problem, *self.restarts, *(h for d in self.volume.values() for h in d)})
        host = query.split('host="')[1].split('"')[0] if 'host="' in query else None
        if path == "query" and query.startswith("sum by (host)"):
            hosts = sorted({*self.problem, *self.restarts, *(h for d in self.volume.values() for h in d)})
            return {"result": [{"metric": {"host": h}, "value": [0, "5"]} for h in hosts]}
        if path == "query" and "[1h]" in query:
            return {"result": [{"metric": {}, "value": [0, "5"]}]}
        if path == "query":
            end = int(params["time"]) / NS
            if 'or unit = ""' in query:  # lines without a systemd unit (or not JSON at all)
                services = self.untrusted.get(host or "", {}) if end == NOW else {}
                return {"result": [{"metric": {"service": k}, "value": [0, str(c)]} for k, c in services.items()]}
            services = self.volume.get(end, {}).get(host or "", {})
            return {
                "result": [{"metric": {"service": s, "unit": s}, "value": [0, str(c)]} for s, c in services.items()]
            }
        start, end = int(params["start"]) / NS, int(params["end"]) / NS
        source = self.restarts if "Scheduled restart" in query else self.problem
        hosts = [host] if host else list(source)
        return {
            "result": [
                {
                    "stream": {"host": h, "service": "svc"},
                    "values": [[str(int(t * NS)), raw] for t, raw in lines if start <= t < end],
                }
                for h in hosts
                for lines in [source.get(h, [])]
            ]
        }


def journald(message: str, identifier: str = "app", pid: str = "77", unit: str = "app.service") -> str:
    # Compact, as Vector writes the line.
    fields = {"message": message, "syslog_identifier": identifier, "host": "h", "pid": pid, "unit": unit}
    return json.dumps(fields, separators=(",", ":"))


def pid1(message: str) -> str:
    return journald(message, "systemd", "1", "init.scope")


def context(tmp_path: Path, loki: Any, flux: Callable[[str], list[dict[str, str]]] | None = None) -> Any:
    config = json.loads(render_config(cfg(backfill_days=2)))
    config["state_dir"] = str(tmp_path)
    config["nyxmon_db"] = ""
    config["tls_hosts"] = []
    return pack.Context(config=config, now=NOW, loki=loki, flux=flux or (lambda q: []), state_dir=str(tmp_path))


def test_volume_reports_changed_appeared_and_vanished_services(tmp_path: Path) -> None:
    loki = Loki()
    for day in range(8):
        services = {"steady": 1000.0, "gone": 200.0, "loud": 1000.0}
        if day == 0:
            services = {"steady": 1000.0, "loud": 9000.0, "fresh": 40.0, "session-12": 5.0}
        loki.volume[NOW - day * DAY] = {"web": services}
    ctx = context(tmp_path, loki)

    section = pack.section_volume(ctx, ["web"])

    assert section["changed"] == [
        {"host": "web", "service": "loud", "lines_24h": 9000, "median_7d": 1000, "factor": 9.0}
    ]
    assert section["appeared"] == [{"host": "web", "service": "fresh", "lines_24h": 40}]
    assert section["vanished"] == [{"host": "web", "service": "gone", "median_7d": 200}]
    assert section["hosts"] == [{"host": "web", "lines_24h": 10045, "median_7d": 2200}]
    selector = next(p["query"] for path, p in loki.calls if path == "query" and "sum by (service)" in p["query"])
    assert 'service!~"(session|run-u)-?[0-9].*"' in selector


def test_signatures_fill_the_baseline_then_report_only_new_and_surging_templates(tmp_path: Path) -> None:
    loki = Loki()
    old = [(NOW - 2 * DAY + 60 + i, journald(f"disk {i} is slow")) for i in range(3)]
    old += [(NOW - DAY - 3000, journald("cache miss for key 1 timeout"))]
    today = [(NOW - 100 - i, journald(f"disk {i} is slow")) for i in range(2)]
    today += [(NOW - 200 - i, journald(f"cache miss for key {i} timeout")) for i in range(60)]
    today += [(NOW - 300 - i, journald(f"brand new failure in worker {i}")) for i in range(4)]
    today += [(NOW - 400, journald("rare failure once"))]
    loki.problem = {"web": old + today}
    ctx = context(tmp_path, loki)

    section = pack.section_signatures(ctx, ["web"])

    assert section["baseline_days"] == 2
    assert [(e["template"], e["count"]) for e in section["new"]] == [("brand new failure in worker #", 4)]
    assert [(e["template"], e["count"]) for e in section["surging"]] == [("cache miss for <id> # timeout", 60)]
    assert "signature baseline filled from 2 earlier days" in ctx.notes[0]
    stored = json.loads((tmp_path / "signatures.json").read_text())
    assert len(stored["covered_days"]) == 3
    assert stored["schema"] == 2

    again = pack.section_signatures(context(tmp_path, loki), ["web"])

    assert [(e["template"], e["count"]) for e in again["new"]] == [("brand new failure in worker #", 4)]
    assert [(e["template"], e["count"]) for e in again["surging"]] == [("cache miss for <id> # timeout", 60)]
    assert json.loads((tmp_path / "signatures.json").read_text())["covered_days"] == stored["covered_days"]


def test_a_window_at_the_line_limit_is_split(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pack, "PROBLEM_LINES", 4)
    monkeypatch.setattr(pack, "MAX_SPLIT", 3)
    loki = Loki()
    loki.problem = {"web": [(NOW - 6 * 3600 + i * 600, journald("boom failed")) for i in range(30)]}
    ctx = context(tmp_path, loki)

    found = pack.problem_lines(ctx, "web", NOW - 6 * 3600, NOW)

    assert len(found) >= 16
    assert any("limit reached" in note for note in ctx.notes)


def test_unit_restarts_skip_transient_units(tmp_path: Path) -> None:
    loki = Loki()
    loki.restarts = {
        "web": [(NOW - 10 - i, pid1("api.service: Scheduled restart job, restart counter is at 3.")) for i in range(3)]
        + [(NOW - 50, pid1("api.service: Start request repeated too quickly."))]
        + [(NOW - 60, pid1("run-u77.service: Failed with result 'exit-code'."))]
    }

    found = pack.section_unit_restarts(context(tmp_path, loki), ["web"])

    assert found == [{"host": "web", "unit": "api.service", "restart": 3, "gave_up": 1}]


def flux_rows(query: str) -> list[dict[str, str]]:
    def row(metric: str, value: float, when: float, **tags: str) -> dict[str, str]:
        return {"host": tags.pop("host", "web"), "metric": metric, "_value": str(value), "_time": iso(when), **tags}

    def iso(epoch: float) -> str:
        return str(pack.iso(epoch))

    if "|> last()" in query:
        return [
            row("host.load1", 2.0, NOW - 60),
            row("host.filesystem_used_ratio", 0.9, NOW - 60, mountpoint="/data"),
            row("host.filesystem_used_ratio", 0.5, NOW - 60, mountpoint="/private/tmp/x"),
            row("host.temperature_celsius", 50.0, NOW - 5 * 3600, sensor_label="cpu"),
            row("host.network_receive_bytes_total", 1.0, NOW - 9 * 3600, device="veth12"),
            row("host.load1", 1.0, NOW - 5 * 3600, host="atlas"),
            row("host.memory_used_bytes", 1.0, NOW - 60, host="new"),
        ]
    if "|> first()" in query:
        return [
            row("host.load1", 2.0, NOW - 14 * DAY),
            row("host.memory_used_bytes", 1.0, NOW - 3600, host="new"),
        ]
    if "aggregateWindow" in query:
        fn = "max" if "fn: max" in query else "mean"
        base = {"mean": 2.0, "max": 4.0}[fn]
        rows = [row("host.load1", base + 0.1 * (i % 3), NOW - (i + 2) * DAY) for i in range(10)]
        rows += [
            row("host.filesystem_used_ratio", 0.8 + 0.01 * (9 - i), NOW - (i + 2) * DAY, mountpoint="/data")
            for i in range(10)
        ]
        return rows
    if "|> mean()" in query:
        return [row("host.load1", 2.1, NOW), row("host.filesystem_used_ratio", 0.9, NOW, mountpoint="/data")]
    if "|> max()" in query:
        return [row("host.load1", 40.0, NOW)]
    raise AssertionError(query)


def test_metrics_report_deviations_silent_and_new_series_and_filling_disks(tmp_path: Path) -> None:
    section = pack.section_metrics(context(tmp_path, Loki(), flux_rows))

    assert [(d["series"], d["stat"]) for d in section["deviations"]] == [("web host.load1", "max")]
    assert section["silent"] == [
        {"host": "web", "subject": "{sensor_label=cpu}", "metrics": ["host.temperature_celsius"], "silent_hours": 5}
    ]
    assert section["appeared"] == ["new host.memory_used_bytes"]
    assert section["filesystems"] == [
        {"series": "web host.filesystem_used_ratio {mountpoint=/data}", "used": 0.9, "days_to_full": 11}
    ]


def test_robust_deviation_ignores_flat_noise_but_sees_a_jump() -> None:
    z_noise, _ = pack.robust_deviation(100.4, [100.0] * 10)
    z_jump, relative = pack.robust_deviation(400.0, [100.0, 101.0, 99.0, 100.0, 102.0, 98.0, 100.0])
    assert abs(z_noise) < 1
    assert z_jump > 50
    assert relative == 3.0


def test_a_broken_section_is_an_error_not_a_crash(tmp_path: Path) -> None:
    def broken(path: str, params: dict[str, str]) -> Any:
        raise RuntimeError("unreachable: refused")

    def broken_flux(query: str) -> list[dict[str, str]]:
        raise RuntimeError("InfluxDB reported a query error")

    result = pack.build_pack(context(tmp_path, broken, broken_flux))

    assert result["logs"] == {}
    assert result["metrics"] is None
    assert any(e.startswith("log hosts: RuntimeError") for e in result["errors"])
    assert any(e.startswith("metrics: RuntimeError") for e in result["errors"])


def test_main_writes_pack_latest_and_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = json.loads(render_config(cfg()))
    config.update({"state_dir": str(tmp_path), "nyxmon_db": "", "tls_hosts": []})
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    monkeypatch.setattr(pack, "loki_client", lambda base: Loki())
    monkeypatch.setattr(pack, "flux_client", lambda *a: lambda q: [])
    (tmp_path / "packs").mkdir()
    (tmp_path / "packs/2026-01-01.json").write_text("{}")

    assert pack.main(["--config", str(path), "--now", str(NOW)]) == 0

    latest = json.loads((tmp_path / "packs/latest.json").read_text())
    assert latest["date"] == pack.day_of(NOW)
    assert (tmp_path / f"packs/{latest['date']}.json").exists()
    assert not (tmp_path / "packs/2026-01-01.json").exists()
    assert json.loads((tmp_path / "status.json").read_text())["pack_epoch"] == int(NOW)


def test_a_bad_config_exits_2(tmp_path: Path) -> None:
    (tmp_path / "c.json").write_text("{}")
    assert pack.main(["--config", str(tmp_path / "c.json")]) == 2


def test_nyxmon_section_lists_checks_whose_last_result_is_not_ok(tmp_path: Path) -> None:
    import sqlite3

    db = sqlite3.connect(tmp_path / "db.sqlite3")
    db.executescript(
        "create table service (id integer primary key, name text);"
        "create table health_check (id integer primary key, name text, service_id int, disabled bool);"
        "create table check_result (id integer primary key, status text, health_check_id int);"
        "insert into service values (1, 'svc');"
        "insert into health_check values (1, 'good', 1, 0), (2, 'bad', 1, 0), (3, 'off', 1, 1);"
        "insert into check_result values (1, 'error', 1), (2, 'ok', 1), (3, 'warning', 2), (4, 'error', 3);"
    )
    db.commit()
    db.close()
    ctx = context(tmp_path, Loki())
    ctx.config["nyxmon_db"] = str(tmp_path / "db.sqlite3")

    assert pack.section_nyxmon(ctx) == [{"service": "svc", "check": "bad", "status": "warning"}]


# -- the status endpoint ---------------------------------------------------------------------------


def status_config(tmp_path: Path) -> dict[str, Any]:
    config: dict[str, Any] = json.loads(render_config(cfg()))
    config.update({"state_dir": str(tmp_path), "status_listen": "127.0.0.1:0"})
    return config


def test_unit_loops_need_enough_events_or_systemd_giving_up(tmp_path: Path) -> None:
    loki = Loki()
    restart = "a.service: Scheduled restart job, restart counter is at 9."
    loki.restarts = {
        "web": [(NOW - 10 - i, pid1(restart)) for i in range(5)]
        + [(NOW - 20 - i, pid1("b.service: Failed with result 'exit-code'.")) for i in range(4)]
        + [(NOW - 30, pid1("c.service: Start request repeated too quickly."))]
        + [(NOW - 40 - i, pid1("session-4.scope: Failed with result 'x'.")) for i in range(9)],
        "db": [(NOW - 5000, pid1(restart)) for _ in range(9)],
    }

    config = status_config(tmp_path)
    config["log_hosts"] = ["db", "web"]
    result = status_mod.unit_loops(config, NOW, loki)

    assert result["count"] == 2
    assert [(e["host"], e["unit"]) for e in result["loops"]] == [("web", "a.service"), ("web", "c.service")]


def test_unit_loops_are_not_ok_without_full_host_coverage(tmp_path: Path) -> None:
    class Partial(Loki):
        def __call__(self, path: str, params: dict[str, str]) -> Any:
            if path == "query" and params["query"].startswith("sum by (host)"):
                hosts = ["atlas", "db", "web"] if "[86400s]" in params["query"] else ["web"]
                return {"result": [{"metric": {"host": h}, "value": [0, "3"]} for h in hosts]}
            return super().__call__(path, params)

    status = status_mod.Status(status_config(tmp_path))
    status.loki = Partial()
    status.refresh(NOW)
    section = status.document(NOW)["unit_loops"]
    assert (section["ok"], section["missing_hosts"]) == (False, ["db"])  # atlas sleeps by design

    class Empty(Loki):
        def __call__(self, path: str, params: dict[str, str]) -> Any:
            if path == "query" and params["query"].startswith("sum by (host)"):
                return {"result": []}
            return super().__call__(path, params)

    status.loki = Empty()
    status.refresh(NOW)
    assert status.document(NOW)["unit_loops"]["ok"] is False


def test_long_unit_names_are_counted_apart(tmp_path: Path) -> None:
    loki = Loki()
    names = [f"{'x' * 50}-{i}.service" for i in range(5)]
    loki.restarts = {
        "web": [(NOW - 10 - i, pid1(f"{name}: Failed with result 'exit-code'.")) for i, name in enumerate(names)]
    }

    assert status_mod.unit_loops(status_config(tmp_path), NOW, loki)["count"] == 0
    units = pack.section_unit_restarts(context(tmp_path, loki), ["web"])
    assert len(units) == 5
    assert sorted(u["unit"] for u in units) == sorted(names)
    assert all(u["failed"] == 1 for u in units)


def test_the_endpoint_reports_ages_and_never_for_missing_files(tmp_path: Path) -> None:
    config = status_config(tmp_path)
    (tmp_path / "status.json").write_text(
        json.dumps({"pack_date": "2026-11-18", "pack_epoch": NOW - 100, "pack_errors": 0})
    )
    status = status_mod.Status(config)
    status.loki = Loki()
    status.loki.restarts = {"web": []}

    assert status.document(NOW)["unit_loops"]["ok"] is False  # not checked yet
    status.refresh(NOW)
    document = status.document(NOW + 5)

    assert document["pack"] == {"date": "2026-11-18", "errors": 0, "age_seconds": 105}
    assert document["triage"]["age_seconds"] == status_mod.NEVER
    assert document["unit_loops"]["ok"] is True
    assert document["unit_loops"]["age_seconds"] == 5
    assert status.document(NOW + 3600)["unit_loops"]["ok"] is False  # stale

    def down(path: str, params: dict[str, str]) -> Any:
        raise RuntimeError("unreachable")

    status.loki = down
    status.refresh(NOW)
    assert status.document(NOW)["unit_loops"]["ok"] is False


def test_only_systemds_own_lines_count_as_restarts(tmp_path: Path) -> None:
    loki = Loki()
    quoted = "a.service: Scheduled restart job, restart counter is at 9."
    # An application may set SYSLOG_IDENTIFIER=systemd; journald's _PID and _SYSTEMD_UNIT it cannot fake.
    loki.restarts = {"web": [(NOW - 10 - i, journald(quoted, "systemd")) for i in range(9)]}

    assert status_mod.unit_loops(status_config(tmp_path), NOW, loki)["count"] == 0
    assert pack.section_unit_restarts(context(tmp_path, loki), ["web"]) == []


@pytest.fixture
def server(tmp_path: Path) -> Iterator[str]:
    from http.server import ThreadingHTTPServer

    status = status_mod.Status(status_config(tmp_path))
    status.loki = Loki()
    status.refresh(NOW)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), status_mod.handler(status))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_the_endpoint_serves_only_its_path(server: str) -> None:
    with urllib.request.urlopen(f"{server}/.well-known/obs-daily", timeout=5) as response:
        assert {"pack", "triage", "unit_loops"} <= set(json.load(response))
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(f"{server}/other", timeout=5)


# -- the hand-over point ---------------------------------------------------------------------------


def ctl_config(tmp_path: Path) -> Path:
    config = json.loads(render_config(cfg()))
    config["state_dir"] = str(tmp_path)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path


def test_pack_prints_the_latest_pack_or_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = ctl_config(tmp_path)
    assert ctl.main(["--config", str(path), "pack"]) == 3
    (tmp_path / "packs").mkdir()
    (tmp_path / "packs/latest.json").write_text('{"date": "2026-11-18"}')
    assert ctl.main(["--config", str(path), "pack"]) == 0
    assert '"2026-11-18"' in capsys.readouterr().out


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("[]", "not an object"),
        ('{"date": "18.11.", "status": "ok"}', "YYYY-MM-DD"),
        ('{"date": "2026-11-18", "status": "maybe"}', "status"),
        ('{"date": "2026-11-18", "status": "ok", "ran_at": 1, "new_items": "x"}', "new_items"),
    ],
)
def test_unusable_triage_results_are_refused(raw: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ctl.parse_result(raw)


def test_deliver_sends_the_message_and_records_freshness_only_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []
    outcome = {"ok": True}

    def fake_send(config: dict[str, Any], message: str) -> tuple[bool, str]:
        sent.append(message)
        return (True, "delivered") if outcome["ok"] else (False, "sender exit 1: refused")

    monkeypatch.setattr(ctl, "send", fake_send)
    config = json.loads(ctl_config(tmp_path).read_text())
    result = {
        "date": "2026-11-18",
        "status": "ok",
        "ran_at": NOW,
        "message": "Neu: x" + "y" * 5000,
        "new_items": [{"slug": "a"}],
    }

    assert ctl.deliver(config, json.dumps(result), NOW) == 0

    assert len(sent[0]) <= ctl.MAX_MESSAGE
    triage = json.loads((tmp_path / "triage.json").read_text())
    assert (triage["epoch"], triage["delivered"], triage["new_items"]) == (int(NOW), True, 1)
    archived = list((tmp_path / "triage").glob("2026-11-18-*.json"))
    assert len(archived) == 1
    assert json.loads(archived[0].read_text())["status"] == "ok"
    assert oct(os.stat(tmp_path / "triage.json").st_mode)[-3:] == "640"

    outcome["ok"] = False
    assert ctl.deliver(config, json.dumps(result), NOW + 100) == 1
    triage = json.loads((tmp_path / "triage.json").read_text())
    assert (triage["epoch"], triage["delivered"]) == (int(NOW), False)

    outcome["ok"] = True
    quiet = {"date": "2026-11-19", "status": "ok", "ran_at": NOW, "message": "", "new_items": []}
    assert ctl.deliver(config, json.dumps(quiet), NOW + 200) == 0
    assert len(sent) == 2  # no queue here: the caller sends a refused digest again
    assert json.loads((tmp_path / "triage.json").read_text())["epoch"] == int(NOW + 200)


def test_send_runs_the_sender_as_nyxmon_through_systemd_run(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs["input"] == "hallo"
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(ctl.subprocess, "run", fake_run)
    config = json.loads(render_config(cfg()))

    assert ctl.send(config, "hallo") == (True, "delivered")
    assert calls[0][:5] == ["systemd-run", "--quiet", "--wait", "--pipe", "--collect"]
    assert "--uid=nyxmon" in calls[0]
    assert calls[0][-5:] == [
        "/home/nyxmon/site/.venv/bin/python",
        "-I",
        "/usr/local/lib/obs-daily/obs_daily_send.py",
        "--env-file",
        "/home/nyxmon/site/.env",
    ]
    assert not any("EnvironmentFile" in arg for arg in calls[0])


# -- the sender ------------------------------------------------------------------------------------


def test_the_sender_needs_nyxmon() -> None:
    done = subprocess.run([sys.executable, "-I", str(SENDER), "--check"], capture_output=True, text=True, check=False)
    assert done.returncode == 2
    assert "not importable: nyxmon" in done.stderr


def test_the_sender_uses_nyxmons_notifier(tmp_path: Path) -> None:
    package = tmp_path / "nyxmon/adapters"
    package.mkdir(parents=True)
    (tmp_path / "nyxmon/__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    (package / "notification.py").write_text(
        "import json, os\n"
        "class AsyncTelegramNotifier:\n"
        "    def __init__(self):\n"
        "        self.token, self.chat_id = os.environ.get('T'), 'chat'\n"
        "    @staticmethod\n"
        "    def escape_markdown_v2(text):\n"
        "        return text.replace('.', '\\\\.')\n"
        "    async def async_send(self, text, high_priority=False):\n"
        f"        open({str(tmp_path / 'out.json')!r}, 'w').write(json.dumps([text, high_priority]))\n"
        "        return os.environ.get('RESULT') == 'ok'\n"
    )

    def send(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SENDER), *args],
            input="a.b",
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(tmp_path), **env},
            check=False,
        )

    assert send("--check").returncode == 2
    assert send("--check", T="x").stdout.strip() == "obs-daily-send: notifier ready"
    assert send("--high", T="x", RESULT="ok").returncode == 0
    assert json.loads((tmp_path / "out.json").read_text()) == ["a\\.b", True]
    assert send(T="x", RESULT="no").returncode == 1
    (tmp_path / "env").write_text("# nyxmon\nexport T='from-file'\nOTHER=1\n")
    assert send("--env-file", str(tmp_path / "env"), "--check").returncode == 0
    assert send("--env-file", str(tmp_path / "missing"), "--check").returncode == 2


# -- the deploy ------------------------------------------------------------------------------------

P = "Observability routine: daily evidence pack and status endpoint | "
UNITS = "/etc/systemd/system"
LIB = "/usr/local/lib/obs-daily"


def converged(config: ObsDailyConfig, token: str = "present") -> dict[str, Any]:
    return {
        **fakehost.UBUNTU,
        "check http://127.0.0.1:8086": [token],
        "/.well-known/obs-daily": ["sections ok"],
        "while True:": ["trusted"],
        **fakehost.directory(LIB),
        **fakehost.directory(UNITS),
        **fakehost.stat("/etc/obs-daily", group="nyxmon", mode="drwxr-x---"),
        **fakehost.stat("/var/lib/obs-daily", user="nyxmon", group="adm", mode="drwxr-s---"),
        **fakehost.file(f"{LIB}/obs_pack.py", od.PACK_SCRIPT),
        **fakehost.file(f"{LIB}/obs_status.py", od.STATUS_SCRIPT),
        **fakehost.file(f"{LIB}/obs_ctl.py", od.CTL_SCRIPT),
        **fakehost.file(f"{LIB}/obs_daily_send.py", od.SEND_SCRIPT),
        **fakehost.file("/etc/obs-daily/config.json", render_config(config)),
        **fakehost.file(f"{UNITS}/obs-daily-pack.service", render_pack_service(config)),
        **fakehost.file(f"{UNITS}/obs-daily-pack.timer", render_pack_timer(config)),
        **fakehost.file(f"{UNITS}/obs-daily-status.service", render_status_service(config)),
        **fakehost.service("obs-daily-pack.timer"),
        **fakehost.service("obs-daily-status.service"),
    }


def run(responses: dict[str, Any], config: ObsDailyConfig) -> FakeRun:
    result = run_deploy_fake(deploy_obs_daily, config, None, responses=responses)
    assert result.succeeded, result.error
    return result


def test_a_converged_host_changes_nothing_and_runs_nothing() -> None:
    config = cfg()

    result = run(converged(config), config)

    assert result.mutating_changed_ops == []
    assert not any("ensure http" in c or "obs_pack.py --config" in c for c in result.executed_commands)
    assert any(
        "systemd-run" in c and "obs_daily_send.py --env-file /home/nyxmon/site/.env --check" in c
        for c in result.executed_commands
    )
    assert not any("EnvironmentFile" in c for c in result.executed_commands)
    assert all(not fish_unsafe(c) for c in result.executed_commands)


def test_a_fresh_host_installs_everything_and_makes_the_token() -> None:
    config = cfg()

    result = run(
        {
            **fakehost.UBUNTU,
            "check http://127.0.0.1:8086": ["missing"],
            "/.well-known/obs-daily": ["sections ok"],
            "while True:": ["trusted"],
        },
        config,
    )

    assert result.mutating_changed_ops == [
        f"{P}Ensure {LIB}",
        f"{P}Ensure /etc/obs-daily",
        f"{P}Ensure /var/lib/obs-daily",
        f"{P}Install {LIB}/obs_pack.py",
        f"{P}Install {LIB}/obs_status.py",
        f"{P}Install {LIB}/obs_ctl.py",
        f"{P}Install {LIB}/obs_daily_send.py",
        f"{P}Install /etc/obs-daily/config.json",
        f"{P}Create the read-only InfluxDB token",
        f"{P}Install systemd unit obs-daily-pack.service",
        f"{P}Install systemd unit obs-daily-pack.timer",
        f"{P}Reload systemd for obs-daily-pack.timer",
        f"{P}Enable obs-daily-pack.timer",
        f"{P}Start obs-daily-pack.timer",
        f"{P}Install systemd unit obs-daily-status.service",
        f"{P}Reload systemd for obs-daily-status.service",
        f"{P}Enable obs-daily-status.service",
        f"{P}Start obs-daily-status.service",
    ]
    assert not any("obs_pack.py --config" in c for c in result.executed_commands)


def test_a_changed_config_restarts_the_endpoint_but_not_the_timer() -> None:
    config = cfg(loop_events=7)

    result = run(converged(cfg()), config)

    assert result.mutating_changed_ops == [
        f"{P}Install /etc/obs-daily/config.json",
        f"{P}Restart obs-daily-status.service",
    ]


def test_a_changed_calendar_restarts_only_the_timer() -> None:
    config = cfg(on_calendar="*-*-* 05:00:00")

    result = run(converged(cfg()), config)

    assert result.mutating_changed_ops == [
        f"{P}Install systemd unit obs-daily-pack.timer",
        f"{P}Reload systemd for obs-daily-pack.timer",
        f"{P}Restart obs-daily-pack.timer",
    ]


def test_a_missing_nyxmon_stops_the_deploy() -> None:
    result = run_deploy_fake(
        deploy_obs_daily, cfg(), None, responses={"id -u nyxmon": {"success": False}, **converged(cfg())}
    )

    assert not result.succeeded


def test_a_silent_endpoint_fails_the_deploy() -> None:
    result = run_deploy_fake(
        deploy_obs_daily, cfg(), None, responses={**converged(cfg()), "/.well-known/obs-daily": {"success": False}}
    )

    assert not result.succeeded


def test_launchd_reports_are_kept_with_their_arrival_time(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    report = {
        "host": "studio",
        "checked": 3,
        "loops": [{"label": "x.y", "runs_since_last_sample": 9, "last_exit": "1"}],
    }

    assert ctl.launchd_report(config, json.dumps(report), NOW) == 0

    kept = json.loads((tmp_path / "launchd.json").read_text())
    assert kept == {
        "host": "studio",
        "checked": 3,
        "errors": 0,
        "loops": [{"label": "x.y", "runs": 9, "last_exit": "1", "state": "", "last_seen": int(NOW)}],
        "epoch": int(NOW),
    }
    assert ctl.launchd_report(config, '{"host": "bad host", "loops": []}', NOW) == 2
    assert ctl.launchd_report(config, '{"host": "studio"}', NOW) == 2
    assert ctl.launchd_report(config, '{"host": "studio", "checked": 0, "loops": []}', NOW) == 2

    status = status_mod.Status(status_config(tmp_path))
    status.loki = Loki()
    section = status.document(NOW + 60)["launchd"]
    assert (section["count"], section["age_seconds"], section["host"]) == (1, 60, "studio")


def test_tls_checks_configured_hosts_and_every_https_host_nyxmon_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlite3

    db = sqlite3.connect(tmp_path / "db.sqlite3")
    db.executescript(
        "create table health_check (id integer primary key, url text, data text, disabled bool);"
        "insert into health_check values (1, 'https://a.example/x', '{}', 0), (2, 'http://127.0.0.1:1/', '{}', 0),"
        " (3, 'https://b.example:8443/', '{}', 0), (4, 'https://off.example/', '{}', 1);"
    )
    db.commit()
    db.close()
    days = {"a.example": 40.0, "b.example": 5.0, "c.example": 90.0}

    def fake_days(host: str, port: int, now: float) -> float:
        if host not in days:
            raise OSError("refused")
        return days[host]

    monkeypatch.setattr(pack, "certificate_days", fake_days)
    ctx = context(tmp_path, Loki())
    ctx.config.update(nyxmon_db=str(tmp_path / "db.sqlite3"), tls_hosts=["c.example", "d.example:993"])

    section = pack.section_tls(ctx)

    assert section["checked"] == 4
    assert section["findings"] == [
        {"host": "b.example:8443", "days_left": 5.0},
        {"host": "d.example:993", "error": "OSError: refused"},
    ]


def test_deliver_never_follows_or_overwrites_a_planted_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctl, "send", lambda config, message: (True, "delivered"))
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    state = tmp_path / "state"
    state.mkdir()
    (state / "triage.json").symlink_to(outside)
    config = json.loads(render_config(cfg()))
    config["state_dir"] = str(state)

    assert ctl.deliver(config, json.dumps({"date": "2026-11-18", "status": "ok", "ran_at": NOW}), NOW) == 1

    assert outside.read_text() == "keep"
    assert (state / "triage.json").is_symlink()  # refused, neither followed nor replaced
    assert not list(state.glob(".obs-ctl-*"))


def test_silent_host_check_ignores_lokis_own_lines(tmp_path: Path) -> None:
    loki = Loki()
    ctx = context(tmp_path, loki)
    pack.section_volume(ctx, ["web"])
    silence = [p["query"] for path, p in loki.calls if path == "query" and "[1h]" in p["query"]]
    assert silence
    assert all('!= "\\"syslog_identifier\\":\\"logyard-loki\\""' in q for q in silence)


def test_the_transient_filter_is_anchored() -> None:
    import re

    transient = re.compile(pack.TRANSIENT_LINES)
    assert transient.search(pid1("run-u77.service: Failed with result 'exit-code'."))
    assert not transient.search(pid1("backup-session-4.service: Failed with result 'exit-code'."))


def test_expired_days_do_not_count_as_baseline(tmp_path: Path) -> None:
    key = pack.signature_key("web", "app", "boom failed")
    old_day = pack.day_of(NOW - 40 * DAY)
    store = {"schema": 2, "signatures": {key: {"days": {old_day: 9}}}, "covered_days": [old_day]}
    (tmp_path / "signatures.json").write_text(json.dumps(store))
    loki = Loki()
    loki.problem = {"web": [(NOW - 100 - i, journald("boom failed")) for i in range(5)]}

    first = pack.section_signatures(context(tmp_path, loki), ["web"])
    again = pack.section_signatures(context(tmp_path, loki), ["web"])

    assert [e["template"] for e in first["new"]] == ["boom failed"]
    assert [e["template"] for e in again["new"]] == ["boom failed"]


def test_a_configured_log_host_stays_missing_however_long_it_is_silent(tmp_path: Path) -> None:
    config = status_config(tmp_path)
    config["log_hosts"] = ["gone", "web"]
    loki = Loki()
    loki.restarts = {"web": []}

    result = status_mod.unit_loops(config, NOW, loki)

    assert result["missing_hosts"] == ["gone"]


def test_failures_that_render_alike_stay_separate_findings(tmp_path: Path) -> None:
    loki = Loki()
    loki.problem = {
        "a": [(NOW - 100 - i, journald("OpenSSL handshake failed")) for i in range(4)],
        "b": [(NOW - 100 - i, journald("Redis handshake failed")) for i in range(4)],
    }

    section = pack.section_signatures(context(tmp_path, loki), ["a", "b"])

    assert [(e["template"], e["hosts"], e["count"]) for e in section["new"]] == [
        ("OpenSSL handshake failed", ["a"], 4),
        ("Redis handshake failed", ["b"], 4),
    ]
    assert section["new_total"] == 2


def test_caller_named_services_are_marked_as_such(tmp_path: Path) -> None:
    loki = Loki()
    for day in range(8):
        loki.volume[NOW - day * DAY] = {"web": {"steady": 1000.0}}
    loki.untrusted = {"web": {"alice": 40.0}}
    loki.problem = {"web": [(NOW - 10 - i, json.dumps({"message": "boom failed", "unit": ""})) for i in range(4)]}

    volume = pack.section_volume(context(tmp_path, loki), ["web"])
    signatures = pack.section_signatures(context(tmp_path, loki), ["web"])

    assert volume["appeared"] == [{"host": "web", "service": "ident:alice", "lines_24h": 40}]
    assert signatures["new"][0]["source"] == "ident:svc"


def test_a_busy_lock_sends_nothing_and_exits_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import fcntl

    monkeypatch.setattr(ctl, "LOCK_WAIT", 0)
    config = json.loads(ctl_config(tmp_path).read_text())
    holder = os.open(ctl.LOCK, os.O_RDWR | os.O_CREAT)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        assert (
            ctl.deliver(config, json.dumps({"date": "2026-11-18", "status": "ok", "ran_at": NOW, "message": "x"}), NOW)
            == 3
        )
    finally:
        os.close(holder)
    assert not (tmp_path / "triage.json").exists()


def test_masking_long_words_is_bounded() -> None:
    import time as clock

    started = clock.monotonic()
    for _ in range(50):
        pack.mask("x" * 8000 + " failed")
    assert clock.monotonic() - started < 2


def test_only_a_triage_that_ran_refreshes_its_freshness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctl, "send", lambda config, message: (True, "delivered"))
    config = json.loads(ctl_config(tmp_path).read_text())
    ok = {"date": "2026-11-18", "status": "ok", "ran_at": NOW, "message": ""}
    skipped = {"date": "2026-11-19", "status": "skipped", "message": "übersprungen"}

    assert ctl.deliver(config, json.dumps(ok), NOW) == 0
    assert ctl.deliver(config, json.dumps(skipped), NOW + DAY) == 0

    triage = json.loads((tmp_path / "triage.json").read_text())
    assert (triage["epoch"], triage["ok_epoch"]) == (int(NOW + DAY), int(NOW))
    status = status_mod.Status(status_config(tmp_path))
    section = status.document(NOW + DAY + 10)["triage"]
    assert (section["age_seconds"], section["delivery_age_seconds"]) == (DAY + 10, 10)


def test_pack_hosts_and_notes_keep_their_real_names(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pack, "PROBLEM_LINES", 2)
    loki = Loki()
    loki.problem = {"odd host": [(NOW - 100 - i, journald("boom failed")) for i in range(9)]}
    ctx = context(tmp_path, loki)
    ctx.config["log_hosts"] = ["web"]

    result = pack.build_pack(ctx)

    assert result["log_hosts"] == ["odd host", "web"]
    assert any(note.startswith("odd host: 2-line limit") for note in result["notes"])


def test_a_replayed_old_result_does_not_refresh_the_triage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctl, "send", lambda config, message: (True, "delivered"))
    config = json.loads(ctl_config(tmp_path).read_text())
    assert ctl.deliver(config, json.dumps({"date": "2026-11-18", "status": "ok", "ran_at": NOW}), NOW) == 0
    old = {"date": "2026-11-14", "status": "ok", "ran_at": NOW - 4 * DAY}
    assert ctl.deliver(config, json.dumps(old), NOW + 60) == 0
    assert json.loads((tmp_path / "triage.json").read_text())["ok_epoch"] == int(NOW)
    with pytest.raises(ValueError, match="ran_at"):
        ctl.parse_result('{"date": "2026-11-18", "status": "ok"}')


def test_a_launchd_loop_is_held_for_nyxmons_polling(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    loop = {"host": "studio", "checked": 3, "loops": [{"label": "x", "runs_since_last_sample": 9, "last_exit": "1"}]}
    clean = {"host": "studio", "checked": 3, "loops": []}

    assert ctl.launchd_report(config, json.dumps(loop), NOW) == 0
    assert ctl.launchd_report(config, json.dumps(clean), NOW + 600) == 0
    assert len(json.loads((tmp_path / "launchd.json").read_text())["loops"]) == 1
    assert ctl.launchd_report(config, json.dumps(clean), NOW + ctl.LOOP_HOLD + 1) == 0
    assert json.loads((tmp_path / "launchd.json").read_text())["loops"] == []


def test_a_fifo_in_the_state_directory_does_not_hang_a_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(ctl.Unreadable):
        ctl.read_as("nobody", str(tmp_path / "fifo"))
    assert ctl.read_as("nobody", str(tmp_path / "missing")) == {}
    os.mkfifo(tmp_path / "triage.json")
    config = json.loads(ctl_config(tmp_path).read_text())
    monkeypatch.setattr(ctl, "send", lambda config, message: (True, "delivered"))
    assert ctl.deliver(config, json.dumps({"date": "2026-11-18", "status": "skipped", "message": "x"}), NOW) == 1
    with pytest.raises(ctl.Unreadable):
        ctl._read_regular(str(tmp_path / "fifo"))


def test_untrusted_target_paths_stop_the_deploy_while_planning() -> None:
    result = run_deploy_fake(
        deploy_obs_daily, cfg(), None, responses={**converged(cfg()), "while True:": ["untrusted: /usr/local/lib"]}
    )

    assert not result.succeeded
    assert "not root-only" in str(result.error)


def test_each_launchd_loop_is_held_on_its_own(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())

    def report(*labels: str) -> str:
        loops = [{"label": label, "runs_since_last_sample": 9, "last_exit": "1"} for label in labels]
        return json.dumps({"host": "studio", "checked": 3, "loops": loops})

    assert ctl.launchd_report(config, report("a"), NOW) == 0
    assert ctl.launchd_report(config, report("b"), NOW + 600) == 0
    kept = json.loads((tmp_path / "launchd.json").read_text())
    assert [loop["label"] for loop in kept["loops"]] == ["a", "b"]


def test_the_pack_is_read_without_following_links(tmp_path: Path) -> None:
    (tmp_path / "secret.txt").write_text("raw log line")
    (tmp_path / "packs").mkdir()
    (tmp_path / "packs/latest.json").symlink_to(tmp_path / "secret.txt")
    assert ctl.read_pack(str(tmp_path)) is None
    (tmp_path / "packs/latest.json").unlink()
    (tmp_path / "packs/latest.json").write_text('{"date": "x"}')
    assert ctl.read_pack(str(tmp_path)) == b'{"date": "x"}'


def test_the_endpoint_ignores_a_fifo_state_file(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "status.json")
    assert status_mod._read(str(tmp_path / "status.json")) == {}


def test_future_run_times_are_refused(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    future = {"date": "2026-11-18", "status": "ok", "ran_at": NOW + DAY}
    assert ctl.deliver(config, json.dumps(future), NOW) == 2
    assert not (tmp_path / "triage.json").exists()


def test_the_trusted_path_check_refuses_a_linked_state_directory(tmp_path: Path) -> None:
    import shlex
    import subprocess as sp

    (tmp_path / "real").mkdir()
    (tmp_path / "state").symlink_to(tmp_path / "real")
    argv = shlex.split(od.trusted_paths_command(cfg(site_path=str(tmp_path / "state"))))
    out = sp.run([*argv[:4], "/usr/bin/env", "--", str(tmp_path / "state")], capture_output=True, text=True)
    assert "untrusted" in out.stdout
    assert str(tmp_path / "state") in out.stdout


def test_series_that_render_alike_are_calculated_apart(tmp_path: Path) -> None:
    def rows(query: str) -> list[dict[str, str]]:
        def row(value: float, when: float, source: str) -> dict[str, str]:
            return {"host": "web", "metric": "host.filesystem_used_ratio", "mountpoint": "/data",
                    "source_instance": source, "_value": str(value), "_time": pack.iso(when)}  # fmt: skip

        if "|> last()" in query or "|> first()" in query:
            return [row(0.92, NOW - 60, "a"), row(0.51, NOW - 60, "b")]
        return []

    section = pack.section_metrics(context(tmp_path, Loki(), rows))

    assert [d["used"] for d in section["filesystems"]] == [0.92]


def test_a_host_without_pid1_lines_is_not_covered(tmp_path: Path) -> None:
    class NoInit(Loki):
        def __call__(self, path: str, params: dict[str, str]) -> Any:
            if path == "query" and 'service="init"' in params.get("query", "") and "sum by (host)" in params["query"]:
                return {"result": []}
            return super().__call__(path, params)

    loki = NoInit()
    loki.restarts = {"web": []}
    result = status_mod.unit_loops(status_config(tmp_path), NOW, loki)
    assert result["no_pid1_hosts"] == ["web"]


def test_held_launchd_loops_expire_in_the_endpoint_too(tmp_path: Path) -> None:
    report = {
        "host": "studio",
        "checked": 3,
        "epoch": int(NOW),
        "loops": [{"label": "x", "last_seen": int(NOW - 1790)}],
    }
    (tmp_path / "launchd.json").write_text(json.dumps(report))
    status = status_mod.Status(status_config(tmp_path))
    assert status.document(NOW)["launchd"]["count"] == 1
    assert status.document(NOW + 20)["launchd"]["count"] == 0


def test_provenance_is_parsed_in_loki_not_matched_as_text(tmp_path: Path) -> None:
    loki = Loki()
    pack.volume_by_service(context(tmp_path, loki), "web", NOW)
    queries = [p["query"] for path, p in loki.calls if path == "query"]
    assert any('| json unit="unit" | __error__ = "" | unit != ""' in q for q in queries)
    assert any('| __error__ != "" or unit = "" | drop __error__, __error_details__' in q for q in queries)
    assert '| __error__ = "" | pid="1" | unit="init.scope"' in pack.restart_selector("web", "")


def test_flux_windows_follow_the_packs_clock(tmp_path: Path) -> None:
    seen: list[str] = []

    def record(query: str) -> list[dict[str, str]]:
        seen.append(query)
        return []

    pack.section_metrics(context(tmp_path, Loki(), record))
    assert seen
    assert all("now()" not in q and "-15d" not in q for q in seen)
    assert any(f"stop: {pack.iso(NOW)}" in q for q in seen)


def test_the_token_file_holds_token_and_id_and_the_pack_uses_the_first_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def fake_http(request: Any, timeout: float = 60, max_body: int = 0, wall: bool = False) -> bytes:
        seen.append(request.headers["Authorization"])
        return b""

    (tmp_path / "token").write_text("secret-token\nauth-id\n")
    monkeypatch.setattr(pack, "_http", fake_http)
    pack.flux_client("http://127.0.0.1:1", "org", str(tmp_path / "token"))("buckets()")
    assert seen == ["Token secret-token"]


def test_a_steep_decline_is_a_change_even_below_500_lines_today(tmp_path: Path) -> None:
    loki = Loki()
    for day in range(8):
        loki.volume[NOW - day * DAY] = {"web": {"api": 25.0 if day == 0 else 2000.0}}
    section = pack.section_volume(context(tmp_path, loki), ["web"])
    assert [(c["service"], c["lines_24h"]) for c in section["changed"]] == [("api", 25)]


def test_a_malformed_nyxmon_url_does_not_hide_the_others(tmp_path: Path) -> None:
    import sqlite3

    db = sqlite3.connect(tmp_path / "db.sqlite3")
    db.executescript(
        "create table health_check (id integer primary key, url text, data text, disabled bool);"
        "insert into health_check values (1, 'https://a.example:99999/', '{}', 0), (2, 'https://b.example/', '{}', 0);"
    )
    db.commit()
    db.close()
    assert pack.nyxmon_https_hosts(str(tmp_path / "db.sqlite3")) == ["b.example:443"]


def test_odd_ran_at_values_are_dropped_and_items_trimmed() -> None:
    result = ctl.parse_result(
        json.dumps(
            {"date": "2026-11-18", "status": "skipped", "ran_at": "x" * 1000, "new_items": [{"slug": "a" * 900}]}
        )
    )
    assert result["ran_at"] is None
    assert result["new_items"] == [{"slug": "a" * 200, "title": ""}]


@pytest.mark.parametrize(
    "report",
    [
        {"host": "studio", "checked": True, "loops": []},
        {"host": "studio", "checked": 3, "loops": ["invalid"]},
        {"host": "studio", "checked": 3, "errors": -1, "loops": []},
        {"host": "studio", "checked": 3, "loops": [{"label": "x", "runs_since_last_sample": "9"}]},
    ],
)
def test_malformed_launchd_reports_are_refused(tmp_path: Path, report: dict[str, Any]) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    assert ctl.launchd_report(config, json.dumps(report), NOW) == 2
    assert not (tmp_path / "launchd.json").exists()


def test_an_empty_metric_feed_is_a_pack_error(tmp_path: Path) -> None:
    ctx = context(tmp_path, Loki(), lambda q: [])
    pack.section_metrics(ctx)
    assert ctx.errors == ["metrics: 0 series in 15 days, 0 updated within 2 h"]


def test_day_windows_end_at_the_packs_time_of_day(tmp_path: Path) -> None:
    seen: list[str] = []

    def record(query: str) -> list[dict[str, str]]:
        seen.append(query)
        return []

    pack.section_metrics(context(tmp_path, Loki(), record))
    assert any(f"offset: {int(NOW % DAY)}s" in q for q in seen)


def test_a_stalled_launchd_merge_releases_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctl, "READ_TIMEOUT", 0.5)
    monkeypatch.setattr(ctl, "_launchd_merge", lambda *args: __import__("time").sleep(30))
    config = json.loads(ctl_config(tmp_path).read_text())
    report = {"host": "studio", "checked": 3, "loops": []}
    assert ctl.launchd_report(config, json.dumps(report), NOW) == 1
    monkeypatch.undo()
    monkeypatch.setattr(ctl, "LAUNCHD_LOCK", str(tmp_path / "launchd.lock"))
    assert ctl.launchd_report(config, json.dumps(report), NOW) == 0


def test_more_than_twenty_loops_are_counted_and_kept_in_part(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    loops = [{"label": f"job{i}", "runs_since_last_sample": 9, "last_exit": "1"} for i in range(25)]
    assert ctl.launchd_report(config, json.dumps({"host": "studio", "checked": 30, "loops": loops}), NOW) == 0
    assert len(json.loads((tmp_path / "launchd.json").read_text())["loops"]) == 25
    assert len(status_mod.Status(status_config(tmp_path)).document(NOW)["launchd"]["loops"]) == 20


def test_loops_beyond_twenty_keep_their_own_history(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())

    def report(start: int) -> str:
        loops = [{"label": f"job{i}", "runs_since_last_sample": 9, "last_exit": "1"} for i in range(start, start + 25)]
        return json.dumps({"host": "studio", "checked": 60, "loops": loops})

    assert ctl.launchd_report(config, report(0), NOW) == 0
    assert ctl.launchd_report(config, report(25), NOW + 60) == 0
    status = status_mod.Status(status_config(tmp_path))
    section = status.document(NOW + 120)["launchd"]
    assert (section["count"], len(section["loops"])) == (50, 20)


def test_no_log_host_is_an_error_and_records_no_baseline(tmp_path: Path) -> None:
    ctx = context(tmp_path, Loki())
    ctx.config["log_hosts"] = ["web"]
    result = pack.build_pack(ctx)
    assert any(e.startswith("log hosts:") for e in result["errors"])
    assert result["logs"]["volume"]["silent_last_hour"] == ["web"]
    assert not (tmp_path / "signatures.json").exists()


def test_a_configured_silent_host_stays_in_the_pack(tmp_path: Path) -> None:
    loki = Loki()
    loki.volume[NOW] = {"web": {"api": 10.0}}
    ctx = context(tmp_path, loki)
    ctx.config["log_hosts"] = ["gone", "web"]
    assert pack.log_hosts(ctx) == ["gone", "web"]


def test_an_oversized_launchd_state_fails_visibly_instead_of_being_erased(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    (tmp_path / "launchd.json").write_text(json.dumps({"loops": [], "pad": "x" * (ctl.MAX_STATE + 10)}))
    assert ctl.launchd_report(config, json.dumps({"host": "studio", "checked": 3, "loops": []}), NOW) == 1
    assert len((tmp_path / "launchd.json").read_text()) > ctl.MAX_STATE


def test_merged_launchd_state_stays_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctl, "MAX_STORED_LOOPS", 30)
    config = json.loads(ctl_config(tmp_path).read_text())
    for round_ in range(3):
        loops = [{"label": f"j{round_}-{i}", "runs_since_last_sample": 9, "last_exit": "1"} for i in range(30)]
        assert ctl.launchd_report(config, json.dumps({"host": "s", "checked": 99, "loops": loops}), NOW + round_) == 0
    kept = json.loads((tmp_path / "launchd.json").read_text())["loops"]
    assert len(kept) == 30
    assert all(loop["label"].startswith("j2-") for loop in kept)


def test_a_lone_surrogate_cannot_stop_signature_analysis(tmp_path: Path) -> None:
    loki = Loki()
    raw = '{"message":"boom failed \\ud800 here","unit":"app.service"}'
    loki.problem = {"web": [(NOW - 100 - i, raw) for i in range(4)]}
    section = pack.section_signatures(context(tmp_path, loki), ["web"])
    assert section["new_total"] == 1


def test_the_url_a_json_metrics_check_really_fetches_is_probed(tmp_path: Path) -> None:
    import sqlite3

    db = sqlite3.connect(tmp_path / "db.sqlite3")
    db.executescript(
        "create table health_check (id integer primary key, url text, data text, disabled bool);"
        "insert into health_check values (1, 'https://shown.example/', '{\"url\": \"https://real.example/x\"}', 0);"
    )
    db.commit()
    db.close()
    assert pack.nyxmon_https_hosts(str(tmp_path / "db.sqlite3")) == ["shown.example:443", "real.example:443"]


def test_an_empty_or_oversized_queue_file_is_unreadable_not_missing(tmp_path: Path) -> None:
    (tmp_path / "empty.json").write_text("")
    with pytest.raises(ctl.Unreadable, match="empty"):
        ctl.read_as("nobody", str(tmp_path / "empty.json"))
    (tmp_path / "big.json").write_text("{}" + " " * (ctl.MAX_STATE + 10))
    with pytest.raises(ctl.Unreadable, match="larger"):
        ctl.read_as("nobody", str(tmp_path / "big.json"))


def test_huge_counts_are_refused_and_merged_state_stays_small(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    huge = {"host": "s", "checked": 10**12, "loops": []}
    assert ctl.launchd_report(config, json.dumps(huge), NOW) == 2
    loops = [{"label": "x" * 120 + str(i), "runs_since_last_sample": 9, "last_exit": "1"} for i in range(500)]
    for round_ in range(4):
        report = {
            "host": "s",
            "checked": 999,
            "loops": [{**loop, "label": f"{round_}{loop['label']}"} for loop in loops],
        }
        assert ctl.launchd_report(config, json.dumps(report), NOW + round_) == 0
    assert (tmp_path / "launchd.json").stat().st_size <= ctl.MAX_STATE


def test_volume_groups_trusted_lines_by_their_full_unit(tmp_path: Path) -> None:
    loki = Loki()
    pack.volume_by_service(context(tmp_path, loki), "web", NOW)
    queries = [p["query"] for path, p in loki.calls if path == "query"]
    assert any(q.startswith("sum by (unit)") for q in queries)
    assert any(q.startswith("sum by (service)") and 'or unit = ""' in q for q in queries)


def test_a_failing_host_keeps_the_other_hosts_loops(tmp_path: Path) -> None:
    class OneDown(Loki):
        def __call__(self, path: str, params: dict[str, str]) -> Any:
            if path == "query_range" and 'host="db"' in params.get("query", ""):
                raise RuntimeError("timed out")
            return super().__call__(path, params)

    loki = OneDown()
    loki.restarts = {"web": [(NOW - 10, pid1("c.service: Start request repeated too quickly."))], "db": []}
    result = status_mod.unit_loops(status_config(tmp_path), NOW, loki)
    assert result["count"] == 1
    assert result["failed_hosts"]


def test_long_launchd_labels_stay_distinct(tmp_path: Path) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    loops = [{"label": "x" * 250 + suffix, "runs_since_last_sample": 9, "last_exit": "1"} for suffix in "ab"]
    assert ctl.launchd_report(config, json.dumps({"host": "s", "checked": 2, "loops": loops}), NOW) == 0
    assert len(json.loads((tmp_path / "launchd.json").read_text())["loops"]) == 2


def test_an_oversized_loki_answer_narrows_the_window(tmp_path: Path) -> None:
    calls: list[tuple[float, float]] = []

    def huge(path: str, params: dict[str, str]) -> Any:
        calls.append((int(params["start"]) / NS, int(params["end"]) / NS))
        raise pack.TooLarge("too big")

    ctx = context(tmp_path, huge)
    assert pack.problem_lines(ctx, "web", NOW - 6 * 3600, NOW) == []
    assert len(calls) > 1
    assert any("too large" in note for note in ctx.notes)


@pytest.mark.parametrize("wrapped", [False, True])
def test_a_connection_loki_closes_without_an_answer_is_dropped(monkeypatch: pytest.MonkeyPatch, wrapped: bool) -> None:
    import http.client
    import urllib.error

    def closed(request: Any, timeout: float) -> Any:
        error = http.client.RemoteDisconnected("Remote end closed connection without response")
        raise urllib.error.URLError(error) if wrapped else error

    monkeypatch.setattr(pack.urllib.request, "urlopen", closed)
    with pytest.raises(pack.Dropped, match="unreachable: Remote end closed"):
        pack.loki_client("http://loki")("query_range", {})


def test_a_refused_connection_still_fails_the_section(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(request: Any, timeout: float) -> Any:
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setattr(pack.urllib.request, "urlopen", refused)
    with pytest.raises(RuntimeError) as caught:
        pack.loki_client("http://loki")("query_range", {})
    assert not isinstance(caught.value, pack.TooLarge)


def test_a_window_loki_does_not_answer_is_split_and_the_rest_is_read(tmp_path: Path) -> None:
    loki = Loki()
    loki.problem = {"web": [(NOW - 3600 * h - 30, journald("boom failed")) for h in range(6)]}
    calls: list[tuple[float, float]] = []

    def dropping(path: str, params: dict[str, str]) -> Any:
        if path == "query_range" and "|~" in params["query"]:
            start, end = int(params["start"]) / NS, int(params["end"]) / NS
            calls.append((start, end))
            # Loki drops every answer that covers the newest half hour.
            if end > NOW - 1800:
                raise pack.Dropped("unreachable: Remote end closed connection without response")
        return loki(path, params)

    ctx = context(tmp_path, dropping)
    found = pack.problem_lines(ctx, "web", NOW - 6 * 3600, NOW)

    assert len(found) == 5  # the line inside the unanswered newest window is the one missing
    assert len(calls) > 2
    assert any("connection closed without an answer" in note for note in ctx.notes)
    assert ctx.skipped_windows == 3  # the three 11-minute windows that end in the newest half hour


def test_an_unanswered_window_keeps_the_day_out_of_the_baseline_without_failing_the_section(
    tmp_path: Path,
) -> None:
    loki = Loki()
    loki.problem = {"web": [(NOW - 100 - i, journald("brand new failure in worker 7")) for i in range(5)]}

    def dropping(path: str, params: dict[str, str]) -> Any:
        if path == "query_range" and "|~" in params["query"] and int(params["end"]) / NS > NOW - 60:
            raise pack.Dropped("unreachable: Remote end closed connection without response")
        return loki(path, params)

    ctx = context(tmp_path, dropping)
    section = pack.section_signatures(ctx, ["web"])

    assert isinstance(section, dict)
    assert pack.day_of(NOW) not in json.loads((tmp_path / "signatures.json").read_text())["covered_days"]
    assert any("today incomplete" in e and "not answered" in e for e in ctx.errors)


def test_a_loki_that_answers_no_problem_query_fails_the_section_after_a_bounded_number(tmp_path: Path) -> None:
    calls = 0

    def outage(path: str, params: dict[str, str]) -> Any:
        nonlocal calls
        if path == "query_range":
            calls += 1
            raise pack.Dropped("unreachable: Remote end closed connection without response")
        return Loki()(path, params)

    with pytest.raises(RuntimeError, match="windows not answered; giving up"):
        pack.section_signatures(context(tmp_path, outage), ["web"])
    assert calls == pack.MAX_DROPPED + 1


def test_a_pass_that_gives_up_keeps_the_backfilled_days_it_read_completely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pack, "MAX_DROPPED", 3)
    loki = Loki()

    def dropping(path: str, params: dict[str, str]) -> Any:
        if path == "query_range" and int(params["end"]) / NS > NOW - 1.5 * DAY:
            raise pack.Dropped("unreachable: Remote end closed connection without response")
        return loki(path, params)

    expired = pack.day_of(NOW - 40 * DAY)
    key = pack.signature_key("web", "app.service", "old failure")
    store = {"schema": 2, "signatures": {key: {"days": {expired: 3}}}, "covered_days": [expired]}
    (tmp_path / "signatures.json").write_text(json.dumps(store))
    ctx = context(tmp_path, dropping)
    ctx.activity = {"web": {pack.day_of(NOW - back * DAY): True for back in range(8)}}

    with pytest.raises(RuntimeError, match="giving up"):
        pack.section_signatures(ctx, ["web"])
    stored = json.loads((tmp_path / "signatures.json").read_text())
    # The completely read day is kept, the expired one is pruned, and the activity is merged.
    assert stored["covered_days"] == [pack.day_of(NOW - 2 * DAY)]
    assert stored["signatures"] == {}
    assert stored["host_active"]["web"] == sorted(pack.day_of(NOW - back * DAY) for back in range(8))


def test_the_problem_line_limit_leaves_the_unit_restart_limit_alone() -> None:
    assert pack.PROBLEM_LINES * 1200 < 4 * 1024 * 1024
    assert pack.MAX_LINES == 5000


def test_a_day_with_a_skipped_window_stays_out_of_the_baseline(tmp_path: Path) -> None:
    def huge(path: str, params: dict[str, str]) -> Any:
        if path == "query_range":
            raise pack.TooLarge("too big")
        return Loki()(path, params)

    ctx = context(tmp_path, huge)
    section = pack.section_signatures(ctx, ["web"])

    assert section["baseline_days"] == 0
    stored = json.loads((tmp_path / "signatures.json").read_text())
    assert stored["covered_days"] == []
    assert any("incomplete" in e for e in ctx.errors)


def test_an_oversized_pack_is_trimmed_and_flagged() -> None:
    big = {"errors": [], "metrics": {"filesystems": [{"series": "x" * 1000} for _ in range(100)]}}
    pack.fit_pack(big, limit=20_000)
    assert len(json.dumps(big)) <= 20_000
    assert big["errors"] == ["pack: lists trimmed to fit 20000 bytes"]


def test_a_pack_that_cannot_be_trimmed_becomes_an_error_pack() -> None:
    big: dict[str, Any] = {
        "schema": 1,
        "date": "d",
        "generated_at": "t",
        "errors": [],
        "metrics": {"x": ["y" * 50_000]},
    }
    pack.fit_pack(big, limit=20_000)
    assert len(json.dumps(big)) <= 20_000
    assert big["errors"][-1].startswith("pack: larger than 20000 bytes")
    assert "metrics" not in big


def test_a_window_still_at_the_line_limit_keeps_the_day_out_of_the_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pack, "PROBLEM_LINES", 2)
    monkeypatch.setattr(pack, "MAX_SPLIT", 0)
    loki = Loki()
    loki.problem = {"web": [(NOW - 100 - i, journald("boom failed")) for i in range(9)]}
    ctx = context(tmp_path, loki)
    pack.section_signatures(ctx, ["web"])
    assert pack.day_of(NOW) not in json.loads((tmp_path / "signatures.json").read_text())["covered_days"]
    assert any("today incomplete" in e for e in ctx.errors)


def test_a_new_host_is_not_measured_against_days_before_it_shipped(tmp_path: Path) -> None:
    old_days = [pack.day_of(NOW - d * DAY) for d in range(19, 0, -1)]
    key = pack.signature_key("new", "app.service", "boom failed")
    store = {"schema": 2, "signatures": {key: {"days": {old_days[-1]: 60}}}, "covered_days": old_days}
    (tmp_path / "signatures.json").write_text(json.dumps(store))
    loki = Loki()
    loki.problem = {"new": [(NOW - 100 - i, journald("boom failed")) for i in range(60)]}

    def run(inactive_before: bool) -> list[Any]:
        (tmp_path / "signatures.json").write_text(json.dumps(store))
        ctx = context(tmp_path, loki)
        ctx.config["backfill_days"] = 0
        # logs.volume saw the host only from yesterday on (or on every day).
        ctx.activity = {"new": {day: not inactive_before or day == old_days[-1] for day in old_days}}
        return list(pack.section_signatures(ctx, ["new"])["surging"])

    assert run(inactive_before=True) == []
    assert run(inactive_before=False) != []  # an established host with a jump does surge


def test_the_most_urgent_filesystems_survive_the_cap(tmp_path: Path) -> None:
    def rows(query: str) -> list[dict[str, str]]:
        def row(mount: str, value: float) -> dict[str, str]:
            return {"host": "web", "metric": "host.filesystem_used_ratio", "mountpoint": mount,
                    "_value": str(value), "_time": pack.iso(NOW - 60)}  # fmt: skip

        if "|> last()" in query or "|> first()" in query:
            return [row("/a", 0.86), row("/b", 0.999)]
        return []

    ctx = context(tmp_path, Loki(), rows)
    ctx.config["caps"]["series"] = 1
    assert [d["used"] for d in pack.section_metrics(ctx)["filesystems"]] == [0.999]


def test_an_invisible_message_is_refused() -> None:
    with pytest.raises(ValueError, match="visible"):
        ctl.parse_result(json.dumps({"date": "2026-11-18", "status": "skipped", "message": chr(0x200B)}))


# -- raw lines for the triage (owner decision 2026-11-19) ------------------------------------------


def test_new_templates_carry_raw_example_lines(tmp_path: Path) -> None:
    loki = Loki()
    loki.problem = {
        "web": [(NOW - 10 - i, journald(f"upload of /srv/{i}.bin failed for bob " + "x" * 500)) for i in range(5)]
    }

    signatures = pack.section_signatures(context(tmp_path, loki), ["web"])

    examples = signatures["new"][0]["examples"]
    assert len(examples) == pack.EXAMPLES
    assert examples[0].startswith("upload of /srv/0.bin failed for bob")
    assert len(examples[0]) == pack.EXAMPLE_CHARS
    store = json.loads((tmp_path / "signatures.json").read_text())
    assert "bob" not in json.dumps(store)  # the baseline keeps counts only


class SampleLoki:
    """Lines per (host, service) for ``logs.samples``."""

    def __init__(self, lines: dict[tuple[str, str], list[tuple[float, str]]], broken: str = "") -> None:
        self.lines = lines
        self.broken = broken
        self.calls: list[dict[str, str]] = []

    def __call__(self, path: str, params: dict[str, str]) -> Any:
        query = params["query"]
        host = query.split('host="')[1].split('"')[0]
        if path == "query":
            counts = {s: len(v) for (h, s), v in self.lines.items() if h == host}
            return {"result": [{"metric": {"service": s}, "value": [0, str(c)]} for s, c in counts.items()]}
        self.calls.append(params)
        service = query.split('service="')[1].split('"')[0]
        if service == self.broken:
            raise RuntimeError("HTTP 500: boom")
        start, end, limit = int(params["start"]) / NS, int(params["end"]) / NS, int(params["limit"])
        found = sorted((t for t in self.lines[(host, service)] if start <= t[0] < end), reverse=True)[:limit]
        stream = {"host": host, "service": service, "level": "info"}
        return {"result": [{"stream": stream, "values": [[str(int(t * NS)), raw] for t, raw in found]}]}


def test_samples_show_every_service_at_any_level_grouped_with_raw_examples(tmp_path: Path) -> None:
    lines = {
        ("web", "nginx"): [(NOW - 60 - i, journald(f"GET /page/{i} 200")) for i in range(40)]
        + [(NOW - 5000, journald("worker pid 4711 exited on signal 11"))],
        ("web", "quiet"): [(NOW - 7200, json.dumps({"message": "token rotated", "level": "info"}))],
        ("db", "postgres"): [(NOW - 300, "plain text checkpoint complete")],
    }
    ctx = context(tmp_path, SampleLoki(lines))

    section = pack.section_samples(ctx, ["db", "web"])

    by_name = {(s["host"], s["service"]): s for s in section["services"]}
    assert list(by_name) == [("db", "postgres"), ("web", "nginx"), ("web", "quiet")]
    nginx = by_name[("web", "nginx")]
    assert (nginx["lines_24h"], nginx["sampled"], nginx["groups"]) == (41, 41, 2)
    assert nginx["lines"][0].endswith("n=40 info GET /page/0 200")
    assert nginx["lines"][1].endswith("n=1 info worker pid 4711 exited on signal 11")
    assert by_name[("web", "quiet")]["lines"][0].endswith("n=1 info token rotated")
    assert by_name[("db", "postgres")]["lines"][0].endswith("plain text checkpoint complete")
    assert section["detail"] == {"top": 6, "rare": 3, "chars": 400}


def test_samples_read_each_window_up_to_the_limit(tmp_path: Path) -> None:
    loki = SampleLoki({("web", "app"): [(NOW - 60 * i, journald(f"event {i}")) for i in range(1, 1400)]})
    ctx = context(tmp_path, loki)
    ctx.config["sample_lines_per_window"] = 10

    section = pack.section_samples(ctx, ["web"])

    assert len(loki.calls) == 4
    assert {c["limit"] for c in loki.calls} == {"10"}
    assert section["services"][0]["sampled"] == 40


def test_samples_shrink_their_detail_to_the_budget(tmp_path: Path) -> None:
    lines = {
        ("web", f"svc{n}"): [(NOW - 60 - i, journald(f"message kind {chr(97 + i)} " + "y" * 600)) for i in range(9)]
        for n in range(20)
    }
    ctx = context(tmp_path, SampleLoki(lines))
    ctx.config["sample_budget_bytes"] = 20_000

    section = pack.section_samples(ctx, ["web"])

    assert len(json.dumps(section["services"]).encode()) <= 20_000
    assert section["detail"]["top"] < 6
    assert len(section["services"]) == 20


def test_a_failing_service_sample_is_an_error_and_the_rest_stays(tmp_path: Path) -> None:
    lines = {("web", "good"): [(NOW - 60, journald("fine"))], ("web", "bad"): [(NOW - 60, journald("x"))]}
    ctx = context(tmp_path, SampleLoki(lines, broken="bad"))

    section = pack.section_samples(ctx, ["web"])

    entries = {s["service"]: s for s in section["services"]}
    assert entries["bad"]["error"] == "not (completely) read"
    assert entries["good"]["lines"][0].endswith("fine")
    assert ctx.errors == ["logs.samples: web bad: RuntimeError: HTTP 500: boom"]


# -- drill-down queries ----------------------------------------------------------------------------


class QueryLoki:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, path: str, params: dict[str, str]) -> Any:
        self.calls.append((path, params))
        if "rate(" in params["query"]:
            return {"resultType": "matrix", "result": [{"metric": {"host": "web"}, "values": [[NOW - 60, "1.5"]]}]}
        return {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"host": "web", "service": "app", "level": "info"},
                    "values": [
                        [str(int((NOW - 10) * NS)), journald("second line, password=hunter2", "app")],
                        [str(int((NOW - 20) * NS)), "plain first line"],
                    ],
                }
            ],
        }


def run_queries(specs: Any, capsys: pytest.CaptureFixture[str], **clients: Any) -> tuple[int, Any]:
    clients = {"loki": QueryLoki(), "flux": lambda q: [], **clients}
    code = ctl.queries({"influx": {"bucket": "graphyard"}}, json.dumps(specs), NOW, clients)
    out = capsys.readouterr().out
    return code, json.loads(out) if out else None


def test_log_queries_return_raw_records_in_time_order(capsys: pytest.CaptureFixture[str]) -> None:
    loki = QueryLoki()
    spec = {"kind": "loki", "query": '{host="web"} |= "line"', "start": "-2h", "limit": 50}

    code, answer = run_queries({"queries": [spec]}, capsys, loki=loki)

    assert code == 0
    result = answer["results"][0]
    assert result["lines"] == [
        "2026-11-18T11:06:20Z web/app info plain first line",
        "2026-11-18T11:06:30Z web/app info second line, password=hunter2"
        ' | {"syslog_identifier":"app","host":"h","pid":"77","unit":"app.service"}',
    ]
    path, params = loki.calls[0]
    assert (path, params["limit"]) == ("query_range", "50")
    assert int(params["end"]) - int(params["start"]) == 2 * 3600 * NS


def test_metric_queries_return_series(capsys: pytest.CaptureFixture[str]) -> None:
    spec = {"kind": "loki", "query": 'sum(rate({host="web"}[5m]))', "start": "-1d", "step": 300}
    _code, answer = run_queries({"queries": [spec]}, capsys)
    assert answer["results"][0]["series"] == [{"metric": {"host": "web"}, "values": [["2026-11-18T11:05:40Z", "1.5"]]}]


def test_a_long_series_keeps_its_newest_points_within_the_budget(capsys: pytest.CaptureFixture[str]) -> None:
    def loki(path: str, params: dict[str, str]) -> Any:
        values = [[NOW - 60 * i, str(i) * 30] for i in range(1000, 0, -1)]
        return {"resultType": "matrix", "result": [{"metric": {"host": "web"}, "values": values}]}

    spec = {"kind": "loki", "query": 'sum(rate({host="web"}[5m]))', "start": "-1d", "step": 60}
    _code, answer = run_queries({"queries": [spec]}, capsys, loki=loki)

    result = answer["results"][0]
    points = result["series"][0]["values"]
    assert 0 < len(points) < 1000
    assert result["points_cut"] == 1000 - len(points)
    assert points[-1][1] == "1" * 30  # the newest point stays
    assert len(json.dumps(result["series"]).encode()) <= ctl.MAX_RESULT


def test_influx_queries_are_built_from_a_selector(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[str] = []

    def flux(query: str) -> list[dict[str, str]]:
        seen.append(query)
        return [{"_time": "t", "_value": "1.5", "metric": "host.load5", "table": "0", "_field": "value"}]

    specs = [
        {"kind": "influx", "query": "metric=host.load5 subject_id=fractal", "start": "-3d", "fn": "max"},
        {"kind": "influx_series", "query": "metric=~^host\\.temp subject_id!=atlas", "start": "-1d"},
    ]
    _code, answer = run_queries({"queries": specs}, capsys, flux=flux)

    assert answer["results"][0]["rows"] == [{"_time": "t", "_value": "1.5", "metric": "host.load5"}]
    aggregated, latest = seen
    assert aggregated.startswith(
        'from(bucket: "graphyard") |> range(start: 2026-11-15T11:06:40.000000Z, stop: 2026-11-18T11:06:40.000000Z)'
    )
    assert 'r["metric"] == "host.load5" and r["subject_id"] == "fractal"' in aggregated
    assert "aggregateWindow(every: 519s, fn: max, createEmpty: false)" in aggregated
    assert 'r["metric"] =~ /^host\\.temp/ and r["subject_id"] != "atlas"' in latest
    assert latest.endswith("|> last() |> group()")


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        ({"kind": "loki", "query": "{}", "limit": 5000}, "limit must be"),
        ({"kind": "loki", "query": "{}", "start": "-40d"}, "at most 31 days"),
        ({"kind": "influx", "query": "metric=host.load5", "start": "-60d"}, "at most 31 days"),
        ({"kind": "loki", "query": "{}", "start": "yesterday"}, "unreadable time"),
        ({"kind": "loki", "query": ""}, "non-empty string"),
        ({"kind": "flux", "query": 'from(bucket: "b")'}, '"kind"'),
        ({"kind": "influx", "query": 'metric=x") |> to(bucket: "y'}, "unreadable selector term"),
        ({"kind": "influx", "query": "metric=~a/b"}, "unreadable selector term"),
        ({"kind": "influx", "query": "metric=~a\\sb"}, "backslashes other than"),
        ({"kind": "influx", "query": "metric=~a\\\\.d"}, "backslashes other than"),
        ({"kind": "influx", "query": "metric=~("}, "bad regex"),
        ({"kind": "influx", "query": "metric=x", "fn": "drop"}, "fn must be one of"),
        ({"kind": "influx", "query": "metric x"}, "unreadable selector term"),
        ({"kind": "influx", "query": "metric=${string(v: 1)}"}, "unreadable selector term"),
        ({"kind": "influx", "query": 'metric=a"b'}, "unreadable selector term"),
        ({"kind": "influx", "query": "metric=a\\b"}, "unreadable selector term"),
    ],
)
def test_unsafe_or_unbounded_queries_are_refused(
    spec: dict[str, Any], reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    ran: list[str] = []

    def flux(query: str) -> list[dict[str, str]]:
        ran.append(query)
        return []

    _code, answer = run_queries({"queries": [spec]}, capsys, flux=flux)
    assert reason in answer["results"][0]["error"]
    assert answer["results"][0]["error"].startswith("refused")
    assert ran == []


def test_influx_rows_are_bounded_and_one_failure_does_not_cost_the_others(capsys: pytest.CaptureFixture[str]) -> None:
    rows = [{"_time": f"t{i}", "_value": "x" * 100, "table": "0", "result": "_result"} for i in range(1000)]

    def flux(query: str) -> list[dict[str, str]]:
        if "boom" in query:
            raise RuntimeError("HTTP 400: bad query")
        return rows

    specs = [{"kind": "influx", "query": "metric=a"}, {"kind": "influx", "query": "metric=boom"}]
    _code, answer = run_queries({"queries": specs}, capsys, flux=flux)

    first, second = answer["results"]
    assert first["rows"][0] == {"_time": "t0", "_value": "x" * 100}
    assert first["cut"] > 0
    assert len(json.dumps(first["rows"]).encode()) <= ctl.MAX_RESULT
    assert second["error"] == "RuntimeError: HTTP 400: bad query"


@pytest.mark.parametrize("raw", ["not json", "{}", json.dumps({"queries": []}), json.dumps({"queries": [{}] * 11})])
def test_unusable_query_input_exits_2(raw: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert ctl.queries({}, raw, NOW, {"loki": QueryLoki(), "flux": lambda q: []}) == 2


def test_queries_stop_starting_after_the_deadline(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ctl, "QUERY_DEADLINE", -1)
    _code, answer = run_queries({"queries": [{"kind": "loki", "query": "{}"}]}, capsys)
    assert answer["results"][0]["error"].startswith("not run")


def test_a_lone_surrogate_in_a_query_answer_is_escaped(capsys: pytest.CaptureFixture[str]) -> None:
    def loki(path: str, params: dict[str, str]) -> Any:
        raw = '{"message":"bad \\udc80 byte"}'
        return {"resultType": "streams", "result": [{"stream": {"host": "h"}, "values": [[str(int(NOW * NS)), raw]]}]}

    _code, answer = run_queries({"queries": [{"kind": "loki", "query": "{}"}]}, capsys, loki=loki)
    assert answer["results"][0]["lines"][0].endswith("bad \\udc80 byte")


def test_the_query_action_drops_to_nyxmon_before_reading_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dropped: list[str] = []
    monkeypatch.setattr(ctl, "drop_privileges", dropped.append)
    seen: list[str] = []

    def queries(config: dict[str, Any], raw: str, now: float) -> int:
        seen.append(raw)
        return 0

    monkeypatch.setattr(ctl, "queries", queries)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO('{"queries": []}'))

    assert ctl.main(["--config", str(ctl_config(tmp_path)), "query"]) == 0
    assert dropped == ["nyxmon"]
    assert seen == ['{"queries": []}']


def test_a_hanging_query_is_abandoned_at_the_wall_clock_limit(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import time as clock

    monkeypatch.setattr(ctl, "QUERY_TIMEOUT", -4.7)  # joins for 0.3 s
    release = threading.Event()

    def loki(path: str, params: dict[str, str]) -> Any:
        release.wait(5)  # a server that keeps trickling

    started = clock.monotonic()
    specs = [{"kind": "loki", "query": "{}"}, {"kind": "influx", "query": "metric=a"}]
    _code, answer = run_queries({"queries": specs}, capsys, loki=loki)

    elapsed = clock.monotonic() - started
    release.set()
    assert elapsed < 2
    assert answer["results"][0]["error"].startswith("no answer within")
    assert answer["results"][1]["rows"] == []


def test_quoted_blank_lines_do_not_end_a_flux_table() -> None:
    text = ',result,table,_value\r\n,_result,0,"a\r\n\r\nb"\r\n,_result,0,c\r\n\r\n,result,table,x\r\n,_result,1,y\r\n'
    assert pack.parse_flux_csv(text) == [
        {"": "", "result": "_result", "table": "0", "_value": "a\r\n\r\nb"},
        {"": "", "result": "_result", "table": "0", "_value": "c"},
        {"": "", "result": "_result", "table": "1", "x": "y"},
    ]


def test_a_lone_surrogate_in_an_example_does_not_stop_the_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loki = Loki()
    loki.problem = {
        "web": [(NOW - 10 - i, '{"message":"boom failed \\udc80","unit":"a\\udc81.service"}') for i in range(4)]
    }
    ctx = context(tmp_path, loki)
    result = pack.build_pack(ctx)
    pack.fit_pack(result)
    pack._write_json(str(tmp_path / "latest.json"), result)
    assert "\\udc80" in result["logs"]["signatures"]["new"][0]["examples"][0]
    assert result["logs"]["signatures"]["new"][0]["source"] == "a\\udc81.service"


def test_the_sample_section_is_capped_as_published(tmp_path: Path) -> None:
    lines = {("web", f"svc{n}"): [(NOW - 60, journald("m " * 300))] for n in range(250)}
    ctx = context(tmp_path, SampleLoki(lines))
    ctx.config["sample_budget_bytes"] = 50_000

    section = pack.section_samples(ctx, ["web"])

    published = json.dumps({"logs": {"samples": section}}, indent=1, sort_keys=True, ensure_ascii=False)
    assert len(published.encode()) <= 50_000
    assert any(note.startswith("logs.samples: over 50000 bytes") for note in ctx.notes)


def test_a_kept_host_field_that_differs_from_the_label(capsys: pytest.CaptureFixture[str]) -> None:
    def loki(path: str, params: dict[str, str]) -> Any:
        raw = '{"message":"m","host":"real-host","service":"app"}'
        stream = {"stream": {"service": "app"}, "values": [[str(int(NOW * NS)), raw]]}
        return {"resultType": "streams", "result": [stream]}

    _code, answer = run_queries({"queries": [{"kind": "loki", "query": "{}"}]}, capsys, loki=loki)
    assert answer["results"][0]["lines"][0].endswith('?/app - m | {"host":"real-host"}')


def test_the_surge_average_counts_template_days_and_active_days_together(tmp_path: Path) -> None:
    today = pack.day_of(NOW)
    days = [pack.day_of(NOW - back * DAY) for back in range(1, 9)]
    key = pack.signature_key("web", "app.service", "disk slow")
    store = {"schema": 2, "covered_days": days, "signatures": {key: {"days": {days[-1]: 40}}},
             "host_active": {"web": days[:7]}}  # fmt: skip
    (tmp_path / "signatures.json").write_text(json.dumps(store))
    loki = Loki()
    loki.problem = {"web": [(NOW - 10 - i, journald("disk slow")) for i in range(50)]}
    ctx = context(tmp_path, loki)
    ctx.config["backfill_days"] = 0

    section = pack.section_signatures(ctx, ["web"])

    assert today not in days
    assert [(e["count"], e["daily_average_before"]) for e in section["surging"]] == [(50, 5.0)]


def test_a_tiny_range_is_checked_at_the_precision_sent(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[str] = []

    def flux(query: str) -> list[dict[str, str]]:
        seen.append(query)
        return []

    specs = [
        {"kind": "influx", "query": "metric=a", "start": NOW - 0.00000025, "end": NOW},
        {"kind": "influx", "query": "metric=a", "start": NOW + 0.0000002, "end": NOW + 0.0000004},
    ]
    _code, answer = run_queries({"queries": specs}, capsys, flux=flux)
    assert "range(start: 2026-11-18T11:06:39.999999Z, stop: 2026-11-18T11:06:40.000000Z)" in seen[0]
    assert "start must lie before end" in answer["results"][1]["error"]


def test_a_null_host_field_without_a_label_is_kept(capsys: pytest.CaptureFixture[str]) -> None:
    def loki(path: str, params: dict[str, str]) -> Any:
        stream = {"stream": {"service": "app"}, "values": [[str(int(NOW * NS)), '{"message":"m","host":null}']]}
        return {"resultType": "streams", "result": [stream]}

    _code, answer = run_queries({"queries": [{"kind": "loki", "query": "{}"}]}, capsys, loki=loki)
    assert answer["results"][0]["lines"][0].endswith('?/app - m | {"host":null}')


def test_a_31_day_window_is_sent_exactly(capsys: pytest.CaptureFixture[str]) -> None:
    loki = QueryLoki()
    spec = {"kind": "loki", "query": "{}", "start": NOW + 0.3 - 31 * DAY, "end": NOW + 0.3}
    _code, answer = run_queries({"queries": [spec]}, capsys, loki=loki)
    assert "error" not in answer["results"][0]
    params = loki.calls[0][1]
    assert int(params["end"]) == int(NOW * 1e6) * 1000
    assert 0 < int(params["end"]) - int(params["start"]) <= 31 * DAY * NS


def test_delivered_is_printed_only_after_telegram_acknowledged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    result = {"date": "2026-11-18", "status": "ok", "ran_at": NOW, "message": "neu"}
    monkeypatch.setattr(ctl, "send", lambda config, message: (False, "sender exit 1: timeout"))
    assert ctl.deliver(config, json.dumps(result), NOW) == 1
    assert "obs-ctl: delivered" not in capsys.readouterr().out
    assert json.loads((tmp_path / "triage.json").read_text()).get("ok_epoch") is None

    monkeypatch.setattr(ctl, "send", lambda config, message: (True, "delivered"))
    assert ctl.deliver(config, json.dumps(result), NOW + 60) == 0
    assert "obs-ctl: delivered" in capsys.readouterr().out
    assert json.loads((tmp_path / "triage.json").read_text())["ok_epoch"] == int(NOW)


def test_a_fractional_clock_never_moves_the_window_end_into_the_future(capsys: pytest.CaptureFixture[str]) -> None:
    loki = QueryLoki()
    now = 1795000000.000002
    ctl.queries({}, json.dumps({"queries": [{"kind": "loki", "query": "{}"}]}), now, {"loki": loki, "flux": None})
    capsys.readouterr()
    assert int(loki.calls[0][1]["end"]) <= 1795000000000002000
    assert int(loki.calls[0][1]["end"]) == ctl._micros(now) * 1000


def test_an_rfc3339_microsecond_is_kept_exactly(capsys: pytest.CaptureFixture[str]) -> None:
    loki = QueryLoki()
    spec = {"kind": "loki", "query": "{}", "start": "2026-11-18T11:06:39.000000Z", "end": "2026-11-18T11:06:39.000001Z"}
    _code, answer = run_queries({"queries": [spec]}, capsys, loki=loki)
    assert "error" not in answer["results"][0]
    params = loki.calls[0][1]
    assert int(params["end"]) - int(params["start"]) == 1000


def test_stdout_carries_only_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = json.loads(ctl_config(tmp_path).read_text())
    monkeypatch.setattr(ctl, "send", lambda config, message: (False, "sender exit 1: obs-ctl: delivered"))
    result = {"date": "2026-11-18", "status": "ok", "ran_at": NOW, "message": "neu"}
    assert ctl.deliver(config, json.dumps(result), NOW) == 1
    assert capsys.readouterr().out == ""
