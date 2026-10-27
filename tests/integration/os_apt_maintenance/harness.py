"""Real systemd/HTTP/SQLite owned fixture; synthetic apt/reboot command effects only."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shlex
import sqlite3
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import patch

from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.local import LocalConnector

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.os_apt_maintenance import (
    OsAptMaintenanceConfig,
    OsAptNyxmonConfig,
    deploy_os_apt_maintenance,
    deploy_os_apt_maintenance_nyxmon,
)
from ops_deploy.services.os_apt_maintenance.deploy import role_vars
from ops_deploy.testing.harness import collect_ops

ROOT = Path("/opt/os-apt-fixture")
EVIDENCE = Path(sys.argv[1])
LIBRARY = ROOT / "collections/ansible_collections/local/ops_library"
REF = SecretRef("fixture.yml")
VALUE = secrets.token_urlsafe(24)
RUST_VERSION = "0.1.0"
RUST_SHA = "7befbd0f4151d6eb11009d7a93a7e7defbd4559cb0c2086915fa598c6d85fc27"
UNIT = "fixture-apt-endpoint.service"
PHASES: list[dict[str, Any]] = []
DB = ROOT / "nyxmon/db.sqlite3"


def sh(*args: str, check: bool = True, **kwargs: Any) -> str:
    result = subprocess.run(args, text=True, capture_output=True, timeout=900, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-1500:]}")
    return str(result.stdout).strip()


def write(name: str, value: Any) -> None:
    (EVIDENCE / name).write_text(json.dumps(value, indent=2, default=str))


def cfg(**changes: Any) -> OsAptMaintenanceConfig:
    return OsAptMaintenanceConfig.model_validate(
        {
            "secrets": str(REF),
            "auth_user": "fixture",
            "host_id": "owned-fixture",
            "bind": "127.0.0.1",
            "port": 19106,
            "user": "metrics",
            "group": "metrics",
            "state_dir": str(ROOT / "state"),
            "lock_file": str(ROOT / "apt.lock"),
            "script_path": str(ROOT / "apt-runner"),
            "server_path": str(ROOT / "httpd.py"),
            "htpasswd_dir": str(ROOT / "auth"),
            "maintenance_service_name": "fixture-apt",
            "refresh_service_name": "fixture-apt-refresh",
            "service_name": "fixture-apt-endpoint",
            "apt_get_path": str(ROOT / "fake-apt"),
            "systemctl_path": str(ROOT / "fake-systemctl"),
            # Avoid fixture timer expiry and persistent catch-up. Original cadence has independent Ansible parity tests.
            "timer_on_calendar": "2099-01-01 04:00:00",
            "refresh_timer_on_calendar": "2099-01-01 06:00:00",
            "timer_persistent": False,
            "refresh_timer_persistent": False,
            "httpd_impl": os.environ["FIXTURE_IMPL"],
            "httpd_rust_version": RUST_VERSION,
            "httpd_rust_sha256": RUST_SHA,
            **changes,
        }
    )


def fs(path: Path) -> Any:
    if not path.exists() and not path.is_symlink():
        return None
    st = path.lstat()
    return [
        st.st_mode,
        st.st_uid,
        st.st_gid,
        st.st_ino,
        st.st_mtime_ns,
        os.readlink(path)
        if path.is_symlink()
        else hashlib.sha256(path.read_bytes()).hexdigest()
        if path.is_file()
        else None,
    ]


def endpoint_snapshot() -> dict[str, Any]:
    roots = [ROOT / name for name in ("state", "auth", "apt-runner", "httpd.py", "apt-events", "reboot-events")]
    roots += list(Path("/etc/systemd/system").glob("fixture-apt*"))
    roots += [Path("/usr/local/lib/metrics-httpd")]
    files: dict[str, Any] = {}
    for root in roots:
        files[str(root)] = fs(root)
        if root.is_dir():
            files.update({str(p): fs(p) for p in root.rglob("*")})
    return {
        "files": files,
        "pid": sh("systemctl", "show", UNIT, "-p", "MainPID", "--value"),
        "timer_state": {
            unit: sh(
                "systemctl",
                "show",
                unit,
                "-p",
                "ActiveState",
                "-p",
                "UnitFileState",
                "-p",
                "ActiveEnterTimestampMonotonic",
            )
            for unit in ("fixture-apt.timer", "fixture-apt-refresh.timer")
        },
        "packages": sh("dpkg-query", "-W", "-f=${Package}=${Version}\n"),
        "apt_policy": {str(p): fs(p) for p in Path("/etc/apt").rglob("*") if p.is_file()},
        "reboot_flag": fs(Path("/var/run/reboot-required")),
    }


def db_snapshot() -> dict[str, Any]:
    if not DB.exists():
        return {"rows": None, "main": None, "sidecars": {}}
    with closing(sqlite3.connect(f"file:{DB}?mode=ro", uri=True)) as conn:
        rows = [list(row) for row in conn.execute("SELECT * FROM health_check ORDER BY id")]
        services = [list(row) for row in conn.execute("SELECT * FROM service ORDER BY id")]
    # Owned synthetic DB bodies only. Production will only use explicit owned row projections.
    return {
        "rows": rows,
        "services": services,
        "main": fs(DB),
        "sidecars": {str(DB) + suffix: fs(Path(str(DB) + suffix)) for suffix in ("-wal", "-shm")},
    }


def deploy(
    label: str,
    config: Any,
    *,
    nyxmon: bool = False,
    zero: bool = False,
    failure: bool = False,
    fish: bool = False,
    secret: str | None = None,
) -> dict[str, Any]:
    snap = db_snapshot if nyxmon else endpoint_snapshot
    before = snap()
    commands: list[str] = []
    uploads: list[bool] = []
    original = LocalConnector.run_shell_command
    put = LocalConnector.put_file

    def traced(connector: Any, command: Any, **kwargs: Any) -> Any:
        raw = command if isinstance(command, str) else str(command.get_raw_value())
        commands.append(raw)
        if fish:
            command = "fish -c " + shlex.quote(shlex.join(["sh", "-c", raw]))
        return original(connector, command, **kwargs)

    def uploaded(*args: Any, **kwargs: Any) -> Any:
        uploads.append(True)
        return put(*args, **kwargs)

    state = State(Inventory(([("@local", {})], {})), Config())
    error = None
    with patch.object(LocalConnector, "run_shell_command", traced), patch.object(LocalConnector, "put_file", uploaded):
        try:
            connect_all(state)
            add_deploy(
                state,
                deploy_os_apt_maintenance_nyxmon if nyxmon else deploy_os_apt_maintenance,
                cfg=config,
                secrets=SecretValues(REF, {"endpoint_password": VALUE if secret is None else secret}),
            )
            run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
    after = snap()
    managed = [op.name for op in operations if op.changed and not op.read_only]
    result = {
        "label": label,
        "managed": managed,
        "uploads": len(uploads),
        "error": error,
        "before": before,
        "after": after,
        "operations": [asdict(op) for op in operations],
        "fish_transport": fish,
        "commands": len(commands),
    }
    write(label + ".json", result)
    PHASES.append({key: result[key] for key in ("label", "managed", "uploads", "error", "fish_transport")})
    assert bool(error) is failure, result
    if not failure:
        assert all(op.succeeded for op in operations), result
    if zero:
        assert not managed, result
        assert not uploads, result
        # SQLite sidecar bookkeeping is observed, not a global physical no-op assertion.
        for key in before.keys() - {"sidecars"}:
            assert before[key] == after[key], (label, key, before[key], after[key])
        assert not any("daemon-reload" in cmd or "systemctl start fixture-apt.service" in cmd for cmd in commands)
    print(label, len(managed), "managed", len(uploads), "uploads", flush=True)
    return result


def health(secret: str = "") -> dict[str, Any]:
    request = urllib.request.Request("http://127.0.0.1:19106/.well-known/os-apt-maintenance")
    if secret:
        request.add_header("Authorization", "Basic " + base64.b64encode(("fixture:" + secret).encode()).decode())
    for retry in range(30):
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = json.load(response)
                assert body["host_id"] == "owned-fixture", body
                return {
                    "status": response.status,
                    "host": body["host_id"],
                    "last_run_ok": body["summary"]["last_run_ok"],
                }
        except urllib.error.HTTPError as exc:
            if not secret:
                if exc.code != 401:
                    raise AssertionError(f"unexpected anonymous HTTP status {exc.code}") from exc
                return {"status": exc.code}
            raise
        except urllib.error.URLError:
            if retry == 29:
                raise
            time.sleep(0.2)
    raise AssertionError("no HTTP response")


def ansible_repeat(config: OsAptMaintenanceConfig) -> None:
    import yaml

    variables = role_vars(config, "127.0.0.1")
    for name in (
        "enabled",
        "run_on_deploy",
        "run_on_first_deploy",
        "timer_enabled",
        "timer_state",
        "refresh_enabled",
        "refresh_timer_enabled",
        "refresh_timer_state",
    ):
        variables["os_apt_maintenance_" + name] = getattr(config, name)
    variables.update(
        {
            "os_apt_maintenance_endpoint_service_name": config.service_name,
            "os_apt_maintenance_endpoint_htpasswd_dir": str(config.htpasswd_dir),
            "os_apt_maintenance_endpoint_auth_user": "fixture",
            "os_apt_maintenance_endpoint_auth_password": VALUE,
            "os_apt_maintenance_endpoint_impl": config.httpd_impl,
            "metrics_httpd_rust_version": RUST_VERSION,
            "metrics_httpd_rust_sha256": RUST_SHA,
            "ansible_python_interpreter": "/usr/bin/python3",
        }
    )
    path = ROOT / "ansible.yml"
    path.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "gather_facts": True,
                    "vars": variables,
                    "roles": ["local.ops_library.os_apt_maintenance"],
                }
            ]
        )
    )
    path.chmod(0o600)
    before = endpoint_snapshot()
    try:
        output = sh(
            str(Path(sys.executable).parent / "ansible-playbook"),
            "-i",
            "localhost,",
            "-c",
            "local",
            str(path),
            env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "collections")},
        )
    finally:
        path.unlink()
    (EVIDENCE / "ansible-repeat.log").write_text(output)
    assert "changed=0" in output, output
    after = endpoint_snapshot()
    # Ansible intentionally daemon-reloads, but current role resources/state/PID must remain exact.
    assert before == after, {"before": before, "after": after}
    write(
        "ansible-repeat.json",
        {"library_sha": sh("git", "-C", str(LIBRARY), "rev-parse", "HEAD"), "unchanged": True, "reported_changed": 0},
    )


def nyxmon() -> None:
    sh("useradd", "--system", "--home-dir", str(ROOT / "nyxmon"), "--shell", "/usr/sbin/nologin", "fixture-nyxmon")
    DB.parent.mkdir()
    with closing(sqlite3.connect(DB)) as conn:
        conn.executescript(
            "CREATE TABLE service (id INTEGER PRIMARY KEY, name TEXT);"
            "CREATE TABLE health_check (id INTEGER PRIMARY KEY, name TEXT, service_id INT, check_type TEXT, url TEXT,"
            " check_interval INT, status TEXT, next_check_time INT, processing_started_at INT,"
            " disabled INT, data TEXT);"
            "INSERT INTO service VALUES(99,'Unrelated');"
            "INSERT INTO health_check VALUES(99,'Unrelated',99,'http','http://fixture.invalid',99,'processing',123,456,1,'{}');"
        )
        conn.commit()
    sh("chown", "-R", "fixture-nyxmon:fixture-nyxmon", str(DB.parent))
    DB.chmod(0o600)
    config = OsAptNyxmonConfig.model_validate(
        {
            "secrets": str(REF),
            "user": "fixture-nyxmon",
            "site_path": str(DB.parent),
            "db_path": str(DB),
            "targets": [
                {"display_name": name, "url": f"http://100.64.0.{index}:9106/.well-known/os-apt-maintenance"}
                for index, name in enumerate(("one", "two", "three", "four"), 1)
            ],
        }
    )
    deploy("nyxmon-first", config, nyxmon=True)
    deploy("nyxmon-repeat", config, nyxmon=True, zero=True)
    with closing(sqlite3.connect(DB)) as conn:
        conn.execute(
            "UPDATE health_check SET disabled=1,status='processing',next_check_time=123,"
            "processing_started_at=456 WHERE id!=99"
        )
        conn.commit()
    deploy("nyxmon-disabled-current", config, nyxmon=True, zero=True)
    changed = config.model_copy(update={"check_interval": 1800})
    result = deploy("nyxmon-owned-update", changed, nyxmon=True)
    assert len(result["managed"]) == 1
    with closing(sqlite3.connect(DB)) as conn:
        assert (
            list(
                conn.execute(
                    "SELECT status,next_check_time,processing_started_at,disabled FROM health_check WHERE id!=99"
                )
            )
            == [("processing", 123, 456, 0)] * 4
        )
        assert conn.execute("SELECT disabled,check_interval FROM health_check WHERE id=99").fetchone() == (1, 99)
    deploy("nyxmon-update-repeat", changed, nyxmon=True, zero=True, fish=True)
    missing = config.model_copy(update={"db_path": ROOT / "missing.sqlite3"})
    deploy("nyxmon-missing-db", missing, nyxmon=True, zero=True)


def main() -> None:
    for name in ("fake-apt", "fake-systemctl"):
        target = ROOT / name
        event = ROOT / ("apt-events" if name == "fake-apt" else "reboot-events")
        target.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> ' + shlex.quote(str(event)) + "\nexit 0\n")
        target.chmod(0o755)
    write(
        "platform.json",
        {
            "os_release": Path("/etc/os-release").read_text(),
            "kernel": sh("uname", "-r"),
            "systemd": sh("systemctl", "--version"),
            "impl": os.environ["FIXTURE_IMPL"],
            "scope": os.environ["FIXTURE_SCOPE"],
        },
    )
    config = cfg()
    result = deploy("endpoint-fresh", config)
    assert result["managed"]
    events = (ROOT / "apt-events").read_text().splitlines()
    assert len(events) == 4, events
    assert [
        next(action for action in ("update", "dist-upgrade", "autoremove", "autoclean") if action in event.split())
        for event in events
    ] == ["update", "dist-upgrade", "autoremove", "autoclean"]
    assert not (ROOT / "reboot-events").exists()
    write("http-first.json", {"anonymous": health(), "authenticated": health(VALUE)})
    deploy("endpoint-repeat", config, zero=True, fish=True)
    ansible_repeat(config)
    deploy("endpoint-after-ansible", config, zero=True)
    timer = cfg(timer_on_calendar="2099-01-02 04:00:00")
    result = deploy("timer-change", timer)
    assert result["before"]["pid"] == result["after"]["pid"]
    deploy("timer-repeat", timer, zero=True)
    result = deploy("credential-rotation", timer, secret="owned-rotated-password")
    assert result["before"]["pid"] != result["after"]["pid"]
    write("http-rotated.json", health("owned-rotated-password"))
    deploy("credential-repeat", timer, zero=True, secret="owned-rotated-password")
    deploy("credential-restore", timer)
    # Inject the actual loaded-but-unlinked timer condition, without daemon-reload.
    Path("/etc/systemd/system/fixture-apt-refresh.timer").unlink()
    Path("/etc/systemd/system/fixture-apt-refresh.service").unlink()
    assert sh("systemctl", "is-active", "fixture-apt-refresh.timer") == "active"
    off = timer.model_copy(update={"refresh_enabled": False})
    deploy("refresh-off-unlinked", off)
    assert sh("systemctl", "is-active", "fixture-apt-refresh.timer", check=False) != "active"
    deploy("refresh-off-repeat", off, zero=True)
    deploy("refresh-restore", timer)
    deploy("refresh-restored-repeat", timer, zero=True)
    before_events = (ROOT / "apt-events").read_bytes()
    (ROOT / "state/state.json").unlink()
    deploy("missing-state-no-maintenance", timer.model_copy(update={"run_on_first_deploy": False}))
    assert (ROOT / "apt-events").read_bytes() == before_events
    deploy("missing-state-repeat", timer.model_copy(update={"run_on_first_deploy": False}), zero=True)
    assert (ROOT / "apt-events").read_text().splitlines() == events
    nyxmon()


try:
    main()
except BaseException:
    (EVIDENCE / "failure.txt").write_text(traceback.format_exc())
    raise
finally:
    write("summary.json", {"phases": PHASES})
