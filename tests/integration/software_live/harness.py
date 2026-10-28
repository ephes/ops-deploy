"""Owned systemd, released binary, operational observation and SQLite qualification."""

from __future__ import annotations

import base64
import contextlib
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
from collections.abc import Callable
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
from ops_deploy.services.software_live import (
    SoftwareLiveConfig,
    SoftwareLiveNyxmonConfig,
    SoftwareLiveRemoveConfig,
    compare_software_live_shadow,
    deploy_software_live,
    deploy_software_live_nyxmon,
    remove_software_live,
)
from ops_deploy.services.software_live.common import PRODUCTION, SHADOW
from ops_deploy.testing.harness import collect_ops

ROOT = Path("/opt/software-live-fixture")
EVIDENCE = Path(sys.argv[1])
LIBRARY = ROOT / "collections/ansible_collections/local/ops_library"
REF = SecretRef("fixture.yml")
VALUE = secrets.token_urlsafe(24)
PHASES: list[dict[str, Any]] = []
DB = ROOT / "nyxmon/db.sqlite3"
RELEASE = Path("/usr/local/lib/software-live/releases")
STATE_FILE = Path("/var/lib/software-live/state.json")
UNITS = (*PRODUCTION, *SHADOW)
SHA = {
    "ubuntu24.04": "65be5aa98574b73f87e385610d4fa9ffebad99d4ecf64238991abeef5662fc10",
    "debian13": "502663e0d25bdb750996801c28bc6dfc8d5e5b5e7bc0910c89d2cb62d889aec4",
}


def sh(*args: str, check: bool = True, **kwargs: Any) -> str:
    result = subprocess.run(args, text=True, capture_output=True, timeout=900, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-1500:]}")
    return str(result.stdout).strip()


def write(name: str, value: Any) -> None:
    (EVIDENCE / name).write_text(json.dumps(value, indent=2, default=str))


def cfg(*, os_release: Path = Path("/etc/os-release"), **changes: Any) -> SoftwareLiveConfig:
    os_info = dict(line.split("=", 1) for line in os_release.read_text().splitlines() if "=" in line)
    distro, version = os_info["ID"].strip('"'), os_info["VERSION_ID"].strip('"')
    return SoftwareLiveConfig.model_validate(
        {
            "secrets": str(REF),
            "auth_user": "fixture",
            "bind": "127.0.0.1",
            "policy": {
                "host": "owned-fixture",
                "os": {"expected_id": distro, "desired_cycle": version, "product": distro},
                "postgresql": {"expected": False},
                "traefik": {
                    "expected": False,
                    "unit": "traefik.service",
                    "binary_path": "/usr/local/bin/traefik",
                    "desired_version": None,
                },
            },
            "impl": os.environ["FIXTURE_IMPL"],
            "rust_version": "0.1.1",
            "rust_sha256": SHA,
            # Real fixed unit names in a disposable guest; only calendar is moved
            # out of the observation window. Actual role schedules have byte parity.
            "on_calendar": "2099-01-01 04:00:00",
            "shadow_on_calendar": "2099-01-01 06:00:00",
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


def settle() -> None:
    for _ in range(100):
        states = [
            sh("systemctl", "show", unit, "-p", "ActiveState", "--value", check=False)
            for unit in ("software-live-collector.service", "software-live-shadow-collector.service")
        ]
        if not any(state in ("activating", "deactivating", "reloading", "refreshing") for state in states):
            return
        time.sleep(1)
    raise AssertionError("owned collectors did not settle")


def snapshot() -> dict[str, Any]:
    roots = [Path(p) for p in ("/etc/software-live", "/var/lib/software-live", "/usr/local/lib/software-live")]
    roots += list(Path("/etc/systemd/system").glob("software-live*"))
    roots += list(Path("/etc/systemd/system/timers.target.wants").glob("software-live*"))
    roots += list(Path("/etc/systemd/system/multi-user.target.wants").glob("software-live*"))
    files = {}
    for root in roots:
        files[str(root)] = fs(root)
        if root.is_dir():
            files.update({str(p): fs(p) for p in root.rglob("*")})
    return {
        "files": files,
        "units": {
            unit: sh(
                "systemctl",
                "show",
                unit,
                "-p",
                "MainPID",
                "-p",
                "ActiveState",
                "-p",
                "UnitFileState",
                "-p",
                "ActiveEnterTimestampMonotonic",
                check=False,
            )
            for unit in UNITS
        },
        "packages": sh("dpkg-query", "-W", "-f=${Package}=${Version}\n"),
        "apt_policy": {str(p): fs(p) for p in Path("/etc/apt").rglob("*") if p.is_file()},
        "reboot_flag": fs(Path("/var/run/reboot-required")),
    }


def database_snapshot() -> dict[str, Any]:
    if not DB.exists():
        return {"main": None, "rows": None, "sidecars": {}}
    with contextlib.closing(sqlite3.connect(f"file:{DB}?mode=ro", uri=True)) as db:
        rows = [list(row) for row in db.execute("SELECT * FROM health_check ORDER BY id")]
        services = [list(row) for row in db.execute("SELECT * FROM service ORDER BY id")]
    return {
        "main": fs(DB),
        "rows_digest": hashlib.sha256(json.dumps([rows, services]).encode()).hexdigest(),
        "sidecars": {suffix: fs(Path(str(DB) + suffix)) for suffix in ("-wal", "-shm")},
    }


def deploy(
    label: str,
    config: Any,
    *,
    mode: str = "endpoint",
    zero: bool = False,
    failure: bool = False,
    fish: bool = False,
    secret: str | None = None,
) -> dict[str, Any]:
    settle()
    snap = database_snapshot if mode == "nyxmon" else snapshot
    before = snap()
    uploads = []
    operations = []
    error = None
    original = LocalConnector.run_shell_command
    put = LocalConnector.put_file

    def command(connector: Any, command: Any, **kwargs: Any) -> Any:
        raw = command if isinstance(command, str) else str(command.get_raw_value())
        if fish:
            command = "fish -c " + shlex.quote(shlex.join(["sh", "-c", raw]))
        return original(connector, command, **kwargs)

    def uploaded(*args: Any, **kwargs: Any) -> Any:
        uploads.append(True)
        return put(*args, **kwargs)

    functions: dict[str, Callable[..., Any]] = {
        "endpoint": deploy_software_live,
        "nyxmon": deploy_software_live_nyxmon,
        "shadow": compare_software_live_shadow,
        "remove": remove_software_live,
    }
    state = State(Inventory(([("@local", {})], {})), Config())
    with (
        patch.object(LocalConnector, "run_shell_command", command),
        patch.object(LocalConnector, "put_file", uploaded),
        (EVIDENCE / (label + ".log")).open("w") as stream,
        contextlib.redirect_stdout(stream),
        contextlib.redirect_stderr(stream),
    ):
        try:
            connect_all(state)
            kwargs = (
                {}
                if mode == "remove"
                else {"secrets": SecretValues(REF, {"endpoint_password": VALUE if secret is None else secret})}
            )
            add_deploy(state, functions[mode], cfg=config, **kwargs)
            run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
    settle()
    after = snap()
    managed = [op.name for op in operations if op.changed and not op.read_only]
    failed = [op.name for op in operations if not op.succeeded]
    result = {
        "label": label,
        "mode": mode,
        "managed": managed,
        "uploads": len(uploads),
        "failed_operations": failed,
        "error": error,
        "before": before,
        "after": after,
        "operations": [asdict(op) for op in operations],
        "fish_transport": fish,
        "classification": "expected-injected-failure" if failure else "healthy",
    }
    write(label + ".json", result)
    PHASES.append(
        {
            key: result[key]
            for key in ("label", "mode", "managed", "uploads", "failed_operations", "error", "classification")
        }
    )
    assert bool(error or failed) == failure, result
    if zero:
        assert not managed, result
        assert not uploads, result
        assert not failed, result
        if mode == "nyxmon":
            assert before["main"] == after["main"], result
            assert before["rows_digest"] == after["rows_digest"], result
        else:
            assert before == after, result
    return result


def health(secret: str = VALUE) -> dict[str, Any]:
    url = "http://127.0.0.1:9110/.well-known/software-live"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        opener.open(url, timeout=10)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise AssertionError("unexpected anonymous HTTP status") from error
    else:
        raise AssertionError("endpoint allowed anonymous access")
    request = urllib.request.Request(
        url, headers={"Authorization": "Basic " + base64.b64encode(("fixture:" + secret).encode()).decode()}
    )
    with opener.open(request, timeout=10) as response:
        data = json.load(response)
    assert data["schema_version"] == 2
    assert data["host"] == "owned-fixture"
    assert data["summary"]["fresh"]
    assert data["os"]["observed"]
    assert data["postgresql"]["observed"]
    return {"schema_version": 2, "host": data["host"], "fresh": True, "anonymous_status": 401}


def ansible(config: SoftwareLiveConfig) -> None:
    import yaml

    variables = {
        "software_live_" + key: value
        for key, value in config.model_dump(mode="json").items()
        if key not in ("secrets", "service_name", "site_path")
    }
    variables.update(software_live_auth_password=VALUE, ansible_python_interpreter="/usr/bin/python3")
    variables.pop("software_live_rust_local_archive", None)
    variables.pop("software_live_rust_version_check_user", None)
    if not config.rust_release_url:
        variables.pop("software_live_rust_release_url", None)
    path = ROOT / "ansible.yml"
    path.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars": variables,
                    "roles": ["local.ops_library.software_live"],
                }
            ]
        )
    )
    path.chmod(0o600)
    settle()
    before = snapshot()
    try:
        result = subprocess.run(
            [str(Path(sys.executable).parent / "ansible-playbook"), "-i", "localhost,", "-c", "local", str(path)],
            env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "collections")},
            text=True,
            capture_output=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired as exc:
        (EVIDENCE / "ansible.log").write_text(str(exc.stdout or "").replace(VALUE, "<fixture-password>"))
        (EVIDENCE / "ansible.stderr").write_text(str(exc.stderr or "").replace(VALUE, "<fixture-password>"))
        raise
    finally:
        path.unlink()
    (EVIDENCE / "ansible.log").write_text(result.stdout.replace(VALUE, "<fixture-password>"))
    (EVIDENCE / "ansible.stderr").write_text(result.stderr.replace(VALUE, "<fixture-password>"))
    settle()
    after = snapshot()
    write(
        "ansible.json",
        {
            "returncode": result.returncode,
            "before": before,
            "after": after,
            "limit": (
                "Original Ansible always collects despite changed_when=false; "
                "state rewriting is expected, not physical no-op."
            ),
        },
    )
    assert result.returncode == 0, "Original Ansible failed; retained output"
    assert before["packages"] == after["packages"]
    assert before["apt_policy"] == after["apt_policy"]
    assert before["files"][str(STATE_FILE)] != after["files"][str(STATE_FILE)]
    assert health()


def nyxmon() -> None:
    DB.parent.mkdir(mode=0o750)
    sh("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "fixture-nyxmon")
    with sqlite3.connect(DB) as db:
        db.executescript(
            "CREATE TABLE service(id INTEGER PRIMARY KEY,name TEXT UNIQUE);"
            "CREATE TABLE health_check(id INTEGER PRIMARY KEY,name TEXT,service_id INTEGER,check_type TEXT,url TEXT,"
            "check_interval INTEGER,data TEXT,status TEXT,next_check_time INTEGER,"
            "processing_started_at INTEGER,disabled INTEGER);"
        )
    sh("chown", "-R", "fixture-nyxmon:fixture-nyxmon", str(DB.parent))
    config = SoftwareLiveNyxmonConfig(
        secrets=REF,
        user="fixture-nyxmon",
        db_path=str(DB),
        auth_user="fixture",
        targets=({"host_id": "owned-fixture", "url": "http://127.0.0.1:9110/.well-known/software-live"},),
    )
    deploy("nyxmon-create", config, mode="nyxmon")
    with sqlite3.connect(DB) as db:
        db.execute("UPDATE health_check SET status='critical',next_check_time=123,processing_started_at=456")
    deploy("nyxmon-repeat", config, mode="nyxmon", zero=True)
    with sqlite3.connect(DB) as db:
        db.execute("UPDATE health_check SET disabled=1")
    deploy("nyxmon-reenable", config, mode="nyxmon")
    with sqlite3.connect(DB) as db:
        assert db.execute(
            "SELECT status,next_check_time,processing_started_at,disabled FROM health_check"
        ).fetchone() == ("critical", 0, 456, 0)
    deploy("nyxmon-reenabled-repeat", config, mode="nyxmon", zero=True, fish=True)
    disable = config.model_copy(update={"disable_names": ("Software health (owned-fixture)",)})
    deploy("nyxmon-disable", disable, mode="nyxmon")
    deploy("nyxmon-disabled-repeat", disable, mode="nyxmon", zero=True)


def main() -> None:
    write(
        "platform.json",
        {
            "uname": sh("uname", "-a"),
            "os_release": Path("/etc/os-release").read_text(),
            "systemd": sh("systemctl", "--version"),
            "scope": os.environ["FIXTURE_SCOPE"],
            "limits": (
                "Debian13 userspace shares runner kernel. "
                "No inventory, credentials, data or sockets mounted. No upgrade/reboot jobs."
            ),
        },
    )
    config = cfg()
    deploy("first", config)
    write("health.json", health())
    deploy("repeat", config, zero=True)
    deploy("fish-repeat", config, zero=True, fish=True)
    ansible(config)
    deploy("after-ansible", config, zero=True)
    # Synthetic operational state age; collector still executes its real read-only probes.
    stale = json.loads(STATE_FILE.read_text())
    stale["generated_at_epoch"] = time.time() - 1900
    STATE_FILE.write_text(json.dumps(stale))
    before_pid = sh("systemctl", "show", "software-live-endpoint.service", "-p", "MainPID", "--value")
    result = deploy("stale-state", config)
    assert result["managed"] == ["Deploy software live | Collect a changed or stale software observation"]
    assert before_pid == sh("systemctl", "show", "software-live-endpoint.service", "-p", "MainPID", "--value")
    deploy("stale-recovery-repeat", config, zero=True)
    STATE_FILE.unlink()
    deploy("missing-state", config)
    deploy("missing-recovery-repeat", config, zero=True)
    changed = cfg(policy={**config.policy, "apt_max_age_seconds": 172799})
    result = deploy("policy-change", changed)
    assert before_pid == sh("systemctl", "show", "software-live-endpoint.service", "-p", "MainPID", "--value")
    assert len(result["managed"]) == 2
    deploy("policy-repeat", changed, zero=True)
    deploy("policy-recover", config)
    rotated = secrets.token_urlsafe(24)
    deploy("credential-rotation", config, secret=rotated)
    health(rotated)
    deploy("credential-rotation-repeat", config, secret=rotated, zero=True)
    deploy("credential-recover", config)
    # Both matrix legs execute the released Rust implementation and real shadow endpoint.
    rust = cfg(impl="rust")
    deploy("rust-switch", rust)
    deploy("rust-repeat", rust, zero=True)
    shadow = cfg(impl="python", rust_shadow=True)
    deploy("python-with-shadow", shadow)
    deploy("shadow-compare", shadow, mode="shadow", zero=True)
    deploy("shadow-repeat", shadow, zero=True)
    deploy("rust-with-shadow", cfg(impl="rust", rust_shadow=True))
    bad = cfg(impl="python", rust_shadow=True, rust_version="invalid")
    pins = {str(p): fs(p) for p in (RELEASE / ".pins").rglob("*")}
    deploy("invalid-shadow-rollback", bad, failure=True)
    assert not Path("/etc/systemd/system/software-live-endpoint.service.d/impl.conf").exists()
    pid = sh("systemctl", "show", "software-live-endpoint.service", "-p", "MainPID", "--value")
    assert b"software_live.py" in Path("/proc", pid, "cmdline").read_bytes()
    assert pins == {str(p): fs(p) for p in (RELEASE / ".pins").rglob("*")}
    deploy("rollback-recover", cfg(impl="python"))
    deploy("rollback-repeat", cfg(impl="python"), zero=True)
    nyxmon()
    remove = SoftwareLiveRemoveConfig()
    deploy("remove-keep-data", remove, mode="remove")
    assert STATE_FILE.exists()
    deploy("remove-repeat", remove, mode="remove", zero=True)
    deploy("remove-data", SoftwareLiveRemoveConfig(remove_data=True), mode="remove")
    assert not STATE_FILE.parent.exists()
    deploy("removed-data-repeat", SoftwareLiveRemoveConfig(remove_data=True), mode="remove", zero=True)


try:
    main()
except Exception:
    (EVIDENCE / "failure.txt").write_text(traceback.format_exc().replace(VALUE, "<fixture-password>"))
    raise
finally:
    write("summary.json", PHASES)
    (EVIDENCE / "systemd-journal.log").write_text(
        sh(
            "journalctl",
            "--no-pager",
            "-n",
            "350",
            "-u",
            "software-live-collector.service",
            "-u",
            "software-live-endpoint.service",
            check=False,
        ).replace(VALUE, "<fixture-password>")
    )
