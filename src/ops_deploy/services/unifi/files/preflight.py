"""Read-only host probe. Payload/child output stay in memory; stdout is a status only.

Only a private temporary mongosh HOME is created and removed. No Mongo writes or authentication toggles occur; password hashes stay in memory. mongosh consumes its JavaScript over stdin, without credentials in
argv. A malformed/failed command is a refusal, never an absent-resource signal.
"""

from __future__ import annotations

import ctypes
import datetime
import grp
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run(args: list[str], *, stdin: str | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args, input=stdin, text=True, capture_output=True, timeout=45, check=True,
        env=env or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    return result.stdout.strip()


class Refusal(ValueError):
    """An operator-facing fixed label, never a raw exception or data value."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def matches_password(password: str, hashed: str) -> bool:
    # crypt is absent from Python >=3.13, but Ubuntu's libcrypt remains available.
    # No subprocess command line or stdout carries the hash/password.
    if not re.fullmatch(r"\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}", hashed):
        return False
    library = ctypes.CDLL("libcrypt.so.1")
    library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.crypt.restype = ctypes.c_char_p
    answer = library.crypt(password.encode(), hashed.encode())
    return answer is not None and answer.decode() == hashed


def javascript(payload: dict[str, Any]) -> str:
    # JSON encoding prevents JavaScript injection; --file suppresses interactive echo.
    return (
        'if (config.get("disableLogging") !== true || config.get("enableTelemetry") !== false || '
        'config.get("updateURL") !== "") quit(19);\n'
        'const a=db.getSiblingDB("admin");\n'
        f'if (!a.auth("unifi", {json.dumps(payload["mongodb_password"])})) quit(20);\n'
        'const opts=a.runCommand({getCmdLineOpts:1});\n'
        'if (opts.ok !== 1) quit(21);\n'
        'const parameters=a.runCommand({getParameter:1,suppressNoTLSPeerCertificateWarning:1,diagnosticDataCollectionEnabled:1});\n'
        'if (parameters.ok !== 1) quit(22);\n'
        'const u=db.getSiblingDB("unifi");\n'
        f'const ha=u.admin.findOne({{name:{json.dumps(payload["homeassistant_username"])}}});\n'
        'const site=u.site.findOne({name:"default"});\n'
        'const privileges=ha && site ? u.privilege.find({'
        'admin_id:{$in:[ha._id,ha._id.toString()]},site_id:{$in:[site._id,site._id.toString()]}}).toArray() : [];\n'
        'print("OPS_UNIFI="+JSON.stringify({opts:opts.parsed,parameters:parameters,ha:ha,site:!!site,privileges:privileges}));\n'
    )


def check(payload: dict[str, Any]) -> None:
    require(os.geteuid() == 0, "root_connection_required")
    release = dict(
        line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line
    )
    require(release.get("ID", "").strip('"') in {"debian", "ubuntu"}, "unsupported_os")
    if payload.get("routine"):
        require(release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_CODENAME", "").strip('"') == "noble", "routine_requires_ubuntu_noble")
    require(run(["uname", "-m"]) == "x86_64", "unsupported_architecture")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "systemd_required")
    route = run(["ip", "-4", "route", "get", "8.8.8.8"])
    source = re.search(r"\bsrc ([0-9.]+)\b", route)
    require(source is not None and source.group(1) == payload["controller_bind_address"], "controller_address_drift")
    try:
        installed = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}|${Version}", "unifi"])
    except subprocess.CalledProcessError as error:
        require(payload.get("routine") and error.returncode == 1 and not error.stdout, "package_query_failed")
        installed = "absent"
    fresh_runtime = payload.get("routine") and installed == "absent"
    require(
        installed == "absent" or bool(re.fullmatch(r"ii \|[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[0-9]+", installed))
        if payload.get("routine") else installed == f'ii |{payload["installed_package_version"]}',
        "installed_version_mismatch_use_ansible",
    )
    if payload.get("routine") and not fresh_runtime:
        comparison = subprocess.run(["dpkg", "--compare-versions", payload["selected_package_version"],
                                     "lt", installed.removeprefix("ii |")], capture_output=True)
        require(comparison.returncode == 1, "controller_downgrade_or_comparison_failed")
    if fresh_runtime:
        require(not Path("/var/lib/unifi").exists() and not Path("/var/lib/unifi").is_symlink()
                and not Path("/usr/lib/unifi").exists() and not Path("/usr/lib/unifi").is_symlink(), "unpackaged_controller_data_present")
    else:
        require(Path("/usr/lib/unifi/lib/ace.jar").is_file(), "installation_missing_use_ansible")
    if not payload.get("routine"):
        require(Path("/usr/lib/jvm/java-17-openjdk-amd64/bin/java").is_file(), "java17_required")
    try:
        account = pwd.getpwnam("unifi")
    except KeyError:
        require(fresh_runtime, "unifi_user_missing")
    else:
        require(account.pw_gid == grp.getgrnam("unifi").gr_gid, "unifi_group_drift")
        require(account.pw_dir == "/home/unifi" and account.pw_shell == "/usr/sbin/nologin", "unifi_user_drift")
    if not fresh_runtime:
        for path in ("/usr/lib/unifi/data", "/usr/lib/unifi/logs", "/usr/lib/unifi/run"):
            require(Path(path).is_dir(), "installation_layout_missing_use_ansible")
    for path in ("/etc/unifi-secrets", "/etc/traefik/dynamic"):
        item = Path(path)
        require(not item.is_symlink(), "managed_directory_symlink")
        require(not item.exists() or item.is_dir(), "managed_directory_not_directory")
    for path in (
        "/etc/systemd/system/unifi.service", "/etc/unifi-secrets/mongodb.jvmargs",
        "/etc/logrotate.d/mongodb", "/etc/cron.daily/mongodb-log-check", "/etc/traefik/dynamic/unifi.yml",
    ):
        item = Path(path)
        require(not item.is_symlink(), "managed_file_symlink")
        require(not item.exists() or item.is_file(), "managed_file_not_regular")
    # A legacy unit with an inline Mongo URI would expose the old password in
    # pyinfra --diff. Have Ansible migrate that unit before using this port.
    unit = Path("/etc/systemd/system/unifi.service")
    require(unit.is_file() or fresh_runtime, "custom_unit_missing_use_ansible")
    require(not unit.is_file() or "mongodb://" not in unit.read_text(), "legacy_inline_credentials_use_ansible")
    require(run(["systemctl", "is-active", "mongod.service"]) == "active", "mongodb_not_active")
    require(run(["systemctl", "is-enabled", "mongod.service"]) == "enabled", "mongodb_not_enabled")
    # A running config is insufficient if a previous run left newer, unapplied
    # MongoDB settings. Refuse a pending MongoDB restart instead of applying it.
    timestamp = run(["systemctl", "show", "--timestamp=us+utc", "-p", "ActiveEnterTimestamp", "--value", "mongod.service"])
    start = datetime.datetime.strptime(timestamp, "%a %Y-%m-%d %H:%M:%S.%f UTC").replace(tzinfo=datetime.timezone.utc)
    if not payload.get("routine"):
        require(Path("/etc/mongod.conf").stat().st_mtime_ns <= int(start.timestamp() * 1_000_000_000), "mongodb_pending_restart")
    check_mongodb_state(mongodb_state(payload), payload)
    if payload["manage_firewall"]:
        run(["ufw", "show", "added"])


def mongodb_state(payload: dict[str, Any]) -> dict[str, Any]:
    # mongosh normally creates per-user logs/config. Isolate all such state
    # under a unique 0700 HOME, preload non-secret settings, and always remove
    # it. Even check mode has this ephemeral client footprint; DB reads only.
    with tempfile.TemporaryDirectory(prefix="ops-unifi-probe-") as home:
        directory = Path(home) / ".mongodb" / "mongosh"
        directory.mkdir(parents=True, mode=0o700)
        config = directory / "config"
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"disableLogging": True, "enableTelemetry": False, "updateURL": ""}, stream)
        answer = run(
            ["mongosh", "--quiet", "--norc", "--host", "127.0.0.1", "--port", "27017", "--file", "/dev/stdin"],
            stdin=javascript(payload),
            env={"HOME": home, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    records = [line.removeprefix("OPS_UNIFI=") for line in answer.splitlines() if line.startswith("OPS_UNIFI=")]
    require(len(records) == 1, "mongodb_probe_invalid")
    return json.loads(records[0])


def check_mongodb_state(state: dict[str, Any], payload: dict[str, Any]) -> None:
    opts = state["opts"]
    require(opts.get("security", {}).get("authorization") == "enabled", "mongodb_auth_config_drift")
    net = opts.get("net", {})
    require(net.get("bindIp") == "127.0.0.1" and net.get("port", 27017) == 27017, "mongodb_bind_config_drift")
    if payload.get("routine"):
        return
    log = opts.get("systemLog", {})
    require(log.get("quiet") is True and log.get("verbosity", 0) == 0, "mongodb_logging_config_drift")
    parameters = state["parameters"]
    require(
        parameters.get("suppressNoTLSPeerCertificateWarning") is True
        and parameters.get("diagnosticDataCollectionEnabled") is False,
        "mongodb_parameter_drift",
    )
    if payload["create_homeassistant_user"]:
        if payload.get("routine_verify") and not state["site"]:
            return
        require(state["site"] is True, "ha_default_site_missing_use_ansible")
        ha = state["ha"]
        require(isinstance(ha, dict), "ha_user_missing_use_ansible")
        require(
            matches_password(payload["homeassistant_password"], ha.get("x_shadow", "")),
            "ha_password_drift_use_ansible",
        )
        privileges = state["privileges"]
        # The role writes ObjectId foreign keys; native UniFi installations may
        # use strings. Both are read, but an inconsistent duplicate is refused
        # rather than accepting whichever findOne happened to return first.
        require(
            isinstance(privileges, list) and bool(privileges)
            and all(isinstance(item, dict) and item.get("role") == "readonly"
                    and item.get("permissions") == [] for item in privileges),
            "ha_privilege_drift_use_ansible",
        )
        store = Path("/home/unifi/.homeassistant_unifi_password")
        require(not store.is_symlink() and store.is_file(), "ha_password_store_invalid_use_ansible")
        info = store.stat()
        require(
            info.st_mode & 0o7777 == 0o600 and info.st_uid == pwd.getpwnam("unifi").pw_uid
            and info.st_gid == grp.getgrnam("unifi").gr_gid,
            "ha_password_store_permissions_use_ansible",
        )
        require(store.read_text() == payload["homeassistant_password"], "ha_password_store_drift_use_ansible")

def main() -> int:
    try:
        check(json.load(sys.stdin))
    except Refusal as error:
        # Only our fixed status labels; JSON errors can contain input excerpts.
        status = str(error)
        if re.fullmatch(r"[a-z0-9_]+", status):
            print("refused:" + status)
        else:
            print("refused:invalid_probe_data")
        return 1
    except Exception:
        # Never display child stdout/stderr, JSON or exception strings with credentials.
        print("refused:preflight_failed_use_ansible")
        return 1
    print("ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
