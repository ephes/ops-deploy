"""Target-local persistent network admission/activation; no configuration body output.

Check is read-only. Apply is an explicitly managed configuration/recovery action,
including temporary native validation and possible networkd reconnection. The
controller owns the bounded transient systemd job; no adoption marker is used.
"""

import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

CONFIG = Path("/etc/netplan/99-ops-library.yaml")
MARKER = b"Managed by local.ops_library.netplan_config"
LIMIT = 1024 * 1024
SYS_NET = Path("/sys/class/net")
NETPLAN_SEARCH = (
    (Path("/etc/netplan"), "etc/netplan"),
    (Path("/run/netplan"), "run/netplan"),
    (Path("/lib/netplan"), "lib/netplan"),
)


class Refused(Exception):
    pass


def run(argv, *, allowed=(0,), timeout=120):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused("native network command unavailable or timed out") from error
    if proc.returncode not in allowed or len(proc.stdout) > LIMIT or len(proc.stderr) > LIMIT:
        # Native parsing errors may include unowned config values: never echo them.
        raise Refused("native network command failed")
    return proc.returncode, proc.stdout


def regular(path):
    path = Path(path)
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise Refused("symlink parent in a managed network path")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
        raise Refused("network target must be a bounded ordinary single-link file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_ino != info.st_ino or not stat.S_ISREG(opened.st_mode):
            raise Refused("network target changed before open")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(body) > LIMIT or any(
        getattr(info, k) != getattr(after, k) for k in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    ):
        raise Refused("network target changed during admission")
    return info, body


def unit(name):
    _, text = run(
        ["systemctl", "show", name, "-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState", "-p", "Result"],
        allowed=(0, 1),
    )
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    if "LoadState" not in values:
        raise Refused("native unit metadata missing")
    return values


def guard_paths(cfg):
    name = cfg["route_guard"]["service_name"]
    return [
        Path(cfg["route_guard"]["script_path"]),
        Path("/etc/systemd/system") / (name + ".service"),
        Path("/etc/systemd/system") / (name + ".timer"),
    ]


def runtime_state(guard):
    runtime = Path("/run") / guard["service_name"]
    try:
        info = runtime.lstat()
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(info.st_mode):
        raise Refused("route guard runtime path is not an ordinary directory")
    pending = stat.S_IMODE(info.st_mode) != 0o700 or (info.st_uid, info.st_gid) != (0, 0)
    lock = runtime / "lock"
    try:
        info = lock.lstat()
    except FileNotFoundError:
        return pending
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refused("route guard lock is not an ordinary single-link file")
    return pending or bool(info.st_mode & 0o022) or (info.st_uid, info.st_gid) != (0, 0)


def carrier_state(name):
    try:
        value = (SYS_NET / name / "carrier").read_text().strip()
    except OSError as error:
        try:
            state = (SYS_NET / name / "operstate").read_text().strip()
        except OSError:
            raise Refused("configured interface carrier metadata is unavailable") from error
        if state in ("down", "dormant", "lowerlayerdown", "notpresent"):
            return False
        raise Refused("configured interface carrier metadata is unavailable") from error
    if value not in ("0", "1"):
        raise Refused("configured interface carrier value is invalid")
    return value == "1"


def route_rows(argv):
    _, text = run(argv)
    value = json.loads(text)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise Refused("interface route metadata is malformed")
    return value


def interface_health(interface, strict):
    carrier = carrier_state(interface["name"])
    if not carrier:
        if strict:
            raise Refused("strict static interface has no carrier; recovery not attempted")
        return dict(repair=False, pending=False, dhcp=False)
    _, text = run(["networkctl", "status", "--json=short", interface["name"]])
    value = json.loads(text)
    setup = value.get("AdministrativeState") if isinstance(value, dict) else None
    if setup not in ("configured", "failed", "unmanaged", "linger", "pending", "initialized", "configuring"):
        raise Refused("unsupported networkd setup state")
    routes = route_rows(["ip", "-j", "-4", "route", "show", "default", "dev", interface["name"]])
    wants = any(
        row["to"] in ("default", "0.0.0.0/0") and ipaddress.ip_address(row["via"]).version == 4
        for row in interface["routes"]
    )
    # Periodic recovery intentionally leaves active configuration alone; final
    # convergence must still wait for its declared route and configured state.
    repair = setup == "failed" or (wants and not routes and setup in ("configured", "unmanaged", "linger"))
    pending = (wants and (not routes or setup != "configured")) or (strict and setup != "configured")
    return dict(repair=repair, pending=pending, dhcp=any(row.get("protocol") == "dhcp" for row in routes))


def recovery_interfaces(cfg):
    all_interfaces = cfg["apply"] and cfg["reconfigure_interfaces"] or cfg.get("single_static_default")
    return [
        interface
        for interface in cfg["interfaces"]
        if all_interfaces or (cfg["route_guard"]["enabled"] and interface["name"] in cfg["route_guard"]["interfaces"])
    ]


def inspect(cfg):
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise Refused("netplan requires the existing root/systemd connection")
    for tool in ("netplan", "systemctl", "ip"):
        if shutil.which(tool) is None:
            raise Refused("required native network tool is absent")
    resources = cfg["resources"]
    expected_paths = {str(CONFIG)} | ({str(p) for p in guard_paths(cfg)} if cfg["route_guard"]["enabled"] else set())
    if set(resources) != expected_paths:
        raise Refused("network resource set does not match its declared paths")
    pending = []
    try:
        directory = CONFIG.parent.lstat()
    except FileNotFoundError:
        directory = None
    if directory is not None and not stat.S_ISDIR(directory.st_mode):
        raise Refused("netplan directory is not an ordinary directory")
    if directory is None or stat.S_IMODE(directory.st_mode) != 0o755 or (directory.st_uid, directory.st_gid) != (0, 0):
        pending.append("config_directory")
    network_changed = False
    guard_changed = False
    for path in guard_paths(cfg):
        old = regular(path)
        if old is not None and MARKER not in old[1]:
            raise Refused("unowned route guard target; no overwrite or removal")
        if not cfg["route_guard"]["enabled"] and old is not None:
            pending.append("remove_guard")
    for path, value in resources.items():
        old = regular(path)
        desired = value["content"].encode()
        if (
            old is None
            or old[1] != desired
            or stat.S_IMODE(old[0].st_mode) != int(value["mode"], 8)
            or (old[0].st_uid, old[0].st_gid) != (0, 0)
        ):
            pending.append("resource")
            network_changed |= path == str(CONFIG)
            guard_changed |= path != str(CONFIG)
    for name in cfg["cleanup_files"]:
        path = Path(name)
        if path.parent != CONFIG.parent or path == CONFIG:
            raise Refused("cleanup must name other direct netplan files")
        # Removing an explicit symlink does not follow it; reject directories/devices.
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            raise Refused("cleanup target is not a file or symlink")
        pending.append("cleanup")
        network_changed = True
    guard = cfg["route_guard"]
    if (guard["enabled"] or regular(guard_paths(cfg)[2]) is not None) and runtime_state(guard):
        pending.append("guard_runtime")
    timer = unit(guard["service_name"] + ".timer")
    if guard["enabled"] and (
        timer.get("LoadState") != "loaded"
        or timer.get("ActiveState") != "active"
        or timer.get("UnitFileState") != "enabled"
    ):
        pending.append("guard_timer")
    if not guard["enabled"] and timer.get("LoadState") != "not-found" and timer.get("ActiveState") == "active":
        pending.append("disable_guard")
    dhcp = False
    health_repair = False
    health_pending = False
    targets = recovery_interfaces(cfg)
    if cfg["renderer"] == "networkd" and targets:
        if shutil.which("networkctl") is None:
            raise Refused("requested networkd inspection tool is absent")
        for interface in targets:
            health = interface_health(interface, cfg.get("single_static_default", False))
            dhcp |= health["dhcp"]
            health_repair |= health["repair"]
            health_pending |= health["pending"]
        if cfg.get("single_static_default"):
            all_routes = route_rows(["ip", "-j", "-4", "route", "show", "default"])
            primary = cfg["interfaces"][0]
            gateway = next(row["via"] for row in primary["routes"] if row["to"] in ("default", "0.0.0.0/0"))
            mismatch = len(all_routes) != 1 or any(
                row.get("gateway") != gateway or row.get("dev") != primary["name"] or row.get("protocol") == "dhcp"
                for row in all_routes
            )
            if mismatch and not carrier_state(primary["name"]):
                raise Refused("strict static route drift has no carrier; recovery not attempted")
            health_repair |= mismatch
    if guard["enabled"]:
        service = unit(guard["service_name"] + ".service")
        if service.get("Result") not in ("success", None):
            pending.append("guard_service")
    if health_repair or health_pending or (cfg.get("single_static_default") and dhcp):
        pending.append("network_health")
    return {
        "state": "pending" if pending else "current",
        "pending": sorted(set(pending)),
        "network_changed": network_changed,
        "guard_changed": guard_changed,
        "health_repair": health_repair,
        "dhcp_before": dhcp,
    }


def publish(path, content, mode):
    path = Path(path)
    old = regular(path)
    if old is not None and old[1] == content:
        if stat.S_IMODE(old[0].st_mode) != mode:
            os.chmod(path, mode, follow_symlinks=False)
        if (old[0].st_uid, old[0].st_gid) != (0, 0):
            os.chown(path, 0, 0, follow_symlinks=False)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".ops-deploy-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if old is not None:
            # Preserve ACL/security metadata as the original atomic template writer.
            shutil.copystat(path, temporary, follow_symlinks=False)
        os.chown(temporary, 0, 0)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_candidate(cfg):
    # Native validation writes only its private temporary tree, never in check.
    with tempfile.TemporaryDirectory(prefix="ops-deploy-netplan-") as temporary:
        for source_root, relative in NETPLAN_SEARCH:
            # /lib is the distribution's usr-merge alias. Resolve this known
            # native input root only; all entries still require ordinary files.
            source_root = source_root.resolve()
            target_root = Path(temporary) / relative
            target_root.mkdir(parents=True, mode=0o700)
            if not source_root.exists():
                continue
            if not source_root.is_dir():
                raise Refused("native netplan search root is not a directory")
            for source in source_root.iterdir():
                if source.suffix not in (".yaml", ".yml"):
                    continue
                if relative == "etc/netplan" and str(CONFIG.parent / source.name) in set(cfg["cleanup_files"]) | {
                    str(CONFIG)
                }:
                    continue
                old = regular(source)
                if old is None:
                    raise Refused("existing network input disappeared during validation")
                staged = target_root / source.name
                staged.write_bytes(old[1])
                staged.chmod(0o600)
        target = Path(temporary) / "etc/netplan"
        (target / CONFIG.name).write_text(cfg["resources"][str(CONFIG)]["content"])
        (target / CONFIG.name).chmod(0o600)
        run(["netplan", "generate", "--root-dir", temporary])


def guard_start_timeout(guard):
    return 90 + (guard["confirmation_delay_sec"] + guard["recovery_delay_sec"]) * len(guard["interfaces"])


def apply(cfg):
    before = inspect(cfg)
    if before["state"] == "current":
        return {**before, "changed": False}
    guard = cfg["route_guard"]
    paths = guard_paths(cfg)
    had_timer = regular(paths[2]) is not None
    runtime = Path("/run") / guard["service_name"]
    # The existing periodic guard and this action serialize the same native writes.
    locked = guard["enabled"] or had_timer
    descriptor = None
    if locked:
        runtime_state(guard)
        runtime.mkdir(mode=0o700, exist_ok=True)
        runtime.chmod(0o700)
        os.chown(runtime, 0, 0, follow_symlinks=False)
        if runtime.is_symlink() or not runtime.is_dir():
            raise Refused("route guard runtime path is not an ordinary directory")
        descriptor = os.open(runtime / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(descriptor)
            raise Refused("route guard lock is not an ordinary single-link file")
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        # Nonblocking refusal keeps the native periodic guard ownership intact.
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise Refused("existing route guard holds the network lock") from error
    try:
        # Re-admit after taking the original lock, before any persistent write.
        before = inspect(cfg)
        if before["network_changed"]:
            validate_candidate(cfg)
        CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        CONFIG.parent.chmod(0o755)
        os.chown(CONFIG.parent, 0, 0, follow_symlinks=False)
        units_changed = False
        timer_changed = False
        for path, value in cfg["resources"].items():
            old = regular(path)
            mode = int(value["mode"], 8)
            changed = (
                old is None
                or old[1] != value["content"].encode()
                or stat.S_IMODE(old[0].st_mode) != mode
                or (old[0].st_uid, old[0].st_gid) != (0, 0)
            )
            if changed:
                publish(path, value["content"].encode(), mode)
                units_changed |= path.endswith((".service", ".timer"))
                timer_changed |= path.endswith(".timer")
        for path in cfg["cleanup_files"]:
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass
        if units_changed:
            run(["systemctl", "daemon-reload"])
        if before["network_changed"]:
            run(["netplan", "generate"])
            if cfg["apply"]:
                run(["netplan", "apply"], timeout=180)
        repair = before["network_changed"] or before["health_repair"]
        if cfg["apply"] and cfg["reconfigure_interfaces"] and cfg["renderer"] == "networkd" and repair:
            for interface in cfg["interfaces"]:
                run(["networkctl", "reconfigure", interface["name"]])
        if cfg["apply"] and cfg.get("single_static_default"):
            _, text = run(["ip", "-j", "-4", "route", "show", "default", "dev", cfg["interfaces"][0]["name"]])
            after_dhcp = any(row.get("protocol") == "dhcp" for row in json.loads(text))
            if before["dhcp_before"] or after_dhcp:
                run(["systemctl", "restart", "systemd-networkd"], timeout=240)
        if guard["enabled"]:
            if timer_changed or (before["network_changed"] and had_timer):
                run(["systemctl", "restart", guard["service_name"] + ".timer"])
            run(["systemctl", "enable", guard["service_name"] + ".timer"])
            if unit(guard["service_name"] + ".timer").get("ActiveState") != "active":
                run(["systemctl", "start", guard["service_name"] + ".timer"])
        else:
            if regular(paths[2]) is not None:
                run(["systemctl", "disable", "--now", paths[2].name])
            if regular(paths[1]) is not None:
                run(["systemctl", "stop", paths[1].name])
            for path in paths:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            if had_timer or "remove_guard" in before["pending"]:
                run(["systemctl", "daemon-reload"])
    finally:
        if descriptor is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
    # The original service takes this lock itself: never exercise it while held.
    if guard["enabled"] and (
        before["network_changed"]
        or before["guard_changed"]
        or before["health_repair"]
        or "guard_timer" in before["pending"]
        or "guard_service" in before["pending"]
    ):
        run(
            ["systemctl", "start", guard["service_name"] + ".service"],
            timeout=guard_start_timeout(guard),
        )
    after = inspect(cfg)
    # Original Fractal verification allows ten 2-second readiness intervals.
    for _ in range(9):
        if after["state"] == "current":
            break
        time.sleep(2)
        after = inspect(cfg)
    if after["state"] != "current":
        raise Refused("network activation/recovery did not converge")
    return {**after, "changed": True}


def main():
    action = sys.argv[1]
    cfg = json.loads(base64.b64decode(sys.argv[2])) if len(sys.argv) == 3 else json.load(sys.stdin)
    if action in ("check", "verify"):
        result = inspect(cfg)
        if action == "verify" and result["state"] != "current":
            raise Refused("persistent network verification is not current")
    elif action == "apply":
        result = apply(cfg)
    else:
        raise Refused("unknown network action")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        print(
            json.dumps(
                {
                    "state": "refused",
                    "reason": str(error)
                    if isinstance(error, Refused)
                    else "native network metadata or payload is invalid",
                }
            )
        )
        raise SystemExit(0 if len(sys.argv) > 1 and sys.argv[1] == "check" else 2) from None
