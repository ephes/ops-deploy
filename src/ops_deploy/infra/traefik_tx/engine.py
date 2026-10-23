"""Fail-closed Traefik binary transactions on a Linux host. Requests are trusted operator policy.

A port of ops-library's transaction engine (``roles/traefik_deploy/files/traefik_transaction.py``
at 3110a0f1) for the actions ``inspect``, ``binary`` and ``resume``, plus ``rebaseline``, which
only this engine has. It runs on the host as
root, with the standard library only, under ``/usr/bin/python3`` 3.11 or newer::

    python3 engine.py --request request.json

and prints one JSON object. Exit 0: done (``changed`` says whether anything was written);
1: the transaction failed and was rolled back (``state.phase`` is ``recovery``) or the
rollback did not verify (``degraded``); 2: refused or an error, with ``error``.

``rebaseline`` reconciles route-only drift without a review: when the record is ``clear`` and
the live identity differs from it only in ``dynamic_sha256`` (the ``/etc/traefik/dynamic``
tree that service deploys rewrite), and the baseline probe passes, it writes a new ``clear``
record for the live identity. Any other drift and any other phase stay with a reviewed
``resume``.

It keeps the reference engine's state directory, lock, record schema, request format and
refusal messages, so records written by either engine load unchanged in the other, both
serialize on the same lock, and the controller journal pairs with either one.
``enroll``, ``alias``, ``metrics_bind`` and ``acme_storage`` are not ported: they are
refused before anything is read or written and stay with the Ansible path.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
import uuid
import zlib
from pathlib import Path, PurePosixPath
from typing import Any

STATE_ROOT = Path("/var/lib/traefik-transactions")
LOCK = Path("/run/lock/traefik-transaction.lock")
# The reference engine's actions; only PORTED run here.
ACTIONS = ("inspect", "enroll", "binary", "alias", "metrics_bind", "acme_storage", "resume")
PORTED = ("inspect", "binary", "resume")
# Actions only this engine has; the reference engine refuses them as unknown.
OWN = ("rebaseline",)
# Per-file digests of the route tree at the last rebaseline, the basis for the next one's file list.
ROUTE_INVENTORY = "route-inventory.json"
PHASES = frozenset({"clear", "pending", "recovery", "degraded"})


class Refused(RuntimeError):
    """An invariant or acceptance check did not pass."""


def require(ok: object, message: str) -> None:
    if not ok:
        raise Refused(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(argv: list[str], timeout: int = 30) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    require(result.returncode == 0, f"command failed: {Path(argv[0]).name} (exit {result.returncode})")
    return result.stdout


def atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Replace ``path`` with ``data`` through a synced temporary file in the same directory."""

    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save(path: Path, value: Any) -> None:
    atomic(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def trusted_file(path: Path) -> None:
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022,
        f"not a root-owned, non-writable regular file: {path}",
    )
    for parent in path.parents:
        info = parent.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, f"unsafe parent: {parent}")


def load_state(path: Path) -> dict[str, Any] | None:
    """The host record, or ``None`` before enrollment."""

    if not path.exists():
        require(not path.is_symlink(), "dangling state symlink")
        return None
    trusted_file(path)
    value = json.loads(path.read_text())
    # The reference engine fails with AttributeError on a record that is not an object.
    require(
        isinstance(value, dict) and value.get("schema") == 1 and value.get("phase") in PHASES,
        "invalid recovery state",
    )
    state: dict[str, Any] = value
    return state


def version(path: Path) -> tuple[int, int, int]:
    match = re.search(r"^Version:\s+v?(\d+)\.(\d+)\.(\d+)\s*$", run([str(path), "version"]), re.MULTILINE)
    if match is None:
        raise Refused("unparseable Traefik version")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def route_files(root: Path) -> list[tuple[str, str]]:
    """Relative path and SHA256 of every file below ``root``, sorted; symlinks are refused."""

    require(root.is_dir() and not root.is_symlink(), f"expected ordinary directory: {root}")
    items = []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"symlink in managed configuration: {path}")
        if path.is_file():
            trusted_file(path)
            items.append((str(path.relative_to(root)), digest(path)))
    return items


def inventory_tree(root: Path) -> str:
    """Digest of every file below ``root`` (relative path and content); symlinks are refused."""

    return canonical(route_files(root))


def validate_arguments(args: list[bytes], binary: Path, config: Path) -> None:
    require(len(args) == 2 and args[0] == os.fsencode(binary), "unsupported effective startup arguments")
    key, separator, value = args[1].partition(b"=")
    require(
        separator == b"=" and key.lower() == b"--configfile" and value == os.fsencode(config),
        "unsupported effective startup arguments",
    )


def main_pid() -> int:
    return int(run(["systemctl", "show", "traefik.service", "-p", "MainPID", "--value"]).strip())


def identity(policy: dict[str, Any]) -> dict[str, Any]:
    """Content identity of the installed and running Traefik; refuses anything unmanaged."""

    binary, config = Path(policy["binary_path"]), Path(policy["config_path"])
    trusted_file(binary)
    trusted_file(config)
    static_config = tomllib.loads(config.read_text())
    providers = static_config.get("providers", {})
    require(
        set(providers) == {"file"}
        and providers["file"].get("directory") == policy["dynamic_path"]
        and not providers["file"].get("filename"),
        "only the approved directory file provider is supported",
    )
    pid = main_pid()
    require(pid > 1, "Traefik is not running")
    proc = Path(f"/proc/{pid}")
    require(os.readlink(proc / "exe") == str(binary), "running executable path differs from managed path")
    args = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    validate_arguments(args, binary, config)
    env = (proc / "environ").read_bytes().split(b"\0")
    require(not any(item.startswith(b"TRAEFIK_") for item in env), "Traefik environment overrides are unsupported")
    binary_hash = digest(binary)
    require(digest(proc / "exe") == binary_hash, "running/installed executable hash drift")
    unit = run(["systemctl", "cat", "traefik.service"])
    result = {
        "machine_id": Path("/etc/machine-id").read_text().strip(),
        "binary_path": str(binary),
        "binary_sha256": binary_hash,
        "version": ".".join(map(str, version(binary))),
        "config_path": str(config),
        "config_sha256": digest(config),
        "dynamic_sha256": inventory_tree(Path(policy["dynamic_path"])),
        "unit_sha256": hashlib.sha256(unit.encode()).hexdigest(),
    }
    require(main_pid() == pid, "Traefik restarted during observation")
    return result


def state_for(policy: dict[str, Any], phase: str, live: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "schema": 1,
        "host": policy["host"],
        "phase": phase,
        "identity": live,
        "revision": str(uuid.uuid4()),
        "updated_at": int(time.time()),
        **fields,
    }


def validate_policy(policy: dict[str, Any]) -> None:
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,62}", policy["host"]), "invalid canonical host")
    for key in ["binary_path", "config_path", "dynamic_path"]:
        path = Path(policy[key])
        require(path.is_absolute() and ".." not in path.parts and str(path) == policy[key], f"invalid {key}")
    require(policy["binary_path"] in ["/usr/bin/traefik", "/usr/local/bin/traefik"], "unsupported binary location")
    require(policy["config_path"] == "/etc/traefik/traefik.toml", "unsupported static config source")
    require(policy["dynamic_path"] == "/etc/traefik/dynamic", "unsupported dynamic provider directory")


def evidence(request: dict[str, Any], live: dict[str, Any]) -> None:
    """Fresh operator evidence tied to the exact live identity."""

    proof = request["evidence"]
    require(proof["baseline"] == live, "reviewed baseline does not match live state")
    age = time.time() - proof["verified_at"]
    require(0 <= age <= 3600, "preflight evidence must be at most one hour old")
    # The legacy ``console_recovery`` counts only when ``recovery_access`` is absent.
    recovery = proof.get("recovery_access", proof.get("console_recovery"))
    require(
        isinstance(recovery, str) and bool(recovery.strip()) and "CHANGEME" not in recovery,
        "missing evidence: recovery_access",
    )
    for key in ["owner", "review_reference", "independent_observer", "observer_delivery_test"]:
        require(
            isinstance(proof.get(key), str) and proof[key].strip() and "CHANGEME" not in proof[key],
            f"missing evidence: {key}",
        )
    require(proof.get("observer_watch_active") is True, "independent observer must be watching")


def check_probe(spec: dict[str, Any]) -> None:
    """Run a root-owned probe program whose exact SHA256 the request approves."""

    argv = spec["argv"]
    require(
        isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv),
        "invalid probe command",
    )
    path = Path(argv[0])
    require(path.is_absolute(), "probe executable must be absolute")
    trusted_file(path)
    require(digest(path) == spec["sha256"], "probe program identity changed")
    run(argv, timeout=120)


def candidate_binary(archive: Path, checksum: str, destination: Path, target: str) -> Path:
    """The release's ``traefik`` executable as ``destination/candidate``, checksum and version checked."""

    require(re.fullmatch(r"[0-9a-f]{64}", checksum), "exact SHA256 is required")
    require(digest(archive) == checksum, "release archive checksum mismatch")
    require(re.fullmatch(r"3\.\d+\.\d+", target), "unsupported release")
    with tarfile.open(archive) as bundle:
        members = [member for member in bundle.getmembers() if member.name == "traefik"]
        require(
            len(members) == 1 and members[0].isfile() and 0 < members[0].size < 512 * 1024 * 1024,
            "archive must contain one bounded regular traefik executable",
        )
        stream = bundle.extractfile(members[0])
        if stream is None:  # a regular member always has a stream
            raise Refused("archive must contain one bounded regular traefik executable")
        output = destination / "candidate"
        atomic(output, stream.read(), 0o755)
    require(version(output) == tuple(map(int, target.split("."))), "candidate version mismatch")
    return output


def backup(policy: dict[str, Any], directory: Path) -> None:
    """``prechange.tar.gz`` of the configured rollback set, which must cover binary, config and unit."""

    paths = policy["backup_paths"]
    required = {policy["binary_path"], "/etc/traefik", "/etc/systemd/system/traefik.service"}
    if Path("/etc/letsencrypt").exists():
        required.add("/etc/letsencrypt")
    if Path("/etc/systemd/system/traefik.service.d").exists():
        required.add("/etc/systemd/system/traefik.service.d")
    require(required.issubset(set(paths)), "backup set omits binary, config, unit or external certificates")
    require(set(policy["acme_paths"]).issubset(set(paths)), "backup set omits approved active ACME stores")
    require(all(Path(p).is_absolute() and ".." not in Path(p).parts for p in paths), "invalid backup path")
    # An ACME target that does not exist yet (before its adoption) is the only allowed gap.
    require(all(Path(p).exists() or p == policy.get("acme_target") for p in paths), "required backup path absent")
    paths = [p for p in paths if Path(p).exists()]
    archive = directory / "prechange.tar.gz"
    run(["tar", "--acls", "--xattrs", "--numeric-owner", "-czf", str(archive), "--", *paths], timeout=120)
    save(directory / "backup.json", {"paths": paths, "sha256": digest(archive)})


def restart_verify(
    policy: dict[str, Any], expected: dict[str, Any], probe: dict[str, Any], cleanup: dict[str, Any]
) -> dict[str, Any]:
    """Restart, wait for ``expected`` to run, then probe; cleanup runs even when the probe fails."""

    run(["systemctl", "restart", "traefik.service"], timeout=60)
    last: Exception | None = None
    for _ in range(15):
        try:
            live = identity(policy)
            require(live == expected, "post-start identity differs from expected state")
            break
        except (Refused, OSError, ValueError, subprocess.SubprocessError) as exc:
            last = exc
            time.sleep(1)
    else:
        raise Refused("post-start identity verification failed") from last
    try:
        check_probe(probe)
    finally:
        check_probe(cleanup)
    require(identity(policy) == expected, "identity changed during acceptance probe")
    return live


def resume(
    request: dict[str, Any], policy: dict[str, Any], state: dict[str, Any], live: dict[str, Any], state_path: Path
) -> dict[str, Any]:
    """Reviewed reconciliation: a new clear record for the live identity once the baseline probe passes."""

    require(
        state["phase"] in ["clear", "recovery", "degraded", "pending"],
        "resume requires an explicit recovery record",
    )
    require(request.get("recovery_review_reference"), "reviewed recovery reference required")
    check_probe(request["baseline_probe"])
    resumed = state_for(
        policy,
        "clear",
        live,
        owner=request["evidence"]["owner"],
        resumed_from=state["revision"],
        recovery_review_reference=request["recovery_review_reference"],
    )
    save(state_path, resumed)
    return {"changed": True, "state": resumed}


def recorded_route_files(dynamic_sha256: str) -> list[tuple[str, str]] | None:
    """The route files the last rebaseline saw, if they are exactly the tree ``dynamic_sha256`` names."""

    path = STATE_ROOT / ROUTE_INVENTORY
    try:
        if not path.exists():
            return None
        trusted_file(path)
        value = json.loads(path.read_text())
    except (OSError, ValueError, Refused):
        return None
    files = value.get("files") if isinstance(value, dict) else None
    if not isinstance(files, list) or not all(
        isinstance(item, list) and len(item) == 2 and all(isinstance(part, str) for part in item) for item in files
    ):
        return None
    if canonical(files) != dynamic_sha256:
        return None
    return [(name, sha) for name, sha in files]


def archived_route_files(record: dict[str, Any], dynamic: str) -> list[tuple[str, str]] | None:
    """The route files in the record's transaction ``prechange.tar.gz``, if they are its exact tree.

    A ``clear`` record from ``binary`` names its transaction directory, whose archive holds
    ``/etc/traefik`` as it was when that record's identity was taken.
    """

    transaction = record.get("transaction")
    if not isinstance(transaction, str):
        return None
    directory = Path(transaction)
    uuid_name = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    if str(directory.parent) != str(STATE_ROOT) or not re.fullmatch(uuid_name, directory.name):
        return None
    prefix = dynamic.lstrip("/") + "/"
    files: dict[str, str] = {}
    try:
        archive = directory / "prechange.tar.gz"
        trusted_file(archive)
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                if member.isfile() and member.name.startswith(prefix):
                    stream = bundle.extractfile(member)
                    if stream is None:
                        return None
                    content = hashlib.sha256()
                    while chunk := stream.read(1 << 20):
                        content.update(chunk)
                    files[member.name[len(prefix) :]] = content.hexdigest()
    except (OSError, EOFError, ValueError, tarfile.TarError, zlib.error, Refused):
        return None
    # In ``route_files`` order: by path components, as ``sorted`` orders paths ("a/b" before "a.yml").
    items = sorted(files.items(), key=lambda item: PurePosixPath(item[0]))
    return items if canonical(items) == record["identity"]["dynamic_sha256"] else None


def rebaseline(
    request: dict[str, Any], policy: dict[str, Any], state: dict[str, Any], live: dict[str, Any], state_path: Path
) -> dict[str, Any]:
    """Route-only reconciliation: a new clear record when only the dynamic tree differs and the baseline passes."""

    require(state["phase"] == "clear", "rebaseline requires a clear record; anything else needs a reviewed resume")
    recorded = state["identity"]
    require(isinstance(recorded, dict) and isinstance(recorded.get("dynamic_sha256"), str), "invalid recovery state")
    drift = sorted(
        key for key in set(recorded) | set(live) if key != "dynamic_sha256" and recorded.get(key) != live.get(key)
    )
    require(not drift, f"rebaseline reconciles route drift only; also differs: {', '.join(drift)}")
    require(recorded.get("dynamic_sha256") != live["dynamic_sha256"], "no route drift to rebaseline")
    check_probe(request["baseline_probe"])
    files = route_files(Path(policy["dynamic_path"]))
    require(canonical(files) == live["dynamic_sha256"], "route tree changed during rebaseline")
    require(identity(policy) == live, "identity changed during rebaseline probe")
    basis, before = "route_inventory", recorded_route_files(recorded["dynamic_sha256"])
    if before is None:
        basis, before = "prechange_archive", archived_route_files(state, policy["dynamic_path"])
    if before is None:
        basis = "unavailable"
    changed: dict[str, list[str]] | None = None
    if before is not None:
        old, new = dict(before), dict(files)
        changed = {
            "added": sorted(new.keys() - old.keys()),
            "modified": sorted(name for name in old.keys() & new.keys() if old[name] != new[name]),
            "removed": sorted(old.keys() - new.keys()),
        }
    # The inventory first: one that does not match the record it follows is ignored next time.
    save(STATE_ROOT / ROUTE_INVENTORY, {"dynamic_sha256": live["dynamic_sha256"], "files": files})
    rebaselined = state_for(
        policy,
        "clear",
        live,
        owner=request["evidence"]["owner"],
        rebaselined_from=state["revision"],
        rebaseline={
            "previous_dynamic_sha256": recorded["dynamic_sha256"],
            "dynamic_sha256": live["dynamic_sha256"],
            "changed_files": changed,
            "changed_files_basis": basis,
            "review_reference": request["evidence"]["review_reference"],
        },
    )
    save(state_path, rebaselined)
    return {"changed": True, "state": rebaselined}


def replace_binary(
    request: dict[str, Any], policy: dict[str, Any], state: dict[str, Any], live: dict[str, Any], state_path: Path
) -> dict[str, Any]:
    """Replace only the executable; roll back to the original on any failure."""

    require(state["phase"] == "clear" and state["identity"] == live, "active recovery or unreviewed baseline drift")
    check_probe(request["baseline_probe"])
    compatibility = request["compatibility"]
    require(
        compatibility["baseline"] == live and compatibility["architecture"] == os.uname().machine,
        "isolated preflight must match baseline and native architecture",
    )
    require(
        compatibility.get("passed") is True
        and compatibility.get("baseline_pair_passed") is True
        and compatibility.get("report_reference"),
        "isolated preflight proof required",
    )
    directory = STATE_ROOT / str(uuid.uuid4())
    directory.mkdir(mode=0o700)
    save(directory / "request.json", request)
    expected = dict(live)
    target = request["release"]["version"]
    require(
        tuple(map(int, target.split("."))) >= tuple(map(int, live["version"].split("."))),
        "ordinary downgrade refused",
    )
    candidate = candidate_binary(Path(request["archive_path"]), request["release"]["sha256"], directory, target)
    expected["binary_sha256"], expected["version"] = digest(candidate), target
    require(
        compatibility["candidate_binary_sha256"] == expected["binary_sha256"], "candidate differs from isolated test"
    )
    require(
        compatibility["candidate_config_sha256"] == live["config_sha256"],
        "binary-only operation must preserve static config",
    )
    destination = Path(policy["binary_path"])
    if expected == live:
        try:
            check_probe(request["acceptance_probe"])
        finally:
            check_probe(request["cleanup_probe"])
        require(identity(policy) == live, "identity changed during no-op verification")
        return {"changed": False, "state": state}
    backup(policy, directory)
    original = directory / "original"
    shutil.copy2(destination, original)
    mode = stat.S_IMODE(destination.stat().st_mode)
    require(identity(policy) == live, "baseline changed during preparation")
    pending = state_for(
        policy,
        "pending",
        live,
        owner=request["evidence"]["owner"],
        operation="binary",
        transaction=str(directory),
        intended_identity=expected,
        previous_revision=state["revision"],
    )
    save(state_path, pending)
    replaced = False
    try:
        replaced = True
        atomic(destination, candidate.read_bytes(), mode)
        accepted = restart_verify(policy, expected, request["acceptance_probe"], request["cleanup_probe"])
        complete = state_for(policy, "clear", accepted, owner=request["evidence"]["owner"], transaction=str(directory))
        save(state_path, complete)
        return {"changed": True, "state": complete}
    except BaseException as failure:
        # Interrupted operations are recovered too; the journal stays active for review.
        recovery = state_for(
            policy,
            "recovery",
            live,
            owner=request["evidence"]["owner"],
            transaction=str(directory),
            reason=type(failure).__name__,
            review_due=int(time.time()) + 3600,
        )
        try:
            cleanup_failure: BaseException | None = None
            try:
                check_probe(request["cleanup_probe"])
            except BaseException as exc:
                cleanup_failure = exc
            if replaced:
                atomic(destination, original.read_bytes(), mode)
                restart_verify(policy, live, request["baseline_probe"], request["cleanup_probe"])
            if cleanup_failure is not None:
                raise cleanup_failure
            recovery["identity"] = identity(policy)
        except BaseException as restore_failure:
            # Any interrupted or unverified recovery is degraded.
            recovery["phase"] = "degraded"
            recovery["recovery_error"] = type(restore_failure).__name__
        save(state_path, recovery)
        return {"changed": replaced, "failed": True, "state": recovery}


def execute(request: dict[str, Any]) -> dict[str, Any]:
    policy, action = request["policy"], request["action"]
    validate_policy(policy)
    require(action in ACTIONS or action in OWN, "unknown action")
    require(
        action in PORTED or action in OWN,
        f"action not ported to ops-deploy, use the Ansible transaction path: {action}",
    )
    state_path = STATE_ROOT / "state.json"
    if action == "inspect":
        return {"identity": identity(policy), "state": load_state(state_path)}
    require(os.geteuid() == 0, "root is required")
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(
        not STATE_ROOT.is_symlink()
        and STATE_ROOT.stat().st_uid == 0
        and stat.S_IMODE(STATE_ROOT.stat().st_mode) == 0o700,
        "unsafe state directory",
    )
    with LOCK.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = load_state(state_path)
        live = identity(policy)
        evidence(request, live)
        supplied = request.get("controller_state")
        require(state == supplied, "controller and host recovery records disagree")
        if state is None or state["host"] != policy["host"]:
            raise Refused("missing or wrong host enrollment")
        if action == "resume":
            return resume(request, policy, state, live, state_path)
        if action == "rebaseline":
            return rebaseline(request, policy, state, live, state_path)
        return replace_binary(request, policy, state, live, state_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Guarded Traefik binary transaction (inspect, binary, resume, rebaseline)."
    )
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        request = json.loads(args.request.read_text())
        result = execute(request)
        print(json.dumps(result, sort_keys=True))
        return 1 if result.get("failed") else 0
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"failed": True, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
