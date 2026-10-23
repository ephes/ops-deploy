#!/usr/bin/env python3
"""Fail-closed Linux Traefik transactions. Requests are trusted operator policy."""

from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
import uuid
from pathlib import Path
from typing import Any

STATE_ROOT = Path("/var/lib/traefik-transactions")
LOCK = Path("/run/lock/traefik-transaction.lock")


class Refused(RuntimeError):
    """An invariant or acceptance check did not pass."""


def require(ok: Any, message: str) -> None:
    if not ok:
        raise Refused(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(argv: list[str], timeout: int = 30, **kwargs: Any) -> str:
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False, **kwargs
    )
    require(
        result.returncode == 0,
        f"command failed: {Path(argv[0]).name} (exit {result.returncode})",
    )
    return result.stdout


def atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
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
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_gid == 0
        and not info.st_mode & 0o022,
        f"not a root-owned, non-writable regular file: {path}",
    )
    for parent in path.parents:
        info = parent.stat()
        require(
            info.st_uid == 0 and not info.st_mode & 0o022, f"unsafe parent: {parent}"
        )


def load_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        require(not path.is_symlink(), "dangling state symlink")
        return None
    trusted_file(path)
    value = json.loads(path.read_text())
    require(
        value.get("schema") == 1
        and value.get("phase") in {"clear", "pending", "recovery", "degraded"},
        "invalid recovery state",
    )
    return value


def version(path: Path) -> tuple[int, int, int]:
    match = re.search(
        r"^Version:\s+v?(\d+)\.(\d+)\.(\d+)\s*$",
        run([str(path), "version"]),
        re.MULTILINE,
    )
    require(match is not None, "unparseable Traefik version")
    assert match is not None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def inventory_tree(root: Path) -> str:
    require(
        root.is_dir() and not root.is_symlink(), f"expected ordinary directory: {root}"
    )
    items = []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"symlink in managed configuration: {path}")
        if path.is_file():
            trusted_file(path)
            items.append((str(path.relative_to(root)), digest(path)))
    return canonical(items)


def validate_arguments(args: list[bytes], binary: Path, config: Path) -> None:
    require(
        len(args) == 2 and args[0] == os.fsencode(binary),
        "unsupported effective startup arguments",
    )
    key, separator, value = args[1].partition(b"=")
    require(
        separator == b"="
        and key.lower() == b"--configfile"
        and value == os.fsencode(config),
        "unsupported effective startup arguments",
    )


def identity(policy: dict[str, Any]) -> dict[str, Any]:
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
    pid = int(
        run(
            ["systemctl", "show", "traefik.service", "-p", "MainPID", "--value"]
        ).strip()
    )
    require(pid > 1, "Traefik is not running")
    proc = Path(f"/proc/{pid}")
    require(
        os.readlink(proc / "exe") == str(binary),
        "running executable path differs from managed path",
    )
    args = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    validate_arguments(args, binary, config)
    env = (proc / "environ").read_bytes().split(b"\0")
    require(
        not any(item.startswith(b"TRAEFIK_") for item in env),
        "Traefik environment overrides are unsupported",
    )
    binary_hash = digest(binary)
    require(
        digest(proc / "exe") == binary_hash, "running/installed executable hash drift"
    )
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
    require(
        int(
            run(
                ["systemctl", "show", "traefik.service", "-p", "MainPID", "--value"]
            ).strip()
        )
        == pid,
        "Traefik restarted during observation",
    )
    return result


def state_for(
    policy: dict[str, Any], phase: str, live: dict[str, Any], **fields: Any
) -> dict[str, Any]:
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
    require(
        re.fullmatch(r"[a-z][a-z0-9-]{0,62}", policy["host"]), "invalid canonical host"
    )
    for key in ["binary_path", "config_path", "dynamic_path"]:
        path = Path(policy[key])
        require(
            path.is_absolute() and ".." not in path.parts and str(path) == policy[key],
            f"invalid {key}",
        )
    require(
        policy["binary_path"] in ["/usr/bin/traefik", "/usr/local/bin/traefik"],
        "unsupported binary location",
    )
    require(
        policy["config_path"] == "/etc/traefik/traefik.toml",
        "unsupported static config source",
    )
    require(
        policy["dynamic_path"] == "/etc/traefik/dynamic",
        "unsupported dynamic provider directory",
    )


def evidence(request: dict[str, Any], live: dict[str, Any]) -> None:
    proof = request["evidence"]
    require(proof["baseline"] == live, "reviewed baseline does not match live state")
    age = time.time() - proof["verified_at"]
    require(0 <= age <= 3600, "preflight evidence must be at most one hour old")
    recovery = proof.get("recovery_access", proof.get("console_recovery"))
    require(
        isinstance(recovery, str)
        and bool(recovery.strip())
        and "CHANGEME" not in recovery,
        "missing evidence: recovery_access",
    )
    for key in [
        "owner",
        "review_reference",
        "independent_observer",
        "observer_delivery_test",
    ]:
        require(
            isinstance(proof.get(key), str)
            and proof[key].strip()
            and "CHANGEME" not in proof[key],
            f"missing evidence: {key}",
        )
    require(
        proof.get("observer_watch_active") is True,
        "independent observer must be watching",
    )


def check_probe(spec: dict[str, Any]) -> None:
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


def validate_alias(before: bytes, after: bytes, approved: dict[str, str]) -> None:
    old, new = tomllib.loads(before.decode()), tomllib.loads(after.decode())
    entries = old.get("entryPoints", {})
    require(
        entries and set(entries) == set(approved),
        "alias map must cover every entrypoint",
    )
    expected = copy.deepcopy(old)
    for name, setting in approved.items():
        require(setting == "delete", "only the approved delete strategy is supported")
        require(
            not str(entries[name]["address"]).endswith("/udp"),
            "UDP requires a separately reviewed policy",
        )
        http = expected["entryPoints"][name].setdefault("http", {})
        require(
            "underscoreHeadersStrategy" not in http,
            "legacy underscore strategy needs separate reconciliation",
        )
        http["aliasHeadersStrategy"] = setting
    require(new == expected, "alias candidate changes unrelated configuration")


def validate_metrics_bind(
    before: bytes, after: bytes, approved: dict[str, str]
) -> None:
    """Allow only the loopback metrics entrypoint repair."""
    old, new = tomllib.loads(before.decode()), tomllib.loads(after.decode())
    entries = old.get("entryPoints")
    if not isinstance(entries, dict) or not entries:
        raise Refused("entrypoints are required")
    require("traefik" not in entries, "metrics entrypoint already exists")
    require(
        set(approved) == set(entries) | {"traefik"},
        "metrics binding policy must cover every resulting entrypoint",
    )
    for name, setting in approved.items():
        require(setting == "delete", "only the approved delete strategy is supported")
        if name != "traefik":
            require(
                entries[name].get("http", {}).get("aliasHeadersStrategy") == "delete",
                "existing entrypoint alias policy is incomplete",
            )
    metrics = old.get("metrics")
    if not isinstance(metrics, dict):
        raise Refused("Prometheus metrics must already be enabled")
    prometheus = metrics.get("prometheus")
    if not isinstance(prometheus, dict) or "entryPoint" in prometheus:
        raise Refused("Prometheus must use the implicit entrypoint before repair")
    expected = copy.deepcopy(old)
    expected["entryPoints"]["traefik"] = {
        "address": "127.0.0.1:8080",
        "http": {"aliasHeadersStrategy": "delete"},
    }
    expected["metrics"]["prometheus"]["entryPoint"] = "traefik"
    require(
        new == expected,
        "metrics binding candidate changes unrelated static configuration",
    )


def validate_acme_storage(before: bytes, after: bytes, policy: dict[str, Any]) -> None:
    """Accept only the misplaced resolver email/storage repair, without reserializing."""
    require(policy.get("acme_source") == "/acme.json", "unsupported ACME source")
    require(
        policy.get("acme_target") == "/etc/traefik/acme/acme.json",
        "unsupported ACME target",
    )
    old, new = tomllib.loads(before.decode()), tomllib.loads(after.decode())
    expected = copy.deepcopy(old)
    misplaced = expected.pop("acme", None)
    require(
        isinstance(misplaced, dict) and set(misplaced) == {"email", "storage"},
        "expected only misplaced email and storage",
    )
    require(isinstance(misplaced["email"], str), "email must be a string")
    if expected.get("letsencrypt") == {}:
        del expected["letsencrypt"]
    resolver = expected["certificatesResolvers"]["letsencrypt"]["acme"]
    require(
        "email" not in resolver and "storage" not in resolver,
        "resolver already has email or storage",
    )
    resolver.update(email=misplaced["email"], storage=policy["acme_target"])
    require(new == expected, "ACME candidate changes unrelated configuration")


def certificate_set(data: bytes) -> list[tuple[tuple[str, ...], str]]:
    """Public certificate identities only; never serialize account or key material."""
    store = json.loads(data)
    require(set(store) == {"letsencrypt"}, "expected one letsencrypt resolver")
    certificates = store["letsencrypt"]["Certificates"]
    require(isinstance(certificates, list) and certificates, "empty certificate store")
    result = []
    for item in certificates:
        domain = item["domain"]
        names = tuple(sorted({domain["main"], *domain.get("sans", [])}))
        require(
            all(isinstance(name, str) and name for name in names),
            "invalid certificate domains",
        )
        pem = base64.b64decode(item["certificate"], validate=True)
        # OpenSSL parses the leaf at the start of Traefik's PEM chain.
        expiry = run(
            ["openssl", "x509", "-noout", "-enddate"], input=pem.decode("ascii")
        ).strip()
        require(expiry.startswith("notAfter="), "missing certificate expiry")
        result.append((names, expiry))
    return sorted(result)


def acme_preflight(
    policy: dict[str, Any],
) -> tuple[bytes, list[tuple[tuple[str, ...], str]]]:
    source, target = Path(policy["acme_source"]), Path(policy["acme_target"])
    trusted_file(source)
    require(stat.S_IMODE(source.stat().st_mode) == 0o600, "ACME source must be 0600")
    for parent in (target.parent.parent, target.parent):
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o022,
            "unsafe ACME parent directory",
        )
    data = source.read_bytes()
    if target.exists() or target.is_symlink():
        trusted_file(target)
        # An exact copy is what a rolled-back attempt leaves; anything else is foreign.
        require(
            target.stat().st_size == 0 or target.read_bytes() == data,
            "ACME target must be absent, empty or an exact copy of the source",
        )
    return data, certificate_set(data)


def tls_fingerprints(names: list[str]) -> dict[str, str]:
    """Probe every stored hostname directly on local Traefik using SNI."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    result = {}
    for name in names:
        with (
            socket.create_connection(("127.0.0.1", 443), timeout=10) as connection,
            context.wrap_socket(connection, server_hostname=name) as connection_tls,
        ):
            cert = connection_tls.getpeercert(binary_form=True)
            if not cert:
                raise Refused("missing served certificate")
            result[name] = hashlib.sha256(cert).hexdigest()
    return result


def verify_tls_fingerprints(names: list[str], baseline: dict[str, str]) -> None:
    """Allow bounded resolver startup settling; never accept a different leaf."""
    last: Exception | None = None
    for attempt in range(5):
        try:
            require(
                tls_fingerprints(names) == baseline,
                "served certificate fingerprint changed",
            )
            return
        except (OSError, Refused) as exc:
            last = exc
            if attempt < 4:
                time.sleep(2)
    raise Refused("TLS fingerprint verification failed") from last


def candidate_binary(
    archive: Path, checksum: str, destination: Path, target: str
) -> Path:
    require(re.fullmatch(r"[0-9a-f]{64}", checksum), "exact SHA256 is required")
    require(digest(archive) == checksum, "release archive checksum mismatch")
    require(re.fullmatch(r"3\.\d+\.\d+", target), "unsupported release")
    with tarfile.open(archive) as bundle:
        members = [member for member in bundle.getmembers() if member.name == "traefik"]
        require(
            len(members) == 1
            and members[0].isfile()
            and 0 < members[0].size < 512 * 1024 * 1024,
            "archive must contain one bounded regular traefik executable",
        )
        stream = bundle.extractfile(members[0])
        assert stream is not None
        output = destination / "candidate"
        atomic(output, stream.read(), 0o755)
    require(
        version(output) == tuple(map(int, target.split("."))),
        "candidate version mismatch",
    )
    return output


def backup(policy: dict[str, Any], directory: Path) -> None:
    paths = policy["backup_paths"]
    required = {
        policy["binary_path"],
        "/etc/traefik",
        "/etc/systemd/system/traefik.service",
    }
    if Path("/etc/letsencrypt").exists():
        required.add("/etc/letsencrypt")
    if Path("/etc/systemd/system/traefik.service.d").exists():
        required.add("/etc/systemd/system/traefik.service.d")
    require(
        required.issubset(set(paths)),
        "backup set omits binary, config, unit or external certificates",
    )
    require(
        set(policy["acme_paths"]).issubset(set(paths)),
        "backup set omits approved active ACME stores",
    )
    require(
        all(Path(p).is_absolute() and ".." not in Path(p).parts for p in paths),
        "invalid backup path",
    )
    require(
        all(Path(p).exists() or p == policy.get("acme_target") for p in paths),
        "required backup path absent",
    )
    paths = [p for p in paths if Path(p).exists()]
    run(
        [
            "tar",
            "--acls",
            "--xattrs",
            "--numeric-owner",
            "-czf",
            str(directory / "prechange.tar.gz"),
            "--",
            *paths,
        ],
        timeout=120,
    )
    save(
        directory / "backup.json",
        {"paths": paths, "sha256": digest(directory / "prechange.tar.gz")},
    )


def restart_verify(
    policy: dict[str, Any],
    expected: dict[str, Any],
    probe: dict[str, Any],
    cleanup: dict[str, Any],
) -> dict[str, Any]:
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


def execute(request: dict[str, Any]) -> dict[str, Any]:
    policy, action = request["policy"], request["action"]
    validate_policy(policy)
    require(
        action
        in [
            "inspect",
            "enroll",
            "binary",
            "alias",
            "metrics_bind",
            "acme_storage",
            "resume",
        ],
        "unknown action",
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
        if action == "enroll":
            require(
                state is None,
                "enrollment cannot overwrite any existing recovery record",
            )
            state = state_for(policy, "clear", live, owner=request["evidence"]["owner"])
            save(state_path, state)
            return {"changed": True, "state": state}
        require(
            state is not None and state["host"] == policy["host"],
            "missing or wrong host enrollment",
        )
        assert state is not None
        if action == "resume":
            require(
                state["phase"] in ["clear", "recovery", "degraded", "pending"],
                "resume requires an explicit recovery record",
            )
            require(
                request.get("recovery_review_reference"),
                "reviewed recovery reference required",
            )
            check_probe(request["baseline_probe"])
            state = state_for(
                policy,
                "clear",
                live,
                owner=request["evidence"]["owner"],
                resumed_from=state["revision"],
                recovery_review_reference=request["recovery_review_reference"],
            )
            save(state_path, state)
            return {"changed": True, "state": state}
        require(
            state["phase"] == "clear" and state["identity"] == live,
            "active recovery or unreviewed baseline drift",
        )
        check_probe(request["baseline_probe"])
        compatibility = request["compatibility"]
        require(
            compatibility["baseline"] == live
            and compatibility["architecture"] == os.uname().machine,
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
        old_config = Path(policy["config_path"]).read_bytes()
        expected = dict(live)
        if action == "binary":
            target = request["release"]["version"]
            require(
                tuple(map(int, target.split(".")))
                >= tuple(map(int, live["version"].split("."))),
                "ordinary downgrade refused",
            )
            candidate = candidate_binary(
                Path(request["archive_path"]),
                request["release"]["sha256"],
                directory,
                target,
            )
            expected["binary_sha256"], expected["version"] = digest(candidate), target
            require(
                compatibility["candidate_binary_sha256"] == expected["binary_sha256"],
                "candidate differs from isolated test",
            )
            require(
                compatibility["candidate_config_sha256"] == live["config_sha256"],
                "binary-only operation must preserve static config",
            )
            destination = Path(policy["binary_path"])
        else:
            require(
                tuple(map(int, live["version"].split("."))) >= (3, 7, 12),
                "alias policy requires a compatible running and installed binary",
            )
            require(
                live["binary_sha256"] == request["approved_binary_sha256"],
                "alias operation requires approved executable hash",
            )
            after = base64.b64decode(request["candidate_config_base64"], validate=True)
            if action == "alias":
                validate_alias(old_config, after, policy["alias_policy"])
            elif action == "acme_storage":
                validate_acme_storage(old_config, after, policy)
            else:
                validate_metrics_bind(old_config, after, policy["alias_policy"])
            candidate = directory / "candidate.toml"
            atomic(candidate, after)
            expected["config_sha256"] = digest(candidate)
            require(
                compatibility["candidate_binary_sha256"] == live["binary_sha256"]
                and compatibility["candidate_config_sha256"]
                == expected["config_sha256"],
                "alias candidate differs from isolated test",
            )
            destination = Path(policy["config_path"])
        if expected == live:
            try:
                check_probe(request["acceptance_probe"])
            finally:
                check_probe(request["cleanup_probe"])
            require(
                identity(policy) == live, "identity changed during no-op verification"
            )
            return {"changed": False, "state": state}
        if action == "acme_storage":
            require(
                policy["acme_source"] in policy["acme_paths"]
                and policy["acme_source"] in policy["backup_paths"],
                "source backup is required",
            )
            source_bytes, certificates = acme_preflight(policy)
            source_hash = hashlib.sha256(source_bytes).hexdigest()
            names = sorted({name for domains, _ in certificates for name in domains})
            fingerprints = tls_fingerprints(names)
            save(
                directory / "acme-baseline.json",
                {
                    "source_sha256": source_hash,
                    "certificates": certificates,
                    "tls_fingerprints": fingerprints,
                },
            )
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
            operation=action,
            transaction=str(directory),
            intended_identity=expected,
            previous_revision=state["revision"],
        )
        save(state_path, pending)
        replaced = False
        try:
            if action == "acme_storage":
                # Recheck after backup and baseline capture, before any live write.
                latest, _ = acme_preflight(policy)
                require(
                    hashlib.sha256(latest).hexdigest() == source_hash,
                    "ACME source changed before copy",
                )
                target = Path(policy["acme_target"])
                if target.exists():
                    atomic(directory / "acme-target.orig", target.read_bytes())
                target.parent.chmod(0o700)
                atomic(target, source_bytes, 0o600)
                require(digest(target) == source_hash, "ACME copy hash mismatch")
            replaced = True
            atomic(destination, candidate.read_bytes(), mode)
            accepted = restart_verify(
                policy, expected, request["acceptance_probe"], request["cleanup_probe"]
            )
            if action == "acme_storage":
                require(
                    digest(Path(policy["acme_source"])) == source_hash,
                    "ACME source changed since copy",
                )
                require(
                    certificate_set(Path(policy["acme_target"]).read_bytes())
                    == certificates,
                    "ACME certificate set changed",
                )
                verify_tls_fingerprints(names, fingerprints)
            complete = state_for(
                policy,
                "clear",
                accepted,
                owner=request["evidence"]["owner"],
                transaction=str(directory),
            )
            save(state_path, complete)
            return {"changed": True, "state": complete}
        except BaseException as failure:  # noqa: BLE001
            # Recover interrupted operations too; retain an active journal.
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
                cleanup_failure = None
                try:
                    check_probe(request["cleanup_probe"])
                except BaseException as exc:  # noqa: BLE001
                    cleanup_failure = exc
                if replaced:
                    atomic(destination, original.read_bytes(), mode)
                    restart_verify(
                        policy,
                        live,
                        request["baseline_probe"],
                        request["cleanup_probe"],
                    )
                    if action == "acme_storage":
                        verify_tls_fingerprints(names, fingerprints)
                if cleanup_failure is not None:
                    raise cleanup_failure
                recovery["identity"] = identity(policy)
            except BaseException as restore_failure:  # noqa: BLE001
                # Any interrupted recovery must retain degraded state.
                recovery["phase"] = "degraded"
                recovery["recovery_error"] = type(restore_failure).__name__
            save(state_path, recovery)
            return {"changed": replaced, "failed": True, "state": recovery}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        request = json.loads(args.request.read_text())
        result = execute(request)
        print(json.dumps(result, sort_keys=True))
        return 1 if result.get("failed") else 0
    except (
        Refused,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        print(json.dumps({"failed": True, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
