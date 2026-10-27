"""Ordinary Traefik deployment through the existing transaction engine when declared enrolled."""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import shlex
import stat
import time
import tomllib
from collections.abc import Generator
from pathlib import Path
from typing import Any

from pydantic import Field
from pyinfra.api import DeployError, FunctionCommand, deploy, operation
from pyinfra.operations import files, systemd

from ops_deploy.backups.remote import Runner, SshTarget, ssh_runner
from ops_deploy.base._common import output, require_linux, require_systemd
from ops_deploy.infra import traefik_deploy as ordinary
from ops_deploy.infra._common import directory
from ops_deploy.infra.traefik_probes import (
    PROGRAM,
    PROGRAM_SHA256,
    ProbeBaseline,
    ProbeSpec,
    capture_memory_traefik_health_probes,
    config_json,
)
from ops_deploy.infra.traefik_tx import engine, proof, transport


class TraefikRoutineConfig(ordinary.TraefikDeployConfig):
    """Private orchestration inputs; enrollment is declarative, never inferred from missing state."""

    canonical_host: str
    ssh_address: str
    controller_journal: Path
    transaction_policy: dict[str, Any] = Field(default_factory=dict)
    authority: str
    implementation_reference: str


def static_equivalent(actual: str, desired: str) -> bool:
    """Ignore TOML spelling and only the documented default Prometheus entrypoint."""

    def normalized(text: str) -> dict[str, Any]:
        value = tomllib.loads(text)
        prometheus = value.get("metrics", {}).get("prometheus")
        if isinstance(prometheus, dict):
            prometheus.setdefault("entryPoint", "traefik")
        return value

    return normalized(actual) == normalized(desired)


def resources(runner: Runner, paths: list[str]) -> dict[str, Any]:
    payload = base64.b64encode(json.dumps(paths).encode()).decode()
    script = f"""import base64,json,pathlib,os,stat
result = {{}}
for name in json.loads(base64.b64decode({payload!r})):
    path = pathlib.Path(name)
    if not os.path.lexists(path):
        result[name] = None
        continue
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
        raise RuntimeError("unsafe routine resource")
    result[name] = {{"text": path.read_text(), "mode": stat.S_IMODE(info.st_mode)}}
print(json.dumps(result))
"""
    result = runner(transport.memory_script(script), [], 60)
    if not result.ok:
        raise DeployError("Traefik resource observation failed")
    return dict(json.loads(result.stdout))


def read_record(path: Path) -> dict[str, Any] | None:
    if not os.path.lexists(path):
        return None
    parent = path.parent.lstat()
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o077
        or path.is_symlink()
        or not path.is_file()
        or path.stat().st_uid != os.geteuid()
        or path.stat().st_mode & 0o077
    ):
        raise DeployError("Unsafe Traefik controller journal")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise DeployError("Invalid Traefik controller journal")
    return value


def admitted(cfg: TraefikRoutineConfig, runner: Runner) -> tuple[dict[str, Any], dict[str, Any]]:
    observed = transport.inspect_memory_host(runner, cfg.transaction_policy)
    record = read_record(cfg.controller_journal)
    live, remote = observed.response.get("identity"), observed.response.get("state")
    if observed.exit_code or not isinstance(live, dict) or not isinstance(record, dict) or remote != record:
        raise DeployError("Traefik required enrollment or paired identity is unavailable")
    if record.get("host") != cfg.canonical_host or record.get("phase") != "clear":
        raise DeployError("Traefik recovery must be reconciled before ordinary deployment")
    drift = {key for key in set(live) | set(record["identity"]) if live.get(key) != record["identity"].get(key)}
    if drift - {"dynamic_sha256"}:
        raise DeployError("Traefik non-route identity drift requires reconciliation")
    installed, floor = tuple(map(int, live["version"].split("."))), tuple(map(int, cfg.version.split(".")))
    if installed[:2] != floor[:2]:
        raise DeployError("Traefik installed version is outside the declared patch line")
    return record, live


def selected_release(cfg: TraefikRoutineConfig, installed: str) -> dict[str, str] | None:
    """Explicit floor only, with architecture read from the target, never the controller."""

    if tuple(map(int, installed.split("."))) >= tuple(map(int, cfg.version.split("."))):
        return None
    native = ordinary.ARCHITECTURES.get(output("uname -m").strip())
    arch = cfg.arch or native
    if arch is None or (native is not None and arch != native):
        raise DeployError("Traefik target architecture is unsupported or differs from the declared arch")
    return {"version": cfg.version, "arch": arch, "sha256": cfg.checksum.removeprefix("sha256:")}


def ordinary_evidence(cfg: TraefikRoutineConfig, live: dict[str, Any], baseline: ProbeBaseline) -> dict[str, Any]:
    return {
        "kind": "ordinary",
        "owner": cfg.authority,
        "review_reference": cfg.implementation_reference,
        "baseline": live,
        "verified_at": int(time.time()),
        "recovery_access": "fresh root SSH outside Traefik; detached full-manifest safe restore",
        "observations": {
            "identity": live,
            "probes": [item.model_dump(exclude_none=True) for item in baseline.observations],
        },
    }


def transaction_probes(transaction_id: str, baseline: ProbeBaseline, candidate: ProbeBaseline) -> dict[str, Any]:
    root = f"{transport.TRANSPORT_ROOT}/{transaction_id}"

    def command(mode: str, config: str) -> dict[str, Any]:
        return {"argv": [f"{root}/health.py", mode, f"{root}/{config}.json"], "sha256": PROGRAM_SHA256}

    return {
        "probe_files": {
            "health.py": PROGRAM.decode(),
            "baseline.json": config_json(baseline),
            "candidate.json": config_json(candidate),
        },
        "baseline_probe": command("health", "baseline"),
        "acceptance_probe": command("health", "candidate"),
        # Cleanup owns no resources; it must not reject the opposite tree during rollback.
        "cleanup_probe": {"argv": ["/usr/bin/true"], "sha256": ""},
    }


def transact(
    cfg: TraefikRoutineConfig, runner: Runner, record: dict[str, Any], request: dict[str, Any], transaction_id: str
) -> dict[str, Any]:
    transport.stage_transaction(runner, request, transaction_id)
    pending = {
        "schema": 1,
        "host": cfg.canonical_host,
        "phase": "pending",
        "operation": request["action"],
        "transaction_id": transaction_id,
        "previous_revision": record["revision"],
        "updated_at": int(time.time()),
    }
    engine.save(cfg.controller_journal, pending)
    # A lost start answer never means the detached transaction did not start.
    with contextlib.suppress(transport.TransportError):
        transport.start_transaction(runner, transaction_id)
    status = transport.wait_for_transaction(runner, transaction_id, timeout=1600)
    returned = status.host_record
    if returned is not None and returned.get("host") == cfg.canonical_host and returned.get("schema") == 1:
        engine.save(cfg.controller_journal, returned)
    if status.final:
        transport.cleanup_transaction(runner, transaction_id)
    if returned is None or returned.get("phase") != "clear" or status.engine_exit != 0:
        raise DeployError("Traefik transaction did not finish clear; paired recovery retained")
    return returned


def apply_core(
    cfg: TraefikRoutineConfig,
    runner: Runner,
    planned: dict[str, Any],
    initial: dict[str, Any],
    desired_files: dict[str, str],
    spec: ProbeSpec,
    release: dict[str, str] | None,
) -> None:
    lock_path = cfg.controller_journal.with_suffix(".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "r+") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise DeployError("Unsafe Traefik controller lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record, live = admitted(cfg, runner)
        if record != planned or live != initial:
            raise DeployError("Traefik changed after operation planning")
        baseline = capture_memory_traefik_health_probes(runner, spec)
        if engine.canonical(sorted(baseline.dynamic.items(), key=lambda item: Path(item[0]))) != live["dynamic_sha256"]:
            raise DeployError("Traefik dynamic tree changed during observation")
        # Exact program identity for an executable that performs no cleanup writes.
        true_result = runner("sha256sum /usr/bin/true", [], 30)
        if not true_result.ok:
            raise DeployError("Traefik cleanup program observation failed")
        true_sha = true_result.stdout.split()[0]
        if record["identity"] != live:
            txid = transport.new_transaction_id()
            request = {
                "action": "rebaseline",
                "policy": cfg.transaction_policy,
                "controller_state": record,
                "evidence": ordinary_evidence(cfg, live, baseline),
                **transaction_probes(txid, baseline, baseline),
                "metadata": {"probe_config": json.loads(config_json(baseline))},
            }
            request["cleanup_probe"]["sha256"] = true_sha
            record = transact(cfg, runner, record, request, txid)
        if not desired_files and release is None:
            return
        proof_request = {
            "policy": cfg.transaction_policy,
            "release": release or {"version": live["version"]},
            "fetch_release": release is not None,
            "routine_files": desired_files,
            "probe_baseline": json.loads(config_json(baseline)),
        }
        verified = transport.prove_routine(runner, proof_request)
        compatibility = proof.compatibility(verified, live)
        candidate = baseline.model_copy(deep=True)
        if "certificates" in desired_files:
            candidate.dynamic["certificates.yml"] = hashlib.sha256(desired_files["certificates"].encode()).hexdigest()
        txid = transport.new_transaction_id()
        request = {
            "action": "routine",
            "policy": cfg.transaction_policy,
            "controller_state": record,
            "evidence": ordinary_evidence(cfg, live, baseline),
            "files": desired_files,
            "compatibility": compatibility,
            **transaction_probes(txid, baseline, candidate),
            "metadata": {
                "probe_config": json.loads(config_json(candidate)),
                "route_inventory": {
                    "dynamic_sha256": compatibility["candidate_dynamic_sha256"],
                    "files": sorted(candidate.dynamic.items(), key=lambda item: Path(item[0])),
                },
            },
        }
        request["cleanup_probe"]["sha256"] = true_sha
        if release is not None:
            request["release"] = release
        transact(cfg, runner, record, request, txid)


@operation()
def routine_change(
    cfg: TraefikRoutineConfig,
    runner: Runner,
    record: dict[str, Any],
    live: dict[str, Any],
    desired: dict[str, str],
    spec: ProbeSpec,
    release: dict[str, str] | None,
) -> Generator[FunctionCommand, None, None]:
    if desired or release is not None or record["identity"] != live:
        yield FunctionCommand(apply_core, (cfg, runner, record, live, desired, spec, release), {})


@deploy("Traefik ordinary routine")
def deploy_traefik_routine(cfg: TraefikRoutineConfig, *, runner: Runner | None = None) -> None:
    require_linux("traefik_routine")
    require_systemd("traefik_routine")
    if not cfg.transaction_required:
        if read_record(cfg.controller_journal) is not None:
            raise DeployError("Unexpected Traefik enrollment for ordinary host")
        installed = ordinary.installed_version(cfg.binary_path)
        if installed and tuple(map(int, installed.split("."))) > tuple(map(int, cfg.version.split("."))):
            raise DeployError("Traefik ordinary downgrade refused")
        ordinary.deploy_traefik(cfg=cfg)
        return
    access = runner or ssh_runner(SshTarget(cfg.ssh_address, user="root"))
    record, live = admitted(cfg, access)
    paths = [cfg.static_path, str(engine.UNIT_PATH), f"{cfg.dynamic_path}/certificates.yml", str(engine.PROBE_CONFIG)]
    actual = resources(access, paths)
    if actual[paths[0]] is None or actual[paths[1]] is None or actual[paths[3]] is None:
        raise DeployError("Required Traefik routine resources/probe spec absent")
    baseline_config = json.loads(actual[paths[3]]["text"])
    spec = ProbeSpec.model_validate({key: baseline_config[key] for key in ("probes", "entrypoints")})
    spec = spec.model_copy(update={"tls_fingerprints": True})
    captured = capture_memory_traefik_health_probes(access, spec)
    if any(
        p.scheme == "https" and o.tls_sha256 is None
        for p, o in zip(captured.probes, captured.observations, strict=True)
    ):
        raise DeployError("Traefik TLS observation failed")
    engine.evidence({"action": "routine", "evidence": ordinary_evidence(cfg, live, captured)}, live)
    if admitted(cfg, access) != (record, live):
        raise DeployError("Traefik identity changed during ingress observation")
    desired: dict[str, str] = {}
    static = ordinary.render_static(cfg)
    if not static_equivalent(actual[paths[0]]["text"], static):
        desired["static"] = static
    unit = ordinary.render_unit(cfg)
    if actual[paths[1]]["text"] != unit:
        desired["unit"] = unit
    if cfg.file_certificates:
        content = ordinary.render_certificates(cfg)
        ordinary.validate_certificates(content)
        for cert in cfg.file_certificates:
            for path in (cert.cert_file, cert.key_file):
                if output(f"test -f {shlex.quote(path)} && echo present").strip() != "present":
                    raise DeployError("Traefik external certificate file missing")
        if actual[paths[2]] is None or actual[paths[2]]["text"] != content:
            desired["certificates"] = content
    release = selected_release(cfg, live["version"])
    routine_change(
        cfg=cfg,
        runner=access,
        record=record,
        live=live,
        desired=desired,
        spec=spec,
        release=release,
        name="Reconcile Traefik owned resources and record",
    )
    # Outside the core transaction; failures are deployment failures, never hidden by a clear core record.
    for path, mode in (
        (cfg.config_dir, "0755"),
        (cfg.dynamic_path, "0755"),
        (cfg.acme_path, "0700"),
        (cfg.log_dir, "0755"),
    ):
        directory(path, user="root", group="root", mode=mode)
    files.file(
        name="Preserve ACME store ownership",
        path=cfg.acme_storage_path,
        present=True,
        touch=False,
        user="root",
        group="root",
        mode="0600",
    )
    for path, mode in ((cfg.binary_path, "0755"), (cfg.static_path, "0644"), (str(engine.UNIT_PATH), "0644")):
        files.file(
            name=f"Ensure Traefik resource mode {path}",
            path=path,
            present=True,
            touch=False,
            user="root",
            group="root",
            mode=mode,
        )
    if cfg.file_certificates:
        files.file(
            name="Ensure owned certificate-list mode",
            path=f"{cfg.dynamic_path}/certificates.yml",
            present=True,
            touch=False,
            user="root",
            group="root",
            mode="0644",
        )
    ordinary._put("Configure Traefik log rotation", ordinary.render_logrotate(cfg), ordinary.LOGROTATE_PATH)
    ordinary._disarm_web_servers(cfg)
    ordinary._firewall(cfg)
    systemd.service(name="Ensure Traefik enabled and running", service="traefik.service", running=True, enabled=True)
