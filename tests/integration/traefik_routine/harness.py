"""Native install/update/config/certificate/unit and detached death proof, on an owned VM."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

from ops_deploy.backups.remote import CommandResult, SubprocessRunner
from ops_deploy.infra.traefik_deploy import FileCertificate, render_static, render_unit
from ops_deploy.infra.traefik_probes import (
    PROGRAM,
    Probe,
    ProbeSpec,
)

# The bootstrap workflow runs against an immutable implementation checkout.
# Resolve feature-only interfaces at execution time so baseline Main can typecheck.
engine = import_module("ops_deploy.infra.traefik_tx.engine")
proof = import_module("ops_deploy.infra.traefik_tx.proof")
transport = import_module("ops_deploy.infra.traefik_tx.transport")

OLD_SHA = "52cd039a34258dd61c617a95d69252bc6bcae27c520f338186c31c7fef8f6394"
FAULT_SHA = "759a7bc0d66b74c588255ed9e41c7f9d4aba60bdb7bce9dde551b1268a55eb07"
NEW_SHA = "d08641f5de2dd3788097bddab1ce4b29c10a0b788566970db707fa5c94c71f15"
ACCESS = SubprocessRunner()
TRACE_ARGS = ("strace", "-f", "-s", "1000000", "-v", "-e", "trace=file,process,fchmod,fchown,ftruncate")


def run(*argv: str) -> str:
    return subprocess.check_output(argv, text=True).strip()


def write(path: str, content: str, mode: int = 0o644) -> None:
    target = Path(path)
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    target.write_text(content)
    target.chmod(mode)


def snapshot() -> dict[str, Any]:
    roots = [
        Path(p)
        for p in (
            "/etc/traefik",
            "/var/lib/traefik-transactions",
            "/var/lib/traefik-transport",
            "/var/lib/traefik-update-proofs",
            "/var/lib/traefik-update-probes",
            "/var/tmp/traefik-routine-journal",
        )
    ]
    result = {}
    for root in roots:
        if root.exists():
            for path in [root, *sorted(root.rglob("*"))]:
                stat = path.stat()
                result[str(path)] = {
                    "mtime": stat.st_mtime_ns,
                    "mode": stat.st_mode,
                    "sha256": engine.digest(path) if path.is_file() else None,
                }
    return result


def assert_observation_trace(script: str, lines: list[str]) -> None:
    mutations = [
        line
        for line in lines
        if re.search(
            r"\b(?:open|openat|openat2|creat)\(.*(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)|"
            r"\b(?:mkdir|mkdirat|unlink|unlinkat|rename|renameat|renameat2|chmod|fchmod|fchmodat|fchmodat2|chown|lchown|fchown|fchownat|utime|utimes|futimesat|utimensat|symlink|symlinkat|link|linkat|truncate|ftruncate|mknod|mknodat)\(",
            line,
        )
        and '"/dev/null"' not in line
    ]
    assert not mutations, mutations
    # Fail closed on truncation as well as payload leakage into a process argv.
    packets = re.findall(r"builtin printf '%s' ([A-Za-z0-9+/=]+)", script)
    for line in lines:
        if "execve(" in line:
            assert '"...' not in line, "truncated execve evidence"
            assert all(packet not in line for packet in packets), "payload in execve argv"


def deploy(cfg: Any, evidence: Path, label: str, *, refusal: bool = False) -> None:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.testing.harness import collect_ops

    before = snapshot()
    counter = 0

    def observed_access(script: str, args: Sequence[str], timeout: float) -> CommandResult:
        nonlocal counter
        if not label.endswith("repeat"):
            return ACCESS(script, args, timeout)
        counter += 1
        trace = evidence / f"{label}-observation-{counter}.strace"
        traced = SubprocessRunner(prefix=(*TRACE_ARGS, "-o", str(trace)))
        done = traced(script, args, timeout)
        assert_observation_trace(script, trace.read_text().splitlines())
        return done

    state = State(Inventory(([("@local", {})], {})), Config())
    error = None
    try:
        connect_all(state)
        add_deploy(
            state,
            import_module("ops_deploy.infra.traefik_routine").deploy_traefik_routine,
            cfg=cfg,
            runner=observed_access,
        )
        run_ops(state)
    except Exception as exc:
        error = str(exc)
    finally:
        ops = collect_ops(state, "@local")
        disconnect_all(state)
    changes = [op.name for op in ops if op.changed and not op.read_only]
    result = {
        "error": error,
        "mutations": changes,
        "operations": [asdict(op) for op in ops],
        "filesystem_unchanged": snapshot() == before,
    }
    (evidence / f"{label}.json").write_text(json.dumps(result, indent=2))
    if refusal:
        assert error, result
        assert not changes, result
        assert snapshot() == before, result
    else:
        assert error is None, result
        assert ops, result
        assert all(op.succeeded for op in ops), result
        if label.endswith("repeat"):
            assert not changes, result
            assert snapshot() == before, result


def enroll_fixture(cfg: Any) -> dict[str, Any]:
    """Owned fixture enrollment only, not a new production bootstrap API."""
    engine.STATE_ROOT.mkdir(mode=0o700, exist_ok=True)
    live = engine.identity(cfg.transaction_policy)
    record = engine.state_for(cfg.transaction_policy, "clear", live, owner="owned disposable fixture")
    engine.save(engine.STATE_ROOT / "state.json", record)
    engine.save(cfg.controller_journal, record)
    cfg.controller_journal.with_suffix(".lock").touch(mode=0o600)
    return dict(record)


def fault_request(cfg: Any) -> tuple[dict[str, Any], str]:
    live = engine.identity(cfg.transaction_policy)
    record = json.loads(cfg.controller_journal.read_text())
    spec = ProbeSpec(
        probes=(
            Probe(host="fixture.example.com", scheme="http", port=80, address="127.0.0.1"),
            Probe(host="fixture.example.com", scheme="https", port=443, address="127.0.0.1"),
            Probe(host="fixture.example.com", scheme="https", port=443, address="127.0.0.1", path="/protected"),
        ),
        entrypoints=("web", "web-secure", "traefik"),
        tls_fingerprints=True,
    )
    baseline = import_module("ops_deploy.infra.traefik_probes").capture_memory_traefik_health_probes(ACCESS, spec)
    desired = {
        "static": render_static(cfg.model_copy(update={"log_level": "DEBUG"})),
        "unit": render_unit(cfg) + "# owned fixture candidate\n",
        "certificates": Path("/etc/traefik/dynamic/certificates.yml").read_text() + "# owned fixture candidate\n",
    }
    result = transport.prove_routine(
        ACCESS,
        {
            "policy": cfg.transaction_policy,
            "release": {"version": "3.7.16", "arch": "amd64", "sha256": FAULT_SHA},
            "fetch_release": True,
            "routine_files": desired,
            "probe_baseline": baseline.model_dump(mode="json", exclude_unset=True),
        },
    )
    candidate = baseline.model_copy(deep=True)
    candidate.dynamic["certificates.yml"] = hashlib.sha256(desired["certificates"].encode()).hexdigest()
    txid = transport.new_transaction_id()
    request = {
        "action": "routine",
        "policy": cfg.transaction_policy,
        "controller_state": record,
        "files": desired,
        "release": {"version": "3.7.16", "arch": "amd64", "sha256": FAULT_SHA},
        "compatibility": proof.compatibility(result, live),
        "evidence": import_module("ops_deploy.infra.traefik_routine").ordinary_evidence(cfg, live, baseline),
        **import_module("ops_deploy.infra.traefik_routine").transaction_probes(txid, baseline, candidate),
        "metadata": {
            "probe_config": candidate.model_dump(mode="json", exclude_unset=True),
            "route_inventory": {
                "dynamic_sha256": result["candidate_dynamic_sha256"],
                "files": sorted(candidate.dynamic.items(), key=lambda item: Path(item[0])),
            },
        },
    }
    request["cleanup_probe"]["sha256"] = engine.digest(Path("/usr/bin/true"))
    return request, txid


def deaths(cfg: Any, evidence: Path) -> None:
    """Inject SIGKILL after actual production atomic writes; detached original runner restores."""
    for target in [
        "/usr/local/bin/traefik",
        "daemon-reload",
        "restart",
        "before-clear",
        "/etc/traefik/traefik.toml",
        "/etc/systemd/system/traefik.service",
        "/etc/traefik/dynamic/certificates.yml",
        "/var/lib/traefik-update-probes/checks.json",
        "/var/lib/traefik-transactions/route-inventory.json",
    ]:
        before_identity = engine.identity(cfg.transaction_policy)
        protected = {
            str(path): path.read_bytes() if path.exists() else None
            for path in engine.routine_paths(cfg.transaction_policy).values()
        }
        request, txid = fault_request(cfg)
        marker = Path(f"/var/tmp/traefik-death-{txid}")
        injection = f"""\nif __name__ == "__main__":
    _real_atomic, _real_run = atomic, run
    def crash():
        Path({str(marker)!r}).write_text("injected")
        os.kill(os.getpid(), 9)
    def atomic(path, data, mode=0o600):
        if {target!r} == "before-clear" and str(path) == str(STATE_ROOT / "state.json"):
            if json.loads(data).get("phase") == "clear":
                crash()
        _real_atomic(path, data, mode)
        if str(path) == {target!r}:
            crash()
    def run(argv, timeout=30):
        result = _real_run(argv, timeout)
        if argv == ["systemctl", {target!r}] or argv == ["systemctl", {target!r}, "traefik.service"]:
            crash()
        return result
"""
        source = transport.ENGINE.replace(
            b'if __name__ == "__main__":', injection.encode() + b'\nif __name__ == "__main__":'
        )
        with (
            patch.object(transport, "ENGINE", source),
            patch.object(transport, "ENGINE_SHA256", hashlib.sha256(source).hexdigest()),
        ):
            transport.stage_transaction(ACCESS, request, txid)
        transport.start_transaction(ACCESS, txid)
        status = transport.wait_for_transaction(ACCESS, txid, timeout=1600)
        assert marker.exists(), target
        assert status.final, status
        assert status.safe_restore, status
        assert status.safe_restore.get("phase") == "recovery", status
        assert engine.identity(cfg.transaction_policy) == before_identity
        for name, content in protected.items():
            path = Path(name)
            assert (path.read_bytes() if path.exists() else None) == content, name
        (evidence / f"death-{Path(target).name}.json").write_text(json.dumps(asdict(status), indent=2))
        transport.cleanup_transaction(ACCESS, txid)
        # This fixture owns the state; qualification explicitly verifies restoration before its next case.
        enroll_fixture(cfg)


def main() -> None:
    evidence = Path(sys.argv[1])
    # Demonstrate on this VM that argv leakage is visible and rejected.
    sentinel = "A" * 400
    negative_trace = evidence / "trace-negative-selfcheck.strace"
    subprocess.run([*TRACE_ARGS, "-o", str(negative_trace), "/usr/bin/python3", "-c", "pass", sentinel], check=True)
    try:
        assert_observation_trace("builtin printf '%s' " + sentinel, negative_trace.read_text().splitlines())
    except AssertionError as exc:
        if str(exc) != "payload in execve argv":
            raise RuntimeError("unexpected trace self-check failure") from exc
    else:
        raise AssertionError("trace payload negative self-check did not detect argv")
    assert engine.__file__
    provenance = {
        "implementation": os.environ["IMPLEMENTATION_SHA"],
        "harness": os.environ["HARNESS_SHA"],
        "engine_sha256": engine.digest(Path(engine.__file__)),
        "runner_sha256": transport.RUNNER_SHA256,
        "result": "started",
    }
    (evidence / "provenance.json").write_text(json.dumps(provenance, indent=2))
    marker = json.loads(Path("/var/tmp/traefik-routine-owned-vm.json").read_text())
    assert marker["machine"] == Path("/etc/machine-id").read_text().strip()
    journal = Path("/var/tmp/traefik-routine-journal")
    journal.mkdir(mode=0o700)
    cfg = import_module("ops_deploy.infra.traefik_routine").TraefikRoutineConfig(
        checksum="sha256:" + OLD_SHA,
        letsencrypt_email="fixture@example.com",
        canonical_host="fixture",
        ssh_address="127.0.0.1",
        controller_journal=journal / "fixture.json",
        authority="owned ephemeral VM fixture",
        implementation_reference=os.environ["IMPLEMENTATION_SHA"],
        configure_firewall=True,
        conflicting_web_services=("apache2.service", "caddy.service", "lighttpd.service"),
        file_certificates=(
            FileCertificate(cert_file="/etc/fixture-tls/cert.pem", key_file="/etc/fixture-tls/key.pem"),
        ),
    )
    write(
        "/etc/nginx/sites-enabled/default",
        'server { listen 127.0.0.1:18081; root /var/www/html; location / { return 200 "fixture backend"; } }\n',
    )
    run("nginx", "-t")
    run("systemctl", "enable", "--now", "nginx")
    run("systemctl", "restart", "nginx")
    nginx_pid = run("systemctl", "show", "nginx", "-p", "MainPID", "--value")
    assert run("ufw", "status") == "Status: inactive"
    Path("/etc/fixture-tls").mkdir(mode=0o700)
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "/etc/fixture-tls/key.pem",
        "-out",
        "/etc/fixture-tls/cert.pem",
        "-days",
        "2",
        "-subj",
        "/CN=fixture.example.com",
        "-addext",
        "subjectAltName=DNS:fixture.example.com",
    )
    write("/usr/local/share/ca-certificates/traefik-fixture.crt", Path("/etc/fixture-tls/cert.pem").read_text())
    run("update-ca-certificates")
    deploy(cfg, evidence, "fresh-install")
    deploy(cfg, evidence, "fresh-repeat")
    write(
        "/etc/traefik/dynamic/fixture.yml",
        """http:
  routers:
    fixture:
      rule: Host(`fixture.example.com`)
      entryPoints: [web]
      service: fixture
    fixture-secure:
      rule: Host(`fixture.example.com`)
      entryPoints: [web-secure]
      service: fixture
      tls: {}
  services:
    fixture:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:18081
""",
    )
    import yaml

    route_path = Path("/etc/traefik/dynamic/fixture.yml")
    route = yaml.safe_load(route_path.read_text())
    fixture_hash = run("openssl", "passwd", "-apr1", "-salt", "fixture1", "fixture-only-password")
    route["http"]["routers"]["protected"] = {
        "rule": "Host(`fixture.example.com`) && PathPrefix(`/protected`)",
        "entryPoints": ["web-secure"],
        "service": "fixture",
        "tls": {},
        "middlewares": ["fixture-auth"],
    }
    route["http"]["middlewares"] = {"fixture-auth": {"basicAuth": {"users": ["fixture:" + fixture_hash]}}}
    route_path.write_text(yaml.safe_dump(route))
    # Real loopback nginx backend remains active while the isolated proof cannot reach it.
    policy = {
        "host": "fixture",
        "binary_path": cfg.binary_path,
        "config_path": cfg.static_path,
        "dynamic_path": cfg.dynamic_path,
        "acme_paths": [cfg.acme_storage_path],
        "backup_paths": [
            cfg.binary_path,
            "/etc/traefik",
            str(engine.UNIT_PATH),
            cfg.acme_storage_path,
            "/etc/fixture-tls",
        ],
    }
    cfg = cfg.model_copy(update={"transaction_required": True, "transaction_policy": policy})
    spec = ProbeSpec(
        probes=(
            Probe(host="fixture.example.com", scheme="http", port=80, address="127.0.0.1"),
            Probe(host="fixture.example.com", scheme="https", port=443, address="127.0.0.1"),
            Probe(host="fixture.example.com", scheme="https", port=443, address="127.0.0.1", path="/protected"),
        ),
        entrypoints=("web", "web-secure", "traefik"),
        tls_fingerprints=True,
    )
    for _attempt in range(30):
        observed = subprocess.run(
            [
                "curl",
                "--silent",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--resolve",
                "fixture.example.com:443:127.0.0.1",
                "https://fixture.example.com/protected",
            ],
            capture_output=True,
            text=True,
        )
        if observed.returncode == 0 and observed.stdout == "401":
            break
        time.sleep(1)
    else:
        raise RuntimeError("fixture HTTPS/auth route did not settle")
    baseline = import_module("ops_deploy.infra.traefik_probes").capture_memory_traefik_health_probes(ACCESS, spec)
    write("/var/lib/traefik-update-probes/health.py", PROGRAM.decode(), 0o755)
    write(str(engine.PROBE_CONFIG), baseline.model_dump_json(exclude_unset=True), 0o600)
    enroll_fixture(cfg)
    deploy(cfg, evidence, "enrolled-repeat")
    cfg = cfg.model_copy(update={"version": "3.7.14", "checksum": "sha256:" + NEW_SHA})
    protected = {
        name: engine.digest(Path(name))
        for name in [
            cfg.acme_storage_path,
            "/etc/fixture-tls/cert.pem",
            "/etc/fixture-tls/key.pem",
            "/etc/traefik/dynamic/fixture.yml",
        ]
    }
    deploy(cfg, evidence, "binary-update")
    deploy(cfg, evidence, "binary-repeat")
    deploy(cfg.model_copy(update={"version": "3.7.13", "checksum": "sha256:" + OLD_SHA}), evidence, "floor-repeat")
    write("/etc/traefik/dynamic/other-owner.yml", "# unrelated route-owner baseline\n")
    deploy(cfg, evidence, "route-rebaseline")
    deploy(cfg, evidence, "route-repeat")
    cfg = cfg.model_copy(update={"log_level": "WARN"})
    deploy(cfg, evidence, "static-update")
    deploy(cfg, evidence, "static-repeat")
    # Exercise the ordinary caller's unit and owned-certificate desired reconciliation.
    write(str(engine.UNIT_PATH), render_unit(cfg) + "# fixture baseline\n")
    write(
        "/etc/traefik/dynamic/certificates.yml",
        Path("/etc/traefik/dynamic/certificates.yml").read_text() + "# baseline\n",
    )
    run("systemctl", "daemon-reload")
    enroll_fixture(cfg)
    deploy(cfg, evidence, "unit-certificate-repair")
    deploy(cfg, evidence, "repair-repeat")
    record = cfg.controller_journal.read_bytes()
    cfg.controller_journal.unlink()
    deploy(cfg, evidence, "missing-record-refusal", refusal=True)
    cfg.controller_journal.write_bytes(record)
    cfg.controller_journal.chmod(0o600)
    deaths(cfg, evidence)
    deploy(cfg, evidence, "final-repeat")
    assert {name: engine.digest(Path(name)) for name in protected} == protected
    assert run("systemctl", "show", "nginx", "-p", "MainPID", "--value") == nginx_pid
    assert run("systemctl", "is-enabled", "nginx") == "enabled"
    assert run("ufw", "status") == "Status: inactive"
    assert "ufw allow 80/tcp" in run("ufw", "show", "added")
    assert "ufw allow 443/tcp" in run("ufw", "show", "added")
    (evidence / "protection.json").write_text(json.dumps({"unchanged": True, "sha256": protected}, indent=2))
    (evidence / "provenance.json").write_text(
        json.dumps(
            {
                "implementation": os.environ["IMPLEMENTATION_SHA"],
                "harness": os.environ["HARNESS_SHA"],
                "result": "passed",
            }
        )
    )


if __name__ == "__main__":
    main()
