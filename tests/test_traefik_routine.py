"""Ordinary deployment extensions: real files and the actual detached recovery caller."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from ops_deploy.backups.remote import SubprocessRunner
from ops_deploy.infra.traefik_tx import engine, transport


def test_inspect_memory_has_no_files_even_on_refusal(tmp_path: Path) -> None:
    before = list(tmp_path.iterdir())
    with patch.object(transport, "PYTHON", sys.executable):
        result = transport.inspect_memory_host(SubprocessRunner(), {"host": "bad/host"})
    assert result.exit_code == 2
    assert result.response["error"] == "invalid canonical host"
    assert list(tmp_path.iterdir()) == before


@pytest.fixture
def owned_tree(tmp_path: Path) -> dict[str, Path]:
    paths = {
        name: tmp_path / name
        for name in ("binary", "static", "unit", "certificates", "probe_config", "route_inventory")
    }
    for name, path in paths.items():
        path.write_text(f"original {name}\n")
        path.chmod(0o600 if name in {"probe_config", "route_inventory"} else 0o644)
    return paths


def relaxed_file(path: Path) -> None:
    assert path.is_file()
    assert not path.is_symlink()


def test_restore_all_originals_and_absence(owned_tree: dict[str, Path], tmp_path: Path) -> None:
    directory = tmp_path / "transaction"
    directory.mkdir()
    owned_tree["certificates"].unlink()
    policy: dict[str, Any] = {"host": "fixture"}
    with (
        patch.object(engine, "routine_paths", return_value=owned_tree),
        patch.object(engine, "trusted_file", side_effect=relaxed_file),
        patch.object(engine, "trusted_file_parent"),
        patch.object(engine, "run") as run,
    ):
        engine.manifest_snapshot(directory, policy, {name: b"candidate" for name in owned_tree})
        # The test user is not root; emulate only the snapshot ownership, not restore behavior.
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for item in manifest["entries"].values():
            if item["original"]["exists"]:
                item["original"].update(uid=0, gid=0)
        engine.save(manifest_path, manifest)
        expected = engine.digest(manifest_path)
        for path in owned_tree.values():
            path.write_text("candidate")
        engine.restore_manifest(policy, directory, expected)
        for name, path in owned_tree.items():
            if name == "certificates":
                assert not path.exists()
            else:
                assert path.read_text() == f"original {name}\n"
        run.assert_called_once_with(["systemctl", "daemon-reload"])


def test_corrupt_original_refuses_before_any_restore(owned_tree: dict[str, Path], tmp_path: Path) -> None:
    directory = tmp_path / "transaction"
    directory.mkdir()
    with (
        patch.object(engine, "routine_paths", return_value=owned_tree),
        patch.object(engine, "trusted_file", side_effect=relaxed_file),
        patch.object(engine, "trusted_file_parent"),
    ):
        engine.manifest_snapshot(directory, {}, {name: b"candidate" for name in owned_tree})
        (directory / "original-static").write_text("corrupted")
        before = {name: path.read_bytes() for name, path in owned_tree.items()}
        with pytest.raises(engine.Refused, match="restore original changed"):
            engine.restore_manifest({}, directory, engine.digest(directory / "manifest.json"))
        assert {name: path.read_bytes() for name, path in owned_tree.items()} == before


def test_ordinary_evidence_does_not_require_manual_observer_attestations() -> None:
    live = {"version": "3.7.14"}
    request: dict[str, Any] = {
        "action": "routine",
        "evidence": {
            "kind": "ordinary",
            "baseline": live,
            "verified_at": 100,
            "owner": "standing ordinary deployment authority",
            "review_reference": "reviewed immutable implementation",
            "recovery_access": "root SSH observed",
            "observations": {"identity": live, "probes": [{"exit": 0, "status": "401"}]},
        },
    }
    with patch("time.time", return_value=100):
        engine.evidence(request, live)
        request["evidence"]["observations"]["probes"][0]["exit"] = 7
        with pytest.raises(engine.Refused, match="invalid automatic ingress"):
            engine.evidence(request, live)


def test_routine_staging_without_release_does_not_invent_archive() -> None:
    request = {"action": "routine", "files": {"static": "[api]\n"}}
    data = json.loads(transport.staged_request(request, "6f1c2c1e-0a3b-4c5d-8e9f-0123456789ab"))
    assert data == request


@pytest.mark.parametrize("fail_acceptance", [False, True])
def test_routine_execute_changes_or_restores_static_through_production_caller(
    tmp_path: Path, fail_acceptance: bool
) -> None:
    from tests.traefik_tx_fixtures import FakeHost, base_setup

    host = FakeHost(engine, tmp_path)
    host.install()
    with host.patched(), patch.object(engine, "trusted_file_parent"):
        setup = base_setup(host, "routine")
        request = setup.request
        request.pop("release")
        request.pop("archive_path")
        original = host.config.read_text()
        candidate = original + '\n[log]\nlevel = "WARN"\n'
        request["files"] = {"static": candidate}
        sha = hashlib.sha256(candidate.encode()).hexdigest()
        live = host.identity(request["policy"])
        request["compatibility"].update(
            candidate_binary_sha256=live["binary_sha256"],
            candidate_config_sha256=sha,
            candidate_dynamic_sha256=live["dynamic_sha256"],
            candidate_unit_sha256=live["unit_sha256"],
            routine_files={"static": sha},
        )
        host.state_root.mkdir(mode=0o700)
        engine.save(host.state_root / "state.json", setup.state)
        if fail_acceptance:
            host.failing["acceptance"] = 1
        original_snapshot = engine.snapshot_file

        def root_snapshot(path: Path) -> dict[str, Any]:
            value = original_snapshot(path)
            if value["exists"]:
                value.update(uid=0, gid=0)
            return value

        with patch.object(engine, "snapshot_file", side_effect=root_snapshot):
            result = engine.execute(request)
        assert result["changed"] is True
        assert host.config.read_text() == (original if fail_acceptance else candidate)
        assert result["state"]["phase"] == ("recovery" if fail_acceptance else "clear")
        assert host.calls.count("restart") == (2 if fail_acceptance else 1)
        assert "probe acceptance" in host.calls


def test_semantic_comparison_does_not_hide_unknown_changes() -> None:
    from ops_deploy.infra.traefik_routine import static_equivalent

    assert static_equivalent("[metrics.prometheus]\n", '[metrics.prometheus]\nentryPoint="traefik"\n')
    assert not static_equivalent("[metrics.prometheus]\n", '[metrics.prometheus]\nentryPoint="other"\n')
    assert not static_equivalent("[api]\ndebug=false\n", "[api]\ndebug=true\n")


def test_converged_enrolled_caller_does_not_stage_upload_or_write_journal(tmp_path: Path) -> None:
    from ops_deploy.infra import traefik_routine as routine
    from ops_deploy.infra.traefik_deploy import render_static, render_unit
    from ops_deploy.infra.traefik_probes import Probe, ProbeBaseline
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost
    from tests.test_infra_traefik import converged

    cfg = routine.TraefikRoutineConfig(
        checksum="sha256:" + "a" * 64,
        letsencrypt_email="fixture@example.com",
        canonical_host="fixture",
        ssh_address="127.0.0.1",
        controller_journal=tmp_path / "fixture.json",
        transaction_required=True,
        authority="standing fixture authority",
        implementation_reference="fixture",
    )
    live = {"version": "3.7.13", "dynamic_sha256": engine.canonical([])}
    record = {"identity": live, "phase": "clear"}
    baseline = ProbeBaseline(
        probes=(Probe(host="example.com", scheme="http", port=80, address="127.0.0.1"),),
        entrypoints=("web",),
        observations=({"status": "401", "exit": 0},),
        dynamic={},
    )
    found = {
        cfg.static_path: {"text": render_static(cfg)},
        str(engine.UNIT_PATH): {"text": render_unit(cfg)},
        str(engine.PROBE_CONFIG): {"text": baseline.model_dump_json()},
        f"{cfg.dynamic_path}/certificates.yml": None,
    }
    with (
        patch.object(routine, "admitted", return_value=(record, live)),
        patch.object(routine, "resources", return_value=found),
        patch.object(routine, "capture_memory_traefik_health_probes", return_value=baseline),
        patch.object(routine, "apply_core", side_effect=AssertionError("unexpected mutation")),
        patch.object(transport, "stage_transaction", side_effect=AssertionError("unexpected stage")),
    ):
        result = run_deploy_fake(
            routine.deploy_traefik_routine,
            cfg,
            responses={
                **converged(cfg),
                **fakehost.stat(cfg.binary_path, mode="-rwxr-xr-x"),
            },
        )
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert result.uploaded_paths == []
    assert list(tmp_path.iterdir()) == []


def test_required_enrollment_cannot_fall_back_to_unguarded_deployment(tmp_path: Path) -> None:
    from ops_deploy.infra import traefik_routine as routine
    from ops_deploy.testing import run_deploy_fake
    from tests.test_infra_traefik import converged

    cfg = routine.TraefikRoutineConfig(
        checksum="sha256:" + "a" * 64,
        letsencrypt_email="fixture@example.com",
        canonical_host="fixture",
        ssh_address="127.0.0.1",
        controller_journal=tmp_path / "absent.json",
        transaction_required=True,
        authority="standing fixture authority",
        implementation_reference="fixture",
    )
    with (
        patch.object(
            transport, "inspect_memory_host", return_value=transport.EngineRun(0, {"identity": {}, "state": None})
        ),
        patch("ops_deploy.infra.traefik_deploy.deploy_traefik", side_effect=AssertionError("unguarded fallback")),
    ):
        result = run_deploy_fake(routine.deploy_traefik_routine, cfg, responses=converged(cfg))
    assert not result.succeeded
    assert result.uploaded_paths == []
    assert result.executed_commands == []


def test_real_health_accepts_the_transaction_probe_serialization(tmp_path: Path) -> None:
    import http.server
    import subprocess
    import threading

    from ops_deploy.infra.traefik_probes import Probe, ProbeBaseline
    from ops_deploy.infra.traefik_routine import transaction_probes

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(301)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        baseline = ProbeBaseline(
            probes=(Probe(host="localhost", scheme="http", port=server.server_port, address="127.0.0.1"),),
            entrypoints=("web",),
            observations=({"status": "301", "exit": 0},),
            dynamic={},
        )
        payload = transaction_probes("fixture", baseline, baseline)
        program = tmp_path / "health.py"
        # Substitute only the fixture's dynamic-root path; execute the actual health implementation.
        dynamic = tmp_path / "dynamic"
        dynamic.mkdir()
        program.write_text(payload["probe_files"]["health.py"].replace("/etc/traefik/dynamic", str(dynamic)))
        for name in ("baseline.json", "candidate.json"):
            config = tmp_path / name
            config.write_text(payload["probe_files"][name])
            result = subprocess.run(
                [sys.executable, str(program), "health", str(config)],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            assert result.returncode == 0, result.stderr
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_absent_binary_reaches_the_actual_non_enrolled_install_path(tmp_path: Path) -> None:
    from ops_deploy.infra import traefik_routine as routine
    from ops_deploy.testing import run_deploy_fake
    from tests.test_infra_traefik import converged

    cfg = routine.TraefikRoutineConfig(
        checksum="sha256:" + "a" * 64,
        letsencrypt_email="fixture@example.com",
        canonical_host="fixture",
        ssh_address="127.0.0.1",
        controller_journal=tmp_path / "absent.json",
        transaction_required=False,
        authority="fixture",
        implementation_reference="fixture",
    )
    responses = converged(cfg)
    responses["/usr/local/bin/traefik version"] = []
    responses["uname -m"] = ["x86_64"]
    result = run_deploy_fake(routine.deploy_traefik_routine, cfg, responses=responses)
    assert result.succeeded, result.error
    assert any("Install Traefik" in name for name in result.mutating_changed_ops)


def test_memory_transport_has_no_heredoc_or_payload_in_python_argv() -> None:
    import base64
    import re
    import shlex
    import zlib

    source = "print('private-fixture-marker')\n" + "# source padding\n" * 10000
    script = transport.memory_script(source)
    assert "<<" not in script
    match = re.search(r"^builtin printf '%s' ([A-Za-z0-9+/=]+) \| ", script)
    assert match is not None
    packet = match[1]
    assert zlib.decompress(base64.b64decode(packet)).decode() == source
    argv = shlex.split(script.split("|", 1)[1])
    assert packet not in argv
    assert all("private-fixture-marker" not in arg for arg in argv)


def test_mutating_path_creates_only_a_safe_controller_lock(tmp_path: Path) -> None:
    from pyinfra.api import DeployError

    from ops_deploy.infra import traefik_routine as routine
    from ops_deploy.infra.traefik_probes import Probe, ProbeSpec

    cfg = routine.TraefikRoutineConfig(
        checksum="sha256:" + "a" * 64,
        letsencrypt_email="fixture@example.com",
        canonical_host="fixture",
        ssh_address="127.0.0.1",
        controller_journal=tmp_path / "fixture.json",
        transaction_required=True,
        authority="fixture",
        implementation_reference="fixture",
    )
    spec = ProbeSpec(
        probes=(Probe(host="localhost", scheme="http", port=80, address="127.0.0.1"),), entrypoints=("web",)
    )
    with patch.object(routine, "admitted", side_effect=DeployError("after lock acquired")) as admission:
        with pytest.raises(DeployError, match="after lock acquired"):
            routine.apply_core(cfg, SubprocessRunner(), {}, {}, {}, spec, None)
        admission.assert_called_once()
    lock = tmp_path / "fixture.lock"
    assert lock.stat().st_mode & 0o777 == 0o600
    lock.unlink()
    victim = tmp_path / "victim"
    victim.write_text("protected")
    lock.symlink_to(victim)
    with (
        patch.object(routine, "admitted", side_effect=AssertionError("followed lock symlink")),
        pytest.raises(OSError, match="symbolic links"),
    ):
        routine.apply_core(cfg, SubprocessRunner(), {}, {}, {}, spec, None)
    assert victim.read_text() == "protected"


@pytest.mark.parametrize(("machine", "expected"), [("aarch64", "arm64"), ("x86_64", "amd64")])
def test_selected_release_reads_target_architecture_and_preserves_newer_floor(
    tmp_path: Path, machine: str, expected: str
) -> None:
    from ops_deploy.infra import traefik_routine as routine

    cfg = routine.TraefikRoutineConfig(
        version="3.7.14",
        checksum="sha256:" + "a" * 64,
        letsencrypt_email="fixture@example.com",
        canonical_host="fixture",
        ssh_address="127.0.0.1",
        controller_journal=tmp_path / "fixture.json",
        authority="fixture",
        implementation_reference="fixture",
    )
    with patch.object(routine, "output", return_value=machine) as target:
        assert routine.selected_release(cfg, "3.7.13") == {"version": "3.7.14", "arch": expected, "sha256": "a" * 64}
        target.assert_called_once_with("uname -m")
    with patch.object(routine, "output", side_effect=AssertionError("unnecessary remote observation")):
        assert routine.selected_release(cfg, "3.7.16") is None
