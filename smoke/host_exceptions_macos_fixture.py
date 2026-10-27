"""Both native baseline branches on one disposable hosted macOS machine."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import pwd
import secrets
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ollama_macos_fixture import command, owned_runner, pid, unload

from ops_deploy.base import HostnameConfig, deploy_hostname
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.graphyard import GraphyardVectorConfig, GraphyardVectorDarwinConfig, deploy_graphyard_vector
from ops_deploy.testing import run_deploy_ssh

TOKEN = secrets.token_hex(32)
VALUES = SecretValues(SecretRef("fixture.yml"), {"vector_ingest_token": TOKEN})
DELIVERED = 0


class Ingest(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        global DELIVERED
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_response(401)
            self.end_headers()
            return
        events = json.loads(body)
        assert isinstance(events, list)
        DELIVERED += len(events)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


def deploy(cfg: GraphyardVectorConfig, *, succeeds: bool = True) -> list[str]:
    result = run_deploy_ssh(deploy_graphyard_vector, cfg, VALUES, host_name="@local", host_data={})
    assert result.succeeded is succeeds, str(result.error)
    assert TOKEN not in str(result.error)
    return result.mutating_changed_ops


def name_state() -> dict[str, dict[str, Any]]:
    result = {}
    for key in ("HostName", "ComputerName", "LocalHostName"):
        response = command("/usr/sbin/scutil", "--get", key, check=False)
        result[key] = {"rc": response.returncode, "value": response.stdout.strip()}
    return result


def names() -> dict[str, str]:
    return {key: value["value"] for key, value in name_state().items()}


def state(cfg: GraphyardVectorConfig) -> dict[str, Any]:
    assert cfg.darwin is not None
    paths = [cfg.config_path, cfg.global_config_path, cfg.darwin.newsyslog_conf_path, cfg.darwin.launchd_plist_path]
    peer = Path(cfg.config_dir) / "10-retained-peer.toml"
    if peer.exists():
        paths.append(peer)
    result = {}
    for path in paths:
        assert path is not None
        p = Path(path)
        s = p.stat()
        result[str(path)] = {
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "inode": s.st_ino,
            "uid": s.st_uid,
            "gid": s.st_gid,
            "mode": s.st_mode,
            "mtime_ns": s.st_mtime_ns,
            "ctime_ns": s.st_ctime_ns,
        }
    return {"files": result, "pid": pid(cfg.darwin.launchd_label)}


def buffer_topology(cfg: GraphyardVectorConfig) -> dict[str, Any]:
    root = Path(cfg.data_dir)
    result = {}
    for path in (root, *root.rglob("*")):
        metadata = path.stat()
        result[str(path.relative_to(root))] = {
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": metadata.st_mode,
        }
    return result


def no_op(cfg: GraphyardVectorConfig, report: dict[str, Any], name: str) -> None:
    before = state(cfg)
    buffers = buffer_topology(cfg)
    changes = deploy(cfg)
    assert changes == []
    assert state(cfg) == before
    after = buffer_topology(cfg)
    for path, metadata in buffers.items():
        assert after.get(path) == metadata, "owned buffer topology changed during no-op"
    report["repeats"][name] = changes
    report.setdefault("buffer_continuity", {})[name] = {
        "original_entries": len(buffers),
        "new_entries": len(set(after) - set(buffers)),
        "original_metadata_preserved": True,
        "size_mtime_excluded": "active Vector may append; buffer contents never read",
        "inline_apply_or_staging_selected": False,
    }


def wait_delivery(previous: int) -> None:
    for _ in range(30):
        if previous < DELIVERED:
            return
        time.sleep(1)
    raise AssertionError("owned Vector did not deliver host metrics")


def main() -> None:
    run_id = owned_runner()
    source = Path(__file__).resolve().parents[1]
    expected = os.environ["IMPLEMENTATION_SHA"]
    assert (
        command("git", "-c", "safe.directory=" + str(source), "-C", str(source), "rev-parse", "HEAD").stdout.strip()
        == expected
    )
    dist = importlib.metadata.distribution("ops-deploy")
    assert not json.loads(dist.read_text("direct_url.json") or "{}").get("dir_info", {}).get("editable")
    installed = Path(str(importlib.resources.files("ops_deploy")))
    assert installed.is_relative_to(Path("/private/var/tmp/baseline-controller"))
    hashes = {}
    for relative in (
        "base/hostname.py",
        "services/graphyard/vector.py",
        "services/graphyard/vector_darwin.py",
        "services/graphyard/files/graphyard_vector_host.py",
        "services/graphyard/templates/vector.launchd.plist.j2",
        "services/graphyard/templates/vector.newsyslog.conf.j2",
    ):
        content = (installed / relative).read_bytes()
        assert content == (source / "src/ops_deploy" / relative).read_bytes()
        hashes[relative] = hashlib.sha256(content).hexdigest()
    suffix = run_id + "-" + str(os.getpid())
    root = Path("/private/var/tmp") / ("ops-deploy-baseline-" + suffix)
    label = "com.example.ops-deploy.graphyard-" + suffix
    plist = Path("/Library/LaunchDaemons") / (label + ".plist")
    assert not root.exists()
    assert not plist.exists()
    legacy = Path("/etc/vector/vector.yaml")
    assert not os.path.lexists(legacy)
    created_legacy_parent = not legacy.parent.exists()
    brew = os.environ["FIXTURE_BREW_BIN"]
    owner = pwd.getpwuid(Path(brew).stat().st_uid).pw_name
    assert owner == "runner"

    def brew_run(*args: str) -> str:
        return command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            owner,
            "--",
            "/usr/bin/env",
            "HOMEBREW_NO_AUTO_UPDATE=1",
            brew,
            *args,
            check=False,
        ).stdout.strip()

    assert not brew_run("list", "--versions", "vector"), "fixture requires an absent Vector package to prove install"
    evidence = Path(os.environ["BASELINE_EVIDENCE_DIR"])
    evidence.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "implementation_sha": expected,
        "resource_hashes": hashes,
        "scope": "owned GitHub-hosted macOS; no inventory host",
        "repeats": {},
    }
    original = name_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Ingest)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    native = GraphyardVectorDarwinConfig(
        brew_user=owner,
        brew_bin=Path(brew),
        launchd_label=label,
        launchd_plist_path=plist,
        log_dir=root / "logs",
        newsyslog_conf_path=root / "newsyslog.conf",
    )
    cfg = GraphyardVectorConfig(
        host_id="fixture",
        service_id="fixture_host_metrics",
        source_tag="fixture-vector",
        ingest_url=f"http://127.0.0.1:{server.server_port}/v1/metrics",
        config_dir=root / "config",
        data_dir=root / "data",
        darwin=native,
        scrape_interval_secs=1,
        collectors=("cpu", "filesystem"),
        metric_prefixes=("cpu_",),
        filesystem_mountpoint_excludes=("/Volumes/Backups of fixture",),
    )
    try:
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.symlink_to(root / "owned-obsolete-monolithic-config")
        name = "ops-baseline-" + run_id[-10:]
        # Exercise the real unset case, not just a different configured value.
        command("/usr/sbin/scutil", "--set", "HostName", "")
        assert name_state()["HostName"]["rc"] != 0
        hostname = run_deploy_ssh(deploy_hostname, HostnameConfig(hostname=name), host_name="@local", host_data={})
        assert hostname.succeeded, str(hostname.error)
        assert set(names().values()) == {name}
        repeat = run_deploy_ssh(deploy_hostname, HostnameConfig(hostname=name), host_name="@local", host_data={})
        assert repeat.succeeded
        assert repeat.mutating_changed_ops == []
        report["repeats"]["hostname"] = repeat.mutating_changed_ops
        report["initial_changes"] = deploy(cfg)
        assert not os.path.lexists(legacy)
        report["owned_legacy_config_removed"] = True
        wait_delivery(0)
        peer = Path(cfg.config_dir) / "10-retained-peer.toml"
        peer.write_text("[api]\nenabled = false\n")
        peer.chmod(0o640)
        before = state(cfg)
        no_op(cfg, report, "initial")
        report["installed_package"] = brew_run("list", "--versions", "vector")
        binary = Path(brew_run("--prefix")) / "bin/vector"
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["binary_version"] = command(str(binary), "--version").stdout.strip()
        update = cfg.model_copy(update={"darwin": native.model_copy(update={"brew_update": True})})
        report["explicit_metadata_update_changes"] = deploy(update)
        assert report["explicit_metadata_update_changes"]
        assert state(cfg) == before
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == report["binary_sha256"]
        no_op(cfg, report, "metadata-update")
        brew_run("services", "start", "vector")
        entries = json.loads(brew_run("services", "info", "vector", "--json"))
        assert any(item.get("loaded") or item.get("running") or item.get("registered") for item in entries)
        invalid_with_duplicate = cfg.model_copy(update={"collectors": ("not_a_collector",)})
        deploy(invalid_with_duplicate, succeeds=False)
        assert state(cfg) == before
        retained = json.loads(brew_run("services", "info", "vector", "--json"))
        assert any(item.get("loaded") or item.get("running") or item.get("registered") for item in retained)
        report["owned_brew_duplicate_changes"] = deploy(cfg)
        assert report["owned_brew_duplicate_changes"]
        stopped = json.loads(brew_run("services", "info", "vector", "--json"))
        assert not any(item.get("loaded") or item.get("running") or item.get("registered") for item in stopped)
        assert state(cfg) == before
        no_op(cfg, report, "brew-duplicate")
        # Real parser failure must preserve the valid files and active PID.
        invalid = cfg.model_copy(update={"collectors": ("not_a_collector",)})
        deploy(invalid, succeeds=False)
        assert state(cfg) == before
        missing = cfg.model_copy(update={"darwin": native.model_copy(update={"binary_path": root / "missing-vector"})})
        deploy(missing, succeeds=False)
        assert state(cfg) == before
        changed = cfg.model_copy(
            update={
                "batch_max_events": 10,
                "darwin": native.model_copy(update={"launchd_path": native.launchd_path + ":/usr/local/sbin"}),
            }
        )
        previous = DELIVERED
        assert deploy(changed)
        wait_delivery(previous)
        updated = state(changed)
        assert updated["pid"] != before["pid"]
        no_op(changed, report, "config")
        unload(label)
        assert deploy(changed)
        wait_delivery(DELIVERED)
        no_op(changed, report, "recovery")
        report["delivered_event_count"] = DELIVERED
        report["faults"] = [
            "actual Vector invalid config preserves files/PID",
            "missing executable preserves files/PID",
        ]
        report["installer_coverage"] = (
            "actual absent formula install plus present/config/service paths; no formula upgrade"
        )
    except BaseException as error:
        # Exception text may contain fixture payloads. The CI traceback records
        # the failing assertion; the artifact keeps its type without secrets.
        report["failure"] = type(error).__name__
        raise
    finally:
        errors = []
        try:
            brew_run("services", "stop", "vector")
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            for key, entry in original.items():
                command("/usr/sbin/scutil", "--set", key, entry["value"] if entry["rc"] == 0 else "")
            # Distinguish an unset preference (nonzero get) from empty text.
            assert name_state() == original
        except Exception as error:
            errors.append("hostname/endpoint cleanup: " + type(error).__name__)
        try:
            unload(label)
        except Exception as error:
            # Retain the owned plist/tree if launchd cannot release the job.
            errors.append("launchd cleanup: " + type(error).__name__)
        else:
            try:
                plist.unlink(missing_ok=True)
                if root.exists():
                    shutil.rmtree(root)
            except Exception as error:
                errors.append("owned plist/tree cleanup: " + type(error).__name__)
        try:
            if legacy.is_symlink() and os.readlink(legacy) == str(root / "owned-obsolete-monolithic-config"):
                legacy.unlink()
            if created_legacy_parent:
                legacy.parent.rmdir()
        except Exception as error:
            errors.append("owned legacy cleanup: " + type(error).__name__)
        report["cleanup_completed"] = not errors
        report["cleanup_errors"] = errors
        (evidence / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        if errors:
            raise RuntimeError("owned fixture cleanup failed; see result.json")
    print(
        json.dumps(
            {
                "passed": True,
                "result": str(evidence / "result.json"),
                "version": report["binary_version"],
                "repeats": report["repeats"],
            }
        )
    )


if __name__ == "__main__":
    main()
