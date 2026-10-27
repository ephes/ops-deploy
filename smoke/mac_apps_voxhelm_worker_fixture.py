"""Actual ARM Voxhelm remote worker: public PyPI/Parakeet/models, launchd, fault, repeat.

The worker polls an owned loopback control plane that never offers a job, so
no audio is fetched and nothing is transcribed. Parakeet weights and whisper.cpp
models are real public pinned downloads, verified independently here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mac_apps_owned import OwnedMac, command, file_state, job_pid, port

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.services.voxhelm_remote_worker import VoxhelmRemoteWorkerConfig, deploy_voxhelm_remote_worker
from ops_deploy.services.voxhelm_remote_worker.render import payload
from ops_deploy.testing import run_deploy_ssh

UV_SHA = "743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73"
WHISPER_TREE = "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/"
TINY_EN = ("ggml-tiny.en.bin", "921e4cf8686fdd993dcd081a5da5b6c365bfde1162e72b08d75ac75289920b1f")
TINY = ("ggml-tiny.bin", "be07e048e1e599ad46341c8d2a135645097a538221678b7acdd1b1919c6e1b21")
PARAKEET_SHA = "05e01c7f396c298cf7d23f61da7b504adeab698f0aaeafd9c82d198625464592"
PREFIX = "voxhelm_remote_worker_"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def metadata_only(paths: list[Path]) -> dict[str, tuple[int, ...]]:
    return {
        str(path): (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        for path in paths
        for s in [path.lstat()]
    }


class ControlPlane:
    """Owned loopback worker API: heartbeats are accepted, claims never return a job."""

    def __init__(self, token: str, worker_id: str):
        self.calls: list[dict[str, Any]] = []
        calls = self.calls

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                calls.append(
                    {
                        "path": self.path,
                        "authorized": self.headers.get("Authorization") == "Bearer " + token,
                        "worker_id": body.get("worker_id") == worker_id,
                        "capabilities": sorted(body.get("capabilities", {})),
                    }
                )
                if self.path == "/v1/internal/workers/heartbeat":
                    data = json.dumps({"poll_after_seconds": 2}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                elif self.path == "/v1/internal/work/claim":
                    self.send_response(204)
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def wait(self, after: int, seconds: float = 300) -> list[dict[str, Any]]:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            paths = {call["path"] for call in self.calls[after:]}
            if {"/v1/internal/workers/heartbeat", "/v1/internal/work/claim"} <= paths:
                return self.calls[after:]
            time.sleep(1)
        raise AssertionError("owned worker did not heartbeat and poll the owned control plane")

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def main() -> None:
    owned = OwnedMac("voxhelm-worker")
    failure: BaseException | None = None
    control: ControlPlane | None = None
    try:
        root = owned.root
        owned.verify_implementation()
        owned.report["stage"] = "verified uv, owned account and public fixture models"
        installed_uv = run_deploy_ssh(
            deploy_uv_install,
            UvInstallConfig(
                darwin=True,
                version="0.13.5",
                checksums={"aarch64-apple-darwin": UV_SHA},
                install_dir=str(root / "tool-bin"),
                owner="root",
                group="wheel",
            ),
            host_name="@local",
            host_data={},
        )
        assert installed_uv.succeeded, str(installed_uv.error)
        user, home = owned.create_existing_user("worker")
        uid = int(command("/usr/bin/dscl", ".", "-read", "/Users/" + user, "UniqueID").stdout.split()[-1])
        for relative in ["Library", "Library/Caches", "Library/Application Support"]:
            (home / relative).mkdir(mode=0o700)
            os.chown(home / relative, uid, 20)
        public = root / "public-models"
        public.mkdir(mode=0o755)
        source_model = public / TINY_EN[0]
        urllib.request.urlretrieve(WHISPER_TREE + TINY_EN[0], source_model)
        assert sha256(source_model) == TINY_EN[1]
        source_model.chmod(0o644)
        owned.report["limitations"].append(
            "Homebrew formulae installed for the fixture remain until the disposable VM is destroyed."
        )
        launchd = root / "launchd"
        launchd.mkdir(mode=0o755)
        label = owned.label("voxhelm-remote-worker")
        token = "owned-fixture-worker-" + owned.suffix
        control = ControlPlane(token, "fixture-worker")
        secrets = {
            PREFIX + "token": token,
            PREFIX + "artifact_s3_access_key_id": "owned-fixture-access-" + owned.suffix,
            PREFIX + "artifact_s3_secret_access_key": "owned-fixture-secret-" + owned.suffix,
        }
        base: dict[str, Any] = {
            PREFIX + "service_user": user,
            PREFIX + "service_group": "staff",
            PREFIX + "service_home": str(home),
            PREFIX + "config_dir": str(root / "etc"),
            PREFIX + "log_dir": str(root / "logs"),
            PREFIX + "uv_bin": str(root / "tool-bin/uv"),
            PREFIX + "python_version": "3.14.8",
            PREFIX + "package_version": "0.1.11",
            # The diarization extra needs a private Hugging Face credential.
            PREFIX + "package_extras": [],
            PREFIX + "diarization_backend": "none",
            PREFIX + "base_url": "http://127.0.0.1:" + str(control.server.server_port),
            PREFIX + "id": "fixture-worker",
            PREFIX + "hostname": "fixture-worker.local",
            PREFIX + "poll_seconds": 2,
            PREFIX + "launchd_label": label,
            PREFIX + "launchd_plist_path": str(launchd / (label + ".plist")),
            PREFIX + "brew_user": "runner",
            # No Metal device is assumed in the VM, so MLX is never selected.
            PREFIX + "stt_backend": "whispercpp",
            PREFIX + "whispercpp_model": TINY_EN[0],
            PREFIX + "whispercpp_model_source": str(source_model),
            PREFIX + "parakeet_enabled": True,
            PREFIX + "ad_analysis_enabled": True,
            PREFIX + "window_model": TINY[0],
            PREFIX + "window_model_url": WHISPER_TREE + TINY[0],
            PREFIX + "window_model_sha256": TINY[1],
            # Never contacted: no job is ever offered.
            PREFIX + "artifact_s3_endpoint_url": "http://127.0.0.1:" + str(port()),
        }
        cfg = VoxhelmRemoteWorkerConfig.model_validate(base)
        cache = Path(cfg.voxhelm_remote_worker_model_cache_dir)
        parakeet = Path(cfg.voxhelm_remote_worker_parakeet_model_dir)

        def deploy(config: VoxhelmRemoteWorkerConfig, *, succeeds: bool = True) -> list[str]:
            result = run_deploy_ssh(deploy_voxhelm_remote_worker, config, secrets, host_name="@local", host_data={})
            assert result.succeeded is succeeds, str(result.error)
            for value in secrets.values():
                assert value not in str(result.error)
            return result.mutating_changed_ops

        def tool(binary: str, package: str) -> list[str]:
            python = Path(binary).resolve().parent / "python"
            code = (
                "import importlib.metadata,json,platform;"
                "print(json.dumps([importlib.metadata.version(" + repr(package) + "),platform.python_version()]))"
            )
            return list(json.loads(command(str(python), "-B", "-c", code).stdout))

        def state(config: VoxhelmRemoteWorkerConfig) -> dict[str, Any]:
            files = [Path(path) for path in payload(config, secrets)["contents"]]
            files += [
                Path(config.voxhelm_remote_worker_install_transcript_path),
                Path(config.voxhelm_remote_worker_config_dir) / ".native-artifacts.json",
                parakeet / "VOXHELM_MODEL_REVISION",
                parakeet / "config.json",
            ]
            models = [
                cache / TINY_EN[0],
                cache / config.voxhelm_remote_worker_window_model,
                parakeet / "model.safetensors",
            ]
            models += [Path(config.voxhelm_remote_worker_binary_path), Path(config.voxhelm_remote_worker_parakeet_bin)]
            return {
                "files": file_state(files),
                "models": metadata_only(models),
                "pid": job_pid("system/" + label),
                "restart_intent": os.path.lexists(
                    Path(config.voxhelm_remote_worker_config_dir) / ".ops-deploy-restart"
                ),
            }

        def no_op(config: VoxhelmRemoteWorkerConfig, name: str) -> None:
            before = state(config)
            assert not before["restart_intent"]
            changes = deploy(config)
            assert changes == [], changes
            assert state(config) == before
            owned.report["repeats"][name] = changes

        owned.report["stage"] = "fresh public worker, Parakeet and ad-analysis profile"
        owned.report["first_changes"] = deploy(cfg)
        assert owned.report["first_changes"]
        calls = control.wait(0)
        assert all(call["authorized"] and call["worker_id"] for call in calls)
        owned.report["control_plane"] = {
            "paths": sorted({call["path"] for call in calls}),
            "capability_keys": calls[0]["capabilities"],
            "claims_answered_without_job": True,
        }
        assert tool(cfg.voxhelm_remote_worker_binary_path, "voxhelm") == ["0.1.11", "3.14.8"]
        parakeet_version = tool(cfg.voxhelm_remote_worker_parakeet_bin, "parakeet-mlx")
        assert parakeet_version[0] == "0.5.3"
        assert parakeet_version[1].startswith("3.13.")
        assert sha256(parakeet / "model.safetensors") == PARAKEET_SHA
        assert (parakeet / "VOXHELM_MODEL_REVISION").read_text().endswith("sha256=" + PARAKEET_SHA + "\n")
        link = cache / TINY_EN[0]
        assert link.is_symlink()
        assert link.readlink() == source_model
        assert sha256(cache / TINY[0]) == TINY[1]
        provenance = json.loads((root / "etc/.native-artifacts.json").read_text())
        assert provenance[str(cache / TINY[0])]["pin"] == TINY[1]
        transcript = Path(cfg.voxhelm_remote_worker_install_transcript_path).read_text()
        assert "package=voxhelm==0.1.11\n" in transcript
        pid = job_pid("system/" + label)
        assert pid is not None
        table = command("/bin/ps", "-Aww", "-o", "pid=,ppid=,uid=,command=").stdout.splitlines()
        job = next(line for line in table if line.split()[0] == str(pid))
        owned.report["worker_process"] = job.split(None, 3)[3]
        # caffeinate takes its assertions for its own PID and then execs the
        # worker in place, so the launchd job PID is the worker holding them.
        assert cfg.voxhelm_remote_worker_binary_path in job.split(None, 3)[3]
        assert job.split()[2] == str(uid)
        held = [
            line.strip()
            for line in command("/usr/bin/pmset", "-g", "assertions").stdout.splitlines()
            if re.search(r"\bpid " + str(pid) + r"\(", line)
        ]
        kinds = sorted({found[1] for line in held if (found := re.search(r"\]\s+\S+\s+(\w+)\s+named", line))})
        owned.report["caffeinate_assertions"] = {"lines": held, "kinds": kinds}
        assert any("caffeinate" in line for line in held)
        assert {"PreventUserIdleSystemSleep", "PreventDiskIdle"} <= set(kinds)
        owned.report["runtime"] = {
            "voxhelm": "0.1.11",
            "python": "3.14.8",
            "parakeet_mlx": parakeet_version,
            "parakeet_weight_sha256_verified": True,
            "caffeinate": "worker PID holds the caffeinate assertions (-i -m -s) as the service account",
        }
        owned.report["limitations"].append(
            "No job was offered, so S3 artifacts, audio decoding, Parakeet/whisper inference and MLX are not exercised."
        )
        no_op(cfg, "fresh")

        owned.report["stage"] = "configuration change restarts once"
        faster = VoxhelmRemoteWorkerConfig.model_validate({**base, PREFIX + "poll_seconds": 3})
        mark = len(control.calls)
        owned.report["config_change_changes"] = deploy(faster)
        assert job_pid("system/" + label) not in {None, pid}
        control.wait(mark)
        no_op(faster, "configuration")

        owned.report["stage"] = "rejected window model keeps the running worker"
        running = job_pid("system/" + label)
        before = state(faster)
        bad = VoxhelmRemoteWorkerConfig.model_validate(
            {
                **base,
                PREFIX + "poll_seconds": 3,
                PREFIX + "window_model": "fixture-rejected-window.bin",
                PREFIX + "window_model_url": WHISPER_TREE + TINY_EN[0],
                PREFIX + "window_model_sha256": "0" * 64,
            }
        )
        deploy(bad, succeeds=False)
        after = state(faster)
        assert after["pid"] == running, "a failed model change must not stop the running worker"
        assert after["restart_intent"]
        assert {key: value for key, value in after.items() if key != "restart_intent"} == {
            key: value for key, value in before.items() if key != "restart_intent"
        }
        assert not (cache / "fixture-rejected-window.bin").exists()
        assert not list(cache.glob(".window-model-*"))
        owned.report["fault_recovery_changes"] = deploy(faster)
        assert owned.report["fault_recovery_changes"], "the owed restart is completed on recovery"
        assert job_pid("system/" + label) not in {None, running}
        no_op(faster, "post-fault")

        owned.report["stage"] = "disabled role skips without stopping"
        before = state(faster)
        disabled = VoxhelmRemoteWorkerConfig.model_validate({**base, PREFIX + "enabled": False})
        assert deploy(disabled) == []
        assert state(faster) == before
        owned.report["disabled_skip_retained_running_worker"] = True
        owned.report["no_job_audio_or_inference_executed"] = True
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    finally:
        if control is not None:
            control.close()
        failure = owned.finish(failure)
    if failure is not None:
        raise failure
    print("owned ARM Voxhelm worker install/models/launchd/fault/repeat passed; fixture removed")


if __name__ == "__main__":
    main()
