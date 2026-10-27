"""Actual ARM Voxhelm control plane: fresh/bootstrap/prune/model/source/fault/repeat.

Runs the real public 0.1.11 source on Python 3.14.8 with real Django, Homebrew,
Piper, Kokoro and WhisperKit provisioning in an owned root. No audio is
submitted, no transcription/synthesis or inference request is made, and the
prune job is installed, rescheduled and removed without ever running.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.request
from pathlib import Path
from typing import Any

from mac_apps_owned import OwnedMac, command, file_state, job_pid, port

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.services.voxhelm import VoxhelmConfig, deploy_voxhelm
from ops_deploy.services.voxhelm.render import payload
from ops_deploy.testing import run_deploy_ssh

APP = "a6ca44237edaa83c4ede9cbd071a16b23e0defb6"
HISTORICAL = "11de4d2ac99f9862ca9256f357130590f01a917e"
RETAINED = ["BACKLOG.md", "README.md", "specs/2026-10-15_parakeet_asr_backend.md"]
UV_SHA = "743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73"
WHISPER_TREE = "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/"
TINY_EN = ("ggml-tiny.en.bin", "921e4cf8686fdd993dcd081a5da5b6c365bfde1162e72b08d75ac75289920b1f")
TINY = ("ggml-tiny.bin", "be07e048e1e599ad46341c8d2a135645097a538221678b7acdd1b1919c6e1b21")
PRODUCTION_CERTIFI_SHA = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"


def metadata_only(paths: list[Path]) -> dict[str, tuple[int, ...]]:
    """Model continuity by lstat only; repeats never re-read model bodies."""

    return {
        str(path): (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        for path in paths
        for s in [path.lstat()]
    }


def main() -> None:
    owned = OwnedMac("voxhelm")
    failure: BaseException | None = None
    try:
        root = owned.root
        owned.verify_implementation()
        owned.report["stage"] = "owned public source, transport and verified uv"
        source = owned.source("voxhelm", APP)
        command("git", "-C", str(source), "fetch", "--depth=1", "https://github.com/ephes/voxhelm.git", HISTORICAL)
        retained = {
            name: command("git", "-C", str(source), "show", HISTORICAL + ":" + name).stdout for name in RETAINED
        }
        for name, content in retained.items():
            assert content.encode() != (source / name).read_bytes(), "overlay blob must differ from the clean revision"
        transport = owned.ssh_transport()
        rsync_path = transport.pop("remote_rsync_path")
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
        # uv's standard public selectors keep the managed interpreter and
        # package cache inside the owned root; every command is the real uv.
        uv = root / "uv-owned-dirs"
        uv.write_text(
            "#!/bin/sh\nexec /usr/bin/env UV_PYTHON_INSTALL_DIR="
            + str(root / "uv-python")
            + " UV_CACHE_DIR="
            + str(root / "uv-cache")
            + " "
            + str(root / "tool-bin/uv")
            + ' "$@"\n'
        )
        uv.chmod(0o755)
        for candidate in [Path("/var/root/Documents/huggingface"), Path("/var/root/.cache/huggingface")]:
            if os.path.lexists(candidate):
                owned.report["limitations"].append(str(candidate) + " pre-existed on the runner and is not removed")
            else:
                owned.created_outside_root(candidate)
        owned.report["limitations"].append(
            "Homebrew formulae installed for the fixture remain until the disposable VM is destroyed."
        )
        launchd = root / "launchd"
        launchd.mkdir(mode=0o755)
        labels = {name: owned.label("voxhelm-" + name) for name in ["api", "worker", "wyoming", "whisperkit", "prune"]}
        app_port, wyoming_port, whisperkit_port = port(), port(), port()
        token = "owned-fixture-api-" + owned.suffix
        secrets = {
            "voxhelm_django_secret_key": "owned-fixture-django-" + owned.suffix + "-" + "x" * 40,
            "voxhelm_bearer_tokens_env": "fixture=" + token,
            "voxhelm_bootstrap_operator_password": "owned-fixture-password-" + owned.suffix,
        }
        base: dict[str, Any] = {
            "remote_rsync_path": rsync_path,
            "voxhelm_source_path": str(source),
            "source_preservation_revision": APP,
            "source_overrides": retained,
            "voxhelm_app_dir": str(root / "app"),
            "voxhelm_config_dir": str(root / "etc"),
            "voxhelm_log_dir": str(root / "logs"),
            "voxhelm_uv_bin": str(uv),
            "voxhelm_python_version": "3.14.8",
            "voxhelm_bind_host": "127.0.0.1",
            "voxhelm_app_port": app_port,
            "voxhelm_launchd_label": labels["api"],
            "voxhelm_launchd_plist_path": str(launchd / (labels["api"] + ".plist")),
            "voxhelm_worker_label": labels["worker"],
            "voxhelm_worker_plist_path": str(launchd / (labels["worker"] + ".plist")),
            "voxhelm_wyoming_stt_label": labels["wyoming"],
            "voxhelm_wyoming_stt_plist_path": str(launchd / (labels["wyoming"] + ".plist")),
            "voxhelm_wyoming_stt_host": "127.0.0.1",
            "voxhelm_wyoming_stt_port": wyoming_port,
            # No Metal device is assumed in the VM; the whisper.cpp backend is
            # served by the same real Wyoming daemon without loading MLX.
            "voxhelm_wyoming_stt_backend": "whispercpp",
            "voxhelm_whisperkit_enabled": True,
            "voxhelm_whisperkit_label": labels["whisperkit"],
            "voxhelm_whisperkit_plist_path": str(launchd / (labels["whisperkit"] + ".plist")),
            "voxhelm_whisperkit_port": whisperkit_port,
            "voxhelm_whisperkit_model": "tiny.en",
            # CPU-only CoreML health on CI; production renders cpuAndGPU.
            "voxhelm_whisperkit_audio_encoder_compute_units": "cpuOnly",
            "voxhelm_whisperkit_text_decoder_compute_units": "cpuOnly",
            "voxhelm_whisperkit_concurrent_worker_count": 1,
            "voxhelm_prune_enabled": True,
            "voxhelm_prune_dry_run": True,
            "voxhelm_prune_label": labels["prune"],
            "voxhelm_prune_plist_path": str(launchd / (labels["prune"] + ".plist")),
            "voxhelm_tts_kokoro_enabled": True,
            "voxhelm_tts_language_routing_enabled": True,
            "voxhelm_whispercpp_model": TINY_EN[0],
            "voxhelm_whispercpp_model_url": WHISPER_TREE + TINY_EN[0],
            "voxhelm_whispercpp_model_sha256": TINY_EN[1],
            "voxhelm_bootstrap_operator_username": "fixture-operator",
            "voxhelm_bootstrap_operator_email": "operator@example.test",
            "voxhelm_healthcheck_retries": 150,
            "voxhelm_healthcheck_delay": 2,
        }
        cfg = VoxhelmConfig.model_validate(base)
        units = ["api", "worker", "wyoming", "whisperkit"]

        def deploy(config: VoxhelmConfig, values: dict[str, str], *, succeeds: bool = True) -> list[str]:
            result = run_deploy_ssh(deploy_voxhelm, config, values, host_name="@local", host_data=transport)
            assert result.succeeded is succeeds, str(result.error)
            for value in values.values():
                assert value not in str(result.error)
            return result.mutating_changed_ops

        def operator() -> tuple[Any, ...]:
            database = sqlite3.connect("file:" + str(root / "app/db.sqlite3") + "?mode=ro", uri=True)
            try:
                row = database.execute("SELECT * FROM auth_user WHERE username = ?", ("fixture-operator",)).fetchone()
            finally:
                database.close()
            assert row is not None
            return tuple(row)

        def runs(label: str) -> int:
            output = command("/bin/launchctl", "print", "system/" + label).stdout
            match = re.search(r"^\s*runs = ([0-9]+)$", output, re.M)
            return int(match[1]) if match else 0

        def pids() -> dict[str, int | None]:
            return {name: job_pid("system/" + labels[name]) for name in units}

        def models(config: VoxhelmConfig) -> list[Path]:
            paths = [Path(config.voxhelm_model_cache_dir) / config.voxhelm_whispercpp_model]
            paths += [
                Path(config.voxhelm_piper_voice_dir) / (voice + suffix)
                for voice in config.voxhelm_piper_voices
                for suffix in [".onnx", ".onnx.json"]
            ]
            paths += [Path(config.voxhelm_kokoro_model_dir) / item.dest for item in config.voxhelm_kokoro_artifacts]
            return paths

        def certifi() -> Path:
            python = root / "app/.venv/bin/python"
            return Path(command(str(python), "-B", "-c", "import certifi;print(certifi.where())").stdout.strip())

        def state(config: VoxhelmConfig, values: dict[str, str]) -> dict[str, Any]:
            managed = [Path(path) for path in payload(config, values)["contents"]]
            managed += [Path(config.voxhelm_config_dir) / ".native-artifacts.json", certifi()]
            managed += [root / "app" / name for name in ["pyproject.toml", "uv.lock", *RETAINED]]
            markers = sorted(p.name for p in Path(config.voxhelm_config_dir).glob(".ops-deploy-*"))
            return {
                "files": file_state(managed),
                "models": metadata_only(models(config)),
                "operator": operator(),
                "pids": pids(),
                "prune_loaded": command("/bin/launchctl", "print", "system/" + labels["prune"], check=False).returncode
                == 0,
                "markers": markers,
            }

        def no_op(config: VoxhelmConfig, values: dict[str, str], name: str) -> None:
            before = state(config, values)
            assert before["markers"] == []
            changes = deploy(config, values)
            assert changes == [], changes
            assert state(config, values) == before
            owned.report["repeats"][name] = changes

        def healthy() -> None:
            with urllib.request.urlopen("http://127.0.0.1:" + str(app_port) + "/v1/health", timeout=10) as response:
                assert response.status == 200
                assert json.load(response).get("status") == "ok"
            with urllib.request.urlopen("http://127.0.0.1:" + str(whisperkit_port) + "/health", timeout=10) as response:
                assert response.status == 200
            command("/usr/bin/nc", "-z", "127.0.0.1", str(wyoming_port))

        owned.report["stage"] = "fresh full role"
        owned.report["first_changes"] = deploy(cfg, secrets)
        assert owned.report["first_changes"]
        healthy()
        python = str(root / "app/.venv/bin/python")
        versions = json.loads(
            command(
                python,
                "-B",
                "-c",
                "import importlib.metadata as m,json,platform;"
                "print(json.dumps([m.version('voxhelm'),m.version('django'),m.version('certifi'),platform.python_version()]))",
            ).stdout
        )
        assert versions[0] == "0.1.11"
        assert versions[3] == "3.14.8"
        owned.report["runtime"] = {"voxhelm": versions[0], "django": versions[1], "python": versions[3]}
        trust = hashlib.sha256(certifi().read_bytes()).hexdigest()
        owned.report["trust"] = {
            "certifi": versions[2],
            "cacert_sha256": trust,
            "matches_production_bundle": trust == PRODUCTION_CERTIFI_SHA,
            "scope": "fresh frozen sync from the public a6ca lock; inventory bytes are preserved, not re-synced",
        }
        for name, content in retained.items():
            assert (root / "app" / name).read_bytes() == content.encode()
        assert (root / "app/pyproject.toml").read_bytes() == (source / "pyproject.toml").read_bytes()
        owned.report["source_overlay"] = {"retained_historical_blobs": RETAINED, "revision": APP}
        provenance = json.loads((root / "etc/.native-artifacts.json").read_text())
        whisper = str(root / "app/var/models" / TINY_EN[0])
        assert provenance[whisper]["pin"] == TINY_EN[1]
        for item in cfg.voxhelm_kokoro_artifacts:
            assert provenance[str(Path(cfg.voxhelm_kokoro_model_dir) / item.dest)]["pin"] == item.sha256
        owned.report["piper_voices_unpinned_upstream"] = {
            str(path.name): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in models(cfg)
            if path.parent == Path(cfg.voxhelm_piper_voice_dir)
        }
        assert all(pid is not None for pid in pids().values())
        assert runs(labels["prune"]) == 0
        original = operator()
        owned.report["bootstrap"] = {"id": original[0], "created": True}
        brew = command("/usr/bin/sudo", "-H", "-u", "runner", "--", "/opt/homebrew/bin/brew", "list", "--versions")
        owned.report["homebrew_formulae"] = sorted(
            line
            for line in brew.stdout.splitlines()
            if line.split()[0] in {"whisper.cpp", "whisperkit-cli", "espeak-ng"}
        )
        no_op(cfg, secrets, "fresh")

        owned.report["stage"] = "bootstrap flag drift repaired without password write"
        database = sqlite3.connect(str(root / "app/db.sqlite3"))
        with database:
            database.execute("UPDATE auth_user SET is_staff = 0 WHERE username = ?", ("fixture-operator",))
        database.close()
        before = pids()
        owned.report["bootstrap_flag_changes"] = deploy(cfg, secrets)
        assert owned.report["bootstrap_flag_changes"]
        assert operator() == original, "only the drifted flag may be written back"
        assert pids() == before
        no_op(cfg, secrets, "bootstrap-flag")
        rotated = {**secrets, "voxhelm_bootstrap_operator_password": "owned-fixture-rotated-" + owned.suffix}
        owned.report["bootstrap_password_changes"] = deploy(cfg, rotated)
        assert owned.report["bootstrap_password_changes"]
        changed_row = operator()
        assert changed_row[0] == original[0]
        assert changed_row[1] != original[1]
        assert changed_row[2:] == original[2:]
        assert pids() == before
        no_op(cfg, rotated, "bootstrap-password")
        secrets = rotated

        owned.report["stage"] = "prune schedule changes without running pruning"
        local = time.localtime(time.time() + 12 * 3600)
        daily = VoxhelmConfig.model_validate({**base, "voxhelm_prune_daily_time": time.strftime("%H:%M", local)})
        owned.report["prune_daily_changes"] = deploy(daily, secrets)
        assert runs(labels["prune"]) == 0
        no_op(daily, secrets, "prune-daily")
        disabled = VoxhelmConfig.model_validate({**base, "voxhelm_prune_enabled": False})
        owned.report["prune_disable_changes"] = deploy(disabled, secrets)
        assert command("/bin/launchctl", "print", "system/" + labels["prune"], check=False).returncode != 0
        assert not Path(cfg.voxhelm_prune_plist_path).exists()
        assert not Path(cfg.voxhelm_prune_script_path).exists()
        no_op(disabled, secrets, "prune-disabled")
        owned.report["prune_never_ran"] = True

        owned.report["stage"] = "rejected model change retains services and model"
        before_fault = state(disabled, secrets)
        bad = VoxhelmConfig.model_validate(
            {
                **base,
                "voxhelm_prune_enabled": False,
                "voxhelm_whispercpp_model": TINY[0],
                "voxhelm_whispercpp_model_url": WHISPER_TREE + TINY[0],
                "voxhelm_whispercpp_model_sha256": "0" * 64,
            }
        )
        deploy(bad, secrets, succeeds=False)
        assert state(disabled, secrets) == before_fault
        cache = Path(cfg.voxhelm_model_cache_dir)
        assert not (cache / TINY[0]).exists()
        assert not list(cache.glob(".voxhelm-model-*"))
        no_op(disabled, secrets, "post-fault")

        owned.report["stage"] = "verified changed model provisions with provenance"
        changed = VoxhelmConfig.model_validate(
            {
                **base,
                "voxhelm_prune_enabled": False,
                "voxhelm_whispercpp_model": TINY[0],
                "voxhelm_whispercpp_model_url": WHISPER_TREE + TINY[0],
                "voxhelm_whispercpp_model_sha256": TINY[1],
            }
        )
        before = pids()
        owned.report["model_change_changes"] = deploy(changed, secrets)
        assert json.loads((root / "etc/.native-artifacts.json").read_text())[str(cache / TINY[0])]["pin"] == TINY[1]
        after = pids()
        assert all(after[name] != before[name] for name in units), "environment change restarts ordinary units"
        healthy()
        no_op(changed, secrets, "model-change")

        owned.report["stage"] = "deliberately changed source resumes ordinary rsync"
        with (source / "README.md").open("a") as stream:
            stream.write("\nOwned fixture source update.\n")
        before = pids()
        owned.report["source_update_changes"] = deploy(changed, secrets)
        assert (root / "app/README.md").read_bytes() == (source / "README.md").read_bytes()
        assert pids() != before
        healthy()
        no_op(changed, secrets, "source-update")
        assert operator()[0] == original[0]
        owned.report["no_audio_inference_or_prune_executed"] = True
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    finally:
        failure = owned.finish(failure)
    if failure is not None:
        raise failure
    print("owned ARM Voxhelm fresh/bootstrap/prune/model/source/fault/repeat passed; fixture removed")


if __name__ == "__main__":
    main()
