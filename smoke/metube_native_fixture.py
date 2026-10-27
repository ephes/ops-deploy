"""Run on the dedicated Linux fixture only; actual Git/Angular/uv/systemd, no media I/O.

Requires /srv/metube-fixture/source to contain the reviewed source snapshot.
This script owns /srv/metube-fixture, /opt/metube-fixture, its service and user.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import subprocess
import sys
import urllib.parse
import urllib.request
import wave
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from pyinfra import logger

from ops_deploy.core.git_source import GitSource
from ops_deploy.services.metube import MetubeConfig, deploy_metube
from ops_deploy.testing import run_deploy_ssh

ROOT = Path("/srv/metube-fixture")
SOURCE = ROOT / "source"
RECEIPTS: list[dict[str, object]] = []


def command(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(list(args), cwd=cwd, text=True).strip()


def commit(message: str) -> str:
    command("git", "add", "-A", cwd=SOURCE)
    if not command("git", "diff", "--cached", "--name-only", cwd=SOURCE):
        return command("git", "rev-parse", "HEAD", cwd=SOURCE)
    command(
        "git",
        "-c",
        "user.name=Owned fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        message,
        cwd=SOURCE,
    )
    return command("git", "rev-parse", "HEAD", cwd=SOURCE)


def snapshot() -> dict[str, str]:
    result = {"pid": command("systemctl", "show", "metube-fixture", "-p", "MainPID", "--value")}
    for name in ["app/main.py", "uv.lock", "ui/dist/metube/.metube-ui-rev", "ui/dist/metube/browser/index.html"]:
        path = Path("/opt/metube-fixture") / name
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def cfg(ref: str, *, python: str = "3.14.0") -> MetubeConfig:
    return MetubeConfig(
        service_name="metube-fixture",
        user="metube-fixture",
        site_path="/opt/metube-fixture",
        home="/var/lib/metube-fixture",
        state_dir="/var/lib/metube-fixture",
        download_dir="/srv/metube-fixture/media",
        audio_download_dir="/srv/metube-fixture/media",
        temp_dir="/srv/metube-fixture/media",
        build_root="/var/cache/metube-fixture",
        env_dir="/etc/metube-fixture",
        port=18083,
        source=GitSource(repo=SOURCE.as_uri(), ref=ref),
        python_version=python,
        extra_groups=(),
        traefik_enabled=False,
    )


def deploy(
    label: str,
    config: MetubeConfig,
    *,
    expect_failure: bool = False,
    repeat: bool = False,
    expected_message: str | None = None,
) -> None:
    diagnostics = io.StringIO()
    handler = logging.StreamHandler(diagnostics)
    logger.addHandler(handler)
    try:
        run = run_deploy_ssh(deploy_metube, config, host_name="@local", host_data={})
    finally:
        logger.removeHandler(handler)
    row = {"label": label, "success": run.succeeded, "changed": run.mutating_changed_ops, "error": str(run.error)}
    if expect_failure:
        assert expected_message is not None, "expected failures must name their actual diagnostic"
        row["diagnostic"] = diagnostics.getvalue()[-3000:]
        assert expected_message in diagnostics.getvalue(), row
        if expected_message == "active/queued work":
            stage = next(op for op in run.ops if op.name.endswith("Stage MeTube source, locked runtime and UI"))
            assert stage.succeeded, "busy refusal must reach the guard after successful staging"
            guard = next(op for op in run.ops if op.name.endswith("Protect active MeTube rollout"))
            assert not guard.succeeded, "expected queue guard did not fail"
    RECEIPTS.append(row)
    print(json.dumps(row), flush=True)
    (ROOT / "receipts.json").write_text(json.dumps(RECEIPTS, indent=2))
    assert run.succeeded != expect_failure, row
    if repeat:
        assert run.mutating_changed_ops == [], row
    if not expect_failure:
        for endpoint in ["", "history", "formats", "version"]:
            with urllib.request.urlopen(config.health_url + endpoint, timeout=10) as response:
                assert response.status == 200
                body = response.read()
                assert body
        for path, body in (
            (ROOT / "media/owned-asset.txt", b"owned media sentinel\n"),
            (Path("/var/lib/metube-fixture/owned-state.txt"), b"owned state sentinel\n"),
        ):
            if path.exists():
                assert path.read_bytes() == body


def cleanup_owned_pending() -> None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:18083/history", timeout=3) as response:
            history = json.load(response)
    except urllib.error.URLError:
        return
    owned = [
        entry["url"] for entry in history["pending"] if entry.get("url") == "http://owned-fixture.invalid/owned.wav"
    ]
    if owned:
        request = urllib.request.Request(
            "http://127.0.0.1:18083/delete",
            data=json.dumps({"ids": owned, "where": "queue", "delete_files": False}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            assert json.load(response)["status"] == "ok"


def busy_queue(config: MetubeConfig) -> None:
    assets = ROOT / "owned-assets"
    assets.mkdir(exist_ok=True)
    with wave.open(str(assets / "owned.wav"), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes(b"\0\0" * 8000)

    class AssetProxy(SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, directory=str(assets), **kwargs)

        def translate_path(self, path: str) -> str:
            return super().translate_path(urllib.parse.urlsplit(path).path)

        def log_message(self, _format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), AssetProxy)
    thread = Thread(target=server.serve_forever)
    thread.start()
    configured = config.model_copy(
        update={"ytdl_options": {**config.ytdl_options, "proxy": f"http://127.0.0.1:{server.server_port}"}}
    )

    def post(endpoint: str, data: dict[str, object]) -> object:
        request = urllib.request.Request(
            config.health_url + endpoint, data=json.dumps(data).encode(), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    try:
        deploy("configure owned fixture asset proxy", configured)
        result = post(
            "add",
            {
                "url": "http://owned-fixture.invalid/owned.wav",
                "download_type": "video",
                "format": "any",
                "quality": "best",
                "auto_start": False,
            },
        )
        assert isinstance(result, dict), result
        assert result.get("status") == "ok", result
        with urllib.request.urlopen(config.health_url + "history", timeout=10) as response:
            history = json.load(response)
        assert len(history["pending"]) == 1, history
        before = snapshot()
        deploy("busy pending queue zero-change repeat", configured, repeat=True)
        assert snapshot() == before
        deploy(
            "busy queue env mutation refusal",
            configured.model_copy(update={"loglevel": "DEBUG"}),
            expect_failure=True,
            expected_message="active/queued work",
        )
        assert snapshot() == before
        deploy(
            "busy queue source mutation refusal",
            configured.model_copy(update={"python_version": "3.14.2"}),
            expect_failure=True,
            expected_message="active/queued work",
        )
        assert snapshot() == before
        post("delete", {"ids": [history["pending"][0]["url"]], "where": "queue", "delete_files": False})
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    deploy("restore ordinary fixture configuration", config)


def inactive_recovery(config: MetubeConfig) -> None:
    pending = Path("/opt/metube-fixture/.ops-deploy-metube-pending")
    pending.write_text(str(config.source.ref) + "\n")
    owner = pending.parent.stat()
    os.chown(pending, owner.st_uid, owner.st_gid)
    command("systemctl", "stop", "metube-fixture")
    deploy("inactive interrupted-rollout recovery", config)
    assert command("systemctl", "is-active", "metube-fixture") == "active"
    assert not pending.exists()
    deploy("inactive recovery zero-change repeat", config, repeat=True)


if __name__ == "__main__":
    assert os.geteuid() == 0
    assert Path("/etc/hostname").read_text().strip() == "lima-metube-native-20261027"
    if sys.argv[1:] == ["--inactive-only"]:
        os.environ["GIT_CONFIG_GLOBAL"] = str(ROOT / "gitconfig")
        inactive_recovery(cfg(command("git", "rev-parse", "HEAD", cwd=SOURCE), python="3.14.1"))
        raise SystemExit(0)
    cleanup_owned_pending()
    command("git", "init", "--quiet", "--template=", cwd=SOURCE)
    # Git's local file transport checks both reader identities. Limit this
    # fixture-only trust to the exact owned repository; production uses HTTPS.
    gitconfig = ROOT / "gitconfig"
    gitconfig.write_text(
        "[safe]\n\tdirectory = /srv/metube-fixture/source\n\tdirectory = /srv/metube-fixture/source/.git\n"
    )
    os.environ["GIT_CONFIG_GLOBAL"] = str(gitconfig)
    initial = commit("Owned native fixture source snapshot")
    deploy("first native deployment", cfg(initial))
    for path, body in (
        (ROOT / "media/owned-asset.txt", b"owned media sentinel\n"),
        (Path("/var/lib/metube-fixture/owned-state.txt"), b"owned state sentinel\n"),
    ):
        path.write_bytes(body)
    before = snapshot()
    deploy("first zero-change repeat", cfg(initial), repeat=True)
    assert snapshot() == before
    deploy("actual Python runtime update", cfg(initial, python="3.14.1"))
    assert command("/opt/metube-fixture/venv/bin/python", "--version") == "Python 3.14.1"
    deploy("runtime zero-change repeat", cfg(initial, python="3.14.1"), repeat=True)
    # Simulate an interrupted rollout after source/runtime convergence: the
    # persistent completion marker must force a real retry/restart, then clear.
    before = snapshot()
    pending = Path("/opt/metube-fixture/.ops-deploy-metube-pending")
    pending.write_text(initial + "\n")
    owner = Path("/opt/metube-fixture").stat()
    os.chown(pending, owner.st_uid, owner.st_gid)
    deploy("interrupted-rollout recovery", cfg(initial, python="3.14.1"))
    assert snapshot()["pid"] != before["pid"]
    assert not pending.exists()
    deploy("recovery zero-change repeat", cfg(initial, python="3.14.1"), repeat=True)
    inactive_recovery(cfg(initial, python="3.14.1"))
    busy_queue(cfg(initial, python="3.14.1"))
    index = SOURCE / "ui/src/index.html"
    index.write_text(index.read_text().replace("<head>", '<head>\n<meta name="owned-fixture" content="ui-update">', 1))
    updated = commit("Owned Angular UI update fixture")
    deploy("actual Angular UI update", cfg(updated, python="3.14.1"))
    assert b"owned-fixture" in Path("/opt/metube-fixture/ui/dist/metube/browser/index.html").read_bytes()
    deploy("UI zero-change repeat", cfg(updated, python="3.14.1"), repeat=True)
    before = snapshot()
    angular = SOURCE / "ui/angular.json"
    original_angular = angular.read_text()
    moved = json.loads(original_angular)
    moved["projects"]["metube"]["architect"]["build"]["options"]["outputPath"]["base"] = "dist/owned-output"
    angular.write_text(json.dumps(moved, indent=2) + "\n")
    moved_commit = commit("Owned Angular successful build to different output path")
    deploy(
        "fresh output required after successful Angular build",
        cfg(moved_commit, python="3.14.1"),
        expect_failure=True,
        expected_message="produced no browser/index.html",
    )
    assert snapshot() == before
    angular.write_text(original_angular)
    repaired_output = commit("Restore owned Angular output path")
    deploy("retry after missing fresh UI output", cfg(repaired_output, python="3.14.1"))
    before = snapshot()
    package = SOURCE / "ui/package.json"
    original = package.read_text()
    data = json.loads(original)
    data["scripts"]["build"] = "ng build --definitely-invalid-owned-fixture-option"
    package.write_text(json.dumps(data, indent=2) + "\n")
    failed = commit("Owned real Angular failure injection")
    deploy(
        "real Angular build failure",
        cfg(failed, python="3.14.1"),
        expect_failure=True,
        expected_message="Unknown argument",
    )
    assert snapshot() == before, "failed staged build modified live source/UI/runtime/process"
    package.write_text(original)
    repaired = commit("Repair owned Angular failure")
    deploy("retry after actual build failure", cfg(repaired, python="3.14.1"))
    deploy("final zero-change repeat", cfg(repaired, python="3.14.1"), repeat=True)
    print("MEtube native Linux fixture complete", flush=True)
