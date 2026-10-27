"""Real Traefik on an owned disposable GitHub Ubuntu VM; no inventory hosts."""

from __future__ import annotations

import hashlib
import http.server
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ops_deploy.services.opsgate import OpsGateIngressConfig, deploy_opsgate_ingress
from ops_deploy.services.voxhelm import VoxhelmIngressConfig, deploy_voxhelm_ingress
from ops_deploy.testing import run_deploy_ssh

ROOT = Path("/var/tmp/mac-ingress-owned")
EVIDENCE = Path("/var/tmp/mac-ingress-evidence")
DYNAMIC = Path("/etc/traefik/dynamic")
UNIT = Path("/etc/systemd/system/traefik.service")
PIN = "d08641f5de2dd3788097bddab1ce4b29c10a0b788566970db707fa5c94c71f15"


def command(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=check)


def state() -> dict[str, Any]:
    return {
        "pid": command("systemctl", "show", "traefik", "-p", "MainPID", "--value").stdout.strip(),
        "files": {
            str(path): {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "inode": path.stat().st_ino,
                "mtime_ns": path.stat().st_mtime_ns,
                "uid": path.stat().st_uid,
                "gid": path.stat().st_gid,
                "mode": path.stat().st_mode & 0o7777,
            }
            for path in [UNIT, ROOT / "static.yml", *DYNAMIC.glob("*.yml")]
        },
    }


def request(host: str, path: str = "/") -> tuple[int, dict[str, str]]:
    # Only this loopback fixture request skips verification of Traefik's default
    # self-signed certificate. No system trust or inventory policy changes.
    import ssl

    req = urllib.request.Request("https://127.0.0.1:19443" + path, headers={"Host": host})
    try:
        with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=3) as response:
            return response.status, dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers)


def wait_http(host: str, expected: int, path: str = "/") -> dict[str, str]:
    for _ in range(50):
        try:
            status, headers = request(host, path)
            if status == expected:
                return headers
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise AssertionError("Owned Traefik routing did not become ready")


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"owned backend\n")

    def log_message(self, *_: Any) -> None:
        pass


def main() -> None:
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.geteuid() == 0
    assert command("ps", "-p", "1", "-o", "comm=").stdout.strip() == "systemd"
    assert command("uname", "-m").stdout.strip() == "x86_64"
    assert not ROOT.exists()
    assert not UNIT.exists()
    assert not DYNAMIC.parent.exists()
    report: dict[str, Any] = {"implementation": os.environ["IMPLEMENTATION_SHA"], "status": "failed", "repeats": {}}
    EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    ROOT.mkdir(mode=0o700)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 19081), Backend)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        source = Path(os.environ["IMPLEMENTATION_ROOT"])
        import ops_deploy

        installed = Path(ops_deploy.__file__).resolve().parent
        direct = json.loads(importlib.metadata.distribution("ops-deploy").read_text("direct_url.json") or "{}")
        assert direct.get("vcs_info", {}).get("commit_id") == report["implementation"]
        assert not direct.get("dir_info", {}).get("editable", False)
        tracked = command(
            "git", "-C", str(source), "ls-tree", "-r", "--name-only", report["implementation"], "src/ops_deploy/"
        ).stdout.splitlines()
        resources = {}
        for name in tracked:
            raw = subprocess.check_output(["git", "-C", str(source), "show", report["implementation"] + ":" + name])
            relative = name.removeprefix("src/ops_deploy/")
            assert (installed / relative).read_bytes() == raw, relative
            resources[relative] = hashlib.sha256(raw).hexdigest()
        report.update(installed_resources=resources, direct_url=direct)
        archive = ROOT / "traefik.tar.gz"
        urllib.request.urlretrieve(
            "https://github.com/traefik/traefik/releases/download/v3.7.14/traefik_v3.7.14_linux_amd64.tar.gz", archive
        )
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == PIN
        with tarfile.open(archive) as bundle:
            member = bundle.getmember("traefik")
            assert member.isfile()
            content = bundle.extractfile(member)
            assert content is not None
            (ROOT / "traefik").write_bytes(content.read())
        (ROOT / "traefik").chmod(0o755)
        report["traefik_fixture_prerequisite"] = {
            "archive_sha256": PIN,
            "version": command(str(ROOT / "traefik"), "version").stdout.strip(),
        }
        DYNAMIC.mkdir(parents=True)
        (ROOT / "static.yml").write_text(
            "entryPoints:\n  web:\n    address: ':19080'\n  web-secure:\n    address: ':19443'\n"
            "providers:\n  file:\n    directory: /etc/traefik/dynamic\n    watch: true\nlog:\n  level: ERROR\n"
        )
        unit = (
            "[Unit]\nDescription=Owned Mac ingress fixture\n[Service]\nExecStart="
            + str(ROOT / "traefik")
            + " --configFile="
            + str(ROOT / "static.yml")
            + "\nExecReload=/bin/true\n"
        )
        UNIT.write_text(unit)
        command("systemctl", "daemon-reload")
        command("systemctl", "start", "traefik")
        ops = OpsGateIngressConfig(traefik_host="opsgate.example.invalid", backend_url="http://127.0.0.1:19081")
        vox = VoxhelmIngressConfig(traefik_host="voxhelm.example.invalid", backend_url="http://127.0.0.1:19081")

        def deploy(fn: Any, cfg: Any, name: str, *, repeat: bool = False, fails: bool = False) -> None:
            before = state()
            result = run_deploy_ssh(fn, cfg, host_name="@local", host_data={})
            report.setdefault("operations", {})[name] = result.mutating_changed_ops
            if fails:
                assert not result.succeeded
                assert state() == before
            else:
                assert result.succeeded, str(result.error)
            if repeat:
                assert not result.mutating_changed_ops, result.mutating_changed_ops
                assert state() == before
                report["repeats"][name] = result.mutating_changed_ops

        old_pid = state()["pid"]
        deploy(deploy_opsgate_ingress, ops, "opsgate-first")
        assert wait_http(ops.traefik_host, 200)["X-Frame-Options"] == "SAMEORIGIN"
        assert state()["pid"] == old_pid
        assert ("Deploy OpsGate ingress | Reload Traefik, restart only when reload fails") in report["operations"][
            "opsgate-first"
        ]
        deploy(deploy_opsgate_ingress, ops, "opsgate-repeat", repeat=True)
        deploy(deploy_voxhelm_ingress, vox, "voxhelm-first")
        assert wait_http(vox.traefik_host, 200)["X-Frame-Options"] == "DENY"
        wait_http(vox.traefik_host, 403, "/v1/internal/jobs")
        deploy(deploy_voxhelm_ingress, vox, "voxhelm-repeat", repeat=True)
        for label, fn, cfg in (("opsgate", deploy_opsgate_ingress, ops), ("voxhelm", deploy_voxhelm_ingress, vox)):
            denied = cfg.model_copy(update={"allowed_ip_ranges": ("100.64.0.0/10",)})
            deploy(fn, denied, label + "-source-denied")
            wait_http(cfg.traefik_host, 404)
            report.setdefault("source_allowlist_denials", {})[label] = 404
            deploy(fn, cfg, label + "-source-restored")
            wait_http(cfg.traefik_host, 200)
            deploy(fn, cfg, label + "-restored-repeat", repeat=True)
        # Traefik has no native reload signal; the original role falls back to
        # restart when the service manager has no successful ExecReload.
        UNIT.write_text(unit.replace("ExecReload=/bin/true\n", ""))
        command("systemctl", "daemon-reload")
        before_pid = state()["pid"]
        changed = ops.model_copy(update={"allowed_ip_ranges": ("127.0.0.1/32",)})
        deploy(deploy_opsgate_ingress, changed, "reload-unsupported-fallback")
        wait_http(ops.traefik_host, 200)
        assert state()["pid"] != before_pid
        deploy(deploy_opsgate_ingress, changed, "fallback-repeat", repeat=True)
        # Real transaction-lock refusal happens before route publication/reload.
        from ops_deploy.helpers.traefik import TRANSACTION_LOCK

        lock = Path(TRANSACTION_LOCK)
        assert not lock.exists()
        with subprocess.Popen(
            ["flock", "-x", str(lock), "sh", "-c", "printf ready; exec sleep 60"],
            stdout=subprocess.PIPE,
            start_new_session=True,
        ) as holder:
            assert holder.stdout is not None
            assert holder.stdout.read(5) == b"ready"
            try:
                deploy(deploy_opsgate_ingress, ops, "transaction-refusal", fails=True)
            finally:
                os.killpg(holder.pid, signal.SIGTERM)
                holder.wait(timeout=5)
                lock.unlink()
        deploy(deploy_opsgate_ingress, changed, "post-fault-repeat", repeat=True)
        disabled = vox.model_copy(update={"traefik_enabled": False})
        deploy(deploy_voxhelm_ingress, disabled, "disabled-repeat", repeat=True)
        report["status"] = "passed"
    except BaseException as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        (EVIDENCE / "traefik-journal.txt").write_text(
            command("journalctl", "-u", "traefik", "--no-pager", "-n", "200", check=False).stdout
        )
        raise
    finally:
        server.shutdown()
        command("systemctl", "stop", "traefik", check=False)
        UNIT.unlink(missing_ok=True)
        command("systemctl", "daemon-reload", check=False)
        shutil.rmtree(DYNAMIC.parent, ignore_errors=True)
        shutil.rmtree(ROOT, ignore_errors=True)
        report["cleanup"] = (
            not ROOT.exists()
            and not UNIT.exists()
            and not DYNAMIC.parent.exists()
            and command("systemctl", "is-active", "--quiet", "traefik", check=False).returncode != 0
        )
        (EVIDENCE / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
    assert report["status"] == "passed"
    assert report["cleanup"]


if __name__ == "__main__":
    main()
