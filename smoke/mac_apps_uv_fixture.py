"""Real pinned ARM uv installation in an owned disposable Darwin directory."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import platform
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.testing import run_deploy_ssh

TARGET = "aarch64-apple-darwin"
CHECKSUM = "743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73"


def snapshot(root: Path) -> dict[str, tuple[int, ...]]:
    return {
        str(path.relative_to(root)): (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        for path in (root, *root.rglob("*"))
        for info in [path.lstat()]
    }


def converge(cfg: UvInstallConfig, *, succeeds: bool = True) -> list[str]:
    result = run_deploy_ssh(deploy_uv_install, cfg, host_name="@local", host_data={})
    assert result.succeeded is succeeds, str(result.error)
    return result.mutating_changed_ops


def main() -> None:
    evidence = Path(os.environ["MAC_APPS_EVIDENCE_DIR"])
    evidence.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "implementation": os.environ["IMPLEMENTATION_SHA"],
        "arch": platform.machine(),
        "status": "failed",
        "limitations": ["Metadata observer covers the owned installation, not a whole-host syscall trace."],
    }
    root: Path | None = None
    failure: BaseException | None = None
    try:
        assert os.environ.get("GITHUB_ACTIONS") == "true"
        assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        assert platform.system() == "Darwin"
        assert platform.machine() == "arm64"
        assert os.geteuid() != 0
        source = Path(__file__).resolve().parents[1]
        installed = importlib.resources.files("ops_deploy.base")
        report["resources"] = {}
        for name in ("uv_install.py", "uv_install_darwin.py"):
            content = installed.joinpath(name).read_bytes()
            assert content == (source / "src/ops_deploy/base" / name).read_bytes()
            report["resources"][name] = hashlib.sha256(content).hexdigest()
        report["host_python"] = subprocess.run(
            ["/usr/bin/python3", "--version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        root = Path(tempfile.mkdtemp(prefix="mac-apps-uv-", dir=Path.home()))
        cfg = UvInstallConfig(
            darwin=True,
            version="0.13.5",
            checksums={TARGET: CHECKSUM},
            install_dir=str(root / "bin"),
            owner=pwd.getpwuid(os.getuid()).pw_name,
            group="staff",
        )
        report["first_changes"] = converge(cfg)
        assert report["first_changes"]
        binaries = [root / "bin/uv", root / "bin/uvx"]
        for binary in binaries:
            assert binary.stat().st_mode & 0o777 == 0o755
            result = subprocess.run([str(binary), "--version"], capture_output=True, check=True, text=True)
            assert result.stdout.startswith(binary.name + " 0.13.5 ")
        report["binary_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries}
        before = snapshot(root)
        report["repeat_changes"] = converge(cfg)
        assert report["repeat_changes"] == []
        assert snapshot(root) == before
        # Prove failure before publication against the real official archive.
        bad = cfg.model_copy(update={"force_reinstall": True, "checksums": {TARGET: "0" * 64}})
        protected = {p.name: (snapshot(p), p.read_bytes()) for p in binaries}
        converge(bad, succeeds=False)
        for binary in binaries:
            info, content = protected[binary.name]
            assert snapshot(binary) == info
            assert binary.read_bytes() == content
        assert {p.name for p in (root / "bin").iterdir()} == {"uv", "uvx"}
        report["invalid_archive_preserved_existing_binaries"] = True
        before = snapshot(root)
        report["post_fault_repeat_changes"] = converge(cfg)
        assert report["post_fault_repeat_changes"] == []
        assert snapshot(root) == before
    except BaseException as error:
        failure = error
        report["failure_type"] = type(error).__name__
    finally:
        try:
            if root is not None:
                shutil.rmtree(root)
        except OSError as error:
            report["cleanup_error_type"] = type(error).__name__
        report["cleanup"] = root is None or not root.exists()
        report["status"] = "passed" if failure is None and report["cleanup"] else "failed"
        (evidence / "uv-proof.json").write_text(json.dumps(report, indent=2) + "\n")
    if failure is not None:
        raise failure
    if not report["cleanup"]:
        raise RuntimeError("owned uv fixture cleanup failed")
    print("owned ARM uv installation/fault/repeat passed; fixture removed", file=sys.stdout)


if __name__ == "__main__":
    main()
