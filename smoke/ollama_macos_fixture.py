"""Owned GitHub-hosted macOS qualification, never an inventory-host fixture."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import platform
import plistlib
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from contextlib import suppress
from pathlib import Path
from typing import Any

from ops_deploy.services.ollama import OllamaConfig, deploy_ollama
from ops_deploy.testing import run_deploy_ssh


def command(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def owned_runner() -> str:
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not (
        platform.system() == "Darwin"
        and os.geteuid() == 0
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("SUDO_USER") == "runner"
        and re.fullmatch(r"[0-9]+", run_id)
        and Path("/Users/runner").is_dir()
        and not Path("/Users/jochen").exists()
    ):
        raise RuntimeError("fixture requires a disposable GitHub-hosted macOS runner")
    return run_id


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def pid(label: str) -> int:
    status = command("/bin/launchctl", "print", "system/" + label).stdout
    match = re.search(r"^\s*pid = ([0-9]+)$", status, re.MULTILINE)
    assert match is not None, status
    return int(match[1])


def unload(label: str) -> None:
    command("/bin/launchctl", "bootout", "system/" + label, check=False)
    for _ in range(30):
        if command("/bin/launchctl", "print", "system/" + label, check=False).returncode:
            return
        time.sleep(1)
    raise RuntimeError("fixture label did not unload")


def health(port: int) -> dict[str, Any]:
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/version", timeout=3) as response:
                return dict(json.load(response))
        except OSError:
            time.sleep(1)
    raise AssertionError("fixture Ollama API did not become healthy")


def deploy(cfg: OllamaConfig, *, succeeds: bool = True) -> list[str]:
    result = run_deploy_ssh(deploy_ollama, cfg, host_name="@local", host_data={})
    assert result.succeeded is succeeds, str(result.error)
    return result.mutating_changed_ops


def cleanup(root: Path, user: str, label: str, plist: Path) -> None:
    unload(label)
    plist.unlink(missing_ok=True)
    command("/usr/bin/dscl", ".", "-delete", "/Users/" + user, check=False)
    command("/usr/sbin/dseditgroup", "-o", "delete", "-L", user, check=False)
    preferences = Path("/Library/Preferences/com.apple.loginwindow.plist")
    if preferences.exists():
        with preferences.open("rb") as handle:
            users = plistlib.load(handle).get("HiddenUsersList", [])
        if user in users:
            command(
                "/usr/bin/defaults",
                "write",
                str(preferences),
                "HiddenUsersList",
                "-array",
                *(value for value in users if value != user),
            )
    assert root.parent == Path("/private/var/tmp")
    assert root.name.startswith("ops-deploy-ollama-")
    shutil.rmtree(root)


def main() -> None:
    run_id = owned_runner()
    implementation = Path(__file__).resolve().parents[1]
    selected = os.environ["IMPLEMENTATION_SHA"]
    actual = command(
        "git", "-c", "safe.directory=" + str(implementation), "-C", str(implementation), "rev-parse", "HEAD"
    ).stdout.strip()
    assert actual == selected
    distribution = importlib.metadata.distribution("ops-deploy")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    assert not direct.get("dir_info", {}).get("editable")
    installed_package = Path(str(importlib.resources.files("ops_deploy.services.ollama")))
    assert installed_package.is_relative_to(Path("/private/var/tmp/ollama-controller"))
    resource_hashes = {}
    for relative in (
        "__init__.py",
        "config.py",
        "deploy.py",
        "files/ollama_host.py",
        "templates/ollama.launchd.plist.j2",
    ):
        installed_bytes = (installed_package / relative).read_bytes()
        assert installed_bytes == (implementation / "src/ops_deploy/services/ollama" / relative).read_bytes()
        resource_hashes[relative] = hashlib.sha256(installed_bytes).hexdigest()
    suffix = f"{run_id[-12:]}-{os.getpid()}"
    root = Path("/private/var/tmp") / ("ops-deploy-ollama-" + suffix)
    user = "opso" + run_id[-12:] + str(os.getpid())
    label = "com.example.ops-deploy.ollama-" + suffix
    plist = Path("/Library/LaunchDaemons") / (label + ".plist")
    assert not root.exists()
    assert not plist.exists()
    assert command("/usr/bin/dscl", ".", "-read", "/Users/" + user, check=False).returncode
    assert command("/usr/bin/dscl", ".", "-read", "/Groups/" + user, check=False).returncode
    brew_bin = os.environ["FIXTURE_BREW_BIN"]
    owner = pwd.getpwuid(Path(brew_bin).stat().st_uid).pw_name
    assert owner == "runner", owner
    before_package = command(
        "/usr/bin/sudo",
        "-H",
        "-u",
        owner,
        "--",
        "/usr/bin/env",
        "HOMEBREW_NO_AUTO_UPDATE=1",
        brew_bin,
        "list",
        "--versions",
        "ollama",
        check=False,
    ).stdout.strip()
    assert not before_package, "fresh fixture must exercise an absent Ollama formula"
    root.mkdir(mode=0o755)
    port = available_port()
    cfg = OllamaConfig(
        user=user,
        group=user,
        site_path=root / "home",
        models_dir=root / "home/models",
        log_dir=root / "logs",
        brew_bin=Path(brew_bin),
        brew_user=owner,
        launchd_label=label,
        env={"OLLAMA_HOST": f"127.0.0.1:{port}", "OLLAMA_MODELS": str(root / "home/models")},
        health_url=f"http://127.0.0.1:{port}/api/version",
    )
    evidence: dict[str, Any] = {
        "run_id": run_id,
        "implementation_sha": actual,
        "installed_package": str(installed_package),
        "installed_resource_sha256": resource_hashes,
    }
    try:
        evidence["install"] = deploy(cfg)
        assert evidence["install"]
        first_pid = pid(label)
        evidence["version"] = health(port)
        expected = plistlib.loads(plist.read_bytes())
        binary = Path(expected["ProgramArguments"][0])
        evidence["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        evidence["brew_package"] = command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            owner,
            "--",
            "/usr/bin/env",
            "HOMEBREW_NO_AUTO_UPDATE=1",
            brew_bin,
            "list",
            "--versions",
            "ollama",
        ).stdout.strip()
        canary = root / "home/models/retained-canary"
        canary.write_bytes(b"owned fixture retained data; not a model")
        os.chown(canary, pwd.getpwnam(user).pw_uid, pwd.getpwnam(user).pw_gid)
        before = (canary.stat().st_ino, canary.stat().st_mtime_ns, plist.stat().st_ino, plist.stat().st_mtime_ns)
        evidence["repeat"] = deploy(cfg)
        assert evidence["repeat"] == []
        assert pid(label) == first_pid
        assert (
            canary.stat().st_ino,
            canary.stat().st_mtime_ns,
            plist.stat().st_ino,
            plist.stat().st_mtime_ns,
        ) == before
        changed_env = {**(cfg.env or {}), "OLLAMA_NUM_PARALLEL": "1"}
        updated = OllamaConfig(**{**cfg.model_dump(), "env": changed_env})
        evidence["config_update"] = deploy(updated)
        assert evidence["config_update"]
        updated_pid = pid(label)
        assert updated_pid != first_pid
        assert health(port) == evidence["version"]
        assert plistlib.loads(plist.read_bytes())["EnvironmentVariables"]["OLLAMA_NUM_PARALLEL"] == "1"
        evidence["config_repeat"] = deploy(updated)
        assert evidence["config_repeat"] == []
        assert pid(label) == updated_pid
        # An owned, empty manual serve under the Brew owner is the role's
        # actual conflict case. It uses a separate model store and loopback port.
        foreign_store = root / "foreign-models"
        foreign_store.mkdir(mode=0o750)
        brew_owner = pwd.getpwnam(owner)
        os.chown(foreign_store, brew_owner.pw_uid, brew_owner.pw_gid)
        foreign_port = available_port()
        with (root / "foreign-serve.log").open("w") as output:
            foreign = subprocess.Popen(
                [
                    "/usr/bin/sudo",
                    "-H",
                    "-u",
                    owner,
                    "--",
                    "/usr/bin/env",
                    f"OLLAMA_HOST=127.0.0.1:{foreign_port}",
                    f"OLLAMA_MODELS={foreign_store}",
                    str(binary),
                    "serve",
                ],
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                assert health(foreign_port) == evidence["version"]
                evidence["foreign_cleanup"] = deploy(updated)
                assert evidence["foreign_cleanup"]
                foreign.wait(timeout=15)
                assert pid(label) == updated_pid
                evidence["foreign_cleanup_repeat"] = deploy(updated)
                assert evidence["foreign_cleanup_repeat"] == []
            finally:
                with suppress(ProcessLookupError):
                    os.killpg(foreign.pid, signal.SIGTERM)
                try:
                    foreign.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    with suppress(ProcessLookupError):
                        os.killpg(foreign.pid, signal.SIGKILL)
                    foreign.wait(timeout=5)
        before_fault = plist.read_bytes()
        invalid = OllamaConfig(**{**updated.model_dump(), "binary_path": root / "missing-ollama"})
        evidence["missing_binary_fault"] = deploy(invalid, succeeds=False)
        assert plist.read_bytes() == before_fault
        assert pid(label) == updated_pid
        assert deploy(updated) == []
        unload(label)
        evidence["unloaded_recovery"] = deploy(updated)
        assert evidence["unloaded_recovery"]
        recovered_pid = pid(label)
        assert recovered_pid != updated_pid
        assert health(port) == evidence["version"]
        evidence["recovery_repeat"] = deploy(updated)
        assert evidence["recovery_repeat"] == []
        assert pid(label) == recovered_pid
        assert canary.read_bytes() == b"owned fixture retained data; not a model"
        assert (canary.stat().st_ino, canary.stat().st_mtime_ns) == before[:2]
        evidence["limits"] = (
            "Homebrew install/present and plist update tested; no formula upgrade, model pull or inference."
        )
    finally:
        primary_failure = sys.exc_info()[1]
        if primary_failure is not None:
            evidence["failure"] = str(primary_failure)
        evidence["cleanup"] = "attempted"
        cleanup_failure = None
        try:
            cleanup(root, user, label, plist)
            evidence["cleanup"] = "completed"
        except Exception as exc:
            cleanup_failure = exc
            evidence["cleanup"] = "failed: " + str(exc)
        finally:
            destination = Path(os.environ["OLLAMA_EVIDENCE_DIR"])
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
        if cleanup_failure is not None and primary_failure is None:
            raise cleanup_failure
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
