"""Verify actual installed controller/artifact bytes inside the owned native guest."""

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
from pathlib import Path

import ops_deploy

kind = sys.argv[1]
assert kind in ("github-hosted", "kvm-owned")
if kind == "github-hosted":
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    run = os.environ["GITHUB_RUN_ID"]
    scope = "native x86 Ubuntu24 systemd userspace on owned GitHub VM shared kernel; no emulation"
else:
    assert not os.environ.get("GITHUB_ACTIONS")
    assert not os.environ.get("RUNNER_ENVIRONMENT")
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() == "kvm"
    run = os.environ["MINIO_OWNED_ID"]
    assert Path("/etc/ops-minio-owned-id").read_text().strip() == run
    scope = (
        "native x86 Ubuntu24 independent KVM guest kernel; offline guest, Docker tooling only /dev/kvm; no emulation"
    )
source = Path("/opt/controller")
selected = os.environ["IMPLEMENTATION_SHA"]
assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == selected
assert not subprocess.run(
    ["git", "config", "--local", "--get-regexp", "credential|extraheader|insteadof"], capture_output=True
).stdout
installed = Path(ops_deploy.__file__).resolve().parent
direct_text = importlib.metadata.distribution("ops-deploy").read_text("direct_url.json")
assert direct_text is not None
direct = json.loads(direct_text)
assert direct["vcs_info"]["commit_id"] == selected
assert not direct.get("dir_info", {}).get("editable", False)
assert installed == (Path(sysconfig.get_paths()["purelib"]) / "ops_deploy").resolve()
assert not installed.is_relative_to(source / "src")
paths = subprocess.check_output(
    ["git", "ls-tree", "-r", "--name-only", selected, "src/ops_deploy/"], text=True
).splitlines()
expected = {p.removeprefix("src/ops_deploy/") for p in paths}
actual = {str(p.relative_to(installed)) for p in installed.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
assert actual == expected
resources = {}
for path in paths:
    relative = path.removeprefix("src/ops_deploy/")
    data = (installed / relative).read_bytes()
    assert data == subprocess.check_output(["git", "show", selected + ":" + path]), relative
    resources[relative] = hashlib.sha256(data).hexdigest()
artifacts = {}
for name, sha in {
    "minio": "2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4",
    "mc": "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891",
}.items():
    artifact_path = Path("/opt/minio-artifacts") / name
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == sha
    artifact_path.chmod(0o755)
    artifacts[name] = {
        "sha256": sha,
        "size": artifact_path.stat().st_size,
        "version": subprocess.check_output([str(artifact_path), "--version"], text=True),
    }
machine_id = Path("/etc/machine-id").read_text().strip()
assert re.fullmatch(r"[0-9a-f]{32}", machine_id)
os_release = platform.freedesktop_os_release()
assert os_release["ID"] == "ubuntu"
assert os_release["VERSION_ID"] == "24.04"
Path("/var/tmp/minio-evidence/installed-artifact.json").write_text(
    json.dumps(
        {
            "implementation_sha": selected,
            "direct_url": direct,
            "installed_root": str(installed),
            "resources": resources,
            "artifacts": artifacts,
            "scope": scope,
            "kind": kind,
            "run": run,
            "machine_id": machine_id,
            "os_release": {key: os_release[key] for key in ("ID", "VERSION_ID", "PRETTY_NAME")},
            "kernel": subprocess.check_output(["uname", "-a"], text=True).strip(),
        },
        indent=2,
    )
)
with open("/var/tmp/minio-owned-guest.json", "x") as stream:
    json.dump({"run": run, "machine": machine_id}, stream)
