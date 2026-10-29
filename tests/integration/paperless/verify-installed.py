"""Verify the entire actual installed package against exact public Git in the owned guest."""

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sysconfig
from pathlib import Path

import ops_deploy

assert os.environ.get("GITHUB_ACTIONS") == "true"
assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
run = os.environ["PAPERLESS_OWNED_ID"]
assert re.fullmatch(r"paperless-[0-9]+-[0-9]+", run)
assert Path("/etc/ops-paperless-owned-id").read_text().strip() == run
scope = "native x86 Ubuntu24 systemd userspace on owned public GitHub VM; shared kernel, not KVM"
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
assert direct["url"] == "https://github.com/ephes/ops-deploy.git"
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
machine_id = Path("/etc/machine-id").read_text().strip()
assert re.fullmatch(r"[0-9a-f]{32}", machine_id)
os_release = platform.freedesktop_os_release()
assert os_release["ID"] == "ubuntu"
assert os_release["VERSION_ID"] == "24.04"
Path("/var/tmp/paperless-evidence/installed-artifact.json").write_text(
    json.dumps(
        {
            "implementation_sha": selected,
            "direct_url": direct,
            "installed_root": str(installed),
            "resources": resources,
            "scope": scope,
            "kind": "github-hosted-systemd-container",
            "run": run,
            "fixture_case": os.environ["PAPERLESS_FIXTURE_CASE"],
            "machine_id": machine_id,
            "os_release": {key: os_release[key] for key in ("ID", "VERSION_ID", "PRETTY_NAME")},
            "kernel": subprocess.check_output(["uname", "-a"], text=True).strip(),
        },
        indent=2,
    )
)
with open("/var/tmp/paperless-owned-guest.json", "x") as stream:
    json.dump({"run": run, "machine": machine_id}, stream)
