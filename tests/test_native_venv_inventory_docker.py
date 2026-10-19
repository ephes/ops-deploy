"""Real production fact caller in an explicitly provided, bounded owned Docker fixture."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.services.native_app.inventory import VenvInventoryRequest, VenvInventoryResult, probe_venv_inventory
from ops_deploy.testing.harness import collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("NATIVE_VENV_DOCKER_CONTAINER"), reason="no explicitly owned Docker inventory fixture"
)


class DockerFixture:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["NATIVE_VENV_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        self.timings: dict[str, float] = {}
        info = json.loads(self.command("container", "inspect", self.identifier).stdout)[0]
        assert info["Name"].startswith("/native-p0a-")
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "native-venv-inventory"
        assert info["Config"]["Labels"]["ops-deploy.run"] == os.environ["NATIVE_VENV_RUN_ID"]
        assert info["Image"] == os.environ["NATIVE_VENV_IMAGE_ID"]
        assert info["Config"]["User"] == "65534:65534"
        cfg = info["HostConfig"]
        assert cfg["ReadonlyRootfs"]
        assert cfg["NetworkMode"] == "none"
        assert not cfg["Binds"]
        assert not cfg.get("Mounts")
        assert not info["Mounts"]
        assert not info["Config"]["Volumes"]
        assert cfg["Privileged"] is False
        assert cfg["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges:true"])
        assert cfg["PidMode"] == cfg["UTSMode"] == cfg["UsernsMode"] == ""
        assert cfg["IpcMode"] == cfg["CgroupnsMode"] == "private"
        assert not cfg["Devices"]
        assert not cfg["DeviceRequests"]
        assert not cfg["VolumesFrom"]
        assert not cfg["PortBindings"]
        assert cfg["Memory"] == cfg["MemorySwap"] == 256 * 1024 * 1024
        assert cfg["NanoCpus"] == 1000000000
        assert cfg["PidsLimit"] == 32
        assert cfg["CapDrop"] == ["ALL"]
        assert [name.removeprefix("CAP_") for name in cfg["CapAdd"]] == ["CHOWN"]
        assert set(cfg["Tmpfs"]) == {"/opt/native-venv-inventory-fixture"}
        assert set(cfg["Tmpfs"]["/opt/native-venv-inventory-fixture"].split(",")) == {
            "rw",
            "nosuid",
            "nodev",
            "noexec",
            "size=32m",
            "mode=0755",
            "uid=65534",
            "gid=65534",
        }

    def command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=30)

    def run(self, command: str, *, user: str = "65534:65534") -> subprocess.CompletedProcess[str]:
        return self.command("exec", "-i", "--user", user, self.identifier, "sh", "-c", command)

    def out(self, command: str) -> str:
        return self.run(command).stdout.strip()

    def guard_connector(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = tmp / "docker-fact-transport"
        wrapper.write_text(
            '#!/bin/sh\ncase "$1:$2" in container:inspect|exec:*) ;; *) exit 97 ;; esac\nexec '
            + shlex.quote(self.binary)
            + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        monkeypatch.setattr(DockerConnector, "docker_cmd", shlex.quote(str(wrapper)))


ROOT = "/opt/native-venv-inventory-fixture"
VENV = ROOT + "/venv"
SITE = VENV + "/lib/python3.12/site-packages"


def _probe(
    host: DockerFixture,
    version: str,
    label: str,
    *,
    venv: str = VENV,
    distributions: dict[str, str] | None = None,
) -> VenvInventoryResult:
    result: list[VenvInventoryResult] = []
    request = VenvInventoryRequest.model_validate(
        {
            "venv": venv,
            "owner_uid": 65534,
            "python_version": version,
            "distributions": distributions if distributions is not None else {"fixture-package": "1.2.3"},
        }
    )

    def read_only() -> None:
        result.append(probe_venv_inventory(request))

    name = f"@docker/{host.identifier}"
    state = State(Inventory(([(name, {})], {})), Config())
    started = time.monotonic()
    try:
        connect_all(state)
        assert state.activated_hosts
        add_deploy(state, read_only)
        run_ops(state)
        assert collect_ops(state, name) == []
    finally:
        disconnect_all(state)
    host.timings[label] = time.monotonic() - started
    assert len(result) == 1
    return result[0]


def _snapshot(host: DockerFixture) -> str:
    return host.out(
        "python3 -I -B - <<'FIXTURE_PY'\n"
        "import os,json,hashlib,stat\n"
        "from pathlib import Path\n"
        f"root=Path({ROOT!r});items=[]\n"
        "for p in sorted([root,*root.rglob('*')]):\n"
        " s=p.lstat();body=None\n"
        " if stat.S_ISREG(s.st_mode):body=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " items.append([str(p),s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns,body])\n"
        "print(json.dumps(items))\nFIXTURE_PY"
    )


def _unchanged_probe(
    host: DockerFixture,
    version: str,
    label: str,
    *,
    venv: str = VENV,
    distributions: dict[str, str] | None = None,
) -> VenvInventoryResult:
    before = _snapshot(host)
    result = _probe(host, version, label, venv=venv, distributions=distributions)
    assert _snapshot(host) == before
    assert host.out(f"test ! -e {ROOT}/executed && echo clear") == "clear"
    return result


def _prepare_fixture(fixture: DockerFixture) -> str:
    version = fixture.out("/usr/bin/python3 -I -S -B -c 'import sys;print(\".\".join(map(str,sys.version_info[:3])))'")
    assert version == "3.12.13"  # Exact pinned official image in the approved fixture manifest.
    setup = f"""import shutil,os
from pathlib import Path
root=Path({ROOT!r})
for item in root.iterdir():
 if item.is_dir() and not item.is_symlink():shutil.rmtree(item)
 else:item.unlink()
venv=Path({VENV!r});site=Path({SITE!r})
(venv/'bin').mkdir(parents=True)
info=site/'fixture_package-1.2.3.dist-info';info.mkdir(parents=True)
(venv/'pyvenv.cfg').write_text('version_info = {version}\\ninclude-system-site-packages = false\\n')
(venv/'bin/python').write_text('#!/bin/sh\\ntouch {ROOT}/executed\\nexit 99\\n')
(venv/'bin/python').chmod(0o755)
(info/'METADATA').write_text('Name: fixture-package\\nVersion: 1.2.3\\n\\n')
"""
    fixture.run("python3 -I -B - <<'FIXTURE_PY'\n" + setup + "\nFIXTURE_PY")
    return version


def test_native_venv_inventory_fact_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = DockerFixture()
    fixture.guard_connector(tmp_path, monkeypatch)
    version = _prepare_fixture(fixture)
    first = _unchanged_probe(fixture, version, "candidate")
    assert first.status == "matching_candidate"
    assert first.python_entry == "regular"
    assert _unchanged_probe(fixture, version, "repeat") == first
    assert _unchanged_probe(fixture, version, "absent", venv=ROOT + "/missing").status == "absent"

    meta = SITE + "/fixture_package-1.2.3.dist-info/METADATA"
    fixture.run(f"chmod 0666 {meta}")
    assert _unchanged_probe(fixture, version, "unsafe-mode").status == "refused_untrusted"
    fixture.run(f"chmod 0644 {meta}")
    fixture.run(f"chown 65533 {meta}", user="0:0")
    assert _unchanged_probe(fixture, version, "foreign-owner").status == "refused_untrusted"
    fixture.run(f"chown 65534 {meta}", user="0:0")
    fixture.run(f"mv {meta} {ROOT}/saved-metadata; ln -s {ROOT}/saved-metadata {meta}")
    assert _unchanged_probe(fixture, version, "metadata-symlink").status == "refused_untrusted"
    fixture.run(f"rm {meta}; mv {ROOT}/saved-metadata {meta}; ln -s {VENV} {ROOT}/linked-venv")
    assert _unchanged_probe(fixture, version, "root-symlink", venv=ROOT + "/linked-venv").status == "refused_untrusted"
    fixture.run(f"printf 'Name: fixture-package\\nVersion: 2.0.0\\n\\n' > {meta}")
    assert _unchanged_probe(fixture, version, "newer").status == "recognizable_newer"
    fixture.run(f"printf '\\377' > {meta}")
    assert _unchanged_probe(fixture, version, "undecodable").reason == "malformed_metadata"
    fixture.run(f"printf 'Name: fixture-package\\nVersion: 1.2.3\\n\\n' > {meta}")
    fixture.run(f"printf 'import os; os.mkdir(\"{ROOT}/executed\")\\n' > {SITE}/unknown.pth")
    hook = _unchanged_probe(fixture, version, "path-hook")
    assert hook.status == "unknown"
    assert hook.reason == "unsupported_layout"
    assert json.loads(_snapshot(fixture))
    print(
        json.dumps(
            {
                "cases_seconds": fixture.timings,
                "all_zero_operations": True,
                "all_fixture_snapshots_unchanged": True,
                "execution_sentinel_absent": True,
            }
        )
    )


@pytest.mark.parametrize(
    "case",
    [
        "sitecustomize.py",
        "sitecustomize.pyc",
        "sitecustomize.so",
        "sitecustomize/__init__.py",
        "usercustomize.py",
        "mixed-versions",
        "different-python-unsafe",
        "different-python-hook",
    ],
)
def test_native_venv_inventory_review_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    fixture = DockerFixture()
    fixture.guard_connector(tmp_path, monkeypatch)
    version = _prepare_fixture(fixture)
    expected = {"fixture-package": "1.2.3"}
    requested = version
    status, reason = "unknown", "unsupported_layout"
    meta = SITE + "/fixture_package-1.2.3.dist-info/METADATA"
    if case == "mixed-versions":
        fixture.run(
            f"printf 'Name: fixture-package\nVersion: 2.0.0\n\n' > {meta}; "
            f"mkdir {SITE}/z-1.0rc1.dist-info; "
            f"printf 'Name: z\nVersion: 1.0rc1\n\n' > {SITE}/z-1.0rc1.dist-info/METADATA"
        )
        expected["z"] = "1.0"
        reason = "uncomparable_version"
    elif case.startswith("different-python"):
        requested = "3.12.12"
        if case.endswith("unsafe"):
            fixture.run(f"chmod 0666 {meta}")
            status, reason = "refused_untrusted", "unsafe_owner_or_mode"
        else:
            fixture.run(f"printf 'import os; os.mkdir(\"{ROOT}/executed\")\n' > {SITE}/unknown.pth")
    else:
        path = SITE + "/" + case
        if "/" in case:
            fixture.run(f"mkdir {SITE}/sitecustomize")
        fixture.run(f"printf 'import os; os.mkdir(\"{ROOT}/executed\")\n' > {path}")
    result = _unchanged_probe(fixture, requested, case, distributions=expected)
    assert (result.status, result.reason) == (status, reason)
    print(
        json.dumps(
            {
                "case": case,
                "zero_operations": True,
                "unchanged_fixture": True,
                "execution_sentinel_absent": True,
                "seconds": fixture.timings[case],
            }
        )
    )


@pytest.mark.parametrize(
    ("case", "installed", "expected", "requested", "status"),
    [
        ("newer-missing", {"a": "2.0"}, {"a": "1.0", "b": "1.0"}, "3.12.13", "different_inventory"),
        ("newer-extra", {"a": "2.0", "c": "1.0"}, {"a": "1.0"}, "3.12.13", "different_inventory"),
        ("newer-older", {"a": "2.0", "b": "0.5"}, {"a": "1.0", "b": "1.0"}, "3.12.13", "different_inventory"),
        ("python-newer-older", {"a": "0.5"}, {"a": "1.0"}, "3.12.12", "different_inventory"),
        ("python-newer-missing", {}, {"a": "1.0"}, "3.12.12", "different_inventory"),
        ("python-newer-equivalent", {"a": "1.0.0"}, {"a": "1.0"}, "3.12.12", "different_inventory"),
        ("python-older-newer", {"a": "2.0"}, {"a": "1.0"}, "3.12.14", "different_inventory"),
        ("all-newer", {"a": "2.0"}, {"a": "1.0"}, "3.12.12", "recognizable_newer"),
    ],
)
def test_native_venv_inventory_mixed_drift_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    installed: dict[str, str],
    expected: dict[str, str],
    requested: str,
    status: str,
) -> None:
    fixture = DockerFixture()
    fixture.guard_connector(tmp_path, monkeypatch)
    _prepare_fixture(fixture)
    fixture.run(
        "python3 -I -S -B - <<'FIXTURE_PY'\n"
        "from pathlib import Path\n"
        f"site=Path({SITE!r})\n"
        "original=site/'fixture_package-1.2.3.dist-info'\n"
        "(original/'METADATA').unlink();original.rmdir()\n"
        f"installed={installed!r}\n"
        "for name,version in installed.items():\n"
        " info=site/f'{name}-{version}.dist-info';info.mkdir()\n"
        " (info/'METADATA').write_text(f'Name: {name}\\nVersion: {version}\\n\\n')\n"
        "FIXTURE_PY"
    )
    result = _unchanged_probe(fixture, requested, case, distributions=expected)
    assert result.status == status
    print(
        json.dumps(
            {
                "case": case,
                "status": result.status,
                "zero_operations": True,
                "unchanged_fixture": True,
                "execution_sentinel_absent": True,
                "seconds": fixture.timings[case],
            }
        )
    )
