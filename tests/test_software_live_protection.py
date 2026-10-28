"""Run shipped host probes over owned files, process links and cgroup membership."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.helpers.probes import probe_command, stdin_arguments
from ops_deploy.services.software_live.common import RESOURCE


@pytest.fixture
def owned_tree(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "releases"
    root.mkdir()
    proc = tmp_path / "proc"
    cgroup = tmp_path / "cgroup"
    (cgroup / "fixture").mkdir(parents=True)
    (cgroup / "fixture/cgroup.procs").write_text("100\n101\n")
    for pid, target in ((100, root / "1.0.0/software-live"), (101, root / "0.9.0/software-live-apt (deleted)")):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "exe").symlink_to(target)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\nfor unit do :; done\n"
        'if [ "$unit" = software-live-collector.service ]; then\n'
        " echo ActiveState=active; echo MainPID=100; echo ControlPID=0; echo ControlGroup=/fixture\n"
        f" echo 'ExecStart={{ path={root}/1.0.0/software-live ; }}'\n"
        "else\n echo ActiveState=inactive; echo MainPID=0; echo ControlPID=0; echo ControlGroup=\nfi\n"
    )
    systemctl.chmod(0o755)
    names: dict[str, Any] = {
        "dropins": [str(tmp_path / "endpoint.conf"), str(tmp_path / "collector.conf")],
        "units": [str(tmp_path / "shadow-endpoint.service"), str(tmp_path / "shadow-collector.service")],
        "pin": str(root / ".pins/software-live"),
        "shadow_pin": str(root / ".pins/software-live-shadow"),
    }
    Path(names["dropins"][0]).write_text(f"[Service]\nExecStart={root}/2.0.0/software-live serve\n")
    (root / ".pins").mkdir()
    Path(names["pin"]).write_text("0.8.0\n")
    return {"root": str(root), "proc": str(proc), "cgroup": str(cgroup), "paths": names}


def inspect(tree: dict[str, Any], login_shell: str = "bash") -> dict[str, Any]:
    script = (
        RESOURCE.joinpath("files/software_live_impl.py").read_text()
        + "\n"
        + RESOURCE.joinpath("files/live_state_host.py").read_text()
    )
    base = Path(tree["root"]).parent
    command = probe_command(shlex.join([sys.executable, "-I", "-", json.dumps(tree)]))
    remote = make_unix_command(StringCommand(command)).get_raw_value()
    stdin = stdin_arguments(script)
    assert repr(stdin["_stdin"]) == "<stdin redacted>"
    assert stdin["_get_pty"] is False
    assert script not in remote
    result = subprocess.run(
        [login_shell, "-c", remote],
        input="".join(stdin["_stdin"]),
        env={**os.environ, "PATH": str(base / "bin") + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=True,
    )
    value: dict[str, Any] = json.loads(result.stdout)
    return value


@pytest.mark.parametrize("login_shell", ["bash", "fish"])
def test_actual_host_driver_protects_loaded_files_processes_and_apt_child(
    owned_tree: dict[str, Any], login_shell: str
) -> None:
    if not shutil.which(login_shell):
        pytest.skip(f"{login_shell} unavailable")
    found = inspect(owned_tree, login_shell)
    assert found["unknown"] == []
    assert found["versions"] == ["0.9.0", "1.0.0", "2.0.0"]
    assert found["pin"] == "0.8.0"  # release helper protects pins separately
    assert found["last_live"] == "0.8.0"


def test_actual_host_driver_marks_missing_active_cgroup_unknown(owned_tree: dict[str, Any]) -> None:
    Path(owned_tree["cgroup"], "fixture/cgroup.procs").unlink()
    found = inspect(owned_tree)
    assert found["unknown"]
    assert "1.0.0" in found["versions"]


def test_actual_host_driver_marks_symlinked_control_file_unknown(owned_tree: dict[str, Any]) -> None:
    path = Path(owned_tree["paths"]["dropins"][0])
    path.unlink()
    path.symlink_to(path.parent / "unread-control-file")
    assert inspect(owned_tree)["unknown"]
