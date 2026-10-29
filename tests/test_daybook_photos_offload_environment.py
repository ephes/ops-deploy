"""Owned real .venv replacement/metadata, controlled UV and GUI probes."""

from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import re
import runpy
import shutil
import subprocess
import sys
import types
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    package = "ops_deploy.services.daybook_photos_offload"
    source = types.ModuleType("ops_photos_source")
    source.__dict__.update(runpy.run_path(str(files(package).joinpath("files/photos_source.py"))))
    fs = types.ModuleType("ops_photos_filesystem")
    fs.__dict__.update(
        runpy.run_path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py")))
    )
    monkeypatch.setitem(sys.modules, "ops_photos_source", source)
    monkeypatch.setitem(sys.modules, "ops_photos_filesystem", fs)
    module = runpy.run_path(str(files(package).joinpath("files/photos_environment.py")))
    root = tmp_path / "root-protected-checkout"
    root.mkdir()
    (root / "tracked.py").write_text("OWNED protected code never imported\n")
    data = {
        "checkout": str(root),
        "uid": os.getuid(),
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "uv_bin": "/owned/uv",
        "python_version": "3.14.7",
    }

    class Probes:
        def __init__(self) -> None:
            self.version_ok = False
            self.context_ok = True
            self.lock_ok = True
            self.calls: list[Any] = []
            self.managed: list[Any] = []

        def run(self, argv: list[str], *, user: bool = False, extra: Any = None) -> Any:
            assert user
            self.calls.append((argv, extra))
            if argv == ["/usr/bin/id", "-u"]:
                return SimpleNamespace(returncode=0 if self.context_ok else 1, stdout=str(data["uid"]).encode())
            if "--check" in argv:
                return SimpleNamespace(returncode=0 if self.lock_ok else 1, stdout=b"")
            assert argv[1:4] == ["-I", "-B", "-S"]
            return SimpleNamespace(returncode=0 if self.version_ok else 1, stdout=b"")

        def managed_user(self, argv: list[str], *, cwd: str, extra: Any = None) -> Any:
            self.managed.append((argv, cwd, extra))
            assert not (root / ".venv/stale-marker").exists(), "wrong-interpreter environment was not recreated"
            (root / ".venv/bin").mkdir(exist_ok=True)
            (root / ".venv/bin/python").write_text("OWNED fake interpreter never executed")
            self.version_ok = True
            return SimpleNamespace(returncode=0)

    class Controls:
        def require_quiescent(self) -> None:
            pass

    return SimpleNamespace(module=module, data=data, probes=Probes(), controls=Controls(), root=root)


def managed(c: Any) -> None:
    # Simulated root identity only. Actual filesystem writes stay in the owned
    # current-user temporary tree; no real chown, sudo, UV or interpreter call.
    with patch("os.geteuid", return_value=0):
        c.module["converge_environment"](c.data, c.probes, c.controls)


def test_missing_environment_preparation_and_exact_original_sync_flags(environment: Any) -> None:
    c = environment
    assert not c.module["environment_current"](c.data, c.probes)
    assert not (c.root / ".venv").exists()
    assert not c.probes.managed
    before = (c.root / "tracked.py").read_bytes()
    managed(c)
    assert c.module["environment_current"](c.data, c.probes)
    assert (c.root / "tracked.py").read_bytes() == before
    argv, cwd, extra = c.probes.managed[0]
    assert argv == [
        "/owned/uv",
        "sync",
        "--frozen",
        "--no-config",
        "--no-dev",
        "--no-install-project",
        "--python",
        "3.14.7",
    ]
    assert cwd == str(c.root)
    assert extra == {"UV_PROJECT_ENVIRONMENT": ".venv", "UV_PYTHON_PREFERENCE": "only-managed"}
    check = next(argv for argv, _ in c.probes.calls if "--check" in argv)
    assert all(
        flag in check
        for flag in (
            "--frozen",
            "--no-config",
            "--no-dev",
            "--no-install-project",
            "--offline",
            "--no-python-downloads",
            "--no-cache",
        )
    )
    assert "--no-build" not in check


def test_wrong_interpreter_root_rebuilds_state_free_env_only(environment: Any) -> None:
    c = environment
    venv = c.root / ".venv"
    (venv / "bin").mkdir(parents=True)
    venv.chmod(0o700)
    (venv / "bin/python").write_text("OWNED old fake interpreter")
    (venv / "stale-marker").write_text("OWNED stale environment")
    outside = c.root.parent / "outside"
    outside.write_text("OWNED protected outside")
    before = (c.root / "tracked.py").read_bytes(), outside.read_bytes()
    managed(c)
    assert not (venv / "stale-marker").exists()
    assert ((c.root / "tracked.py").read_bytes(), outside.read_bytes()) == before


def test_current_version_keeps_environment_and_dependency_negative_is_pure(environment: Any) -> None:
    c = environment
    managed(c)
    marker = c.root / ".venv/keep"
    marker.write_text("OWNED keep")
    count = len(c.probes.managed)
    assert c.module["environment_current"](c.data, c.probes)
    assert len(c.probes.managed) == count
    c.probes.lock_ok = False
    assert not c.module["environment_current"](c.data, c.probes)
    assert marker.exists()
    assert len(c.probes.managed) == count


def test_unavailable_gui_transition_refuses_before_removal(environment: Any) -> None:
    c = environment
    venv = c.root / ".venv"
    venv.mkdir()
    (venv / "keep").write_text("OWNED keep")
    c.probes.context_ok = False
    with pytest.raises(c.module["PhotosEnvironmentError"], match="gui_context_unavailable"):
        managed(c)
    assert (venv / "keep").exists()
    assert not c.probes.managed


def test_symlink_environment_refuses_before_managed_execution(environment: Any) -> None:
    c = environment
    (c.root / ".venv").symlink_to(c.root.parent)
    with pytest.raises((RuntimeError, OSError)):
        managed(c)
    assert not c.probes.managed


def test_managed_user_preserves_original_cwd_after_login_transition(tmp_path: Path) -> None:
    source = runpy.run_path(str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_source.py")))
    account = pwd.getpwuid(os.getuid())
    data = {"user": account.pw_name, "home": account.pw_dir, "path": "/usr/bin:/bin"}
    probes = source["PhotosProbes"](data)
    # Real owned non-escalating execution checks the inner chdir. Native checks
    # the root-to-GUI -i transition; its exact argv is asserted separately here.
    result = probes.managed_user(["/bin/pwd", "-P"], cwd=str(tmp_path))
    assert result.returncode == 0
    assert Path(result.stdout.decode().strip()) == tmp_path.resolve()
    with (
        patch("os.geteuid", return_value=0),
        patch("subprocess.run", return_value=SimpleNamespace(returncode=0)) as run,
    ):
        probes.managed_user(["/owned/uv", "sync", "--frozen"], cwd=str(tmp_path))
    command = run.call_args.args[0]
    assert command[:8] == ["/usr/bin/sudo", "-n", "-H", "-i", "-u", account.pw_name, "--", "/usr/bin/python3"]
    assert command[8:13] == ["-I", "-B", "-S", "-c", command[-1]]
    assert "$" not in command[-1]
    encoded = re.search(r"b64decode\('([^']+)'\)", command[-1])
    assert encoded
    payload = json.loads(base64.b64decode(encoded[1]))
    assert payload == {
        "cwd": str(tmp_path),
        "argv": ["/owned/uv", "sync", "--frozen"],
        "env": {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name, "PATH": "/usr/bin:/bin"},
    }


def sudo_i_text(argv: list[str]) -> str:
    # sudo's documented -i escaping: dollar remains unescaped. This deliberately
    # differs from shlex.quote, which would hide the broken old implementation.
    return " ".join(
        "".join(c if c.isascii() and (c.isalnum() or c in "_-$") else "\\" + c for c in arg) for arg in argv
    )


@pytest.mark.parametrize("shell", ["/bin/zsh", shutil.which("fish")])
def test_actual_login_shell_serialization_old_negative_and_dollar_safe_fixed_positive(
    tmp_path: Path, shell: str | None
) -> None:
    if shell is None or not Path(shell).exists():
        pytest.skip("Exact login shell is unavailable; hosted Darwin proves its native shell")
    source = runpy.run_path(str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_source.py")))
    account = pwd.getpwuid(os.getuid())
    root = tmp_path / "owned space $not_a_variable"
    root.mkdir()
    probes = source["PhotosProbes"]({"user": account.pw_name, "home": account.pw_dir, "path": "/usr/bin:/bin"})
    with (
        patch("os.geteuid", return_value=0),
        patch("subprocess.run", return_value=SimpleNamespace(returncode=0)) as run,
    ):
        probes.managed_user(["/bin/pwd", "-P"], cwd=str(root))
    command = run.call_args.args[0]
    fixed = subprocess.run([shell, "-c", sudo_i_text(command[7:])], capture_output=True, text=True)
    assert fixed.returncode == 0, fixed.stderr
    assert Path(fixed.stdout.strip()) == root.resolve()
    old = ["/bin/sh", "-c", 'cd "$1" && shift && exec "$@"', "photos-managed-user", str(root), "/bin/pwd", "-P"]
    negative = subprocess.run([shell, "-c", sudo_i_text(old)], capture_output=True, text=True)
    assert negative.returncode != 0 or negative.stdout.strip() != str(root.resolve())


def test_pure_probe_bounds_do_not_become_managed_git_deadlines(tmp_path: Path) -> None:
    source = runpy.run_path(str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_source.py")))
    account = pwd.getpwuid(os.getuid())
    probes = source["PhotosProbes"](
        {"user": account.pw_name, "home": account.pw_dir, "path": "/usr/bin:/bin", "checkout": str(tmp_path)}
    )
    with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=b"")) as run:
        probes.run(["/bin/true"])
        assert run.call_args.kwargs["timeout"] == 30
        probes.git("checkout", "--detach", "a" * 40, managed=True)
        assert run.call_args.kwargs["timeout"] is None
        probes.git("fetch", "--no-tags", "--force", "origin", "refs/heads/main", managed=True)
        assert run.call_args.kwargs["timeout"] is None
