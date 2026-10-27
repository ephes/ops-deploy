"""Owned runner admission and strict filesystem observer boundaries."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "tests/integration/mail_web/harness.py"


def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("owned_mail_web_fixture", HARNESS)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "line",
    [
        '1 openat(AT_FDCWD, "/tmp/write", O_WRONLY|O_CREAT, 0600) = 3',
        '1 chmod("/etc/config", 0644) = 0',
        '1 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3',
        '1 unlink("/tmp/file") = 0',
    ],
)
def test_trace_rejects_writes(line: str) -> None:
    with pytest.raises(AssertionError):
        harness().trace_read_only(line)


def test_trace_accepts_reads_and_exact_absent_tty() -> None:
    harness().trace_read_only(
        '1 openat(AT_FDCWD, "/etc/config", O_RDONLY) = 3\n'
        '1 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = -1 ENXIO (No such device or address)'
    )


def test_runner_refuses_outside_owned_github_before_commands() -> None:
    result = subprocess.run(
        ["bash", str(HARNESS.with_name("run.sh"))], env={"PATH": "/usr/bin:/bin"}, capture_output=True
    )
    assert result.returncode != 0
    assert result.stdout == b""


def test_runner_syntax() -> None:
    subprocess.run(["bash", "-n", str(HARNESS.with_name("run.sh"))], check=True)


def test_trace_ignores_write_tokens_inside_exec_source() -> None:
    harness().trace_read_only('1 execve("/usr/bin/python3", ["python3", "-c", "os.chmod("/tmp/file", 0644)"], []) = 0')


def test_upgrader_observer_counts_only_successful_actual_exec() -> None:
    module = harness()
    good = '21 execve("/usr/bin/php", ["php", "public/upgrade.php"], []) = 0'
    assert module.is_upgrader_exec(good)
    assert not module.is_upgrader_exec(good.replace(" = 0", " = -1 ENOENT (No such file or directory)"))
    assert not module.is_upgrader_exec('21 execve("/usr/bin/python3", ["python3", "public/upgrade.php"], []) = 0')


@pytest.mark.parametrize("defect", [None, "editable", "wrong_ref", "source_import", "tampered", "missing", "extra"])
def test_actual_artifact_preamble_admits_only_exact_git_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str | None
) -> None:
    import importlib.metadata
    import json
    import os
    import shutil
    import sys
    import sysconfig
    from types import SimpleNamespace

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    source = tmp_path / ".implementation"
    package = source / "src/ops_deploy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# owned fixture package\n")
    (package / "resource.txt").write_text("exact resource\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "src"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    purelib = source / ".venv/lib/python/site-packages"
    installed = purelib / "ops_deploy"
    shutil.copytree(package, installed)
    direct: dict[str, Any] = {"vcs_info": {"commit_id": commit}}
    if defect == "editable":
        direct["dir_info"] = {"editable": True}
    if defect == "wrong_ref":
        direct["vcs_info"]["commit_id"] = "0" * 40
    if defect == "tampered":
        (installed / "resource.txt").write_text("changed")
    if defect == "missing":
        (installed / "resource.txt").unlink()
    if defect == "extra":
        (installed / "untracked.py").write_text("# unexpected importable code")
    imported = package if defect == "source_import" else installed
    monkeypatch.setitem(sys.modules, "ops_deploy", SimpleNamespace(__file__=str(imported / "__init__.py")))
    monkeypatch.setattr(
        importlib.metadata, "distribution", lambda _: SimpleNamespace(read_text=lambda _: json.dumps(direct))
    )
    monkeypatch.setattr(sysconfig, "get_paths", lambda: {"purelib": str(purelib)})
    for key, value in {
        "IMPLEMENTATION_ROOT": str(source),
        "IMPLEMENTATION_SHA": commit,
        "HARNESS_SHA": commit,
        "GITHUB_RUN_ID": "123",
    }.items():
        monkeypatch.setenv(key, value)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    marker = tmp_path / "owned.json"
    script = (
        HARNESS.with_name("run.sh").read_text().split("\"$CONTROLLER_PYTHON\" - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    )
    script = script.replace("/var/tmp/mail-web-evidence", str(evidence)).replace(
        "/var/tmp/mail-web-owned-vm.json", str(marker)
    )
    machine = tmp_path / "machine-id"
    machine.write_text("owned-fixture")
    script = script.replace("/etc/machine-id", str(machine))
    if defect:
        with pytest.raises((AssertionError, FileNotFoundError)):
            exec(compile(script, "artifact-preamble", "exec"), {})
        assert not marker.exists()
    else:
        exec(compile(script, "artifact-preamble", "exec"), {})
        record = json.loads((evidence / "installed-artifact.json").read_text())
        assert record["implementation_sha"] == commit
        assert set(record["resources"]) == {"__init__.py", "resource.txt"}
        assert json.loads(marker.read_text())["run"] == os.environ["GITHUB_RUN_ID"]


@pytest.mark.parametrize("markers", [0, 1, 2])
def test_partial_bootstrap_fault_modifies_exact_public_source_marker(markers: int) -> None:
    import ast
    import base64
    import shlex

    source = "SQL = " + repr("SELECT " + "$1::varchar " * markers) + "\n"
    encoded = base64.b64encode(source.encode()).decode()
    loader = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<mail-web>','exec'))"
    command = shlex.join(["python3", "-I", "-B", "-c", loader])
    if markers != 1:
        with pytest.raises(AssertionError):
            harness().partial_bootstrap_command(command)
        return
    modified = harness().partial_bootstrap_command(command)
    argv = shlex.split(modified)
    assert argv[:-1] == shlex.split(command)[:-1]
    literal = next(
        node.args[0]
        for node in ast.walk(ast.parse(argv[-1]))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "b64decode"
    )
    assert base64.b64decode(ast.literal_eval(literal)).decode() == source.replace("$1::varchar", "$1")
