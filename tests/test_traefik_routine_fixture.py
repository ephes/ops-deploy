"""The native fixture must refuse outside its owned hosted-VM envelope."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_fixture_refuses_before_any_host_command_without_hosted_authority(tmp_path: Path) -> None:
    sentinel = tmp_path / "called"
    fake_id = tmp_path / "id"
    fake_id.write_text(f"#!/bin/sh\ntouch '{sentinel}'\nexit 0\n")
    fake_id.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "GITHUB_ACTIONS": "false"}
    done = subprocess.run(
        ["bash", str(ROOT / "tests/integration/traefik_routine/run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode != 0
    assert not sentinel.exists()


def test_workflow_uses_immutable_feature_and_owned_fixture() -> None:
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/traefik-routine-integration.yml").read_text())
    steps = workflow["jobs"]["real-linux"]["steps"]
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts[1]["with"]["ref"] == "${{ inputs.implementation_sha }}"
    assert checkouts[1]["with"]["persist-credentials"] is False
    runner = (ROOT / "tests/integration/traefik_routine/run.sh").read_text()
    assert 'rev-parse HEAD) == "$IMPLEMENTATION_SHA"' in runner
    assert 'rev-parse HEAD) == "$HARNESS_SHA"' in runner
    assert "os.O_CREAT|os.O_EXCL|os.O_WRONLY" in runner


def test_trace_guard_detects_payload_and_mutations() -> None:
    import importlib.util

    import pytest

    spec = importlib.util.spec_from_file_location(
        "routine_fixture", ROOT / "tests/integration/traefik_routine/harness.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    packet = "A" * 400
    script = "builtin printf '%s' " + packet + " | python3"
    module.assert_observation_trace(script, ['execve("/usr/bin/python3", ["python3", "-c", "bootstrap"], []) = 0'])
    module.assert_observation_trace(
        script,
        [
            '10491 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = -1 ENXIO (No such device or address)',
        ],
    )
    for line in (
        '10491 openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3',
        '10491 openat(AT_FDCWD, "/tmp/example", O_RDWR|O_CREAT) = -1 EACCES (Permission denied)',
        'execve("/usr/bin/python3", ["python3", "' + packet + '"], []) = 0',
        'execve("/usr/bin/python3", ["python3", "AAAA"...], []) = 0',
        'fchmodat(AT_FDCWD, "/tmp/example", 0600) = 0',
        'fchownat(AT_FDCWD, "/tmp/example", 0, 0, 0) = 0',
        'symlinkat("target", AT_FDCWD, "/tmp/example") = 0',
        'linkat(AT_FDCWD, "source", AT_FDCWD, "target", 0) = 0',
        'mknodat(AT_FDCWD, "/tmp/example", S_IFIFO|0600) = 0',
    ):
        with pytest.raises(AssertionError):
            module.assert_observation_trace(script, [line])


def test_fixture_binary_obeys_unchanged_engine_policy() -> None:
    import ast

    from ops_deploy.infra.traefik_tx.engine import validate_policy

    tree = ast.parse((ROOT / "tests/integration/traefik_routine/harness.py").read_text())
    binary = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "FIXTURE_BINARY" for target in node.targets)
    )
    validate_policy(
        {
            "host": "fixture",
            "binary_path": binary,
            "config_path": "/etc/traefik/traefik.toml",
            "dynamic_path": "/etc/traefik/dynamic",
        }
    )
    runner = (ROOT / "tests/integration/traefik_routine/run.sh").read_text()
    assert f"! -e {binary}" in runner

    deaths = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "deaths")
    loop = next(node for node in deaths.body if isinstance(node, ast.For))
    targets = eval(compile(ast.Expression(loop.iter), "fixture-targets", "eval"), {"FIXTURE_BINARY": binary})
    assert binary in targets
    assert "/usr/local/bin/traefik" not in targets
