"""Controller source binding and actual local CLI fact-stdin confidentiality."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime.inspect import (
    observation_command,
    observation_payload,
    source_manifest,
)
from tests.test_daybook_runtime_contract import config


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def source(tmp_path: Path) -> SourceTree:
    git(tmp_path, "init", "--quiet", "--template=")
    (tmp_path / "src/daybook").mkdir(parents=True)
    (tmp_path / "src/daybook/operations_runtime.py").write_text("# synthetic owned code; never imported\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="owned-daybook-fixture"\nversion="0.0.0"\n')
    git(tmp_path, "add", ".")
    git(
        tmp_path,
        "-c",
        "user.name=Owned Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--quiet",
        "-m",
        "owned",
    )
    return SourceTree(tmp_path, git(tmp_path, "rev-parse", "HEAD"))


def test_payload_binds_exact_source_keeps_enabled_state_and_no_credential_hash(source: SourceTree) -> None:
    cfg = config(revision=source.commit)
    value = "owned-fixture-executor-credential-" + "x" * 32
    payload = observation_payload(cfg, {"executor_token": value}, source)
    assert payload["preserve_enabled"] is True
    assert payload["revision"] == source.commit
    assert set(payload["source_hashes"]) == {"src/daybook/operations_runtime.py", "pyproject.toml"}
    assert not any("sha" in key for key in payload["resources"][-1])
    assert value not in observation_command()
    assert value not in observation_command("verify")
    from ops_deploy.services.daybook_operations_runtime.render import render_credential

    assert payload["resources"][-1]["content"].encode() == render_credential(value).reveal()
    assert json.loads(payload["resources"][-1]["content"]) == {"token": value}


def test_controller_source_difference_and_dirty_tree_refuse_before_observation(source: SourceTree) -> None:
    with pytest.raises(ValueError, match="once-resolved"):
        source_manifest(source, config())
    (source.path / "src/daybook/operations_runtime.py").write_text("dirty\n")
    with pytest.raises(ValueError, match="exact and clean"):
        source_manifest(source, config(revision=source.commit))


@pytest.mark.parametrize("stream", [False, True])
def test_actual_verbose_local_cli_fact_stdin_boundary(tmp_path: Path, stream: bool) -> None:
    private = "OWNED-STDIN-FIXTURE-NEVER-ECHO-" + "x" * 32
    probe = "import json,sys;v=json.load(sys.stdin);assert len(v['private'])>20;print('current')"
    launcher = "import base64;exec(base64.b64decode('" + base64.b64encode(probe.encode()).decode() + "'))"
    import shlex

    command = shlex.join([sys.executable, "-I", "-B", "-c", launcher])
    stdin = "io.StringIO(values['request'])" if stream else "values['request']"
    module = tmp_path / "deploy.py"
    module.write_text(
        "import io\nfrom pyinfra import host\nfrom pyinfra.facts.server import Command\n"
        "from ops_deploy.core.secrets import SecretRef,SecretValues\n"
        f"values=SecretValues(SecretRef('fixture.yml'),{{'request':{json.dumps({'private': private})!r}}})\n"
        f"result=host.get_fact(Command,command={command!r},_stdin={stdin},_get_pty=False)\n"
        "assert result=='current','owned secret stdin fact failed'\n"
    )
    executable = Path(sys.executable).with_name("pyinfra")
    run = subprocess.run(
        [str(executable), "@local", str(module), "--debug", "-vv", "-y"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert (private not in run.stdout + run.stderr) is stream
    assert private not in command
    assert "Loaded fact server.Command" in run.stdout + run.stderr
    (tmp_path / "verbose-local-fact.log").write_text(run.stdout + run.stderr)
