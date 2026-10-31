"""Ordinary CLI retry flag and real SDK/notification history, synthetic commands."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = """
import json, shlex
from pathlib import Path
from pyinfra import state
from pyinfra.api import operation
from pyinfra.operations import python, server
from ops_deploy.services.homeassistant import interpreter
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.services.homeassistant.python_runtime import PythonRuntimeChanges
root = Path(__ROOT__)
mode = __MODE__
marker = shlex.quote(str(root / 'installed'))
once = shlex.quote(str(root / 'failed-once'))
installs = shlex.quote(str(root / 'installs'))
def command(cfg, action):
    if action == 'install':
        return 'touch ' + marker + '; printf "install\\n" >> ' + installs
    if mode == 'transient':
        return ('test -f ' + marker + ' || exit 7; if test -f ' + once +
                '; then printf "/owned/python\\n"; else touch ' + once + '; exit 7; fi')
    return 'test -f ' + marker + ' && printf "/owned/python\\n"'
interpreter.interpreter_command = command
@operation()
def noop():
    yield from ()
unchanged = noop(name='Owned unchanged sibling')
installed = interpreter.install_python(HomeAssistantRuntimeConfig(), deferred=True)
changes = PythonRuntimeChanges(installed, unchanged, unchanged, unchanged, None,
                               unchanged, unchanged, unchanged)
server.shell(name='Owned HA notification', commands=['printf "ha\\n" >> ' +
             shlex.quote(str(root / 'notifications'))], _if=changes.homeassistant_changed)
server.shell(name='Owned Matter notification', commands=['printf "matter\\n" >> ' +
             shlex.quote(str(root / 'notifications'))], _if=changes.matter_changed)
def record():
    (root / 'result.json').write_text(json.dumps({
      'retry_config':state.config.RETRY, 'complete':installed.is_complete(),
      'success':installed.did_succeed(), 'executed':installed.executed,
      'changed':installed.did_change(), 'ha':changes.homeassistant_changed(),
      'matter':changes.matter_changed()}))
python.call(name='Record owned completion', function=record)
"""


@pytest.mark.parametrize("mode", ["present", "cold", "transient"])
def test_actual_cli_inherited_retry_preserves_both_restart_notifications(tmp_path: Path, mode: str) -> None:
    deploy = tmp_path / "owned-deploy.py"
    deploy.write_text(SCRIPT.replace("__ROOT__", repr(str(tmp_path))).replace("__MODE__", repr(mode)))
    if mode == "present":
        (tmp_path / "installed").touch()
    executable = Path(sys.executable).parent / "pyinfra"
    for attempt in (0, 1):
        process = subprocess.run(
            [sys.executable, str(executable), "--retry", "1", "--retry-delay", "0", "-y", "@local", str(deploy)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert process.returncode == 0, process.stdout + process.stderr
        result = json.loads((tmp_path / "result.json").read_text())
        changed = mode != "present" and attempt == 0
        assert result == {
            "retry_config": 1,
            "complete": True,
            "success": True,
            "executed": changed,
            "changed": changed,
            "ha": changed,
            "matter": changed,
        }
        if mode == "present":
            assert not (tmp_path / "installs").exists()
            assert not (tmp_path / "notifications").exists()
        else:
            assert (tmp_path / "installs").read_text().splitlines() == ["install"]
            assert (tmp_path / "notifications").read_text().splitlines() == ["ha", "matter"]
