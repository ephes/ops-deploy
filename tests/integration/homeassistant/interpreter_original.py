"""Actual original command/become cwd oracle in the admitted synthetic guest."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml

from .fixture import EVIDENCE, ROOT, write
from .matter_ready import bounded_command

CONTEXTS = {
    "controller": Path("/opt/controller"),
    "private-playbook": ROOT,
    "user-home": Path("/home/homeassistant"),
}

CORE_HASH = "9e6c1ff93b5f065e9dce44fda519406905b57bbe36fb0f519b07c1d556b38c9a"
IDENTITY = f"""
import ansible, ansible.release, hashlib, json
from pathlib import Path
root = Path(ansible.__file__).resolve().parent
resources = sorted((str(p.relative_to(root)), hashlib.sha256(p.read_bytes()).hexdigest())
                   for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
identity = hashlib.sha256(json.dumps(resources, separators=(',', ':')).encode()).hexdigest()
assert ansible.release.__version__ == '2.21.5'
assert len(resources) == 801 and identity == {CORE_HASH!r}
print(json.dumps({{'core_version':ansible.release.__version__, 'root':str(root),
                  'count':len(resources), 'identity':identity, 'resources':dict(resources)}}))
"""


def play(result: Path) -> list[dict[str, Any]]:
    """Original find task parameters, plus fixed public cwd/result observations."""
    return [
        {
            "hosts": "localhost",
            "gather_facts": False,
            "connection": "local",
            "become": True,
            "become_user": "homeassistant",
            "vars": {"ansible_python_interpreter": "/usr/bin/python3"},
            "tasks": [
                {
                    "name": "Observe original command effective cwd",
                    "ansible.builtin.command": {"argv": ["pwd"]},
                    "register": "owned_cwd",
                    "changed_when": False,
                },
                {
                    "name": "Original requested Python find",
                    "ansible.builtin.command": {"cmd": "/usr/local/bin/uv python find 3.14.8"},
                    "register": "owned_find",
                    "changed_when": False,
                    "failed_when": False,
                    "check_mode": False,
                },
                {
                    "name": "Retain owned public command result",
                    "become": False,
                    "ansible.builtin.copy": {
                        "dest": str(result),
                        "mode": "0600",
                        "content": (
                            "{{ {'effective_cwd': owned_cwd.stdout, 'cwd_rc': owned_cwd.rc, "
                            "'find_rc': owned_find.rc, 'find_stdout': owned_find.stdout, "
                            "'find_stderr': owned_find.stderr} | to_json }}"
                        ),
                    },
                },
            ],
        }
    ]


def verify_original_contexts() -> None:
    """No HA role or application; every original command runs as owned account."""
    identity = bounded_command(["/opt/homeassistant-ansible/bin/python", "-I", "-B", "-c", IDENTITY], timeout=30)
    write("interpreter-original-identity.json", identity)
    if identity["exit"] or identity["truncated"] or identity["timed_out"]:
        raise RuntimeError("owned original Ansible identity failed")
    proof = json.loads(identity["output"])
    assert proof["count"] == 801
    assert proof["identity"] == CORE_HASH
    previous = Path.cwd()
    for name, directory in CONTEXTS.items():
        path = directory / "owned-interpreter-original.yml"
        result = EVIDENCE / ("interpreter-original-" + name + ".json")
        assert not result.exists()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(yaml.safe_dump(play(result)))
            os.chdir(directory)
            command = bounded_command(
                ["/opt/homeassistant-ansible/bin/ansible-playbook", "-i", "localhost,", "-c", "local", str(path)],
                timeout=120,
            )
            write("interpreter-original-" + name + "-process.json", command)
            if command["exit"] or command["truncated"] or command["timed_out"]:
                raise RuntimeError("owned original interpreter command oracle failed")
            value = json.loads(result.read_text())
            if not isinstance(value, dict) or set(value) != {
                "effective_cwd",
                "cwd_rc",
                "find_rc",
                "find_stdout",
                "find_stderr",
            }:
                raise RuntimeError("owned original interpreter result missing")
            assert value["cwd_rc"] == 0
            if name == "private-playbook":
                assert value["effective_cwd"].startswith("/home/homeassistant/.ansible/tmp/ansible-moduletmp-")
            else:
                assert value["effective_cwd"] == str(directory)
            if name == "controller":
                assert value["find_rc"] != 0
                assert "Permission denied" in value["find_stderr"]
            else:
                assert value["find_rc"] == 0
                assert value["find_stdout"].startswith("/")
        finally:
            os.chdir(previous)
            path.unlink()
