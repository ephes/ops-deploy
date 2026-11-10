"""Record what ops-library renders for the Echoport runners, computed by ``ansible-playbook`` itself.

Run with ansible-core 2.21 (and the ``community.general`` collection, for the
role's ``dict_kv``) on ``PATH`` and an ops-library checkout::

    OPS_LIBRARY_PATH=../ops-library uv run --locked python tests/parity/echoport_runner/generate.py

``inputs.json`` holds, per runner, the vendored template and the variables
the register playbook renders it with (resolved values, no ``{{ }}``). For
each runner the script renders ``roles/echoport_backup/templates/<template>``
with ansible's ``template`` module on localhost. For each case in
``ROLE_CASES`` it runs the ``fastdeploy_runner`` role's own tasks that build
``config.json`` and the sudoers rule (read from ``tasks/main.yml``, with the
destination moved into a temporary directory and without owner, group and
``visudo``). ``expected.json`` records the sha256 of every rendering, the full
``config.json`` and sudoers texts, the sha256 of each source template and the
ops-library commit.

A runner whose template is in ``render.FORKED`` is rendered from ops-deploy's
own template instead (ops-deploy is its source now): its ``source_sha256`` is
ops-deploy's, and ``forked_from`` records the sha256 of ops-library's copy,
which only the Ansible rollback renders.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from ops_deploy.services._echoport_runner.render import FORKED, PACKAGE, render_runner

HERE = Path(__file__).parent
OWN_TEMPLATES = HERE.parents[2] / "src" / PACKAGE.replace(".", "/") / "templates"
ROLE_TASKS = (
    "fastdeploy_runner | Define the FastDeploy service configuration",
    "fastdeploy_runner | Write config.json with the fixed script path",
    "fastdeploy_runner | Permit only the fixed script path through the runner chain",
)
# fastdeploy_runner_* variables (without the prefix) of each role case.
ROLE_CASES: dict[str, dict[str, Any]] = {
    "root-runner": {
        "service": "paperless-backup",
        "description": "Paperless backup \u2013 same-host PostgreSQL + filesystem backup/restore with rollback safety",
        "steps": ["init", "dump_database", "upload", "result"],
        "template": "unused.py.j2",
        "run_as": "root",
    },
    "deploy-runner": {
        "service": "homepage-staging-backup",
        "steps": ["init", "error", "result"],
        "template": "unused.py.j2",
        "sudoers_file": "/etc/sudoers.d/homepage_staging_backup",
    },
    "own-paths": {
        "service": "delve-backup",
        "description": 'Delve "SQLite" backup',
        "steps": ["backup"],
        "content": "#!/usr/bin/env python3\n",
        "script_name": "run.py",
        "libexec_root": "/opt/runners",
        "fastdeploy_root": "/srv/fastdeploy",
        "deploy_user": "runner",
        "fastdeploy_user": "fd",
        "run_as": "backup",
    },
}


def ansible_env(base: Path) -> dict[str, str]:
    return {
        **os.environ,
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_LOCALHOST_WARNING": "0",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "0",
        "ANSIBLE_RETRY_FILES_ENABLED": "0",
        "ANSIBLE_LOCAL_TEMP": str(base / "ansible-local"),
        "ANSIBLE_REMOTE_TEMP": str(base / "ansible-remote"),
    }


def play(base: Path, plays: list[dict[str, Any]]) -> None:
    path = base / "play.json"
    path.write_text(json.dumps(plays))  # JSON is YAML
    argv = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(path)]
    result = subprocess.run(argv, capture_output=True, text=True, env=ansible_env(base), timeout=900, check=False)
    if result.returncode != 0:
        raise SystemExit(result.stdout + result.stderr)


def render_templates(library: Path, runners: dict[str, Any], base: Path) -> dict[str, str]:
    """Every runner's script as Ansible's ``template`` module writes it."""

    templates = library / "roles/echoport_backup/templates"
    plays = []
    for name, runner in runners.items():
        variables = base / f"{name}.vars.json"
        variables.write_text(json.dumps(runner["inputs"]))
        task = {"ansible.builtin.template": {"src": str(templates / runner["template"]), "dest": str(base / name)}}
        plays.append({"hosts": "localhost", "gather_facts": False, "vars_files": [str(variables)], "tasks": [task]})
    play(base, plays)
    return {name: (base / name).read_text() for name in runners}


def role_tasks(library: Path, out: Path) -> list[dict[str, Any]]:
    tasks = yaml.safe_load((library / "roles/fastdeploy_runner/tasks/main.yml").read_text())
    picked = []
    for task in tasks:
        if task.get("name") not in ROLE_TASKS:
            continue
        task = copy.deepcopy(task)
        module = task.get("ansible.builtin.copy")
        if module is not None:
            for key in ("owner", "group", "mode", "validate"):
                module.pop(key, None)
            module["dest"] = str(out / ("config.json" if "config.json" in task["name"] else "sudoers"))
        picked.append(task)
    assert [task["name"] for task in picked] == list(ROLE_TASKS), "the role's tasks moved; update ROLE_TASKS"
    return picked


def render_role(library: Path, base: Path) -> dict[str, dict[str, str]]:
    """``config.json`` and the sudoers rule of each case, from the role's own tasks."""

    # Play vars, not vars_files: the case's values must win over the role's defaults.
    defaults = yaml.safe_load((library / "roles/fastdeploy_runner/defaults/main.yml").read_text())
    plays = []
    for name, case in ROLE_CASES.items():
        out = base / f"role-{name}"
        out.mkdir()
        values = {f"fastdeploy_runner_{key}": value for key, value in case.items()}
        plays.append(
            {
                "hosts": "localhost",
                "gather_facts": False,
                "vars": {**defaults, **values},
                "tasks": role_tasks(library, out),
            }
        )
    play(base, plays)
    return {
        name: {
            "config.json": (base / f"role-{name}" / "config.json").read_text(),
            "sudoers": (base / f"role-{name}" / "sudoers").read_text(),
        }
        for name in ROLE_CASES
    }


def main() -> None:
    library = Path(os.environ["OPS_LIBRARY_PATH"]).resolve()
    runners = json.loads((HERE / "inputs.json").read_text())["runners"]
    head = subprocess.run(["git", "-C", str(library), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    version = subprocess.run(["ansible", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[
        0
    ]
    library_runners = {name: runner for name, runner in runners.items() if runner["template"] not in FORKED}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        rendered = render_templates(library, library_runners, base)
        role = render_role(library, base)
    for name, runner in runners.items():
        if runner["template"] in FORKED:
            rendered[name] = render_runner(runner["template"], runner["inputs"])
    rendered = {name: rendered[name] for name in runners}
    templates = library / "roles/echoport_backup/templates"
    expected = {
        "provenance": (
            f"Rendered by ansible-playbook locally ({version}) from inputs.json; "
            "tests/parity/echoport_runner/generate.py"
        ),
        "source_ref": head.stdout.strip(),
        "runners": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in rendered.items()},
        "source_sha256": {
            path.name: hashlib.sha256(
                (OWN_TEMPLATES / path.name if path.name in FORKED else path).read_bytes()
            ).hexdigest()
            for path in sorted(templates.glob("*.j2"))
        },
        "forked_from": {name: hashlib.sha256((templates / name).read_bytes()).hexdigest() for name in sorted(FORKED)},
        "role_cases": ROLE_CASES,
        "role": role,
    }
    (HERE / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
