"""Record what the openclaw_deploy role writes, computed by ansible-core itself.

Run with the Python of an ansible-core 2.21 installation and an ops-library
checkout::

    OPS_LIBRARY_PATH=../ops-library <ansible-core python> tests/parity/openclaw_deploy/generate.py

For every case directory (``vars.json``: role variables and
``metrics_httpd_impl``; optional ``openclaw.json``: the gateway config the
host already holds; optional ``present.json``: other paths that exist) it
walks the role's task files in ``tasks/main.yml`` order with ansible-core's
``Templar``: ``when``, ``loop``, task ``vars``, ``set_fact``, ``template``,
``copy`` (``content``, ``src``, ``force: false``), ``file``, ``stat`` and
``slurp`` against an in-memory host, and the role's inline ``python3 -c``
scripts on a temporary copy of the file. Tasks that need Docker, systemd or
the network are skipped; the deploy's own tests cover them. ``expected.json``
lists every file (sha256, owner, group, mode) and directory the role would
write, plus the full text of the resulting ``openclaw.json``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml
from ansible.errors import AnsibleUndefinedVariable
from ansible.template import Templar, trust_as_template

HERE = Path(__file__).parent
ROLE = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles" / "openclaw_deploy"
TASK_FILES = (
    "directories.yml",
    "env.yml",
    "config.yml",
    "audio_transcription.yml",
    "compose.yml",
    "systemd.yml",
    "traefik.yml",
    "logrotate.yml",
    "weeknotes.yml",
    "imap.yml",
    "calendar.yml",
    "paperless.yml",
    "homeassistant.yml",
    "opsgate.yml",
    "workspace_skills.yml",
    "metrics.yml",
    "session_state.yml",
)
MAIN_WHEN = {
    "audio_transcription.yml": "openclaw_audio_transcription_enabled | bool",
    "traefik.yml": "openclaw_traefik_enabled | bool",
    "weeknotes.yml": "openclaw_weeknotes_enabled | bool",
    "imap.yml": "openclaw_imap_enabled | bool",
    "calendar.yml": "openclaw_calendar_enabled | bool",
    "paperless.yml": "openclaw_paperless_enabled | bool",
    "homeassistant.yml": "openclaw_homeassistant_enabled | bool",
    "opsgate.yml": "openclaw_opsgate_enabled | bool",
    "workspace_skills.yml": "openclaw_workspace_skills | length > 0",
}
SKIPPED = {
    "ansible.builtin.import_tasks",
    "ansible.builtin.include_role",
    "ansible.builtin.meta",
    "ansible.builtin.debug",
    "ansible.builtin.assert",
    "ansible.builtin.systemd",
    "ansible.builtin.package",
    "ansible.builtin.group",
    "ansible.builtin.user",
    "ansible.builtin.wait_for",
}


def trusted(value: Any) -> Any:
    if isinstance(value, str):
        return trust_as_template(value)
    if isinstance(value, list):
        return [trusted(item) for item in value]
    if isinstance(value, dict):
        return {key: trusted(item) for key, item in value.items()}
    return value


def plain(value: Any) -> Any:
    if isinstance(value, str):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    return value


class Host:
    def __init__(self, existing: dict[str, Any] | None, present: list[str]) -> None:
        self.files: dict[str, dict[str, Any]] = {}
        self.dirs: dict[str, dict[str, Any]] = {}
        self.removed: list[str] = []
        self.present = set(present)
        self.existing: dict[str, bytes] = {}
        self.existing_config = existing

    def content(self, path: str) -> bytes | None:
        if path in self.files:
            data: bytes = self.files[path]["bytes"]
            return data
        return self.existing.get(path)


UNDECIDED: list[str] = []


def holds(task: dict[str, Any], context: dict[str, Any]) -> bool:
    conditions = task["when"] if isinstance(task.get("when"), list) else [task["when"]] if "when" in task else []
    templar = Templar(variables=context)
    try:
        return all(templar.evaluate_conditional(trust_as_template(str(c))) for c in conditions)
    except AnsibleUndefinedVariable:
        # Gated on the result of a skipped task (Docker, htpasswd): left to the deploy's tests.
        UNDECIDED.append(task["name"])
        return False


def walk(tasks: list[dict[str, Any]], variables: dict[str, Any], host: Host) -> None:
    for task in tasks:
        if "block" in task:
            if holds(task, variables):
                walk(task["block"], variables, host)
            continue
        scoped = dict(variables)
        for key, value in (task.get("vars") or {}).items():
            scoped[key] = trusted(value)
        # ``when`` is evaluated per loop item, after the loop.
        items: list[Any] = (
            plain(Templar(variables=scoped).template(trusted(task["loop"]))) if "loop" in task else [None]
        )
        results = []
        for item in items:
            # set_fact in a loop sees the previous iterations' facts.
            context = {**variables, **{key: value for key, value in scoped.items() if key in (task.get("vars") or {})}}
            if item is not None:
                context["item"] = item
            if holds(task, context):
                try:
                    run(task, context, variables, host)
                except AnsibleUndefinedVariable:
                    UNDECIDED.append(task["name"])
                if "loop" in task and "register" in task and task["register"] in variables:
                    results.append({**variables.pop(task["register"]), "item": item})
        if "loop" in task and "register" in task:
            variables[task["register"]] = {"results": results}


def run(task: dict[str, Any], context: dict[str, Any], variables: dict[str, Any], host: Host) -> None:
    templar = Templar(variables=context)

    def value(raw: Any) -> Any:
        return plain(templar.template(trusted(raw)))

    action = next(key for key in task if key.startswith("ansible.builtin."))
    args = task[action]
    if action in SKIPPED:
        return
    if action == "ansible.builtin.set_fact":
        for key, raw in args.items():
            variables[key] = value(raw)
        return
    if action == "ansible.builtin.template":
        source = (ROLE / "templates" / value(args["src"])).read_text()
        text = Templar(variables=context).template(trust_as_template(source), escape_backslashes=False)
        write(host, value(args["dest"]), text.encode(), args, value)
        return
    if action == "ansible.builtin.copy":
        dest = value(args["dest"])
        if args.get("force") is False and (dest in host.present or host.content(dest) is not None):
            return
        data = Path(value(args["src"])).read_bytes() if "src" in args else str(value(args["content"])).encode()
        write(host, dest, data, args, value)
        return
    if action == "ansible.builtin.file":
        path = value(args["path"])
        if args["state"] == "directory":
            host.dirs[path] = {
                "owner": str(value(args["owner"])),
                "group": str(value(args["group"])),
                "mode": args["mode"],
            }
        elif args["state"] == "absent" and path in host.present:
            host.removed.append(path)
        return
    if action == "ansible.builtin.stat":
        path = value(args["path"])
        exists = path in host.present or host.content(path) is not None
        variables[task["register"]] = {"stat": {"exists": exists}}
        return
    if action == "ansible.builtin.slurp":
        variables[task["register"]] = {"content": base64.b64encode(host.content(value(args["src"])) or b"").decode()}
        return
    if action == "ansible.builtin.command":
        argv = args.get("argv") if isinstance(args, dict) else None
        if not argv or argv[0] != "python3":
            return
        rendered = [str(value(item)) for item in argv]
        path = rendered[3]
        with tempfile.TemporaryDirectory() as work:
            local = Path(work) / Path(path).name
            if host.content(path) is None:
                return
            local.write_bytes(host.content(path) or b"")
            os.chmod(local, 0o600)
            result = subprocess.run(
                [sys.executable, "-c", rendered[2], str(local), *rendered[4:]],
                capture_output=True,
                text=True,
                check=True,
            )
            data = local.read_bytes()
            if data != host.content(path):
                entry = host.files.get(path, {"owner": "1000", "group": "1000", "mode": "0600"})
                host.files[path] = {**entry, "bytes": data}
        if "register" in task:
            variables[task["register"]] = {"stdout": result.stdout.strip(), "rc": result.returncode}
        return
    raise SystemExit(f"unhandled action {action} in task {task.get('name')}")


def write(host: Host, dest: str, data: bytes, args: dict[str, Any], value: Any) -> None:
    host.files[dest] = {
        "bytes": data,
        "owner": str(value(args.get("owner", "root"))),
        "group": str(value(args.get("group", "root"))),
        "mode": str(value(args.get("mode", "0644"))),
    }


def load_vars(case: Path) -> dict[str, Any]:
    """``vars.json`` with workspace skill sources (``./...``) relative to the case directory."""

    inputs: dict[str, Any] = json.loads((case / "vars.json").read_text())
    for skill in inputs.get("openclaw_workspace_skills", []):
        for item in skill["files"]:
            item["src"] = str((case / item["src"]).resolve())
    return inputs


def generate(case: Path) -> dict[str, Any]:
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    inputs = load_vars(case)
    variables = {key: trusted(item) for key, item in {**defaults, **inputs}.items()}
    existing = json.loads((case / "openclaw.json").read_text()) if (case / "openclaw.json").exists() else None
    present = json.loads((case / "present.json").read_text()) if (case / "present.json").exists() else []
    host = Host(existing, present)
    data_dir = str(Templar(variables=variables).template(trust_as_template("{{ openclaw_data_dir }}")))
    site_dir = str(Templar(variables=variables).template(trust_as_template("{{ openclaw_site_dir }}")))
    config_path = f"{data_dir}/openclaw.json"
    if existing is not None:
        host.existing[config_path] = (case / "openclaw.json").read_bytes()
    for name in TASK_FILES:
        condition = MAIN_WHEN.get(name)
        if condition and not Templar(variables=variables).evaluate_conditional(trust_as_template(condition)):
            continue
        walk(yaml.safe_load((ROLE / "tasks" / name).read_text()), variables, host)
    config = host.content(config_path)
    return {
        "files": {
            path: {
                "sha256": hashlib.sha256(entry["bytes"]).hexdigest(),
                "owner": entry["owner"],
                "group": entry["group"],
                "mode": entry["mode"],
            }
            for path, entry in sorted(host.files.items())
        },
        "directories": dict(sorted(host.dirs.items())),
        "removed": host.removed,
        "undecided": sorted(set(UNDECIDED)),
        "openclaw_json": config.decode() if config is not None else None,
        "env": host.files[f"{site_dir}/.env"]["bytes"].decode(),
    }


if __name__ == "__main__":
    for case in sorted(path for path in HERE.iterdir() if (path / "vars.json").exists()):
        UNDECIDED.clear()
        (case / "expected.json").write_text(json.dumps(generate(case), indent=2, sort_keys=True) + "\n")
        print(f"wrote {case.name}/expected.json")
