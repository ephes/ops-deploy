"""Owned real application qualification; fixture matrix has no inventory access."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import os
import shlex
import sys
import time
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.local import LocalConnector

from ops_deploy.helpers.checks import is_read_only
from ops_deploy.services.homeassistant import HomeAssistantDeployConfig, deploy_homeassistant
from ops_deploy.testing.harness import collect_ops

from .fixture import EVIDENCE, ROOT, VALUES, BoundedLog, PhaseProgress, command, metadata, public_file, sanitize, write

ORIGINAL_LIBRARY_SHA = "0cb32a609d07e342502fce115cd2943b1a412ba7"
PHASES: list[dict[str, Any]] = []
HOME = Path("/home/homeassistant/site")
CONFIG = HOME / "config"
API_URL = "http://127.0.0.1:10020"


@dataclass
class Snapshot:
    public: dict[str, Any]
    private: dict[str, bytes]


def snapshot() -> Snapshot:
    programs = [
        Path("/usr/local/bin/uv"),
        Path("/usr/local/bin/uvx"),
        Path("/etc/systemd/system/homeassistant.service"),
        Path("/etc/systemd/system/matter-server.service"),
        Path("/etc/systemd/system/homeassistant.service.d/50-uv-system-certs.conf"),
        Path("/etc/systemd/system/homeassistant.service.d/99-owned-forbidden.conf"),
        Path("/etc/udev/rules.d/99-homeassistant-zbt1.rules"),
        Path("/etc/traefik/dynamic/homeassistant.yml"),
        HOME / ".python-security-constraints.txt",
        HOME / "bin/llama_cpp_provision.py",
        HOME / ".venv/.ansible-python-version",
        HOME / ".venv-matter-server/.ansible-python-version",
    ]
    component = CONFIG / "custom_components/custom_conversation"
    component_files: dict[str, Any] = {}
    if component.is_dir() and not component.is_symlink():
        for parent, dirs, names in os.walk(component, followlinks=False):
            dirs[:] = [name for name in dirs if name != "__pycache__"]
            for name in ["", *dirs, *names]:
                path = Path(parent) / name
                if path.suffix == ".pyc":
                    continue
                component_files[str(path.relative_to(component))] = public_file(path)
                if len(component_files) > 2048:
                    raise RuntimeError("owned public custom component metadata exceeds bound")
    protected = [CONFIG / "configuration.yaml", CONFIG / "secrets.yaml"]
    private = {str(path): path.read_bytes() for path in protected if path.is_file()}
    units = command(
        "systemctl",
        "show",
        "homeassistant.service",
        "matter-server.service",
        "--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState",
        check=False,
    ).stdout
    packages = command("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Status}\n").stdout.splitlines()
    installed: dict[str, Any] = {}
    for name in (".venv", ".venv-matter-server"):
        python = HOME / name / "bin/python"
        if python.exists():
            result = command(
                str(python),
                "-I",
                "-B",
                "-c",
                'import importlib.metadata,json,platform;print(json.dumps({"python":platform.python_version(),'
                '"packages":sorted((x.metadata["Name"],x.version) for x in importlib.metadata.distributions())}))',
                check=False,
            )
            installed[name] = {"exit": result.returncode}
            if result.returncode == 0:
                installed[name]["distribution"] = json.loads(result.stdout)
    return Snapshot(
        public={
            "programs": {str(path): public_file(path) for path in programs},
            "public_custom_component": component_files,
            "private_file_metadata": {str(path): metadata(path) for path in protected},
            "roots": {str(path): metadata(path) for path in (HOME, CONFIG, HOME / "data", HOME / "logs", HOME / "bin")},
            "units": units,
            "packages": packages,
            "installed": installed,
            "db_metadata_observed_only": {
                str(path): metadata(path)
                for path in (
                    CONFIG / "home-assistant_v2.db",
                    CONFIG / "home-assistant_v2.db-wal",
                    CONFIG / "home-assistant_v2.db-shm",
                )
            },
            "registry_metadata_observed_only": {
                name: metadata(CONFIG / ".storage" / name)
                for name in ("auth", "core.config_entries", "core.area_registry", "assist_pipeline.pipelines")
            },
        },
        private=private,
    )


def snapshot_receipt(label: str, side: str, value: Snapshot) -> dict[str, Any]:
    raw = json.dumps(value.public, sort_keys=True).encode()
    if len(raw) > 20 * 1024 * 1024:
        raise RuntimeError("owned snapshot exceeds bound")
    compressed = gzip.compress(raw, mtime=0)
    name = label + "-" + side + ".json.gz"
    (EVIDENCE / name).write_bytes(compressed)
    return {"file": name, "sha256": hashlib.sha256(compressed).hexdigest(), "raw_size": len(raw)}


def api(action: str, *, token: str = "", command_value: dict[str, Any] | None = None) -> dict[str, Any]:
    # The actual HA interpreter supplies aiohttp. No dev dependencies are added
    # to the immutable controller package or substituted for HA's real client.
    script = Path(__file__).with_name("api.py")
    result = command(
        str(HOME / ".venv/bin/python"),
        "-I",
        "-B",
        str(script),
        stdin=json.dumps({"action": action, "url": API_URL, "token": token, "command": command_value}),
        timeout=130,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("owned API result invalid")
    return value


def wait_http() -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        result = command(
            "curl",
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--max-time",
            "5",
            API_URL + "/manifest.json",
            check=False,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout == "200":
            return
        time.sleep(2)
    raise RuntimeError("owned application did not become ready within180s")


def planned_rows(state: State) -> list[dict[str, Any]]:
    """Stored SDK facts only; never evaluate result callbacks or generators."""
    rows = []
    for operation in state.get_op_order():
        for host in state.inventory.iter_activated_hosts():
            if operation not in state.ops[host]:
                continue
            data = state.get_op_data_for_host(host, operation)
            possible = data.operation_meta._maybe_is_change
            conditional = bool(data.global_arguments["_if"])
            rows.append(
                {
                    "name": ", ".join(sorted(state.get_op_meta(operation).names)),
                    "change": possible is True and not conditional,
                    "conditional_change": possible is True and conditional,
                    "unresolved": possible is None,
                    "has_condition": conditional,
                    "read_only": is_read_only(state, operation),
                }
            )
    return rows


def typed(
    label: str,
    cfg: HomeAssistantDeployConfig,
    *,
    failure: bool = False,
    fish: bool = False,
    plan: bool = False,
    stable: bool = False,
) -> dict[str, Any]:
    progress = PhaseProgress(label)
    before = snapshot()
    before_receipt = snapshot_receipt(label, "before", before)
    write(label + "-started.json", {"before": before_receipt, "plan": plan})
    state = State(Inventory(([("@local", {})], {})), Config())
    state.add_callback_handler(progress.callback())
    uploads: list[bool] = []
    execute_original = LocalConnector.run_shell_command
    put_original = LocalConnector.put_file

    def execute(connector: Any, cmd: Any, **kwargs: Any) -> Any:
        if fish:
            raw = cmd if isinstance(cmd, str) else str(cmd.get_raw_value())
            cmd = "fish -c " + shlex.quote(shlex.join(["sh", "-c", raw]))
        return execute_original(connector, cmd, **kwargs)

    def put(*args: Any, **kwargs: Any) -> Any:
        if plan:
            raise AssertionError("owned planning attempted a file upload")
        uploads.append(True)
        return put_original(*args, **kwargs)

    error = None
    planned: list[dict[str, Any]] = []
    raw_path = ROOT / "private-current-cli.log"
    log = EVIDENCE / (label + ".log")
    with (
        patch.object(LocalConnector, "run_shell_command", execute),
        patch.object(LocalConnector, "put_file", put),
        open(raw_path, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as raw,
        log.open("w") as durable,
        BoundedLog(raw, durable) as stream,
        contextlib.redirect_stdout(stream),
        contextlib.redirect_stderr(stream),
    ):
        try:
            progress.record("connect")
            connect_all(state)
            progress.record("prepare")
            add_deploy(state, deploy_homeassistant, cfg=cfg)
            planned = planned_rows(state)
            if not plan:
                progress.record("execute")
                run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
            progress.record("executor-returned")
    text = raw_path.read_text()
    exposed = any(value and value in text for value in VALUES)
    log.write_text(sanitize(text))
    raw_path.unlink()
    after = snapshot()
    managed = [op.name for op in operations if op.changed and not op.read_only]
    failed = [op.name for op in operations if not op.succeeded] if not plan else []
    stable_fields = ("programs", "public_custom_component", "private_file_metadata", "units", "packages", "installed")
    comparisons = {key: before.public[key] == after.public[key] for key in stable_fields}
    comparisons["private_file_bodies_equal"] = before.private == after.private
    receipt = {
        "label": label,
        "plan": plan,
        "fish": fish,
        "managed": managed,
        "uploads": len(uploads),
        "failed_operations": failed,
        "error": sanitize(error) if error else None,
        "operations": [asdict(op) for op in operations],
        "raw_planned_operations": planned,
        "before": before_receipt,
        "after": snapshot_receipt(label, "after", after),
        "comparisons": comparisons,
        "plaintext_secret_logged": exposed,
        "classification": "expected-owned-fault" if failure else "plan" if plan else "healthy",
        "limitations": "DB/registry/root background metadata observed separately; no globalIO or zero-managed claim",
    }
    write(label + ".json", receipt)
    PHASES.append(
        {key: receipt[key] for key in ("label", "managed", "uploads", "failed_operations", "error", "classification")}
    )
    assert not exposed, label
    assert bool(error or failed) == failure, label
    if stable:
        assert all(comparisons.values()), label
        assert not uploads, label
    if plan:
        assert all(comparisons.values()), label
        assert before.private == after.private, label
        assert not uploads, label
    return receipt


def original(label: str, variables: dict[str, Any]) -> None:
    before = snapshot()
    before_receipt = snapshot_receipt(label, "before", before)
    write(label + "-started.json", {"before": before_receipt})
    path = ROOT / "owned-original.yml"
    play = [
        {
            "hosts": "localhost",
            "gather_facts": True,
            "connection": "local",
            "vars": variables,
            "roles": ["local.ops_library.homeassistant_deploy"],
        }
    ]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(yaml.safe_dump(play))
        result = command(
            "/opt/homeassistant-ansible/bin/ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            str(path),
            timeout=2400,
            check=False,
            env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "collections")},
        )
    finally:
        path.unlink()
    text = result.stdout + result.stderr
    assert len(text.encode()) < 20 * 1024 * 1024
    (EVIDENCE / (label + ".log")).write_text(sanitize(text))
    after = snapshot()
    write(
        label + ".json",
        {
            "exit": result.returncode,
            "before": before_receipt,
            "after": snapshot_receipt(label, "after", after),
            "private_file_bodies_equal": before.private == after.private,
            "plaintext_secret_logged": any(value and value in text for value in VALUES),
        },
    )
    assert result.returncode == 0, label
    assert not any(value and value in text for value in VALUES), label


def admit() -> None:
    assert os.getuid() == 0
    assert os.uname().machine == "x86_64"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    owned = os.environ["HOMEASSISTANT_OWNED_ID"]
    assert Path("/etc/ops-homeassistant-owned-id").read_text().strip() == owned
    assert json.loads(Path("/var/tmp/homeassistant-owned-guest.json").read_text())["run"] == owned
    artifact = json.loads((EVIDENCE / "installed-artifact.json").read_text())
    assert artifact["implementation_sha"] == os.environ["IMPLEMENTATION_SHA"]
    assert artifact["machine_id"] == Path("/etc/machine-id").read_text().strip()
    assert not Path("/home/homeassistant").exists()
    assert (
        command(
            "git", "-C", str(ROOT / "collections/ansible_collections/local/ops_library"), "rev-parse", "HEAD"
        ).stdout.strip()
        == ORIGINAL_LIBRARY_SHA
    )


def main() -> None:
    """Use canonical module state for both direct and module execution."""
    admitted = False
    completed = False
    try:
        admit()
        admitted = True
        from .matrix import run

        run()
        completed = True
    finally:
        if admitted:
            write(
                "summary.json",
                {
                    "completed": completed,
                    "phases": PHASES,
                    "case": os.environ["HOMEASSISTANT_FIXTURE_CASE"],
                    "scope": (
                        "owned real HA / synthetic peers / shared disposableVM kernel; no inventory/hardware proof"
                    ),
                },
            )
    if not completed:
        sys.exit(1)


if __name__ == "__main__":
    from .harness import main as canonical_main

    canonical_main()
