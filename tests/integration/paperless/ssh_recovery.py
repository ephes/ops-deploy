"""Complete only an observed lost original SSH handler in the owned fixture."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import yaml

from tests.integration.paperless.application_matrix import scanner_sftp, sftp_diagnostic

DROPIN = "/etc/ssh/sshd_config.d/sftp-scanner.conf"
HANDLER = {"name": "restart ssh", "ansible.builtin.systemd": {"name": "ssh", "state": "restarted", "enabled": True}}


def admit_lost_handler(
    before: dict[str, Any], after: dict[str, Any], current: dict[str, Any], prepared: dict[str, Any], log: str
) -> None:
    assert before["files"][DROPIN] is None, "scanner drop-in was not newly created by the failed original run"
    info = after["files"][DROPIN]
    assert stat.S_ISREG(info["mode"])
    assert (stat.S_IMODE(info["mode"]), info["uid"], info["gid"]) == (0o644, 0, 0)
    assert info == current["files"][DROPIN]
    assert after["public_program_hashes"][DROPIN] == current["public_program_hashes"][DROPIN]
    assert before["units"]["ssh"] == after["units"]["ssh"] == current["units"]["ssh"]
    fields = dict(line.split("=", 1) for line in current["units"]["ssh"].splitlines())
    assert fields["ActiveState"] == "active"
    assert fields["MainPID"] == prepared["after"]["unit"]["MainPID"]
    assert fields["MainPID"].isdigit()
    assert int(fields["MainPID"]) > 0
    assert "RUNNING HANDLER [local.ops_library.paperless_deploy : restart ssh]" not in log
    assert "TASK [local.ops_library.paperless_deploy : Deploy scanner SSH configuration]" in log


def recorded_snapshot(harness: Any, proof: dict[str, Any]) -> dict[str, Any]:
    name = proof["file"]
    assert Path(name).name == name
    assert name.endswith(".json.gz")
    body = (harness.EVIDENCE / name).read_bytes()
    assert hashlib.sha256(body).hexdigest() == proof["sha256"]
    raw = gzip.decompress(body)
    assert len(raw) == proof["raw_size"]
    return dict(json.loads(raw))


def complete_pending_handler(harness: Any) -> None:
    assert harness.OWNED_ADMITTED
    harness.write("owned-ssh-pretyped-diagnostic.json", sftp_diagnostic(harness))
    probe = scanner_sftp(harness, "pwd\n", "owned-ssh-before-handler")
    if probe.returncode == 0:
        harness.write("owned-ssh-pending-handler.json", {"required": False, "probe_exit": 0})
        return
    # Other authentication, network and path failures remain failures. Retain
    # exact output first; never turn a generic SSH error into a restart request.
    assert probe.returncode == 255
    lines = [line.strip() for line in probe.stderr.splitlines() if not line.startswith("Warning: Permanently added ")]
    assert lines == ["Connection closed"]
    prerequisite = json.loads((harness.EVIDENCE / "owned-original-index-prerequisite-started.json").read_text())
    label = prerequisite["failed_original"]
    assert label in {"00-original-install", "00b-original-install-after-fixture-cache-recovery"}
    failed = json.loads((harness.EVIDENCE / (label + ".json")).read_text())
    assert failed["exit"] != 0
    before_original = recorded_snapshot(harness, failed["before"])
    after_original = recorded_snapshot(harness, failed["after"])
    log = (harness.EVIDENCE / (label + ".log")).read_text()
    prepared = json.loads((harness.EVIDENCE / "owned-ssh-prerequisite.json").read_text())
    before = harness.snapshot()
    admit_lost_handler(before_original, after_original, before.public, prepared, log)
    source = harness.LIBRARY / "roles/paperless_deploy/handlers/main.yml"
    handlers = [item for item in yaml.safe_load(source.read_text()) if item.get("name") == "restart ssh"]
    assert handlers == [HANDLER]
    classification = "explicit owned completion of lost original restart+enable SSH handler; not pristine bootstrap"
    harness.write(
        "owned-ssh-pending-handler-started.json",
        {
            "classification": classification,
            "failed_original": label,
            "handler_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "handler": HANDLER,
            "before": harness.snapshot_receipt("owned-ssh-pending-handler", "before", before),
        },
    )
    path = harness.ROOT / "owned-pending-ssh-handler.yml"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            yaml.safe_dump(
                [{"hosts": "localhost", "gather_facts": False, "connection": "local", "tasks": handlers}], stream
            )
        result = harness.command(
            "/opt/paperless-ansible/bin/ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            str(path),
            timeout=90,
            check=False,
        )
        harness.write(
            "owned-ssh-pending-handler-result.json",
            {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )
    finally:
        path.unlink()
    after = harness.snapshot()
    comparable = json.loads(json.dumps(after.public))
    comparable["units"]["ssh"] = before.public["units"]["ssh"]
    fields = dict(line.split("=", 1) for line in after.public["units"]["ssh"].splitlines())
    old = dict(line.split("=", 1) for line in before.public["units"]["ssh"].splitlines())
    receipt = {
        "required": True,
        "classification": classification,
        "handler_exit": result.returncode,
        "after": harness.snapshot_receipt("owned-ssh-pending-handler", "after", after),
        "only_ssh_unit_changed": comparable == before.public,
        "private_content_equal": before.private == after.private,
        "new_ssh_pid": fields["MainPID"] != old["MainPID"],
        "ssh_active_enabled": fields["ActiveState"] == "active" and fields["UnitFileState"] == "enabled",
    }
    harness.write("owned-ssh-pending-handler.json", receipt)
    assert result.returncode == 0
    assert all(
        receipt[key] for key in ("only_ssh_unit_changed", "private_content_equal", "new_ssh_pid", "ssh_active_enabled")
    )
    probe = scanner_sftp(harness, "pwd\n", "owned-ssh-after-handler")
    assert probe.returncode == 0, "SFTP still failed after source-bound pending-handler completion"
