"""Run the actual encoded host command/stdin through Bash and available fish."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.services.paperless.commands import host_command, index_payload, scanner_password_payload
from ops_deploy.services.paperless.config import PaperlessConfig, PaperlessCredentials
from ops_deploy.services.paperless.index_contract import expected_index_sentinels


@pytest.mark.parametrize("shell", ["bash", "fish"])
def test_actual_metadata_command_and_stdin(shell: str, tmp_path: Path) -> None:
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} is unavailable; caller/native qualification must record actual shell coverage")
    index = tmp_path / "data/index"
    index.mkdir(parents=True)
    (index / ".index_settings.json").write_text(json.dumps(expected_index_sentinels("3.2.1", "eng+deu")))
    (index / "meta.json").write_text(json.dumps({"segments": []}))
    cfg = PaperlessConfig(traefik_domain="home.example.test", external_storage_root=str(tmp_path))
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in index.iterdir()}
    result = subprocess.run(
        [executable, "-c", host_command("index_state")],
        input=index_payload(cfg, 0),
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(result.stdout) == {"reindex": False, "reasons": [], "document_count": 0, "indexed_count": 0}
    assert result.stderr == ""
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in index.iterdir()} == before


def test_force_config_reaches_index_decision() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test", force_reindex=True)
    assert json.loads(index_payload(cfg, 0, ("release",)))["triggers"] == ["release", "force"]


def test_scanner_secret_payload_is_protected_stdin_only() -> None:
    secret = "synthetic;stdin-only"
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    credentials = PaperlessCredentials.model_validate(
        {
            "secret_key": "synthetic-key-" * 5,
            "postgres_password": "synthetic-db",
            "admin_password": "synthetic-admin",
            "scanner_password": secret,
        }
    )
    payload = scanner_password_payload(cfg, credentials, apply=False)
    arguments = stdin_arguments(payload)
    assert secret not in host_command("scanner_password")
    assert secret not in repr(arguments)
    assert json.loads("".join(arguments["_stdin"]))["password"] == secret
    assert arguments["_get_pty"] is False


def test_only_declared_host_resources_are_available() -> None:
    with pytest.raises(ValueError, match="unknown"):
        host_command("../../unrelated")
