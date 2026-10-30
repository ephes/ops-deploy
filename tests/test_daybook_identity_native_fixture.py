"""Refusal boundary for the hosted explicit identity fixture."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("fixture", ["identity", "activation"])
def test_fixture_refuses_local_machine_before_provenance_keys_or_host_work(tmp_path: Path, fixture: str) -> None:
    script = Path(__file__).resolve().parents[1] / f"smoke/daybook_{fixture}_native_fixture.py"
    evidence = tmp_path / "evidence"
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        timeout=20,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
    )
    assert result.returncode != 0
    paths = list(evidence.glob("*.json"))
    assert len(paths) == 1
    receipt = json.loads(paths[0].read_text())
    assert receipt["failure_type"] == "RefusedHost"
    assert "installed_resources" not in receipt
    assert "transport" not in receipt
    assert "phases" not in receipt


def test_activation_receipt_extracts_fixed_codes_from_real_connector_output(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyinfra.connectors.util import CommandOutput, OutputLine

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "smoke"))
    module = importlib.import_module("daybook_activation_native_fixture")
    code = "weeknotes_activation_enabled_bootstrap_failed"
    report = json.dumps({"schema_version": 1, "status": "failed", "reason_code": code})
    output = CommandOutput([OutputLine("stdout", "OWNED unrelated"), OutputLine("stderr", report)])
    assert module.content_free_reasons(output) == [code]
    assert module.content_free_reasons([("stderr", report)]) == [code]
    assert module.content_free_reasons([report]) == [code]
    assert module.content_free_reasons([json.dumps({"reason_code": code, "private": "synthetic"})]) == []
    with pytest.raises(AssertionError):
        module.content_free_reasons(CommandOutput([OutputLine("stderr", "PRIVATE_SYNTHETIC_UNTRUSTED_BODY")]))
