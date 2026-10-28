"""Fractal-specific two-row Nyxmon semantics, kept separate from generic upsert."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from pyinfra.api import DeployError, deploy

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe
from ops_deploy.ops import secret_stdin
from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck

from .config import FractalMonitoringChecksConfig
from .deploy import SCRIPT as ENDPOINT_SCRIPT
from .deploy import password

SCRIPT = (Path(__file__).parent / "files/nyxmon_check.py").read_text()


@deploy("Fractal's original two Nyxmon checks")
def deploy_fractal_monitoring_checks(cfg: FractalMonitoringChecksConfig, secrets: SecretValues) -> None:
    credential = password(secrets)
    actual = probe("tailscale ip -4", name="Authorized Fractal alert relay backend identity")
    if actual is None or actual.strip() != cfg.expected_relay_ipv4:
        raise DeployError("Relay backend Tailscale identity differs from the declared Fractal trust")
    # Validate both cache-only endpoints before either SQLite row is updated.
    for check, schema in zip(cfg.checks, (cfg.storage_schema, cfg.backup_schema), strict=True):
        payload = dict(
            url=check.url,
            username=check.auth_username,
            password=credential,
            schema=[rule.model_dump() for rule in schema],
            timeout=cfg.endpoint_timeout,
        )
        mark_read_only(
            secret_stdin(
                name=f"Require fresh compatible cached endpoint for {check.name}",
                command=shlex.join(["python3", "-I", "-c", ENDPOINT_SCRIPT, "http"]),
                content=SecretContent(json.dumps(payload)),
            )
        )
    for check in cfg.checks:
        upsert_fractal_check(check, credential)


def upsert_fractal_check(check: JsonMetricsCheck, credential: str) -> None:
    """One original Fractal SQL row; the composite validates HTTP endpoints first."""
    if (
        check.name not in {"Fractal Storage", "Fractal Backup"}
        or check.service_name != "fractal"
        or check.check_interval != 300
    ):
        raise DeployError("Fractal check helper refuses a different row identity")
    data = check.desired_data(credential)
    suppression = data.get("notification_suppression")
    if isinstance(suppression, dict):
        suppression["auth"] = {"username": check.auth_username, "password": credential}
    content = json.dumps(data)
    command = ["runuser", "-u", check.user, "--", "python3", "-I", "-c", SCRIPT]
    state = probe(
        shlex.join([*command, "check", str(check.db_path), check.name]),
        name=f"Fractal-specific Nyxmon row {check.name}",
        stdin=content,
    )
    if state == "current":
        return
    if state != "pending":
        raise DeployError("Fractal Nyxmon row state is unknown; no update admitted")
    secret_stdin(
        name=f"Upsert original Fractal Nyxmon row {check.name}",
        command=shlex.join([*command, "apply", str(check.db_path), check.name]),
        content=SecretContent(content),
    )
