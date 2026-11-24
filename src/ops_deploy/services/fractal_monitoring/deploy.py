"""Fractal's original alerting roles and cached endpoints, with bounded refresh."""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, Sha256File
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.infra import _monitoring as common
from ops_deploy.infra.mail_relay_client import deploy_mail_relay_client
from ops_deploy.infra.smartd import deploy_smartd
from ops_deploy.infra.zed import deploy_zed
from ops_deploy.services import _metrics_httpd as metrics_httpd

from .config import (
    BackupEndpointConfig,
    FractalMonitoringConfig,
    SchemaRule,
    StorageEndpointConfig,
)
from .render import render

CREDENTIAL_FIELD = "nyxmon_storage_metrics_password"
# The MinIO client the replication lag monitor installed until 307fa27
# (RELEASE.2025-08-13T08-35-41Z, linux-amd64). ``retired_mc_absent`` removes
# exactly this file and refuses anything else at that path.
RETIRED_MC_PATH = "/usr/local/bin/mc"
RETIRED_MC_SHA256 = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
SCRIPT = (Path(__file__).parent / "files/endpoint_host.py").read_text()


def password(secrets: SecretValues) -> str:
    value = secrets.require((CREDENTIAL_FIELD,))[CREDENTIAL_FIELD]
    if value == "CHANGE_ME" or re.search(r"[\x00-\x1f\x7f]", value) or len(value.encode()) > 72:
        raise DeployError(
            "Monitoring endpoint password must be non-placeholder, at most 72 bcrypt bytes without controls"
        )
    return value


@operation()
def reconcile_endpoint(payload: dict[str, Any], credential: SecretStr) -> Generator[StringCommand, None, None]:
    content = json.dumps({**payload, "password": credential.get_secret_value()})
    command = shlex.join(["python3", "-I", "-c", SCRIPT])
    state = probe(command + " check", name="Cached metrics endpoint configuration/auth/refresh state", stdin=content)
    if state == "current":
        host.noop("Cached metrics endpoint is current; no collection")
    elif state == "pending":
        yield StringCommand(command + " apply", _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Cached metrics endpoint state is unknown; mutation refused")


@operation()
def finish_endpoint(
    payload: dict[str, Any], credential: SecretStr, dropin: OperationMeta, inputs: OperationMeta
) -> Generator[StringCommand, None, None]:
    # Planning uses the public potential-change property. Result methods are
    # valid only after execution; a pending resource write also plans the final
    # debt cleanup, without pretending that a planned command already ran.
    force_restart = dropin.did_change() if dropin.is_complete() else dropin.will_change or inputs.will_change
    content = json.dumps({**payload, "password": credential.get_secret_value(), "force_restart": force_restart})
    command = shlex.join(["python3", "-I", "-c", SCRIPT])
    state = probe(command + " finish-check", name="Selected cached HTTP endpoint rollout state", stdin=content)
    if state == "current":
        host.noop("Selected cached HTTP endpoint is current")
    elif state == "pending":
        yield StringCommand(command + " finish", _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Selected HTTP endpoint rollout state is unknown; mutation refused")


@operation()
def endpoint_account(user: str, group: str) -> Generator[StringCommand, None, None]:
    content = json.dumps({"user": user, "group": group})
    command = shlex.join(["python3", "-I", "-c", SCRIPT])
    state = probe(command + " account-check", name="Endpoint account metadata", stdin=content)
    if state == "current":
        host.noop("Endpoint account metadata is current")
    elif state == "pending":
        yield StringCommand(
            command + " account-apply", _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh"
        )
    else:
        raise DeployError("Endpoint account metadata is unknown; no creation/change admitted")


def admit_paths(paths: list[dict[str, Any]]) -> None:
    command = shlex.join(["python3", "-I", "-c", SCRIPT, "admit"])
    answer = probe(command, name="Declared monitoring path metadata admission", stdin=json.dumps({"paths": paths}))
    if answer != "current":
        raise DeployError("Monitoring paths are unavailable/linked/unsafe; no deployment admitted")


def path_row(path: str, kind: str = "file", *, required: bool = False) -> dict[str, Any]:
    return dict(path=path, kind=kind, required=required)


def httpd_endpoint(cfg: StorageEndpointConfig | BackupEndpointConfig) -> metrics_httpd.Endpoint:
    storage = isinstance(cfg, StorageEndpointConfig)
    realm = "storage-metrics" if storage else "backup-metrics"
    sandbox: tuple[str, ...] = ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes")
    if storage:
        sandbox += (f"ReadOnlyPaths={cfg.data_dir}",)
    return metrics_httpd.Endpoint(
        service_name=cfg.service_name,
        argv=(
            "json-file",
            "--bind",
            cfg.bind,
            "--port",
            str(cfg.port),
            "--path",
            cfg.path,
            "--json-path",
            cfg.json_path,
            "--htpasswd-file",
            cfg.htpasswd_path,
            "--realm",
            realm,
            "--server-name",
            realm + "-httpd/0.1",
        ),
        user=cfg.user,
        group=cfg.group,
        sandbox=sandbox,
        python_script=cfg.server_path,
        probe_bind=cfg.bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm=realm,
        ip_address_allow=("localhost", "100.64.0.0/10"),
    )


def deploy_endpoint(
    cfg: StorageEndpointConfig | BackupEndpointConfig,
    rows: list[dict[str, Any]],
    schema: tuple[SchemaRule, ...],
    credential: str,
) -> None:
    if not cfg.enabled:
        return
    debt = f"/var/lib/ops-deploy/fractal-monitoring/{cfg.service_name}-rollout.json"
    paths = [path_row(p, "directory") for p in (cfg.data_dir, cfg.htpasswd_dir, str(PurePosixPath(debt).parent))]
    paths += [
        path_row(p)
        for p in (
            cfg.server_path,
            cfg.htpasswd_path,
            cfg.json_path,
            cfg.json_path + ".tmp",
            debt,
            str(PurePosixPath(debt).parent / "lock"),
            f"/etc/systemd/system/{cfg.service_name}.service",
            f"/etc/systemd/system/{cfg.timer_name}.service",
            f"/etc/systemd/system/{cfg.timer_name}.timer",
        )
    ]
    paths += [path_row(str(row["path"])) for row in rows]
    if isinstance(cfg, StorageEndpointConfig) and not any(row["path"] == cfg.exporter_path for row in rows):
        paths.append(path_row(cfg.exporter_path, required=True))
    admit_paths(paths)
    common.prerequisites(cfg.packages)
    endpoint_account(
        name="Ensure endpoint group/nologin account without home or verifier export", user=cfg.user, group=cfg.group
    )
    for directory in (cfg.data_dir, cfg.htpasswd_dir):
        files.directory(
            name="Ensure monitoring endpoint directory", path=directory, user="root", group=cfg.group, mode="0750"
        )
    storage = isinstance(cfg, StorageEndpointConfig)
    prefix = "storage" if storage else "backup"
    resources = [
        (cfg.server_path, f"{prefix}_metrics_httpd.py", 0o755, dict(restart=True)),
        (
            f"/etc/systemd/system/{cfg.service_name}.service",
            f"{prefix}-metrics-endpoint.service",
            0o644,
            dict(restart=True),
        ),
        (
            f"/etc/systemd/system/{cfg.timer_name}.service",
            f"{prefix}-metrics-collector.service",
            0o644,
            dict(refresh=True),
        ),
        (
            f"/etc/systemd/system/{cfg.timer_name}.timer",
            f"{prefix}-metrics-collector.timer",
            0o644,
            dict(refresh=True, timer=True),
        ),
    ]
    rows = [
        *rows,
        *[
            dict(path=path, content=render(cfg, resource), mode=mode, **flags)
            for path, resource, mode, flags in resources
        ],
    ]
    payload = dict(
        files=rows,
        paths=paths,
        group=cfg.group,
        auth_user=cfg.auth_user,
        htpasswd_path=cfg.htpasswd_path,
        json_path=cfg.json_path,
        freshness_sec=cfg.freshness_sec,
        schema=[rule.model_dump() for rule in schema],
        service=cfg.service_name + ".service",
        timer=cfg.timer_name + ".timer",
        collector=cfg.timer_name + ".service",
        collector_timeout=600,
        debt=debt,
    )
    reconciliation = reconcile_endpoint(
        name=f"Reconcile {prefix} cached resources; gated managed refresh",
        payload=payload,
        credential=SecretStr(credential),
    )
    selection = metrics_httpd.select(
        httpd_endpoint(cfg), cfg, check_when=lambda: reconciliation.did_change(), transient_check_is_mutation=True
    )
    systemd.daemon_reload(name="Reload for monitoring HTTP implementation", _if=any_changed(selection.dropin))
    finish_endpoint(
        name=f"Start/restart selected {prefix} HTTP server once",
        payload=payload,
        credential=SecretStr(credential),
        dropin=selection.dropin,
        inputs=reconciliation,
    )
    metrics_httpd.verify(selection)


def remove_retired_mc() -> None:
    """Remove the lag monitor's pinned ``mc``; a different file at the path is refused."""

    info = host.get_fact(File, path=RETIRED_MC_PATH)
    if info is None:
        host.noop("Retired MinIO client is absent")
        return
    if info is False:
        raise DeployError(f"{RETIRED_MC_PATH} is not a regular file; the retired MinIO client is not removed")
    if host.get_fact(Sha256File, path=RETIRED_MC_PATH) != RETIRED_MC_SHA256:
        raise DeployError(f"{RETIRED_MC_PATH} is not the retired lag monitor's MinIO client; not removed")
    files.file(name="Remove the retired lag monitor's MinIO client", path=RETIRED_MC_PATH, present=False)


@deploy("Fractal cached storage and backup monitoring")
def deploy_fractal_monitoring(cfg: FractalMonitoringConfig, secrets: SecretValues) -> None:
    credential = password(secrets)
    actual = probe("tailscale ip --4", name="Fractal alert relay Tailscale identity")
    if actual is None or actual.strip() != cfg.expected_tailscale_ipv4:
        raise DeployError("Fractal Tailscale identity differs from the declared mail authorization")
    deploy_mail_relay_client(cfg=cfg.relay)
    deploy_smartd(cfg=cfg.smartd)
    deploy_zed(cfg=cfg.zed)
    if cfg.exporter.enabled:
        cache_dir = str(PurePosixPath(cfg.exporter.pool_cache_path).parent)
        admit_paths(
            [path_row(cache_dir, "directory"), path_row(cfg.exporter.pool_cache_path), path_row(cfg.exporter.bin_path)]
        )
        common.prerequisites(cfg.exporter.packages)
        files.directory(
            name="Ensure original exporter pool-cache directory", path=cache_dir, user="root", group="root", mode="0755"
        )
    exporter: dict[str, Any] = dict(
        path=cfg.exporter.bin_path,
        content=render(cfg.exporter, "nyxmon-storage-metrics.py"),
        mode=int(cfg.exporter.mode, 8),
        refresh=True,
    )
    if cfg.exporter.enabled and not cfg.storage.enabled:
        files.put(
            name="Install independently enabled storage exporter",
            src=StringIO(exporter["content"]),
            dest=cfg.exporter.bin_path,
            user="root",
            group="root",
            mode=cfg.exporter.mode,
        )
    deploy_endpoint(cfg.storage, [exporter] if cfg.exporter.enabled else [], cfg.storage_schema, credential)
    backup_rows = [
        dict(
            path=cfg.backup.exporter_path,
            content=render(cfg.backup, "backup_metrics_exporter.py"),
            mode=0o755,
            refresh=True,
        ),
        dict(
            path=cfg.backup.usb_health_module_path,
            content=(Path(__file__).parent / "files/backup_metrics_usb_health.py").read_text(),
            mode=0o644,
            refresh=True,
        ),
    ]
    deploy_endpoint(cfg.backup, backup_rows, cfg.backup_schema, credential)
    if cfg.retired_mc_absent:
        remove_retired_mc()
