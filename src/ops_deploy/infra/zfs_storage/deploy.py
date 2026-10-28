"""Native declared ZFS pools/datasets; all key material travels on private stdin."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator, Mapping
from io import StringIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import SecretStr
from pyinfra import host, logger
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.operations import apt, files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.helpers.probes import StdinLines, probe, verify_probe

from .config import ZfsDatasetConfig, ZfsPoolConfig, ZfsStorageConfig

SCRIPT = (Path(__file__).parents[1] / "files/zfs_storage.py").read_text()
ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def command(action: str) -> str:
    return shlex.join(["python3", "-I", "-B", "-c", SCRIPT, action])


def pool_payload(cfg: ZfsPoolConfig, credential: SecretStr | None) -> dict[str, object]:
    value = "" if credential is None else credential.get_secret_value()
    if cfg.encryption_enabled:
        raw = value.encode()
        valid = (
            len(raw) == 32 if cfg.keyformat == "raw" else (8 <= len(raw.split(b"\n", 1)[0]) <= 512 and b"\0" not in raw)
        )
        if not valid or value == "CHANGEME":
            raise DeployError("Native encryption requires valid non-placeholder source key material; value suppressed")
    result = cfg.model_dump(mode="json")
    result.update(
        keyfile_path=cfg.resolved_keyfile,
        mountpoint=cfg.resolved_mountpoint,
        unlock_service_name=cfg.resolved_unlock_unit,
        credential=value,
    )
    return result


def dataset_payload(cfg: ZfsDatasetConfig) -> dict[str, object]:
    return {**cfg.model_dump(mode="json"), "effective_properties": cfg.effective_properties}


@operation()
def native_module() -> Generator[StringCommand, None, None]:
    answer = probe(command("module-check"), name="Native ZFS loaded-module metadata", stdin="{}")
    if answer == "current":
        host.noop("Native ZFS module already loaded")
    elif answer == "pending":
        yield StringCommand("modprobe", "zfs")
    else:
        raise DeployError("Native module metadata unavailable; no module/storage command admitted")


@operation()
def reconcile(data: SecretStr, kind: str) -> Generator[StringCommand, None, None]:
    content = data.get_secret_value()
    answer = probe(command(kind + "-check"), name="Declared native storage and source-key validation", stdin=content)
    try:
        value = json.loads(answer) if answer is not None else None
    except (ValueError, TypeError):
        raise DeployError("Native storage state unavailable; no writes admitted") from None
    if not isinstance(value, dict) or type(value.get("pending")) is not bool:
        raise DeployError("Native storage returned unknown state; no writes admitted")
    if value.get("casesensitivity_mismatch"):
        logger.warning(
            f"{host.print_prefix}Existing dataset casesensitivity differs from original macOS creation policy; "
            "never recreate."
        )
    if value["pending"]:
        yield StringCommand(
            command(kind + "-apply"), _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh"
        )
    else:
        host.noop("Declared native storage is current (or original validation-only); no storage mutation")


def render_unlock(cfg: ZfsPoolConfig) -> str:
    return ENV.get_template("zfs-unlock-pool.service.j2").render(
        ansible_managed="Ansible managed", zfs_pool_name=cfg.name, zfs_pool_keyfile_path=cfg.resolved_keyfile
    )


@deploy("Deploy declared ZFS pool")
def deploy_zfs_pool(cfg: ZfsPoolConfig, credential: SecretStr | None = None) -> None:
    data = SecretStr(json.dumps(pool_payload(cfg, credential)))
    require_linux("zfs_pool_deploy")
    require_systemd("zfs_pool_deploy")
    apt.packages(
        name="Ensure original native ZFS packages/cache policy",
        packages=list(cfg.packages),
        update=True,
        cache_time=3600,
    )
    native_module(name="Ensure original ZFS module is loaded")
    reconcile(name="Validate source key before publishing; converge original pool properties", data=data, kind="pool")
    if (
        cfg.encryption_enabled
        and cfg.configure_boot_unlock
        and cfg.keylocation_type == "file"
        and not cfg.validate_only
    ):
        unit = files.put(
            name="Original boot unlock unit",
            src=StringIO(render_unlock(cfg)),
            dest="/etc/systemd/system/" + cfg.resolved_unlock_unit + ".service",
            user="root",
            group="root",
            mode="0644",
        )
        systemd.daemon_reload(name="Reload only changed original unlock unit", _if=any_changed(unit))
        systemd.service(
            name="Enable/start original unlock lifecycle; never restart/unload during deploy",
            service=cfg.resolved_unlock_unit,
            enabled=True,
            running=True,
        )


@deploy("Deploy declared ZFS dataset")
def deploy_zfs_dataset(cfg: ZfsDatasetConfig, *, parent_pool: ZfsPoolConfig | None = None) -> None:
    """Deploy one filesystem; parent_pool declares an earlier explicit pool creation.

    A genuinely absent declared parent may be deferred during planning only.
    Execution still requires the actual parent, so a failed predecessor never
    turns into an implicit pool creation or a dataset create with ``-p``.
    """
    data = dataset_payload(cfg)
    if parent_pool is not None:
        if parent_pool.name != cfg.name.split("/")[0] or not parent_pool.allow_create or parent_pool.validate_only:
            raise DeployError("Dataset's declared creation predecessor must be its exact deployable parent pool")
        data.update(planned_parent=parent_pool.name, parent_packages=list(parent_pool.packages))
    require_linux("zfs_dataset")
    reconcile(
        name="Converge original filesystem properties/mount without recreation",
        data=SecretStr(json.dumps(data)),
        kind="dataset",
    )


@deploy("Deploy original declared storage bundle")
def deploy_zfs_storage(cfg: ZfsStorageConfig, credentials: Mapping[str, SecretStr]) -> None:
    # Validate every requested source key before declaring any operation. The
    # source pool's real native verification still precedes its key publication.
    for pool in cfg.pools:
        pool_payload(pool, credentials.get(pool.name))
    parents = {pool.name: pool for pool in cfg.pools}
    for pool in cfg.pools:
        deploy_zfs_pool(cfg=pool, credential=credentials.get(pool.name))
    for dataset in cfg.ordered_datasets:
        parent = parents[dataset.name.split("/")[0]]
        deploy_zfs_dataset(
            cfg=dataset, parent_pool=parent if parent.allow_create and not parent.validate_only else None
        )
    payload = {
        "pools": [pool_payload(p, credentials.get(p.name)) for p in cfg.pools],
        "datasets": [dataset_payload(d) for d in cfg.ordered_datasets],
    }
    verify_probe(
        command("verify"),
        name="Original selected storage properties/source-key equality",
        expect="current",
        stdin=json.dumps(payload),
    )
