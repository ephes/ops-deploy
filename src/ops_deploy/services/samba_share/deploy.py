from __future__ import annotations

import shlex

from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server

from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.services._samba import deploy as common

from .config import SambaShareGroup, SambaSharesConfig
from .render import render


def validate_secrets(cfg: SambaSharesConfig, secrets: SecretValues | None) -> None:
    common.secret_users(secrets, cfg.users, strict=False)


def _group_entries(key: str) -> list[list[str]]:
    # getent exits 2 for "not found"; any other failure fails the probe.
    command = f"getent group {shlex.quote(key)}; rc=$?; [ $rc -eq 0 ] || [ $rc -eq 2 ]"
    output = probe(command, name=f"Unix group {key}")
    if output is None:
        raise DeployError(f"Cannot read the Unix group {key}")
    return [line.split(":") for line in output.splitlines() if line]


def ensure_group(group: SambaShareGroup) -> None:
    """Create ``group`` with its gid, or refuse when the name or the gid is taken otherwise."""

    for row in _group_entries(group.name) + _group_entries(str(group.gid)):
        if row[0] != group.name or row[2:3] != [str(group.gid)]:
            raise DeployError(f"Unix group {group.name} or gid {group.gid} exists with another gid or name")
    server.group(name=f"Ensure share group {group.name}", group=group.name, gid=group.gid, system=True)


@deploy("Configure Samba share batch")
def deploy_samba_shares(cfg: SambaSharesConfig, secrets: SecretValues | None = None) -> None:
    credentials = common.secret_users(secrets, cfg.users, strict=False)
    common.prerequisites(cfg)
    if cfg.manage_system_users:
        common.unix_users(cfg.users, cfg.system_group)
    for group in cfg.groups:
        ensure_group(group)
    for share in cfg.shares:
        if share.path_owner or share.path_group or share.path_mode:
            files.directory(
                name=f"Share {share.name} root metadata only",
                path=share.path,
                user=share.path_owner or None,
                group=share.path_group or None,
                mode=share.path_mode or None,
                recursive=False,
            )
    payload = common.request(
        cfg,
        base=render(cfg, cfg.shares[0], "smb.conf"),
        fragments=[
            {"path": f"{cfg.snippet_dir}/{row.name}.conf", "content": render(cfg, row, "smb-share.conf")}
            for row in cfg.shares
        ],
    )
    common.configure(name="Reconcile share batch with one native candidate validation", payload=payload)
    common.accounts(
        name="Admit missing share accounts only", config=cfg.config_file, names=cfg.users, credentials=credentials
    )
    common.rollout(name="One Samba daemon rollout for the whole share batch", payload=payload)
