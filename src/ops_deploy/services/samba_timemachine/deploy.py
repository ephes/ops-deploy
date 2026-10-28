from __future__ import annotations

import shlex

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import Directory
from pyinfra.operations import files, server

from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.services._samba import deploy as common

from .config import SambaTimeMachineConfig
from .render import fruit_block, render


def validate_secrets(cfg: SambaTimeMachineConfig, secrets: SecretValues) -> None:
    common.secret_users(secrets, cfg.users, strict=True)


@deploy("Configure Samba Time Machine")
def deploy_samba_timemachine(cfg: SambaTimeMachineConfig, secrets: SecretValues) -> None:
    credentials = common.secret_users(secrets, cfg.users, strict=True)
    if cfg.required_dataset is not None:
        actual = probe(
            shlex.join(["zfs", "list", "-H", "-o", "name", cfg.required_dataset]),
            name="Required Time Machine dataset metadata",
        )
        if actual != cfg.required_dataset:
            raise DeployError("Required Time Machine dataset must already exist")
    if not host.get_fact(Directory, path=cfg.path):
        raise DeployError("Time Machine directory must already exist; create its dataset separately")
    common.prerequisites(cfg)
    server.group(name="Ensure Time Machine system group", group=cfg.system_group, gid=cfg.system_gid, system=True)
    server.user(
        name="Ensure Time Machine system owner",
        user=cfg.system_user,
        uid=cfg.system_uid,
        group=cfg.system_group,
        home=cfg.path,
        shell="/usr/sbin/nologin",
        system=True,
        create_home=False,
        ensure_home=False,
    )
    files.directory(
        name="Time Machine root metadata only",
        path=cfg.path,
        user=cfg.system_user,
        group=cfg.system_group,
        mode="0770",
        recursive=False,
    )
    if cfg.manage_system_users:
        common.unix_users(cfg.users, cfg.system_group)
    payload = common.request(
        cfg,
        base=render(cfg, "smb.conf"),
        fruit=fruit_block(cfg),
        fragments=[{"path": cfg.snippet_path, "content": render(cfg, "smb-timemachine.conf")}],
    )
    common.configure(name="Reconcile Time Machine config with native candidate validation", payload=payload)
    common.accounts(
        name="Admit missing Time Machine accounts only",
        config=cfg.config_file,
        names=cfg.users,
        credentials=credentials,
    )
    common.rollout(name="One Samba daemon rollout after Time Machine changes", payload=payload)
