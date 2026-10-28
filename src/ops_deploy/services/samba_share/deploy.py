from __future__ import annotations

from pyinfra.api import deploy
from pyinfra.operations import files

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services._samba import deploy as common

from .config import SambaSharesConfig
from .render import render


def validate_secrets(cfg: SambaSharesConfig, secrets: SecretValues | None) -> None:
    common.secret_users(secrets, cfg.users, strict=False)


@deploy("Configure Samba share batch")
def deploy_samba_shares(cfg: SambaSharesConfig, secrets: SecretValues | None = None) -> None:
    credentials = common.secret_users(secrets, cfg.users, strict=False)
    common.prerequisites(cfg)
    if cfg.manage_system_users:
        common.unix_users(cfg.users, cfg.system_group)
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
