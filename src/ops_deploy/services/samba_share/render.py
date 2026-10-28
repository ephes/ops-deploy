from typing import Any

from ops_deploy.services._samba.render import role_render

from .config import SambaShare, SambaSharesConfig


def role_vars(cfg: SambaSharesConfig, share: SambaShare) -> dict[str, Any]:
    values = {"samba_share_" + key: value for key, value in cfg.model_dump().items()}
    values.update({"samba_share_" + key: value for key, value in share.model_dump().items()})
    values["samba_share_snippet_path"] = f"{cfg.snippet_dir}/{share.name}.conf"
    return values


def render(cfg: SambaSharesConfig, share: SambaShare, resource: str) -> str:
    return role_render("samba_share", resource, role_vars(cfg, share))
