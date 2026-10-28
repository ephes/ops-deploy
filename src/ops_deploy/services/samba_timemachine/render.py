from typing import Any

from ops_deploy.services._samba.render import role_render

from .config import SambaTimeMachineConfig


def role_vars(cfg: SambaTimeMachineConfig) -> dict[str, Any]:
    values = {"samba_tm_" + key: value for key, value in cfg.model_dump().items()}
    values["samba_tm_users"] = [{"name": name} for name in cfg.users]
    return values


def render(cfg: SambaTimeMachineConfig, resource: str) -> str:
    return role_render("samba_timemachine", resource, role_vars(cfg))


def fruit_block(cfg: SambaTimeMachineConfig) -> str:
    return (
        "# macOS/Time Machine compatibility (vfs_fruit)\n"
        "   vfs objects = fruit streams_xattr\n"
        f"   fruit:metadata = {cfg.fruit_metadata}\n"
        f"   fruit:model = {cfg.fruit_model}\n"
        f"   fruit:posix_rename = {'yes' if cfg.fruit_posix_rename else 'no'}\n"
        "   fruit:veto_appledouble = no\n"
        "   fruit:nfs_aces = no\n"
        "   fruit:wipe_intentionally_left_blank_rfork = yes\n"
        "   fruit:delete_empty_adfiles = yes\n"
    )
