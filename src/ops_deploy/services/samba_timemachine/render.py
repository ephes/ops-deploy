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
    """The managed block in [global]: only vfs_fruit's global-only options.

    The share options (vfs objects, metadata, POSIX rename, AppleDouble
    handling) are in the Time Machine snippet (:func:`snippet`), so they do not
    become defaults for every other share on the host.
    """
    return (
        "# macOS/Time Machine compatibility (vfs_fruit global-only options;\n"
        "# the share options are in the Time Machine snippet)\n"
        f"   fruit:model = {cfg.fruit_model}\n"
        "   fruit:nfs_aces = no\n"
    )


def snippet(cfg: SambaTimeMachineConfig) -> str:
    """The Time Machine share snippet: the role template plus the fruit share options."""
    return render(cfg, "smb-timemachine.conf") + (
        "\n"
        "    # macOS compatibility (vfs_fruit share options)\n"
        f"    fruit:metadata = {cfg.fruit_metadata}\n"
        f"    fruit:posix_rename = {'yes' if cfg.fruit_posix_rename else 'no'}\n"
        "    fruit:veto_appledouble = no\n"
        "    fruit:wipe_intentionally_left_blank_rfork = yes\n"
        "    fruit:delete_empty_adfiles = yes\n"
    )
