"""Host-level base deploys ported from the ops-library base/bootstrap roles.

Each module holds one role: a typed config and a ``@deploy`` function, used on
their own (hostname, unit masks, headless mode, journald, shell basics, authorized keys)
or as a step of a service deploy (uv, Node.js). They are deploys, not shared
helpers, so they sit outside the size-capped helpers/ops/core layer.
"""

from ops_deploy.base._common import RoleConfig
from ops_deploy.base.headless_mode import HeadlessModeConfig, deploy_headless_mode
from ops_deploy.base.hostname import HostnameConfig, deploy_hostname
from ops_deploy.base.journald_config import JournaldConfig, deploy_journald_config
from ops_deploy.base.nodejs_install import NodejsInstallConfig, deploy_nodejs_install
from ops_deploy.base.shell_basics import ShellBasicsConfig, deploy_shell_basics
from ops_deploy.base.ssh_authorized_keys import AuthorizedKey, SshAuthorizedKeysConfig, deploy_ssh_authorized_keys
from ops_deploy.base.systemd_unit_masks import SystemdUnitMasksConfig, UnitMask, deploy_systemd_unit_masks
from ops_deploy.base.uv_install import UvInstallConfig, deploy_uv_install

__all__ = [
    "AuthorizedKey",
    "HeadlessModeConfig",
    "HostnameConfig",
    "JournaldConfig",
    "NodejsInstallConfig",
    "RoleConfig",
    "ShellBasicsConfig",
    "SshAuthorizedKeysConfig",
    "SystemdUnitMasksConfig",
    "UnitMask",
    "UvInstallConfig",
    "deploy_headless_mode",
    "deploy_hostname",
    "deploy_journald_config",
    "deploy_nodejs_install",
    "deploy_shell_basics",
    "deploy_ssh_authorized_keys",
    "deploy_systemd_unit_masks",
    "deploy_uv_install",
]
