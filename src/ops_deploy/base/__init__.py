"""Host-level base deploys ported from the ops-library base/bootstrap roles.

Each module holds one role: a typed config and a ``@deploy`` function, used on
their own (hostname, unit masks, headless mode, journald, shell basics, authorized keys (whole file or single entries),
the Echoport remote command guard,
SSH guard, dpkg foreign architectures, stale binary restart, unattended upgrades, IPv4 options drop, remote LUKS
unlock, boot-visible i915, external bind storage, default qdisc) or as a
step of a service deploy (uv, Node.js). They are deploys, not shared helpers, so they sit outside the
size-capped helpers/ops/core layer.
"""

from ops_deploy.base._common import RoleConfig
from ops_deploy.base.boot_visible_i915 import BootVisibleI915Config, deploy_boot_visible_i915
from ops_deploy.base.default_qdisc import DefaultQdiscConfig, deploy_default_qdisc
from ops_deploy.base.dpkg_arch_remove import DpkgArchRemoveConfig, deploy_dpkg_arch_remove
from ops_deploy.base.echoport_command_guard import (
    EchoportCommandGuardConfig,
    EchoportGuardConfirmConfig,
    deploy_echoport_command_guard,
    deploy_echoport_command_guard_confirm,
)
from ops_deploy.base.external_bind_storage import (
    BindSource,
    EngineBinds,
    ExternalBindStorageConfig,
    deploy_external_bind_storage,
)
from ops_deploy.base.headless_mode import HeadlessModeConfig, deploy_headless_mode
from ops_deploy.base.hostname import HostnameConfig, deploy_hostname
from ops_deploy.base.ip_options_drop import IpOptionsDropConfig, deploy_ip_options_drop
from ops_deploy.base.journald_config import JournaldConfig, deploy_journald_config
from ops_deploy.base.nodejs_install import NodejsInstallConfig, deploy_nodejs_install
from ops_deploy.base.remote_luks_unlock import RemoteLuksUnlockConfig, deploy_remote_luks_unlock
from ops_deploy.base.shell_basics import ShellBasicsConfig, deploy_shell_basics
from ops_deploy.base.ssh_authorized_key_entries import (
    SshAuthorizedKeyEntriesConfig,
    deploy_ssh_authorized_key_entries,
)
from ops_deploy.base.ssh_authorized_keys import AuthorizedKey, SshAuthorizedKeysConfig, deploy_ssh_authorized_keys
from ops_deploy.base.ssh_guard import SshGuardConfig, deploy_ssh_guard
from ops_deploy.base.stale_exe_restart import (
    StaleExeHttpProbe,
    StaleExeRestartConfig,
    StaleExeUnit,
    deploy_stale_exe_restart,
)
from ops_deploy.base.systemd_unit_masks import SystemdUnitMasksConfig, UnitMask, deploy_systemd_unit_masks
from ops_deploy.base.unattended_upgrades import UnattendedUpgradesConfig, deploy_unattended_upgrades
from ops_deploy.base.uv_install import UvAliasConfig, UvInstallConfig, deploy_uv_install

__all__ = [
    "AuthorizedKey",
    "BindSource",
    "BootVisibleI915Config",
    "DefaultQdiscConfig",
    "DpkgArchRemoveConfig",
    "EchoportCommandGuardConfig",
    "EchoportGuardConfirmConfig",
    "EngineBinds",
    "ExternalBindStorageConfig",
    "HeadlessModeConfig",
    "HostnameConfig",
    "IpOptionsDropConfig",
    "JournaldConfig",
    "NodejsInstallConfig",
    "RemoteLuksUnlockConfig",
    "RoleConfig",
    "ShellBasicsConfig",
    "SshAuthorizedKeyEntriesConfig",
    "SshAuthorizedKeysConfig",
    "SshGuardConfig",
    "StaleExeHttpProbe",
    "StaleExeRestartConfig",
    "StaleExeUnit",
    "SystemdUnitMasksConfig",
    "UnattendedUpgradesConfig",
    "UnitMask",
    "UvAliasConfig",
    "UvInstallConfig",
    "deploy_boot_visible_i915",
    "deploy_default_qdisc",
    "deploy_dpkg_arch_remove",
    "deploy_echoport_command_guard",
    "deploy_echoport_command_guard_confirm",
    "deploy_external_bind_storage",
    "deploy_headless_mode",
    "deploy_hostname",
    "deploy_ip_options_drop",
    "deploy_journald_config",
    "deploy_nodejs_install",
    "deploy_remote_luks_unlock",
    "deploy_shell_basics",
    "deploy_ssh_authorized_key_entries",
    "deploy_ssh_authorized_keys",
    "deploy_ssh_guard",
    "deploy_stale_exe_restart",
    "deploy_systemd_unit_masks",
    "deploy_unattended_upgrades",
    "deploy_uv_install",
]
