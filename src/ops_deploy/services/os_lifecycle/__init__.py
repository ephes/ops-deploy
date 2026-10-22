"""OS lifecycle: a per-host status report (EOL horizon, security updates, reboot), its exposure, Nyxmon checks."""

from ops_deploy.services.os_lifecycle.checks import (
    Thresholds,
    endpoint_rules,
    lifecycle_check,
    remote_rules,
    report_rules,
)
from ops_deploy.services.os_lifecycle.deploy import (
    PASSWORD_KEY,
    PRIVATE_KEY_KEY,
    EolSnapshot,
    OsLifecycleChecksConfig,
    OsLifecycleConfig,
    RemoteHost,
    RemotePull,
    SshReport,
    deploy_os_lifecycle,
    deploy_os_lifecycle_checks,
)

__all__ = [
    "PASSWORD_KEY",
    "PRIVATE_KEY_KEY",
    "EolSnapshot",
    "OsLifecycleChecksConfig",
    "OsLifecycleConfig",
    "RemoteHost",
    "RemotePull",
    "SshReport",
    "Thresholds",
    "deploy_os_lifecycle",
    "deploy_os_lifecycle_checks",
    "endpoint_rules",
    "lifecycle_check",
    "remote_rules",
    "report_rules",
]
