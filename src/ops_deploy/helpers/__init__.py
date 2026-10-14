"""Deploy-level helpers that replace the shared parts of the Ansible roles.

Each helper is a plain function called inside a ``@deploy``; it adds pyinfra
operations and returns their ``OperationMeta`` so callers can gate later steps
on change (``when_changed=...``, ``restart_when=...``).
"""

from ops_deploy.helpers.checks import http_check, is_read_only, mark_read_only, wait_port
from ops_deploy.helpers.python import django_manage, uv_sync
from ops_deploy.helpers.systemd import Rollout, service_rollout, systemd_unit
from ops_deploy.helpers.traefik import BasicAuth, HealthCheck, RedirectRegex, TraefikRoute, traefik_route
from ops_deploy.helpers.users import SystemUser, system_user

__all__ = [
    "BasicAuth",
    "HealthCheck",
    "RedirectRegex",
    "Rollout",
    "SystemUser",
    "TraefikRoute",
    "django_manage",
    "http_check",
    "is_read_only",
    "mark_read_only",
    "service_rollout",
    "system_user",
    "systemd_unit",
    "traefik_route",
    "uv_sync",
    "wait_port",
]
