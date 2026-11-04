"""OpenClaw removal: the ``openclaw_remove`` role's steps, planned from what the host has.

``files/remove_defaults.yml`` is the role's ``defaults/main.yml``; the
playbook sets ``openclaw_data_dir``. Removal needs ``confirm``; data, image
and account removal stay opt-in and the Traefik route goes by default, as in
the role. Best-effort steps (the compose ``down``, container and image
removal) never fail the removal. Like the role, the metrics endpoint units
are left in place. The role's ``reload traefik`` handler is not ported
(Traefik's file provider drops the route by itself); the route file is
removed only while no Traefik transaction holds its lock.
"""

from __future__ import annotations

import shlex
from typing import Any

from pydantic import Field, JsonValue, field_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server, systemd

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.services._lifecycle import exists, remove_account, remove_path, stop_disable
from ops_deploy.services.openclaw.variables import ansible_bool, defaults, resolve

FLAGS = ("confirm", "data", "image", "user", "traefik_config", "site_dir", "build_dir", "log_dir")


class OpenClawRemoveConfig(RoleConfig):
    """The removal toggles (``openclaw_remove_*`` of the role) and its other variables."""

    confirm: bool = False
    data: bool = False
    image: bool = False
    user: bool = False
    traefik_config: bool = True
    site_dir: bool = True
    build_dir: bool = True
    log_dir: bool = True
    variables: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("variables")
    @classmethod
    def _role_names(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - set(defaults("remove")))
        toggles = sorted(name for name in value if name.startswith("openclaw_remove_"))
        if unknown or toggles:
            raise ValueError(f"not settable here: {', '.join(unknown + toggles)}")
        return value

    def role_variables(self) -> dict[str, Any]:
        toggles = {f"openclaw_remove_{name}": getattr(self, name) for name in FLAGS}
        return resolve({**self.variables, **toggles}, role="remove")


@deploy("Remove OpenClaw")
def deploy_openclaw_remove(cfg: OpenClawRemoveConfig) -> None:
    v = cfg.role_variables()
    if not ansible_bool(v["openclaw_remove_confirm"]):
        raise DeployError(
            "Set openclaw_remove_confirm=true to allow removal. Data deletion is opt-in via openclaw_remove_data=true."
        )
    unit = f"{v['openclaw_service_name']}.service"
    stop_disable([unit])
    if remove_path(v["openclaw_systemd_unit_path"]):
        systemd.daemon_reload(name="Reload systemd after removing the OpenClaw unit")
    remove_path(v["openclaw_logrotate_path"])
    compose = v["openclaw_compose_path"]
    if exists(compose):
        server.shell(
            name="Remove OpenClaw compose stack (best effort)",
            commands=[f"/usr/bin/docker compose -f {shlex.quote(compose)} down --remove-orphans || true"],
        )
    for container in (v["openclaw_container_name"], v["openclaw_cli_container_name"]):
        if output(f"docker container inspect {shlex.quote(container)} >/dev/null && echo present").strip() == "present":
            server.shell(
                name=f"Remove container {container} (best effort)",
                commands=[f"docker container rm -f {shlex.quote(container)} || true"],
            )
    if ansible_bool(v["openclaw_remove_image"]):
        reference = shlex.quote(f"reference={v['openclaw_image_name']}:*")
        ids = list(
            dict.fromkeys(line for line in output(f"docker images --filter={reference} --quiet").split() if line)
        )
        for image_id in ids:
            server.shell(
                name=f"Remove image {image_id} (best effort)",
                commands=[f"docker image rm {shlex.quote(image_id)} || true"],
            )
    remove_path(compose)
    for toggle, key in (
        ("site_dir", "openclaw_site_dir"),
        ("build_dir", "openclaw_build_dir"),
        ("log_dir", "openclaw_log_dir"),
    ):
        if ansible_bool(v[f"openclaw_remove_{toggle}"]):
            remove_path(v[key])
    if ansible_bool(v["openclaw_remove_traefik_config"]):
        remove_path(v["openclaw_traefik_config_path"])
    if ansible_bool(v["openclaw_remove_data"]):
        remove_path(v["openclaw_data_dir"])
    if ansible_bool(v["openclaw_remove_user"]):
        remove_account(v["openclaw_user"], v["openclaw_group"])
    logger.info(
        f"{host.name}: OpenClaw removal planned (data={cfg.data}, image={cfg.image}, "
        f"traefik config={cfg.traefik_config}, user/group={cfg.user})"
    )
