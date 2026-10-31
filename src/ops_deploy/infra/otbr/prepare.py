"""Pure original rendering, build triggers and explicit source effect map."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Any

import jinja2

from ops_deploy.infra.otbr.config import OtbrConfig


def resolved_interfaces(cfg: OtbrConfig, default_ipv4_interface: str | None = None) -> OtbrConfig:
    infra = cfg.infra_interface or default_ipv4_interface
    if not infra:
        raise ValueError("Set infra_interface or establish the original default IPv4 interface")
    # model_copy does not validate updates; validate the resolved mapping again.
    return OtbrConfig.model_validate(
        {
            **cfg.model_dump(),
            "infra_interface": infra,
            "backbone_interface": infra if cfg.backbone_interface is None else cfg.backbone_interface,
        }
    )


def build_values(cfg: OtbrConfig) -> dict[str, str]:
    return {
        "REST_API": str(int(cfg.rest_api_enabled)),
        "WEB_GUI": str(int(cfg.web_enabled)),
        "OTBR_MDNS": cfg.mdns,
        "OTBR_DHCP6_PD_CLIENT": cfg.dhcp6_pd_client,
        "BACKBONE_ROUTER": str(int(cfg.backbone_router)),
        "BORDER_ROUTING": str(int(cfg.border_routing)),
        "NAT64": str(int(cfg.nat64)),
        "DISCOVERY_PROXY": str(int(cfg.discovery_proxy)),
        "FIREWALL": str(int(cfg.firewall)),
        "INFRA_IF_NAME": cfg.infra_interface,
        "OTBR_OPTIONS": cfg.build_options,
    }


def build_record(cfg: OtbrConfig) -> str:
    return "".join(f"{key}={value}\n" for key, value in build_values(cfg).items())


def build_environment(cfg: OtbrConfig) -> dict[str, str]:
    return dict(cfg.build_env) if cfg.build_env is not None else build_values(cfg)


@cache
def _templates() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.infra.otbr", "templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
    )
    env.filters["ternary"] = lambda value, yes, no: yes if value else no
    return env


def render(cfg: OtbrConfig, name: str) -> str:
    return _templates().get_template(name).render(**{"otbr_" + key: value for key, value in cfg.model_dump().items()})


@dataclass(frozen=True)
class BuildEffects:
    source_changed: bool
    bootstrap: bool
    setup: bool
    publish_build_record: bool
    restart_agent_after_setup: bool
    restart_web_after_setup: bool


def build_effects(
    cfg: OtbrConfig, *, source_changed: bool, marker_exists: bool, agent_exists: bool, record_current: bool
) -> BuildEffects:
    setup = cfg.force_rebuild or source_changed or not record_current or not agent_exists
    restart = setup and cfg.restart_on_change and cfg.service_state == "started"
    return BuildEffects(
        source_changed,
        cfg.force_bootstrap or source_changed or not marker_exists,
        setup,
        setup,
        restart,
        restart and cfg.web_enabled,
    )


def source_effect_map(cfg: OtbrConfig, source: dict[str, Any], effects: BuildEffects) -> dict[str, Any]:
    """A later live-window proposal must use a fresh resolved upstream source.

    No installed-ref substitution: moving main can rebuild, restart and modify
    the radio/network stack. The returned source fields contain commit metadata.
    """
    return {
        "installed_commit": source.get("before"),
        "resolved_commit": source.get("resolved"),
        "resolution_pending_git_fetch": source.get("resolution_pending_git_fetch", False),
        "source_changed": effects.source_changed,
        "bootstrap": effects.bootstrap,
        "setup": effects.setup,
        "restart_agent_after_setup": effects.restart_agent_after_setup,
        "restart_web_after_setup": effects.restart_web_after_setup,
        "may_manage_prerequisite_packages": cfg.manage_packages,
        "may_install_original_os_apt_dependency": cfg.manage_packages,
        "may_update_apt_cache": cfg.manage_packages,
        "may_remove_bind": cfg.remove_bind,
        "may_purge_bind_packages": cfg.remove_bind and cfg.manage_packages,
        "udev_rule_managed": cfg.manage_udev,
        "source_ref_is_installed_mask": False,
    }
