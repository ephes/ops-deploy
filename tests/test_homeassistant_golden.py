"""Home Assistant's host files stay byte for byte what hosts have today.

The goldens were recorded from the deploy when it still rendered exactly what
the retired ``homeassistant_deploy`` role wrote (synthetic inputs only): the
two units, ``configuration.yaml``, ``secrets.yaml``, the include files, the
Traefik route, the uv system-certificates drop-in and the udev rule. A change
to any of them rewrites the file on the next deploy (and restarts Home
Assistant or Matter); see ``tests/goldens.py`` for recording an intended one.
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.resources import files
from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.services.homeassistant.configuration_render import (
    ConfigurationSecrets,
    ConfigurationValues,
    render_configuration,
    render_include,
    render_secrets,
)
from ops_deploy.services.homeassistant.ingress import HomeAssistantIngressConfig, render_ingress
from ops_deploy.services.homeassistant.render import render_unit
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.services.homeassistant.trust import dropin_text
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "homeassistant"

CUSTOM_RUNTIME = HomeAssistantRuntimeConfig(
    user="ha_test",
    site_path="/srv/ha",
    matter_server_service_name="matter-test",
    matter_server_log_file="",
)
OWNED_RUNTIME = HomeAssistantRuntimeConfig(config_path="/srv/owned-config", data_path="/srv/owned-data")
# The UniFi host default is a LAN address; the goldens use a documentation address.
DEFAULT_VALUES = ConfigurationValues(unifi_host="192.0.2.94")
CUSTOM_VALUES = ConfigurationValues(
    unifi_host="192.0.2.94",
    external_url="https://ha.example.test",
    internal_url="http://owned:8123",
    latitude=51.2,
    longitude=-1.4,
    elevation=23,
    trusted_proxies=("192.0.2.3",),
    logger_logs={"owned.second": "error", "owned.first": "debug"},
    db_url=SecretStr("postgresql://owned:synthetic@localhost/fixture"),
)
INCLUDES = (
    "automations.yaml",
    "scripts.yaml",
    "scenes.yaml",
    "groups.yaml",
    "persons.yaml",
    "presence_automations.yaml",
)


def ingress(resolver: str) -> HomeAssistantIngressConfig:
    return HomeAssistantIngressConfig(
        domain="owned.example",
        certresolver=resolver,
        default_ipv4="192.0.2.11",
        entrypoints=("owned-one", "owned-two"),
        middlewares=("second", "first"),
        local_middlewares=(),
        app_port=8321,
    )


RENDERS: dict[str, Callable[[], str | bytes]] = {
    "defaults/homeassistant.service": lambda: render_unit(HomeAssistantRuntimeConfig(), "homeassistant"),
    "defaults/matter-server.service": lambda: render_unit(HomeAssistantRuntimeConfig(), "matter-server"),
    "custom/homeassistant.service": lambda: render_unit(CUSTOM_RUNTIME, "homeassistant"),
    "custom/matter-server.service": lambda: render_unit(CUSTOM_RUNTIME, "matter-server"),
    "defaults/configuration.yaml": lambda: render_configuration(OWNED_RUNTIME, DEFAULT_VALUES).get_secret_value(),
    "custom/configuration.yaml": lambda: render_configuration(OWNED_RUNTIME, CUSTOM_VALUES).get_secret_value(),
    "defaults/secrets.yaml": lambda: render_secrets(
        ConfigurationSecrets(unifi_password_effective=SecretStr('owned"literal'))
    ).get_secret_value(),
    "custom/secrets.yaml": lambda: render_secrets(
        ConfigurationSecrets(
            unifi_password_effective=SecretStr('owned"literal'),
            mqtt_password=SecretStr(""),
            db_password=SecretStr("synthetic"),
            weather_api_key=SecretStr("fixture"),
        )
    ).get_secret_value(),
    **{f"includes/{name}": (lambda name=name: render_include(name).get_secret_value()) for name in INCLUDES},  # type: ignore[misc]
    "custom/homeassistant.traefik.yml": lambda: render_ingress(ingress("")).get_secret_value(),
    "resolver/homeassistant.traefik.yml": lambda: render_ingress(ingress("owned-resolver")).get_secret_value(),
    "defaults/uv-system-certs.conf": dropin_text,
    "defaults/99-homeassistant-zbt1.rules": lambda: (
        files("ops_deploy.services.homeassistant").joinpath("templates/99-homeassistant-zbt1.rules.j2").read_bytes()
    ),
}


@pytest.mark.parametrize("name", sorted(RENDERS))
def test_host_file_is_golden(name: str) -> None:
    assert_golden(GOLDEN / name, RENDERS[name]())


def test_rendered_secrets_stay_out_of_reprs() -> None:
    rendered = render_configuration(OWNED_RUNTIME, CUSTOM_VALUES)
    assert "synthetic" not in repr(CUSTOM_VALUES)
    assert "recorder:" not in repr(rendered)
    assert "recorder:" not in str(rendered)
    secrets = ConfigurationSecrets(unifi_password_effective=SecretStr('owned"literal'))
    assert "owned" not in repr(secrets)
    assert "literal" not in str(render_secrets(secrets))
