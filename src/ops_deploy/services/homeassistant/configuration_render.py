"""Original configuration bytes in protected values; no host read or write.

Rendered configuration can contain a database credential even when secrets.yaml
is unmanaged. Every output is SecretStr; consumers must use protected stdin and
must not serialize the unwrapped bodies into controller evidence.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictFloat, StrictInt, StrictStr

from .render import templates
from .runtime_config import HomeAssistantRuntimeConfig


class ConfigurationValues(BaseModel):
    """Original template inputs, independent of the physical ownership policy."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)
    name: StrictStr = "Home Assistant"
    latitude: StrictInt | StrictFloat = 0.0
    longitude: StrictInt | StrictFloat = 0.0
    elevation: StrictInt = 0
    unit_system: StrictStr = "metric"
    time_zone: StrictStr = "UTC"
    country: StrictStr = "DE"
    currency: StrictStr = "EUR"
    external_url: StrictStr = ""
    internal_url: StrictStr = ""
    host: StrictStr = "0.0.0.0"
    app_port: StrictInt = 10020
    trusted_proxies: tuple[StrictStr, ...] = ("127.0.0.1", "::1")
    db_url: SecretStr | None = None
    recorder_keep_days: StrictInt = 10
    recorder_commit_interval: StrictInt = 5
    logger_default: StrictStr = "warning"
    logger_logs: dict[StrictStr, StrictStr] = Field(
        default_factory=lambda: {"homeassistant.core": "info", "homeassistant.components.http": "info"}
    )
    unifi_host: StrictStr = "192.168.178.94"
    unifi_port: StrictInt = 8443
    unifi_username: StrictStr = "homeassistant"
    unifi_site: StrictStr = "default"


class ConfigurationSecrets(BaseModel):
    """Already-resolved values; host-local UniFi source resolution is separate.

    Optional commented examples preserve the original template's defaults.
    Empty values stay empty; the original Jinja default filter is not boolean.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    unifi_password_effective: SecretStr
    mqtt_password: SecretStr | None = None
    db_password: SecretStr | None = None
    weather_api_key: SecretStr | None = None


def render_configuration(runtime: HomeAssistantRuntimeConfig, values: ConfigurationValues) -> SecretStr:
    context = {f"homeassistant_{key}": value for key, value in values.model_dump(exclude={"db_url"}).items()}
    context["homeassistant_data_path"] = runtime.data_path
    context["homeassistant_db_url"] = (
        values.db_url.get_secret_value()
        if values.db_url is not None
        else f"sqlite:///{runtime.config_path}/home-assistant_v2.db"
    )
    return SecretStr(templates().get_template("configuration.yaml.j2").render(**context))


def render_secrets(values: ConfigurationSecrets) -> SecretStr:
    context = {"homeassistant_unifi_password_effective": values.unifi_password_effective.get_secret_value()}
    for name in ("mqtt_password", "db_password", "weather_api_key"):
        value = getattr(values, name)
        if value is not None:
            context[name] = value.get_secret_value()
    return SecretStr(templates().get_template("secrets.yaml.j2").render(**context))


def render_include(name: str) -> SecretStr:
    """Original stock include bytes; unknown templates retain loader refusal."""
    return SecretStr(templates().get_template(name + ".j2").render())
