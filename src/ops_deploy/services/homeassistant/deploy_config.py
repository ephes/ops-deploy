"""Original normal-role inputs composed from the prepared HA components."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, Self

from pydantic import Field, PrivateAttr, SecretStr, StrictBool, StrictInt, model_validator

from ops_deploy.base._common import RoleConfig

from .builtin_conversation import BuiltinConversationConfig
from .configuration import ConfigurationPolicy
from .configuration_deploy import INCLUDES, UnifiSecretSource
from .configuration_render import ConfigurationSecretExamples, ConfigurationValues
from .custom_component import CustomComponentConfig
from .custom_conversation import CustomConversationConfig
from .ingress import HomeAssistantIngressConfig
from .integration_flows import HomeAssistantApiConfig, IntegrationSelection
from .runtime_config import HomeAssistantRuntimeConfig


class AssistSelection(RoleConfig):
    """Protected declared list and original standalone voice defaults."""

    pipelines: SecretStr = SecretStr("[]")
    manage_stt: StrictBool = False
    manage_tts: StrictBool = False
    pipeline_id: str = ""
    stt_engine_id: str = ""
    stt_language: str = ""
    tts_engine_id: str = ""
    tts_language: str = ""
    tts_voice: str = ""

    def definitions(self) -> list[dict[str, Any]]:
        try:
            result = json.loads(self.pipelines.get_secret_value())
            if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("Home Assistant declared pipelines must be a list of mappings") from None
        return result

    def builtin_selected(self) -> bool:
        return any(item.get("conversation_engine") == "auto:llama_cpp" for item in self.definitions())

    def payload(self, *, wyoming_host: str, wyoming_port: int, builtin_enabled: bool) -> SecretStr:
        return SecretStr(
            json.dumps(
                {
                    **self.model_dump(exclude={"pipelines"}),
                    "pipelines": self.definitions(),
                    "wyoming_host": wyoming_host,
                    "wyoming_port": wyoming_port,
                    "llama_cpp_enabled": builtin_enabled,
                }
            )
        )


class HomeAssistantDeployConfig(RoleConfig):
    _include_renderer: Callable[[str], SecretStr] | None = PrivateAttr(default=None)
    _ingress_renderer: Callable[[], SecretStr] | None = PrivateAttr(default=None)

    def with_template_renderers(
        self,
        *,
        include: Callable[[str], SecretStr] | None = None,
        ingress: Callable[[], SecretStr] | None = None,
    ) -> Self:
        """Attach protected lazy controller callbacks without serializing context."""
        result = self.model_copy()
        result._include_renderer = include
        result._ingress_renderer = ingress
        return result

    runtime: HomeAssistantRuntimeConfig = Field(default_factory=HomeAssistantRuntimeConfig)
    configuration: ConfigurationPolicy = Field(default_factory=ConfigurationPolicy)
    values: ConfigurationValues = Field(default_factory=ConfigurationValues)
    unifi: UnifiSecretSource = Field(default_factory=UnifiSecretSource)
    secret_examples: ConfigurationSecretExamples = Field(default_factory=ConfigurationSecretExamples)
    ingress: HomeAssistantIngressConfig = Field(default_factory=HomeAssistantIngressConfig)
    ingress_rendered: SecretStr | None = None
    include_files: tuple[str, ...] = INCLUDES
    include_rendered: dict[str, SecretStr] = Field(default_factory=dict)
    api: HomeAssistantApiConfig = Field(default_factory=HomeAssistantApiConfig)
    additional_packages: tuple[str, ...] = (
        "build-essential",
        "python3-dev",
        "libffi-dev",
        "libssl-dev",
        "libjpeg-dev",
        "libturbojpeg",
        "zlib1g-dev",
        "autoconf",
        "libopenjp2-7",
        "libtiff-dev",
        "libtiff6",
        "libfreetype6-dev",
        "libwebp-dev",
        "tzdata",
        "ffmpeg",
        "sqlite3",
    )
    area_updates: SecretStr = SecretStr("[]")
    manage_matter_integration: StrictBool = False
    matter_integration_url: SecretStr = SecretStr("ws://localhost:5580/ws")
    manage_otbr_integration: StrictBool = False
    otbr_integration_url: SecretStr = SecretStr("http://127.0.0.1:8081")
    manage_wyoming_integration: StrictBool = False
    wyoming_host: str = ""
    wyoming_port: StrictInt = 10300
    builtin_enabled: StrictBool = False
    builtin: BuiltinConversationConfig = Field(default_factory=BuiltinConversationConfig)
    custom: CustomConversationConfig = Field(default_factory=CustomConversationConfig)
    custom_component: CustomComponentConfig = Field(default_factory=CustomComponentConfig)
    assist: AssistSelection = Field(default_factory=AssistSelection)

    @model_validator(mode="before")
    @classmethod
    def dependent_defaults(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        result = dict(value)
        values = result.get("values", {})
        port = values.app_port if isinstance(values, ConfigurationValues) else values.get("app_port", 10020)
        runtime = result.get("runtime", {})
        matter_port = (
            runtime.matter_server_port
            if isinstance(runtime, HomeAssistantRuntimeConfig)
            else runtime.get("matter_server_port", 5580)
        )
        result.setdefault("matter_integration_url", f"ws://localhost:{matter_port}/ws")
        if "api" not in result:
            result["api"] = {"url": f"http://localhost:{port}"}
        elif isinstance(result["api"], dict):
            result["api"] = {"url": f"http://localhost:{port}", **result["api"]}
        if "ingress" not in result:
            result["ingress"] = {"app_port": port}
        elif isinstance(result["ingress"], dict):
            result["ingress"] = {"app_port": port, **result["ingress"]}
        # Original one default-route fact feeds both API and ingress defaults.
        # Preserve an explicit component override, including an explicit None.
        api = result["api"]
        ingress = result["ingress"]
        api_fields = api.model_fields_set if isinstance(api, HomeAssistantApiConfig) else api
        ingress_fields = ingress.model_fields_set if isinstance(ingress, HomeAssistantIngressConfig) else ingress
        api_ip = api.default_ipv4 if isinstance(api, HomeAssistantApiConfig) else api.get("default_ipv4")
        ingress_ip = (
            ingress.default_ipv4 if isinstance(ingress, HomeAssistantIngressConfig) else ingress.get("default_ipv4")
        )
        if "default_ipv4" not in ingress_fields and api_ip is not None:
            result["ingress"] = (
                ingress.model_copy(update={"default_ipv4": api_ip})
                if isinstance(ingress, HomeAssistantIngressConfig)
                else {**ingress, "default_ipv4": api_ip}
            )
        if "default_ipv4" not in api_fields and ingress_ip is not None:
            result["api"] = (
                api.model_copy(update={"default_ipv4": ingress_ip})
                if isinstance(api, HomeAssistantApiConfig)
                else {**api, "default_ipv4": ingress_ip}
            )
        custom = result.get("custom", {})
        version = custom.version if isinstance(custom, CustomConversationConfig) else custom.get("version", "1.6.1")
        if "custom_component" not in result:
            result["custom_component"] = {"version": version}
        return result

    def areas(self) -> list[dict[str, Any]]:
        from .area_registry import validate_updates

        try:
            result = json.loads(self.area_updates.get_secret_value())
        except ValueError:
            raise ValueError("Home Assistant area declarations are invalid") from None
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise ValueError("Home Assistant area declarations must be a list of mappings")
        validate_updates(result)
        return result

    def integrations(self) -> tuple[IntegrationSelection, ...]:
        result = []
        if self.manage_matter_integration:
            result.append(IntegrationSelection(domain="matter", url=self.matter_integration_url))
        if self.manage_otbr_integration:
            result.append(IntegrationSelection(domain="otbr", url=self.otbr_integration_url))
        if self.manage_wyoming_integration:
            result.append(
                IntegrationSelection(domain="wyoming", wyoming_host=self.wyoming_host, wyoming_port=self.wyoming_port)
            )
        return tuple(result)

    @model_validator(mode="after")
    def original_selected_validation(self) -> Self:
        definitions = self.assist.definitions()
        areas = self.areas()
        flows = self.integrations()
        if definitions or areas or flows or self.assist.manage_stt or self.assist.manage_tts:
            self.api.validate_selected()
        for flow in flows:
            flow.desired()
        discovery = bool(self.wyoming_host) and self.wyoming_port > 0
        if definitions:
            if any("name" not in item or "language" not in item for item in definitions):
                raise ValueError("Home Assistant pipelines require name and language")
            if sum(bool(item.get("preferred", False)) for item in definitions) > 1:
                raise ValueError("Home Assistant permits at most one preferred pipeline")
            for kind in ("stt", "tts"):
                if any(kind + "_engine_id" not in item for item in definitions) and not discovery:
                    raise ValueError("Home Assistant pipelines need explicit engines or Wyoming discovery")
        else:
            for kind in ("stt", "tts"):
                if (
                    getattr(self.assist, "manage_" + kind)
                    and not getattr(self.assist, kind + "_engine_id")
                    and not discovery
                ):
                    raise ValueError("Home Assistant voice needs explicit engines or Wyoming discovery")
        if self.builtin_enabled:
            match = re.fullmatch(r"homeassistant==([0-9]+)\.([0-9]+)\.([0-9]+)", self.runtime.package_spec)
            if self.custom.enabled or match is None or tuple(map(int, match.groups())) < (2026, 10, 2):
                raise ValueError("Core llama_cpp requires pinned Core >=2026.10.2 and exclusive voice bridge ownership")
            if (
                len(self.api.token.get_secret_value()) < 32
                or any(
                    not value.get_secret_value()
                    for value in (self.builtin.base_url, self.builtin.api_key, self.builtin.model)
                )
                or not self.builtin.instructions.get_secret_value().strip()
            ):
                raise ValueError("Core llama_cpp requires original connection details, token and instructions")
        return self
