"""Explicit owned trust/configuration/custom-component faults and recovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ops_deploy.services.homeassistant import HomeAssistantDeployConfig
from ops_deploy.services.homeassistant.custom_conversation import CustomConversationConfig
from ops_deploy.services.homeassistant.deploy_config import AssistSelection

from .fixture import command, metadata, write
from .harness import CONFIG, HOME, api, typed, wait_http
from .matrix import MODEL_URL
from .model_server import MODEL


def revalidate(cfg: HomeAssistantDeployConfig, values: dict[str, Any]) -> HomeAssistantDeployConfig:
    return HomeAssistantDeployConfig.model_validate(cfg.model_copy(update=values).model_dump())


def run(selected: HomeAssistantDeployConfig, token: str) -> None:
    extra = Path("/etc/systemd/system/homeassistant.service.d/99-owned-forbidden.conf")
    assert not extra.exists()
    extra.write_text("[Service]\nEnvironment=SSL_CERT_FILE=/owned-not-a-trust-store.pem\n")
    try:
        result = typed("24-foreign-trust-dropin-refusal", selected, failure=True)
        assert not result["managed"]
        assert not result["uploads"]
    finally:
        extra.unlink()
    typed("25-trust-corrected-repeat", selected, stable=True)

    constraints = HOME / ".python-security-constraints.txt"
    expected = constraints.read_bytes()
    constraints.write_text("# declared owned wrong-constraints fault\n")
    typed("26-constraints-recovery", selected)
    assert constraints.read_bytes() == expected
    typed("27-constraints-repeat", selected, stable=True)

    configuration = CONFIG / "configuration.yaml"
    body = configuration.read_bytes()
    configuration.write_text("homeassistant: [owned invalid configuration\n")
    try:
        result = typed("28-invalid-configuration", selected, failure=True)
        assert not result["uploads"]
    finally:
        configuration.write_bytes(body)
    write(
        "28-fixture-configuration-reset.json",
        {"classification": "declared owned invalid-config correction", "metadata": metadata(configuration)},
    )
    typed("29-configuration-corrected-repeat", selected, stable=True)

    # Actual area API setup is a labelled fixture operation. Only the selected
    # area's declared alias changes belong to the typed role; unrelated rows stay.
    area = api("ws", token=token, command_value={"type": "config/area_registry/create", "name": "Owned selected area"})[
        "result"
    ]
    other = api(
        "ws", token=token, command_value={"type": "config/area_registry/create", "name": "Owned unrelated area"}
    )["result"]
    area_cfg = revalidate(
        selected,
        {
            "area_updates": SecretStr(
                json.dumps([{"area_id": area["area_id"], "aliases": ["Owned alias", " Owned alias "]}])
            )
        },
    )
    typed("30-area-update", area_cfg)
    typed("31-area-repeat", area_cfg, stable=True)
    rows = api("ws", token=token, command_value={"type": "config/area_registry/list"})["result"]
    current = next(item for item in rows if item["area_id"] == area["area_id"])
    retained = next(item for item in rows if item["area_id"] == other["area_id"])
    assert current["aliases"] == ["Owned alias"]
    assert retained == other
    write("31-area-selection.json", {"selected_aliases_equal": True, "unrelated_area_equal": True})

    # Exercise the original voice-only branch against the real selected entity,
    # then return to list composition. It must preserve current registry bytes.
    voice = revalidate(selected, {"assist": AssistSelection(manage_stt=True, manage_tts=True)})
    typed("32-voice-current", voice, stable=True)
    bad_voice = revalidate(voice, {"assist": AssistSelection(manage_stt=True, stt_engine_id="stt.owned_missing")})
    typed("33-voice-missing-stt", bad_voice, failure=True)
    typed("34-voice-recovery", selected, stable=True)

    custom = revalidate(
        selected,
        {
            "builtin_enabled": False,
            "custom": CustomConversationConfig(
                enabled=True,
                base_url=SecretStr(MODEL_URL + "/v1"),
                api_key=selected.builtin.api_key,
                model=SecretStr(MODEL),
                instructions=selected.builtin.instructions,
            ),
            "assist": AssistSelection(
                pipelines=SecretStr(
                    json.dumps(
                        [
                            {
                                "name": "Owned native pipeline",
                                "language": "en",
                                "conversation_engine": "auto:custom_conversation",
                                "preferred": True,
                            }
                        ]
                    )
                )
            ),
        },
    )
    typed("35-custom-install-and-real-canary", custom)
    wait_http()
    typed("36-custom-repeat", custom, stable=True)
    stamp = CONFIG / "custom_components/custom_conversation/.ansible-cc-version"
    stamp.write_text("owned-wrong-stamp\n")
    typed("37-custom-stamp-recovery", custom)
    typed("38-custom-stamp-repeat", custom, stable=True)
    archive = HOME / f"downloads/custom-conversation-{custom.custom_component.version}.tar.gz"
    assert archive.is_file(), "selected custom component archive must exist before owned fault"
    archive.write_bytes(b"owned-invalid-archive\n")
    typed("39-custom-archive-recovery", custom)
    typed("40-custom-archive-repeat", custom, stable=True)
    disabled = revalidate(
        custom, {"custom": custom.custom.model_copy(update={"enabled": False}), "assist": AssistSelection()}
    )
    typed("41-custom-disable", disabled)
    typed("42-custom-disabled-repeat", disabled, stable=True)
    typed("43-custom-recreate", custom)
    # Builtin re-enable must use the real prior custom entry/component/LiteLLM,
    # retire it and rebuild as original; no synthetic registry file rewrite.
    typed("44-real-legacy-retirement", selected)
    wait_http()
    typed("45-legacy-retirement-repeat", selected, stable=True)
    entries = api("ws", token=token, command_value={"type": "config_entries/get"})["result"]
    assert not any(item["domain"] == "custom_conversation" for item in entries)
    assert not (CONFIG / "custom_components/custom_conversation").exists()
    assert (
        command(
            str(HOME / ".venv/bin/python"),
            "-I",
            "-B",
            "-c",
            'import importlib.metadata as m;assert not any(d.metadata["Name"].lower().replace("_","-")'
            '.startswith("litellm") for d in m.distributions())',
        ).returncode
        == 0
    )
    write(
        "45-legacy-retirement.json",
        {"actual_prior_custom_entry_retired": True, "actual_component_absent": True, "actual_litellm_absent": True},
    )
