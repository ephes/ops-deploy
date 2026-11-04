"""What the role renders and computes on the controller, from its variables.

The templates under ``templates/`` are the role's, byte for byte, rendered
with the options of Ansible's ``template`` module. The payloads below are the
role's ``set_fact`` expressions in Python, in the role's key order, with
Ansible's filter semantics where they differ from Python's (``unique`` and
``sort`` ignore case, ``combine(recursive=True)`` replaces lists, ``to_nice_json``
sorts keys and escapes non-ASCII). ``tests/parity/openclaw_deploy`` holds
what ansible-core itself rendered and computed from the same variables.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Mapping
from functools import cache
from typing import Any

import jinja2

from ops_deploy.services.openclaw.variables import ansible_bool as bool_
from ops_deploy.services.openclaw.variables import dict2items

TEMPLATE_PACKAGE = "ops_deploy.services.openclaw"


@cache
def templates() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters.update(
        to_json=json.dumps,
        to_nice_json=to_nice_json,
        bool=bool_,
        dict2items=dict2items,
        quote=lambda v: shlex.quote(str(v)),
    )
    return env


def render(template: str, variables: Mapping[str, Any], **extra: Any) -> str:
    return templates().get_template(template).render(**variables, **extra)


def to_nice_json(value: Any) -> str:
    """Ansible's ``to_nice_json``."""

    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


def combine(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    """``left | combine(right, recursive=True)``: dicts merge, everything else is replaced."""

    result = dict(left)
    for key, value in right.items():
        current = result.get(key)
        result[key] = combine(current, value) if isinstance(current, dict) and isinstance(value, dict) else value
    return result


def unique(values: Iterable[Any]) -> list[Any]:
    """Ansible's ``unique``: the first of each value, strings compared without case."""

    seen: list[Any] = []
    result: list[Any] = []
    for value in values:
        key = value.lower() if isinstance(value, str) else value
        if key not in seen:
            seen.append(key)
            result.append(value)
    return result


def clean(values: Iterable[Any]) -> list[str]:
    """``map('string') | map('trim') | reject('equalto', '') | unique | list``."""

    return unique(item for item in (str(value).strip() for value in values) if item != "")


def trimmed(value: Any) -> str:
    return str(value).strip()


def version_text(variables: Mapping[str, Any]) -> str:
    return re.sub(r"^v", "", str(variables["openclaw_version"]))


def image(variables: Mapping[str, Any]) -> str:
    return f"{variables['openclaw_image_name']}:{variables['openclaw_image_tag']}"


# -- env.yml ---------------------------------------------------------------------------------


def environment_values(v: Mapping[str, Any]) -> dict[str, Any]:
    """``openclaw_env`` as env.yml assembles it."""

    ca = " --use-openssl-ca" if len(v["openclaw_ca_store_path"]) > 0 else ""
    env: dict[str, Any] = {
        "OPENCLAW_GATEWAY_TOKEN": v["openclaw_gateway_token"],
        "ANTHROPIC_API_KEY": v["openclaw_anthropic_api_key"],
        "TELEGRAM_BOT_TOKEN": v["openclaw_telegram_bot_token"],
        "NODE_OPTIONS": f"--max-old-space-size={v['openclaw_node_max_old_space_size']}{ca}",
    }
    env = combine(env, v["openclaw_extra_env"])
    if len(v["openclaw_openai_api_key"]) > 0:
        env["OPENAI_API_KEY"] = v["openclaw_openai_api_key"]
    if len(v["openclaw_openrouter_api_key"]) > 0:
        env["OPENROUTER_API_KEY"] = v["openclaw_openrouter_api_key"]
    if bool_(v["openclaw_audio_transcription_enabled"]):
        env[v["openclaw_audio_transcription_api_key_env"]] = v["openclaw_audio_transcription_api_key"]
    if len(v["openclaw_ollama_api_key"]) > 0 or len(v["openclaw_ollama_base_url"]) > 0:
        env["OLLAMA_API_KEY"] = (
            v["openclaw_ollama_api_key"] if len(v["openclaw_ollama_api_key"]) > 0 else "ollama-local"
        )
    if len(v["openclaw_ollama_base_url"]) > 0:
        env["OLLAMA_BASE_URL"] = v["openclaw_ollama_base_url"]
    weeknotes = bool_(v["openclaw_weeknotes_enabled"])
    if weeknotes and len(v["openclaw_weeknotes_tz"]) > 0:
        env["TZ"] = v["openclaw_weeknotes_tz"]
    if weeknotes and v["openclaw_weeknotes_backend"] == "s3":
        prefix = "OPENCLAW_WEEKNOTES_S3_"
        for key in (
            "endpoint",
            "region",
            "bucket",
            "prefix",
            "access_key",
            "secret_key",
            "note_key_format",
            "todo_list_mode",
            "todo_list_key_regex",
        ):
            env[prefix + key.upper()] = v[f"openclaw_weeknotes_s3_{key}"]
        env[prefix + "TODO_CACHE_REFRESH_SECS"] = str(v["openclaw_weeknotes_s3_todo_cache_refresh_secs"])
        env[prefix + "MC_ALIAS"] = v["openclaw_weeknotes_s3_mc_alias"]
        env[prefix + "MC_BIN"] = v["openclaw_weeknotes_s3_mc_container_path"]
    return env


def render_env(v: Mapping[str, Any]) -> str:
    return render("openclaw.env.j2", v, openclaw_env=environment_values(v))


# -- config.yml ------------------------------------------------------------------------------


def managed_plugins(v: Mapping[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    """``_openclaw_managed_plugin_entries``, ``_load_paths`` and ``_allow``."""

    entries: dict[str, Any] = {
        "telegram": {"enabled": bool_(v["openclaw_telegram_enabled"])},
        "whatsapp": {"enabled": False},
    }
    heartbeat = bool_(v["openclaw_heartbeat_recovery_managed"])
    codex = bool_(v["openclaw_codex_plugin_enabled"])
    opsgate = bool_(v["openclaw_opsgate_enabled"])
    if heartbeat:
        hooks = {"allowConversationAccess": True, "allowPromptInjection": True}
        entries = combine(
            entries,
            {"heartbeat-recovery": {"enabled": bool_(v["openclaw_heartbeat_recovery_enabled"]), "hooks": hooks}},
        )
    if codex:
        entries = combine(entries, {v["openclaw_codex_plugin_id"]: {"enabled": True}})
    if opsgate:
        entries = combine(entries, {v["openclaw_opsgate_extension_id"]: {"enabled": True}})
    load = ([v["openclaw_opsgate_container_extension_dir"]] if opsgate else []) + (
        ["/home/node/.openclaw/extensions/heartbeat-recovery"] if heartbeat else []
    )
    allow = unique(
        ([v["openclaw_codex_plugin_id"]] if codex else [])
        + ([v["openclaw_opsgate_extension_id"]] if opsgate else [])
        + (["heartbeat-recovery"] if heartbeat else [])
    )
    return entries, load, allow


def gateway_settings(v: Mapping[str, Any]) -> dict[str, Any]:
    """The ``gateway`` mapping both the seed and the runtime patch start from."""

    bind = "lan" if v["openclaw_network_mode"] == "bridge" and bool_(v["openclaw_traefik_enabled"]) else "loopback"
    port = v["openclaw_host_port"] if v["openclaw_network_mode"] == "host" else v["openclaw_container_port"]
    return {
        "mode": "local",
        "bind": bind,
        "port": int(port),
        "trustedProxies": v["openclaw_gateway_trusted_proxies"],
        "allowRealIpFallback": bool_(v["openclaw_gateway_allow_real_ip_fallback"]),
        "http": {
            "endpoints": {"chatCompletions": {"enabled": bool_(v["openclaw_gateway_http_chat_completions_enabled"])}}
        },
    }


def rate_limit_patch(v: Mapping[str, Any]) -> dict[str, Any]:
    if not bool_(v["openclaw_gateway_auth_rate_limit_enabled"]):
        return {}
    limit = {
        "maxAttempts": int(v["openclaw_gateway_auth_rate_limit_max_attempts"]),
        "windowMs": int(v["openclaw_gateway_auth_rate_limit_window_ms"]),
        "lockoutMs": int(v["openclaw_gateway_auth_rate_limit_lockout_ms"]),
        "exemptLoopback": bool_(v["openclaw_gateway_auth_rate_limit_exempt_loopback"]),
    }
    return {"gateway": {"auth": {"rateLimit": limit}}}


def control_ui_patch(v: Mapping[str, Any]) -> dict[str, Any]:
    if not bool_(v["openclaw_traefik_enabled"]):
        return {}
    return {"gateway": {"controlUi": {"allowedOrigins": ["https://" + str(v["openclaw_traefik_host"])]}}}


def policy_patches(v: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The model policy, reasoning and auth-order patches (in the role's combine order)."""

    if len(v["openclaw_gateway_config"]) > 0:
        return [{}, {}, {}]
    primary = trimmed(v["openclaw_agent_model_primary"])
    model = (
        {
            "agents": {
                "defaults": {
                    "model": {
                        "primary": primary,
                        "fallbacks": [trimmed(f) for f in v["openclaw_agent_model_fallbacks"]],
                    }
                }
            }
        }
        if len(primary) > 0
        else {}
    )
    thinking = trimmed(v["openclaw_agent_thinking_default"])
    reasoning = {"agents": {"defaults": {"thinkingDefault": thinking}}} if len(thinking) > 0 else {}
    order = v["openclaw_openai_auth_order"]
    auth = {"auth": {"order": {"openai": [trimmed(item) for item in order]}}} if len(order) > 0 else {}
    return [model, reasoning, auth]


def audio_model_entry(v: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "provider": trimmed(v["openclaw_audio_transcription_provider"]),
        "model": trimmed(v["openclaw_audio_transcription_model"]),
        "profile": trimmed(v["openclaw_audio_transcription_profile_id"]),
        "baseUrl": trimmed(v["openclaw_audio_transcription_base_url"]),
        "capabilities": ["audio"],
    }


def audio_config_patch(v: Mapping[str, Any]) -> dict[str, Any] | None:
    """``_openclaw_audio_config_patch`` (``None`` where the role leaves it undefined)."""

    if len(v["openclaw_gateway_config"]) > 0 or not bool_(v["openclaw_audio_transcription_managed"]):
        return None
    if not bool_(v["openclaw_audio_transcription_enabled"]):
        return {"tools": {"media": {"models": [], "audio": {"enabled": False}}}}
    entry = audio_model_entry(v)
    provider, model = entry["provider"], entry["model"]
    tools = {
        "tools": {
            "media": {
                "models": [entry],
                "audio": {
                    "enabled": True,
                    "preferredModel": f"{provider}/{model}",
                    "timeoutSeconds": int(v["openclaw_audio_transcription_timeout_seconds"]),
                },
            }
        }
    }
    providers = {
        provider: {
            "baseUrl": entry["baseUrl"],
            "models": [{"id": model, "name": model}],
            "request": {"allowPrivateNetwork": bool_(v["openclaw_audio_transcription_allow_private_network"])},
        }
    }
    return combine(tools, {"models": {"providers": providers}})


def built_config(v: Mapping[str, Any]) -> dict[str, Any]:
    """``_openclaw_built_config``: the seed when the role builds the config itself."""

    entries, load, allow = managed_plugins(v)
    telegram = {
        "enabled": bool_(v["openclaw_telegram_enabled"]),
        "dmPolicy": v["openclaw_telegram_dm_policy"],
        "allowFrom": v["openclaw_telegram_allow_from"],
        "streaming": streaming(v),
    }
    config: dict[str, Any] = {
        "channels": {"telegram": telegram},
        "session": {"dmScope": v["openclaw_session_dm_scope"]},
        "plugins": {"entries": entries},
    }
    if len(allow) > 0:
        config = combine(config, {"plugins": {"allow": allow}})
    if len(load) > 0:
        config = combine(config, {"plugins": {"load": {"paths": load}}})
    access = combine(combine({"gateway": gateway_settings(v)}, rate_limit_patch(v)), control_ui_patch(v))
    config = combine(config, access)
    for patch in policy_patches(v):
        config = combine(config, patch)
    return combine(config, audio_config_patch(v) or {})


def streaming(v: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mode": v["openclaw_telegram_streaming_mode"],
        "preview": {
            "toolProgress": bool_(v["openclaw_telegram_streaming_preview_tool_progress"]),
            "commandText": v["openclaw_telegram_streaming_preview_command_text"],
        },
    }


def render_seed(v: Mapping[str, Any]) -> str:
    seed = v["openclaw_gateway_config"] if len(v["openclaw_gateway_config"]) > 0 else None
    return render("openclaw-config.json.j2", v, _openclaw_built_config=seed if seed is not None else built_config(v))


def runtime_inputs(v: Mapping[str, Any]) -> dict[str, Any]:
    """What the host script needs to patch an existing ``openclaw.json`` as config.yml does.

    Everything that does not depend on the existing file is computed here;
    the host applies the parts that read it (plugin allow and load paths,
    the model allowlist, the preserved media models, the audio provider).
    """

    entries, load, allow = managed_plugins(v)
    base = {
        "plugins": {"entries": entries},
        "channels": {"telegram": {"streaming": streaming(v)}},
        "session": {"dmScope": v["openclaw_session_dm_scope"]},
        "gateway": gateway_settings(v),
    }
    model, reasoning, auth = policy_patches(v)
    return {
        "base": combine(base, rate_limit_patch(v)),
        "plugin_allow": allow,
        "control_ui": control_ui_patch(v),
        "plugin_load_paths": load,
        "model_policy": model,
        "model_primary": trimmed(v["openclaw_agent_model_primary"]) if len(v["openclaw_gateway_config"]) == 0 else "",
        "reasoning": reasoning,
        "auth_order": auth,
        "audio_managed": bool_(v["openclaw_audio_transcription_managed"]),
        "audio_enabled": bool_(v["openclaw_audio_transcription_enabled"]),
        "audio_provider": trimmed(v["openclaw_audio_transcription_provider"]),
        "audio_profile_id": v["openclaw_audio_transcription_profile_id"],
        "audio_model_entry": audio_model_entry(v),
        "audio_config_patch": audio_config_patch(v),
    }


# -- skills ----------------------------------------------------------------------------------


def imap_credentials(v: Mapping[str, Any]) -> dict[str, Any]:
    accounts: dict[str, Any] = {}
    for key, item in v["openclaw_imap_account_map"].items():
        accounts = combine(
            accounts,
            {
                key: {
                    "username": item["username"],
                    "password": item["password"],
                    "mailbox": item.get("mailbox", v["openclaw_imap_default_mailbox"]),
                }
            },
        )
    for key, item in accounts.items():
        if not all(len(str(item[field]).strip()) > 0 for field in ("username", "password", "mailbox")):
            raise ValueError(f"IMAP account {key} did not resolve to non-empty username/password/mailbox.")
    return {"default_account": v["openclaw_imap_default_account"], "accounts": accounts}


def smtp_credentials(v: Mapping[str, Any]) -> dict[str, Any]:
    accounts: dict[str, Any] = {}
    for key, item in v["openclaw_smtp_account_map"].items():
        accounts = combine(
            accounts,
            {
                key: {
                    "username": item["username"],
                    "password": item["password"],
                    "from_address": item["from_address"],
                    "from_name": item.get("from_name", ""),
                    "reply_to": item.get("reply_to", ""),
                }
            },
        )
    for key, item in accounts.items():
        if not all(len(str(item[field]).strip()) > 0 for field in ("username", "password", "from_address")):
            raise ValueError(f"SMTP account {key} did not resolve to non-empty username/password/from_address.")
    return {"default_account": v["openclaw_smtp_default_account"], "accounts": accounts}


def calendar_runtime(v: Mapping[str, Any]) -> dict[str, Any]:
    accounts: dict[str, Any] = {}
    for key, item in v["openclaw_calendar_account_map"].items():
        accounts = combine(
            accounts, {str(key).strip().lower(): {"username": str(item["username"]), "password": str(item["password"])}}
        )
    calendars: dict[str, Any] = {}
    for key, item in v["openclaw_calendar_map"].items():
        account = accounts.get(str(item.get("account", v["openclaw_calendar_default_account"])).strip().lower(), {})
        # ``.get(...) | default(fallback, true)``: a missing or empty account value falls back.
        username = account.get("username") or str(item.get("username", ""))
        password = account.get("password") or str(item.get("password", ""))
        calendars = combine(
            calendars,
            {
                str(key).strip().lower(): {
                    "display_name": str(item.get("display_name", key)).strip(),
                    "url": re.sub(r"/+$", "", str(item["url"]).strip()),
                    "username": username,
                    "password": password,
                    "read": bool_(item.get("read", True)),
                    "write": bool_(item.get("write", False)),
                }
            },
        )
    for key, item in calendars.items():
        valid = all(len(str(item[f]).strip()) > 0 for f in ("display_name", "url", "username", "password"))
        if not valid or not (item["read"] or item["write"]):
            raise ValueError(
                f"Calendar entry {key} did not resolve to valid display_name/url/username/password/read/write fields."
            )
    payload = {
        "timezone": str(v["openclaw_calendar_timezone"]).strip(),
        **{
            name: int(v[f"openclaw_calendar_{name}"])
            for name in (
                "default_duration_minutes",
                "request_timeout_seconds",
                "read_parallelism",
                "read_aggregate_timeout_seconds",
                "default_limit",
                "max_limit",
                "title_max_chars",
                "location_max_chars",
            )
        },
        "health_state_path": str(v["openclaw_calendar_container_health_state_path"]).strip(),
        "auth_failure_window_seconds": int(v["openclaw_calendar_auth_failure_window_seconds"]),
        "auth_failure_threshold": int(v["openclaw_calendar_auth_failure_threshold"]),
        "calendars": calendars,
    }
    return payload


def paperless_runtime(v: Mapping[str, Any]) -> dict[str, Any]:
    p = "openclaw_paperless_"
    ints = (
        "search_timeout_seconds",
        "download_timeout_seconds",
        "delivery_timeout_seconds",
        "default_limit",
        "max_limit",
        "latest_default_days",
        "latest_max_days",
        "title_max_chars",
        "correspondent_max_chars",
        "max_download_bytes",
        "download_chunk_bytes",
    )
    return {
        "base_url": re.sub(r"/+$", "", str(v[p + "base_url"]).strip()),
        "token": v[p + "token"],
        **{name: int(v[p + name]) for name in ints},
        "downloads_dir": str(v[p + "container_downloads_dir"]).strip(),
        "session_state_path": str(v[p + "container_session_state_path"]).strip(),
        "session_target_max_age_seconds": int(v[p + "session_target_max_age_seconds"]),
        "delivery_channel": str(v[p + "delivery_channel"]).strip(),
        "health_state_path": str(v[p + "container_health_state_path"]).strip(),
        "auth_failure_window_seconds": int(v[p + "auth_failure_window_seconds"]),
        "auth_failure_threshold": int(v[p + "auth_failure_threshold"]),
    }


def homeassistant_runtime(v: Mapping[str, Any]) -> dict[str, Any]:
    p = "openclaw_homeassistant_"

    def names(key: str) -> list[str]:
        return unique(str(item).strip().lower() for item in v[p + key])

    ints = (
        "request_timeout_seconds",
        "default_limit",
        "max_limit",
        "state_max_chars",
        "friendly_name_max_chars",
        "attribute_max_items",
        "attribute_value_max_chars",
    )
    return {
        "base_url": str(v[p + "base_url"]).strip(),
        "token": v[p + "token"],
        "allow_domains": names("allow_domains"),
        "allow_entities": names("allow_entities"),
        "allow_write_domains": names("allow_write_domains"),
        "allow_write_entities": names("allow_write_entities"),
        **{name: int(v[p + name]) for name in ints},
    }


def opsgate_runtime(v: Mapping[str, Any]) -> dict[str, Any]:
    p = "openclaw_opsgate_"
    approval = (
        v[p + "approval_base_url"] if len(str(v[p + "approval_base_url"]).strip()) > 0 else v[p + "submit_base_url"]
    )
    ints = (
        "submit_timeout_seconds",
        "ticket_expires_seconds",
        "title_max_chars",
        "summary_max_chars",
        "request_max_chars",
        "task_ref_max_chars",
    )
    return {
        "submit_base_url": re.sub(r"/+$", "", str(v[p + "submit_base_url"]).strip()),
        "approval_base_url": re.sub(r"/+$", "", str(approval).strip()),
        "submit_token": v[p + "submit_token"],
        **{name: int(v[p + name]) for name in ints},
    }


def sort(values: Iterable[str]) -> list[str]:
    """Ansible's ``sort`` (Jinja's, case-insensitive)."""

    return sorted(values, key=lambda value: value.lower())


def managed_skills_manifest(v: Mapping[str, Any]) -> str:
    """session_state.yml's manifest file content.

    The task ends its content with ``{{ '\\n' }}`` in a folded scalar; Ansible
    escapes backslashes in task arguments, so the file ends in a literal
    backslash and ``n``, not in a newline.
    """

    slash: list[Any] = []
    if bool_(v["openclaw_weeknotes_enabled"]):
        slash += list(v["openclaw_weeknotes_command_skill_names"])
    for feature in ("imap", "calendar", "paperless", "homeassistant", "opsgate"):
        if bool_(v[f"openclaw_{feature}_enabled"]):
            slash.append(v[f"openclaw_{feature}_command_skill_name"])
    workspace = [skill["name"] for skill in v["openclaw_workspace_skills"]]
    manifest = {
        "version": 3,
        "managed_slash_skills": sort(clean(slash)),
        "managed_workspace_skills": sort(clean(workspace)),
    }
    return to_nice_json(manifest) + "\\n"


def credentials_json(payload: Mapping[str, Any]) -> str:
    """``copy: content: "{{ payload | to_nice_json }}\\n"``."""

    return to_nice_json(payload) + "\n"


def logrotate(v: Mapping[str, Any]) -> str:
    return (
        f"{v['openclaw_log_dir']}/*.log {{\n"
        "    daily\n"
        f"    rotate {v['openclaw_logrotate_days']}\n"
        "    compress\n"
        "    delaycompress\n"
        "    missingok\n"
        "    notifempty\n"
        "    create 0640 1000 1000\n"
        "}\n"
    )
