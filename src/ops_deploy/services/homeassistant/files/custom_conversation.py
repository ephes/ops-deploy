import asyncio
import json
import sys
from urllib.parse import urlparse, urlunparse

import aiohttp

# Secrets arrive on stdin, never in the task environment: under become,
# Ansible puts task environment values into the command it hands to sudo,
# and sudo logs that command.
PAYLOAD = json.loads(sys.stdin.read())
STDIN_SECRETS = PAYLOAD['secrets']
ENV = PAYLOAD['settings']
PHASE = 'input'
MUTATION_ATTEMPTS = 0


class ProvisionError(RuntimeError):
    """Only source-owned diagnostics; never arbitrary upstream response text."""


DOMAIN = "custom_conversation"
PLATFORM = "custom_conversation"

CONF_PRIMARY_PROVIDER = "primary_provider"
CONF_PRIMARY_API_KEY = "primary_api_key"
CONF_PRIMARY_BASE_URL = "primary_base_url"
CONF_PRIMARY_CHAT_MODEL = "primary_chat_model"
CONF_SECONDARY_PROVIDER_ENABLED = "secondary_provider_enabled"
CONF_LLM_HASS_API = "llm_hass_api"
CONF_AGENTS_SECTION = "agents"
CONF_ENABLE_HASS_AGENT = "enable_home_assistant_agent"
CONF_ENABLE_LLM_AGENT = "enable_llm_agent"
CONF_IGNORED_INTENTS_SECTION = "ignored_intents_section"
CONF_IGNORED_INTENTS = "ignored_intents"
CONF_CUSTOM_PROMPTS_SECTION = "custom_prompts"
CONF_INSTRUCTIONS_PROMPT = "instructions_prompt"
CONF_LANGFUSE_SECTION = "langfuse"
CONF_ENABLE_LANGFUSE = "enable_langfuse"

# Mirrors custom-conversation v1.6.1 const.DEFAULT_INSTRUCTIONS_PROMPT.
# The component's options flow rewrites an empty instructions_prompt
# back to this default (config_flow.async_step_init) and the prompt
# manager falls back to it when the key is absent. Embedding the exact
# text lets drift detection stay idempotent when the desired
# instructions are "" (restore the component default) instead of
# re-writing the entry on every run. Pinned alongside the component
# version/sha; a component bump that changes the default only causes
# one harmless re-apply.
DEFAULT_INSTRUCTIONS_PROMPT = (
    "You are a voice assistant for Home Assistant.\n"
    "Answer questions about the world truthfully.\n"
    "Answer in plain text. Keep it simple and to the point.\n"
)
# The constant above is verified against exactly this component
# version. Empty desired instructions ("restore the component
# default") with any OTHER pinned version fails fast in main()
# instead of comparing against a possibly-stale constant, which
# would re-apply options and report changed on every run.
# Format matches homeassistant_custom_conversation_version (bare
# semver, no leading "v" — the tag URL template adds nothing).
DEFAULT_PROMPT_VERIFIED_VERSION = "1.6.1"

# The component validates credentials by issuing GET <base_url>/models
# (providers.LiteLLMProvider.get_supported_models). A non-200 response
# is tolerated: the call returns an empty model list, the flow advances
# to the model step, and the model field falls back to free text — so a
# Chat-Completions-only endpoint (e.g. the OpenClaw gateway, which does
# not serve /models) still completes the flow without a compatibility
# proxy. A credentials-step failure therefore means the base URL was
# unreachable at the transport level or the request was otherwise
# rejected, not merely that /models is absent.
CREDENTIALS_HINT = (
    "the component validates credentials with GET <base_url>/models; a "
    "non-200 response is tolerated (empty model list, free-text model "
    "field), so a failure here means the base URL is unreachable or the "
    "request was rejected at the transport level, not that /models is "
    "missing"
)

API_URL = ENV["HA_API_URL"].rstrip("/")
TOKEN = STDIN_SECRETS["HA_TOKEN"]
STORAGE_PATH = ENV["HA_STORAGE_PATH"]
ENABLED = ENV.get("HA_CC_ENABLED") == "1"
PROVIDER = ENV.get("HA_CC_PROVIDER", "openai")
BASE_URL = ENV.get("HA_CC_BASE_URL", "")
API_KEY = STDIN_SECRETS.get("HA_CC_API_KEY", "")
MODEL = ENV.get("HA_CC_MODEL", "")
INSTRUCTIONS = ENV.get("HA_CC_INSTRUCTIONS", "")
COMPONENT_VERSION = ENV.get("HA_CC_VERSION", "")
CANARY_TEXT = ENV.get("HA_CANARY_TEXT", "Reply with the single word OK.")
TIMEOUT = float(ENV.get("HA_TIMEOUT", "30"))
CANARY_TIMEOUT = float(ENV.get("HA_CANARY_TIMEOUT", "90"))
RESOLVE_RETRIES = int(ENV.get("HA_RESOLVE_RETRIES", "20"))
RESOLVE_DELAY = float(ENV.get("HA_RESOLVE_DELAY", "3"))
FORWARDED_FOR = ENV.get("HA_FORWARDED_FOR", "127.0.0.1")
FORWARDED_PROTO = ENV.get("HA_FORWARDED_PROTO", "http")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "X-Forwarded-For": FORWARDED_FOR,
    "X-Forwarded-Proto": FORWARDED_PROTO,
}


def ws_url(api_url: str) -> str:
    parsed = urlparse(api_url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    path = (parsed.path.rstrip("/") if parsed.path else "") + "/api/websocket"
    return urlunparse((ws_scheme, parsed.netloc, path, "", "", ""))


async def rest(session, method, path, body=None, timeout=TIMEOUT):
    global PHASE, MUTATION_ATTEMPTS
    PHASE = 'canary' if path == '/api/conversation/process' else 'configuration' if method != 'GET' else 'read'
    if method != 'GET':
        MUTATION_ATTEMPTS += 1
    url = API_URL + path
    async with session.request(
        method,
        url,
        headers=HEADERS,
        json=body,
        timeout=aiohttp.ClientTimeout(total=timeout),
    ) as resp:
        text = await resp.text()
        try:
            data = json.loads(text) if text else {}
        except ValueError:
            data = {}
        return resp.status, data


def flow_error(step, status, data, hint=""):
    global PHASE
    PHASE = step
    # Original response reason/errors can contain upstream input/body values.
    # Keep the exact failed step/status and original source-owned recovery hint.
    message = f"config flow step '{step}' failed with HTTP {status}"
    if hint:
        message += f" ({hint})"
    raise ProvisionError(message)


async def load_current():
    # A fresh HA instance has no core.config_entries yet; that means
    # "no entries", not a provisioning failure.
    try:
        with open(STORAGE_PATH, encoding="utf-8") as handle:
            stored = json.load(handle)
    except FileNotFoundError:
        return []
    entries = (stored.get("data") or {}).get("entries") or []
    return [e for e in entries if e.get("domain") == DOMAIN]


def credentials_body():
    body = {CONF_PRIMARY_API_KEY: API_KEY}
    if BASE_URL:
        body[CONF_PRIMARY_BASE_URL] = BASE_URL
    return body


def model_body():
    return {
        CONF_PRIMARY_CHAT_MODEL: MODEL,
        CONF_SECONDARY_PROVIDER_ENABLED: False,
    }


async def create_entry(session):
    status, data = await rest(
        session,
        "POST",
        "/api/config/config_entries/flow",
        {"handler": DOMAIN, "show_advanced_options": True},
    )
    if data.get("type") != "form" or data.get("step_id") != "user":
        flow_error("start", status, data)
    flow_id = data["flow_id"]
    base = f"/api/config/config_entries/flow/{flow_id}"

    status, data = await rest(session, "POST", base, {CONF_PRIMARY_PROVIDER: PROVIDER})
    if data.get("type") != "form":
        flow_error("provider", status, data)

    status, data = await rest(session, "POST", base, credentials_body())
    if data.get("type") != "form" or data.get("errors"):
        flow_error("credentials", status, data, CREDENTIALS_HINT)

    status, data = await rest(session, "POST", base, model_body())
    if data.get("type") != "create_entry":
        flow_error("model", status, data)
    return data["result"]["entry_id"]


async def reconfigure_entry(session, entry_id):
    # A reconfigure flow is started exactly the way Home Assistant's
    # own "Reconfigure" button does (frontend createConfigFlow): the
    # integration DOMAIN as the handler plus the existing entry_id.
    # The REST view's get_context() promotes a top-level entry_id to
    # context["source"] = SOURCE_RECONFIGURE and copies it to
    # context["entry_id"], which dispatches the flow to the
    # component's async_step_reconfigure. Passing the entry_id AS the
    # handler would fail (unknown handler), and a top-level "source"
    # field is ignored — entry_id is the sole reconfigure trigger.
    status, data = await rest(
        session,
        "POST",
        "/api/config/config_entries/flow",
        {
            "handler": DOMAIN,
            "entry_id": entry_id,
            "show_advanced_options": True,
        },
    )
    if data.get("type") != "form" or data.get("step_id") != "reconfigure_provider":
        flow_error("reconfigure_start", status, data)
    flow_id = data["flow_id"]
    base = f"/api/config/config_entries/flow/{flow_id}"

    status, data = await rest(session, "POST", base, {CONF_PRIMARY_PROVIDER: PROVIDER})
    if data.get("type") != "form":
        flow_error("reconfigure_provider", status, data)

    status, data = await rest(session, "POST", base, credentials_body())
    if data.get("type") != "form" or data.get("errors"):
        flow_error("reconfigure_credentials", status, data, CREDENTIALS_HINT)

    status, data = await rest(session, "POST", base, model_body())
    if not (data.get("type") == "abort" and data.get("reason") == "reconfigure_successful"):
        flow_error("reconfigure_model", status, data)


async def set_options(session, entry_id, current_options):
    # Only llm_hass_api and the instructions prompt are managed by
    # this role. Every other option section (agents, ignored
    # intents, Langfuse) is submitted back with its CURRENT stored
    # value so an operator-tuned setting survives a managed-field
    # drift repair; hardcoded values here would silently erase it.
    # Defaults below apply only when the entry has no stored value
    # yet (fresh create) and mirror the component's own defaults.
    current_options = current_options or {}
    agents = current_options.get(CONF_AGENTS_SECTION) or {}
    langfuse = current_options.get(CONF_LANGFUSE_SECTION) or {}
    ignored = current_options.get(CONF_IGNORED_INTENTS_SECTION) or {}
    # The options form schema requires ignored_intents to be a
    # LIST. An empty list is the correct "no stored value"
    # submission: the component's own handler replaces a falsy
    # list with its canonical default (llm.AssistAPI.IGNORE_INTENTS),
    # so we never hardcode that HA-version-coupled default here.
    ignored_list = ignored.get(CONF_IGNORED_INTENTS)
    if not isinstance(ignored_list, list):
        ignored_list = []
    status, data = await rest(
        session,
        "POST",
        "/api/config/config_entries/options/flow",
        {"handler": entry_id, "show_advanced_options": True},
    )
    if data.get("type") != "form" or data.get("step_id") != "init":
        flow_error("options_start", status, data)
    flow_id = data["flow_id"]
    base = f"/api/config/config_entries/options/flow/{flow_id}"
    payload = {
        CONF_LLM_HASS_API: "none",
        CONF_AGENTS_SECTION: {
            CONF_ENABLE_HASS_AGENT: agents.get(CONF_ENABLE_HASS_AGENT, True),
            CONF_ENABLE_LLM_AGENT: agents.get(CONF_ENABLE_LLM_AGENT, True),
        },
        CONF_IGNORED_INTENTS_SECTION: {CONF_IGNORED_INTENTS: ignored_list},
        CONF_CUSTOM_PROMPTS_SECTION: {CONF_INSTRUCTIONS_PROMPT: INSTRUCTIONS},
        CONF_LANGFUSE_SECTION: {
            CONF_ENABLE_LANGFUSE: langfuse.get(CONF_ENABLE_LANGFUSE, False),
            **{k: v for k, v in langfuse.items() if k != CONF_ENABLE_LANGFUSE},
        },
    }
    status, data = await rest(session, "POST", base, payload)
    if data.get("type") != "create_entry":
        flow_error("options", status, data)


def data_drift(entry):
    data = entry.get("data") or {}
    return (
        data.get(CONF_PRIMARY_PROVIDER) != PROVIDER
        or data.get(CONF_PRIMARY_BASE_URL) != BASE_URL
        or data.get(CONF_PRIMARY_CHAT_MODEL) != MODEL
        or data.get(CONF_PRIMARY_API_KEY) != API_KEY
        # The role guarantees the secondary provider stays disabled;
        # an entry with it enabled must be reconfigured.
        or bool(data.get(CONF_SECONDARY_PROVIDER_ENABLED, False))
    )


def options_drift(entry):
    options = entry.get("options") or {}
    # An empty desired prompt means "restore the component default".
    # The component stores DEFAULT_INSTRUCTIONS_PROMPT for an empty
    # submission and falls back to it when the key is absent, so both
    # sides are normalised to that default before comparison. This
    # makes clearing a previously-set custom prompt drift (and get
    # restored) while staying idempotent once restored.
    desired_instr = INSTRUCTIONS or DEFAULT_INSTRUCTIONS_PROMPT
    current_instr = (options.get(CONF_CUSTOM_PROMPTS_SECTION) or {}).get(
        CONF_INSTRUCTIONS_PROMPT
    ) or DEFAULT_INSTRUCTIONS_PROMPT
    hass_api = options.get(CONF_LLM_HASS_API)
    instr_drift = desired_instr != current_instr
    api_drift = hass_api not in (None, "none")
    return instr_drift or api_drift


async def ws_entities(session):
    global PHASE
    PHASE = "entity-registry"
    # receive_timeout bounds every subsequent read — a half-open
    # socket consumes one resolve retry instead of hanging forever.
    # Same forwarded headers as the REST calls: HA runs with
    # use_x_forwarded_for + trusted_proxies, and loopback WS
    # upgrades without the header hit the ban/forwarded middleware
    # differently than the header-carrying REST requests.
    async with session.ws_connect(
        ws_url(API_URL),
        timeout=TIMEOUT,
        receive_timeout=TIMEOUT,
        headers={
            "X-Forwarded-For": FORWARDED_FOR,
            "X-Forwarded-Proto": FORWARDED_PROTO,
        },
    ) as ws:
        hello = await ws.receive_json()
        if hello.get("type") == "auth_required":
            await ws.send_json({"type": "auth", "access_token": TOKEN})
            auth = await ws.receive_json()
        else:
            auth = hello
        if auth.get("type") != "auth_ok":
            raise ProvisionError("Home Assistant WebSocket authentication failed")
        await ws.send_json({"id": 1, "type": "config/entity_registry/list"})
        while True:
            msg = await ws.receive_json()
            if msg.get("id") == 1:
                if not msg.get("success"):
                    raise ProvisionError("entity_registry/list failed")
                return msg["result"]


async def resolve_entity(session, entry_id):
    # Transient transport failures (WS handshake, REST call, canary
    # timeout) consume one attempt like any other miss instead of
    # aborting provisioning — HA is often still settling right after
    # the restart that loaded the component.
    last_error = None
    for attempt in range(RESOLVE_RETRIES):
        try:
            entities = await ws_entities(session)
            candidates = [
                e["entity_id"]
                for e in entities
                if e.get("platform") == PLATFORM
                and (entry_id is None or e.get("config_entry_id") == entry_id)
                and str(e.get("entity_id", "")).startswith("conversation.")
            ]
            if candidates:
                entity_id = candidates[0]
                status, state = await rest(
                    session, "GET", f"/api/states/{entity_id}"
                )
                if status == 200 and (state.get("state") not in (None, "unavailable")):
                    ok = await canary(session, entity_id)
                    if ok:
                        return entity_id
        except (
            aiohttp.ClientError,
            asyncio.TimeoutError,
            OSError,
            # receive_json() surfaces closed sockets / non-text
            # frames as TypeError subclasses and malformed JSON as
            # ValueError — all transient right after the restart.
            # Deliberate RuntimeErrors (auth failure) still abort.
            TypeError,
            ValueError,
        ) as exc:
            last_error = exc
        await asyncio.sleep(RESOLVE_DELAY)
    suffix = f" Last transient error type: {type(last_error).__name__}." if last_error else ""
    raise ProvisionError(
        "Custom Conversation agent did not resolve to a live conversation "
        "entity (registry entry, non-unavailable state, and a successful "
        "conversation/process canary) within the retry budget." + suffix
    )


async def canary(session, entity_id):
    status, data = await rest(
        session,
        "POST",
        "/api/conversation/process",
        {"text": CANARY_TEXT, "agent_id": entity_id, "language": "en"},
        timeout=CANARY_TIMEOUT,
    )
    if status != 200:
        return False
    # Positive liveness only: require a well-formed response object
    # with a recognized successful type. An empty or malformed 200
    # body is a failed canary, not a pass.
    response = data.get("response")
    if not isinstance(response, dict):
        return False
    return response.get("response_type") in ("action_done", "query_answer")


def finish(result):
    # Selected entity ID remains protected process RAM at the controller. There
    # is no target result file, model speech, registry body or credential output.
    print(json.dumps({**result, 'mutation_attempts': MUTATION_ATTEMPTS}))


async def main():
    result = {
        "status": "success",
        "changed": False,
        "action": "unchanged",
        "entity_id": "",
    }
    current = await load_current()
    # Original outer task rejects duplicates even when disabling.
    if len(current) > 1:
        raise ProvisionError("multiple custom_conversation entries")
    if ENABLED and not INSTRUCTIONS and COMPONENT_VERSION != DEFAULT_PROMPT_VERIFIED_VERSION:
        raise ProvisionError(
            "empty instructions ('restore component default') are only "
            f"supported with pinned component {DEFAULT_PROMPT_VERIFIED_VERSION}; "
            "the requested version differs or is unset. Verify the new version's "
            "DEFAULT_INSTRUCTIONS_PROMPT and update the helper constant, or "
            "set explicit instructions."
        )
    async with aiohttp.ClientSession() as session:
        if not ENABLED:
            for entry in current:
                status, _ = await rest(
                    session,
                    "DELETE",
                    f"/api/config/config_entries/entry/{entry['entry_id']}",
                )
                if status != 200:
                    raise ProvisionError(
                        "failed to remove the selected config entry"
                    )
                result["changed"] = True
                result["action"] = "removed"
            finish(result)
            return

        if not current:
            entry_id = await create_entry(session)
            result["changed"] = True
            result["action"] = "created"
            if INSTRUCTIONS:
                await set_options(session, entry_id, {})
        else:
            entry = current[0]
            entry_id = entry["entry_id"]
            if data_drift(entry):
                await reconfigure_entry(session, entry_id)
                result["changed"] = True
                result["action"] = "updated"
            if options_drift(entry):
                await set_options(session, entry_id, entry.get("options"))
                result["changed"] = True
                result["action"] = "updated"

        result["entity_id"] = await resolve_entity(session, entry_id)
        finish(result)


try:
    asyncio.run(main())
except Exception as exc:
    diagnostic = str(exc) if isinstance(exc, ProvisionError) else type(exc).__name__
    print(json.dumps({'status': 'error', 'diagnostic': diagnostic,
                      'phase': PHASE, 'mutation_attempts': MUTATION_ATTEMPTS,
                      'partial_possible': MUTATION_ATTEMPTS > 0}))
    raise SystemExit(1)
