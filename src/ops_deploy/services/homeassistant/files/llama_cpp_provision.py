#!/usr/bin/env python3
"""Provision core llama_cpp through HA APIs; credentials arrive only on stdin."""

import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import aiohttp

MANAGED_TITLE = "Managed voice bridge"
TRANSIENT_ERRORS = (aiohttp.ClientError, TimeoutError)


class ProvisionError(Exception):
    """An intentionally credential-free operator diagnostic."""


class HAHTTPError(ProvisionError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"HA API request failed (HTTP {status})")


class Provisioner:
    def __init__(self, config):
        self.config = config
        self.base = config["api_url"].rstrip("/")
        self.changed = False
        self.session = None

    async def request(self, method, path, body=None, timeout=30):
        assert self.session is not None
        async with self.session.request(
            method,
            self.base + path,
            json=body,
            headers={
                "Authorization": "Bearer " + self.config["api_token"],
                "X-Forwarded-For": self.config["forwarded_for"],
                "X-Forwarded-Proto": self.config["forwarded_proto"],
            },
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=self.config.get("validate_certs", True),
        ) as response:
            if response.status not in (200, 201):
                raise HAHTTPError(response.status)
            return await response.json()

    async def websocket(self, command):
        parts = urlsplit(self.base)
        url = urlunsplit(
            (
                "wss" if parts.scheme == "https" else "ws",
                parts.netloc,
                parts.path + "/api/websocket",
                "",
                "",
            )
        )
        assert self.session is not None
        async with self.session.ws_connect(
            url,
            receive_timeout=30,
            headers={
                "X-Forwarded-For": self.config["forwarded_for"],
                "X-Forwarded-Proto": self.config["forwarded_proto"],
            },
            ssl=self.config.get("validate_certs", True),
        ) as ws:
            hello = await ws.receive_json()
            if hello.get("type") != "auth_required":
                raise ProvisionError("Unexpected HA WebSocket greeting")
            await ws.send_json(
                {"type": "auth", "access_token": self.config["api_token"]}
            )
            if (await ws.receive_json()).get("type") != "auth_ok":
                raise ProvisionError("HA WebSocket authentication failed")
            await ws.send_json({"id": 1, **command})
            while True:
                reply = await ws.receive_json()
                if reply.get("id") == 1:
                    if not reply.get("success"):
                        raise ProvisionError("HA WebSocket command failed")
                    return reply["result"]

    def stored_entry(self, entry_id):
        try:
            entries = json.loads(Path(self.config["storage_path"]).read_text())["data"][
                "entries"
            ]
        except FileNotFoundError:
            return None
        return next((e for e in entries if e["entry_id"] == entry_id), None)

    @staticmethod
    def expect_form(reply, step):
        if (
            reply.get("type") != "form"
            or reply.get("step_id") != step
            or reply.get("errors")
        ):
            raise ProvisionError(f"llama_cpp config flow failed at {step}")

    async def entries(self, domain, check_unmarked=False):
        entries = await self.request(
            "GET", "/api/config/config_entries/entry?domain=" + domain
        )
        if domain == "llama_cpp":
            # The config flow can persist a credential before the separate
            # managed-title update succeeds. Refuse an ambiguous retry rather
            # than creating a second entry or leaving its credential invisible.
            for entry in entries if check_unmarked else []:
                if entry.get("title") == MANAGED_TITLE:
                    continue
                stored = self.stored_entry(entry["entry_id"])
                if (
                    entry.get("title", "").rstrip("/")
                    == self.config["base_url"].rstrip("/")
                ) or (
                    stored
                    and stored.get("data", {}).get("base_url", "").rstrip("/")
                    == self.config["base_url"].rstrip("/")
                ):
                    raise ProvisionError(
                        "Unmarked llama_cpp entry uses the configured endpoint; "
                        "verify ownership and rename it to Managed voice bridge, "
                        "or remove it in HA before redeploying"
                    )
            entries = [
                entry for entry in entries if entry.get("title") == MANAGED_TITLE
            ]
        if len(entries) > 1:
            raise ProvisionError(f"Multiple {domain} entries; refusing to choose")
        return entries

    async def local_fallback(self, entry_ids):
        entities = await self.websocket({"type": "config/entity_registry/list"})
        agents = {
            e["entity_id"] for e in entities if e.get("config_entry_id") in entry_ids
        }
        pipelines = await self.websocket({"type": "assist_pipeline/pipeline/list"})
        for pipeline in pipelines["pipelines"]:
            if pipeline.get("conversation_engine") not in agents:
                continue
            allowed = {
                "name",
                "language",
                "conversation_engine",
                "conversation_language",
                "stt_engine",
                "stt_language",
                "tts_engine",
                "tts_language",
                "tts_voice",
                "wake_word_entity",
                "wake_word_id",
                "prefer_local_intents",
                "acknowledge_media_id",
            }
            await self.websocket(
                {
                    **{k: v for k, v in pipeline.items() if k in allowed},
                    "type": "assist_pipeline/pipeline/update",
                    "pipeline_id": pipeline["id"],
                    "conversation_engine": "conversation.home_assistant",
                }
            )
            self.changed = True

    async def retire_legacy(self):
        entries = await self.entries("custom_conversation")
        if entries:
            await self.local_fallback({entry["entry_id"] for entry in entries})
        for entry in entries:
            reply = await self.request(
                "DELETE", "/api/config/config_entries/entry/" + entry["entry_id"]
            )
            if reply.get("require_restart"):
                raise ProvisionError(
                    "Legacy integration removal requires an HA restart"
                )
            self.changed = True
        return {"changed": self.changed}

    async def disable(self):
        entries = await self.entries("llama_cpp")
        if entries:
            await self.local_fallback({entry["entry_id"] for entry in entries})
        for entry in entries:
            await self.request(
                "DELETE", "/api/config/config_entries/entry/" + entry["entry_id"]
            )
            self.changed = True
        return {"changed": self.changed, "entity_id": ""}

    async def create(self):
        reply = await self.request(
            "POST", "/api/config/config_entries/flow", {"handler": "llama_cpp"}
        )
        self.expect_form(reply, "user")
        path = "/api/config/config_entries/flow/" + reply["flow_id"]
        reply = await self.request(
            "POST",
            path,
            {
                "base_url": self.config["base_url"],
                "api_key": self.config["api_key"],
            },
        )
        self.expect_form(reply, "model")
        reply = await self.request(
            "POST", path, {"chat_model": self.config["model"]}, timeout=120
        )
        if reply.get("type") != "create_entry":
            raise ProvisionError("llama_cpp model validation failed")
        entry_id = reply["result"]["entry_id"]
        await self.websocket(
            {
                "type": "config_entries/update",
                "entry_id": entry_id,
                "title": MANAGED_TITLE,
            }
        )
        self.changed = True
        return entry_id

    async def wait_subentry(self, entry_id):
        for _ in range(30):
            entries = await self.websocket(
                {"type": "config_entries/subentries/list", "entry_id": entry_id}
            )
            if len(entries) == 1 and entries[0].get("subentry_type") == "conversation":
                return entries[0]["subentry_id"]
            if entries:
                raise ProvisionError(
                    "Expected exactly one llama_cpp conversation subentry"
                )
            await asyncio.sleep(2)
        raise ProvisionError("llama_cpp conversation subentry did not appear")

    async def configure_subentry(self, entry_id, subentry_id, stored):
        desired = {
            "chat_model": self.config["model"],
            # Core's TemplateSelector trims surrounding whitespace on storage.
            "prompt": self.config["instructions"].strip(),
            "llm_hass_api": [],
            "recommended": True,
        }
        normalized = dict(stored or {})
        normalized["llm_hass_api"] = normalized.get("llm_hass_api") or []
        if stored is not None and all(
            normalized.get(k) == v for k, v in desired.items()
        ):
            return
        reply = await self.request(
            "POST",
            "/api/config/config_entries/subentries/flow",
            {
                "handler": [entry_id, "conversation"],
                "subentry_id": subentry_id,
            },
        )
        self.expect_form(reply, "init")
        path = "/api/config/config_entries/subentries/flow/" + reply["flow_id"]
        reply = await self.request("POST", path, desired, timeout=120)
        # Toggling recommended settings returns the expanded/contracted form.
        if reply.get("type") == "form":
            self.expect_form(reply, "init")
            reply = await self.request("POST", path, desired, timeout=120)
        if (
            reply.get("type") != "abort"
            or reply.get("reason") != "reconfigure_successful"
        ):
            raise ProvisionError("llama_cpp conversation options update failed")
        self.changed = True

    async def resolve_and_canary(self, entry_id, subentry_id):
        try:
            async with asyncio.timeout(180):
                return await self._resolve_and_canary(entry_id, subentry_id)
        except TimeoutError:
            raise ProvisionError(
                "llama_cpp entity did not answer the conversation canary within 180 seconds"
            ) from None

    async def _resolve_and_canary(self, entry_id, subentry_id):
        for _ in range(30):
            try:
                entries = await self.websocket({"type": "config/entity_registry/list"})
                entities = [
                    e["entity_id"]
                    for e in entries
                    if e.get("platform") == "llama_cpp"
                    and e.get("config_entry_id") == entry_id
                    and e.get("config_subentry_id") == subentry_id
                    and e.get("entity_id", "").startswith("conversation.")
                    and not e.get("disabled_by")
                ]
                if len(entities) > 1:
                    raise ProvisionError("Ambiguous llama_cpp conversation entities")
                if len(entities) == 1:
                    reply = await self.request(
                        "POST",
                        "/api/conversation/process",
                        {
                            "agent_id": entities[0],
                            "text": self.config["canary_text"],
                            "language": "en",
                        },
                        timeout=120,
                    )
                    response = reply.get("response", {})
                    speech = (
                        response.get("speech", {}).get("plain", {}).get("speech", "")
                    )
                    if response.get("response_type") != "error" and speech.strip():
                        return entities[0]
            except HAHTTPError as exc:
                if exc.status not in (400, 404) and exc.status < 500:
                    raise
            except TRANSIENT_ERRORS:
                pass
            await asyncio.sleep(2)
        raise ProvisionError("llama_cpp entity did not answer the conversation canary")

    async def ensure(self):
        current = await self.entries("llama_cpp", check_unmarked=True)
        stored = self.stored_entry(current[0]["entry_id"]) if current else None
        if current and stored is None:
            raise ProvisionError(
                "Live llama_cpp entry is not yet persisted; retry deployment"
            )
        if stored and (
            stored.get("data", {}).get("base_url", "").rstrip("/")
            != self.config["base_url"].rstrip("/")
            or stored.get("data", {}).get("api_key") != self.config["api_key"]
        ):
            # Core exposes no connection reconfigure flow. Recreate only our
            # single managed entry; pipeline entity IDs are resolved afterwards.
            await self.local_fallback({current[0]["entry_id"]})
            await self.request(
                "DELETE", "/api/config/config_entries/entry/" + current[0]["entry_id"]
            )
            current, stored = [], None
            self.changed = True
        entry_id = current[0]["entry_id"] if current else await self.create()
        subentry_id = await self.wait_subentry(entry_id)
        previous = (
            next(
                (
                    s["data"]
                    for s in stored.get("subentries", [])
                    if s["subentry_id"] == subentry_id
                ),
                None,
            )
            if stored
            else None
        )
        await self.configure_subentry(entry_id, subentry_id, previous)
        entity_id = await self.resolve_and_canary(entry_id, subentry_id)
        return {"changed": self.changed, "entity_id": entity_id}

    async def run(self):
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            self.session = session
            if self.config["action"] == "retire":
                return await self.retire_legacy()
            if self.config["action"] == "disable":
                return await self.disable()
            return await self.ensure()


def main():
    try:
        result = asyncio.run(Provisioner(json.load(sys.stdin)).run())
    except Exception as exc:  # noqa: BLE001
        # Never serialize upstream responses, request URLs, or exception text:
        # they can contain either the HA token or the gateway credential.
        detail = str(exc) if isinstance(exc, ProvisionError) else type(exc).__name__
        print(json.dumps({"error": detail}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
