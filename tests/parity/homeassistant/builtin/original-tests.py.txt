"""Exercise the provisioner's public workflow at the HA transport boundary."""

import copy
import importlib.util
import unittest
from unittest.mock import AsyncMock, patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "llama_cpp_provision",
    ROOT / "roles/homeassistant_deploy/files/llama_cpp_provision.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def settings():
    return {
        "action": "ensure",
        "api_url": "http://localhost:10020",
        "api_token": "fixture-ha",  # pragma: allowlist secret
        "api_key": "fixture-gateway",  # pragma: allowlist secret
        "base_url": "http://localhost:18789/v1",
        "model": "openclaw",
        "instructions": "Shared family microphone; answer briefly.",
        "canary_text": "Say OK",
        "storage_path": "/unused",
        "forwarded_for": "127.0.0.1",
        "forwarded_proto": "http",
    }


class FakeHA(MODULE.Provisioner):
    def __init__(self):
        super().__init__(settings())
        self.calls = []
        self.current = None
        self.foreign = [{"entry_id": "foreign", "title": "My real llama server"}]
        self.foreign_storage = {}
        self.legacy = []
        self.pipelines = [
            {
                "id": "de",
                "name": "Home Assistant DE",
                "language": "de",
                "conversation_engine": "conversation.old",
                "prefer_local_intents": True,
                "tts_voice": "retained",
                "acknowledge_media_id": "retained-chime",
            }
        ]
        self.flow_step = None
        self.flow_errors = False
        self.toggle_form = False
        self.canary_error = False
        self.canary_http_errors = []
        self.rename_error = False

    def stored_entry(self, entry_id):
        if self.current and self.current["entry_id"] == entry_id:
            return copy.deepcopy(self.current)
        return copy.deepcopy(self.foreign_storage.get(entry_id))

    async def request(self, method, path, body=None, timeout=30):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == "GET":
            if path.endswith("domain=custom_conversation"):
                return self.legacy
            return self.foreign + ([self.current] if self.current else [])
        if method == "DELETE":
            if path.endswith("old"):
                self.legacy = []
            else:
                self.current = None
            return {"require_restart": False}
        if path == "/api/config/config_entries/flow":
            self.flow_step = "user"
            return {"type": "form", "step_id": "user", "flow_id": "new"}
        if path.endswith("/flow/new"):
            if self.flow_step == "user":
                self.flow_step = "model"
                self.connection = body
                return {"type": "form", "step_id": "model"}
            if self.flow_errors:
                return {
                    "type": "form",
                    "step_id": "model",
                    "errors": {"base": "unknown"},
                }
            self.current = {
                "entry_id": "managed",
                "title": self.config["base_url"],
                "data": self.connection,
                "subentries": [{"subentry_id": "sub", "data": {}}],
            }
            return {"type": "create_entry", "result": {"entry_id": "managed"}}
        if path == "/api/config/config_entries/subentries/flow":
            return {"type": "form", "step_id": "init", "flow_id": "options"}
        if path.endswith("/flow/options"):
            if self.toggle_form:
                self.toggle_form = False
                return {"type": "form", "step_id": "init"}
            self.current["subentries"][0]["data"] = body
            return {"type": "abort", "reason": "reconfigure_successful"}
        if path == "/api/conversation/process":
            if self.canary_http_errors:
                raise MODULE.HAHTTPError(self.canary_http_errors.pop(0))
            if self.canary_error:
                raise MODULE.ProvisionError("Injected canary failure")
            assert self.current["subentries"][0]["data"].get("llm_hass_api", []) == []
            return {
                "response": {
                    "response_type": "action_done",
                    "speech": {"plain": {"speech": "OK"}},
                }
            }
        raise AssertionError((method, path, body))

    async def websocket(self, command):
        self.calls.append(("WS", command["type"], copy.deepcopy(command)))
        kind = command["type"]
        if kind == "config_entries/update":
            if self.rename_error:
                raise MODULE.ProvisionError("Injected title-update failure")
            self.current["title"] = command["title"]
            return {}
        if kind == "config_entries/subentries/list":
            return [{"subentry_id": "sub", "subentry_type": "conversation"}]
        if kind == "config/entity_registry/list":
            return [
                {
                    "entity_id": "conversation.builtin",
                    "platform": "llama_cpp",
                    "config_entry_id": "managed",
                    "config_subentry_id": "sub",
                },
                {
                    "entity_id": "conversation.old",
                    "platform": "custom_conversation",
                    "config_entry_id": "old",
                },
                {
                    "entity_id": "conversation.foreign",
                    "platform": "llama_cpp",
                    "config_entry_id": "foreign",
                },
            ]
        if kind == "assist_pipeline/pipeline/list":
            return {"pipelines": self.pipelines, "preferred_pipeline": "de"}
        if kind == "assist_pipeline/pipeline/update":
            self.pipelines[0].update(
                {k: v for k, v in command.items() if k not in ("type", "pipeline_id")}
            )
            return {}
        raise AssertionError(command)


class ProvisionTests(unittest.IsolatedAsyncioTestCase):
    async def test_create_sets_no_tools_before_canary(self):
        ha = FakeHA()
        result = await ha.ensure()
        self.assertEqual(result, {"changed": True, "entity_id": "conversation.builtin"})
        self.assertEqual(ha.current["title"], MODULE.MANAGED_TITLE)
        self.assertEqual(
            ha.current["subentries"][0]["data"]["prompt"], ha.config["instructions"]
        )
        self.assertFalse(any(c[0] == "DELETE" for c in ha.calls))

    async def test_repeat_is_idempotent_but_still_checks_canary(self):
        ha = FakeHA()
        await ha.ensure()
        ha.calls = []
        ha.changed = False
        result = await ha.ensure()
        self.assertFalse(result["changed"])
        self.assertEqual(
            [c[1] for c in ha.calls if c[0] == "POST"], ["/api/conversation/process"]
        )

    async def test_yaml_block_prompt_matches_core_trimmed_storage(self):
        ha = FakeHA()
        ha.config["instructions"] = "\n  Shared microphone.\nKeep replies brief.\n"
        await ha.ensure()
        stored = ha.current["subentries"][0]["data"]
        self.assertEqual(stored["prompt"], "Shared microphone.\nKeep replies brief.")
        ha.calls = []
        ha.changed = False
        result = await ha.ensure()
        self.assertFalse(result["changed"])
        self.assertEqual(
            [c[1] for c in ha.calls if c[0] == "POST"], ["/api/conversation/process"]
        )

    async def test_prompt_and_control_drift_repaired_without_recreating(self):
        ha = FakeHA()
        await ha.ensure()
        ha.current["subentries"][0]["data"]["llm_hass_api"] = ["assist"]
        ha.config["instructions"] = "Updated prompt"
        ha.calls = []
        ha.changed = False
        await ha.ensure()
        self.assertTrue(ha.changed)
        self.assertFalse(any(c[0] == "DELETE" for c in ha.calls))
        self.assertEqual(ha.current["subentries"][0]["data"]["llm_hass_api"], [])

    async def test_key_rotation_recreates_only_managed_entry_after_local_fallback(self):
        ha = FakeHA()
        await ha.ensure()
        ha.pipelines[0]["conversation_engine"] = "conversation.builtin"
        ha.config["api_key"] = "rotated-fixture"  # pragma: allowlist secret
        ha.calls = []
        await ha.ensure()
        deletes = [c for c in ha.calls if c[0] == "DELETE"]
        self.assertEqual(len(deletes), 1)
        self.assertTrue(deletes[0][1].endswith("managed"))
        kinds = [c[1] for c in ha.calls]
        self.assertLess(
            kinds.index("assist_pipeline/pipeline/update"), kinds.index(deletes[0][1])
        )
        self.assertEqual(ha.foreign[0]["entry_id"], "foreign")

    async def test_retirement_preserves_local_voice_before_removing_agent(self):
        ha = FakeHA()
        ha.legacy = [{"entry_id": "old"}]
        await ha.retire_legacy()
        self.assertEqual(
            ha.pipelines[0]["conversation_engine"], "conversation.home_assistant"
        )
        self.assertTrue(ha.pipelines[0]["prefer_local_intents"])
        self.assertEqual(ha.pipelines[0]["tts_voice"], "retained")
        self.assertEqual(ha.pipelines[0]["acknowledge_media_id"], "retained-chime")
        self.assertLess(
            next(
                i
                for i, c in enumerate(ha.calls)
                if c[1] == "assist_pipeline/pipeline/update"
            ),
            next(i for i, c in enumerate(ha.calls) if c[0] == "DELETE"),
        )

    async def test_disabled_removes_only_managed_entry(self):
        ha = FakeHA()
        await ha.ensure()
        ha.pipelines[0]["conversation_engine"] = "conversation.builtin"
        ha.calls = []
        await ha.disable()
        self.assertIsNone(ha.current)
        self.assertEqual(len(ha.foreign), 1)
        self.assertEqual(
            ha.pipelines[0]["conversation_engine"], "conversation.home_assistant"
        )

    async def test_disable_preserves_foreign_entry_at_same_endpoint(self):
        ha = FakeHA()
        await ha.ensure()
        ha.foreign_storage["foreign"] = {"data": {"base_url": ha.config["base_url"]}}
        ha.pipelines[0]["conversation_engine"] = "conversation.builtin"
        ha.calls = []
        await ha.disable()
        self.assertIsNone(ha.current)
        self.assertEqual(ha.foreign[0]["entry_id"], "foreign")
        self.assertEqual(
            ha.pipelines[0]["conversation_engine"], "conversation.home_assistant"
        )
        self.assertEqual(
            [c[1] for c in ha.calls if c[0] == "DELETE"],
            ["/api/config/config_entries/entry/managed"],
        )

    async def test_canary_deadline_has_sanitized_operator_diagnostic(self):
        ha = FakeHA()
        with patch.object(
            ha, "_resolve_and_canary", new_callable=AsyncMock, side_effect=TimeoutError
        ):
            with self.assertRaisesRegex(MODULE.ProvisionError, "canary within 180"):
                await ha.resolve_and_canary("managed", "sub")

    async def test_duplicate_managed_entries_fail_before_mutation(self):
        ha = FakeHA()
        ha.foreign = [
            {"entry_id": str(i), "title": MODULE.MANAGED_TITLE} for i in range(2)
        ]
        with self.assertRaisesRegex(MODULE.ProvisionError, "Multiple"):
            await ha.ensure()
        self.assertTrue(all(c[0] == "GET" for c in ha.calls))

    async def test_recommended_toggle_form_is_completed(self):
        ha = FakeHA()
        ha.toggle_form = True
        await ha.ensure()
        self.assertEqual(sum(c[1].endswith("/flow/options") for c in ha.calls), 2)

    async def test_model_validation_failure_prevents_canary(self):
        ha = FakeHA()
        ha.flow_errors = True
        with self.assertRaisesRegex(MODULE.ProvisionError, "model validation"):
            await ha.ensure()
        self.assertFalse(any(c[1] == "/api/conversation/process" for c in ha.calls))

    async def test_transient_http_error_retried_after_entry_reload(self):
        for status in (400, 404, 503):
            with self.subTest(status=status):
                ha = FakeHA()
                ha.canary_http_errors = [status]
                with patch.object(MODULE.asyncio, "sleep", new_callable=AsyncMock):
                    result = await ha.ensure()
                self.assertEqual(result["entity_id"], "conversation.builtin")
                self.assertEqual(
                    sum(c[1] == "/api/conversation/process" for c in ha.calls), 2
                )

    async def test_auth_error_fails_without_retry(self):
        ha = FakeHA()
        ha.canary_http_errors = [401]
        with self.assertRaises(MODULE.HAHTTPError):
            await ha.ensure()
        self.assertEqual(sum(c[1] == "/api/conversation/process" for c in ha.calls), 1)

    async def test_interrupted_title_update_cannot_create_duplicate(self):
        ha = FakeHA()
        ha.rename_error = True
        with self.assertRaisesRegex(MODULE.ProvisionError, "title-update"):
            await ha.ensure()
        ha.rename_error = False
        ha.calls = []
        with self.assertRaisesRegex(MODULE.ProvisionError, "Unmarked"):
            await ha.ensure()
        self.assertTrue(all(c[0] == "GET" for c in ha.calls))

    async def test_absent_no_tools_and_trailing_slash_are_equivalent(self):
        ha = FakeHA()
        await ha.ensure()
        del ha.current["subentries"][0]["data"]["llm_hass_api"]
        ha.current["data"]["base_url"] += "/"
        ha.calls = []
        ha.changed = False
        # A missing llm_hass_api is also a no-tools configuration in core.
        result = await ha.ensure()
        self.assertEqual(result["entity_id"], "conversation.builtin")
        self.assertFalse(ha.changed)
        self.assertFalse(
            any(c[0] == "DELETE" or c[1].endswith("/flow/options") for c in ha.calls)
        )

    async def test_canary_failure_does_not_return_entity(self):
        ha = FakeHA()
        ha.canary_error = True
        with self.assertRaisesRegex(MODULE.ProvisionError, "canary"):
            await ha.ensure()


if __name__ == "__main__":
    unittest.main()
