"""Render the original cf3 runtime resources; secrets remain explicitly wrapped."""

from __future__ import annotations

import json
import re
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretContent

from .config import DaybookRuntimeConfig

PACKAGE = "ops_deploy.services.daybook_operations_runtime"
IMPORTER_ADAPTERS = ("voice_memos.ingest.v1", "voice_memos.transcribe_long.v1")


def role_values(cfg: DaybookRuntimeConfig) -> dict[str, Any]:
    values = {"daybook_operations_runtime_" + k: v for k, v in cfg.model_dump(mode="json").items()}
    values["daybook_operations_runtime_kinds"] = [k.model_dump(exclude_none=True) for k in cfg.kinds]
    values["daybook_operations_runtime_importer_adapters"] = IMPORTER_ADAPTERS
    return values


def render_resource(cfg: DaybookRuntimeConfig, template: str) -> str:
    if template not in {"policy.json.j2", "runtime.plist.j2"}:
        raise ValueError("unsupported public runtime resource")
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["combine"] = lambda left, right: {**left, **right}
    env.filters["to_nice_json"] = lambda value: json.dumps(value, indent=4, sort_keys=True, ensure_ascii=True)
    return env.get_template(template).render(role_values(cfg))


def credential_text(token: str) -> str:
    """One original credential encoding shared by installer and observer."""
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", token) or "CHANGEME" in token:
        raise ValueError("runtime executor credential is invalid")
    return json.dumps({"token": token}, indent=4, sort_keys=True) + "\n"


def render_credential(token: str) -> SecretContent:
    return SecretContent(credential_text(token))
