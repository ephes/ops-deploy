"""Pure monitor endpoint client; never invokes executor status or local Journal.

Only the reviewed deployed schema-one surface is accepted. Tokens and the full
response stay in memory. Exceptions contain fixed categories, never HTTP bodies,
URLs, credentials or arbitrary server values.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ops_deploy.core.secrets import SecretValues

MAX_STATUS_BYTES = 256 * 1024
STATUS_TIMEOUT = 30
STATES = {"pending", "assigned", "awaiting_apply", "needs_reconciliation", "failed"}


class StatusError(RuntimeError):
    """A sanitized failure; a failed monitor is never treated as successful."""


@dataclass(frozen=True)
class SourceStatus:
    binding: str
    enabled: bool
    active_state: str | None
    expiry_pending: bool
    unapplied_receipts: int
    needs_operator: bool


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StatusError("monitor_invalid_json")
        result[key] = value
    return result


def _sources(sources: Sequence[str]) -> None:
    if (
        not sources
        or len(set(sources)) != len(sources)
        or any(not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,49}", source) for source in sources)
    ):
        raise StatusError("monitor_invalid_sources")


def _invalid_constant(value: str) -> Any:
    raise StatusError("monitor_invalid_json")


def parse_status(body: bytes, sources: Sequence[str]) -> tuple[SourceStatus, ...]:
    """Keep exactly six reviewed metadata fields for each declared source."""
    _sources(sources)
    if len(body) > MAX_STATUS_BYTES:
        raise StatusError("monitor_response_too_large")
    try:
        payload = json.loads(body, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise StatusError("monitor_invalid_json") from None
    if (
        not isinstance(payload, dict)
        or type(payload.get("schema")) is not int
        or payload["schema"] != 1
        or not isinstance(payload.get("bindings"), list)
        or len(payload["bindings"]) > 1024
    ):
        raise StatusError("monitor_invalid_schema")
    selected: dict[str, SourceStatus] = {}
    for row in payload["bindings"]:
        if not isinstance(row, dict) or not isinstance(row.get("binding"), str):
            raise StatusError("monitor_invalid_schema")
        name = row["binding"]
        if name not in sources:
            continue
        if name in selected:
            raise StatusError("monitor_duplicate_source")
        state = row.get("active_state")
        if (
            "active_state" not in row
            or (state is not None and (not isinstance(state, str) or state not in STATES))
            or any(type(row.get(key)) is not bool for key in ("enabled", "expiry_pending", "needs_operator"))
            or type(row.get("unapplied_receipts")) is not int
            or row["unapplied_receipts"] < 0
        ):
            raise StatusError("monitor_invalid_schema")
        selected[name] = SourceStatus(
            name, row["enabled"], state, row["expiry_pending"], row["unapplied_receipts"], row["needs_operator"]
        )
    if set(selected) != set(sources):
        raise StatusError("monitor_missing_source")
    return tuple(selected[name] for name in sources)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def fetch_status(origin: str, monitor_access: SecretValues, sources: Sequence[str]) -> tuple[SourceStatus, ...]:
    """One HTTPS GET using an existing monitor-purpose token. No fallback/retry.

    ``monitor_access["monitor_token"]`` is the existing monitor-purpose token.
    This is deliberately separate from the runtime's executor credential. Server
    purpose checks are authoritative: an executor token produces a real failure.
    """
    _sources(sources)
    try:
        parsed = urlsplit(origin)
    except ValueError:
        raise StatusError("monitor_invalid_origin") from None
    if (
        parsed.scheme != "https"
        or origin != f"https://{parsed.netloc}"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in origin)
    ):
        raise StatusError("monitor_invalid_origin")
    try:
        _ = parsed.port
        token = monitor_access["monitor_token"]
    except (KeyError, ValueError):
        raise StatusError("monitor_invalid_access") from None
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", token) or "CHANGEME" in token:
        raise StatusError("monitor_invalid_access")
    request = urllib.request.Request(
        origin + "/v1/status", headers={"Authorization": "Bearer " + token, "Accept": "application/json"}, method="GET"
    )
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(request, timeout=STATUS_TIMEOUT) as response:
            if response.status != 200:
                raise StatusError("monitor_http_failed")
            body = response.read(MAX_STATUS_BYTES + 1)
    except urllib.error.HTTPError as error:
        # Close without reading or serializing the potentially sensitive body.
        error.close()
        raise StatusError("monitor_http_failed") from None
    except (OSError, ValueError):
        raise StatusError("monitor_transport_failed") from None
    return parse_status(body, sources)
