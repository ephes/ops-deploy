"""Exact original Inbox resources; credential bodies remain secret values."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.resources import files

import jinja2

from ops_deploy.core.secrets import SecretContent

from .config import PACKAGE, DaybookInboxConfig

SECRET_DEFAULTS: dict[str, str] = json.loads(files(PACKAGE).joinpath("secret_defaults.json").read_text())


def role_values(cfg: DaybookInboxConfig, secrets: Mapping[str, str]) -> dict[str, object]:
    if set(secrets) - set(SECRET_DEFAULTS):
        raise ValueError("Unsupported Inbox credential field")
    if cfg.daybook_voice_memo_inbox_enabled and any(
        not isinstance(secrets.get(key), str) or not secrets[key].strip() or secrets[key] == "CHANGEME"
        for key in SECRET_DEFAULTS
    ):
        raise ValueError("Inbox required credentials are incomplete")
    if any(not isinstance(value, str) or "\x00" in value for value in secrets.values()):
        raise ValueError("Inbox credential type is invalid")
    return {**cfg.model_dump(mode="json"), **SECRET_DEFAULTS, **secrets}


def render_template(name: str, values: Mapping[str, object]) -> str:
    if name not in {
        "policy.json.j2",
        "credentials.json.j2",
        "voice-memo-inbox.launchd.plist.j2",
        "voice-memo-inbox-long.launchd.plist.j2",
    }:
        raise ValueError("Inbox template must be an original packaged basename")
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(bool=bool, to_json=json.dumps)
    return env.get_template(name).render(values)


@dataclass(frozen=True)
class InboxResource:
    path: str
    owner: str
    group: str
    mode: int
    content: SecretContent


@dataclass(frozen=True)
class _InboxResourceText:
    """Private expected text, like Sessions' internal resource rendering."""

    path: str
    owner: str
    group: str
    mode: int
    content: str = field(repr=False)


def _resource_texts(cfg: DaybookInboxConfig, secrets: Mapping[str, str]) -> tuple[_InboxResourceText, ...]:
    if not cfg.daybook_voice_memo_inbox_enabled:
        return ()
    values = role_values(cfg, secrets)
    rows = [
        ("policy.json.j2", cfg.daybook_voice_memo_inbox_policy_path, "root", "wheel", 0o644),
        (
            "credentials.json.j2",
            cfg.daybook_voice_memo_inbox_credential_path,
            cfg.daybook_voice_memo_inbox_service_user,
            "staff",
            0o600,
        ),
        ("voice-memo-inbox.launchd.plist.j2", cfg.daybook_voice_memo_inbox_plist_path, "root", "wheel", 0o644),
    ]
    if cfg.daybook_voice_memo_inbox_long_label_enabled:
        rows.append(
            (
                "voice-memo-inbox-long.launchd.plist.j2",
                cfg.daybook_voice_memo_inbox_long_plist_path,
                "root",
                "wheel",
                0o644,
            )
        )
    return tuple(
        _InboxResourceText(path, owner, group, mode, render_template(name, values))
        for name, path, owner, group, mode in rows
    )


def resources(cfg: DaybookInboxConfig, secrets: Mapping[str, str]) -> tuple[InboxResource, ...]:
    """Public rendered values remain wrapped; only secret_stdin unwraps content."""
    return tuple(
        InboxResource(row.path, row.owner, row.group, row.mode, SecretContent(row.content))
        for row in _resource_texts(cfg, secrets)
    )
