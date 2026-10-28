"""Original role resources, keeping environment bodies out of argument reprs."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretContent

from .config import PACKAGE, DaybookSessionsConfig

SECRET_DEFAULTS: dict[str, str] = json.loads(files(PACKAGE).joinpath("secret_defaults.json").read_text())


def role_values(
    cfg: DaybookSessionsConfig, secrets: Mapping[str, str], *, identity_verified: bool = False
) -> dict[str, Any]:
    if set(secrets) - set(SECRET_DEFAULTS):
        raise ValueError("Unsupported Sessions secret field")
    values = {**cfg.model_dump(mode="json"), **SECRET_DEFAULTS, **secrets}
    if not cfg.daybook_sessions_enabled:
        return values
    required = {"daybook_sessions_aws_access_key_id", "daybook_sessions_aws_secret_access_key"}
    if cfg.daybook_archive_quote_classifier_enabled:
        required.add("daybook_archive_token")
    if cfg.daybook_weeknotes_reconcile_enabled:
        required.update(
            {
                "daybook_weeknotes_cast_token",
                "daybook_weeknotes_home_token",
                "daybook_weeknotes_public_repositories_json",
                "daybook_weeknotes_confidential_names_json",
            }
        )
    if any(
        not isinstance(values[key], str) or not values[key].strip() or values[key] == "CHANGEME" for key in required
    ):
        raise ValueError("Sessions required credentials are incomplete")
    if any(not isinstance(values[key], str) or "\x00" in values[key] for key in SECRET_DEFAULTS):
        raise ValueError("Sessions credential type is invalid")
    if cfg.daybook_sessions_aws_endpoint_url_s3 in {"", "CHANGEME"}:
        raise ValueError("Sessions storage endpoint is missing")
    if cfg.daybook_archive_quote_classifier_enabled or cfg.daybook_weeknotes_reconcile_enabled:
        if not re.fullmatch(r"https://[^/?#]+(?:/[^?#]*)?", cfg.daybook_archive_url):
            raise ValueError("Archive endpoint must use the original HTTPS contract")
        if cfg.daybook_archive_url == "CHANGEME":
            raise ValueError("Archive endpoint is missing")
        for key in ("daybook_quotes_unused_path", "daybook_quotes_used_path", "daybook_quote_lifecycle_state"):
            if values[key] in {"", "CHANGEME"}:
                raise ValueError("Quote storage declaration is incomplete")
    if cfg.daybook_weeknotes_reconcile_enabled:
        try:
            repositories = json.loads(values["daybook_weeknotes_public_repositories_json"])
            names = json.loads(values["daybook_weeknotes_confidential_names_json"])
        except (ValueError, TypeError):
            raise ValueError("Weeknotes public/private metadata shape is invalid") from None
        if (
            not isinstance(repositories, dict)
            or not repositories
            or not isinstance(names, list)
            or any(not isinstance(v, str) for v in names)
        ):
            raise ValueError("Weeknotes public/private metadata shape is invalid")
        for url in (cfg.daybook_weeknotes_cast_base_url, cfg.daybook_weeknotes_home_url):
            if not re.fullmatch(r"https://[^/?#]+(?:/[^?#]*)?", url):
                raise ValueError("Weeknotes endpoints must use the original HTTPS contract")
        ids = (cfg.daybook_weeknotes_public_blog_id, cfg.daybook_weeknotes_family_blog_id)
        if any(not re.fullmatch(r"[1-9][0-9]*", value) for value in ids) or ids[0] == ids[1]:
            raise ValueError("Weeknotes requires distinct positive blog IDs")
        if not cfg.daybook_weeknotes_path.startswith("s3://"):
            raise ValueError("Weeknotes requires its original S3 path")
        if cfg.daybook_weeknotes_post_identity_epoch and not identity_verified:
            raise ValueError("Existing Weeknotes identity proof must be verified before rendering its epoch")
    values["daybook_weeknotes_identity_attestation_verified"] = identity_verified
    return values


def render_template(template: str, values: Mapping[str, Any]) -> str:
    if not template.endswith(".j2") or "/" in template or "\\" in template:
        raise ValueError("Sessions template must be a packaged basename")
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(quote=shlex.quote, bool=bool, ternary=lambda condition, yes, no: yes if condition else no)
    return env.get_template(template).render(values)


@dataclass(frozen=True)
class SessionResource:
    path: str
    owner: str
    group: str
    mode: int
    content: str | SecretContent


@dataclass(frozen=True)
class _ResourceText:
    path: str
    owner: str
    group: str
    mode: int
    content: str = field(repr=False)
    private: bool = False


def _resource_texts(
    cfg: DaybookSessionsConfig, secrets: Mapping[str, str], *, identity_verified: bool = False
) -> tuple[_ResourceText, ...]:
    if not cfg.daybook_sessions_enabled:
        return ()
    values = role_values(cfg, secrets, identity_verified=identity_verified)
    user, group = cfg.daybook_sessions_service_user, cfg.daybook_sessions_service_group
    system_owner, system_group = ("root", "wheel") if cfg.daybook_sessions_launchd_scope == "system" else (user, group)
    rendered: list[_ResourceText] = []

    def add(template: str, path: str, owner: str, file_group: str, mode: int, *, secret: bool = False) -> None:
        body = render_template(template, values)
        rendered.append(_ResourceText(path, owner, file_group, mode, body, secret))

    add("sessions.env.j2", cfg.daybook_sessions_env_file, user, group, 0o600, secret=True)
    add("ship-sessions.sh.j2", cfg.daybook_sessions_launcher_path, system_owner, system_group, 0o755)
    if cfg.daybook_sessions_launchd_enabled:
        add("sessions.launchd.plist.j2", cfg.daybook_sessions_launchd_plist_path, system_owner, system_group, 0o644)
    if cfg.daybook_archive_quote_classifier_enabled:
        add("archive-quotes.env.j2", cfg.daybook_archive_quote_classifier_env_file, user, group, 0o600, secret=True)
        add(
            "classify-archive-quotes.sh.j2",
            cfg.daybook_archive_quote_classifier_launcher_path,
            system_owner,
            system_group,
            0o755,
        )
        if cfg.daybook_archive_quote_classifier_launchd_enabled:
            add(
                "archive-quotes.launchd.plist.j2",
                cfg.daybook_archive_quote_classifier_launchd_plist_path,
                system_owner,
                system_group,
                0o644,
            )
    if cfg.daybook_weeknotes_reconcile_enabled:
        add("weeknotes-identity-ops.py.j2", cfg.daybook_weeknotes_identity_helper_path, "root", "wheel", 0o755)
        add("weeknotes-identity-ops.sh.j2", cfg.daybook_weeknotes_identity_launcher_path, "root", "wheel", 0o755)
        add("weeknotes-reconcile.env.j2", cfg.daybook_weeknotes_reconcile_env_file, user, group, 0o600, secret=True)
        # This checksum is the ORIGINAL managed activation guard, not an observer
        # credential attestation. Never include its body/digest in proof metadata.
        env = render_template("weeknotes-reconcile.env.j2", values)
        checksum = hashlib.sha256(env.encode()).hexdigest() + "  " + cfg.daybook_weeknotes_reconcile_env_file + "\n"
        rendered.append(
            _ResourceText(cfg.daybook_weeknotes_reconcile_env_checksum_file, "root", "wheel", 0o644, checksum, True)
        )
        add("reconcile-weeknotes.sh.j2", cfg.daybook_weeknotes_reconcile_launcher_path, "root", "wheel", 0o755)
        if not cfg.daybook_weeknotes_reconcile_launchd_retired:
            add(
                "weeknotes-reconcile.launchd.plist.j2",
                cfg.daybook_weeknotes_reconcile_launchd_plist_path,
                "root",
                "wheel",
                0o644,
            )
    if len({resource.path for resource in rendered}) != len(rendered):
        raise ValueError("Sessions managed resource paths overlap")
    return tuple(rendered)


def resources(
    cfg: DaybookSessionsConfig, secrets: Mapping[str, str], *, identity_verified: bool = False
) -> tuple[SessionResource, ...]:
    return tuple(
        SessionResource(
            row.path, row.owner, row.group, row.mode, SecretContent(row.content) if row.private else row.content
        )
        for row in _resource_texts(cfg, secrets, identity_verified=identity_verified)
    )
