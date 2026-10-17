"""The canonical file set: compose file, env files, config files and unit, rendered from the config.

Everything is rendered on the controller before the deploy connects, so a bad
value fails the run before any change. Env files with a host value
(:class:`HostSecret`, :class:`HostId`) leave here as a template of pieces
that ``files/compose_host.py`` completes on the host. The fingerprint the
applied stamp records keeps those pieces symbolic.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import PurePosixPath
from typing import Any

import jinja2
import yaml

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.services.compose_app.config import (
    ComposeAppConfig,
    ComposeService,
    ConfigFile,
    EnvFile,
    HostId,
    HostSecret,
    Secret,
    pieces,
)

TEMPLATE_PACKAGE = "ops_deploy.services.compose_app"
MANAGED = "Managed by ops-deploy (compose_app). Local changes are overwritten by the next deploy."
# Values the playbooks' asserts refuse in a secret.
PLACEHOLDERS = frozenset({"CHANGEME", "CHANGE_ME"})


@cache
def _templates() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render_unit(cfg: ComposeAppConfig) -> str:
    return _templates().get_template("unit.service.j2").render(cfg=cfg, managed=MANAGED)


# -- secrets ---------------------------------------------------------------------


def check_secrets(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    """Every referenced secret is set, single-line and no placeholder. Errors name keys only."""

    secrets.require(cfg.required_secret_keys)
    for key in cfg.required_secret_keys:
        value = secrets[key]
        if value.strip() in PLACEHOLDERS or "CHANGEME" in value:
            raise ValueError(f"secret {key} must be set and not a placeholder")
        if any(c in value for c in "\r\n\0"):
            raise ValueError(f"secret {key} must be a single line")


def resolve(secret: Secret, secrets: SecretValues) -> str:
    """The value of ``secret`` in its form; errors name the key only."""

    value = secrets[secret.secret]
    if secret.form == "int":
        if not value.strip().isdigit():
            raise ValueError(f"secret {secret.secret} must be a number")
        return str(int(value.strip()))
    if secret.form == "first_ipv4":
        # The playbooks' filter: whitespace removed, split at commas, IPv6 (":") dropped.
        candidates = [part for part in "".join(value.split()).split(",") if part and ":" not in part]
        if not candidates:
            raise ValueError(f"secret {secret.secret} has no IPv4 address")
        try:
            ipaddress.ip_interface(candidates[0])
        except ValueError:
            raise ValueError(f"secret {secret.secret} has no IPv4 address") from None
        return candidates[0]
    return value


def json_value(value: Any, secrets: SecretValues) -> Any:
    """``value`` with :class:`Secret` leaves resolved (``int`` secrets as numbers)."""

    if isinstance(value, Secret):
        text = resolve(value, secrets)
        return int(text) if value.form == "int" else text
    if isinstance(value, dict):
        return {key: json_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [json_value(item, secrets) for item in value]
    return value


# -- env files -------------------------------------------------------------------


def env_value_problem(value: str) -> str | None:
    r"""Why ``value`` cannot be one line ``KEY='value'`` of a Compose env file, or ``None``.

    Compose reads a single-quoted value literally (no ``${}`` interpolation),
    but a backslash may still escape the closing quote, and its parse error
    then prints the value; such values are refused, with ``'``, line breaks,
    NUL and leading or trailing whitespace.
    """

    if "'" in value:
        return "contains a single quote"
    if "\\" in value:
        return "contains a backslash"
    if any(c in value for c in "\r\n\0"):
        return "is not a single line"
    if value != value.strip():
        return "has leading or trailing whitespace"
    return None


# A piece of a host-rendered file, as files/compose_host.py reads it.
Segment = list[Any]


@dataclass(frozen=True)
class RenderedEnv:
    """One env file: its content (controller-rendered) or its segments (host-rendered)."""

    path: PurePosixPath
    mode: str
    content: SecretContent | None
    segments: tuple[Segment, ...]
    # sha256 of the content, or of the segments with the host values symbolic.
    digest: str

    @property
    def host_rendered(self) -> bool:
        return self.content is None


def render_env(cfg: ComposeAppConfig, env: EnvFile, secrets: SecretValues) -> RenderedEnv:
    """``# header`` then ``KEY='value'`` lines; secrets resolved, host values left as segments."""

    segments: list[Segment] = [["text", f"# {MANAGED}\n"]]
    for entry in env.entries:
        segments.append(["text", f"{entry.key}='"])
        for piece in pieces(entry.value):
            if isinstance(piece, HostSecret):
                segments.append(["host_secret", str(piece.host_secret), piece.bytes])
            elif isinstance(piece, HostId):
                segments.append([*piece.ref])
            else:
                text = resolve(piece, secrets) if isinstance(piece, Secret) else piece
                problem = env_value_problem(text)
                if problem:
                    source = f"secret {piece.secret}" if isinstance(piece, Secret) else "value"
                    raise ValueError(f"{source} for {entry.key} in {env.name} {problem}")
                segments.append(["text", text])
        segments.append(["text", "'\n"])
    merged = _merged(segments)
    path = cfg.env_path(env)
    mode = env.mode.rjust(4, "0")
    if env.host_rendered:
        return RenderedEnv(path, mode, None, tuple(merged), digest(json.dumps(merged, separators=(",", ":"))))
    text = "".join(text for _, text in merged)
    return RenderedEnv(path, mode, SecretContent(text), (), digest(text))


def _merged(segments: list[Segment]) -> list[Segment]:
    """Adjacent text segments joined."""

    merged: list[Segment] = []
    for segment in segments:
        if segment[0] == "text" and merged and merged[-1][0] == "text":
            merged[-1] = ["text", merged[-1][1] + segment[1]]
        else:
            merged.append(list(segment))
    return merged


def host_refs(cfg: ComposeAppConfig) -> list[list[str]]:
    """Every :class:`HostId` the env files use, as ``[kind, name]`` (the stamp records their values)."""

    refs = {
        piece.ref
        for env in cfg.env_files
        for entry in env.entries
        for piece in pieces(entry.value)
        if isinstance(piece, HostId)
    }
    return [list(ref) for ref in sorted(refs)]


# -- config files ----------------------------------------------------------------


def render_config(config: ConfigFile, secrets: SecretValues) -> tuple[str, bool]:
    """The file's text and whether it holds a secret."""

    data = json_value(config.data, secrets)
    has_secret = any(True for _ in _secret_leaves(config.data))
    if config.format == "json":
        return json.dumps(data, indent=2, sort_keys=False) + "\n", has_secret
    text = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True, width=4096)
    return f"# {MANAGED}\n{text}", has_secret


def _secret_leaves(value: Any) -> Any:
    if isinstance(value, Secret):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _secret_leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from _secret_leaves(item)


# -- compose file ----------------------------------------------------------------


def _escaped(value: Any) -> Any:
    """Every ``$`` doubled: Compose interpolates the whole file, the model's values are literal."""

    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, dict):
        return {key: _escaped(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_escaped(item) for item in value]
    return value


def service_document(cfg: ComposeAppConfig, service: ComposeService) -> dict[str, Any]:
    """One service's mapping in the compose file, in a fixed key order."""

    doc: dict[str, Any] = {"image": service.image}
    if service.container_name:
        doc["container_name"] = service.container_name
    if service.command is not None:
        doc["command"] = list(service.command)
    if service.entrypoint is not None:
        doc["entrypoint"] = list(service.entrypoint)
    if service.user:
        doc["user"] = service.user
    if service.profiles:
        doc["profiles"] = list(service.profiles)
    if service.network_mode:
        doc["network_mode"] = service.network_mode
    if service.networks:
        doc["networks"] = ["default", *service.networks]
    if service.ports:
        doc["ports"] = [
            f"{_host(port.host_ip)}:{port.published}:{port.target}" + ("/udp" if port.protocol == "udp" else "")
            for port in service.ports
        ]
    if service.env_files:
        doc["env_file"] = [str(cfg.site_path / name) for name in service.env_files]
    if service.environment:
        doc["environment"] = {entry.key: entry.value for entry in service.environment}
    if service.binds:
        doc["volumes"] = [
            {
                "type": "bind",
                "source": str(bind.source),
                "target": str(bind.container_path),
                **({"read_only": True} if bind.read_only else {}),
                # A missing (or unmounted) source fails instead of becoming an empty directory.
                "bind": {"create_host_path": False},
            }
            for bind in service.binds
        ]
    if service.cap_add:
        doc["cap_add"] = list(service.cap_add)
    if service.devices:
        doc["devices"] = [f"{device}:{device}" for device in service.devices]
    if service.sysctls:
        doc["sysctls"] = {sysctl.key: sysctl.value for sysctl in service.sysctls}
    for key in ("shm_size", "mem_limit", "cpus", "pids_limit"):
        if getattr(service, key) is not None:
            doc[key] = getattr(service, key)
    depends: dict[str, Any] = {}
    if service.provider:
        # Started only once the namespace provider is healthy, and restarted with it.
        depends[service.provider] = {"condition": "service_healthy", "restart": True}
    for dep in service.depends_on:
        depends[dep.service] = {"condition": dep.condition}
    if depends:
        doc["depends_on"] = depends
    if service.healthcheck:
        check = service.healthcheck
        doc["healthcheck"] = {
            "test": list(check.test),
            "interval": check.interval,
            "timeout": check.timeout,
            "retries": check.retries,
            "start_period": check.start_period,
        }
    doc["restart"] = service.restart
    return _escaped(doc)  # type: ignore[no-any-return]


def _host(address: str) -> str:
    return f"[{address}]" if ":" in address else address


def render_compose(cfg: ComposeAppConfig) -> str:
    doc: dict[str, Any] = {
        "name": cfg.project,
        "services": {service.name: service_document(cfg, service) for service in cfg.services},
    }
    if cfg.external_networks:
        doc["networks"] = {name: {"name": name, "external": True} for name in cfg.external_networks}
    text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=4096)
    return f"# {MANAGED}\n{text}"


# -- fingerprint -----------------------------------------------------------------


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def service_digests(cfg: ComposeAppConfig, envs: Mapping[str, RenderedEnv]) -> dict[str, str]:
    """Per service: its compose mapping and the env files it reads (what Compose recreates it on)."""

    result = {}
    for service in cfg.services:
        reads = [envs[name].digest for name in service.env_files]
        result[service.name] = digest(json.dumps([service_document(cfg, service), reads], sort_keys=True))
    return result
