"""Typed API steps after the rollout (2.8): data only, a read-only probe, then an apply.

Each kind is a host-side script (``python3 -I``, its request with any secret
on stdin) with a ``probe`` mode that only reads and prints the drift, and an
``apply`` mode that reconciles and verifies. The probe runs while planning;
``apply`` is added only when it reports drift (or failed), so a converged host
shows read-only work only. After a run that recreates the containers the
probe's answer is stale, and ``apply`` runs (it prints ``noop`` when nothing
had to change).
"""

from __future__ import annotations

from typing import Any

from pyinfra import host, logger

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.ops import secret_stdin
from ops_deploy.services.compose_app.config import (
    ComposeAppConfig,
    HostSecret,
    HttpJsonItems,
    HttpJsonSettings,
    JsonKeyCopy,
    QbittorrentPreferences,
    Secret,
)
from ops_deploy.services.compose_app.render import json_value, resolve
from ops_deploy.services.compose_app.state import COMPOSE_HOST, HTTP_JSON, QBITTORRENT, payload, script, stdin_probe


def _qbittorrent_request(cfg: ComposeAppConfig, step: QbittorrentPreferences, secrets: SecretValues) -> dict[str, Any]:
    username = resolve(step.username, secrets) if isinstance(step.username, Secret) else step.username
    return {
        "port": step.port,
        "username": username,
        "password": resolve(step.password, secrets),
        "preferences": json_value(dict(step.preferences), secrets),
        "project": cfg.project,
        "compose_file": str(cfg.compose_path),
        "service": step.service,
        "wait": step.wait_seconds,
    }


def _copy_request(step: JsonKeyCopy) -> dict[str, Any]:
    return {
        "source": str(step.source),
        "keys": list(step.keys),
        "dest": str(step.dest),
        "template": step.template,
        "owner": step.owner,
        "group": step.group,
        "mode": step.mode.rjust(4, "0"),
        "wait": step.wait_seconds,
    }


def qbittorrent_preferences(
    cfg: ComposeAppConfig, step: QbittorrentPreferences, secrets: SecretValues, *, recreated: bool
) -> None:
    request = _qbittorrent_request(cfg, step, secrets)
    if not recreated:
        answer = stdin_probe(script(QBITTORRENT, "probe"), request, name="qBittorrent preferences")
        if answer == "current":
            host.noop("qBittorrent preferences are current")
            return
        if answer is not None:
            logger.info(f"{host.print_prefix}qBittorrent preferences: {answer}")
    secret_stdin(
        name="Reconcile qBittorrent credentials and preferences",
        command=script(QBITTORRENT, "apply"),
        content=SecretContent(payload(request)),
    )


def json_key_copy(step: JsonKeyCopy) -> None:
    request = _copy_request(step)
    answer = stdin_probe(script(COMPOSE_HOST, "copy-probe"), request, name=step.name)
    if answer == "same":
        host.noop(f"{step.dest} is current")
        return
    secret_stdin(name=step.name, command=script(COMPOSE_HOST, "copy-apply"), content=SecretContent(payload(request)))


def _api_json(value: Any, secrets: SecretValues) -> Any:
    """``value`` with :class:`Secret` leaves resolved; :class:`HostSecret` leaves stay references for the host."""

    if isinstance(value, HostSecret):
        return {"host_secret": str(value.host_secret)}
    if isinstance(value, dict):
        return {key: _api_json(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_api_json(item, secrets) for item in value]
    return json_value(value, secrets)


def _http_json_request(
    cfg: ComposeAppConfig, step: HttpJsonSettings | HttpJsonItems, secrets: SecretValues
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "name": step.name,
        "port": step.port,
        "prefix": step.prefix,
        "path": step.path,
        "auth": {"header": step.auth.header, "value": _api_json(step.auth.value, secrets)},
        "write_only": list(step.write_only),
        "path_keys": list(step.path_keys),
        "wait": step.wait_seconds,
        # Digests of the write-only values last written (root 0600, never the values).
        "state": str(cfg.state_dir / "http_json.json"),
    }
    if isinstance(step, HttpJsonSettings):
        request["desired"] = _api_json(step.desired, secrets)
    else:
        request.update(
            match=step.match,
            items=_api_json(list(step.items), secrets),
            schema=None if step.schema_ref is None else {"path": step.schema_ref.path, "key": step.schema_ref.key},
            tags_path=step.tags_path,
            force_save=step.force_save,
        )
    return request


def http_json(
    cfg: ComposeAppConfig, step: HttpJsonSettings | HttpJsonItems, secrets: SecretValues, *, recreated: bool
) -> None:
    """Probe while planning; apply only on drift, a failed probe, or after the containers were recreated."""

    kind = "settings" if isinstance(step, HttpJsonSettings) else "items"
    request = _http_json_request(cfg, step, secrets)
    if not recreated:
        answer = stdin_probe(script(HTTP_JSON, f"{kind}-probe"), request, name=step.name)
        if answer == "current":
            host.noop(f"{step.name} is current")
            return
        if answer is not None:
            logger.info(f"{host.print_prefix}{step.name}: {answer}")
    secret_stdin(name=step.name, command=script(HTTP_JSON, f"{kind}-apply"), content=SecretContent(payload(request)))


def api_steps(cfg: ComposeAppConfig, secrets: SecretValues, *, recreated: bool) -> None:
    for step in cfg.steps:
        if isinstance(step, QbittorrentPreferences):
            qbittorrent_preferences(cfg, step, secrets, recreated=recreated)
        elif isinstance(step, (HttpJsonSettings, HttpJsonItems)):
            http_json(cfg, step, secrets, recreated=recreated)
        else:
            json_key_copy(step)
