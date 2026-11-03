"""Pinned GPS Timeline integration and Location Timeline Card (both opt-in).

GPS Timeline (``iamyacin/gps-timeline``) keeps location history in its own
SQLite database, ``config/gps_timeline/gps_timeline.db``, independent of the
recorder's global retention; the Location Timeline Card
(``iamyacin/timeline_card``) shows it with ``history_source: gps_timeline``.

Both are pinned downloads verified by sha256 before anything is replaced:

- the integration's release archive goes to ``downloads/``, only its
  ``custom_components/gps_timeline`` is installed (owner ``homeassistant``),
  and a stamp with version and checksum makes a repeat run a no-op;
- the card is ``config/www/timeline_card.js`` (``www/`` 0755), always the same
  file name, so the dashboard resource ``/local/timeline_card.js?v=<version>``
  only needs its ``?v=`` bumped.

Home Assistant restarts only when one of them changed (``/local`` exists only
if ``www/`` existed at startup, so the first install's restart covers it).
The integration is configured in the UI (config flow); nothing here writes
``configuration.yaml``, ``automations.yaml`` or ``scripts.yaml``, and nothing
here deletes or writes the integration's data directory.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from importlib.resources import files as resources
from typing import Annotated, Any

from pydantic import Field, SecretStr, StrictBool, StrictInt, model_validator
from pyinfra import host, state
from pyinfra.api import OperationError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from ops_deploy.base._common import RoleConfig, Sha256
from ops_deploy.helpers.probes import StdinLines

from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command

PinVersion = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")]


class _PinnedConfig(RoleConfig):
    enabled: StrictBool = False
    download_url: SecretStr | None = None
    command_timeout: StrictInt = Field(default=900, ge=1)

    @model_validator(mode="before")
    @classmethod
    def version_with_checksum(cls, value: Any) -> Any:
        # The checksum belongs to one artifact: another version needs its own.
        default = cls.model_fields["version"].default
        if isinstance(value, dict) and value.get("version", default) != default and "sha256" not in value:
            raise ValueError("set sha256 together with a non-default version")
        return value


class GpsTimelineConfig(_PinnedConfig):
    version: PinVersion = "0.1.0-beta.3"
    sha256: Sha256 = "feb29bc1705181aab9146cacf2c7552a70d969042825734af0435000db1ee34e"

    def url(self) -> str:
        if self.download_url is not None:
            return self.download_url.get_secret_value()
        return f"https://github.com/iamyacin/gps-timeline/archive/refs/tags/{self.version}.tar.gz"


class TimelineCardConfig(_PinnedConfig):
    version: PinVersion = "1.9.3"
    sha256: Sha256 = "d81404bc66ef2affcbd701af08a04fcfee199dadfb6b82674576291db50987a5"

    def url(self) -> str:
        if self.download_url is not None:
            return self.download_url.get_secret_value()
        return f"https://github.com/iamyacin/timeline_card/releases/download/v{self.version}/timeline_card.js"


def gps_timeline_payload(cfg: HomeAssistantRuntimeConfig, item: GpsTimelineConfig, action: str) -> SecretStr:
    parent = cfg.config_path + "/custom_components"
    return SecretStr(
        json.dumps(
            {
                "action": action,
                "kind": "component",
                "version": item.version,
                "sha256": item.sha256,
                "url": item.url(),
                "archive": cfg.site_path + f"/downloads/gps-timeline-{item.version}.tar.gz",
                # GitHub's tag archive: <repo>-<tag>/custom_components/<domain>.
                "member": f"gps-timeline-{item.version}/custom_components/gps_timeline",
                "parent": parent,
                "component": parent + "/gps_timeline",
                "user": cfg.user,
                "group": cfg.group,
            }
        )
    )


def timeline_card_payload(cfg: HomeAssistantRuntimeConfig, item: TimelineCardConfig, action: str) -> SecretStr:
    return SecretStr(
        json.dumps(
            {
                "action": action,
                "kind": "file",
                "version": item.version,
                "sha256": item.sha256,
                "url": item.url(),
                "dest": cfg.config_path + "/www/timeline_card.js",
                "user": cfg.user,
                "group": cfg.group,
            }
        )
    )


def helper_command(cfg: HomeAssistantRuntimeConfig) -> str:
    source = resources("ops_deploy.services.homeassistant").joinpath("files/pinned_assets.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-pinned>','exec'))"
    )
    return shlex.join([cfg.security.system_python, "-I", "-B", "-c", launcher])


def _needed(cfg: HomeAssistantRuntimeConfig, payload: SecretStr) -> bool:
    success, output = run_protected_command(
        host,
        StringCommand(helper_command(cfg)),
        _stdin=StdinLines(payload.get_secret_value()),
        _get_pty=False,
        _timeout=90,
    )
    try:
        report = json.loads(str(output.stdout))
        if not success or not isinstance(report, dict) or set(report) != {"success", "changed"}:
            raise ValueError
        if report["success"] is not True or type(report["changed"]) is not bool:
            raise ValueError
        return report["changed"]
    except (ValueError, TypeError):
        raise OperationError("Home Assistant pinned asset observation failed") from None


@operation()
def _pinned_asset(
    cfg: HomeAssistantRuntimeConfig,
    check: SecretStr,
    apply: SecretStr,
    predecessors: tuple[OperationMeta, ...],
) -> Generator[StringCommand, None, None]:
    # Planning: a directory still to be created means a change; otherwise ask
    # the host. Execution always asks again, so an unchanged host runs nothing.
    pending = not state.is_executing and any(item.will_change for item in predecessors)
    if not pending and not _needed(cfg, check):
        return
    yield StringCommand(helper_command(cfg), _stdin=StdinLines(apply.get_secret_value()), _get_pty=False)


def _directory(cfg: HomeAssistantRuntimeConfig, path: str) -> OperationMeta:
    return files.directory(
        name="Ensure Home Assistant directory " + path.rsplit("/", 1)[-1],
        path=path,
        user=cfg.user,
        group=cfg.group,
        mode="0755",
    )


def install_pinned_assets(
    cfg: HomeAssistantRuntimeConfig, gps_timeline: GpsTimelineConfig, timeline_card: TimelineCardConfig
) -> list[OperationMeta]:
    """Register the enabled installs; Home Assistant needs a restart when one of them changed."""

    changes = []
    if gps_timeline.enabled:
        parents = (
            _directory(cfg, cfg.config_path + "/custom_components"),
            _directory(cfg, cfg.site_path + "/downloads"),
        )
        changes.append(
            _pinned_asset(
                name=f"Install pinned Home Assistant GPS Timeline {gps_timeline.version}",
                cfg=cfg,
                check=gps_timeline_payload(cfg, gps_timeline, "check"),
                apply=gps_timeline_payload(cfg, gps_timeline, "apply"),
                predecessors=parents,
                _timeout=gps_timeline.command_timeout,
            )
        )
    if timeline_card.enabled:
        www = _directory(cfg, cfg.config_path + "/www")
        changes.append(
            _pinned_asset(
                name=f"Install pinned Location Timeline Card {timeline_card.version}",
                cfg=cfg,
                check=timeline_card_payload(cfg, timeline_card, "check"),
                apply=timeline_card_payload(cfg, timeline_card, "apply"),
                predecessors=(www,),
                _timeout=timeline_card.command_timeout,
            )
        )
    return changes
