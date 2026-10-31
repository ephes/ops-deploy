"""Prepared original Custom Conversation archive/stamp/extract task sequence."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from dataclasses import dataclass
from importlib.resources import files as resources
from io import StringIO

from pydantic import Field, SecretStr, StrictInt
from pyinfra import host, state
from pyinfra.api import OperationError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from ops_deploy.base._common import RoleConfig, Sha256
from ops_deploy.helpers.probes import StdinLines

from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command


class CustomComponentConfig(RoleConfig):
    version: str = Field(default="1.6.1", min_length=1)
    sha256: Sha256 = "6397258af29908ffed7b0eaa79c332ddce7000cb9b9faec5e3bf0e399c020382"
    download_url: SecretStr | None = None
    command_timeout: StrictInt = Field(default=900, ge=1)

    def url(self) -> str:
        if self.download_url is not None:
            return self.download_url.get_secret_value()
        return f"https://github.com/michelle-avery/custom-conversation/archive/refs/tags/{self.version}.tar.gz"


@dataclass(frozen=True)
class CustomComponentChanges:
    archive: OperationMeta
    extraction: OperationMeta
    stamp: OperationMeta

    def homeassistant_changed(self) -> bool:
        # Original get_url and parent metadata do not notify the handler.
        return self.extraction.did_change() or self.stamp.did_change()


def component_payload(cfg: HomeAssistantRuntimeConfig, component: CustomComponentConfig, action: str) -> SecretStr:
    parent = cfg.config_path + "/custom_components"
    root = parent + "/custom_conversation"
    return SecretStr(
        json.dumps(
            {
                "action": action,
                "version": component.version,
                "sha256": component.sha256,
                "url": component.url(),
                "archive": cfg.site_path + f"/downloads/custom-conversation-{component.version}.tar.gz",
                "parent": parent,
                "component": root,
                "stamp": root + "/.ansible-cc-version",
                "user": cfg.user,
                "group": cfg.group,
            }
        )
    )


def component_command(cfg: HomeAssistantRuntimeConfig) -> str:
    source = resources("ops_deploy.services.homeassistant").joinpath("files/custom_component.py").read_bytes()
    encoded = base64.b64encode(source).decode()
    launcher = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<ha-cc-component>','exec'))"
    return shlex.join([cfg.security.system_python, "-I", "-B", "-c", launcher])


def _needed(cfg: HomeAssistantRuntimeConfig, component: CustomComponentConfig, check: str) -> bool:
    success, output = run_protected_command(
        host,
        StringCommand(component_command(cfg)),
        _stdin=StdinLines(component_payload(cfg, component, check).get_secret_value()),
        _get_pty=False,
        _timeout=90,
    )
    try:
        report = json.loads(str(output.stdout))
        if (
            not success
            or not isinstance(report, dict)
            or set(report)
            != {
                "success",
                "changed",
                "effects_started",
                "archive_replaced",
                "component_removed",
                "extracted",
            }
        ):
            raise ValueError
        if report["success"] is not True or type(report["changed"]) is not bool:
            raise ValueError
        if any(
            report[key] is not False
            for key in ("effects_started", "archive_replaced", "component_removed", "extracted")
        ):
            raise ValueError
        return bool(report["changed"])
    except (ValueError, TypeError):
        raise OperationError("Home Assistant Custom Conversation component observation failed") from None


@operation()
def _component_action(
    cfg: HomeAssistantRuntimeConfig,
    component: CustomComponentConfig,
    action: str,
    deferred: bool,
    predecessors: tuple[OperationMeta, ...],
) -> Generator[StringCommand, None, None]:
    pending = not state.is_executing and (deferred or any(item.will_change for item in predecessors))
    check = "check-archive" if action == "download" else "check-install"
    if not pending and not _needed(cfg, component, check):
        return
    yield StringCommand(
        component_command(cfg),
        _stdin=StdinLines(component_payload(cfg, component, action).get_secret_value()),
        _get_pty=False,
    )


def install_custom_component(
    cfg: HomeAssistantRuntimeConfig,
    component: CustomComponentConfig,
    *,
    deferred: bool = False,
) -> CustomComponentChanges:
    """Call only for original selected optional component after account creation.

    Parent dirs/download/stamp keep original metadata. Hash mismatch downloads
    before verified atomic replacement. Stamp mismatch removes/extracts in place;
    failures may have partial effects and do not queue an invented rollback.
    Caller owns the later original handler flush. Checks always refresh at run.
    """
    parents = tuple(
        files.directory(
            name="Ensure Home Assistant Custom Conversation parent",
            path=path,
            user=cfg.user,
            group=cfg.group,
            mode="0755",
        )
        for path in (cfg.config_path + "/custom_components", cfg.site_path + "/downloads")
    )
    archive = _component_action(
        name="Fetch pinned Home Assistant Custom Conversation archive",
        cfg=cfg,
        component=component,
        action="download",
        deferred=deferred,
        predecessors=parents,
        _timeout=component.command_timeout,
    )
    extraction = _component_action(
        name="Extract Home Assistant Custom Conversation component",
        cfg=cfg,
        component=component,
        action="extract",
        deferred=deferred,
        predecessors=parents,
        _timeout=component.command_timeout,
    )
    stamp = files.put(
        name="Record Home Assistant Custom Conversation version and checksum",
        src=StringIO(component.version + " " + component.sha256 + "\n"),
        dest=cfg.config_path + "/custom_components/custom_conversation/.ansible-cc-version",
        user=cfg.user,
        group=cfg.group,
        mode="0644",
        _if=extraction.did_change,
    )
    return CustomComponentChanges(archive, extraction, stamp)
