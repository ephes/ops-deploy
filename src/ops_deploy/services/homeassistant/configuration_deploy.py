"""Original configuration task order using protected host-local file operations.

Prepared component only: outer deploy owns layout prerequisites and later
service flushes. Every generator rechecks at execution; planned predecessor
writes are explicitly deferred, not mistaken for current target contents.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass, field
from functools import cache, partial
from importlib.resources import files
from typing import Any

from pydantic import BaseModel, ConfigDict, SecretStr, StrictStr
from pyinfra import host, state
from pyinfra.api import OperationError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.base._common import AbsolutePath
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines

from .configuration import LEGACY_MET, OBSOLETE, ConfigurationPolicy
from .configuration_render import (
    ConfigurationSecretExamples,
    ConfigurationValues,
    render_configuration,
    render_include,
    render_secret_parts,
)
from .runtime_config import HomeAssistantRuntimeConfig
from .security import _present

INCLUDES = (
    "automations.yaml",
    "scripts.yaml",
    "scenes.yaml",
    "groups.yaml",
    "persons.yaml",
    "presence_automations.yaml",
)


class UnifiSecretSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    explicit: SecretStr = SecretStr("")
    source: StrictStr = "file"
    file: AbsolutePath = "/home/unifi/.homeassistant_unifi_password"
    variable: SecretStr = SecretStr("")

    def protected_payload(self) -> SecretStr:
        return SecretStr(
            json.dumps(
                {
                    "explicit": self.explicit.get_secret_value(),
                    "source": self.source,
                    "file": self.file,
                    "variable": self.variable.get_secret_value(),
                }
            )
        )


@dataclass
class _InitialFiles:
    exists: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class ConfigurationChanges:
    replacements: tuple[OperationMeta, ...]

    def homeassistant_changed(self) -> bool:
        """Original only-replacement notifications from actual helper output."""
        for result in self.replacements:
            if result.did_succeed() and result.stdout.strip():
                try:
                    report = json.loads(result.stdout)
                    if report["success"] is True and report["changed"] is True:
                        return True
                except (ValueError, TypeError, KeyError):
                    raise OperationError("Home Assistant configuration result is invalid") from None
        return False


def file_command(cfg: HomeAssistantRuntimeConfig) -> str:
    body = files("ops_deploy.services.homeassistant").joinpath("files/configuration_file.py").read_bytes()
    script = (
        "import base64;exec(compile(base64.b64decode("
        + repr(base64.b64encode(body).decode())
        + "),'<ha-config>','exec'))"
    )
    return shlex.join([cfg.security.system_python, "-I", "-B", "-c", script])


def _pending(cfg: HomeAssistantRuntimeConfig, protected: SecretStr) -> bool:
    payload = json.loads(protected.get_secret_value())
    payload["action"] = "check"
    success, output = host.run_shell_command(
        StringCommand(file_command(cfg)),
        _stdin=StdinLines(json.dumps(payload)),
        _get_pty=False,
        print_input=False,
        print_output=False,
    )
    try:
        report = json.loads(output.stdout)
        if (
            not success
            or set(report)
            != {"success", "changed", "effects_started", "backup_created", "body_written", "metadata_written"}
            or report["success"] is not True
            or type(report["changed"]) is not bool
        ):
            raise ValueError
        if any(
            report[key] is not False
            for key in ("effects_started", "backup_created", "body_written", "metadata_written")
        ):
            raise ValueError
        return bool(report["changed"])
    except (ValueError, TypeError, KeyError):
        raise OperationError("Home Assistant configuration inspection failed") from None


@operation()
def _capture_initial(
    cfg: HomeAssistantRuntimeConfig, names: tuple[str, ...], initial: _InitialFiles
) -> Generator[StringCommand, None, None]:
    initial.exists = {name: _present(host, cfg.config_path + "/" + name, cfg.security.system_python) for name in names}
    # A source-declared metadata probe, no executor command or target write.
    yield from ()


@operation()
def _configuration_file(
    cfg: HomeAssistantRuntimeConfig,
    protected: SecretStr,
    deferred: bool,
    initial: _InitialFiles | None,
    filename: str,
    skip_existing: bool,
    require_existing: bool,
    predecessors: tuple[OperationMeta, ...],
    content: Callable[[], SecretStr] | None = None,
) -> Generator[StringCommand, None, None]:
    if initial is not None:
        exists = initial.exists.get(filename)
        if exists is None:
            raise OperationError("Home Assistant configuration baseline is missing")
        if (skip_existing and exists) or (require_existing and not exists):
            return
    if content is not None:
        # Original template lookup follows the item's when/existence guard.
        # An existing skipped include need not have any controller source.
        payload = json.loads(protected.get_secret_value())
        payload["content"] = content().get_secret_value()
        protected = SecretStr(json.dumps(payload))
    if not state.is_executing and (deferred or any(item.will_change for item in predecessors)):
        # Actual execution regenerates this operation and inspects after the
        # preceding declared writes. No credential or current body is guessed.
        yield StringCommand(file_command(cfg), _stdin=StdinLines(protected.get_secret_value()), _get_pty=False)
        return
    if _pending(cfg, protected):
        yield StringCommand(file_command(cfg), _stdin=StdinLines(protected.get_secret_value()), _get_pty=False)


def _include_content(
    filename: str,
    rendered: Mapping[str, SecretStr],
    renderer: Callable[[str], SecretStr] | None,
) -> SecretStr:
    if filename in rendered:
        return rendered[filename]
    return render_include(filename) if renderer is None else renderer(filename)


def configure_files(
    cfg: HomeAssistantRuntimeConfig,
    policy: ConfigurationPolicy,
    values: ConfigurationValues,
    *,
    unifi: UnifiSecretSource | None = None,
    examples: ConfigurationSecretExamples | None = None,
    include_files: tuple[str, ...] = INCLUDES,
    include_rendered: Mapping[str, SecretStr] | None = None,
    include_renderer: Callable[[str], SecretStr] | None = None,
    deferred: bool = False,
) -> ConfigurationChanges:
    """Compose stock or explicitly rendered configuration after account/layout creation.

    ``deferred`` is only for a declared pending prerequisite. This internal
    component performs no prerequisite repair, API call or handler flush.
    Unmanaged secret/config/include branches issue no body/credential probes.
    """

    def task(
        filename: str,
        kind: str,
        additions: dict[str, Any],
        *,
        initial: _InitialFiles | None = None,
        skip_existing: bool = False,
        require_existing: bool = False,
        predecessors: tuple[OperationMeta, ...] = (),
        content: Callable[[], SecretStr] | None = None,
    ) -> OperationMeta:
        payload = SecretStr(
            json.dumps(
                {
                    "kind": kind,
                    "action": "apply",
                    "path": cfg.config_path + "/" + filename,
                    "user": cfg.user,
                    "group": cfg.group,
                    "mode": "0600" if filename == "secrets.yaml" else "0644",
                    **additions,
                }
            )
        )
        return _configuration_file(
            name="Manage Home Assistant " + filename + " (" + kind + ")",
            cfg=cfg,
            protected=payload,
            deferred=deferred,
            initial=initial,
            filename=filename,
            skip_existing=skip_existing,
            require_existing=require_existing,
            predecessors=predecessors,
            content=content,
        )

    if policy.manage_secrets:
        prefix, suffix = render_secret_parts(examples or ConfigurationSecretExamples())
        task(
            "secrets.yaml",
            "secrets",
            {
                "prefix": prefix.get_secret_value(),
                "suffix": suffix.get_secret_value(),
                "unifi": json.loads((unifi or UnifiSecretSource()).protected_payload().get_secret_value()),
            },
        )
    replacements: list[OperationMeta] = []
    if policy.manage_configuration:
        initial = _InitialFiles()
        mark_read_only(
            _capture_initial(
                name="Inspect initial Home Assistant configuration path",
                cfg=cfg,
                names=("configuration.yaml",),
                initial=initial,
            )
        )
        template = task(
            "configuration.yaml",
            "template",
            {"content": render_configuration(cfg, values).get_secret_value()},
            initial=initial,
            skip_existing=not policy.overwrite_config,
        )
        patterns = ((LEGACY_MET,) if policy.remove_legacy_met_weather_yaml else ()) + OBSOLETE
        for pattern in patterns:
            replacements.append(
                task(
                    "configuration.yaml",
                    "replace",
                    {"pattern": pattern},
                    initial=initial,
                    require_existing=True,
                    predecessors=(template, *replacements),
                )
            )
    if policy.manage_includes:
        includes = _InitialFiles()
        mark_read_only(
            _capture_initial(
                name="Inspect initial Home Assistant include paths", cfg=cfg, names=include_files, initial=includes
            )
        )
        for filename in include_files:
            task(
                filename,
                "template",
                {},
                initial=includes,
                skip_existing=not policy.overwrite_config,
                content=cache(partial(_include_content, filename, include_rendered or {}, include_renderer)),
            )
    return ConfigurationChanges(tuple(replacements))
