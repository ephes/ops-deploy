"""OpenClaw inputs: the role's variables as the playbook sets them, and the secret ones apart.

The role's interface is its ``defaults/main.yml`` (about 230 variables) and
its ``tasks/validate.yml``; the port keeps both (:mod:`.variables`,
:mod:`.validate`). :class:`OpenClawConfig` carries the non-secret variables
the playbook (or inventory) sets, by their role names; :class:`OpenClawSecrets`
the ones that hold credentials, which reach the host only through
``secret_file``/stdin. Unknown names, a secret variable on the public side and
a public one on the secret side are refused.

Two features of the role are not ported: the heartbeat-recovery extension and
the Codex v2026.9.1 registration backport. The playbook retired both
(``*_managed: false``); a config that manages either is refused.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from pydantic import Field, JsonValue, field_validator, model_validator

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.infra.docker_install import DockerInstallConfig
from ops_deploy.services._metrics_httpd import HttpdSwitchFields
from ops_deploy.services.openclaw import validate as role_validate
from ops_deploy.services.openclaw.variables import defaults, resolve

# The role variables that hold credentials (or, for the calendar map, may).
SECRET_VARIABLES = frozenset(
    {
        "openclaw_gateway_token",
        "openclaw_anthropic_api_key",
        "openclaw_openai_api_key",
        "openclaw_openrouter_api_key",
        "openclaw_ollama_api_key",
        "openclaw_telegram_bot_token",
        "openclaw_audio_transcription_api_key",
        "openclaw_weeknotes_s3_access_key",
        "openclaw_weeknotes_s3_secret_key",
        "openclaw_imap_account_map",
        "openclaw_smtp_account_map",
        "openclaw_calendar_account_map",
        "openclaw_calendar_map",
        "openclaw_paperless_token",
        "openclaw_homeassistant_token",
        "openclaw_opsgate_submit_token",
        "openclaw_metrics_endpoint_auth_password",
        "openclaw_gateway_config",
    }
)
NOT_PORTED = ("openclaw_heartbeat_recovery_managed", "openclaw_codex_v2026_9_1_registration_backport_managed")


def _known(values: dict[str, Any], *, secret: bool) -> dict[str, Any]:
    unknown = sorted(set(values) - set(defaults()))
    if unknown:
        raise ValueError(f"not variables of the openclaw_deploy role: {', '.join(unknown)}")
    wrong = sorted(name for name in values if (name in SECRET_VARIABLES) is not secret)
    if wrong:
        side = "public" if secret else "secret"
        raise ValueError(f"{', '.join(wrong)} belong to the {side} inputs")
    return values


class OpenClawSecrets(RoleConfig):
    """The secret role variables (credentials and the full config override)."""

    variables: dict[str, JsonValue] = Field(default_factory=dict, repr=False)

    @field_validator("variables")
    @classmethod
    def _secret_names(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _known(value, secret=True)


class OpenClawConfig(RoleConfig):
    """The non-secret role variables the playbook sets, and the fleet inputs the role reads."""

    variables: dict[str, JsonValue]
    # Fleet variables metrics_httpd_impl / _rust_version / _rust_sha256 (openclaw_metrics_endpoint_impl).
    httpd: HttpdSwitchFields = HttpdSwitchFields()
    # openclaw_install_docker: the docker_install role with its defaults.
    docker: DockerInstallConfig = DockerInstallConfig()

    @field_validator("variables")
    @classmethod
    def _public_names(cls, value: dict[str, Any]) -> dict[str, Any]:
        value = _known(value, secret=False)
        if not str(value.get("openclaw_version", "")).strip():
            raise ValueError("openclaw_version is required (a release tag such as v2026.10.2)")
        return value

    @model_validator(mode="after")
    def _ported_features(self) -> OpenClawConfig:
        names = resolve(self.variables, extra={"metrics_httpd_impl": self.httpd.httpd_impl})
        for name in NOT_PORTED:
            if names[name] is not False:
                raise ValueError(f"{name}: the port supports only the retired state (false)")
        if names["openclaw_metrics_endpoint_impl"] != self.httpd.httpd_impl:
            raise ValueError("openclaw_metrics_endpoint_impl must follow httpd.httpd_impl")
        return self

    def role_variables(self, secrets: OpenClawSecrets) -> dict[str, Any]:
        """Every role variable, resolved; checked with the role's validate.yml."""

        resolved = resolve({**self.variables, **secrets.variables}, extra={"metrics_httpd_impl": self.httpd.httpd_impl})
        role_validate.validate(resolved)
        return resolved


class OpenClawNyxmonChecks(RoleConfig):
    """The playbook's Nyxmon json-metrics checks (``_nyxmon_checks_json``), login data included."""

    service_name: str = "openclaw"
    user: UnixUser = "nyxmon"
    db_path: PurePosixPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")
    checks: tuple[dict[str, JsonValue], ...] = Field(min_length=1, repr=False)

    @field_validator("checks")
    @classmethod
    def _rows(cls, value: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
        for row in value:
            if set(row) != {"name", "check_type", "url", "check_interval", "data"} or not isinstance(row["data"], dict):
                raise ValueError("each check needs exactly name, check_type, url, check_interval and data")
        return value

    def revealed(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.checks]
