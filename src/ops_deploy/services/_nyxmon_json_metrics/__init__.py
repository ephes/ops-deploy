"""The Nyxmon json-metrics check upsert the host monitoring deploys share.

Port of the private side's ``tasks/upsert-nyxmon-json-metrics-check.yml``
(its json-metrics form) as a step a deploy calls on the Nyxmon host:
``files/json_metrics_check.py`` (its header lists the semantics) runs as the
Nyxmon user with ``python3 -I``. The check data, which carries a monitor
login, travels only on the upsert's stdin, never in argv or the environment
of the Nyxmon user's process; the probe needs no secret and compares
digests, so a converged database gets no mutating operation.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from pyinfra.operations import server

from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops import secret_stdin
from ops_deploy.services.nyxmon_site_checks.deploy import _URL, PlainPath, Text, _json_safe

SCRIPT = (Path(__file__).parent / "files" / "json_metrics_check.py").read_text()
CHECK_TYPE = "json-metrics"
# The task's ``retries: 7`` and ``delay: 5`` (a check Nyxmon is processing, a locked database).
RETRIES = 7
RETRY_DELAY = 5


class JsonMetricsCheck(BaseModel):
    """One json-metrics ``health_check`` row of the Nyxmon service ``service_name``.

    ``data`` is the check's settings without a login: its ``url`` (an http(s)
    URL, also the row's url) and a non-empty ``checks`` list are required, as
    the task asserts. With ``auth_username`` the upsert adds
    ``auth: {username, password}`` with the password the deploy passes in.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)

    service_name: Annotated[Text, Field(max_length=255)]
    name: Annotated[Text, Field(max_length=255)]
    check_interval: Annotated[StrictInt, Field(ge=1)]
    data: dict[str, Any]
    auth_username: Annotated[Text, Field(max_length=255)] | None = None
    user: UnixUser = "nyxmon"
    db_path: PlainPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")

    @field_validator("data", mode="before")
    @classmethod
    def _data_is_json(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise ValueError("data must be a mapping")
        return _json_safe(value)

    @model_validator(mode="after")
    def _data_is_a_json_metrics_check(self) -> JsonMetricsCheck:
        url = self.data.get("url")
        if not isinstance(url, str) or not _URL.fullmatch(url):
            raise ValueError("data.url must be an http(s) URL without whitespace, quotes or backslashes")
        checks = self.data.get("checks")
        if not isinstance(checks, list) or not checks:
            raise ValueError("data.checks must be a non-empty list of rules")
        if "auth" in self.data:
            raise ValueError("data must not carry auth; set auth_username, the deploy adds the password")
        return self

    @property
    def url(self) -> str:
        return str(self.data["url"])

    def desired_data(self, password: str | None) -> dict[str, Any]:
        """``data`` as the upsert stores it: with the login when ``auth_username`` is set."""

        if (self.auth_username is None) != (password is None):
            raise ValueError("a password must be given exactly when the check has auth_username")
        data: dict[str, Any] = json.loads(json.dumps(self.data))
        if self.auth_username is not None:
            data["auth"] = {"username": self.auth_username, "password": password}
        return data

    def stdin(self, password: str | None) -> str:
        return json.dumps({"check_interval": self.check_interval, "data": self.desired_data(password)})

    def digest(self, password: str | None) -> str:
        """What ``probe`` prints for a row that already holds this check (see the script)."""

        data_json = json.dumps(self.desired_data(password), sort_keys=True)
        state = json.dumps([CHECK_TYPE, self.url, self.check_interval, data_json, 0])
        return hashlib.sha256(state.encode()).hexdigest()


def check_command(check: JsonMetricsCheck, mode: Literal["guard", "probe", "apply"]) -> str:
    """``files/json_metrics_check.py`` in ``mode`` as the Nyxmon user, isolated from its Python setup."""

    args = [str(check.db_path)] if mode == "guard" else [str(check.db_path), check.service_name, check.name]
    return shlex.join(["runuser", "-u", check.user, "--", "python3", "-I", "-c", SCRIPT, mode, *args])


def upsert_json_metrics_check(check: JsonMetricsCheck, password: str | None) -> None:
    """Require a private Nyxmon database, then upsert ``check`` unless it is already current."""

    mark_read_only(
        server.shell(
            name=f"Require a private Nyxmon database for {check.name}",
            commands=[check_command(check, "guard")],
        )
    )
    label = f"Nyxmon check {check.name}"
    found = probe(check_command(check, "probe"), name=label)
    if found is not None and found.splitlines()[-1:] == [f"check {check.digest(password)}"]:
        return
    secret_stdin(
        name=f"Upsert {label}",
        command=check_command(check, "apply"),
        content=SecretContent(check.stdin(password)),
        _retries=RETRIES,
        _retry_delay=RETRY_DELAY,
    )
    if found is None:
        verify_probe(check_command(check, "probe"), name=label)
