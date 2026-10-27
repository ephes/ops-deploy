"""Nyxmon site checks: one Nyxmon service and its health checks, upserted in Nyxmon's SQLite database.

Port of the site-check provisioning playbooks on the private side: a play
on the Nyxmon host that requires the Nyxmon database (and optionally a
literal in a deployed Nyxmon source file, so checks that need a newer
Nyxmon are never written for an older one) and upserts one service row and
its checks as the Nyxmon user. Checks named in ``remove_checks`` are deleted
from that service with their results and notification state, as Nyxmon's
dashboard deletes a check. Nothing else is touched: no service restart, no
other service's rows, and checks that are neither listed nor named stay.
The checks reach the script on stdin, never on a command line or in an
environment (check data can carry a monitor login).

While planning, ``files/site_checks.py check`` runs the apply's comparison
on a read-only connection; a converged database gets no mutating operation.
"""

from __future__ import annotations

import json
import math
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)
from pyinfra.api import deploy
from pyinfra.operations import server

from ops_deploy.core.config import BaseServiceConfig, UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import last_line, probe, verify_probe, when_present
from ops_deploy.ops import secret_stdin

SCRIPT = (Path(__file__).parent / "files" / "site_checks.py").read_text()
URL_CHECK_TYPES = frozenset({"http", "json-metrics"})
MAX_DATA_DEPTH = 16

# Commands carry these values; control characters and backslashes are refused
# so that every command stays one line a fish login shell passes unchanged.
_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f-\x9f\\]")
_URL = re.compile(r"^https?://[^\s\"'\\]+$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$"
)
_PLAIN_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")


def _plain_text(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be empty or blank")
    if _UNSAFE_TEXT.search(value):
        raise ValueError("must not contain control characters or backslashes")
    return value


def _plain_path(value: PurePosixPath) -> PurePosixPath:
    if not _PLAIN_PATH.fullmatch(str(value)) or ".." in value.parts or value == PurePosixPath("/"):
        raise ValueError("must be an absolute path of letters, digits, '.', '_', '-' and '/', without '..'")
    return value


Text = Annotated[StrictStr, AfterValidator(_plain_text)]
PlainPath = Annotated[PurePosixPath, AfterValidator(_plain_path)]


def _json_safe(value: Any, depth: int = 0) -> Any:
    """``value`` as JSON-ready data, types unchanged (``10.0`` stays a float, ``3`` an int)."""

    if depth > MAX_DATA_DEPTH:
        raise ValueError(f"data must not nest deeper than {MAX_DATA_DEPTH} levels")
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("data must not contain NaN or infinite numbers")
        return value
    if isinstance(value, str):
        if _UNSAFE_TEXT.search(value):
            raise ValueError("data strings must not contain control characters or backslashes")
        return value
    if isinstance(value, list | tuple):
        return [_json_safe(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or _UNSAFE_TEXT.search(key):
                raise ValueError("data keys must be non-empty strings without control characters or backslashes")
            result[key] = _json_safe(item, depth + 1)
        return result
    raise ValueError("data must hold only JSON values (objects, arrays, strings, numbers, booleans, null)")


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)


class SiteCheck(_Part):
    """One ``health_check`` row: what Nyxmon checks, how often, with which settings (``data``)."""

    name: Annotated[Text, Field(max_length=255)]
    check_type: Literal["http", "json-metrics", "tcp", "imap"]
    # An http(s) URL for http and json-metrics checks, a host name for tcp/imap checks.
    url: Annotated[StrictStr, Field(max_length=512)]
    check_interval: Annotated[StrictInt, Field(ge=1)]
    data: dict[str, Any]

    @field_validator("data", mode="before")
    @classmethod
    def _data_is_json(cls, value: Any) -> Any:
        # Before pydantic's own validation, which would coerce keys (b"k" to "k").
        if not isinstance(value, dict):
            raise ValueError("data must be a mapping")
        return _json_safe(value)

    @model_validator(mode="after")
    def _url_fits_the_type(self) -> SiteCheck:
        if self.check_type in URL_CHECK_TYPES:
            if not _URL.fullmatch(self.url) or _UNSAFE_TEXT.search(self.url):
                raise ValueError(
                    "http and json-metrics checks need an http(s) URL without whitespace, quotes or backslashes"
                )
        elif not _HOSTNAME.fullmatch(self.url):
            raise ValueError("tcp and imap checks need a host name")
        return self

    def as_json(self) -> dict[str, Any]:
        """The check as the playbooks hand it to the upsert (one entry of :func:`checks_json`)."""

        return {
            "name": self.name,
            "check_type": self.check_type,
            "url": self.url,
            "check_interval": self.check_interval,
            "data": json.loads(json.dumps(self.data)),
        }


class SourceLiteral(_Part):
    """A literal a deployed file must contain before any check is written (``grep -Fq``)."""

    path: PlainPath
    literal: Annotated[Text, Field(max_length=200)]


class NyxmonSiteChecksConfig(BaseServiceConfig):
    """One Nyxmon service (``service_name``, the ``service`` row's name) and its checks."""

    user: UnixUser = "nyxmon"
    site_path: PurePosixPath = PurePosixPath("/home/nyxmon/site")
    db_path: PlainPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")
    checks: tuple[SiteCheck, ...] = ()
    # Names of checks of this service to delete (with their results and
    # notification state); a name that is not there is already converged.
    remove_checks: tuple[Annotated[Text, Field(max_length=255)], ...] = ()
    require_literal: SourceLiteral | None = None
    managed_safety: bool = False

    @model_validator(mode="after")
    def _unique_check_names(self) -> NyxmonSiteChecksConfig:
        if not self.checks and not self.remove_checks:
            raise ValueError("checks or remove_checks must name at least one check")
        if self.managed_safety and self.remove_checks:
            raise ValueError("managed checks cannot remove checks")
        names = [check.name for check in self.checks]
        if len(set(names)) != len(names):
            raise ValueError("check names must be unique")
        if len(set(self.remove_checks)) != len(self.remove_checks):
            raise ValueError("remove_checks names must be unique")
        if set(names) & set(self.remove_checks):
            raise ValueError("a check must not be both in checks and in remove_checks")
        return self


def checks_json(cfg: NyxmonSiteChecksConfig) -> str:
    """The checks in config order, as ``files/site_checks.py`` reads them from stdin.

    Without ``remove_checks`` this is the plain list the playbooks pass;
    with it, an object ``{"checks": [...], "remove": [...]}``.
    """

    checks = [check.as_json() for check in cfg.checks]
    if not cfg.remove_checks:
        return json.dumps(checks)
    return json.dumps({"checks": checks, "remove": list(cfg.remove_checks)})


def site_checks_command(cfg: NyxmonSiteChecksConfig, mode: Literal["check", "apply"]) -> str:
    """``files/site_checks.py`` in ``mode`` as the Nyxmon user, isolated from the user's Python setup.

    The command reads :func:`checks_json` on stdin.
    """

    env = {"NYXMON_DB_PATH": str(cfg.db_path), "NYXMON_SERVICE_NAME": cfg.service_name}
    assignments = [f"{key}={value}" for key, value in env.items()]
    return shlex.join(
        [
            "runuser",
            "-u",
            cfg.user,
            "--",
            "env",
            *assignments,
            "python3",
            "-I",
            "-c",
            SCRIPT,
            mode,
            *(["--managed-safety"] if cfg.managed_safety else []),
        ]
    )


def _require(name: str, test: str, message: str) -> None:
    mark_read_only(server.shell(name=name, commands=[f"{test} || {{ echo {shlex.quote(message)} >&2; exit 1; }}"]))


@deploy("Provision Nyxmon site checks")
def deploy_nyxmon_site_checks(cfg: NyxmonSiteChecksConfig) -> None:
    required = cfg.require_literal
    if required is not None:
        _require(
            f"Require {required.literal} in {required.path}",
            shlex.join(["grep", "-Fq", "-e", required.literal, "--", str(required.path)]),
            f"{required.path} lacks {required.literal}: deploy a Nyxmon that supports these checks, then rerun",
        )
    db = shlex.quote(str(cfg.db_path))
    _require("Require the Nyxmon database", f"test -e {db}", f"Nyxmon database not found at {cfg.db_path}")

    name = f"Nyxmon checks for {cfg.service_name}"
    check = when_present([cfg.db_path], last_line(site_checks_command(cfg, "check")), otherwise="missing")
    payload = checks_json(cfg) + "\n"
    state = probe(check, name=name, stdin=payload)
    if (state or "").strip() == "changed=false":
        return
    retry_options: dict[str, Any] = {"_retries": 7, "_retry_delay": 5} if cfg.managed_safety else {}
    secret_stdin(
        name=f"Upsert {name}",
        command=site_checks_command(cfg, "apply"),
        content=SecretContent(payload),
        **retry_options,
    )
    if state is None:
        verify_probe(check, name=name, expect="changed=false", stdin=payload)
