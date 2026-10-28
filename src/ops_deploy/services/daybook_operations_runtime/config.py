"""Protected Daybook runtime profile, preserving the schema-five role contract."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.core.git_source import CommitSha

Adapter = Literal[
    "voice_memos.ingest.v1",
    "voice_memos.transcribe_long.v1",
    "mail.work.v1",
    "mail.review.v1",
    "sessions.ship.v1",
    "archive.classify_quotes.v1",
    "weeknotes.reconcile.v1",
    "voice_memos.work.v1",
    "photos.archive_sync.v1",
    "photos.archive.v1",
    "catalog.work.v1",
    "paperless.intake.v1",
]
Action = Literal["install", "replace", "cutover", "rollback", "closeout", "stop", "verify"]
Name = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,49}$")]
HostName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,49}$")]


class RuntimeKind(RoleConfig):
    adapter: Adapter
    deadline: Annotated[StrictInt, Field(ge=60, le=3600)]
    lease: StrictInt
    long: StrictBool | None = None
    run: dict[str, JsonValue] | None = None

    @model_validator(mode="after")
    def _lease(self) -> Self:
        if self.lease < self.deadline + 60:
            raise ValueError("lease must cover the deadline plus sixty seconds")
        return self


class RuntimeWorkers(RoleConfig):
    count: Annotated[StrictInt, Field(ge=2, le=16)] = 2
    long: Annotated[StrictInt, Field(ge=1)] = 1

    @model_validator(mode="after")
    def _reserve(self) -> Self:
        if self.long >= self.count:
            raise ValueError("long work must leave at least one worker available")
        return self


class RuntimeStopWindow(RoleConfig):
    start: Annotated[str, Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")]
    end: Annotated[str, Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")]


class RuntimeStopPolicy(RoleConfig):
    """Original stop-window inputs; the private update wrapper supplies windows."""

    windows: tuple[RuntimeStopWindow, ...] = ()
    lead_minutes: Annotated[StrictInt, Field(ge=0)] = 0
    timezone: Annotated[str, Field(pattern=r"^[A-Za-z0-9_+/-]+$")] = "Europe/Berlin"

    @model_validator(mode="after")
    def _same_day(self) -> Self:
        for window in self.windows:
            start = int(window.start[:2]) * 60 + int(window.start[3:])
            end = int(window.end[:2]) * 60 + int(window.end[3:])
            if start - self.lead_minutes < 0 or start >= end:
                raise ValueError("stop window and lead must fit one day")
        return self


class DaybookRuntimeConfig(RoleConfig):
    """Nonsecret declaration. Revision is the once-per-run resolved Main commit.

    The controller resolver binds that revision; accepting a commit here does not
    give an operator an alternative pin or bypass Main-only source selection.
    """

    user: UnixUser
    revision: CommitSha
    owner: Literal["root", "user"] = "root"
    action: Action = "install"
    confirmed: StrictBool = False
    start: StrictBool = False
    home: PurePosixPath | None = None
    install_root: PurePosixPath | None = None
    python: PurePosixPath | None = None
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]+\.[0-9]+$")] = "3.14.7"
    uv_bin: PurePosixPath = PurePosixPath("/opt/homebrew/bin/uv")
    policy: PurePosixPath | None = None
    importer_policy: PurePosixPath | None = None
    credential: PurePosixPath | None = None
    api_url: str = "https://operations.home.example.com"
    journal: PurePosixPath | None = None
    mode: Literal["serve", "host"] = "serve"
    host_socket: HostName = "daybook-host"
    host_session: HostName = "host"
    host_tmux: PurePosixPath = PurePosixPath("/opt/homebrew/bin/tmux")
    host_tmpdir: PurePosixPath = PurePosixPath("/private/tmp")
    host_lock: PurePosixPath | None = None
    host_application: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._-]+$")] = "Ghostty"
    workers: RuntimeWorkers = RuntimeWorkers()
    kinds: tuple[RuntimeKind, ...] = (RuntimeKind(adapter="voice_memos.ingest.v1", deadline=330, lease=600),)
    label: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")] = "de.wersdoerfer.daybook.voice-memo-inbox"
    plist: PurePosixPath | None = None
    staged_plist: PurePosixPath | None = None
    legacy_plist: PurePosixPath | None = None
    closeout_marker: PurePosixPath | None = None
    status_sources: tuple[Name, ...] = ("regular",)
    quiet_retries: Annotated[StrictInt, Field(ge=1)] = 30
    quiet_delay: Annotated[StrictInt, Field(ge=0)] = 10
    stop_timeout: Annotated[StrictInt, Field(ge=1)] = 300
    verify_retries: Annotated[StrictInt, Field(ge=1)] = 12
    poll_delay: Annotated[StrictInt, Field(ge=0)] = 5

    @field_validator(
        "home",
        "install_root",
        "python",
        "uv_bin",
        "policy",
        "importer_policy",
        "credential",
        "journal",
        "host_tmux",
        "host_tmpdir",
        "host_lock",
        "plist",
        "staged_plist",
        "legacy_plist",
        "closeout_marker",
    )
    @classmethod
    def _path(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is not None and (
            not value.is_absolute()
            or str(value) == "/"
            or ".." in value.parts
            or any(ord(c) < 32 or ord(c) == 127 for c in str(value))
        ):
            raise ValueError("runtime paths must be absolute non-root paths without traversal/control characters")
        return value

    @field_validator("api_url")
    @classmethod
    def _origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or value != f"https://{parsed.netloc}"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("runtime API must be an HTTPS origin without credentials or path")
        # Accessing .port validates both the numeric range and malformed ports.
        _ = parsed.port
        return value

    @model_validator(mode="after")
    def _defaults_and_guards(self) -> Self:
        if self.user == "CHANGEME":
            raise ValueError("runtime requires an existing GUI user")
        if self.action not in {"install", "verify"} and not self.confirmed:
            raise ValueError("runtime transition requires the original confirmation")
        if self.start and (not self.confirmed or self.action in {"replace", "closeout", "stop", "verify"}):
            raise ValueError("runtime start is not permitted for this action")
        if not self.kinds or len({k.adapter for k in self.kinds}) != len(self.kinds):
            raise ValueError("runtime requires distinct nonempty kinds")
        if not self.status_sources or len(set(self.status_sources)) != len(self.status_sources):
            raise ValueError("runtime requires distinct nonempty status sources")
        self._default("home", PurePosixPath("/Users") / self.user)
        assert self.home is not None
        self._default(
            "install_root",
            (
                PurePosixPath("/Library/Application Support/Daybook/voice-memo-inbox")
                if self.owner == "root"
                else self.home / "Library/Application Support/Daybook/operations"
            ),
        )
        assert self.install_root is not None
        for name, value in {
            "python": self.install_root / "daybook/.venv/bin/python",
            "policy": self.install_root / "operations.json",
            "importer_policy": self.install_root / "policy.json",
            "credential": self.home / ".config/daybook-voice-memo-inbox/operations.json",
            "journal": self.home / ".local/state/daybook/operations",
            "host_lock": self.home / ".local/state/daybook/host/host.lock",
            "plist": self.home / "Library/LaunchAgents" / (self.label + ".plist"),
            "staged_plist": self.install_root / "operations.launchd.plist",
            "legacy_plist": self.install_root / "regular-importer.before-operations.plist",
            "closeout_marker": self.install_root / "closed-out",
        }.items():
            self._default(name, value)
        return self

    def _default(self, name: str, value: PurePosixPath) -> None:
        if getattr(self, name) is None:
            object.__setattr__(self, name, value)
