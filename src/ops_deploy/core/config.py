"""Typed service configuration.

Every service config subclasses :class:`BaseServiceConfig`. Validation runs on
the controller before any connection is opened, so a bad config fails fast and
is unit-testable without a host.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import PurePath, PurePosixPath
from typing import Annotated, Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_core import InitErrorDetails

from ops_deploy.core.secrets import SecretRef

PLACEHOLDER_MARKER = "CHANGEME"

SERVICE_NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
UNIX_USER_PATTERN = r"^[a-z_][a-z0-9_-]{0,31}$"

# Reuse these when a subclass overrides a field with a default: redeclaring a
# pydantic field replaces its constraints, so a bare ``str`` would drop them.
ServiceName = Annotated[str, Field(pattern=SERVICE_NAME_PATTERN)]
UnixUser = Annotated[str, Field(pattern=UNIX_USER_PATTERN)]


class BaseServiceConfig(BaseModel):
    """Base class for all service configurations.

    - unknown keys are rejected (typos fail instead of being ignored),
    - instances are immutable once validated,
    - any string containing ``CHANGEME`` is rejected, including inside nested
      models, lists, dicts and :class:`~pydantic.SecretStr` values,
    - ``secrets`` points at an encrypted file; plaintext never lives here.

    Subclasses list the keys their secret file must provide in
    ``required_secret_keys``; the private side checks them after decryption.
    """

    # hide_input_in_errors: a ValidationError must never echo a (secret) value.
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)

    required_secret_keys: ClassVar[tuple[str, ...]] = ()

    service_name: ServiceName
    user: UnixUser
    site_path: PurePosixPath
    secrets: SecretRef | None = None

    @field_validator("site_path")
    @classmethod
    def _site_path_absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute():
            raise ValueError("site_path must be an absolute POSIX path")
        if ".." in value.parts:
            raise ValueError("site_path must not contain '..'")
        if value == PurePosixPath("/"):
            raise ValueError("site_path must not be '/'")
        return value

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as exc:
            raise _sanitized(exc) from None

    @classmethod
    def model_validate(cls, obj: Any, *args: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, *args, **kwargs)
        except ValidationError as exc:
            raise _sanitized(exc) from None

    @classmethod
    def model_validate_json(cls, json_data: Any, *args: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_json(json_data, *args, **kwargs)
        except ValidationError as exc:
            raise _sanitized(exc) from None

    @classmethod
    def model_validate_strings(cls, obj: Any, *args: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate_strings(obj, *args, **kwargs)
        except ValidationError as exc:
            raise _sanitized(exc) from None

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        # Fail early on literal placeholder defaults. Factories are not called
        # here (they may need validated data); their output is checked by the
        # after-validator, and any error they cause is sanitized.
        super().__pydantic_init_subclass__(**kwargs)
        for name, info in cls.model_fields.items():
            if info.default_factory is not None:
                continue
            for location in _placeholder_locations(info.default, name):
                raise TypeError(
                    f"{cls.__name__}: default of {location} contains the placeholder {PLACEHOLDER_MARKER!r}"
                )

    @model_validator(mode="before")
    @classmethod
    def _reject_placeholders_in_input(cls, data: Any) -> Any:
        # Runs before field validation: a field error would otherwise put a
        # placeholder-bearing mapping key into the error location verbatim.
        _raise_on_placeholder(data)
        return data

    @model_validator(mode="after")
    def _reject_placeholders(self) -> BaseServiceConfig:
        # Also covers defaults, which never pass through the input check.
        _raise_on_placeholder(self)
        return self

    @model_validator(mode="after")
    def _secrets_required_when_keys_declared(self) -> BaseServiceConfig:
        if self.required_secret_keys and self.secrets is None:
            raise ValueError(
                f"{type(self).__name__} requires a secrets file providing {', '.join(self.required_secret_keys)}"
            )
        return self


def _sanitized(exc: ValidationError) -> ValidationError:
    """Rebuild ``exc`` without input values and with placeholder-bearing locations redacted.

    This is the structural guarantee behind "errors never echo a secret":
    whatever path produced the error (input, defaults, factories, nested
    models), the raised error carries no input and no marker-bearing key.
    """

    details: list[InitErrorDetails] = []
    for error in exc.errors(include_url=False):
        detail: InitErrorDetails = {
            "type": error["type"],
            "loc": tuple(_redact_loc(part) for part in error["loc"]),
            "input": None,
        }
        if "ctx" in error:
            detail["ctx"] = error["ctx"]
        details.append(detail)
    return ValidationError.from_exception_data(exc.title, details, hide_input=True)


def _redact_loc(part: str | int) -> str | int:
    if isinstance(part, str) and PLACEHOLDER_MARKER in part:
        return "<key>"
    return part


def _raise_on_placeholder(value: Any) -> None:
    for location in _placeholder_locations(value):
        raise ValueError(f"{location} still contains the placeholder {PLACEHOLDER_MARKER!r}")


def _placeholder_locations(value: Any, path: str = "") -> Iterator[str]:
    """Yield dotted locations of every string value containing the marker."""

    label = path or "<root>"
    if isinstance(value, SecretStr):
        if PLACEHOLDER_MARKER in value.get_secret_value():
            yield label
    elif isinstance(value, str):
        if PLACEHOLDER_MARKER in value:
            yield label
    elif isinstance(value, PurePath):
        if PLACEHOLDER_MARKER in str(value):
            yield label
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _placeholder_locations(getattr(value, name), _join(path, name))
    elif isinstance(value, Mapping):
        for key, item in value.items():
            text_key = key.decode("utf-8", errors="replace") if isinstance(key, (bytes, bytearray)) else key
            if isinstance(text_key, str) and PLACEHOLDER_MARKER in text_key:
                # The key itself may be a mistyped secret: do not echo it.
                yield f"{label}[<key>]"
            yield from _placeholder_locations(item, _join(path, str(key)))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            yield from _placeholder_locations(item, f"{label}[{index}]")


def _join(path: str, name: str) -> str:
    return f"{path}.{name}" if path else name
