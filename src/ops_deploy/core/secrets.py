"""Secret references and the public side of secret handling.

This module never decrypts anything. A :class:`SecretRef` names an encrypted
file (for example ``secrets/prod/nyxmon.yml``) relative to the private
repository; a :class:`SecretStore` implementation in the private repository
turns it into :class:`SecretValues` on the controller.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from pathlib import PurePosixPath
from typing import NoReturn, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

SECRET_FILE_SUFFIXES = (".yml", ".yaml")


class MissingSecretKeysError(KeyError):
    """Raised when decrypted secrets lack keys a service requires."""


class SecretRef(BaseModel):
    """Reference to an encrypted secret file, relative to the private repo root."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: PurePosixPath

    def __init__(self, path: str | PurePosixPath | None = None, /, **data: object) -> None:
        if path is not None:
            data["path"] = path
        super().__init__(**data)

    @model_validator(mode="before")
    @classmethod
    def _from_plain_path(cls, value: object) -> object:
        # Allow ``secrets: secrets/prod/x.yml`` in config input.
        if isinstance(value, (str, PurePosixPath)):
            return {"path": value}
        return value

    @field_validator("path")
    @classmethod
    def _relative_yaml_path(cls, value: PurePosixPath) -> PurePosixPath:
        if value.is_absolute():
            raise ValueError("secret file path must be relative to the private repo root")
        if ".." in value.parts:
            raise ValueError("secret file path must not contain '..'")
        if value.suffix not in SECRET_FILE_SUFFIXES:
            raise ValueError(f"secret file must end in one of {SECRET_FILE_SUFFIXES}")
        return value

    def __str__(self) -> str:
        return str(self.path)


class SecretValues(Mapping[str, str]):
    """Decrypted secret values whose ``repr``/``str`` never show the values."""

    __slots__ = ("_ref", "_values")

    def __init__(self, ref: SecretRef, values: Mapping[str, str]) -> None:
        self._ref = ref
        self._values = dict(values)

    @property
    def ref(self) -> SecretRef:
        return self._ref

    def __getitem__(self, key: str) -> str:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        keys = ", ".join(sorted(self._values))
        return f"SecretValues({str(self._ref)!r}, keys=[{keys}], values=<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretValues must not be pickled")

    def require(self, keys: Iterable[str]) -> SecretValues:
        """Return self, or raise listing every key that is missing or empty."""

        missing = [key for key in keys if not self._values.get(key)]
        if missing:
            raise MissingSecretKeysError(f"{self._ref} is missing required keys: {', '.join(missing)}")
        return self


@runtime_checkable
class SecretStore(Protocol):
    """Controller-side secret loader, implemented in the private repository."""

    def load(self, ref: SecretRef) -> SecretValues: ...


class SecretContent:
    """File content that must only reach a host through ``secret_file``.

    ``repr``/``str`` never show the content, so the value is safe in pyinfra's
    operation argument list and in logs. Instances refuse to be pickled.
    """

    __slots__ = ("_data",)

    def __init__(self, data: str | bytes) -> None:
        self._data = data.encode() if isinstance(data, str) else bytes(data)

    def reveal(self) -> bytes:
        return self._data

    def __len__(self) -> int:
        return len(self._data)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SecretContent) and other._data == self._data

    def __hash__(self) -> int:
        return hash(self._data)

    def __repr__(self) -> str:
        return "SecretContent(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretContent must not be pickled")
