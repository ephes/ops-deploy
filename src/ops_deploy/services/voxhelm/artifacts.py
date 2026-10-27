"""Explicit existing-artifact continuity descriptions, not integrity attestations."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FileContinuity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    dev: int = Field(ge=0)
    ino: int = Field(gt=0)
    size: int = Field(gt=0)
    mtime_ns: int = Field(ge=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mode: int = Field(ge=0, le=0o7777)


class ArtifactMetadata(FileContinuity):
    kind: Literal["regular", "symlink"]
    target: str | None = None
    referent: FileContinuity | None = None

    @model_validator(mode="after")
    def _link(self) -> Self:
        if self.kind == "symlink" and (not self.target or self.referent is None):
            raise ValueError("Artifact link continuity requires its exact target and referent metadata")
        if self.kind == "regular" and (self.target is not None or self.referent is not None):
            raise ValueError("Regular artifact continuity cannot carry link metadata")
        return self


class ArtifactContinuity(BaseModel):
    """Configured historical pin plus observed metadata; no body was read."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    pin: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata: ArtifactMetadata
