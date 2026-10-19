"""Read-only venv metadata inventory; a match is never permission to adopt or execute."""

from __future__ import annotations

import json
import re
import shlex
from importlib.resources import files
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.facts.server import Command

from ops_deploy.base._common import Sha256
from ops_deploy.services.compose_app.config import Part, PlainPath

DistributionName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
DistributionVersion = Annotated[
    str,
    Field(
        max_length=128,
        pattern=r"^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
        r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*)?$",
    ),
]
PythonVersion = Annotated[str, Field(max_length=32, pattern=r"^3\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")]


class VenvInventoryRequest(Part):
    """Expected declared metadata, including the complete intended distribution inventory."""

    venv: PlainPath
    owner_uid: Annotated[int, Field(strict=True, ge=0, le=4294967294)]
    python_version: PythonVersion
    distributions: dict[DistributionName, DistributionVersion] = Field(max_length=4096)

    @model_validator(mode="after")
    def _canonical_names(self) -> Self:
        if len(str(self.venv)) > 4096 or len(self.model_dump_json()) > 65536:
            raise ValueError("venv inventory request exceeds its bounded command size")
        names = [re.sub(r"[-_.]+", "-", name).lower() for name in self.distributions]
        if len(names) != len(set(names)):
            raise ValueError("distribution aliases must be unique")
        return self


class VenvInventoryResult(Part):
    """Only declared names/versions are identified; executable and file integrity are unproven."""

    status: Literal[
        "absent", "refused_untrusted", "unknown", "matching_candidate", "different_inventory", "recognizable_newer"
    ]
    reason: Literal[
        "absent",
        "unsafe_path",
        "unsafe_owner_or_mode",
        "unsupported_layout",
        "malformed_metadata",
        "limits_exceeded",
        "changed_during_read",
        "unreadable",
        "different_python",
        "different_distributions",
        "uncomparable_version",
        "metadata_matches",
    ]
    declared_python: PythonVersion | None = None
    distribution_count: Annotated[int, Field(ge=0, le=4096)] | None = None
    inventory_identity: Sha256 | None = None
    python_entry: Literal["regular", "symlink"] | None = None

    @model_validator(mode="after")
    def _candidate_evidence(self) -> Self:
        if self.status == "matching_candidate" and (
            self.reason != "metadata_matches"
            or self.declared_python is None
            or self.distribution_count is None
            or self.inventory_identity is None
            or self.python_entry is None
        ):
            raise ValueError("matching metadata requires the complete bounded observation")
        if self.reason == "metadata_matches" and self.status != "matching_candidate":
            raise ValueError("metadata match reason requires a matching candidate")
        return self


def venv_inventory_command(request: VenvInventoryRequest) -> str:
    """Command using the independently trusted system Python, never a venv executable."""

    code = files("ops_deploy.services.native_app").joinpath("files/venv_inventory_host.py").read_text()
    return shlex.join(["/usr/bin/python3", "-I", "-S", "-B", "-c", code, request.model_dump_json()])


def probe_venv_inventory(request: VenvInventoryRequest) -> VenvInventoryResult:
    """Read a host fact without registering operations or changing Native deployment dispatch.

    A matching candidate is a metadata observation, not executable trust, actual
    Python identity, dependency content integrity, adoption or liveness proof.
    """

    output = host.get_fact(Command, command=venv_inventory_command(request))
    try:
        if not isinstance(output, str) or len(output) > 4096:
            raise ValueError
        return VenvInventoryResult.model_validate(json.loads(output))
    except (ValueError, TypeError):
        raise ValueError("native venv inventory probe returned an invalid bounded result") from None
