"""Traefik ingress acceptance probes: capture a baseline, install it, verify it.

Port of the ``health_probe_capture`` and ``health_probe`` task entries of
ops-library's ``traefik_deploy`` role (checked against ops-library
``3110a0f1``). The probe program itself, ``files/traefik_health_probe.py``,
is vendored byte for byte, so a host set up by either tool runs the same
program with the same SHA256.

- :func:`capture_traefik_health_probes` (read-only): runs the program's
  ``capture`` mode from a private temporary directory on the host and
  returns the spec merged with the observed ingress results and the hashes of
  the permanent dynamic files. It never touches the installed probes,
  Traefik, routes or units.
- :func:`deploy_traefik_health_probes` (pyinfra): installs the program and the
  captured baseline root-owned under ``/var/lib/traefik-update-probes`` and
  verifies it against live ingress.
- :func:`verify_traefik_health_probes` (read-only): checks the installed
  program and baseline and runs ``health``; returns the exact argv/SHA256
  commands a transaction request takes (:class:`ProbeCommands`).

Capture and verify run from the controller through a
:data:`~ops_deploy.backups.remote.Runner` (``ssh`` to the host, script on
stdin), like the steps in :mod:`ops_deploy.backups`: their result decides what
the caller does next, and a pyinfra operation is planned before it runs and
cannot hand a result back.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import shlex
from io import BytesIO
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, Runner
from ops_deploy.base._common import RoleConfig, output, require_linux
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.infra._common import directory
from ops_deploy.ops.secret_file import secret_file

PROGRAM = (Path(__file__).parent / "files" / "traefik_health_probe.py").read_bytes()
PROGRAM_SHA256 = hashlib.sha256(PROGRAM).hexdigest()
PROBE_DIR = "/var/lib/traefik-update-probes"
PROGRAM_PATH = f"{PROBE_DIR}/health.py"
CHECKS_PATH = f"{PROBE_DIR}/checks.json"
# The role pins this interpreter for installation checks and the transaction's probes.
PYTHON = "/usr/bin/python3"
CAPTURE_PREFIX = "traefik-probe-capture-"
# Program modes and the transaction request keys of their commands, as the role returns them.
COMMAND_MODES = {
    "baseline_probe": "health",
    "acceptance_probe": "health",
    "alias_acceptance_probe": "alias",
    "metrics_bind_acceptance_probe": "metrics_bind",
    "cleanup_probe": "cleanup",
}

_HEX64 = r"^[0-9a-f]{64}$"
# A DNS name as curl's --resolve and TLS SNI take it.
Hostname = Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")]


def _ip_literal(value: str) -> str:
    # curl's --resolve takes only IP literals: with a name it fails before
    # connecting (exit 49), and capture would record that as the baseline.
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("address must be an IP address (IPv6 without brackets)") from None
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        raise ValueError("address must not carry an IPv6 zone")
    return value


# An IP address (IPv6 without brackets), as curl --resolve and socket.create_connection take it.
Address = Annotated[StrictStr, AfterValidator(_ip_literal)]
UrlPath = Annotated[StrictStr, Field(pattern=r"^/[!-~]*$", max_length=2048)]
EntrypointName = Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
DynamicFile = Annotated[StrictStr, Field(min_length=1, max_length=4096)]
Digest = Annotated[StrictStr, Field(pattern=_HEX64)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Probe(_Strict):
    """One ingress request: ``scheme://host:port/path`` sent to ``address``."""

    host: Hostname
    scheme: Literal["http", "https"]
    port: Annotated[StrictInt, Field(ge=1, le=65535)]
    address: Address
    # Absent means ``/``; an explicit null would become part of the URL.
    path: UrlPath = "/"


class Observation(_Strict):
    """What ``capture`` recorded for one probe (curl status and exit, TLS leaf)."""

    status: Annotated[StrictStr, Field(pattern=r"^[0-9]{0,3}$")]
    exit: StrictInt
    tls_sha256: Digest | None = None
    tls_error: Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9_]{1,64}$")] | None = None


class ProbeSpec(_Strict):
    """The private probe specification: explicit probes and entrypoint names.

    ``tls_fingerprints``: also record the served TLS leaf of each HTTPS probe;
    health then refuses any change of it.
    """

    probes: Annotated[tuple[Probe, ...], Field(min_length=1)]
    entrypoints: Annotated[tuple[EntrypointName, ...], Field(min_length=1)]
    tls_fingerprints: StrictBool = False


class ProbeBaseline(ProbeSpec):
    """A spec merged with what ``capture`` observed: the installed ``checks.json``."""

    observations: tuple[Observation, ...]
    dynamic: dict[DynamicFile, Digest]

    @model_validator(mode="after")
    def complete(self) -> Self:
        if len(self.observations) != len(self.probes):
            raise ValueError("observations must match the probes one to one")
        if self.tls_fingerprints is True and any(
            probe.scheme == "https" and "tls_sha256" not in observed.model_fields_set
            for probe, observed in zip(self.probes, self.observations, strict=True)
        ):
            raise ValueError("Missing captured TLS fingerprint baseline")
        return self


class ProbeCommand(_Strict):
    """A transaction request's probe: argv run as root, SHA256 of ``argv[0]``."""

    argv: tuple[str, ...]
    sha256: Digest


class ProbeCommands(_Strict):
    """The role's ``traefik_health_probe_commands``, keyed like the transaction request."""

    baseline_probe: ProbeCommand
    acceptance_probe: ProbeCommand
    alias_acceptance_probe: ProbeCommand
    metrics_bind_acceptance_probe: ProbeCommand
    cleanup_probe: ProbeCommand

    def as_request(self) -> dict[str, dict[str, object]]:
        """Plain JSON for the transaction request (argv as lists)."""

        return {key: {"argv": list(cmd.argv), "sha256": cmd.sha256} for key, cmd in self}


class TraefikHealthProbesConfig(RoleConfig):
    """Input of :func:`deploy_traefik_health_probes`: the captured baseline."""

    baseline: ProbeBaseline


class ProbeError(RuntimeError):
    """Capture or verification failed or was refused; nothing was installed by it.

    The message is one of a fixed set of reasons with public paths only, never
    a probe's host or address: the program's own output names them, so the
    scripts classify it on the host instead of passing it on.
    """


def config_json(config: ProbeSpec) -> str:
    """The configuration as the role writes it: ``to_nice_json`` (no trailing newline).

    Only the keys that were given are written, so a baseline read from a
    file the role wrote serialises to the same bytes.
    """

    data = config.model_dump(mode="json", exclude_unset=True)
    return json.dumps(data, indent=4, sort_keys=True, separators=(",", ": "))


def probe_commands(sha256: str = PROGRAM_SHA256) -> ProbeCommands:
    """The five commands, run as the role returns them: program, mode, ``checks.json``."""

    return ProbeCommands.model_validate(
        {key: {"argv": (PROGRAM_PATH, mode, CHECKS_PATH), "sha256": sha256} for key, mode in COMMAND_MODES.items()}
    )


def _blob(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii")


_PYTHON_CHECK = f"""fail() {{ echo "traefik probes: $*" >&2; exit 1; }}
if ! {PYTHON} -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    fail "{PYTHON} 3.11 or newer is required"
fi
"""

# Read-only: copies the program and spec into a fresh private directory, runs
# ``capture`` there and removes only that directory (also on failure or TERM).
_CAPTURE = """set -euo pipefail
umask 077
{python_check}dir=$(mktemp -d -t {prefix}XXXXXXXXXX)
trap 'rm -rf -- "$dir"' EXIT
trap 'exit 143' TERM HUP INT
base64 -d >"$dir/health.py" <<'OPS_DEPLOY_PROGRAM'
{program}OPS_DEPLOY_PROGRAM
base64 -d >"$dir/spec.json" <<'OPS_DEPLOY_SPEC'
{spec}OPS_DEPLOY_SPEC
chmod 0700 "$dir/health.py"
chmod 0600 "$dir/spec.json"
if ! result=$({python} "$dir/health.py" capture "$dir/spec.json" 2>"$dir/stderr"); then
    grep -q 'At least one explicit ingress probe is required' "$dir/stderr" && fail "no probes"
    fail "capture failed"
fi
printf '%s' "$result"
"""

# Read-only: $1 is the expected program SHA256. The program must be a
# root-owned regular file nobody else can write, below root-owned directories
# nobody else can write (what the transaction engine requires of a probe), and
# checks.json a root-owned 0600 regular file. Prints the program's SHA256 after
# a passing ``health`` run, which runs the program as the engine does: directly,
# through its ``/usr/bin/python3`` shebang. Failures are reported as fixed
# reasons. No backslashes: pyinfra sends it through the login shell.
VERIFY_SCRIPT = f"""set -euo pipefail
{_PYTHON_CHECK}expected=$1
program={PROGRAM_PATH}
checks={CHECKS_PATH}
for path in "$program" "$checks"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "$path is not a regular file"
done
read -r owner mode <<<"$(stat -c '%u:%g %a' -- "$program")"
[ "$owner" = 0:0 ] || fail "$program is not owned by root"
[ -x "$program" ] || fail "$program is not executable"
case "$mode" in *[2367]?|*[2367]) fail "$program is writable by group or others ($mode)" ;; esac
path=$program
while [ "$path" != / ]; do
    path=$(dirname -- "$path")
    read -r owner mode <<<"$(stat -L -c '%u %a' -- "$path")"
    [ "$owner" = 0 ] || fail "$path is not owned by root"
    case "$mode" in *[2367]?|*[2367]) fail "$path is writable by group or others ($mode)" ;; esac
done
[ "$(stat -c '%u:%g %a' -- "$checks")" = "0:0 600" ] || fail "$checks is not root:root 0600"
read -r actual _ <<<"$(sha256sum -- "$program")"
[ "$actual" = "$expected" ] || fail "$program is not the expected probe program"
if ! out=$("$program" health "$checks" 2>&1); then
    case "$out" in
        *"Permanent routing changed"*) fail "permanent routing changed" ;;
        *"Ingress changed for"*) fail "ingress changed" ;;
        *"Missing captured TLS fingerprint baseline"*) fail "missing captured TLS fingerprint baseline" ;;
        *) fail "health check failed" ;;
    esac
fi
echo "$actual"
"""


def capture_script(spec: ProbeSpec) -> str:
    """The capture script for ``spec`` (program and spec embedded base64-encoded)."""

    return _CAPTURE.format(
        python_check=_PYTHON_CHECK,
        prefix=CAPTURE_PREFIX,
        program=_blob(PROGRAM),
        spec=_blob(config_json(spec).encode()),
        python=PYTHON,
    )


def _failure(what: str, result: CommandResult) -> ProbeError:
    # Only the scripts' own classified reasons; anything else is not passed on.
    lines = result.stderr.strip().splitlines()
    if lines and lines[-1].startswith("traefik probes: "):
        return ProbeError(f"{what}: {lines[-1].removeprefix('traefik probes: ')}")
    return ProbeError(f"{what}: failed (exit {result.returncode})")


def capture_traefik_health_probes(runner: Runner, spec: ProbeSpec, *, timeout: float = 300) -> ProbeBaseline:
    """Capture a fresh baseline for ``spec`` (read-only); :class:`ProbeError` on failure.

    The result is the spec with the observed ``observations`` and ``dynamic``
    hashes, as the role's ``traefik_health_probe_captured``. Capture before a
    change, never after a failed one.
    """

    if not isinstance(spec, ProbeSpec) or isinstance(spec, ProbeBaseline):
        raise ProbeError("capture takes a probe spec without observations or dynamic hashes")
    try:
        result = runner(capture_script(spec), [], timeout)
    except RemoteCommandError:
        # Not chained: the ssh error names the target host.
        raise ProbeError("capture: no result (ssh failed or timed out)") from None
    if not result.ok:
        raise _failure("capture", result)
    try:
        captured = json.loads(result.stdout)
        if not isinstance(captured, dict) or set(captured) != {"observations", "dynamic"}:
            raise ValueError("unexpected capture output")
        return ProbeBaseline.model_validate({**spec.model_dump(exclude_unset=True), **captured})
    except (ValueError, ValidationError) as exc:
        raise ProbeError(f"capture: unusable result ({type(exc).__name__})") from None


def verify_traefik_health_probes(runner: Runner, *, timeout: float = 300) -> ProbeCommands:
    """Check the installed probes and run ``health`` (read-only); the commands on success.

    Refuses (:class:`ProbeError`) unless the installed program is exactly the
    vendored one and the live ingress matches the installed baseline.
    """

    try:
        result = runner(VERIFY_SCRIPT, [PROGRAM_SHA256], timeout)
    except RemoteCommandError:
        # Not chained: the ssh error names the target host.
        raise ProbeError("verify: no result (ssh failed or timed out)") from None
    if not result.ok:
        raise _failure("verify", result)
    if result.stdout.strip() != PROGRAM_SHA256:
        raise ProbeError("verify: the installed program identity could not be confirmed")
    return probe_commands(PROGRAM_SHA256)


def _check_python() -> None:
    check = f"{PYTHON} -c 'import sys; print(sys.version_info >= (3, 11))'"
    if output(check).strip() != "True":
        raise DeployError(f"traefik_health_probes: {PYTHON} 3.11 or newer is required")


def verify_command() -> str:
    """:data:`VERIFY_SCRIPT` as one ``bash`` command line for a pyinfra operation."""

    return shlex.join(["bash", "-c", VERIFY_SCRIPT, "traefik-probes-verify", PROGRAM_SHA256])


@deploy("Traefik health probes")
def deploy_traefik_health_probes(cfg: TraefikHealthProbesConfig) -> None:
    """Install the probe program and ``cfg.baseline``, then verify live ingress.

    The baseline goes through ``secret_file`` (stdin, never a command line or
    a diff): it names private hosts and addresses. The closing check is
    read-only; :func:`probe_commands` gives the commands it vouches for.
    """

    require_linux("traefik_health_probes")
    _check_python()
    directory(PROBE_DIR, user="root", group="root", mode="0700")
    files.put(
        name="Install the read-only acceptance program",
        src=BytesIO(PROGRAM),
        dest=PROGRAM_PATH,
        user="root",
        group="root",
        mode="0755",
    )
    secret_file(
        name="Install the captured private acceptance baseline",
        path=CHECKS_PATH,
        content=SecretContent(config_json(cfg.baseline)),
        user="root",
        group="root",
        mode="0600",
    )
    mark_read_only(server.shell(name="Verify the captured baseline against live ingress", commands=[verify_command()]))
