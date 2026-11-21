"""logyard vector: the journald producer that ships a host's logs to Logyard.

Port of the ``logyard_vector_deploy`` role (with ``vector_apt_install``) and
``playbooks/deploy-logyard-vector.yml``. Vector is installed from its apt
channel, the shared global fragment and the Logyard fragment are written into
``config.d``, and the whole directory is validated with ``vector validate``
before either live file is replaced. The fragment template is shipped unchanged
and rendered like Ansible's ``template`` module renders it, so the files are
byte-identical to the retired role's (goldens:
``tests/test_logyard_golden.py``).

The role reads ``vector --version`` after installing the package to decide
whether to emit the template-confinement opt-out (Vector 0.57 and newer).
pyinfra decides while planning, before anything is installed: on a host that
already runs Vector the answer is the same; on a host without it the
configured default applies (``supports_template_confinement``), and the
validation step stops a wrong guess before it replaces the running config.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Literal

import yaml
from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.files import File, FileContents, Sha256File
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import ServiceName
from ops_deploy.helpers import mark_read_only
from ops_deploy.infra import VectorAptInstallConfig, vector_apt_steps
from ops_deploy.services.logyard._common import FILES, Part, Url, Word, probe, render_role

Level = Literal["emerg", "alert", "critical", "error", "warning", "notice", "info", "debug"]
# Loki's own query/table-manager logs reach journald through Docker's journald
# driver and would be shipped back into Loki (each query writes more of them);
# OTBR logs ~200,000 [I] lines a day of mesh chatter on macmini.
DEFAULT_MIN_LEVELS: dict[str, Level] = {"logyard-loki": "warning", "otbr-agent": "notice"}

VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
CONFINEMENT_SINCE = (0, 57, 0)
CONFIG_PATTERNS = ("*.yaml", "*.yml", "*.toml", "*.json")


class Match(Part):
    """One journald ``include_matches`` entry."""

    key: Annotated[str, Field(min_length=1)]
    value: str | tuple[str, ...]


# A file path or glob Vector's file source reads: absolute, no "..", no
# characters with a meaning in YAML or shell beyond the glob's "*" and "?".
FilePath = Annotated[str, Field(pattern=r"^/(?:[A-Za-z0-9@._+*?-]+/)*[A-Za-z0-9@._+*?-]+$")]
# An RE2 pattern rendered into a VRL raw string r'...': no quote, no control characters.
DropPattern = Annotated[str, Field(min_length=1, max_length=400, pattern=r"^[^'\x00-\x1f\x7f]+$")]
FileKind = Literal["plain", "traefik", "postgres", "fail2ban", "echoport"]


class FileSource(Part):
    """One log file (or a glob of them) shipped under one ``service`` label.

    ``kind`` picks the line parser: ``traefik`` (JSON or common log format,
    query values and token-like path segments redacted, ordinary requests
    sampled 1 in ``sample_rate``), ``postgres`` (prefixed lines only, no
    DETAIL/STATEMENT/CONTEXT/QUERY/HINT, no checkpoint or autovacuum
    chatter), ``fail2ban`` (no per-attempt "Found" lines), ``echoport``
    (level prefix, no idle scheduler ticks) and ``plain`` (a level word near
    the start of the line, else info). ``drop`` adds patterns whose lines are
    not shipped; ``min_level`` is a floor like ``min_levels``.

    ``fingerprint``: ``checksum`` (the default, the first line) follows both
    rename-and-create (logrotate ``create``) and copy-and-truncate rotation
    (darwin_log_trim, logrotate ``copytruncate``). ``inode`` misreads
    copy-and-truncate, and after rename-and-create it can match a stale
    checkpoint when the new file gets a freed inode back (logrotate's
    ``delaycompress`` frees the ``.1`` file's inode just before it creates the
    new log): Vector then resumes at the old file's offset and ships nothing
    until the new file grows past it. Use ``inode`` only for files whose
    first line repeats across rotations.
    ``acl``: grant the Vector user read access with POSIX ACLs, ``dir`` on
    the parent directory only (traverse and list), ``files`` also on the
    files and as the directory's default for files created there later.
    """

    service: Word
    paths: Annotated[tuple[FilePath, ...], Field(min_length=1)]
    kind: FileKind = "plain"
    min_level: Level | None = None
    drop: tuple[DropPattern, ...] = ()
    fingerprint: Literal["inode", "checksum"] = "checksum"
    acl: Literal["none", "dir", "files"] = "none"
    # traefik only: one in ``sample_rate`` ordinary requests is shipped.
    sample_rate: int = Field(default=1, ge=1, le=100000)
    # traefik only: requests at least this slow are always shipped.
    slow_ms: int = Field(default=1000, ge=1)

    @field_validator("drop")
    @classmethod
    def _compiles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as error:
                raise ValueError(f"drop pattern does not compile: {error}") from None
        return value

    @field_validator("paths")
    @classmethod
    def _no_parent(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            parts = PurePosixPath(path).parts
            if ".." in parts or "." in parts:
                raise ValueError("file paths must not contain '.' or '..' segments")
        return value

    @property
    def dirs(self) -> tuple[str, ...]:
        """The parent directories, which must be literal (no glob characters) for ``acl``."""

        return tuple(dict.fromkeys(str(PurePosixPath(path).parent) for path in self.paths))


class LogyardVectorDarwin(Part):
    """The Homebrew Vector that Graphyard's Darwin deploy runs under launchd.

    The Logyard fragment joins that process's config directory; this deploy
    only writes the fragment, validates the directory and restarts the job.
    """

    binary_path: PurePosixPath = PurePosixPath("/opt/homebrew/bin/vector")
    launchd_label: Word = "de.wersdoerfer.graphyard.vector"
    config_group: Word = "wheel"

    @field_validator("binary_path")
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute() or ".." in value.parts or not re.fullmatch(r"[A-Za-z0-9/._-]+", str(value)):
            raise ValueError("binary_path must be absolute, plain characters, without '..'")
        return value


class LogyardVectorConfig(RoleConfig):
    """The role's variables without the ``logyard_vector_`` prefix (defaults from its defaults/main.yml)."""

    apt: VectorAptInstallConfig = VectorAptInstallConfig()
    config_dir: PurePosixPath = PurePosixPath("/etc/vector/config.d")
    config_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+\.(yaml|yml)$")] = "30-logyard-journald.yaml"
    global_config_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+\.(yaml|yml)$")] = "00-global.yaml"
    env_file: PurePosixPath = PurePosixPath("/etc/default/vector")
    data_dir: PurePosixPath = PurePosixPath("/var/lib/vector")
    service_name: ServiceName = "vector"
    # The account the Linux package runs Vector as (the ``acl`` grants name it).
    vector_user: Word = "vector"

    ingest_endpoint: Url = "http://127.0.0.1:3101"
    host_id: Word
    environment: Word = "prod"
    source_type: Literal["journald"] = "journald"
    # False on hosts without journald (Darwin): the fragment ships files only.
    journald: bool = True
    include_units: tuple[str, ...] = ()
    exclude_units: tuple[str, ...] = ()
    include_matches: tuple[Match, ...] = ()
    current_boot_only: bool = False
    # Per service label: lines less severe than the level are not shipped.
    # The map replaces DEFAULT_MIN_LEVELS; merge them to keep both floors.
    # Keys are service label values (systemd escapes such as \x2d included).
    min_levels: dict[Annotated[str, Field(pattern=r"^[A-Za-z0-9@._:\\-]+$")], Level] = Field(
        default_factory=lambda: dict(DEFAULT_MIN_LEVELS)
    )

    # Log files beside journald, each with its own ``service`` label; they
    # go to Loki with ``source_type="file"`` (labels host, service, level,
    # environment). The services must be unique.
    files: tuple[FileSource, ...] = ()
    # Set on macOS: no apt, systemd or env file; see LogyardVectorDarwin.
    darwin: LogyardVectorDarwin | None = None
    # Files older than this (seconds since the last write) are not watched.
    file_ignore_older_secs: int = Field(default=7 * 86400, ge=60)

    http_timeout_secs: int = Field(default=15, ge=1)
    request_concurrency: int = Field(default=1, ge=1)
    retry_initial_backoff_secs: int = Field(default=1, ge=1)
    retry_max_duration_secs: int = Field(default=3600, ge=1)
    batch_timeout_secs: int = Field(default=5, ge=1)
    batch_max_events: int = Field(default=200, ge=1)
    buffer_max_size: int = Field(default=268435488, ge=1)
    healthcheck_enabled: bool = False
    allow_unconfined_label_templates: bool = True
    # Used only when the installed Vector version cannot be read while planning.
    supports_template_confinement: bool = True

    @field_validator("config_dir", "env_file", "data_dir")
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
            raise ValueError("paths must be absolute, without '..', and not '/'")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> LogyardVectorConfig:
        services = [source.service for source in self.files]
        if len(services) != len(set(services)):
            raise ValueError("file sources need distinct service labels")
        if not self.journald and not self.files:
            raise ValueError("a producer without journald needs at least one file source")
        if self.files and not self.allow_unconfined_label_templates:
            raise ValueError("file sources need the service and level labels (allow_unconfined_label_templates)")
        if self.darwin is not None and self.journald:
            raise ValueError("Darwin has no journald: set journald to false")
        for source in self.files:
            if source.kind != "traefik" and (source.sample_rate != 1 or source.slow_ms != 1000):
                raise ValueError("sample_rate and slow_ms apply to traefik sources only")
            if source.acl != "none":
                if self.darwin is not None:
                    raise ValueError("acl grants are for Linux producers (Vector runs as root on Darwin)")
                if any(char in directory for directory in source.dirs for char in "*?"):
                    raise ValueError("acl needs literal parent directories (globs in file names only)")
        return self

    @property
    def config_path(self) -> PurePosixPath:
        return self.config_dir / self.config_name

    @property
    def global_config_path(self) -> PurePosixPath:
        return self.config_dir / self.global_config_name


def source_id(service: str) -> str:
    """The Vector component id of a file source: stable (Vector keeps the file checkpoints under it,
    so reordering ``files`` must not change it) and collision-free (every character but a-z and 0-9
    is spelled ``_<hex>``)."""

    return "".join(char if char in "abcdefghijklmnopqrstuvwxyz0123456789" else f"_{ord(char):02x}" for char in service)


def role_vars(cfg: LogyardVectorConfig, supports_confinement: bool | None = None) -> dict[str, object]:
    return {
        "logyard_vector_ingest_endpoint": cfg.ingest_endpoint,
        "logyard_vector_host_id": cfg.host_id,
        "logyard_vector_environment": cfg.environment,
        "logyard_vector_source_type": cfg.source_type,
        "logyard_vector_include_units": list(cfg.include_units),
        "logyard_vector_exclude_units": list(cfg.exclude_units),
        "logyard_vector_include_matches": [
            {"key": m.key, "value": list(m.value) if isinstance(m.value, tuple) else m.value}
            for m in cfg.include_matches
        ],
        "logyard_vector_current_boot_only": cfg.current_boot_only,
        "logyard_vector_journald": cfg.journald,
        "logyard_vector_files": [
            {
                "id": source_id(source.service),
                "service": source.service,
                "paths": list(source.paths),
                "kind": source.kind,
                "min_level": source.min_level,
                "drop": list(source.drop),
                "fingerprint": source.fingerprint,
                "sample_rate": source.sample_rate,
                "slow_ms": source.slow_ms,
            }
            for source in cfg.files
        ],
        "logyard_vector_file_ignore_older_secs": cfg.file_ignore_older_secs,
        "logyard_vector_min_levels": dict(sorted(cfg.min_levels.items())),
        "logyard_vector_http_timeout_secs": cfg.http_timeout_secs,
        "logyard_vector_request_concurrency": cfg.request_concurrency,
        "logyard_vector_retry_initial_backoff_secs": cfg.retry_initial_backoff_secs,
        "logyard_vector_retry_max_duration_secs": cfg.retry_max_duration_secs,
        "logyard_vector_batch_timeout_secs": cfg.batch_timeout_secs,
        "logyard_vector_batch_max_events": cfg.batch_max_events,
        "logyard_vector_buffer_max_size": cfg.buffer_max_size,
        "logyard_vector_healthcheck_enabled": cfg.healthcheck_enabled,
        "logyard_vector_allow_unconfined_label_templates": cfg.allow_unconfined_label_templates,
        "logyard_vector_supports_template_confinement": (
            cfg.supports_template_confinement if supports_confinement is None else supports_confinement
        ),
    }


def render_fragment(cfg: LogyardVectorConfig, supports_confinement: bool | None = None) -> str:
    return render_role("vector.yaml.j2", role_vars(cfg, supports_confinement))


def render_global(cfg: LogyardVectorConfig) -> str:
    """The shared global fragment (``data_dir``), as the role writes it."""

    return f"data_dir: {json.dumps(str(cfg.data_dir))}\n"


def supports_confinement(version_output: str, default: bool) -> bool:
    """Whether ``vector --version`` output names Vector 0.57 or newer; ``default`` when unreadable."""

    found = VERSION_PATTERN.search(version_output)
    if not found:
        return default
    return tuple(int(part) for part in found.group().split(".")) >= CONFINEMENT_SINCE


def global_data_dir(raw: list[str] | None, default: PurePosixPath) -> str:
    """``data_dir`` of the existing shared global fragment (the role's ``from_yaml`` lookup)."""

    if not raw:
        return str(default)
    loaded = yaml.safe_load("\n".join(raw)) or {}
    if not isinstance(loaded, dict):
        raise DeployError("the shared Vector global config is not a mapping")
    return str(loaded.get("data_dir") or default)


def lineinfile(path: str, regexp: str, line: str, *, current: list[str] | None) -> str:
    """``current`` with ``line`` replacing the last line matching ``regexp``, else appended."""

    lines = list(current or [])
    pattern = re.compile(regexp)
    matches = [index for index, text in enumerate(lines) if pattern.search(text)]
    if matches:
        lines[matches[-1]] = line
    else:
        lines.append(line)
    return "\n".join(lines) + "\n"


@operation()
def env_line(path: str, line: str) -> Generator[StringCommand, None, None]:
    """The role's ``lineinfile``: ``VECTOR_CONFIG_DIR=`` set in the defaults file, created if missing."""

    content = lineinfile(path, "^VECTOR_CONFIG_DIR=", line, current=host.get_fact(FileContents, path=path))
    yield from files.put._inner(src=StringIO(content), dest=path, user="root", group="root", mode="0644")


def validate_command(cfg: LogyardVectorConfig, fragment: str, binary: str = "vector", own_global: bool = True) -> str:
    """Validate the config directory with this deploy's fragments swapped in, in a temp directory.

    ``own_global=False`` (Darwin, where graphyard_vector owns it) keeps the live global fragment.
    """

    def b64(text: str) -> str:
        return base64.b64encode(text.encode()).decode()

    live = shlex.quote(str(cfg.config_dir))
    names = " -o ".join(f"-name '{pattern}'" for pattern in CONFIG_PATTERNS)
    owned = (cfg.config_name, cfg.global_config_name) if own_global else (cfg.config_name,)
    skip = " ".join(f"! -name {shlex.quote(name)}" for name in owned)
    write_global = (
        f'printf %s {b64(render_global(cfg))} | base64 -d > "$dir"/{shlex.quote(cfg.global_config_name)}; '
        if own_global
        else ""
    )
    script = (
        "set -e; dir=$(mktemp -d /tmp/logyard-vector-validate-XXXXXX); trap 'rm -rf \"$dir\"' EXIT; "
        f'if [ -d {live} ]; then find {live} -maxdepth 1 -type f \\( {names} \\) {skip} -exec cp {{}} "$dir"/ \\;; fi; '
        + write_global
        + f'printf %s {b64(fragment)} | base64 -d > "$dir"/{shlex.quote(cfg.config_name)}; '
        f'{shlex.quote(binary)} validate --skip-healthchecks --config-dir "$dir"'
    )
    return f"bash -c {shlex.quote(script)}"


def fragments_current(expected: dict[PurePosixPath, str], group: str = "vector") -> bool:
    """Reuse pyinfra's file facts: current bytes, owner, group and mode.

    Only exact current inputs can validate in place. Any missing/non-file or
    metadata/content drift takes the staged validation path before file writes.
    Hashing avoids exposing Graphyard's bearer token in file-content facts.
    """

    for path, text in expected.items():
        info = host.get_fact(File, path=str(path))
        if not info or info["mode"] != 640 or info["user"] != "root" or info["group"] != group:
            return False
        if host.get_fact(Sha256File, path=str(path)) != hashlib.sha256(text.encode()).hexdigest():
            return False
    return True


def acl_request(cfg: LogyardVectorConfig) -> dict[str, object] | None:
    """What ``files/logyard_vector_acl.py`` grants: per parent directory of an ``acl`` source,
    whether its files get access too and which file name patterns are meant."""

    dirs: dict[str, dict[str, object]] = {}
    for source in cfg.files:
        if source.acl == "none":
            continue
        for path in source.paths:
            parent, name = str(PurePosixPath(path).parent), PurePosixPath(path).name
            entry = dirs.setdefault(parent, {"path": parent, "files": False, "patterns": []})
            if source.acl == "files":
                entry["files"] = True
                patterns = entry["patterns"]
                assert isinstance(patterns, list)
                if name not in patterns:
                    patterns.append(name)
    if not dirs:
        return None
    return {"user": cfg.vector_user, "dirs": [dirs[key] for key in sorted(dirs)]}


def acl_command(request: dict[str, object], action: Literal["check", "apply"]) -> str:
    script = (FILES / "logyard_vector_acl.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(script).decode()
        + "'),'<logyard-vector-acl>','exec'))"
    )
    encoded = base64.b64encode(json.dumps(request, sort_keys=True).encode()).decode()
    return shlex.join(["python3", "-I", "-c", launcher, action, encoded])


def darwin_steps(cfg: LogyardVectorConfig, fragment: str) -> None:
    """Add the fragment to the Graphyard Vector's config directory on macOS and restart that job."""

    native = cfg.darwin
    assert native is not None
    binary = str(native.binary_path)
    group = native.config_group
    if probe(f"test -x {shlex.quote(binary)} && echo present").strip() != "present":
        raise DeployError(f"{binary} is missing: deploy graphyard_vector (Homebrew Vector) first")
    existing = global_data_dir(host.get_fact(FileContents, path=str(cfg.global_config_path)) or None, cfg.data_dir)
    if not host.get_fact(File, path=str(cfg.global_config_path)):
        raise DeployError(f"{cfg.global_config_path} is missing: deploy graphyard_vector first")
    if existing != str(cfg.data_dir):
        raise DeployError(
            f"existing shared Vector global config uses data_dir={existing}, "
            f"but data_dir={cfg.data_dir}; align the shared Vector data_dir before deploying"
        )
    # Only this deploy's fragment decides: graphyard_vector owns 00-global.yaml
    # (its data_dir was checked above) and the launchd job. A restart that
    # succeeded records the fragment's hash in the data directory; a fragment
    # without that record (the restart failed, or another run wrote it) gets
    # the restart again.
    live = shlex.quote(str(cfg.config_dir))
    marker = cfg.data_dir / "logyard-fragment.applied"
    digest = hashlib.sha256(fragment.encode()).hexdigest()
    restart = (
        f"/bin/launchctl kickstart -k {shlex.quote('system/' + native.launchd_label)} && "
        f"printf '%s\\n' {digest} > {shlex.quote(str(marker))}"
    )
    if fragments_current({cfg.config_path: fragment}, group):
        mark_read_only(
            server.shell(
                name="Validate the live Vector configuration",
                commands=[f"{shlex.quote(binary)} validate --skip-healthchecks --config-dir {live}"],
            )
        )
        # Also restarted when the job is not running (it is KeepAlive; a stopped
        # job ships nothing although the configuration validates).
        state = probe(
            f"/bin/launchctl print {shlex.quote('system/' + native.launchd_label)} | grep -q 'state = running'"
            f" && cat {shlex.quote(str(marker))}"
        )
        if state.strip() != digest:
            server.shell(name=f"Restart {native.launchd_label} (not yet on this fragment)", commands=[restart])
        return
    server.shell(
        name="Validate the staged Vector configuration",
        commands=[validate_command(cfg, fragment, binary, own_global=False)],
    )
    files.put(
        name="Deploy the Logyard Vector config fragment",
        src=StringIO(fragment),
        dest=str(cfg.config_path),
        user="root",
        group=group,
        mode="0640",
    )
    server.shell(name=f"Restart {native.launchd_label}", commands=[restart])


def vector_steps(cfg: LogyardVectorConfig) -> None:
    if cfg.darwin is not None:
        binary = str(cfg.darwin.binary_path)
        darwin_steps(
            cfg,
            render_fragment(
                cfg, supports_confinement(probe(f"{shlex.quote(binary)} --version"), cfg.supports_template_confinement)
            ),
        )
        return
    vector_apt_steps(cfg.apt)

    fragment = render_fragment(cfg, supports_confinement(probe("vector --version"), cfg.supports_template_confinement))
    existing = global_data_dir(host.get_fact(FileContents, path=str(cfg.global_config_path)) or None, cfg.data_dir)
    if existing != str(cfg.data_dir):
        raise DeployError(
            f"existing shared Vector global config uses data_dir={existing}, "
            f"but data_dir={cfg.data_dir}; align the shared Vector data_dir before deploying"
        )

    # Validation first: nothing live (env file, legacy config) changes if it fails.
    if fragments_current({cfg.global_config_path: render_global(cfg), cfg.config_path: fragment}):
        mark_read_only(
            server.shell(
                name="Validate the live Vector configuration",
                commands=[f"vector validate --skip-healthchecks --config-dir {shlex.quote(str(cfg.config_dir))}"],
            )
        )
    else:
        # This command creates and removes temporary files: it is a mutation,
        # even though it leaves the live directory unchanged.
        server.shell(name="Validate the staged Vector configuration", commands=[validate_command(cfg, fragment)])
    files.directory(
        name="Ensure Vector data directory", path=str(cfg.data_dir), user="vector", group="vector", mode="0750"
    )
    files.directory(
        name="Ensure Vector config directory", path=str(cfg.config_dir), user="root", group="vector", mode="0750"
    )
    env = env_line(
        name="Point Vector at its config directory",
        path=str(cfg.env_file),
        line=f"VECTOR_CONFIG_DIR={cfg.config_dir}",
    )
    files.file(name="Remove the legacy monolithic Vector config", path="/etc/vector/vector.yaml", present=False)
    request = acl_request(cfg)
    # Planned from a read-only check, so a converged host reports no change.
    if request is not None and probe(acl_command(request, "check")).strip() != "current":
        server.shell(name="Grant Vector read access to its log files", commands=[acl_command(request, "apply")])

    global_config = files.put(
        name="Deploy the shared Vector global config",
        src=StringIO(render_global(cfg)),
        dest=str(cfg.global_config_path),
        user="root",
        group="vector",
        mode="0640",
    )
    config = files.put(
        name="Deploy the Logyard Vector config fragment",
        src=StringIO(fragment),
        dest=str(cfg.config_path),
        user="root",
        group="vector",
        mode="0640",
    )
    # The role's "Restart Logyard Vector Service" handler, flushed before the
    # service is enabled and started. It also fires on the run that installed
    # Vector: the package may start the service with its stock config first.
    unit = f"{cfg.service_name}.service"
    systemd.service(
        name=f"Restart {unit}",
        service=unit,
        running=None,
        command="restart",
        _if=any_changed(env, global_config, config),
    )
    systemd.service(name=f"Enable {unit}", service=unit, running=None, enabled=True)
    systemd.service(name=f"Start {unit}", service=unit, running=True)


@deploy("Deploy logyard vector")
def deploy_logyard_vector(cfg: LogyardVectorConfig) -> None:
    vector_steps(cfg)
