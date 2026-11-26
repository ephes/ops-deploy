"""recorder: the podcast recording backend, one static Go binary (``recorderd``).

Port of the ``recorder_deploy`` Ansible role plus the build and smoke steps of
ops-control's ``playbooks/recorder/deploy.yml``. The controller builds the
frontend bundle and cross-compiles the binary from a recorder checkout; the
host gets the binary, an env file, a systemd unit and a Traefik route. The
files written are byte-identical to the retired role's (goldens:
``tests/test_recorder_golden.py``). The SQLite database and the object store
under ``data_dir`` are never touched.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import shlex
import subprocess
from collections.abc import Generator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.api.command import FileUploadCommand
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Sha256File
from pyinfra.operations import apt, files, python, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import TraefikRoute, mark_read_only, service_rollout, system_user, systemd_unit, traefik_route
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES, BasicAuth, Hostname
from ops_deploy.ops import secret_file

TEMPLATE_PACKAGE = "ops_deploy.services.recorder"

# Rendered inside double quotes into a systemd EnvironmentFile: no quotes,
# backslashes or line breaks.
EnvValue = Annotated[str, Field(pattern=r'^[^"\\\r\n]*$')]
Url = Annotated[str, Field(pattern=r"^https?://[^\s\"'\\$`]+$")]
LIVEKIT_HOST_URL = "http://127.0.0.1:7880"
# Secret key -> the recorder.env variable it is written to.
ENV_NAMES = {
    "s3_access_key": "RECORDER_S3_ACCESS_KEY",
    "s3_secret_key": "RECORDER_S3_SECRET_KEY",
    "livekit_url": "RECORDER_LIVEKIT_URL",
    "livekit_host_url": "RECORDER_LIVEKIT_HOST_URL",
    "livekit_api_key": "RECORDER_LIVEKIT_API_KEY",
    "livekit_api_secret": "RECORDER_LIVEKIT_API_SECRET",
    "session_secret": "RECORDER_SESSION_SECRET",
    "admin_emails": "RECORDER_ADMIN_EMAILS",
    "mail_api_url": "RECORDER_MAIL_API_URL",
    "mail_domain": "RECORDER_MAIL_DOMAIN",
    "mail_token": "RECORDER_MAIL_TOKEN",
    "mail_from": "RECORDER_MAIL_FROM",
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    """Runs a controller-side command (build steps, the post-deploy smoke)."""

    def __call__(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str]) -> CommandResult: ...


def subprocess_runner(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str]) -> CommandResult:
    completed = subprocess.run(
        list(argv), cwd=cwd, env={**os.environ, **env}, check=False, text=True, capture_output=True
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class RecorderConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("session_secret", "admin_emails")

    service_name: ServiceName = "recorder"
    user: UnixUser = "recorder"
    # The install directory (the role's recorder_install_dir).
    site_path: PurePosixPath = PurePosixPath("/opt/recorder")
    data_dir: PurePosixPath = PurePosixPath("/var/lib/recorder")
    config_dir: PurePosixPath = PurePosixPath("/etc/recorder")
    # The recorder checkout (the podcast repo's apps/recorder).
    source_path: Path
    # Where the controller writes the cross-compiled binary.
    artifact_path: Path = Path("/tmp/recorderd-linux-amd64")
    # amd64 for the homelab; the smoke VM on Apple silicon needs arm64.
    goarch: Literal["amd64", "arm64"] = "amd64"
    listen_address: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    port: int = Field(default=10015, ge=1, le=65535)
    public_url: Url
    traefik_host: Hostname
    traefik_entrypoints: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")], ...] = ("web-secure",)
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    live_room_prefix: EnvValue = "rec-"
    # None leaves RECORDER_MAX_CHUNK_BYTES out (the binary's 4 MiB default).
    max_chunk_bytes: int | None = Field(default=None, ge=1, le=999_999_999_999_999_999)
    # None leaves RECORDER_UPLOAD_BUFFER_BYTES out (the binary's 64 MiB default):
    # the bytes of chunk uploads buffered at the same time over all takes.
    upload_buffer_bytes: int | None = Field(default=None, ge=1, le=999_999_999_999_999_999)
    # Empty: the binary keeps objects on the local filesystem under data_dir.
    s3_endpoint: EnvValue = ""
    s3_bucket: EnvValue = "recorder"
    s3_use_ssl: bool = False
    # Used when the secrets do not set them (the role's defaults).
    mail_api_url: EnvValue = "https://mailgun.home.xn--wersdrfer-47a.de"
    mail_domain: EnvValue = "mg.wersdoerfer.de"
    mail_from: EnvValue = "Recorder <recorder@wersdoerfer.de>"
    systemd_nofile: int = Field(default=65536, ge=1024)
    # MemoryMax= of the unit; empty leaves it out. recorderd idles below 10 MB
    # and bounds its upload buffers at 64 MiB, so 1G is a backstop, not a budget.
    systemd_memory_max: Annotated[str, Field(pattern=r"^([0-9]+[KMGT]?|infinity)?$")] = "1G"
    healthcheck_retries: int = Field(default=10, ge=1)
    healthcheck_timeout: int = Field(default=30, ge=1)
    # Guests from the internet: with ``guest_basic_auth`` the route splits. Clients in
    # ``internal_ip_ranges`` reach everything without auth, as before. Everyone else
    # reaches only the guest paths (the recording pages, their assets, join and
    # chunk upload), behind basic auth; the host dashboard and its API have no
    # router for them. ``None`` keeps the single public router.
    guest_basic_auth: BasicAuth | None = None
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    # ``False`` with ``guest_basic_auth`` drops the external routers and keeps the
    # internal ones: nobody outside ``internal_ip_ranges`` reaches anything. The
    # switch for taking guest access away without reopening the dashboard; a
    # deploy without ``guest_basic_auth`` is then refused before anything is written.
    external_guests: bool = True
    # With a port, ``/rtc`` on the recorder host goes to the LiveKit signalling
    # port on loopback, so the browser's signalling WebSocket is same-origin with
    # the page and carries the same basic-auth credentials. ``livekit_url`` must
    # then be this host's own ``wss://`` URL.
    livekit_signal_port: int | None = Field(default=None, ge=1, le=65535)
    # Overrides the secrets' ``livekit_url`` (the URL browsers connect to) when set.
    livekit_url: Annotated[str, Field(pattern=r"^(wss?://[A-Za-z0-9.-]+(:[0-9]{1,5})?)?$")] = ""
    # The playbook's post-deploy gate: scripts/smoke.sh through the external URL. None skips it.
    smoke_url: Url | None = None
    expect_accounts: bool = True

    @field_validator("internal_ip_ranges")
    @classmethod
    def _valid_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("internal_ip_ranges must not be empty")
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
        return value

    @model_validator(mode="after")
    def _guest_route(self) -> Self:
        if self.livekit_signal_port is not None and self.livekit_url != f"wss://{self.traefik_host}":
            # Anything else would send browsers to a host that does not serve /rtc.
            raise ValueError("livekit_signal_port needs livekit_url to be wss://<traefik_host>")
        return self

    @field_validator("source_path", "artifact_path")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        # Build steps run in other directories than the controller's cwd.
        return value.expanduser().absolute()

    @field_validator("source_path")
    @classmethod
    def _source_is_a_recorder_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("cmd/recorderd", "web/package.json", "scripts/smoke.sh") if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not a recorder checkout (missing {', '.join(missing)})")
        return value

    @property
    def bin_path(self) -> PurePosixPath:
        return self.site_path / "recorderd"

    @property
    def env_path(self) -> PurePosixPath:
        return self.config_dir / "recorder.env"


def build_steps(cfg: RecorderConfig) -> list[tuple[list[str], Path, dict[str, str]]]:
    """The playbook's pre_tasks: ``npm ci``, ``npm run build``, ``go build`` (argv, cwd, env)."""

    web = cfg.source_path / "web"
    go_env = {"GOOS": "linux", "GOARCH": cfg.goarch, "CGO_ENABLED": "0"}
    go = ["go", "build", "-trimpath", "-ldflags=-s", "-ldflags=-w", "-o", str(cfg.artifact_path), "./cmd/recorderd"]
    return [
        (["npm", "ci", "--no-audit", "--no-fund"], web, {}),
        (["npm", "run", "build"], web, {}),
        (go, cfg.source_path, go_env),
    ]


def build(cfg: RecorderConfig, runner: CommandRunner) -> Path:
    """Build the frontend and the binary on the controller; returns the artifact."""

    for argv, cwd, env in build_steps(cfg):
        result = runner(argv, cwd=cwd, env=env)
        if result.returncode != 0:
            detail = (result.stderr.strip() or result.stdout.strip() or "no output")[-2000:]
            raise RuntimeError(f"{shlex.join(argv[:3])} failed ({result.returncode}): {detail}")
    if not cfg.artifact_path.is_file():
        raise RuntimeError(f"the build left no binary at {cfg.artifact_path}")
    return cfg.artifact_path


def env_lines(cfg: RecorderConfig, secrets: SecretValues) -> list[tuple[str, str]]:
    """``recorder.env`` as (name, value) pairs, in the role template's order."""

    def opt(key: str, default: str = "") -> str:
        return secrets.get(key, default)

    out = [
        ("RECORDER_ADDR", f"{cfg.listen_address}:{cfg.port}"),
        ("RECORDER_DB_PATH", f"{cfg.data_dir}/recorder.db"),
        ("RECORDER_DATA_DIR", f"{cfg.data_dir}/objects"),
        ("RECORDER_PUBLIC_URL", cfg.public_url),
        ("RECORDER_LIVE_ROOM_PREFIX", cfg.live_room_prefix),
    ]
    if cfg.max_chunk_bytes is not None:
        out.append(("RECORDER_MAX_CHUNK_BYTES", str(cfg.max_chunk_bytes)))
    if cfg.upload_buffer_bytes is not None:
        out.append(("RECORDER_UPLOAD_BUFFER_BYTES", str(cfg.upload_buffer_bytes)))
    if cfg.s3_endpoint:
        out += [
            ("RECORDER_S3_ENDPOINT", cfg.s3_endpoint),
            ("RECORDER_S3_BUCKET", cfg.s3_bucket),
            ("RECORDER_S3_ACCESS_KEY", opt("s3_access_key")),
            ("RECORDER_S3_SECRET_KEY", opt("s3_secret_key")),
            ("RECORDER_S3_USE_SSL", str(cfg.s3_use_ssl).lower()),
        ]
    if opt("livekit_api_key"):
        out += [
            ("RECORDER_LIVEKIT_URL", cfg.livekit_url or opt("livekit_url")),
            # The playbook's ``default(..., true)``: empty also falls back.
            ("RECORDER_LIVEKIT_HOST_URL", opt("livekit_host_url") or LIVEKIT_HOST_URL),
            ("RECORDER_LIVEKIT_API_KEY", opt("livekit_api_key")),
            ("RECORDER_LIVEKIT_API_SECRET", opt("livekit_api_secret")),
        ]
    if opt("session_secret"):
        out.append(("RECORDER_SESSION_SECRET", opt("session_secret")))
        if opt("admin_emails"):
            out.append(("RECORDER_ADMIN_EMAILS", opt("admin_emails")))
    if opt("mail_token"):
        out += [
            ("RECORDER_MAIL_API_URL", opt("mail_api_url", cfg.mail_api_url)),
            ("RECORDER_MAIL_DOMAIN", opt("mail_domain", cfg.mail_domain)),
            ("RECORDER_MAIL_TOKEN", opt("mail_token")),
            ("RECORDER_MAIL_FROM", opt("mail_from", cfg.mail_from)),
        ]
    # Check what is written, not what the secrets hold: a key that never
    # reaches the file (the guests' basic-auth password, a ``livekit_url`` the
    # config overrides) must not stop the deploy. Errors name the key only.
    written = {name: key for key, name in ENV_NAMES.items()}
    for name, value in out:
        if any(c in value for c in '"\\\r\n'):
            source = f"secret {written[name]}" if name in written else name
            raise ValueError(f"{source} must be a single line without double quotes or backslashes")
    return out


def render_env(cfg: RecorderConfig, secrets: SecretValues) -> SecretContent:
    header = "# Managed by Ansible (recorder_deploy). Do not edit on the host.\n"
    body = "".join(f'{name}="{value}"\n' for name, value in env_lines(cfg, secrets))
    return SecretContent(header + body)


def traefik_config(cfg: RecorderConfig) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        host=cfg.traefik_host,
        app_port=cfg.port,
        app_host=cfg.listen_address,
        cert_resolver=cfg.traefik_cert_resolver,
        basic_auth=cfg.guest_basic_auth,
        internal_ip_ranges=cfg.internal_ip_ranges,
    )


def render_route(cfg: RecorderConfig, route: TraefikRoute, auth_hash: str | None = None) -> str:
    """The role's own route (security headers), not the shared dual-router one.

    Without ``guest_basic_auth`` it is the role's single public router, byte for
    byte. With it, see :class:`RecorderConfig`.
    """

    if (route.basic_auth is None) != (auth_hash is None):
        raise ValueError("auth_hash must be given exactly when the route has basic_auth")
    if not cfg.external_guests and auth_hash is None:
        # Without basic auth the route is one public router: "closed to guests"
        # must never be rendered as "open to everyone". Checked here, not in the
        # config, because callers may add the credentials only at deploy time.
        raise ValueError("external_guests=False needs guest_basic_auth")
    text = render(
        TEMPLATE_PACKAGE,
        "recorder-traefik.yml.j2",
        route=route,
        entrypoints=cfg.traefik_entrypoints,
        auth_hash=auth_hash,
        live_port=cfg.livekit_signal_port,
        external=cfg.external_guests,
    )
    # The optional blocks at the end of the template must not change how the file ends.
    return text.rstrip("\n") + "\n"


@operation()
def _binary(src: str, dest: str) -> Generator[StringCommand | FileUploadCommand, None, None]:
    """Install the binary next to ``dest`` and rename it into place.

    Writing over a running executable fails (``ETXTBSY``), so a changed
    binary is uploaded to a staging name, given owner and mode, and renamed
    over the old one; the running process keeps its inode. This also avoids
    ``files.put``'s ``--diff``, which reads the remote file as text and fails
    on a binary. An unchanged binary only gets its owner and mode checked.
    """

    remote = host.get_fact(Sha256File, path=dest)
    local = hashlib.sha256(Path(src).read_bytes()).hexdigest()
    if remote == local:
        yield from files.put._inner(src=src, dest=dest, user="root", group="root", mode="0755")
        return
    staged = f"{dest}.ops-deploy-new"
    host.log(f"Will replace {dest}" if remote else f"Will create {dest}", logger.info)
    yield FileUploadCommand(src, staged, remote_temp_filename=host.get_temp_filename(staged))
    yield StringCommand(
        f"chown root:root {shlex.quote(staged)} && chmod 0755 {shlex.quote(staged)} "
        f"&& mv -f {shlex.quote(staged)} {shlex.quote(dest)}"
    )


def _health_check(cfg: RecorderConfig) -> OperationMeta:
    """The role's health.yml: port open, ``/health`` answers 200 with ``status: ok``."""

    url = f"http://{cfg.listen_address}:{cfg.port}/health"
    parse = "import json,sys; sys.exit(json.load(sys.stdin).get('status') != 'ok')"
    probe = f"(exec 3<>/dev/tcp/{cfg.listen_address}/{cfg.port}) 2>/dev/null"
    script = (
        f"for i in $(seq 1 {cfg.healthcheck_timeout}); do {probe} && break; sleep 1; done; "
        f"for i in $(seq 1 {cfg.healthcheck_retries}); do "
        f"body=$(curl -fsS --max-time {cfg.healthcheck_timeout} {shlex.quote(url)} 2>/dev/null) "
        f"&& printf '%s' \"$body\" | python3 -c {shlex.quote(parse)} 2>/dev/null && exit 0; sleep 2; done; "
        f"echo 'recorder /health did not return status=ok' >&2; exit 1"
    )
    return mark_read_only(server.shell(name="Check recorder /health", commands=[f"bash -c {shlex.quote(script)}"]))


def _smoke(cfg: RecorderConfig, runner: CommandRunner) -> None:
    assert cfg.smoke_url is not None
    argv = [str(cfg.source_path / "scripts/smoke.sh"), cfg.smoke_url]
    if cfg.expect_accounts:
        argv.append("--expect-accounts")
    result = runner(argv, cwd=cfg.source_path, env={})
    for line in result.stdout.splitlines():
        logger.info(f"recorder smoke: {line}")
    if result.returncode != 0:
        raise RuntimeError(f"recorder smoke test failed: {result.stderr.strip()[-2000:] or result.returncode}")


@deploy("Deploy recorder")
def deploy_recorder(cfg: RecorderConfig, secrets: SecretValues, runner: CommandRunner = subprocess_runner) -> None:
    secrets.require(cfg.required_secret_keys)
    env_content = render_env(cfg, secrets)
    artifact = build(cfg, runner)

    apt.packages(name="Install recorder runtime packages", packages=["ca-certificates"], update=True, cache_time=3600)
    # The role's user.yml: nologin system user whose home is the data directory (0750).
    system_user(cfg.user, home=cfg.data_dir, shell="/usr/sbin/nologin", mode="0750")
    files.directory(name=f"Ensure {cfg.site_path}", path=str(cfg.site_path), user="root", group="root", mode="0755")
    files.directory(name=f"Ensure {cfg.config_dir}", path=str(cfg.config_dir), user="root", group=cfg.user, mode="0750")

    binary = _binary(name="Install recorder binary", src=str(artifact), dest=str(cfg.bin_path))
    env = secret_file(
        name="Write recorder.env", path=cfg.env_path, content=env_content, mode="0640", user="root", group=cfg.user
    )
    unit = systemd_unit(cfg.service_name, render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=cfg))
    # The role's ``reload traefik`` handler fails (the unit has no ExecReload)
    # and is ignored; the file provider's watch picks the route up.
    traefik_route(
        traefik_config(cfg),
        renderer=lambda route, auth_hash: render_route(cfg, route, auth_hash),
        restart="none",
    )
    service_rollout(cfg.service_name, units=[unit], restart_when=[binary, env])

    _health_check(cfg)
    if cfg.smoke_url is not None:
        mark_read_only(python.call(name="Smoke test through the external URL", function=_smoke, cfg=cfg, runner=runner))
