"""delve: the Delve backend (one static Go binary, ``delved``) behind Traefik.

Port of the ``delve_deploy`` Ansible role. The binary is cross-compiled on the
controller (:func:`build_delved`, the playbook's pre-task) and uploaded; state
is one SQLite database under ``data_dir`` that no step here touches. The files
it writes are byte-identical to the role's (``tests/test_delve_parity.py``),
so Ansible and ops-deploy can take turns on one host without churn.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from collections.abc import Callable, Generator, Sequence
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Sha1File
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import (
    TraefikRoute,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    wait_port,
)
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.ops import secret_file

TEMPLATE_PACKAGE = "ops_deploy.services.delve"
FILES = Path(__file__).parent / "files"
STOREKIT_ROOT_CERTS = FILES / "apple-storekit-root-certs.pem"

# Rendered inside double quotes in the env file and unit files: no whitespace,
# quotes, backslashes, ``$`` or backticks.
_PLAIN = r"[^\s'\"\\$`]"
Url = Annotated[str, Field(pattern=rf"^https?://{_PLAIN}+$")]
# voxhelm and detector origins: http(s)://host[:port], no path, query or
# credentials (the role's check); empty leaves the stage unconfigured.
Origin = Annotated[str, Field(pattern=r"^(https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?)?$")]
Plain = Annotated[str, Field(pattern=rf"^{_PLAIN}*$")]
EntryPoint = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]


def _absolute(value: PurePosixPath) -> PurePosixPath:
    if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
        raise ValueError("paths must be absolute, without '..', and not '/'")
    return value


class DelveConfig(BaseServiceConfig):
    """The role's variables without the ``delve_`` prefix (defaults from its defaults/main.yml)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = ("session_secret",)

    service_name: ServiceName = "delve"
    user: UnixUser = "delve"
    group: UnixUser = "delve"
    # The role has no site path; the install directory takes its place.
    site_path: PurePosixPath = PurePosixPath("/opt/delve")
    data_dir: PurePosixPath = PurePosixPath("/var/lib/delve")
    config_dir: PurePosixPath = PurePosixPath("/etc/delve")
    # The cross-compiled linux/amd64 delved on the controller (see build_delved).
    binary_path: Path

    listen_address: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    port: int = Field(default=10026, ge=1, le=65535)
    public_url: Url = "https://delve.example.com"
    traefik_enabled: bool = True
    traefik_host: Hostname = "delve.example.com"
    traefik_entrypoints: tuple[EntryPoint, ...] = ("web-secure",)
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""

    # Comma-separated operator emails seeded as admins; empty disables /admin.
    admin_emails: Plain = ""
    apple_client_id: Plain = ""
    # None leaves the variable out of the env file (the role's empty string).
    apple_server_notifications: bool | None = None
    profile_legacy_reregister: bool | None = None
    apple_signin_legacy_no_nonce: bool | None = None

    # A host path enables StoreKit; bundle id and product ids are then required.
    storekit_root_certs_path: PurePosixPath | None = None
    storekit_root_certs_src: Path = STOREKIT_ROOT_CERTS
    storekit_bundle_id: Plain = ""
    storekit_product_ids: Plain = ""

    env: Plain = ""  # DELVE_ENV; empty = production behaviour

    discovery_collector_timer_enabled: bool = False
    discovery_collector_timer_state: Literal["started", "stopped"] = "started"
    discovery_collector_calendar: Annotated[str, Field(pattern=r"^[A-Za-z0-9*:,./ -]+$")] = "*-*-* 03,15:17:00"
    discovery_collector_randomized_delay_sec: int = Field(default=3600, ge=0)
    discovery_collector_concurrency: int = Field(default=2, ge=2, le=8)
    discovery_poll_interval_seconds: int = Field(default=43200, ge=21600, le=86400)
    discovery_poll_jitter_seconds: int = Field(default=3600, ge=0)
    discovery_episode_ttl_seconds: int = Field(default=7776000, gt=0)
    discovery_max_items_per_feed: int = Field(default=100, gt=0, le=500)
    discovery_max_sources_per_run: int = Field(default=100, gt=0, le=100)

    systemd_nofile: int = Field(default=65536, ge=1024)

    healthcheck_enabled: bool = True
    healthcheck_timeout: int = Field(default=30, ge=1, le=600)
    healthcheck_retries: int = Field(default=10, ge=1, le=100)
    # Also check /health through Traefik on the host (curl --resolve to
    # 127.0.0.1:443, TLS verified): the playbook's external smoke gate.
    public_health_check: bool = False

    packages: tuple[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.+-]*$")], ...] = ("ca-certificates",)

    # Server ad analysis (DELVE_SMART_SKIP_ANALYSIS). Off: none of the settings
    # below is rendered, and the two secret files are removed. On: ffmpeg, the
    # profile JSON from the controller, the media directory, the voxhelm token
    # and detector API key files (secrets ``voxhelm_token`` and
    # ``detector_api_key``) and the env lines. None leaves an optional value to
    # Delve's default (the role's empty string).
    smart_skip_analysis: bool = False
    smart_skip_analysis_profile_src: Path | None = None
    # None: <config_dir>/smart-skip-analysis-profile.json.
    smart_skip_analysis_profile_path: PurePosixPath | None = None
    # Publisher audio and transcripts; keep it off the backup path. A directory
    # outside data_dir joins the unit's ReadWritePaths.
    analysis_media_dir: PurePosixPath | None = None
    analysis_media_disk_cap_bytes: int | None = Field(default=None, gt=0)
    ffprobe_path: PurePosixPath | None = None
    ffmpeg_path: PurePosixPath | None = None
    smart_skip_packages: tuple[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.+-]*$")], ...] = ("ffmpeg",)
    voxhelm_url: Origin = ""
    # None: <config_dir>/voxhelm-token.
    voxhelm_token_path: PurePosixPath | None = None
    voxhelm_timeout_seconds: int | None = Field(default=None, gt=0)
    voxhelm_upload_timeout_seconds: int | None = Field(default=None, gt=0)
    voxhelm_poll_seconds: int | None = Field(default=None, gt=0)
    detector_url: Origin = ""
    # None: <config_dir>/detector-api-key.
    detector_api_key_path: PurePosixPath | None = None
    detector_timeout_seconds: int | None = Field(default=None, gt=0)

    @field_validator(
        "smart_skip_analysis_profile_path",
        "analysis_media_dir",
        "ffprobe_path",
        "ffmpeg_path",
        "voxhelm_token_path",
        "detector_api_key_path",
    )
    @classmethod
    def _plain_absolute_paths(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is None:
            return None
        if any(c in str(value) for c in " \t\n\r'\"\\$`"):
            raise ValueError("paths are rendered inside double quotes: no whitespace, quotes, backslashes, $ or `")
        return _absolute(value)

    @field_validator("data_dir", "config_dir", "storekit_root_certs_path")
    @classmethod
    def _absolute_paths(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        return None if value is None else _absolute(value)

    @field_validator("binary_path")
    @classmethod
    def _binary_exists(cls, value: Path) -> Path:
        if not value.is_file():
            raise ValueError("binary_path must be the cross-compiled delved binary on the controller")
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> Self:
        if self.storekit_root_certs_path is not None:
            if not (self.storekit_bundle_id and self.storekit_product_ids):
                raise ValueError("StoreKit needs storekit_bundle_id and storekit_product_ids")
            if not self.storekit_root_certs_src.is_file():
                raise ValueError("storekit_root_certs_src must be a file on the controller")
        if self.apple_server_notifications and not self.apple_client_id:
            raise ValueError("apple_server_notifications requires apple_client_id")
        if not self.traefik_entrypoints:
            raise ValueError("traefik_entrypoints must not be empty")
        if self.smart_skip_analysis:
            src = self.smart_skip_analysis_profile_src
            if src is None or not src.is_file():
                raise ValueError("smart_skip_analysis needs smart_skip_analysis_profile_src, a file on the controller")
            try:
                profile = json.loads(src.read_text())
            except (OSError, ValueError) as exc:
                raise ValueError("smart_skip_analysis_profile_src must be a JSON object file") from exc
            if not isinstance(profile, dict):
                raise ValueError("smart_skip_analysis_profile_src must be a JSON object file")
            if self.analysis_media_dir == self.data_dir:
                raise ValueError("analysis_media_dir must not be the data directory itself")
        return self

    @property
    def install_dir(self) -> PurePosixPath:
        return self.site_path

    @property
    def bin_path(self) -> PurePosixPath:
        return self.install_dir / "delved"

    @property
    def env_path(self) -> PurePosixPath:
        return self.config_dir / "delve.env"

    @property
    def profile_path(self) -> PurePosixPath:
        return self.smart_skip_analysis_profile_path or self.config_dir / "smart-skip-analysis-profile.json"

    @property
    def voxhelm_token_file(self) -> PurePosixPath:
        return self.voxhelm_token_path or self.config_dir / "voxhelm-token"

    @property
    def detector_api_key_file(self) -> PurePosixPath:
        return self.detector_api_key_path or self.config_dir / "detector-api-key"

    @property
    def analysis_secret_files(self) -> tuple[tuple[str, str, PurePosixPath, bool], ...]:
        """(secret key, what, file, wanted) of the two analysis secrets."""

        on = self.smart_skip_analysis
        return (
            ("voxhelm_token", "voxhelm producer token", self.voxhelm_token_file, on and bool(self.voxhelm_url)),
            ("detector_api_key", "detector API key", self.detector_api_key_file, on and bool(self.detector_url)),
        )

    @property
    def media_read_write_path(self) -> PurePosixPath | None:
        """The media directory when the unit must name it in ReadWritePaths (outside data_dir)."""

        media = self.analysis_media_dir
        if not self.smart_skip_analysis or media is None or media.is_relative_to(self.data_dir):
            return None
        return media

    @property
    def collector_service_name(self) -> str:
        return f"{self.service_name}-discovery-collect"

    @property
    def optional_flags(self) -> tuple[tuple[str, bool | None], ...]:
        return (
            ("DELVE_APPLE_SERVER_NOTIFICATIONS", self.apple_server_notifications),
            ("DELVE_PROFILE_LEGACY_REREGISTER", self.profile_legacy_reregister),
            ("DELVE_APPLE_SIGNIN_LEGACY_NO_NONCE", self.apple_signin_legacy_no_nonce),
        )


BuildRunner = Callable[[Sequence[str], Path, dict[str, str]], None]


def _run_build(argv: Sequence[str], cwd: Path, env: dict[str, str]) -> None:
    subprocess.run(list(argv), cwd=cwd, env={**os.environ, **env}, check=True)


def build_delved(
    source_path: Path,
    output: Path,
    *,
    goarch: Literal["amd64", "arm64"] = "amd64",
    runner: BuildRunner = _run_build,
) -> Path:
    """Cross-compile ``cmd/delved`` for linux/amd64 (static, no CGO), as the playbook does.

    ``goarch="arm64"`` serves arm64 smoke VMs; production hosts are amd64.

    The build is reproducible: the same source and Go toolchain give the same
    bytes, so an unchanged checkout uploads nothing and restarts nothing.
    """

    output = output.resolve()  # go build runs in source_path
    if not (source_path / "cmd" / "delved").is_dir():
        raise ValueError(f"{source_path} is not a delve backend checkout (missing cmd/delved)")
    argv = ["go", "build", "-trimpath", "-ldflags=-s", "-ldflags=-w", "-o", str(output), "./cmd/delved"]
    runner(argv, source_path, {"GOOS": "linux", "GOARCH": goarch, "CGO_ENABLED": "0"})
    if not output.is_file():
        raise ValueError(f"go build did not produce {output}")
    return output


def render_env(cfg: DelveConfig, secrets: SecretValues) -> SecretContent:
    """``delve.env`` (the role's ``delve.env.j2``)."""

    if len(secrets["session_secret"]) < 16:
        raise ValueError("session_secret must have at least 16 characters")
    for key, value in secrets.items():
        if any(c in value for c in '\n\r"\\'):
            raise ValueError(f"secret {key} must be a single line without double quotes or backslashes")
    return SecretContent(render(TEMPLATE_PACKAGE, "delve.env.j2", cfg=cfg, secrets=secrets))


def analysis_secret_files(cfg: DelveConfig, secrets: SecretValues) -> dict[str, SecretContent]:
    """The contents of the analysis secret files the deploy writes (key -> content).

    The role's checks: a single line of at least 32 characters that is not
    ``CHANGEME``, written trimmed with one newline (what Ansible's ``copy``
    with ``content`` writes). Errors name the key, never the value.
    """

    contents: dict[str, SecretContent] = {}
    for key, _what, _path, wanted in cfg.analysis_secret_files:
        if not wanted:
            continue
        if key not in secrets:
            raise KeyError(f"secret {key} is required while the server ad analysis uses it")
        value = secrets[key].strip()
        if len(value) < 32 or value == "CHANGEME" or any(c in value for c in "\r\n"):
            raise ValueError(f"secret {key} must be a single line of at least 32 characters that is not CHANGEME")
        contents[key] = SecretContent(f"{value}\n")
    return contents


def traefik_config(cfg: DelveConfig) -> TraefikRoute:
    return TraefikRoute(
        name="delve",
        title="Delve",
        host=cfg.traefik_host,
        app_port=cfg.port,
        app_host=cfg.listen_address,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_route(cfg: DelveConfig, route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's ``delve-traefik.yml.j2`` (no basic auth)."""

    if auth_hash is not None:
        raise ValueError("the delve route has no basic auth")
    return render(TEMPLATE_PACKAGE, "delve-traefik.yml.j2", route=route, entrypoints=cfg.traefik_entrypoints)


def health_check(url: str, *, retries: int, timeout: int, name: str, resolve: str | None = None) -> OperationMeta:
    """``url`` answers 200 with ``"status": "ok"`` (the role's health.yml uri + assert)."""

    curl = ["curl", "-sS", "--max-time", str(timeout), "-w", "\\n%{http_code}"]
    if resolve:
        curl += ["--resolve", resolve]
    curl.append(url)
    script = (
        f"for i in $(seq 1 {retries}); do "
        f"out=$({shlex.join(curl)} 2>/dev/null); "
        'code=$(printf %s "$out" | tail -n1); '
        'if [ "$code" = 200 ] && printf %s "$out" | grep -Eq \'"status"[[:space:]]*:[[:space:]]*"ok"\'; '
        "then exit 0; fi; sleep 2; done; "
        f'echo "{url} did not report status ok (last HTTP ${{code:-none}})" >&2; exit 1'
    )
    return mark_read_only(server.shell(name=name, commands=[f"sh -c {shlex.quote(script)}"]))


@operation()
def _binary(src: str, dest: str) -> Generator[StringCommand, None, None]:
    """``root:root 0755``; new bytes are staged next to ``dest`` and renamed in.

    Writing over the running executable fails (``ETXTBSY``) and pyinfra's
    ``files.put`` writes in place; Ansible's ``copy`` renames, and so does this.
    """

    digest = hashlib.sha1(Path(src).read_bytes()).hexdigest()
    target = PurePosixPath(dest)
    if host.get_fact(Sha1File, path=dest) == digest:
        # Same bytes: only owner and mode are converged.
        yield from files.put._inner(src=src, dest=dest, user="root", group="root", mode="0755")
        return
    staged = str(target.with_name(f".{target.name}.ops-deploy"))
    yield from files.put._inner(src=src, dest=staged, user="root", group="root", mode="0755")
    yield StringCommand(f"mv -f {shlex.quote(staged)} {shlex.quote(dest)}")


def _analysis_files(cfg: DelveConfig, contents: dict[str, SecretContent]) -> list[OperationMeta]:
    """The profile and the two secret files (the role's config.yml); returns the restart triggers.

    Secret files of a switched-off analysis or an unset URL are removed (no
    restart of their own: the env file changes with them).
    """

    changes: list[OperationMeta] = []
    if cfg.smart_skip_analysis:
        changes.append(
            files.put(
                name="Install the server ad analysis profile",
                src=str(cfg.smart_skip_analysis_profile_src),
                dest=str(cfg.profile_path),
                user="root",
                group=cfg.group,
                mode="0640",
            )
        )
    for key, what, path, _wanted in cfg.analysis_secret_files:
        if key in contents:
            changes.append(
                secret_file(
                    name=f"Write the {what} file",
                    path=path,
                    content=contents[key],
                    mode="0640",
                    user="root",
                    group=cfg.group,
                )
            )
        else:
            files.file(name=f"Remove the {what} file", path=str(path), present=False)
    return changes


def _collector(cfg: DelveConfig) -> None:
    """Install the Discovery collector oneshot and timer; set the timer state."""

    name = cfg.collector_service_name
    units = [
        systemd_unit(f"{name}.service", render(TEMPLATE_PACKAGE, "delve-discovery-collect.service.j2", cfg=cfg)),
        systemd_unit(f"{name}.timer", render(TEMPLATE_PACKAGE, "delve-discovery-collect.timer.j2", cfg=cfg)),
    ]
    systemd.daemon_reload(name=f"Reload systemd for {name}", _if=any_changed(*units))
    enabled = cfg.discovery_collector_timer_enabled
    systemd.service(
        name=f"Set {name}.timer state",
        service=f"{name}.timer",
        running=enabled and cfg.discovery_collector_timer_state == "started",
        enabled=enabled,
    )


@deploy("Deploy delve")
def deploy_delve(cfg: DelveConfig, secrets: SecretValues) -> None:
    secrets.require(cfg.required_secret_keys)
    env_content = render_env(cfg, secrets)
    analysis_secrets = analysis_secret_files(cfg, secrets)

    packages = list(cfg.packages)
    if (cfg.healthcheck_enabled or cfg.public_health_check) and "curl" not in packages:
        packages.append("curl")  # the read-only checks (the role used Ansible's uri)
    if cfg.smart_skip_analysis:
        packages += [name for name in cfg.smart_skip_packages if name not in packages]
    apt.packages(name="Install delve runtime packages", packages=packages, update=True, cache_time=3600)
    system_user(cfg.user, group=cfg.group, home=cfg.data_dir, shell="/usr/sbin/nologin", mode="0750")
    files.directory(name="Ensure install directory", path=str(cfg.install_dir), user="root", group="root", mode="0755")
    files.directory(name="Ensure config directory", path=str(cfg.config_dir), user="root", group=cfg.group, mode="0750")
    if cfg.smart_skip_analysis and cfg.analysis_media_dir is not None:
        # Before the unit names it in ReadWritePaths; never removed here.
        files.directory(
            name="Ensure the analysis media directory",
            path=str(cfg.analysis_media_dir),
            user=cfg.user,
            group=cfg.group,
            mode="0700",
        )

    binary = _binary(name="Install delved", src=str(cfg.binary_path), dest=str(cfg.bin_path))
    changes = [binary]
    if cfg.storekit_root_certs_path is not None:
        changes.append(
            files.put(
                name="Install StoreKit root certificates",
                src=str(cfg.storekit_root_certs_src),
                dest=str(cfg.storekit_root_certs_path),
                user="root",
                group=cfg.group,
                mode="0644",
            )
        )
    changes.append(
        secret_file(
            name="Write delve.env", path=cfg.env_path, content=env_content, mode="0640", user="root", group=cfg.group
        )
    )
    changes += _analysis_files(cfg, analysis_secrets)

    unit = systemd_unit(cfg.service_name, render(TEMPLATE_PACKAGE, "delve.service.j2", cfg=cfg))
    _collector(cfg)
    if cfg.traefik_enabled:
        # The role's "reload traefik" handler fails on a unit without
        # ExecReload and is ignored; Traefik's file watcher applies the route.
        traefik_route(traefik_config(cfg), renderer=partial(render_route, cfg), restart="none")
    service_rollout(cfg.service_name, units=[unit], restart_when=changes)

    if cfg.healthcheck_enabled:
        wait_port(cfg.port, host=cfg.listen_address, retries=cfg.healthcheck_timeout)
        health_check(
            f"http://{cfg.listen_address}:{cfg.port}/health",
            retries=cfg.healthcheck_retries,
            timeout=cfg.healthcheck_timeout,
            name="Check delve /health",
        )
    if cfg.public_health_check:
        health_check(
            f"https://{cfg.traefik_host}/health",
            retries=cfg.healthcheck_retries,
            timeout=15,
            name="Check delve /health through Traefik",
            resolve=f"{cfg.traefik_host}:443:127.0.0.1",
        )
