"""MeTube's native staged Git/Angular/uv deployment, retaining the role's artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
import tempfile
from collections.abc import Generator
from importlib.resources import files as resources
from io import StringIO
from pathlib import Path
from typing import Any

import jinja2
from pyinfra import host
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.facts.files import File, Sha256File
from pyinfra.facts.server import Command, Groups
from pyinfra.operations import apt, files, server

from ops_deploy.base.uv_install import UvInstallConfig, deploy_uv_install
from ops_deploy.core.git_source import fetch_source
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    http_check,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
)
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.python_security import require_lock_floors, verify_trust

from .config import MetubeConfig

PACKAGE = "ops_deploy.services.metube"
PIPELINE = resources(PACKAGE).joinpath("files/pipeline.py").read_text()
TRUST = resources("ops_deploy.helpers").joinpath("templates/python_security_check.py.txt").read_text()


def render(package: str, template: str, **context: Any) -> str:
    environment = jinja2.Environment(
        loader=jinja2.PackageLoader(package, "templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        autoescape=False,
    )
    return environment.get_template(template).render(**context)


def template_vars(cfg: MetubeConfig, auth: BasicAuth | None = None, auth_hash: str | None = None) -> dict[str, Any]:
    values = {f"metube_{key}": value for key, value in cfg.model_dump().items()}
    values.update(
        metube_group=cfg.user,
        metube_app_dir=cfg.site_path,
        metube_venv_path=cfg.venv_path,
        metube_env_file=cfg.env_file,
        metube_ytdl_options_json=json.dumps(cfg.ytdl_options),
        metube_systemd_after="network.target",
        metube_systemd_restart="on-failure",
        metube_systemd_restart_sec="5s",
        metube_systemd_nofile=65535,
        metube_systemd_hardening=False,
        metube_systemd_tasks_max="",
        metube_systemd_memory_max="",
        metube_basic_auth_enabled=auth is not None,
        metube_basic_auth_user=auth.user if auth else "",
        metube_basic_auth_password_hash=auth_hash,
        metube_basic_auth_remove_header=True,
        metube_traefik_entrypoints=("web-secure",),
        metube_traefik_cert_resolver="",
        metube_traefik_middlewares=(),
        metube_internal_ip_ranges=cfg.internal_ip_ranges,
    )
    return values


def render_env(cfg: MetubeConfig) -> str:
    return render(PACKAGE, "metube.env.j2", **template_vars(cfg))


def render_unit(cfg: MetubeConfig) -> str:
    return render(PACKAGE, "metube.service.j2", **template_vars(cfg))


def pipeline_config(cfg: MetubeConfig, commit: str, lock_sha256: str) -> dict[str, Any]:
    return {
        **cfg.model_dump(mode="json"),
        "commit": commit,
        "repo": cfg.source.repo,
        "build_dir": str(cfg.build_dir),
        "stage_venv": str(cfg.build_root / "venv"),
        "venv_path": str(cfg.venv_path),
        "uv_path": "/usr/local/bin/uv",
        "health_url": cfg.health_url,
        "lock_sha256": lock_sha256,
        "trust_script": TRUST,
    }


def pipeline_command(cfg: MetubeConfig, data: dict[str, Any], action: str, phase: str) -> str:
    encoded_script = base64.b64encode(PIPELINE.encode()).decode()
    encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
    launcher = (
        "import base64,sys;sys.argv[3]=base64.b64decode(sys.argv[3]).decode();"
        f'exec(base64.b64decode("{encoded_script}"))'
    )
    return _as_user(
        cfg.user, cfg.home, {"UV_NO_PROGRESS": "1"}, ["python3", "-c", launcher, action, phase, encoded_data]
    )


@operation()
def _pipeline(cfg: MetubeConfig, data: dict[str, Any], phase: str) -> Generator[StringCommand, None, None]:
    probe = (
        f"if id -u {shlex.quote(cfg.user)} >/dev/null 2>&1; then "
        f"{pipeline_command(cfg, data, 'status', phase)}; else echo changed; fi"
    )
    current = host.get_fact(Command, command=probe)
    if current == "current":
        return
    yield StringCommand(pipeline_command(cfg, data, "apply", phase))


@operation()
def _rollout_guard(cfg: MetubeConfig, data: dict[str, Any]) -> Generator[StringCommand, None, None]:
    """Busy downloads allow an unchanged deploy; guard only an actual rollout."""
    current = host.get_fact(
        Command,
        command=(
            f"if id -u {shlex.quote(cfg.user)} >/dev/null 2>&1; then "
            f"{pipeline_command(cfg, data, 'status', 'live')}; else echo changed; fi"
        ),
    )
    changed = current != "current"
    for path, text in (
        (str(cfg.env_file), render_env(cfg)),
        (f"/etc/systemd/system/{cfg.service_name}.service", render_unit(cfg)),
    ):
        info = host.get_fact(File, path=path)
        metadata = (info["user"], info["group"], info["mode"]) if info else None
        changed |= host.get_fact(Sha256File, path=path) != hashlib.sha256(text.encode()).hexdigest() or metadata != (
            "root",
            "root",
            644,
        )
    if changed:
        command = (
            f"if systemctl is-active --quiet {shlex.quote(cfg.service_name)}; then "
            f"{pipeline_command(cfg, data, 'quiet', 'live')}; fi"
        )
        yield StringCommand(command)


def _node(cfg: MetubeConfig) -> None:
    # Match the role's conditional branch and repository/key paths. A healthy
    # Node install must not acquire another generic NodeSource setup.
    current = host.get_fact(Command, command="node --version 2>/dev/null || true") or ""
    try:
        version = tuple(int(p) for p in current.removeprefix("v").split("."))
    except ValueError:
        version = ()
    minimum = tuple(int(p) for p in cfg.node_min_version.split("."))
    if not version or version[0] != cfg.node_major or version < minimum:
        apt.packages(
            name="Install NodeSource prerequisites",
            packages=["ca-certificates", "curl", "gnupg"],
            update=True,
            cache_time=3600,
        )
        files.directory(path="/etc/apt/keyrings", mode="0755")
        server.shell(
            name="Install MeTube NodeSource key",
            commands=[
                "curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key "
                "| gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg"
            ],
            _if=lambda: (
                not host.get_fact(Command, command="test -s /etc/apt/keyrings/nodesource.gpg && echo present || true")
            ),
        )
        files.put(
            src=StringIO(
                "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] "
                f"https://deb.nodesource.com/node_{cfg.node_major}.x nodistro main\n"
            ),
            dest="/etc/apt/sources.list.d/nodesource-metube.list",
            user="root",
            group="root",
            mode="0644",
        )
        server.shell(
            name="Install selected MeTube Node.js major",
            commands=[
                "apt-get update -q",
                shlex.join(["apt-get", "install", "-y", "--allow-downgrades", f"nodejs={cfg.node_major}.*"]),
            ],
        )
    check = (
        "import subprocess; "
        "v=tuple(map(int,subprocess.check_output(['node','--version'],text=True).strip().lstrip('v').split('.'))); "
        f"assert v[0]=={cfg.node_major} and v>={minimum!r}, 'MeTube Node version below minimum'"
    )
    mark_read_only(server.shell(name="Verify MeTube Node minimum", commands=[shlex.join(["python3", "-c", check])]))


@deploy("Deploy native MeTube")
def deploy_metube(cfg: MetubeConfig, basic_auth: BasicAuth | None = None) -> None:
    if cfg.traefik_enabled and basic_auth is None:
        raise ValueError("MeTube Traefik exposure requires basic auth")
    if cfg.uv_version != "0.13.4":
        raise ValueError("MeTube uv selection needs matching reviewed release checksums")
    # Resolve exactly once with the established source verifier, before any
    # host operation; neither a moving branch nor a stale lock can slip in.
    with tempfile.TemporaryDirectory(prefix="ops-deploy-metube-") as temporary:
        candidate = fetch_source(cfg.source, Path(temporary) / "src")
        require_lock_floors(candidate.path, "MeTube")
        lock_sha256 = hashlib.sha256((candidate.path / "uv.lock").read_bytes()).hexdigest()
        data = pipeline_config(cfg, candidate.commit, lock_sha256)
    preflight = (
        "import pathlib,sys; "
        "assert pathlib.Path('/run/systemd/system').is_dir(), 'MeTube needs systemd'; "
        "paths=sys.argv[1:]; "
        "assert all(pathlib.Path(p).resolve()==pathlib.Path(p) for p in paths), "
        "'MeTube paths must not traverse symlinks'"
    )
    paths = [
        str(p)
        for p in (
            cfg.site_path,
            cfg.home,
            cfg.state_dir,
            cfg.download_dir,
            cfg.audio_download_dir,
            cfg.temp_dir,
            cfg.build_root,
            cfg.venv_path,
            cfg.build_dir,
        )
    ]
    mark_read_only(
        server.shell(name="Validate native MeTube paths", commands=[shlex.join(["python3", "-c", preflight, *paths])])
    )
    for mount in cfg.mounts_required:
        mark_read_only(
            server.shell(name=f"Require MeTube mount {mount}", commands=[shlex.join(["mountpoint", "-q", str(mount)])])
        )
    apt.packages(
        name="Install MeTube packages",
        packages=["git", "ffmpeg", "aria2", "apache2-utils"],
        update=True,
        cache_time=3600,
    )
    deploy_uv_install(cfg=UvInstallConfig())
    _node(cfg)
    system_user(cfg.user, home=cfg.home, shell="/usr/sbin/nologin")
    for group in cfg.extra_groups:
        if group not in (host.get_fact(Groups) or {}):
            raise ValueError(f"MeTube supplemental group {group} must already exist")
        server.user(name=f"Keep MeTube in {group}", user=cfg.user, groups=[group], append=True, ensure_home=False)
    for path in dict.fromkeys(
        (cfg.site_path, cfg.state_dir, cfg.build_root, cfg.download_dir, cfg.audio_download_dir, cfg.temp_dir)
    ):
        mode = "0775" if path in (cfg.download_dir, cfg.audio_download_dir, cfg.temp_dir) else "0755"
        files.directory(
            name=f"Ensure retained MeTube directory {path}",
            path=str(path),
            user=cfg.user,
            group=cfg.user,
            mode=mode,
            recursive=False,
        )
    files.directory(path=str(cfg.env_dir), user="root", group="root", mode="0755")
    _pipeline(name="Stage MeTube source, locked runtime and UI", cfg=cfg, data=data, phase="stage")
    # Stage changes never interrupt the running service. Check the queue only
    # when live source/runtime/UI or env/unit changes would cause a rollout.
    if cfg.protect_queue:
        mark_read_only(_rollout_guard(name="Protect active MeTube rollout", cfg=cfg, data=data))
    code = _pipeline(name="Publish MeTube native source/runtime/UI", cfg=cfg, data=data, phase="live")
    verify_trust(cfg.venv_path / "bin/python", user=cfg.user, home=cfg.home, name="MeTube")
    env = files.put(
        name="Write MeTube environment",
        src=StringIO(render_env(cfg)),
        dest=str(cfg.env_file),
        user="root",
        group="root",
        mode="0644",
    )
    unit = systemd_unit(cfg.service_name, render_unit(cfg))
    if cfg.traefik_enabled:
        route = TraefikRoute(
            name=cfg.service_name,
            host=cfg.traefik_host,
            app_port=cfg.port,
            app_host=cfg.host,
            basic_auth=basic_auth,
            internal_ip_ranges=cfg.internal_ip_ranges,
        )
        traefik_route(
            route,
            renderer=lambda _route, auth_hash: render(
                PACKAGE, "metube-traefik.yml.j2", **template_vars(cfg, basic_auth, auth_hash)
            ),
            restart="none",
        )
    service_rollout(cfg.service_name, units=[unit], restart_when=[code, env])
    http_check(cfg.health_url, retries=15, delay=2)
    files.file(name="Complete MeTube rollout", path=str(cfg.site_path / ".ops-deploy-metube-pending"), present=False)
