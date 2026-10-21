"""gotosocial: a GoToSocial ActivityPub server from a pinned release, on SQLite, behind Traefik.

Port of the ``gotosocial_deploy`` role (deploy only). The role's templates are
shipped unchanged and rendered like Ansible renders them, so ``config.yaml``,
the unit, the admin wrapper and the route are byte-identical to the role's,
and Ansible and ops-deploy can take turns on a host without rewriting a file
or restarting GoToSocial.

The domain-layout guard is the role's: the first deploy records
``"<host> <account-domain>"`` in the data directory, and a deploy asking for
another pair is refused unless ``allow_domain_layout_change`` is set (GoToSocial
cannot change its layout once it has federated). Here the recorded pair is
read and compared while planning, so a refused deploy changes nothing at all.

Differences from the role, all on the side of changing less:

- packages are installed (with the role's hour-old apt cache refresh) only
  when one is missing; the role refreshes an hour-old cache on every run;
- a release is unpacked in a staging directory and renamed into place; an
  existing release directory without the binary is refused, not overwritten;
- a layout marker that exists but is not a regular file is refused (the role
  would pass the guard and fail when it records the layout);
- Traefik is never reloaded (its file provider watches the directory; the
  role's ``reload traefik`` handler ignores its own failure);
- GoToSocial is also restarted when ``config.yaml``, the unit or the
  ``current`` link is newer than the running process (an earlier run that
  failed between writing and restarting); the role loses that restart.
"""

from __future__ import annotations

import base64
import binascii
import json
import shlex
from collections.abc import Callable
from importlib.resources import files as resources
from io import StringIO

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import output, require_linux, require_systemd
from ops_deploy.helpers import mark_read_only, systemd_unit
from ops_deploy.helpers.probes import probe
from ops_deploy.infra.postgres_install import missing_packages
from ops_deploy.ops import secret_file
from ops_deploy.services.gotosocial.config import ARCH_MAP, GotosocialConfig
from ops_deploy.services.gotosocial.render import render_admin_wrapper, render_config, render_route, render_unit

_FILES = resources("ops_deploy.services.gotosocial").joinpath("files")
INSTALLER = _FILES.joinpath("release_host.py").read_text()
RESTART_PROBE = _FILES.joinpath("restart_host.py").read_text()
READINESS = _FILES.joinpath("ready_host.py").read_text()


def _strict(command: str, name: str) -> str:
    """Stdout of a read-only probe; a failing probe fails the deploy while planning."""

    result = probe(command, name=name)
    if result is None:
        raise DeployError(f"gotosocial: read-only probe failed: {name}")
    return result.strip()


def recorded_layout(cfg: GotosocialConfig) -> str | None:
    """The marker's content (``None`` when absent), read like ``slurp`` (raw bytes, base64)."""

    marker = shlex.quote(cfg.layout_marker_path)
    answer = _strict(
        f"if [ -L {marker} ]; then echo other; "
        # A failing read fails the probe (never an empty or partial marker).
        f'elif [ -f {marker} ]; then c=$(base64 -w0 < {marker}) || exit 1; echo "file $c"; '
        f"elif [ -e {marker} ]; then echo other; else echo absent; fi",
        "gotosocial domain layout marker",
    )
    if answer == "absent":
        return None
    if answer == "other":
        raise DeployError(
            f"gotosocial: {cfg.layout_marker_path} exists but is not a regular file; review it before deploying"
        )
    kind, _, payload = answer.partition(" ")
    if kind != "file":
        raise DeployError("gotosocial: unexpected answer from the domain layout probe")
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8", errors="replace")
    except binascii.Error:
        raise DeployError("gotosocial: unexpected answer from the domain layout probe") from None


def check_layout(cfg: GotosocialConfig, recorded: str | None) -> None:
    """layout.yml: refuse a recorded pair other than the requested one, unless overridden."""

    wanted = cfg.domain_layout.strip()
    if recorded is None or recorded.strip() == wanted or cfg.allow_domain_layout_change:
        return
    shown = recorded.strip().encode("unicode_escape").decode("ascii")[:300]
    raise DeployError(
        f'gotosocial: this instance was deployed as "{shown}" (host account-domain) and is now asked to be '
        f'"{wanted}". GoToSocial cannot change its domain layout after federating. Only for a wiped data '
        "directory set allow_domain_layout_change=true."
    )


def install_command(cfg: GotosocialConfig, arch: str) -> str:
    checksum = cfg.release_checksums[arch]  # type: ignore[index]
    payload = {
        "url": cfg.download_url(arch),
        "sha256": checksum.removeprefix("sha256:"),
        "release_dir": cfg.release_dir,
    }
    return shlex.join(["python3", "-I", "-c", INSTALLER, json.dumps(payload, sort_keys=True)])


def _restart_owed(cfg: GotosocialConfig) -> bool:
    """A running GoToSocial older than its config, unit or ``current`` link (a lost restart)."""

    payload = {"unit": f"{cfg.service_name}.service", "paths": [cfg.config_path, cfg.unit_path, cfg.current_link]}
    answer = _strict(
        shlex.join(["python3", "-I", "-c", RESTART_PROBE, json.dumps(payload, sort_keys=True)]),
        "gotosocial restart owed",
    )
    if answer not in ("inactive", "owed", "current"):
        raise DeployError("gotosocial: unexpected answer from the restart probe")
    return answer == "owed"


def readiness_check(cfg: GotosocialConfig) -> OperationMeta:
    """health.yml: ``GET /readyz`` until 200, in Python like the role's ``uri`` (no curl needed)."""

    address = f"[{cfg.bind_address}]" if ":" in cfg.bind_address else cfg.bind_address
    payload = {
        "url": f"http://{address}:{cfg.port}/readyz",
        "retries": cfg.healthcheck_retries,
        "delay": cfg.healthcheck_delay,
        "timeout": 30,
    }
    command = shlex.join(["python3", "-I", "-c", READINESS, json.dumps(payload, sort_keys=True)])
    return mark_read_only(server.shell(name="Wait for GoToSocial readiness", commands=[command]))


def _changed(*ops: OperationMeta | None) -> Callable[[], bool]:
    metas = [op for op in ops if op is not None]
    return lambda: any(op.did_change() for op in metas)


@deploy("Deploy GoToSocial")
def deploy_gotosocial(cfg: GotosocialConfig, smtp_password: SecretStr | None = None) -> None:
    """Install, configure and run GoToSocial; record its domain layout; write its Traefik route."""

    # Everything rendered on the controller first: a template error fails before any operation.
    config_content = render_config(cfg, smtp_password)
    unit_text = render_unit(cfg)
    wrapper_text = render_admin_wrapper(cfg)
    route_text = render_route(cfg) if cfg.traefik_enabled else None

    require_linux("gotosocial")
    require_systemd("gotosocial")
    machine = str(host.get_fact(Command, command="uname -m") or "").strip()
    arch = ARCH_MAP.get(machine, "unsupported")
    if arch not in cfg.release_checksums:
        raise DeployError(f"gotosocial: no release checksum for the host architecture ({machine or 'unknown'})")

    # layout.yml, while planning: a refused deploy changes nothing.
    check_layout(cfg, recorded_layout(cfg))

    # packages.yml
    missing = missing_packages(cfg.packages)
    if missing:
        apt.packages(name="Install GoToSocial packages", packages=missing, update=True, cache_time=3600)

    # user.yml
    server.group(name=f"Ensure group {cfg.group}", group=cfg.group, system=True)
    server.user(
        name=f"Ensure user {cfg.user}",
        user=cfg.user,
        group=cfg.group,
        system=True,
        shell="/usr/sbin/nologin",
        home=cfg.data_dir,
        ensure_home=False,
        create_home=False,
    )
    for path in (cfg.install_root, f"{cfg.install_root}/releases"):
        files.directory(name=f"Ensure {path}", path=path, user="root", group="root", mode="0755")
    files.directory(name=f"Ensure {cfg.config_dir}", path=cfg.config_dir, user="root", group=cfg.group, mode="0750")
    for path in (cfg.data_dir, cfg.storage_dir, cfg.cache_dir):
        files.directory(name=f"Ensure {path}", path=path, user=cfg.user, group=cfg.group, mode="0700")

    # binary.yml
    binary = shlex.quote(f"{cfg.release_dir}/gotosocial")
    release = _strict(
        f"if [ -e {binary} ] || [ -L {binary} ]; then echo present; else echo absent; fi", "gotosocial release"
    )
    if release == "absent":
        server.shell(name=f"Install GoToSocial {cfg.version}", commands=[install_command(cfg, arch)])
    elif release != "present":
        raise DeployError("gotosocial: unexpected answer from the release probe")
    link = files.link(
        name=f"Point {cfg.current_link} at {cfg.version}",
        path=cfg.current_link,
        target=cfg.release_dir,
        user="root",
        group="root",
        create_remote_dir=False,
    )
    files.put(
        name="Install admin wrapper",
        src=StringIO(wrapper_text),
        dest=cfg.admin_wrapper_path,
        user="root",
        group="root",
        mode="0750",
        create_remote_dir=False,
    )

    # config.yml: through stdin, it may carry the SMTP password.
    config = secret_file(
        name=f"Write {cfg.config_path}",
        path=cfg.config_path,
        content=config_content,
        user="root",
        group=cfg.group,
        mode="0640",
    )

    # systemd.yml and service.yml (the role's daemon_reload on every run is a no-op unless owed).
    unit_name = f"{cfg.service_name}.service"
    unit = systemd_unit(cfg.service_name, unit_text)
    reload_owed = output(f"systemctl show -p NeedDaemonReload --value {shlex.quote(unit_name)}").strip() == "yes"
    systemd.daemon_reload(name="Reload systemd", _if=lambda: reload_owed or unit.did_change())
    systemd.service(
        name=f"{'Enable' if cfg.service_enabled else 'Disable'} {unit_name}",
        service=unit_name,
        running=None,
        enabled=cfg.service_enabled,
    )
    if cfg.service_state == "started":
        owed = _restart_owed(cfg)
        start = systemd.service(name=f"Start {unit_name}", service=unit_name, running=True)
        inputs = _changed(link, config, unit)
        systemd.service(
            name=f"Restart {unit_name}",
            service=unit_name,
            running=None,
            restarted=True,
            _if=lambda: not start.did_change() and (owed or inputs()),
        )
        # health.yml
        if cfg.healthcheck_enabled:
            readiness_check(cfg)
    else:
        systemd.service(name=f"Stop {unit_name}", service=unit_name, running=False)

    # layout_record.yml
    files.put(
        name="Record the domain layout",
        src=StringIO(cfg.domain_layout.strip() + "\n"),
        dest=cfg.layout_marker_path,
        user="root",
        group="root",
        mode="0644",
        # The data directory belongs to the service user: never chown it as the parent.
        create_remote_dir=False,
    )

    # traefik.yml (no reload: the file provider watches the directory).
    if route_text is not None:
        directory = cfg.traefik_config_path.rsplit("/", 1)[0] or "/"
        files.directory(name=f"Ensure {directory}", path=directory, user="root", group="root", mode="0755")
        files.put(
            name="Write Traefik route gotosocial",
            src=StringIO(route_text),
            dest=cfg.traefik_config_path,
            user="root",
            group="root",
            mode="0644",
            create_remote_dir=False,
        )
    else:
        files.file(name="Remove Traefik route gotosocial", path=cfg.traefik_config_path, present=False)
