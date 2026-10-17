"""What the host has, read while planning, and what the run therefore owes (2.6 of the design).

Every decision is made here, from read-only probes, before the first
operation: a converged host gets no mutating operation at all, and
``just pyinfra-check`` shows exactly what a deploy would do.

The applied stamp (``/var/lib/ops-deploy/<service>/applied.json``, root
``0600`` in a ``0700`` directory) records the fingerprint of the last
successful apply: the digest of the compose file and of every env and config
file (host values symbolic), a digest per service, the image pins, and the
uid/gid values the env files were completed with. ``pending`` next to it is
written before a run changes any input and removed with the new stamp, so a
run that stopped half-way is finished by the next one.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pyinfra import host, logger
from pyinfra.facts.files import Sha256File
from pyinfra.facts.server import Command

from ops_deploy.base._common import output
from ops_deploy.helpers.probes import probe_command, probe_output
from ops_deploy.services.compose_app.config import ComposeAppConfig
from ops_deploy.services.compose_app.render import RenderedEnv, digest, host_refs, service_digests

FILES = Path(__file__).parent / "files"
COMPOSE_HOST = (FILES / "compose_host.py").read_text()
QBITTORRENT = (FILES / "qbittorrent_prefs.py").read_text()
STAMP_VERSION = 1
PENDING = "pending"
STAMP = "applied.json"


def script(source: str, mode: str) -> str:
    """``python3 -I -c <source> <mode>``: a host-side script; its request comes on stdin."""

    return shlex.join(["python3", "-I", "-c", source, mode])


def payload(request: Mapping[str, Any]) -> str:
    """The request as base64 text (pyinfra writes stdin line by line).

    Keys keep their order: a ``json_key_copy`` template is written in it.
    """

    return base64.encodebytes(json.dumps(request).encode()).decode("ascii")


def stdin_probe(command: str, request: Mapping[str, Any], *, name: str) -> str | None:
    """Stdout of the read-only ``command`` fed ``request`` on stdin, or ``None`` when it failed."""

    raw = host.get_fact(Command, command=probe_command(command), _stdin=payload(request), _get_pty=False)
    result = probe_output(str(raw or ""))
    if result is None:
        logger.warning(f"{host.print_prefix}probe failed: {name}; running the step it gates")
    return result


@dataclass(frozen=True)
class Container:
    status: str
    image: str


@dataclass
class Plan:
    """The decisions of one run (see the module docstring)."""

    desired: dict[str, Any]
    left_pending: bool
    stamp: dict[str, Any] | None
    # Input files whose content on the host differs from the desired render.
    differs: set[str] = field(default_factory=set)
    ids: dict[str, int] | None = None
    host_probe_failed: bool = False
    drift: set[str] = field(default_factory=set)
    orphans: set[str] = field(default_factory=set)
    missing_images: list[str] = field(default_factory=list)
    unit_active: bool = False
    unit_stale: bool = False
    legacy_files: list[str] = field(default_factory=list)

    @property
    def stamp_current(self) -> bool:
        stamp = self.stamp or {}
        return (
            self.stamp is not None
            and all(stamp.get(key) == self.desired[key] for key in ("version", "files", "services", "images"))
            and self.ids is not None
            and stamp.get("ids") == self.ids
        )

    @property
    def apply(self) -> bool:
        return bool(
            self.left_pending
            or not self.stamp_current
            or self.differs
            or self.host_probe_failed
            or self.drift
            or self.orphans
            or self.missing_images
            or not self.unit_active
            or self.legacy_files
        )

    def file_changed(self, path: str) -> bool:
        """``path`` differs from the stamp or on the host (or a run is pending)."""

        stamp_files = (self.stamp or {}).get("files") or {}
        return self.left_pending or stamp_files.get(path) != self.desired["files"][path] or path in self.differs

    def service_changed(self, cfg: ComposeAppConfig, name: str) -> bool:
        """Whether this run may recreate (or start) ``name``."""

        service = cfg.service(name)
        stamp_services = (self.stamp or {}).get("services") or {}
        reads = {str(cfg.site_path / env) for env in service.env_files}
        return bool(
            self.left_pending
            or not self.unit_active
            or stamp_services.get(name) != self.desired["services"][name]
            or str(cfg.compose_path) in self.differs
            or reads & self.differs
            or (self.host_probe_failed and reads)
            or name in self.drift
            or service.image in self.missing_images
        )


def _stamp(cfg: ComposeAppConfig) -> tuple[dict[str, Any] | None, bool]:
    state = shlex.quote(str(cfg.state_dir))
    text = output(f"cat {state}/{STAMP}")
    left = output(f"test -e {state}/{PENDING} && echo pending").strip() == "pending"
    try:
        stamp = json.loads(text) if text.strip() else None
    except json.JSONDecodeError:
        stamp = None
    return (stamp if isinstance(stamp, dict) else None), left


def _containers(cfg: ComposeAppConfig) -> dict[str, Container]:
    fmt = (
        '{{index .Config.Labels "com.docker.compose.service"}} {{.State.Status}} {{.Image}} '
        '{{index .Config.Labels "com.docker.compose.oneoff"}}'
    )
    project = shlex.quote(f"label=com.docker.compose.project={cfg.project}")
    listing = output(
        f'ids=$(docker ps -aq --filter {project}) && [ -n "$ids" ] && docker inspect --format {shlex.quote(fmt)} $ids'
    )
    found: dict[str, Container] = {}
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] != "True":
            found[parts[0]] = Container(status=parts[1], image=parts[2])
    return found


def _image_ids(cfg: ComposeAppConfig) -> dict[str, str]:
    refs = " ".join(shlex.quote(ref) for ref in cfg.images)
    listing = output(
        f'for ref in {refs}; do id=$(docker image inspect --format "{{{{.Id}}}}" "$ref" 2>/dev/null) '
        '&& printf "%s %s\\n" "$ref" "$id"; done'
    )
    ids = {}
    for line in listing.splitlines():
        ref, _, image = line.partition(" ")
        if ref in cfg.images and image.startswith("sha256:"):
            ids[ref] = image.strip()
    return ids


def _unit(cfg: ComposeAppConfig) -> tuple[bool, bool]:
    unit = shlex.quote(f"{cfg.unit_name}.service")
    shown = output(f"systemctl show -p ActiveState -p NeedDaemonReload {unit}")
    props = dict(line.partition("=")[::2] for line in shown.splitlines())
    return props.get("ActiveState") == "active", props.get("NeedDaemonReload") == "yes"


def _host_rendered(
    cfg: ComposeAppConfig, envs: Mapping[str, RenderedEnv]
) -> tuple[dict[str, str] | None, set[str], bool]:
    """(ids, differing paths, probe failed) from ``compose_host.py render-probe``."""

    refs = host_refs(cfg)
    specs = host_specs(envs)
    if not specs and not refs:
        return {}, set(), False
    out = stdin_probe(script(COMPOSE_HOST, "render-probe"), {"ids": refs, "files": specs}, name="env files")
    if out is None:
        return None, set(), True
    ids: dict[str, str] = {}
    same = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "id":
            ids[parts[1]] = parts[2]
        elif len(parts) == 3 and parts[0] == "file" and parts[2] == "same":
            same.add(parts[1])
    # A file the probe did not report as the same is written.
    return ids, {spec["path"] for spec in specs} - same, False


def host_specs(envs: Mapping[str, RenderedEnv]) -> list[dict[str, Any]]:
    return [
        {"path": str(env.path), "mode": env.mode, "owner": "root", "group": "root", "segments": list(env.segments)}
        for env in envs.values()
        if env.host_rendered
    ]


def desired_stamp(
    cfg: ComposeAppConfig, compose: str, envs: Mapping[str, RenderedEnv], configs: Mapping[str, str]
) -> dict[str, Any]:
    files = {str(cfg.compose_path): digest(compose)}
    files.update({str(env.path): env.digest for env in envs.values()})
    files.update({path: digest(text) for path, text in configs.items()})
    return {
        "version": STAMP_VERSION,
        "files": files,
        "services": service_digests(cfg, envs),
        "images": list(cfg.images),
    }


def plan(cfg: ComposeAppConfig, compose: str, envs: Mapping[str, RenderedEnv], configs: Mapping[str, str]) -> Plan:
    """Read the host and decide; ``configs`` maps each config file's path to its text."""

    desired = desired_stamp(cfg, compose, envs, configs)
    stamp, left = _stamp(cfg)
    result = Plan(desired=desired, left_pending=left, stamp=stamp)
    raw_ids, host_differs, failed = _host_rendered(cfg, envs)
    result.host_probe_failed = failed
    result.differs |= host_differs
    if raw_ids is not None and all(value.isdigit() for value in raw_ids.values()):
        result.ids = {key: int(value) for key, value in raw_ids.items()}
    controller_files = {str(cfg.compose_path): digest(compose), **{p: digest(t) for p, t in configs.items()}}
    controller_files.update({str(e.path): e.digest for e in envs.values() if e.content is not None})
    result.differs |= {path for path, sha in controller_files.items() if host.get_fact(Sha256File, path=path) != sha}

    containers = _containers(cfg)
    images = _image_ids(cfg)
    result.missing_images = [ref for ref in cfg.images if ref not in images]
    for service in cfg.running_services:
        container = containers.get(service.name)
        if container is None or container.status != "running" or container.image != images.get(service.image):
            result.drift.add(service.name)
    result.orphans = set(containers) - {s.name for s in cfg.services}
    result.unit_active, result.unit_stale = _unit(cfg)
    result.legacy_files = [
        str(path)
        for path in cfg.legacy_files
        if output(f"test -e {shlex.quote(str(path))} && echo yes").strip() == "yes"
    ]
    return result
