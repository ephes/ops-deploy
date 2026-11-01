"""Role-equivalent Rust candidate, retired drop-ins, shadow units and release pins."""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.operations import files, server, systemd

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, stdin_arguments
from ops_deploy.helpers.rust_release import Install, install_release, pin_release, prune_releases
from ops_deploy.services.software_live.common import RESOURCE, SHADOW, endpoint_json, put, restart, unit
from ops_deploy.services.software_live.config import SoftwareLiveConfig
from ops_deploy.services.software_live.files.software_live_impl import VERSION_RE, software_live_variant


@dataclass(frozen=True)
class Selection:
    triggers: list[OperationMeta]
    install: Install | None
    live: dict[str, Any]
    production: list[OperationMeta] = field(default_factory=list)


def paths(cfg: SoftwareLiveConfig) -> dict[str, Any]:
    return {
        "dropins": [
            str(cfg.systemd_dir / (name + ".d/impl.conf"))
            for name in ("software-live-endpoint.service", "software-live-collector.service")
        ],
        "units": [
            str(cfg.systemd_dir / name)
            for name in ("software-live-shadow-collector.service", "software-live-shadow-endpoint.service")
        ],
        "pin": str(cfg.release_root / ".pins/software-live"),
        "shadow_pin": str(cfg.release_root / ".pins/software-live-shadow"),
    }


def live_state(cfg: SoftwareLiveConfig) -> dict[str, Any]:
    script = (
        RESOURCE.joinpath("files/software_live_impl.py").read_text()
        + "\n"
        + RESOURCE.joinpath("files/live_state_host.py").read_text()
    )
    inputs = {
        "root": str(cfg.release_root),
        "proc": str(cfg.proc_root),
        "cgroup": str(cfg.cgroup_root),
        "paths": paths(cfg),
    }
    raw = probe(
        shlex.join(["/usr/bin/python3", "-I", "-", json.dumps(inputs)]),
        name="Read software-live release protection",
        stdin=script,
    )
    try:
        value = json.loads(raw or "")
        if not isinstance(value, dict) or not all(
            k in value for k in ("versions", "unknown", "last_live", "shadow_pin")
        ):
            raise ValueError("invalid live state")
        return value
    except (ValueError, TypeError):
        # The role does not block the switch when its process probe fails; it prunes nothing.
        return {"versions": [], "unknown": ["software-live live probe unavailable"], "last_live": "", "shadow_pin": ""}


def release_inputs(cfg: SoftwareLiveConfig) -> tuple[str, str, str]:
    raw = probe("cat -- " + shlex.quote(str(cfg.os_release_path)), name="Read software-live release variant")
    variant = software_live_variant(raw)
    checksum = cfg.rust_sha256.get(variant, "")
    if variant not in ("ubuntu24.04", "debian13") or not VERSION_RE.fullmatch(cfg.rust_version):
        raise DeployError("Rust software-live requires a released OS variant and valid release version")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", checksum) and cfg.rust_local_archive is None:
        raise DeployError("Rust software-live requires the variant archive checksum or local archive")
    if cfg.rust_local_archive is not None and not cfg.rust_local_archive.is_file():
        raise DeployError("software-live controller archive unavailable")
    url = cfg.rust_release_url or (
        f"https://github.com/ephes/ops-library/releases/download/software-live-v{cfg.rust_version}/"
        f"software-live-{cfg.rust_version}-x86_64-unknown-linux-gnu-{variant}.tar.gz"
    )
    return variant, checksum, url


def _shadow(cfg: SoftwareLiveConfig) -> list[OperationMeta]:
    changed = []
    if cfg.rust_shadow:
        changed.append(
            files.directory(
                name="Ensure software-live shadow state",
                path=str(cfg.data_dir / "shadow"),
                user="root",
                group=cfg.group,
                mode="0750",
            )
        )
        endpoint = put(
            str(cfg.config_dir / "shadow-endpoint.json"),
            endpoint_json(cfg, "127.0.0.1", shadow=True),
            group=cfg.group,
            mode="0640",
        )
        units = [
            unit(cfg, name, template)
            for name, template in zip(
                SHADOW,
                ("shadow-collector.service.j2", "shadow-collector.timer.j2", "shadow-endpoint.service.j2"),
                strict=True,
            )
        ]
        changed += [endpoint, *units]
        systemd.daemon_reload(name="Reload software-live shadow units", _if=lambda: any(x.did_change() for x in units))
        restart("software-live-shadow-endpoint.service", [endpoint, *units])
        restart("software-live-shadow-collector.timer", units)
    else:
        for name in SHADOW:
            path = str(cfg.systemd_dir / name)
            if host.get_fact(File, path=path) is not None:
                systemd.service(name=f"Stop and disable {name}", service=name, running=False, enabled=False)
            changed.append(files.file(name=f"Remove {name}", path=path, present=False))
        changed.append(
            files.file(
                name="Remove shadow endpoint config", path=str(cfg.config_dir / "shadow-endpoint.json"), present=False
            )
        )
        changed.append(
            files.directory(name="Remove software-live shadow state", path=str(cfg.data_dir / "shadow"), present=False)
        )
        systemd.daemon_reload(
            name="Reload removed software-live shadow units", _if=lambda: any(x.did_change() for x in changed)
        )
    return changed


def select(cfg: SoftwareLiveConfig, live: dict[str, Any], rust_inputs: tuple[str, str, str]) -> Selection:
    """Install and validate the pinned release, then retire the S12 drop-ins.

    The base units name the versioned binary themselves (S12). The impl.conf
    drop-ins earlier deploys wrote are removed only after the candidate
    validated, and before the base units are written, so the caller's single
    daemon reload and restart switch the units over.
    """
    _, checksum, url = rust_inputs
    install = install_release(
        "software-live",
        cfg.rust_version,
        sha256=checksum,
        install_root=str(cfg.release_root),
        release_url=url,
        local_archive=cfg.rust_local_archive,
        members=("software-live", "software-live-apt", "LICENSE", "LICENSE.GPL-3.0"),
        executables=("software-live", "software-live-apt"),
        validate_user=cfg.user if cfg.rust_version_check_user is None else cfg.rust_version_check_user,
    )
    candidate = """import json,subprocess,sys,time
binary,policy,max_age=sys.argv[1:]
subprocess.run([binary,'validate','--config',policy],check=True)
r=subprocess.run([binary+'-apt','observe','--max-age',max_age,'--now',str(int(time.time()))],capture_output=True,text=True,timeout=120)
try:status=json.loads(r.stdout).get('status')
except (ValueError,AttributeError):status=None
if r.returncode or status!='ok':sys.exit('software-live candidate APT observation rejected')
"""
    mark_read_only(
        server.shell(
            name="Validate software-live policy and APT candidate",
            commands=[
                shlex.join(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-",
                        str(cfg.binary),
                        str(cfg.config_dir / "policy.json"),
                        str(cfg.policy.get("apt_max_age_seconds", 172800)),
                    ]
                )
            ],
            **stdin_arguments(candidate),
        )
    )
    # A copy: _shadow's reload condition closes over its own list.
    changed = list(_shadow(cfg))
    production = []
    for path in paths(cfg)["dropins"]:
        removal = files.file(name=f"Remove retired drop-in {path}", path=path, present=False)
        parent = path.rsplit("/", 1)[0]
        # Only an empty directory goes: another drop-in there is not ours.
        server.shell(
            name=f"Remove empty {parent}",
            commands=[shlex.join(["rmdir", "--", parent]) + " 2>/dev/null || true"],
            _if=removal.did_change,
        )
        changed.append(removal)
        production.append(removal)
    return Selection(changed, install, live, production=production)


def verify_and_pin(cfg: SoftwareLiveConfig, selected: Selection) -> None:
    script = (
        RESOURCE.joinpath("files/software_live_impl.py").read_text()
        + "\n"
        + RESOURCE.joinpath("files/verify_host.py").read_text()
    )
    expect = {
        "impl": "rust",
        "binary": str(cfg.binary),
        "script": str(cfg.install_dir / "software_live.py"),
        "shadow": cfg.rust_shadow,
    }
    mark_read_only(
        server.shell(
            name="Verify software-live running implementation",
            commands=[
                shlex.join(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-",
                        "--proc-root",
                        str(cfg.proc_root),
                        "--expect",
                        json.dumps(expect),
                        "--retries",
                        str(cfg.verify_retries),
                        "--delay",
                        str(cfg.verify_delay),
                    ]
                )
            ],
            **stdin_arguments(script),
        )
    )
    # S12: the retired Python program and its bytecode cache leave the host only
    # once the Rust units are verified (the Nyxmon helper stays).
    files.file(
        name="Remove the retired Python software observation program",
        path=str(cfg.install_dir / "software_live.py"),
        present=False,
    )
    files.directory(
        name="Remove the retired Python bytecode cache", path=str(cfg.install_dir / "__pycache__"), present=False
    )
    version = cfg.rust_version
    last = selected.live["last_live"]
    pin_release(
        "software-live",
        "software-live",
        version,
        install_root=str(cfg.release_root),
        previous=last if last and last != (version or "") else "",
    )
    if not cfg.rust_shadow or (selected.live["shadow_pin"] and selected.live["shadow_pin"] != cfg.rust_version):
        pin_release(
            "software-live", "software-live-shadow", None, install_root=str(cfg.release_root), keep_previous=False
        )
    if cfg.rust_shadow:
        pin_release("software-live", "software-live-shadow", cfg.rust_version, install_root=str(cfg.release_root))
    prune_releases(
        "software-live",
        install_root=str(cfg.release_root),
        keep_versions=cfg.rust_keep_versions,
        protect=selected.live["versions"],
        live_state_unknown=bool(selected.live["unknown"]),
        after=[selected.install] if selected.install is not None else [],
    )
