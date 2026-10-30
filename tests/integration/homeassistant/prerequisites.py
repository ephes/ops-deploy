"""Explicit existing-host prerequisites, not an original pristine-bootstrap claim."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import shutil
import tarfile
from pathlib import Path

import yaml

from ops_deploy.services.homeassistant.python_state import EnvironmentState, homeassistant_decision
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.services.homeassistant.uv import HomeAssistantUvConfig

from .fixture import ROOT, command, default_ipv4, metadata, write
from .seed_requirements import VERSIONS

UV_ARCHIVE = "uv-x86_64-unknown-linux-gnu.tar.gz"
UV_ROOT = "uv-x86_64-unknown-linux-gnu"
MINIMAL_CONFIGURATION = """homeassistant:
  name: Owned synthetic native fixture
  time_zone: UTC
  country: DE
  unit_system: metric
http:
  server_host: 0.0.0.0
  server_port: 10020
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
api:
websocket_api:
frontend:
config:
conversation:
assist_pipeline:
recorder:
logger:
  default: warning
"""


def configuration(ipv4: str) -> str:
    """Allow the original loopback-to-own-IPv4 rewrite inside this guest only."""
    value = yaml.safe_load(MINIMAL_CONFIGURATION)
    value["http"]["trusted_proxies"] = ["127.0.0.1", ipv4]
    return yaml.safe_dump(value, sort_keys=False)


def seed(baseline: str) -> None:
    if baseline not in VERSIONS:
        raise ValueError("unqualified owned Home Assistant baseline")
    if Path("/home/homeassistant").exists():
        raise RuntimeError("owned existing-host prerequisite requires fresh home path")
    cfg = HomeAssistantUvConfig()
    archive = ROOT / UV_ARCHIVE
    url = f"https://github.com/astral-sh/uv/releases/download/{cfg.version}/{UV_ARCHIVE}"
    command("curl", "--fail", "--location", "--max-time", "180", "--output", str(archive), url, timeout=190)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != cfg.checksums[UV_ROOT.removeprefix("uv-")]:
        raise RuntimeError("owned UV prerequisite archive checksum mismatch")
    installed = {}
    with tarfile.open(archive, "r:gz") as source:
        for name in ("uv", "uvx"):
            member = source.getmember(UV_ROOT + "/" + name)
            if not member.isfile():
                raise RuntimeError("owned UV prerequisite is not a regular archive member")
            stream = source.extractfile(member)
            assert stream is not None
            path = Path("/usr/local/bin") / name
            with stream, path.open("wb") as output:
                shutil.copyfileobj(stream, output)
            path.chmod(0o755)
            installed[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "metadata": metadata(path)}
    archive.unlink()
    version = command("/usr/local/bin/uv", "--version").stdout.strip()
    if version.split()[:2] != ["uv", cfg.version]:
        raise RuntimeError("owned UV prerequisite version mismatch")
    command("useradd", "--create-home", "--shell", "/bin/bash", "--groups", "dialout", "homeassistant")
    user = pwd.getpwnam("homeassistant")
    config = Path("/home/homeassistant/site/config")
    config.mkdir(parents=True, mode=0o755)
    for path in (config.parent, config):
        path.chmod(0o755)
        os.chown(path, user.pw_uid, user.pw_gid)
    selected = config / "configuration.yaml"
    selected.write_text(configuration(default_ipv4()))
    selected.chmod(0o600)
    os.chown(selected, user.pw_uid, user.pw_gid)
    # The original role is being compared on a declared existing host. Core's
    # wheel alone omits integration dependencies normally resolved at startup.
    # Initialize them through the selected original loader without starting HA.
    application = seed_application(config, baseline)
    # A real inventory server already has udev. The owned systemd userspace
    # installs/starts it explicitly; no physical tty/radio qualification follows.
    command("systemctl", "start", "systemd-udevd.service")
    active = command("systemctl", "is-active", "systemd-udevd.service").stdout.strip()
    assert active == "active"
    write(
        "existing-host-prerequisites.json",
        {
            "classification": "explicit fixture baseline, not pristine original role bootstrap",
            "uv": {"url": url, "archive_sha256": digest, "version": version, "binaries": installed},
            "configuration": {"source": "public minimal synthetic fixture", "metadata": metadata(selected)},
            "account": {"uid": user.pw_uid, "gid": user.pw_gid},
            "application_dependencies": application,
            "udev_active": active,
            "core_onboarding_completed": False,
            "scope": "no real user, device, model provider, inventory or hardware data",
        },
    )


def seed_application(config: Path, baseline: str) -> dict[str, object]:
    if baseline not in VERSIONS:
        raise ValueError("unqualified owned Home Assistant baseline")
    library = os.environ.get("OPS_LIBRARY_PATH", "")
    if not Path(library).is_absolute():
        raise RuntimeError("owned original library path is required")
    prefix = [
        "runuser",
        "-u",
        "homeassistant",
        "--",
        "/usr/bin/env",
        "-u",
        "OPS_DEPLOY_PATH",
        "HOME=/home/homeassistant",
        "OPS_LIBRARY_PATH=" + library,
    ]
    venv = config.parent / ".venv"
    commands = (
        ("venv", ["/usr/local/bin/uv", "venv", "--seed", "--python", "3.14.8", str(venv)], 600),
        (
            "package",
            ["/usr/local/bin/uv", "pip", "install", "--python", str(venv / "bin/python"), "homeassistant==" + baseline],
            900,
        ),
        (
            "requirements",
            [
                str(venv / "bin/python"),
                "-I",
                "-B",
                str(Path(__file__).with_name("seed_requirements.py")),
                str(config),
                baseline,
            ],
            900,
        ),
    )
    report: dict[str, object] = {}
    for label, argv, timeout in commands:
        result = command(*prefix, *argv, timeout=timeout, check=False)
        # Public package/loader diagnostics only: no real app config or secrets
        # exist in this fixture and this helper never starts the application.
        write(
            "existing-host-" + label + ".json",
            {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )
        if result.returncode:
            raise RuntimeError("owned existing-host " + label + " seed failed")
        if label == "requirements":
            value = json.loads(result.stdout)
            if not isinstance(value, dict) or value.get("matter_config_flow_import") is not True:
                raise RuntimeError("owned dependency import proof missing")
            decision = homeassistant_decision(
                HomeAssistantRuntimeConfig(package_spec="homeassistant==" + baseline),
                EnvironmentState(**value["original_environment"]),
            )
            if decision.replace or decision.install_application:
                raise RuntimeError("owned seeded environment would be replaced or reinstalled by original role")
            value["original_environment_retained"] = True
            report = value
    return report
