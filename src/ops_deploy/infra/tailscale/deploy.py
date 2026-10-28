"""Native package/repository policy and identity-preserving normal join/prefs."""

from __future__ import annotations

import ipaddress
import json
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.server import LinuxDistribution, Which
from pyinfra.operations import apt, files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import StdinLines, probe, verify_probe
from ops_deploy.infra._common import deb822_sources

from .config import TailscaleConfig

HOST_SCRIPT = (Path(__file__).parents[1] / "files/tailscale_host.py").read_text()
KEY_SCRIPT = (Path(__file__).parents[1] / "files/tailscale_repo_key.py").read_text()
AUTH_FIELD = "tailscale_auth_key"


def helper(script: str, action: str) -> str:
    return shlex.join(["python3", "-I", "-B", "-c", script, action])


@operation()
def repository_key(data: str) -> Generator[StringCommand, None, None]:
    # gpg is an explicit ordinary prerequisite. A fresh dry plan may describe
    # its subsequent validation; it cannot claim that validation already ran.
    answer = (
        probe(helper(KEY_SCRIPT, "check"), name="Upstream Tailscale public key rotation/validation", stdin=data)
        if host.get_fact(Which, command="gpg")
        else "pending"
    )
    if answer == "current":
        host.noop("Validated upstream public key matches the installed key")
    elif answer == "pending":
        yield StringCommand(
            helper(KEY_SCRIPT, "apply"), _stdin=StdinLines(data), _get_pty=False, _shell_executable="sh"
        )
    else:
        raise DeployError("Tailscale public key refresh/validation failed; installed key preserved")


@operation()
def preferences(data: str) -> Generator[StringCommand, None, None]:
    cfg = json.loads(data)
    if not host.get_fact(Which, command=cfg["binary"]):
        # A fresh dry plan precedes apt's execution. Defer the decision to the
        # same strict helper after the declared package/service prerequisites;
        # missing tools never count as matching selected preferences.
        yield StringCommand(
            helper(HOST_SCRIPT, "apply-prefs"), _stdin=StdinLines(data), _get_pty=False, _shell_executable="sh"
        )
        return
    answer = probe(helper(HOST_SCRIPT, "check"), name="Selected native Tailscale preferences", stdin=data)
    try:
        state: Any = json.loads(answer or "null")
    except ValueError:
        state = None
    if not isinstance(state, dict) or type(state.get("available")) is not bool:
        raise DeployError("Selected native Tailscale preferences are unavailable")
    if state["available"] and type(state.get("needed")) is not bool:
        raise DeployError("Selected native preference schema is unavailable")
    if state["available"] and not state["needed"]:
        host.noop("Running node preferences already match, or node is not Running")
    else:
        yield StringCommand(
            helper(HOST_SCRIPT, "apply-prefs"), _stdin=StdinLines(data), _get_pty=False, _shell_executable="sh"
        )


@operation()
def join(data: str, credential: SecretStr) -> Generator[StringCommand, None, None]:
    answer = probe(helper(HOST_SCRIPT, "check"), name="Native Tailscale backend", stdin=data)
    try:
        state: Any = json.loads(answer or "null")
    except ValueError:
        state = None
    cfg = json.loads(data)
    if not isinstance(state, dict) or not isinstance(state.get("backend"), str):
        # Missing tools during a genuine fresh dry plan are a prerequisite
        # dependency; actual operation generation happens after apt/service.
        if host.get_fact(Which, command=cfg["binary"]):
            raise DeployError("Native Tailscale backend is unavailable; no join admitted")
    elif state["backend"] == "Running" or cfg["manual_up"]:
        host.noop("Running identity preserved, or explicit manual-up policy")
        return
    content = json.dumps({**cfg, "auth_key": credential.get_secret_value()})
    yield StringCommand(helper(HOST_SCRIPT, "join"), _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh")


def tailscale_ipv4(cfg: TailscaleConfig) -> str:
    """The original post-deploy address fact, exporting no peer/status body."""
    answer = probe(helper(HOST_SCRIPT, "ipv4"), name="Native own Tailscale IPv4 address", stdin=cfg.model_dump_json())
    try:
        value = json.loads(answer or "null")
        return str(ipaddress.IPv4Address(value["address"]))
    except (ValueError, TypeError, KeyError):
        raise DeployError("Native own Tailscale IPv4 address is unavailable") from None


@deploy("Deploy Tailscale native core")
def deploy_tailscale(cfg: TailscaleConfig, secrets: SecretValues) -> None:
    require_linux("tailscale")
    require_systemd("tailscale")
    distribution = host.get_fact(LinuxDistribution)
    if distribution["name"] not in {"Ubuntu", "Debian"}:
        raise DeployError("Tailscale native deploy supports Debian/Ubuntu only")
    release = (
        cfg.repo_release
        or distribution["release_meta"].get("VERSION_CODENAME")
        or distribution["release_meta"].get("CODENAME")
    )
    distro = cfg.repo_distro or str(distribution["name"]).lower()
    if not release:
        raise DeployError("Tailscale repository requires a native release codename")
    # Revalidate native facts used in repository URL/source syntax.
    bound = cfg.model_copy(update={"repo_release": release, "repo_distro": distro})
    bound = TailscaleConfig.model_validate(bound.model_dump())
    credential = "" if cfg.manual_up else secrets.require((AUTH_FIELD,))[AUTH_FIELD]
    if not cfg.manual_up and (
        not credential
        or credential.lower() in {"changeme", "placeholder", "example"}
        or any(ord(c) < 32 for c in credential)
    ):
        raise DeployError("Tailscale non-manual deploy requires a non-placeholder auth key")
    data = json.dumps(cfg.model_dump(mode="json"))
    if not host.get_fact(Which, command="gpg"):
        apt.packages(
            name="Install missing native public-key validator", packages=["gnupg"], update=True, cache_time=3600
        )
    repo_url = f"{cfg.repo_base.rstrip('/')}/{cfg.channel}/{bound.repo_distro}"
    key_data = json.dumps({"url": f"{repo_url}/{bound.repo_release}.noarmor.gpg", "path": cfg.repo_keyring})
    key = repository_key(name="Refresh/validate public repository key; compare before write", data=key_data)
    # Preserve original key-before-apt ordering: a missing/damaged key must
    # be repaired before an ordinary apt refresh uses existing repo entries.
    apt.packages(name="Ensure original deb822 prerequisite", packages=["python3-debian"], update=True, cache_time=3600)
    old_repo = files.file(
        name="Remove original legacy one-line Tailscale repository",
        path=f"/etc/apt/sources.list.d/{cfg.repo_name}.list",
        present=False,
    )
    repo = files.put(
        name="Configure original deb822 Tailscale repository",
        src=StringIO(
            deb822_sources(
                name=cfg.repo_name,
                uris=repo_url,
                suites=(str(bound.repo_release),),
                components=(cfg.repo_component,),
                signed_by=cfg.repo_keyring,
            )
        ),
        dest=f"/etc/apt/sources.list.d/{cfg.repo_name}.sources",
        user="root",
        group="root",
        mode="0644",
    )
    apt.update(name="Refresh apt only after actual Tailscale repository changes", _if=any_changed(key, repo, old_repo))
    package = cfg.package_name if cfg.package_version == "latest" else f"{cfg.package_name}={cfg.package_version}"
    apt.packages(name="Ensure original Tailscale package present (latest does not upgrade)", packages=[package])
    systemd.service(
        name="Ensure original tailscaled requested enablement/start",
        service=cfg.service_name,
        running=True,
        enabled=cfg.enable_service,
    )
    preferences(name="Converge selected prefs after native service prerequisite", data=data)
    join(
        name="Join only non-Running, non-manual node via private stdin/file",
        data=data,
        credential=SecretStr(credential),
    )
    verify_probe(helper(HOST_SCRIPT, "verify"), name="Native Tailscale backend/preferences remain readable", stdin=data)
