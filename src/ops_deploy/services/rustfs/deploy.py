"""Pinned RustFS service with check-before-write bucket/IAM convergence."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections.abc import Generator
from functools import cache
from importlib.resources import files as resources
from io import StringIO
from pathlib import PurePosixPath
from typing import Any

import jinja2
from pydantic import SecretStr
from pyinfra import host, state
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, Sha256File
from pyinfra.facts.server import Arch
from pyinfra.operations import files, server

from ops_deploy.base._common import ensure_curl, require_linux, require_systemd
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import TraefikRoute, http_check, mark_read_only, traefik_route, wait_port
from ops_deploy.helpers.probes import StdinLines, probe, stdin_arguments
from ops_deploy.helpers.systemd import service_rollout, systemd_unit
from ops_deploy.ops.secret_file import secret_file
from ops_deploy.services.rustfs.config import (
    BINARY_SHA256,
    RUSTFS_ARTIFACTS,
    RustfsArtifact,
    RustfsConfig,
    RustfsCredentials,
)

RESOURCE = resources("ops_deploy.services.rustfs")


@cache
def environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.rustfs", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(template: str, cfg: RustfsConfig, credentials: RustfsCredentials | None = None) -> str:
    values: dict[str, Any] = {"cfg": cfg}
    if credentials is not None:
        values.update(
            root_access=credentials.root.access.get_secret_value(),
            root_secret=credentials.root.secret.get_secret_value(),
        )
        if credentials.monitor is not None:
            values.update(
                monitor_access=credentials.monitor.access.get_secret_value(),
                monitor_secret=credentials.monitor.secret.get_secret_value(),
            )
    return environment().get_template(template).render(**values)


def host_command(script: str, action: str | None = None) -> str:
    if (script, action) not in (("data_roots", None), ("iam_host", "check"), ("iam_host", "apply")):
        raise ValueError("unknown RustFS host helper/action")
    source = base64.b64encode(RESOURCE.joinpath(f"files/{script}.py").read_bytes()).decode()
    loader = f"import base64;exec(compile(base64.b64decode('{source}'),'<rustfs-host>','exec'))"
    return shlex.join(["python3", "-I", "-B", "-c", loader, *([action] if action else [])])


def iam_client_command(program: bytes, *args: str) -> str:
    """Runs ``program`` on the host with ``files/iam_host.py`` loaded as its library.

    The program finds the helper's names (``Api``, ``Server``, ``Refused``,
    ``ADMIN``, ...) in its globals, so other deploys that talk to RustFS's
    admin API reuse its SigV4 client instead of carrying their own. The
    helper's own ``main`` does not run.
    """
    library = base64.b64encode(RESOURCE.joinpath("files/iam_host.py").read_bytes()).decode()
    source = base64.b64encode(program).decode()
    loader = (
        "import base64;g={'__name__':'rustfs_iam_host'};"
        f"exec(compile(base64.b64decode('{library}'),'<rustfs-host>','exec'),g);"
        "g['__name__']='__main__';"
        f"exec(compile(base64.b64decode('{source}'),'<rustfs-client>','exec'),g)"
    )
    return shlex.join(["python3", "-I", "-B", "-c", loader, *args])


def validate_inputs(cfg: RustfsConfig, credentials: RustfsCredentials) -> None:
    if {identity.name for identity in cfg.identities} != credentials.identities.keys():
        raise ValueError("provide credentials for exactly the declared RustFS identities")
    accesses = [value.access.get_secret_value() for value in credentials.identities.values()]
    if len(accesses) != len(set(accesses)) or credentials.root.access.get_secret_value() in accesses:
        raise ValueError("managed RustFS identities must be distinct from each other and root")
    if cfg.expose_via_traefik and cfg.traefik_api_host == "s3.rustfs.home.example.com":
        raise ValueError("Traefik exposure requires a configured API hostname")
    if cfg.local_binary is not None and hashlib.sha256(cfg.local_binary.read_bytes()).hexdigest() not in BINARY_SHA256:
        raise ValueError("local RustFS executable differs from every pinned binary checksum")
    if bool(cfg.replications) != (credentials.replication is not None):
        raise ValueError("provide replication credentials exactly when replications are declared")
    if (cfg.monitor is not None) != (credentials.monitor is not None):
        raise ValueError("provide monitor credentials exactly when the replication monitor is declared")


def iam_payload(cfg: RustfsConfig, credentials: RustfsCredentials) -> str:
    identities = []
    for identity in cfg.identities:
        material = credentials.identities[identity.name]
        identities.append(
            {
                **identity.model_dump(mode="json"),
                "access": material.access.get_secret_value(),
                "secret": material.secret.get_secret_value(),
            }
        )
    replication = None
    if credentials.replication is not None:
        replication = {
            "access": credentials.replication.access.get_secret_value(),
            "secret": credentials.replication.secret.get_secret_value(),
        }
    return json.dumps(
        {
            "endpoint": cfg.endpoint,
            "region": cfg.region,
            "root_access": credentials.root.access.get_secret_value(),
            "root_secret": credentials.root.secret.get_secret_value(),
            "buckets": [bucket.model_dump(mode="json") for bucket in cfg.buckets],
            "policies": [policy.model_dump(mode="json") for policy in cfg.policies],
            "identities": identities,
            "replications": [item.model_dump(mode="json") for item in cfg.replications],
            "replication": replication,
        }
    )


def iam_pending(payload: str) -> int:
    output = probe(host_command("iam_host", "check"), stdin=payload, name="RustFS declared IAM inspection")
    try:
        result = json.loads(output or "")
        if set(result) != {"pending", "changed"} or type(result["pending"]) is not int or result["pending"] < 0:
            raise ValueError
        if result["changed"] is not False:
            raise ValueError
        return int(result["pending"])
    except (ValueError, TypeError):
        raise DeployError("RustFS IAM inspection failed; refusing writes after an unknown response") from None


@operation()
def converge_iam(payload: SecretStr, deferred: bool) -> Generator[StringCommand, None, None]:
    """Inspect while planning, or at execution when this run changes the server first.

    pyinfra calls the generator again while executing; a deferred inspection
    then runs against the restarted server, so an empty apply is no change.
    """
    raw = payload.get_secret_value()
    if (deferred and not state.is_executing) or iam_pending(raw):
        yield StringCommand(host_command("iam_host", "apply"), _stdin=StdinLines(raw), _get_pty=False)


def monitor_jobs(cfg: RustfsConfig) -> str:
    """The jobs file the monitor script reads; no credentials."""
    assert cfg.monitor is not None
    rows = [{**job.model_dump(mode="json"), "heartbeat_bucket": job.heartbeat_bucket} for job in cfg.monitor.jobs]
    return json.dumps(rows, indent=2, sort_keys=True) + "\n"


def deploy_monitor(cfg: RustfsConfig, credentials: RustfsCredentials) -> None:
    """Install the heartbeat writer or lag probe and its timer; it never runs here."""
    monitor = cfg.monitor
    assert monitor is not None
    files.directory(
        name="Ensure RustFS replication monitor library", path=monitor.library_dir, user="root", group="root",
        mode="0755",
    )  # fmt: skip
    sources = (
        ("files/iam_host.py", f"{monitor.library_dir}/rustfs_iam_host.py", "0644"),
        ("files/replication_monitor.py", monitor.script_path, "0755"),
    )
    for source, dest, mode in sources:
        files.put(
            name=f"Install {dest}",
            src=StringIO(RESOURCE.joinpath(source).read_text()),
            dest=dest,
            user="root",
            group="root",
            mode=mode,
        )
    files.put(
        name="Write RustFS replication monitor jobs",
        src=StringIO(monitor_jobs(cfg)),
        dest=monitor.jobs_path,
        user="root",
        group="root",
        mode="0644",
    )
    secret_file(
        name="Write RustFS replication monitor environment",
        path=PurePosixPath(monitor.env_file),
        content=SecretContent(render("rustfs-replication-monitor.env.j2", cfg, credentials)),
        user="root",
        group="root",
        mode="0600",
    )
    if monitor.role == "replica":
        files.directory(
            name="Ensure RustFS replication monitor state", path=monitor.state_root, user="root", group="root",
            mode="0755",
        )  # fmt: skip
    unit = systemd_unit(monitor.unit, render("rustfs-replication-monitor.service.j2", cfg))
    timer = systemd_unit(f"{monitor.unit}.timer", render("rustfs-replication-monitor.timer.j2", cfg))
    service_rollout(f"{monitor.unit}.timer", units=[unit, timer])


def artifact_for_host() -> RustfsArtifact:
    arch = host.get_fact(Arch)
    if arch not in RUSTFS_ARTIFACTS:
        raise DeployError(f"RustFS has no pinned release artifact for {arch!r}")
    return RUSTFS_ARTIFACTS[arch]


def binary_install_command(path: str, artifact: RustfsArtifact) -> str:
    """Download, verify archive and member in a private directory, then rename into place."""
    parent = shlex.quote(str(PurePosixPath(path).parent / ".rustfs-artifact.XXXXXX"))
    extract = (
        "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); "
        "assert z.namelist()==['rustfs']; open(sys.argv[2],'wb').write(z.read('rustfs'))"
    )
    script = (
        f"set -eu; umask 077; tmp=$(mktemp -d {parent}); "
        "trap 'rm -rf \"$tmp\"' EXIT; "
        f'curl -fsSL --max-time 300 -o "$tmp/archive.zip" {shlex.quote(artifact.url)}; '
        f"printf '%s  %s\\n' {artifact.archive_sha256} \"$tmp/archive.zip\" | sha256sum -c --status -; "
        f'python3 -I -c {shlex.quote(extract)} "$tmp/archive.zip" "$tmp/extracted"; '
        f"printf '%s  %s\\n' {artifact.binary_sha256} \"$tmp/extracted\" | sha256sum -c --status -; "
        'install -o root -g root -m 0755 "$tmp/extracted" "$tmp/binary"; '
        f'mv -f "$tmp/binary" {shlex.quote(path)}'
    )
    return shlex.join(["sh", "-c", script])


def binary(cfg: RustfsConfig, artifact: RustfsArtifact) -> OperationMeta:
    if host.get_fact(Sha256File, path=cfg.bin_path) == artifact.binary_sha256:
        return files.file(
            name="Preserve pinned RustFS executable", path=cfg.bin_path, user="root", group="root", mode="0755"
        )
    if cfg.local_binary is not None:
        if hashlib.sha256(cfg.local_binary.read_bytes()).hexdigest() != artifact.binary_sha256:
            raise DeployError("local RustFS executable is not the pinned binary for this host's architecture")
        # Stage beside the destination and rename: overwriting a running executable fails (ETXTBSY).
        staged = cfg.bin_path + ".ops-deploy-new"
        files.put(
            name="Stage verified RustFS executable",
            src=str(cfg.local_binary),
            dest=staged,
            user="root",
            group="root",
            mode="0755",
        )
        return server.shell(
            name="Install verified RustFS executable",
            commands=[shlex.join(["mv", "-f", staged, cfg.bin_path])],
        )
    ensure_curl("rustfs")
    return server.shell(name="Download pinned RustFS", commands=[binary_install_command(cfg.bin_path, artifact)])


def port_preflight(port: int) -> OperationMeta:
    """The loopback API port is free or held only by rustfs.service."""
    script = (
        f"out=$(ss -Hltnp 'sport = :{port}') || exit 1; "
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        '[ -n "$local" ] || continue; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        "grep -qx '0::/system.slice/rustfs.service' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        'done; [ "$bad" = 0 ]; }'
    )
    return mark_read_only(
        server.shell(name=f"RustFS port preflight tcp/{port}", commands=[shlex.join(["sh", "-c", script])])
    )


def intermediate_directories(cfg: RustfsConfig) -> list[str]:
    mount = PurePosixPath(cfg.required_mount)
    data = PurePosixPath(cfg.data_dir)
    return [str(path) for path in reversed(data.parents) if mount in path.parents]


@deploy("Deploy RustFS")
def deploy_rustfs(cfg: RustfsConfig, credentials: RustfsCredentials) -> None:
    validate_inputs(cfg, credentials)
    require_linux("rustfs")
    require_systemd("rustfs")
    artifact = artifact_for_host()
    admission = json.dumps({"root": cfg.data_dir, "mount": cfg.required_mount, "user": cfg.user, "group": cfg.group})
    data_state = probe(host_command("data_roots"), stdin=admission, name="RustFS data root admission")
    if data_state is None or data_state.strip() not in ("current", "empty"):
        raise DeployError("RustFS data root admission failed (mount absent or foreign data); nothing changed")
    fresh = host.get_fact(File, path=cfg.service_unit) is None
    port_preflight(cfg.api_port)

    server.group(name="Ensure RustFS group", group=cfg.group, system=True)
    server.user(
        name="Ensure RustFS user",
        user=cfg.user,
        group=cfg.group,
        home=cfg.home,
        shell="/usr/sbin/nologin",
        system=True,
        create_home=False,
    )
    files.directory(name="Ensure RustFS home", path=cfg.home, user=cfg.user, group=cfg.group, mode="0750")
    for directory in intermediate_directories(cfg):
        files.directory(
            name=f"Ensure RustFS data parent {directory}", path=directory, user="root", group="root", mode="0755"
        )
    files.directory(name="Ensure RustFS data root", path=cfg.data_dir, user=cfg.user, group=cfg.group, mode="0750")

    triggers = [binary(cfg, artifact)]
    triggers.append(
        secret_file(
            name="Write RustFS environment",
            path=PurePosixPath(cfg.env_file),
            content=SecretContent(render("rustfs.env.j2", cfg, credentials)),
            user="root",
            group="root",
            mode="0600",
        )
    )
    unit = files.put(
        name=f"Write {cfg.service_unit}",
        src=StringIO(render("rustfs.service.j2", cfg)),
        dest=cfg.service_unit,
        user="root",
        group="root",
        mode="0644",
    )
    rollout = service_rollout("rustfs", units=[unit], restart_when=triggers)
    wait_port(cfg.api_port, host=cfg.bind_host, retries=cfg.healthcheck_timeout, delay=1, name="Wait for RustFS API")
    http_check(
        f"{cfg.endpoint}/health/ready",
        retries=cfg.healthcheck_timeout,
        delay=1,
        name="Verify RustFS readiness",
    )

    if cfg.expose_via_traefik:
        route = TraefikRoute(
            name="rustfs",
            host=cfg.traefik_api_host,
            app_port=cfg.api_port,
            internal_ip_ranges=cfg.internal_ip_ranges,
            internal_only=True,
            cert_resolver=cfg.traefik_cert_resolver,
        )
        traefik_route(route, renderer=lambda route, auth_hash: render("traefik-rustfs.yml.j2", cfg), restart="none")

    if cfg.buckets or cfg.policies or cfg.identities or cfg.replications:
        payload = iam_payload(cfg, credentials)
        # Inspect after execution starts whenever this run changes or starts the server.
        deferred = fresh or any(op.will_change for op in (*triggers, unit, rollout.start))
        converge_iam(
            name="Converge declared RustFS buckets and IAM",
            payload=SecretStr(payload),
            deferred=deferred,
        )
        checker = host_command("iam_host", "check")
        verify = "import json,sys; x=json.load(sys.stdin); sys.exit(0 if x=={'pending':0,'changed':False} else 1)"
        script = f"out=$( {checker} ) || exit 1; printf '%s' \"$out\" | python3 -I -c {shlex.quote(verify)}"
        mark_read_only(
            server.shell(
                name="Verify declared RustFS buckets and IAM",
                commands=[shlex.join(["sh", "-c", script])],
                **stdin_arguments(payload),
            )
        )

    if cfg.monitor is not None:
        deploy_monitor(cfg, credentials)
