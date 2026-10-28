"""Pinned MinIO service and check-before-write IAM convergence."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections.abc import Generator
from importlib.resources import files as resources
from io import StringIO
from pathlib import Path, PurePosixPath

from pydantic import SecretStr
from pyinfra import host, state
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, Sha256File
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import BasicAuth, TraefikRoute, mark_read_only, traefik_route, wait_port
from ops_deploy.helpers.probes import StdinLines, probe, stdin_arguments
from ops_deploy.helpers.systemd import service_rollout
from ops_deploy.ops.secret_file import secret_file
from ops_deploy.services.minio.config import (
    MC_DOWNLOAD_URL,
    MC_SHA256,
    MINIO_SHA256,
    MINIO_VERSION,
    MinioConfig,
    MinioCredentials,
)
from ops_deploy.services.minio.render import render

RESOURCE = resources("ops_deploy.services.minio")


def host_command(script: str, action: str | None = None) -> str:
    if script not in ("iam_host", "data_roots") or action not in (
        None,
        "check",
        "apply",
        "inspect-current",
        "recovery",
    ):
        raise ValueError("unknown MinIO host helper/action")
    source = base64.b64encode(RESOURCE.joinpath(f"files/{script}.py").read_bytes()).decode()
    loader = f"import base64;exec(compile(base64.b64decode('{source}'),'<minio-host>','exec'))"
    return shlex.join(["python3", "-I", "-B", "-c", loader, *([action] if action else [])])


def validate_inputs(cfg: MinioConfig, credentials: MinioCredentials) -> None:
    if {identity.name for identity in cfg.identities} != credentials.identities.keys():
        raise ValueError("provide credentials for exactly the declared MinIO identities")
    accesses = [value.access.get_secret_value() for value in credentials.identities.values()]
    if len(accesses) != len(set(accesses)) or credentials.root_user.get_secret_value() in accesses:
        raise ValueError("managed MinIO identities must be distinct from each other and root")
    if cfg.tls_enable and not (credentials.tls_cert_content and credentials.tls_key_content):
        raise ValueError("TLS requires certificate and key content")
    if cfg.sse_enabled and not credentials.sse_master_key:
        raise ValueError("SSE requires its configured key")
    if cfg.expose_via_traefik and (
        cfg.traefik_host == "minio.home.example.com" or cfg.traefik_api_host == "s3.minio.home.example.com"
    ):
        raise ValueError("Traefik exposure requires configured console and API hostnames")
    if cfg.expose_via_traefik and cfg.console_basic_auth_enabled:
        password = credentials.console_basic_auth_password
        if password is None or password.get_secret_value() == "CHANGEME":
            raise ValueError("console authentication requires its configured password")
        BasicAuth(user=cfg.console_basic_auth_user, password=password)
    for path, expected in ((cfg.local_minio_binary, MINIO_SHA256), (cfg.local_mc_binary, MC_SHA256)):
        if path is not None and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("local MinIO fixture artifact differs from the pinned checksum")


def iam_payload(cfg: MinioConfig, credentials: MinioCredentials) -> str:
    identities = []
    root = credentials.root_password.get_secret_value()
    for identity in cfg.identities:
        material = credentials.identities[identity.name]
        value = material.secret.get_secret_value()
        identities.append(
            {
                **identity.model_dump(mode="json"),
                "access": material.access.get_secret_value(),
                "secret": value,
            }
        )
    names = [identity.name for identity in cfg.identities]
    return json.dumps(
        {
            "mc": cfg.mc_bin_path,
            "alias": cfg.host_alias,
            "endpoint": f"http{'s' if cfg.tls_enable else ''}://{cfg.bind_host}:{cfg.api_port}",
            "root_user": credentials.root_user.get_secret_value(),
            "root_password": root,
            "recovery": {
                "env_file": cfg.env_file,
                "service_unit": cfg.service_unit,
                "bin_path": cfg.bin_path,
                "minio_sha256": MINIO_SHA256,
                "mc_sha256": MC_SHA256,
                "unit": render("minio.service.j2", cfg, credentials),
                "environment": render("minio.env.j2", cfg, credentials),
            },
            "shared_config": cfg.mc_config_dir,
            "buckets": [bucket.model_dump(mode="json") for bucket in cfg.buckets],
            "policies": [policy.model_dump(mode="json", exclude={"content"}) for policy in cfg.policies],
            "identities": identities,
            "superseded": [{"name": old.name, "identity": names.index(old.identity)} for old in cfg.superseded],
        }
    )


def iam_pending(payload: str, *, current: bool = False) -> int:
    action = "inspect-current" if current else "check"
    output = probe(host_command("iam_host", action), stdin=payload, name="MinIO owned IAM inspection")
    if output is None:
        raise DeployError("MinIO IAM inspection failed; refusing writes after an unknown response")
    try:
        result = json.loads(output)
        if set(result) != {"pending", "changed"} or type(result["pending"]) is not int or result["pending"] < 0:
            raise ValueError
        if result["changed"] is not False:
            raise ValueError
        return int(result["pending"])
    except (ValueError, KeyError, TypeError):
        raise DeployError("MinIO IAM inspection returned an invalid result; refusing writes") from None


@operation()
def converge_iam(payload: SecretStr, deferred: bool) -> Generator[StringCommand, None, None]:
    """Inspect at execution after prerequisites; never call an empty apply a change."""
    raw = payload.get_secret_value()
    if (deferred and not state.is_executing) or iam_pending(raw, current=not state.is_executing):
        yield StringCommand(host_command("iam_host", "apply"), _stdin=StdinLines(raw), _get_pty=False)


def recovery(payload: str) -> tuple[bool, bool]:
    output = probe(host_command("iam_host", "recovery"), stdin=payload, name="MinIO local recovery prerequisites")
    try:
        result = json.loads(output or "")
        if set(result) != {"recover_client", "recover_service"} or any(
            type(value) is not bool for value in result.values()
        ):
            raise ValueError
        return result["recover_client"], result["recover_service"]
    except (ValueError, TypeError):
        raise DeployError("MinIO recovery identity is unknown; refusing writes") from None


def binary(path: str, local: Path | None, checksum: str, url: str, title: str) -> OperationMeta:
    if host.get_fact(Sha256File, path=path) == checksum:
        return files.file(name=f"Preserve pinned {title} executable", path=path, user="root", group="root", mode="0755")
    if local is not None:
        return files.put(
            name=f"Install verified {title} artifact", src=str(local), dest=path, user="root", group="root", mode="0755"
        )
    return server.shell(name=f"Download pinned {title}", commands=[binary_install_command(path, checksum, url)])


def binary_install_command(path: str, checksum: str, url: str) -> str:
    """Verify in a private temporary directory before replacing an executable."""
    parent = shlex.quote(str(PurePosixPath(path).parent / ".minio-artifact.XXXXXX"))
    script = (
        f"set -eu; umask 077; tmp=$(mktemp -d {parent}); "
        "trap 'rm -rf \"$tmp\"' EXIT; "
        f'curl -fsSL --max-time 120 -o "$tmp/download" {shlex.quote(url)}; '
        f"printf '%s  %s\\n' {shlex.quote(checksum)} \"$tmp/download\" | sha256sum -c --status -; "
        'install -o root -g root -m 0755 "$tmp/download" "$tmp/binary"; '
        f'mv -f "$tmp/binary" {shlex.quote(path)}'
    )
    return shlex.join(["sh", "-c", script])


def port_preflight(port: int) -> OperationMeta:
    """Original private play's loopback ports: only minio.service may own them."""
    script = (
        f"out=$(ss -Hltnp 'sport = :{port}') || exit 1; "
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        'case "${local%:*}" in 127.0.0.1|0.0.0.0|"[::1]"|"[::]"|"*"|"[::ffff:127.0.0.1]") ;; *) continue ;; esac; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        "grep -qx '0::/system.slice/minio.service' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        'done; [ "$bad" = 0 ]; }'
    )
    return mark_read_only(
        server.shell(name=f"MinIO port preflight tcp/{port}", commands=[shlex.join(["sh", "-c", script])])
    )


def put(path: str, text: str, mode: str = "0644") -> OperationMeta:
    return files.put(name=f"Write {path}", src=StringIO(text), dest=path, user="root", group="root", mode=mode)


@deploy("Deploy MinIO")
def deploy_minio(cfg: MinioConfig, credentials: MinioCredentials) -> None:
    validate_inputs(cfg, credentials)
    require_linux("minio")
    require_systemd("minio")
    ownership = json.dumps({"roots": cfg.data_dirs, "user": cfg.user, "group": cfg.group})
    data_state = probe(host_command("data_roots"), stdin=ownership, name="MinIO descendant ownership")
    if data_state not in ("current", "empty"):
        raise DeployError("MinIO data ownership admission failed; no recursive repair is permitted")
    # Existing installations inspect with protected current credentials. Known
    # missing-client/inactive-unit prerequisites are explicit managed recovery;
    # their later IAM refusal must retain the actual partial-change receipt.
    fresh = (
        host.get_fact(File, path=cfg.service_unit) is None
        and host.get_fact(File, path=cfg.env_file) is None
        and data_state == "empty"
    )
    payload = iam_payload(cfg, credentials)
    recover_client = recover_service = False
    if cfg.bootstrap_with_mc and not fresh:
        recover_client, recover_service = recovery(payload)
        if not (recover_client or recover_service):
            iam_pending(payload, current=True)

    for port in (cfg.api_port, cfg.console_port):
        port_preflight(port)

    if recover_client:
        binary(
            cfg.mc_bin_path,
            cfg.local_mc_binary,
            MC_SHA256,
            MC_DOWNLOAD_URL,
            "MinIO recovery client",
        )
    if recover_service:
        systemd.service(
            name="Recover known inactive MinIO using existing configuration", service="minio.service", running=True
        )
        for port in (cfg.api_port, cfg.console_port):
            wait_port(
                port,
                host=cfg.bind_host,
                retries=cfg.healthcheck_timeout,
                delay=1,
                name=f"Wait for recovered MinIO port {port}",
            )
    if recover_client or recover_service:
        mark_read_only(
            server.shell(
                name="Admit owned IAM after managed recovery prerequisites",
                commands=[host_command("iam_host", "inspect-current")],
                **stdin_arguments(payload),
            )
        )

    server.group(name="Ensure MinIO group", group=cfg.group, system=True)
    server.user(
        name="Ensure MinIO user",
        user=cfg.user,
        group=cfg.group,
        home=cfg.home,
        shell="/usr/sbin/nologin",
        system=True,
        create_home=True,
    )
    files.directory(
        name="Ensure MinIO configuration directory", path=cfg.config_dir, user="root", group="root", mode="0755"
    )
    for directory in cfg.data_dirs:
        files.directory(
            name=f"Ensure MinIO data root {directory}", path=directory, user=cfg.user, group=cfg.group, mode="0750"
        )
    minio_binary = binary(
        cfg.bin_path,
        cfg.local_minio_binary,
        MINIO_SHA256,
        f"https://dl.min.io/server/minio/hotfixes/linux-amd64/archive/archive/minio.{MINIO_VERSION}",
        "MinIO",
    )
    triggers = [minio_binary]
    if cfg.tls_enable:
        files.directory(
            name="Ensure MinIO certificate directory", path=cfg.certs_dir, user=cfg.user, group=cfg.group, mode="0750"
        )
        assert credentials.tls_cert_content is not None
        assert credentials.tls_key_content is not None
        for filename, value in (
            ("public.crt", credentials.tls_cert_content),
            ("private.key", credentials.tls_key_content),
        ):
            triggers.append(
                secret_file(
                    name=f"Write MinIO {filename}",
                    path=PurePosixPath(cfg.certs_dir) / filename,
                    content=SecretContent(value.get_secret_value()),
                    user=cfg.user,
                    group=cfg.group,
                    mode="0644" if filename == "public.crt" else "0600",
                )
            )
    triggers.append(
        secret_file(
            name="Write MinIO environment",
            path=PurePosixPath(cfg.env_file),
            content=SecretContent(render("minio.env.j2", cfg, credentials)),
            user="root",
            group="root",
            mode="0600",
        )
    )
    unit = put(cfg.service_unit, render("minio.service.j2", cfg, credentials))
    service_rollout("minio", units=[unit], restart_when=triggers)
    for port in (cfg.api_port, cfg.console_port):
        wait_port(
            port, host=cfg.bind_host, retries=cfg.healthcheck_timeout, delay=1, name=f"Wait for MinIO port {port}"
        )

    if cfg.expose_via_traefik:
        auth = None
        if cfg.console_basic_auth_enabled:
            assert credentials.console_basic_auth_password is not None
            auth = BasicAuth(user=cfg.console_basic_auth_user, password=credentials.console_basic_auth_password)
            apt.packages(name="Ensure MinIO console auth tooling", packages=["apache2-utils"])
        route = TraefikRoute(
            name="minio",
            host=cfg.traefik_host,
            app_port=cfg.console_port,
            basic_auth=auth,
            internal_ip_ranges=cfg.internal_ip_ranges,
            cert_resolver=cfg.traefik_cert_resolver,
        )
        traefik_route(
            route,
            renderer=lambda route, auth_hash: render("traefik-minio.yml.j2", cfg, credentials, auth_hash or ""),
            restart="none",
        )

    if cfg.bootstrap_with_mc:
        if not recover_client:
            binary(
                cfg.mc_bin_path,
                cfg.local_mc_binary,
                MC_SHA256,
                MC_DOWNLOAD_URL,
                "MinIO client",
            )
        files.directory(
            name="Ensure MinIO policy directory", path=cfg.policy_dir, user="root", group="root", mode="0750"
        )
        for policy in cfg.policies:
            put(f"{cfg.policy_dir}/{policy.name}.json", policy.file_content, mode="0640")
        converge_iam(
            name="Converge declared MinIO IAM and bucket configuration",
            payload=SecretStr(payload),
            deferred=fresh or recover_client or recover_service,
        )
        # Superseded files are removed only after the helper has proved the
        # replacement attached and obsolete server policy absent.
        for old in cfg.superseded:
            files.file(
                name="Remove superseded MinIO policy file", path=f"{cfg.policy_dir}/{old.name}.json", present=False
            )
        checker = host_command("iam_host", "check")
        verify = "import json,sys; x=json.load(sys.stdin); sys.exit(0 if x=={'pending':0,'changed':False} else 1)"
        # No shell pipeline: preserve failure of the helper itself.
        script = f"out=$( {checker} ) || exit 1; printf '%s' \"$out\" | python3 -I -c {shlex.quote(verify)}"
        mark_read_only(
            server.shell(
                name="Verify declared MinIO IAM configuration",
                commands=[shlex.join(["sh", "-c", script])],
                **stdin_arguments(payload),
            )
        )
    health = f"http{'s' if cfg.tls_enable else ''}://{cfg.bind_host}:{cfg.api_port}/minio/health/live"
    # Ansible role validate_certs:false is preserved here (TLS is normally off).
    command = f"curl -kfsS --max-time {cfg.healthcheck_timeout} -o /dev/null {shlex.quote(health)}"
    mark_read_only(server.shell(name="Verify MinIO health", commands=[command], _retries=3, _retry_delay=5))
