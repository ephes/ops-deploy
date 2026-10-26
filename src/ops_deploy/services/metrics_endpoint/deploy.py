"""Mail metrics endpoint: exact role templates, ACLs, authentication and switch."""

from __future__ import annotations

import shlex
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

import jinja2
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator
from pyinfra.api import deploy
from pyinfra.operations import apt, files, server

from ops_deploy.core.config import ServiceName
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.systemd import service_rollout, systemd_unit
from ops_deploy.services import _metrics_httpd as httpd
from ops_deploy.services.metrics_endpoint.common import (
    EndpointConfig,
    Package,
    PlainPath,
    UrlPath,
    Word,
    account,
    bind_address,
    credentials,
    password,
    port_preflight,
)


class ProbeState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
    path: PlainPath

    @field_validator("name")
    @classmethod
    def _not_builtin(cls, value: str) -> str:
        if value in {"hostname", "timestamp", "mail", "disk", "services"}:
            raise ValueError("probe name must not shadow a built-in section")
        return value


class MetricsEndpointConfig(EndpointConfig):
    service_name: ServiceName = "metrics-endpoint"
    port: Annotated[StrictInt, Field(ge=1, le=65535)] = 9100
    path: UrlPath = "/.well-known/health"
    packages: tuple[Package, ...] = ("python3", "apache2-utils", "acl")
    script_path: PlainPath = PurePosixPath("/usr/local/bin/mail-metrics.sh")
    server_path: PlainPath = PurePosixPath("/usr/local/bin/metrics_httpd.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/metrics-endpoint")
    script_timeout: Annotated[StrictInt, Field(ge=1)] = 10
    vmail_path: PlainPath = PurePosixPath("/mnt/cryptdata/vmail")
    queue_path: PlainPath = PurePosixPath("/var/spool/postfix")
    services: tuple[Word, ...] = ("postfix", "dovecot", "rspamd")
    probe_states: tuple[ProbeState, ...] = ()


def role_vars(cfg: MetricsEndpointConfig, bind: str) -> dict[str, Any]:
    return {
        "metrics_endpoint_" + k: v
        for k, v in {
            "user": cfg.user,
            "group": cfg.group_name,
            "bind": bind,
            "port": cfg.port,
            "path": cfg.path,
            "script_path": str(cfg.script_path),
            "server_path": str(cfg.server_path),
            "script_timeout": cfg.script_timeout,
            "htpasswd_path": str(cfg.htpasswd_path),
            "vmail_path": str(cfg.vmail_path),
            "queue_path": str(cfg.queue_path),
            "services": list(cfg.services),
            "probe_states": [{"name": p.name, "path": str(p.path)} for p in cfg.probe_states],
        }.items()
    }


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.metrics_endpoint", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    return env


def render_role(template: str, cfg: MetricsEndpointConfig, bind: str) -> str:
    return environment().get_template(template).render(**role_vars(cfg, bind))


def httpd_endpoint(cfg: MetricsEndpointConfig, bind: str) -> httpd.Endpoint:
    return httpd.Endpoint(
        service_name=cfg.service_name,
        argv=(
            "script",
            "--bind",
            bind,
            "--port",
            str(cfg.port),
            "--path",
            cfg.path,
            "--script",
            str(cfg.script_path),
            "--script-timeout",
            str(cfg.script_timeout),
            "--htpasswd-file",
            str(cfg.htpasswd_path),
            "--realm",
            "metrics",
            "--server-name",
            "metrics-httpd/0.1",
        ),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes"),
        python_script=str(cfg.server_path),
        probe_bind=bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm="metrics",
        ip_address_allow=("localhost", "100.64.0.0/10"),
    )


def queue_acl(cfg: MetricsEndpointConfig) -> None:
    script = (Path(__file__).parent / "files" / "queue_acl.py").read_text()
    for name in ("active", "deferred"):
        path = str(cfg.queue_path / name)
        test = shlex.join(["python3", "-I", "-c", script, path, cfg.user])
        state = probe(test, name=f"Postfix queue ACL {name}")
        if state == "changed=false":
            continue
        command = shlex.join(["setfacl", "-m", f"user:{cfg.user}:rX", "--recursive", path])
        server.shell(
            name=f"Allow metrics user to read Postfix {name} queue",
            commands=[shlex.join(["sh", "-c", f"if test -e {shlex.quote(path)}; then {command}; fi"])],
        )


@deploy("Deploy mail metrics endpoint")
def deploy_metrics_endpoint(cfg: MetricsEndpointConfig, secrets: SecretValues) -> None:
    value = password(secrets)
    bind = bind_address(cfg)
    port_preflight(cfg, bind)
    apt.packages(name="Install mail metrics endpoint packages", packages=list(cfg.packages))
    account(cfg)
    queue_acl(cfg)
    script = files.put(
        name=f"Install {cfg.script_path}",
        src=StringIO(render_role("mail-metrics.sh.j2", cfg, bind)),
        dest=str(cfg.script_path),
        user="root",
        group="root",
        mode="0755",
    )
    wrapper = files.put(
        name=f"Install {cfg.server_path}",
        src=StringIO(render_role("metrics_httpd.py.j2", cfg, bind)),
        dest=str(cfg.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    auth = credentials(cfg, value)
    unit = systemd_unit(cfg.service_name, render_role("metrics-endpoint.service.j2", cfg, bind))
    selection = httpd.select(httpd_endpoint(cfg, bind), cfg)
    service_rollout(cfg.service_name, units=[unit, selection.dropin], restart_when=[script, wrapper, *auth])
    httpd.verify(selection)
