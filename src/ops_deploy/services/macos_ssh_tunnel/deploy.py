"""Local owner-session tunnel and optional original forwarding authorization."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from importlib.resources import files
from typing import Any

import jinja2
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.helpers import mark_read_only

from .config import MacosSshTunnelConfig

PACKAGE = "ops_deploy.services.macos_ssh_tunnel"


def payload(cfg: MacosSshTunnelConfig) -> dict[str, Any]:
    data = cfg.model_dump(mode="json")
    values = {"macos_ssh_tunnel_" + name: value for name, value in data.items()}
    values["macos_ssh_tunnel_ca_file"] = str(cfg.ca_file) if cfg.ca_file else ""
    environment = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    ssh_config = environment.get_template("ssh_config.j2").render(values)
    if cfg.ssh_port != 22:
        ssh_config += f"    Port {cfg.ssh_port}\n"
    assert cfg.directory is not None
    health = {
        "label": cfg.label,
        "plist": str(cfg.plist),
        "stderr_log": str(cfg.log_directory / "stderr.log") if cfg.log_directory else "",
        "local_port": cfg.local_port,
        "https_host": cfg.target,
        "ignore_ssl_errors": cfg.ignore_ssl_errors,
        "ca_file": str(cfg.ca_file) if cfg.ca_file else "",
        "health_path": cfg.health_path,
        "health_status": cfg.health_status,
    }
    data["contents"] = {
        str(cfg.plist): environment.get_template("launchagent.plist.j2").render(values),
        str(cfg.directory / "ssh_config"): ssh_config,
        str(cfg.directory / "config.json"): json.dumps(health, indent=4, sort_keys=True) + "\n",
        str(cfg.directory / "tunnel_control.py"): files(PACKAGE).joinpath("files/tunnel_control.py").read_text(),
    }
    return data


def host_command(cfg: MacosSshTunnelConfig, action: str) -> str:
    data = payload(cfg)
    data["relay_script"] = files(PACKAGE).joinpath("files/relay_authorization_host.py").read_text()
    data["hashes"] = {path: hashlib.sha256(value.encode()).hexdigest() for path, value in data["contents"].items()}
    probe = files(PACKAGE).joinpath("identity.py").read_text()
    mutation = files(PACKAGE).joinpath("files/forwarding_identity_host.py").read_text()
    script = files(PACKAGE).joinpath("files/macos_ssh_tunnel_host.py").read_text()
    # All embedded texts/configuration are public deployment resources. The
    # private identity is opened only on its owning local machine, never sent.
    launcher = (
        "import base64,sys,types;m=types.ModuleType('ops_forwarding_identity');"
        "sys.modules[m.__name__]=m;ns=m.__dict__;exec(compile(base64.b64decode('"
        + base64.b64encode(mutation.encode()).decode()
        + "'),'<forwarding-identity>','exec'),ns);p=types.ModuleType('ops_identity_probe');"
        "sys.modules[p.__name__]=p;probe_ns=p.__dict__;exec(compile(base64.b64decode('"
        + base64.b64encode(probe.encode()).decode()
        + "'),'<identity-probe>','exec'),probe_ns);exec(compile(base64.b64decode('"
        + base64.b64encode(script.encode()).decode()
        + "'),'<macos-ssh-tunnel>','exec'))"
    )
    return shlex.join(
        ["/usr/bin/python3", "-B", "-c", launcher, action, base64.b64encode(json.dumps(data).encode()).decode()]
    )


@deploy("Deploy owner-session macOS SSH tunnel stopped")
def deploy_macos_ssh_tunnel(cfg: MacosSshTunnelConfig) -> None:
    if host.get_fact(Command, command=host_command(cfg, "status")) != "current":
        server.shell(
            name="Converge forwarding identity, original relay authorization and stopped tunnel",
            commands=[host_command(cfg, "apply")],
        )
    mark_read_only(
        server.shell(
            name="Verify owner-session tunnel remains installed stopped", commands=[host_command(cfg, "verify")]
        )
    )
