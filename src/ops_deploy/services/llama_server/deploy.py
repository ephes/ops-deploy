"""Native pinned detector; current running models and processes are retained."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from importlib.resources import files
from typing import Any

import jinja2
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin

from .config import LlamaServerConfig

PACKAGE = "ops_deploy.services.llama_server"


def payload(cfg: LlamaServerConfig, secrets: Mapping[str, str]) -> dict[str, Any]:
    data = cfg.model_dump(mode="json", exclude={"wrapper_source"})
    if not cfg.enabled:
        return data
    key = secrets.get("api_key", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{32,}", key) or key == "CHANGEME":
        raise ValueError("detector API key is missing or has an invalid format")
    assert cfg.wrapper_source is not None
    try:
        wrapper = cfg.wrapper_source.read_text()
    except (OSError, UnicodeError):
        raise ValueError("detector controller wrapper is unavailable") from None
    if f'GGUF_SHA256="{cfg.model_sha256}"' not in wrapper or any(
        flag not in wrapper for flag in ("--api-key-file", "--no-slots", "--cache-ram 0")
    ):
        raise ValueError("detector wrapper must carry the configured model pin and private runtime flags")
    values = {"llama_server_" + k: v for k, v in data.items()}
    values.update(
        llama_server_service_user=cfg.user,
        llama_server_service_group=cfg.group,
        llama_server_service_home=str(cfg.home),
        llama_server_bin=str(cfg.binary),
        llama_server_gguf_file=cfg.model_file,
        llama_server_bind_address="__LLAMA_BIND_ADDRESS__",
    )
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=True,
    )
    plist = env.get_template("llama-server.launchd.plist.j2").render(values)
    data["contents"] = {
        str(cfg.wrapper_path): wrapper,
        str(cfg.api_key_path): key + "\n",
        str(cfg.launchd_plist_path): plist,
    }
    return data


def host_command(data: dict[str, Any], action: str) -> str:
    public = {k: v for k, v in data.items() if k != "contents"}
    public["hashes"] = {
        path: hashlib.sha256(value.encode()).hexdigest() for path, value in data.get("contents", {}).items()
    }
    public["plist_template"] = data.get("contents", {}).get(str(data["launchd_plist_path"]), "")
    script = files(PACKAGE).joinpath("files/llama_server_host.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(script).decode()
        + "'),'<llama-server-host>','exec'))"
    )
    return shlex.join(
        ["/usr/bin/python3", "-B", "-c", launcher, action, base64.b64encode(json.dumps(public).encode()).decode()]
    )


@deploy("Deploy pinned native llama-server")
def deploy_llama_server(cfg: LlamaServerConfig, secrets: Mapping[str, str]) -> None:
    data = payload(cfg, secrets)
    current = host.get_fact(Command, command=host_command(data, "status"))
    if current != "current":
        secret_stdin(
            name="Converge native detector package, model, key, wrapper and launchd",
            command=host_command(data, "apply"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    mark_read_only(
        server.shell(name="Verify native detector state and authentication", commands=[host_command(data, "verify")])
    )
