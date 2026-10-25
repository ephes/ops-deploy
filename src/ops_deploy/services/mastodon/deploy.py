"""Existing-install configuration convergence. Source, env and data are immutable."""

from __future__ import annotations

import json
import re
import shlex
from importlib.resources import files as resources
from io import StringIO

from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import mark_read_only, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe
from ops_deploy.ops.secret_file import encode_payload
from ops_deploy.services._traefik_routes import route_put
from ops_deploy.services.mastodon.config import MastodonConfig
from ops_deploy.services.mastodon.release_config import MastodonReleaseConfig
from ops_deploy.services.mastodon.render import render, render_env

RESTART = resources("ops_deploy.services.gotosocial").joinpath("files/restart_host.py").read_text()
PREFLIGHT = resources("ops_deploy.services.mastodon").joinpath("files/preflight.py").read_text()


@deploy("Converge existing Mastodon")
def deploy_mastodon(cfg: MastodonConfig, secrets: SecretValues) -> None:
    """Converge the four units, nginx and Traefik, after strict immutable admission.

    This does not install/upgrade source, dependencies, assets or runtimes, run
    migrations, clear Redis, alter the environment, or manage maintenance.
    A mismatch refuses the entire plan before its first operation.
    """
    if isinstance(cfg, MastodonReleaseConfig):
        from ops_deploy.services.mastodon.release import deploy_release

        deploy_release(cfg, secrets)
        return
    environment = render_env(cfg, secrets)
    require_linux("mastodon")
    require_systemd("mastodon")
    payload = json.dumps({"config": cfg.model_dump(), "environment_b64": encode_payload(environment)})
    answer = probe(shlex.join(["python3", "-I", "-c", PREFLIGHT]), name="mastodon admission", stdin=payload)
    if answer is None or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", answer.strip()):
        raise DeployError("mastodon: existing-install admission failed; no operations planned")
    cfg = cfg.model_copy(update={"node_version": answer.strip()})
    # Render every file before adding an operation.
    content = {
        name: render(cfg, name)
        for name in (
            "web.service.j2",
            "sidekiq.service.j2",
            "streaming.service.j2",
            "nginx.service.j2",
            "nginx.conf.j2",
            "traefik.yml.j2",
        )
    }
    restart_owed: dict[str, bool] = {}
    reload_owed = False
    for component in ("web", "sidekiq", "streaming", "nginx"):
        unit_name = f"mastodon-{component}.service"
        paths = [f"/etc/systemd/system/{unit_name}"]
        if component == "nginx":
            paths.append("/etc/mastodon/nginx.conf")
        else:
            paths.append(f"{cfg.site_path}/.env.production")
        state = probe(
            shlex.join(["python3", "-I", "-c", RESTART, json.dumps({"unit": unit_name, "paths": paths})]),
            name=f"{unit_name} restart debt",
        )
        if state is None or state.strip() not in ("current", "owed"):
            raise DeployError("mastodon: cannot establish restart debt; no operations planned")
        restart_owed[component] = state.strip() == "owed"
        reload = probe(f"systemctl show -p NeedDaemonReload --value {unit_name}", name="Mastodon daemon reload debt")
        if reload is None or reload.strip() not in ("yes", "no"):
            raise DeployError("mastodon: cannot establish systemd reload debt")
        reload_owed = reload_owed or reload.strip() == "yes"
    if reload_owed:
        systemd.daemon_reload(name="Repay Mastodon systemd reload debt")
    nginx = files.put(
        name="Write Mastodon nginx config",
        src=StringIO(content["nginx.conf.j2"]),
        dest="/etc/mastodon/nginx.conf",
        user="root",
        group="root",
        mode="0644",
        create_remote_dir=False,
    )
    for component in ("web", "sidekiq", "streaming", "nginx"):
        unit = systemd_unit(f"mastodon-{component}", content[f"{component}.service.j2"])
        service_rollout(
            f"mastodon-{component}",
            units=[unit],
            restart_when=[nginx] if component == "nginx" else [],
            always_restart=restart_owed[component],
        )
    route_put(
        name="Write Mastodon Traefik route",
        src=content["traefik.yml.j2"],
        dest="/etc/traefik/dynamic/mastodon.yml",
        mode="0644",
        create_remote_dir=False,
    )

    health = """import sys, time, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(NoRedirect)
for attempt in range(6):
    try:
        request = urllib.request.Request(sys.argv[1], headers={"Host": sys.argv[2], "X-Forwarded-Proto": "https"})
        with opener.open(request, timeout=10) as response:
            if response.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(5)
sys.exit("mastodon: instance health check failed")
"""
    mark_read_only(
        server.shell(
            name="Check Mastodon instance health",
            commands=[
                shlex.join(
                    [
                        "python3",
                        "-I",
                        "-c",
                        health,
                        "http://127.0.0.1:10044/api/v1/instance",
                        cfg.web_domain,
                    ]
                )
            ],
        )
    )
