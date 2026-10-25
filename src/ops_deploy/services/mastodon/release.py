"""Ordered existing-install release operations, composed from strict inspection."""

from __future__ import annotations

import json
import re
import shlex
from importlib.resources import files as resources
from io import StringIO
from typing import Any
from urllib.request import urlopen

from pyinfra import logger
from pyinfra.api import DeployError
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import mark_read_only, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe, stdin_arguments
from ops_deploy.ops.secret_file import encode_payload, secret_file
from ops_deploy.services._traefik_routes import route_put
from ops_deploy.services.mastodon.release_config import MastodonReleaseConfig
from ops_deploy.services.mastodon.render import render, render_env

HOST = resources("ops_deploy.services.mastodon").joinpath("files/release_host.py").read_text()
RESTART = resources("ops_deploy.services.gotosocial").joinpath("files/restart_host.py").read_text()


def command(action: str) -> str:
    return shlex.join(["python3", "-I", "-c", HOST, action])


def node_version(requested: str, installed: str | None) -> str:
    """Preserve nvm's installed match, else freeze a concrete matching release."""
    if installed:
        if installed != requested and not installed.startswith(requested + "."):
            raise DeployError("mastodon: nvm resolved a different numeric Node selector")
        return installed
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", requested):
        return requested
    with urlopen("https://nodejs.org/dist/index.json", timeout=30) as response:
        versions = json.load(response)
    candidates: list[str] = [
        row["version"][1:]
        for row in versions
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", row["version"]) and row["version"].startswith("v" + requested + ".")
    ]
    if not candidates:
        raise DeployError("mastodon: no concrete Node release matches the selected source")
    return max(candidates, key=lambda value: tuple(int(part) for part in value.split(".")))


def _probe(action: str, payload: str) -> dict[str, Any]:
    value = probe(command(action), name="Mastodon release " + action, stdin=payload)
    if value is None:
        raise DeployError("mastodon: existing-install release inspection failed before writes")
    try:
        result: dict[str, Any] = json.loads(value)
    except (ValueError, TypeError) as exc:
        raise DeployError("mastodon: invalid release inspection result") from exc
    return result


def deploy_release(cfg: MastodonReleaseConfig, secrets: SecretValues) -> None:
    environment = render_env(cfg, secrets)
    require_linux("mastodon")
    require_systemd("mastodon")

    def payload_for(config: MastodonReleaseConfig) -> str:
        return json.dumps({"config": config.model_dump(), "environment_b64": encode_payload(environment)})

    runtime = _probe("runtime-inspect", payload_for(cfg))
    selector = cfg.node_version
    cfg = cfg.model_copy(update={"node_version": node_version(selector, runtime["node_version"])})
    logger.info(f"Mastodon concrete runtime: Ruby {cfg.ruby_version}, Node {cfg.node_version} (selector {selector})")
    payload = payload_for(cfg)
    observed = _probe("inspect", payload)
    logger.info("Mastodon selected source: " + cfg.source_commit)
    logger.info("Mastodon runtime tool commits: " + json.dumps(cfg.runtime_tool_commits, sort_keys=True))
    logger.info("Mastodon candidate pending migration identities: " + json.dumps(observed["pending_migrations"]))
    # Render and inspect ALL managed configuration before the first write.
    content = {
        name: render(cfg, name)
        for name in (
            "web.service.j2",
            "sidekiq.service.j2",
            "streaming.service.j2",
            "nginx.service.j2",
            "nginx.conf.j2",
            "traefik.yml.j2",
            "maintenance.service.j2",
            "maintenance.timer.j2",
            "maintenance.sh.j2",
        )
    }
    owed: dict[str, bool] = {}
    active: dict[str, bool] = {}
    reload_owed = False
    for component in ("web", "sidekiq", "streaming", "nginx"):
        paths = [f"/etc/systemd/system/mastodon-{component}.service"]
        paths += (
            ["/etc/mastodon/nginx.conf"]
            if component == "nginx"
            else [
                cfg.site_path + "/.env.production",
                cfg.site_path + "/.git/HEAD",
                cfg.site_path + "/Gemfile.lock",
                cfg.site_path + "/yarn.lock",
                "/var/lib/ops-deploy-mastodon/bundle",
                "/var/lib/ops-deploy-mastodon/yarn",
                "/var/lib/ops-deploy-mastodon/assets",
            ]
        )
        answer = probe(
            shlex.join(
                [
                    "python3",
                    "-I",
                    "-c",
                    RESTART,
                    json.dumps(
                        {
                            "unit": f"mastodon-{component}.service",
                            "paths": paths,
                        }
                    ),
                ]
            ),
            name="Mastodon release restart debt",
        )
        if answer is None or answer.strip() not in ("current", "owed", "inactive"):
            raise DeployError("mastodon: cannot establish restart debt before writes")
        owed[component] = answer.strip() == "owed"
        active[component] = answer.strip() != "inactive"
        reload = probe(
            f"systemctl show -p NeedDaemonReload --value mastodon-{component}.service", name="Mastodon reload debt"
        )
        if reload is None or reload.strip() not in ("yes", "no"):
            raise DeployError("mastodon: cannot establish systemd reload debt")
        reload_owed |= reload.strip() == "yes"

    def action(stage: str, name: str, *, read_only: bool = False) -> Any:
        result = server.shell(name=name, commands=[command(stage)], **stdin_arguments(payload))
        return mark_read_only(result) if read_only else result

    source_change = bool(observed["source"])
    runtime_change = bool(observed["runtime"]["ruby"] or observed["runtime"]["node"])
    bundle_change = cfg.bundle_install and (source_change or observed["dependencies"]["bundle"])
    yarn_change = cfg.yarn_install and (source_change or observed["dependencies"]["yarn"])
    assets_change = cfg.precompile_assets and (
        source_change or runtime_change or bundle_change or yarn_change or observed["dependencies"]["assets"]
    )
    migrate_change = cfg.run_migrations and bool(observed["pending_migrations"])
    app_change = source_change or runtime_change or bundle_change or yarn_change or assets_change or migrate_change
    rollout = app_change or observed["env"] or observed["rollout_debt"]
    if source_change:
        action("source", "Update selected Mastodon Git checkout (preserve retained data)")
    if observed["runtime"]["ruby"] or observed["runtime"]["ruby_tool"]:
        action("ruby", "Converge rbenv Ruby and exact ruby-build execution input")
    if observed["runtime"]["node"]:
        action("node", "Converge nvm and selected Node runtime")
    if bundle_change:
        action("bundle", "Install and verify selected locked Ruby dependencies")
    if yarn_change:
        action("yarn", "Install and verify selected locked Yarn dependencies")
    if observed["env"]:
        action("env-debt", "Remember pending environment rollout")
    env_op = secret_file(
        path=cfg.site_path + "/.env.production", content=environment, user="mastodon", group="mastodon", mode="0600"
    )
    if migrate_change:
        action("migrate", "Apply candidate pending migration identities: " + ",".join(observed["pending_migrations"]))
    if assets_change:
        action("assets", "Build and verify selected Mastodon production assets")

    nginx = files.put(
        name="Write Mastodon nginx config",
        src=StringIO(content["nginx.conf.j2"]),
        dest="/etc/mastodon/nginx.conf",
        user="root",
        group="root",
        mode="0644",
        create_remote_dir=False,
    )
    units = {
        component: systemd_unit("mastodon-" + component, content[component + ".service.j2"])
        for component in ("web", "sidekiq", "streaming", "nginx")
    }
    maintenance_units = []
    if cfg.maintenance_enabled:
        files.put(
            name="Write Mastodon maintenance script (do not execute)",
            src=StringIO(content["maintenance.sh.j2"]),
            dest=cfg.maintenance_script_path,
            user="root",
            group="root",
            mode=cfg.maintenance_script_mode,
            create_remote_dir=False,
        )
        for kind, name in (("service", cfg.maintenance_service_name), ("timer", cfg.maintenance_timer_name)):
            maintenance_units.append(
                files.put(
                    name="Write Mastodon maintenance " + kind,
                    src=StringIO(content["maintenance." + kind + ".j2"]),
                    dest=getattr(cfg, "maintenance_" + kind + "_unit")
                    or (cfg.maintenance_unit_dir + "/" + name + "." + kind),
                    user="root",
                    group="root",
                    mode="0644",
                    create_remote_dir=False,
                )
            )
    systemd.daemon_reload(
        name="Reload changed Mastodon units before cache clear",
        _if=lambda: reload_owed or any_changed(*units.values(), *maintenance_units)(),
    )
    if app_change or observed["cache_clear_debt"]:
        action("cache_clear", "Pay pending Mastodon tootctl cache clear")
    for component in ("web", "sidekiq", "streaming", "nginx"):
        service_rollout(
            "mastodon-" + component,
            restart_when=[units[component], nginx] if component == "nginx" else [units[component], env_op],
            always_restart=active[component] and (owed[component] or (rollout and component != "nginx")),
        )
    route_put(
        name="Write Mastodon Traefik route",
        src=content["traefik.yml.j2"],
        dest="/etc/traefik/dynamic/mastodon.yml",
        mode="0644",
        create_remote_dir=False,
    )
    if cfg.maintenance_enabled:
        systemd.service(
            name="Converge Mastodon maintenance timer without executing cleanup",
            service=cfg.maintenance_timer_name + ".timer",
            running=cfg.maintenance_timer_enabled,
            enabled=cfg.maintenance_timer_enabled,
        )
        if cfg.maintenance_timer_enabled:
            systemd.service(
                name="Restart changed Mastodon maintenance timer",
                service=cfg.maintenance_timer_name + ".timer",
                running=None,
                restarted=True,
                _if=any_changed(*maintenance_units),
            )
    action("health", "Verify selected Mastodon instance health", read_only=True)
    if rollout:
        action("complete", "Complete successful Mastodon application rollout")
    if cfg.nginx_federation_cache_enabled:
        if app_change or observed["prime"]:
            action("prime", "Populate and verify Mastodon federation cache")
        else:
            action("verify_cache", "Verify existing Mastodon federation cache", read_only=True)
