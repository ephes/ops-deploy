"""Exact role rendering; secrets stay in the stdin payload, hashes stay on host."""

from __future__ import annotations

from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.postfixadmin.config import PostfixAdminConfig
from ops_deploy.services.snappymail.config import SnappyMailConfig

Config = PostfixAdminConfig | SnappyMailConfig


def render(cfg: Config, secrets: SecretValues) -> dict[str, Any]:
    app = cfg.service_name
    root = cfg.install_path if isinstance(cfg, PostfixAdminConfig) else cfg.install_dir
    values = {app + "_" + k: v for k, v in cfg.model_dump(mode="json").items()}
    values.update(
        {
            app + "_php_fpm_socket": f"/run/php/php{cfg.php_version}-fpm-{app}.sock",
            app + "_traefik_config_path": f"/etc/traefik/dynamic/{app}.yml",
        }
    )
    paths = {
        "php-fpm.conf.j2": f"/etc/php/{cfg.php_version}/fpm/pool.d/{app}.conf",
        f"nginx-{app}.conf.j2": f"/etc/nginx/sites-available/{app}",
    }
    credentials: dict[str, Any] = {"app": app}
    if isinstance(cfg, PostfixAdminConfig):
        secrets.require(("db_password", "setup_password", "admin_password"))
        values.update(
            postfixadmin_public_path=root + "/public",
            postfixadmin_templates_c_path=root + "/templates_c",
            postfixadmin_nginx_server_names=[cfg.traefik_host],
            postfixadmin_setup_password_hash="@OPS_SETUP_HASH@",
            postfixadmin_db_password=secrets["db_password"].replace("\\", "\\\\").replace("'", "\\'"),
        )
        paths["config.local.php.j2"] = root + "/config.local.php"
        credentials.update({k: getattr(cfg, k) for k in ("db_user", "db_host", "db_port", "db_name", "admin_email")})
        credentials.update({k: secrets[k] for k in ("db_password", "setup_password", "admin_password")})
    else:
        secrets.require(("admin_password",))
        private = cfg.data_dir + "/_data_/_default_"
        values.update(
            snappymail_admin_password_hash_effective="@OPS_SNAPPY_HASH@",
            snappymail_nginx_server_name=cfg.traefik_host,
            snappymail_external_url="https://" + cfg.traefik_host,
            snappymail_logging_path=cfg.data_dir + "/logs",
            snappymail_sieve_host=cfg.sieve_host or cfg.imap_host,
        )
        paths.update(
            {
                "include.php.j2": root + "/include.php",
                "application.ini.j2": private + "/configs/application.ini",
                "domain-default.json.j2": private + "/domains/default.json",
            }
        )
        credentials["password"] = secrets["admin_password"]
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services." + app, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    # Typed StrictBool inputs need no Ansible runtime filter dependency.
    env.filters["bool"] = bool
    env.filters["ternary"] = lambda value, yes, no: yes if value else no
    result = {dest: env.get_template(src).render(values) for src, dest in paths.items()}
    if isinstance(cfg, SnappyMailConfig):
        for domain in cfg.domains:
            result[private + "/domains/" + domain + ".json"] = env.get_template("domain.json.j2").render(values)
    route = env.get_template(f"traefik-{app}.yml.j2").render(values)
    return {
        "app": app,
        "root": root,
        "data": cfg.data_dir if isinstance(cfg, SnappyMailConfig) else None,
        "php": cfg.php_version,
        "files": result,
        "credentials": credentials,
        "route": route,
        "port": cfg.listen_port,
        "version": cfg.version,
        "user": cfg.user,
        "group": cfg.group if isinstance(cfg, SnappyMailConfig) else cfg.web_group,
        "web_user": cfg.web_user,
        "web_group": cfg.web_group,
        "remove_domains": list(cfg.remove_domains) if isinstance(cfg, SnappyMailConfig) else [],
        "domains": list(cfg.domains) if isinstance(cfg, SnappyMailConfig) else [],
        "disable_default": cfg.disable_default_nginx_site if isinstance(cfg, SnappyMailConfig) else False,
        "healthcheck": cfg.healthcheck_enabled,
        "healthcheck_timeout": cfg.healthcheck_timeout,
        "healthcheck_retries": cfg.healthcheck_retries,
        "db_admin_user": cfg.db_admin_user if isinstance(cfg, PostfixAdminConfig) else None,
    }
