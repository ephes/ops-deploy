"""Ordinary operations around the shared, app-specific activation boundary."""

from __future__ import annotations

import base64
import gzip
import json
import shlex
from pathlib import Path
from typing import Any

from pyinfra.api import DeployError
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops.secret_file import secret_stdin
from ops_deploy.services._mail_web.render import Config, render
from ops_deploy.services._traefik_routes import route_put
from ops_deploy.services.postfixadmin.config import PostfixAdminConfig
from ops_deploy.services.snappymail.config import SnappyMailConfig

ROOT = Path(__file__).parent


def command() -> str:
    source = "CREDENTIALS_SOURCE = " + repr((ROOT / "files/credentials.php").read_text()) + "\n"
    source += "\n".join(
        (ROOT / "files" / name).read_text()
        for name in ("mail_web_common.py", "mail_web_release.py", "mail_web_candidate.py", "mail_web_host.py")
    )
    # Encode only public source so fish cannot reinterpret Python/PHP escapes.
    # All configuration and credentials still arrive on the real stdin channel.
    encoded = base64.b64encode(source.encode()).decode()
    loader = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<mail-web>','exec'))"
    return shlex.join(["python3", "-I", "-B", "-c", loader])


def release_records(cfg: Config) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    records = [
        json.loads(gzip.decompress(p.read_bytes())) for p in (ROOT / "releases").glob(cfg.service_name + "-*.json.gz")
    ]
    selected = next((r for r in records if r["version"] == cfg.version and not r.get("previous_only")), None)
    if selected is None:
        raise DeployError("Unsupported selected mail web release; add its verified artifact manifest")
    return selected, [r for r in records if r is not selected]


def deploy(cfg: Config, secrets: SecretValues) -> None:
    for key in secrets:
        if "\0" in secrets[key]:
            raise DeployError("Mail web credentials must not contain NUL")
    if isinstance(cfg, PostfixAdminConfig) and any(c in secrets.get("admin_password", "") for c in "\r\n"):
        raise DeployError("PostfixAdmin password must not contain line breaks")
    require_linux(cfg.service_name)
    require_systemd(cfg.service_name)
    if isinstance(cfg, PostfixAdminConfig):
        # Core owns role/password/database lifecycle; web only admits its prerequisite.
        from ops_deploy.services._mail_database import MailDatabaseConfig, require_mail_database

        require_mail_database(
            MailDatabaseConfig(name=cfg.db_name, role=cfg.db_user, port=cfg.db_port, admin_user=cfg.db_admin_user),
            required_privileges=("CONNECT",),
        )
    payload = render(cfg, secrets)
    payload["release"], payload["previous_releases"] = release_records(cfg)
    cmd = command()
    result = probe(
        cmd,
        name="Compare " + cfg.service_name + " code, credentials and owned configuration",
        stdin=json.dumps(payload),
    )
    if result not in ("changed=true", "changed=false"):
        raise DeployError("Mail web read-only admission failed")
    packages = ["nginx", "php" + cfg.php_version + "-fpm", "php" + cfg.php_version + "-cli"]
    extensions = (
        ("pgsql", "mbstring", "intl", "gd", "imap")
        if isinstance(cfg, PostfixAdminConfig)
        else ("curl", "mbstring", "intl", "gd", "xml", "zip", "imap")
    )
    apt.packages(
        name="Ensure " + cfg.service_name + " PHP dependencies",
        packages=packages + ["php" + cfg.php_version + "-" + x for x in extensions],
        update=False,
    )
    if isinstance(cfg, SnappyMailConfig):
        server.group(name="Ensure SnappyMail group", group=cfg.group, system=True)
        server.user(
            name="Ensure SnappyMail user",
            user=cfg.user,
            group=cfg.group,
            home=cfg.install_dir,
            shell=cfg.shell,
            create_home=False,
            ensure_home=False,
            system=True,
        )
        for path in (
            cfg.data_dir,
            cfg.data_dir + "/_data_/_default_",
            cfg.data_dir + "/_data_/_default_/configs",
            cfg.data_dir + "/_data_/_default_/domains",
            cfg.data_dir + "/logs",
        ):
            files.directory(
                name="Ensure SnappyMail owned directory", path=path, user=cfg.user, group=cfg.group, mode="0750"
            )
        root = cfg.install_dir
    else:
        server.user(
            name="Ensure PHP doveadm group access",
            user=cfg.web_user,
            groups=["dovecot"],
            append=True,
            ensure_home=False,
        )
        root = cfg.install_path
        files.directory(
            name="Ensure PostfixAdmin compiled-template directory",
            path=root + "/templates_c",
            user=cfg.web_user,
            group=cfg.web_group,
            mode="0755",
        )
    files.directory(
        name="Ensure " + cfg.service_name + " application root", path=root, user="root", group="root", mode="0755"
    )
    if result == "changed=true":
        payload["apply"] = True
        secret_stdin(
            name="Validate and activate " + cfg.service_name + " owned files",
            command=cmd,
            content=SecretContent(json.dumps(payload)),
        )
    if cfg.traefik_enabled:
        route_put(
            name="Converge " + cfg.service_name + " route",
            src=payload["route"],
            dest="/etc/traefik/dynamic/" + cfg.service_name + ".yml",
        )
    for unit in ("nginx", "php" + cfg.php_version + "-fpm"):
        systemd.service(name="Ensure shared " + unit + " service state", service=unit, running=True, enabled=True)
    # Exact re-admission verifies resulting code/schema/config with no helper staging.
    payload.pop("apply", None)
    verify_probe(cmd, name=cfg.service_name + " final owned state", expect="changed=false", stdin=json.dumps(payload))
