"""Native backend role composition, retaining current config/data/version intent."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import Path

from pydantic import SecretStr
from pyinfra import host, logger
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.files import File
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only, wait_port
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.helpers.systemd import service_rollout
from ops_deploy.ops import secret_file
from ops_deploy.services._mail_config import finish_restart, postfix_group_access, prepare_configs, validate_native
from ops_deploy.services._mail_database import MailDatabaseConfig, ensure_mail_database
from ops_deploy.services._mail_postfix import ensure_maps, verify_master
from ops_deploy.services.mail_backend.config import MailBackendConfig
from ops_deploy.services.mail_backend.render import render_role

CATALOG = (Path(__file__).parent / "files" / "mail_backend_database.py").read_text()


def catalog_command(mode: str) -> str:
    if mode not in {"check", "apply"}:
        raise ValueError("invalid core mail catalog action")
    return shlex.join(["runuser", "-u", "postgres", "--", "python3", "-I", "-c", CATALOG, mode])


@operation()
def _catalog(payload: SecretStr, prerequisites: tuple[OperationMeta, ...] = ()) -> Generator[StringCommand, None, None]:
    # Deliberately after package/foundation operations. The native parser uses
    # six temporary candidate views, dropped/rolled back and connection-closed.
    # This is TRANSIENT catalog validation work, not a read-only fact claim.
    raw = payload.get_secret_value()
    if any(op.will_change for op in prerequisites):
        yield StringCommand(catalog_command("apply"), _stdin=StdinLines(raw), _get_pty=False, _shell_executable="sh")
        return
    output = probe(catalog_command("check"), name="Core mail catalog (transient PostgreSQL validation)", stdin=raw)
    try:
        state = json.loads(output or "null")
        valid = isinstance(state, dict) and state.get("state") in {"current", "pending"}
    except ValueError:
        valid = False
    if not valid:
        raise DeployError("Core mail catalog state is unknown; no catalog reconciliation attempted")
    logger.info("Core mail catalog check performs bounded transient PostgreSQL catalog validation")
    if state["state"] == "current":
        host.noop("Core mail catalog is current")
        return
    yield StringCommand(catalog_command("apply"), _stdin=StdinLines(raw), _get_pty=False, _shell_executable="sh")


def _password(secrets: SecretValues, name: str) -> str:
    value = secrets.get(name, "")
    if not value or any(char in value for char in "\r\n\0"):
        raise ValueError("mail backend requires nonempty credentials without CR/LF/NUL")
    return value


@deploy("Deploy native mail backend")
def deploy_mail_backend(cfg: MailBackendConfig, secrets: SecretValues) -> None:
    postgres_password = _password(secrets, "postgres_password")
    _password(secrets, "relay_password")
    if cfg.initial_user:
        _password(secrets, "initial_user_password")
    packages = [*cfg.packages, "python3-psycopg2"]
    installed = host.get_fact(DebPackages)
    missing = any(package.partition("=")[0] not in installed for package in packages)
    package_install = apt.packages(
        name="Install mail backend packages", packages=packages, update=missing, cache_time=3600
    )
    foundation = ensure_mail_database(
        MailDatabaseConfig(name=cfg.postgres_database, role=cfg.postgres_user, port=cfg.postgres_port),
        role_password=SecretStr(postgres_password),
    )
    _catalog(
        name="Reconcile core mail catalog",
        # A login role still to be created cannot be probed (has_*_privilege
        # would fail), so a pending role also goes straight to apply.
        prerequisites=(package_install, foundation.role, foundation.database),
        payload=SecretStr(
            json.dumps(
                {
                    "config": cfg.model_dump(mode="json", exclude={"secrets"}),
                    "schema_sql": render_role("schema.sql.j2", cfg, secrets),
                    "initial_password": secrets.get("initial_user_password", ""),
                }
            )
        ),
    )
    server.group(name="Ensure virtual mail group", group=cfg.vmail_group, gid=cfg.vmail_gid)
    server.user(
        name="Ensure virtual mail identity",
        user=cfg.vmail_user,
        uid=cfg.vmail_uid,
        group=cfg.vmail_group,
        home=cfg.vmail_path,
        shell="/usr/sbin/nologin",
        create_home=False,
        ensure_home=False,
    )
    files.directory(
        name="Ensure virtual mail root", path=cfg.vmail_path, user=cfg.vmail_user, group=cfg.vmail_group, mode="0750"
    )
    postfix_inputs: list[OperationMeta] = []
    postfix_reload_inputs: list[OperationMeta] = []
    dovecot_inputs: list[OperationMeta] = []
    dkim_inputs: list[OperationMeta] = []
    postfix = prepare_configs("postfix", postfix_inputs)
    postfix_reload = prepare_configs("postfix", postfix_reload_inputs, action="reload")
    dovecot = prepare_configs("dovecot", dovecot_inputs)
    dkim = prepare_configs("opendkim", dkim_inputs) if cfg.dkim_enabled else None
    for path in ("/etc/postfix", "/etc/postfix/sql", "/etc/postfix/sasl", "/etc/dovecot/conf.d"):
        files.directory(name="Ensure backend config directory", path=path, user="root", group="root", mode="0755")

    def put(
        template: str, destination: str, *, group: str = "root", mode: str = "0644", secret: bool = False
    ) -> OperationMeta:
        body = render_role(template, cfg, secrets)
        if secret:
            return secret_file(
                name="Install protected backend configuration",
                path=destination,
                content=SecretContent(body),
                user="root",
                group=group,
                mode=mode,
            )
        return files.put(
            name="Install backend configuration",
            src=StringIO(body),
            dest=destination,
            user="root",
            group=group,
            mode=mode,
        )

    postfix_inputs += [
        put("postfix/main.cf.j2", "/etc/postfix/main.cf"),
        put("postfix/master.cf.j2", "/etc/postfix/master.cf"),
    ]
    if cfg.local_delivery_clients:
        postfix_inputs.append(put("postfix/local_delivery_clients.cidr.j2", "/etc/postfix/local_delivery_clients.cidr"))
    else:
        postfix_inputs.append(
            files.file(
                name="Remove unused local-delivery client map",
                path="/etc/postfix/local_delivery_clients.cidr",
                present=False,
            )
        )
    for name in (
        "virtual_domains",
        "virtual_mailboxes",
        "virtual_aliases",
        "virtual_catchall",
        "virtual_domain_aliases",
        "sender_login",
    ):
        postfix_inputs.append(
            put(f"postfix/sql/{name}.cf.j2", f"/etc/postfix/sql/{name}.cf", group="postfix", mode="0640", secret=True)
        )
    postfix_reload_inputs.append(
        put("postfix/relay_password.j2", "/etc/postfix/relay_password", mode="0600", secret=True)
    )
    maps = ensure_maps(
        name="Ensure backend relay password map",
        paths=("/etc/postfix/relay_password",),
        restart_marker=postfix_reload.marker,
        source_changes=tuple(postfix_reload_inputs),
    )
    dovecot_inputs += [
        put("dovecot/dovecot.conf.j2", "/etc/dovecot/dovecot.conf"),
        put("dovecot/dovecot-sql.conf.ext.j2", "/etc/dovecot/dovecot-sql.conf.ext", mode="0600", secret=True),
    ]
    for name in ("10-auth.conf", "10-mail.conf", "10-master.conf", "10-ssl.conf", "auth-sql.conf.ext", "20-lmtp.conf"):
        dovecot_inputs.append(put("dovecot/conf.d/" + name + ".j2", "/etc/dovecot/conf.d/" + name))
    if cfg.sieve_enabled:
        dovecot_inputs.append(put("dovecot/conf.d/90-sieve.conf.j2", "/etc/dovecot/conf.d/90-sieve.conf"))
    sieve = cfg.sieve_before_dir + "/10-spam-to-junk.sieve"
    if cfg.sieve_enabled and cfg.spam_to_junk_enabled:
        files.directory(
            name="Ensure global Sieve directory", path=cfg.sieve_before_dir, user="root", group="root", mode="0755"
        )
        script = put("dovecot/sieve/10-spam-to-junk.sieve.j2", sieve)
        dovecot_inputs.append(script)
        compiled = host.get_fact(File, path=cfg.sieve_before_dir + "/10-spam-to-junk.svbin")
        if script.will_change or compiled is None:
            dovecot_inputs.append(
                server.shell(name="Compile backend spam-to-Junk Sieve", commands=[shlex.join(["sievec", sieve])])
            )
    else:
        for extension in ("sieve", "svbin"):
            dovecot_inputs.append(
                files.file(
                    name="Remove disabled global spam Sieve",
                    path=cfg.sieve_before_dir + "/10-spam-to-junk." + extension,
                    present=False,
                )
            )
    if cfg.dkim_enabled:
        for path in ("/etc/opendkim", cfg.dkim_key_path):
            files.directory(name="Ensure OpenDKIM directory", path=path, user="opendkim", group="opendkim", mode="0750")
        dkim_inputs.append(put("opendkim/opendkim.conf.j2", "/etc/opendkim.conf"))
        for name in ("signing.table", "key.table", "trusted.hosts"):
            dkim_inputs.append(
                files.put(
                    name="Install backend DKIM configuration",
                    src=StringIO(render_role("opendkim/" + name + ".j2", cfg, secrets)),
                    dest="/etc/opendkim/" + name,
                    user="opendkim",
                    group="opendkim",
                    mode="0640",
                )
            )
        for domain in dict.fromkeys((*cfg.domains, *cfg.sender_only_domains)):
            directory = cfg.dkim_key_path + "/" + domain
            private = directory + "/" + cfg.dkim_selector + ".private"
            if host.get_fact(File, path=private) is None:
                files.directory(
                    name="Ensure missing domain DKIM directory",
                    path=directory,
                    user="opendkim",
                    group="opendkim",
                    mode="0750",
                )
                dkim_inputs.append(
                    server.shell(
                        name="Generate missing backend domain DKIM key",
                        commands=[
                            shlex.join(
                                [
                                    "runuser",
                                    "-u",
                                    "opendkim",
                                    "--",
                                    "opendkim-genkey",
                                    "-b",
                                    str(cfg.dkim_key_bits),
                                    "-d",
                                    domain,
                                    "-D",
                                    directory,
                                    "-s",
                                    cfg.dkim_selector,
                                ]
                            )
                        ],
                    )
                )
                files.file(
                    name="Protect generated backend DKIM private key",
                    path=private,
                    user="opendkim",
                    group="opendkim",
                    mode="0600",
                )
        postfix_inputs.append(postfix_group_access("opendkim", postfix_package_pending="postfix" not in installed))
        files.directory(
            name="Ensure chroot OpenDKIM socket directory",
            path="/var/spool/postfix/opendkim",
            user="opendkim",
            group="postfix",
            mode="0750",
        )
        validate_native(["opendkim", "-n", "-x", "/etc/opendkim.conf"], "Validate backend OpenDKIM configuration")
    validate_native(["postconf", "-n"], "Validate backend Postfix main configuration")
    validate_native(["postconf", "-M"], "Validate backend Postfix master configuration")
    validate_native(["doveconf", "-n", "-x"], "Validate backend Dovecot configuration")
    if cfg.dkim_enabled and dkim is not None:
        service_rollout(
            "opendkim",
            restart_when=[*dkim_inputs, dkim.operation],
            always_restart=dkim.owed or "opendkim" not in installed,
        )
    service_rollout(
        "dovecot",
        restart_when=[*dovecot_inputs, dovecot.operation],
        always_restart=dovecot.owed or "dovecot-core" not in installed,
    )
    postfix_rollout = service_rollout(
        "postfix",
        restart_when=[*postfix_inputs, postfix.operation],
        always_restart=postfix.owed or "postfix" not in installed,
    )
    systemd.service(
        name="Reload backend Postfix for map changes",
        service="postfix",
        running=None,
        reloaded=True,
        _if=lambda: (
            not postfix_rollout.start.did_change()
            and not postfix_rollout.restart.did_change()
            and (postfix_reload.owed or maps.did_change() or any(op.did_change() for op in postfix_reload_inputs))
        ),
    )
    wait_port(25, name="Verify backend SMTP listener")
    verify_master()
    if "imap" in cfg.dovecot_protocols.split():
        # The packaged Dovecot listeners are implicit-TLS IMAPS only (plain imap
        # port 0, ssl=required); tls_enabled toggles Postfix TLS as in the role.
        wait_port(993, name="Verify backend IMAP listener")
    for service in (["opendkim"] if cfg.dkim_enabled else []) + ["dovecot", "postfix"]:
        mark_read_only(
            server.shell(
                name="Verify backend daemon active",
                commands=[shlex.join(["systemctl", "is-active", "--quiet", service])],
            )
        )
    finish_restart(postfix)
    finish_restart(postfix_reload, changes=(maps,))
    finish_restart(dovecot)
    if dkim is not None:
        finish_restart(dkim)
