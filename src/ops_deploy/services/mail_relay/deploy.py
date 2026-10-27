"""Native edge relay: original SMTP/TLS/SASL/SRS/routing policy."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import Path, PurePosixPath

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.deb import DebPackages
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only, wait_port
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.helpers.systemd import service_rollout
from ops_deploy.ops import secret_file
from ops_deploy.services._mail_config import finish_restart, prepare_configs, validate_native
from ops_deploy.services._mail_postfix import ensure_maps, verify_master
from ops_deploy.services.mail_relay.config import MailRelayConfig
from ops_deploy.services.mail_relay.render import render_role

SASL = (Path(__file__).parent / "files" / "mail_relay_sasl.py").read_text()


def sasl_command(mode: str) -> str:
    if mode not in {"check", "apply"}:
        raise ValueError("invalid mail relay SASL action")
    return shlex.join(["python3", "-I", "-c", SASL, mode])


@operation()
def _sasl(payload: SecretStr) -> Generator[StringCommand, None, None]:
    raw = payload.get_secret_value()
    state = probe(sasl_command("check"), name="Native relay SASL credentials", stdin=raw)
    if state == "current":
        host.noop("Relay SASL credentials are current")
        return
    if state not in {"pending-create", "pending-password"}:
        raise DeployError("Relay SASL credential state is unknown; no credential mutation attempted")
    yield StringCommand(sasl_command("apply"), _stdin=StdinLines(raw), _get_pty=False, _shell_executable="sh")


def _credential(secrets: SecretValues, key: str) -> str:
    value = secrets.get(key, "")
    if not value or any(char in value for char in "\r\n\0"):
        raise ValueError("relay requires nonempty credentials without CR/LF/NUL")
    return value


def recursor_check(address: str) -> OperationMeta:
    script = (
        "import subprocess,sys; p=subprocess.run(['dig','+short','+time=3','+tries=2','@'+sys.argv[1],"
        "'2.0.0.127.zen.spamhaus.org','A'],capture_output=True,text=True,timeout=10); "
        "sys.exit(0 if p.returncode==0 and '127.0.0.2' in p.stdout.splitlines() else 1)"
    )
    return mark_read_only(
        server.shell(
            name="Verify edge recursor DNSBL test point",
            commands=[shlex.join(["python3", "-I", "-c", script, address])],
        )
    )


@deploy("Deploy native mail edge relay")
def deploy_mail_relay(cfg: MailRelayConfig, secrets: SecretValues) -> None:
    password = _credential(secrets, "sasl_password")
    if cfg.srs_enabled:
        _credential(secrets, "srs_secret")
        excluded = cfg.srs_exclude_domains if cfg.srs_exclude_domains is not None else cfg.domains
        if not excluded or cfg.srs_domain.lower() not in {domain.lower() for domain in cfg.domains}:
            raise ValueError("SRS needs a hosted SRS domain and sender exclusions")
    packages = [*cfg.packages]
    if cfg.srs_enabled:
        packages.append("postsrsd")
    if cfg.local_recursor_enabled:
        packages.append("bind9-dnsutils")
    installed = host.get_fact(DebPackages)
    missing = any(package.partition("=")[0] not in installed for package in packages)
    apt.packages(name="Install mail relay packages", packages=packages, update=missing, cache_time=3600)
    restart_inputs: list[OperationMeta] = []
    reload_inputs: list[OperationMeta] = []
    postfix = prepare_configs("postfix", restart_inputs)
    reload = prepare_configs("postfix", reload_inputs, action="reload")
    for path in ("/etc/postfix", "/etc/postfix/sasl"):
        files.directory(name="Ensure relay config directory", path=path, user="root", group="root", mode="0755")

    def put(template: str, destination: str, *, mode: str = "0644", secret: bool = False) -> OperationMeta:
        body = render_role(template, cfg, secrets)
        if secret:
            return secret_file(
                name="Install protected relay configuration",
                path=destination,
                content=SecretContent(body),
                user="root",
                group="root",
                mode=mode,
            )
        return files.put(
            name="Install relay configuration",
            src=StringIO(body),
            dest=destination,
            user="root",
            group="root",
            mode=mode,
        )

    restart_inputs += [
        put("main.cf.j2", "/etc/postfix/main.cf"),
        put("master.cf.j2", "/etc/postfix/master.cf"),
        put("smtpd.conf.j2", "/etc/postfix/sasl/smtpd.conf"),
    ]
    for enabled, source, destination in (
        (cfg.postscreen_enabled, "postscreen_access.cidr.j2", "/etc/postfix/postscreen_access.cidr"),
        (cfg.submission_discard_spam, "submission_header_checks.j2", "/etc/postfix/submission_header_checks"),
    ):
        reload_inputs.append(
            put(source, destination)
            if enabled
            else files.file(name="Remove disabled relay policy file", path=destination, present=False)
        )
    mapped = ["transport", "relay_domains", "sasl_passwd", "tls_policy"]
    for name in mapped:
        reload_inputs.append(
            put(
                name + ".j2",
                "/etc/postfix/" + name,
                mode="0600" if name == "sasl_passwd" else "0644",
                secret=name == "sasl_passwd",
            )
        )
    if cfg.recipient_rewrites:
        reload_inputs.append(put("recipient_canonical.j2", "/etc/postfix/recipient_canonical"))
        mapped.append("recipient_canonical")
    else:
        for suffix in ("", ".db"):
            reload_inputs.append(
                files.file(
                    name="Remove disabled relay recipient rewrite map",
                    path="/etc/postfix/recipient_canonical" + suffix,
                    present=False,
                )
            )
    maps = ensure_maps(
        name="Ensure relay routing hash maps",
        paths=tuple("/etc/postfix/" + name for name in mapped),
        restart_marker=reload.marker,
        source_changes=tuple(reload_inputs),
    )
    sasl = _sasl(
        name="Reconcile native relay SASL account",
        payload=SecretStr(
            json.dumps(
                {
                    "path": "/etc/sasldb2",
                    "user": cfg.sasl_user,
                    "realm": cfg.hostname,
                    "password": password,
                    "restart_marker": postfix.marker,
                    "reload_marker": reload.marker,
                }
            )
        ),
    )
    files.file(
        name="Protect relay SASL database permissions", path="/etc/sasldb2", user="root", group="postfix", mode="0640"
    )
    grey_inputs: list[OperationMeta] = []
    grey = prepare_configs("postgrey", grey_inputs) if cfg.greylisting_enabled else None
    if cfg.greylisting_enabled:
        files.directory(
            name="Ensure postgrey config directory", path="/etc/postgrey", user="root", group="root", mode="0755"
        )
        grey_inputs += [
            put("postgrey.default.j2", "/etc/default/postgrey"),
            put("postgrey_whitelist_clients.j2", "/etc/postgrey/whitelist_clients"),
        ]
        validate_native(["bash", "-n", "/etc/default/postgrey"], "Validate relay postgrey defaults")
    srs_inputs: list[OperationMeta] = []
    srs = prepare_configs("postsrsd", srs_inputs) if cfg.srs_enabled else None
    if cfg.srs_enabled:
        srs_inputs += [
            secret_file(
                name="Retain configured SRS signing secret",
                path=cfg.srs_secret_file,
                content=SecretContent(secrets["srs_secret"] + "\n"),
                user="root",
                group="root",
                mode="0600",
            ),
            put("postsrsd.default.j2", "/etc/default/postsrsd"),
        ]
        validate_native(["bash", "-n", "/etc/default/postsrsd"], "Validate relay postsrsd defaults")
    resolved_inputs: list[OperationMeta] = []
    resolved = prepare_configs("systemd-resolved", resolved_inputs)
    if cfg.local_recursor_enabled:
        recursor_check(cfg.local_recursor_address)
        files.directory(
            name="Ensure relay resolved fragment directory",
            path=str(PurePosixPath(cfg.local_recursor_dropin).parent),
            user="root",
            group="root",
            mode="0755",
        )
        resolved_inputs.append(put("resolved-local-recursor.conf.j2", cfg.local_recursor_dropin))
    else:
        resolved_inputs.append(
            files.file(name="Remove disabled relay recursor fragment", path=cfg.local_recursor_dropin, present=False)
        )
    validate_native(["postconf", "-n"], "Validate relay Postfix main configuration")
    validate_native(["postconf", "-M"], "Validate relay Postfix master configuration")
    if grey is not None:
        service_rollout(
            "postgrey",
            restart_when=[*grey_inputs, grey.operation],
            always_restart=grey.owed or "postgrey" not in installed,
        )
    if srs is not None:
        service_rollout(
            "postsrsd",
            restart_when=[*srs_inputs, srs.operation],
            always_restart=srs.owed or "postsrsd" not in installed,
        )
    # The original role owns only its drop-in and change handler, not the
    # global resolver's enablement or unconditional service start.
    systemd.service(
        name="Activate changed relay resolved fragment",
        service="systemd-resolved",
        running=None,
        command="restart",
        _if=lambda: resolved.owed or any(op.did_change() for op in resolved_inputs),
    )
    rollout = service_rollout(
        "postfix",
        restart_when=[*restart_inputs, postfix.operation],
        always_restart=postfix.owed or "postfix" not in installed,
    )
    # Credential create writes a restart marker after the preparation operation;
    # password updates retain the original reload path through sasl_passwd.
    created_account = systemd.service(
        name="Activate newly created relay SASL account",
        service="postfix",
        running=None,
        restarted=True,
        _if=lambda: (
            sasl.did_change()
            and not rollout.start.did_change()
            and not rollout.restart.did_change()
            and sasl.stdout.strip() == "created"
        ),
    )
    systemd.service(
        name="Reload relay Postfix policy maps",
        service="postfix",
        running=None,
        reloaded=True,
        _if=lambda: (
            not rollout.start.did_change()
            and not rollout.restart.did_change()
            and not created_account.did_change()
            and (reload.owed or maps.did_change() or sasl.did_change() or any(op.did_change() for op in reload_inputs))
        ),
    )
    wait_port(25, name="Verify relay SMTP listener")
    verify_master()
    if cfg.submission_enabled:
        wait_port(587, name="Verify relay authenticated submission listener")
    if cfg.greylisting_enabled:
        wait_port(cfg.greylisting_port, name="Verify relay postgrey listener")
    if cfg.srs_enabled:
        wait_port(cfg.srs_forward_port, host=cfg.srs_listen_addr, name="Verify relay SRS forward listener")
        wait_port(cfg.srs_reverse_port, host=cfg.srs_listen_addr, name="Verify relay SRS reverse listener")
    if cfg.local_recursor_enabled:
        recursor_check(cfg.local_recursor_address)
    finish_restart(postfix, changes=(sasl,))
    finish_restart(reload, changes=(maps, sasl))
    if grey is not None:
        finish_restart(grey)
    if srs is not None:
        finish_restart(srs)
    finish_restart(resolved)
