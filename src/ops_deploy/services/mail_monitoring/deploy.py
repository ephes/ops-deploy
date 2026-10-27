"""Native monitor mailbox, Maildir, cleanup and Mailgun relay probe role."""

from __future__ import annotations

import json
import re
import shlex
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

import jinja2
from pydantic import Field, StrictInt, field_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.files import File
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.systemd import service_rollout, systemd_unit
from ops_deploy.ops import secret_file, secret_stdin
from ops_deploy.services.metrics_endpoint.common import PlainPath

Address = Annotated[str, Field(pattern=r"^[A-Za-z0-9_+.-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")]
Positive = Annotated[StrictInt, Field(ge=1)]
Nonnegative = Annotated[StrictInt, Field(ge=0)]
SCRIPT = (Path(__file__).parent / "files" / "mailbox.py").read_text()


class MailMonitoringConfig(BaseServiceConfig):
    service_name: ServiceName = "mail-monitoring"
    user: UnixUser = "vmail"
    site_path: PlainPath = PurePosixPath("/mnt/cryptdata/vmail")
    address: Address
    active: bool = True
    schema_mode: Literal["postfixadmin", "legacy"] = "legacy"
    postgres_database: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]*$")] = "mail"
    vmail_group: UnixUser = "vmail"
    cleanup_enabled: bool = True
    cleanup_ttl_days: Positive = 1
    cleanup_timer_on_calendar: str = "daily"
    cleanup_script_path: PlainPath = PurePosixPath("/usr/local/bin/mail-monitoring-cleanup.sh")
    cleanup_service_name: ServiceName = "mail-monitoring-cleanup"
    relay_probe_enabled: bool = False
    relay_probe_url: str = ""
    relay_probe_domain: str = ""
    relay_probe_from: str = ""
    relay_probe_to: str = ""
    relay_probe_subject_prefix: str = "[nyxmon-relay]"
    relay_probe_timeout: Positive = 30
    relay_probe_retries: Nonnegative = 2
    relay_probe_on_calendar: str = "*:0/15"
    relay_probe_randomized_delay_sec: Nonnegative = 60
    relay_probe_user: UnixUser = "mailgun-relay-probe"
    relay_probe_service_name: ServiceName = "mailgun-relay-probe"

    @field_validator("address")
    @classmethod
    def _address_path(cls, value: str) -> str:
        if any(part in {".", ".."} for part in value.split("@")):
            raise ValueError("mailbox identity must not be a path component")
        return value

    @field_validator("cleanup_timer_on_calendar", "relay_probe_on_calendar", "relay_probe_subject_prefix")
    @classmethod
    def _text(cls, value: str) -> str:
        if not value.strip() or re.search(r"[\x00-\x1f\x7f]", value):
            raise ValueError("timer and subject text must be nonblank without controls")
        return value


def validate_secrets(cfg: MailMonitoringConfig, secrets: SecretValues) -> tuple[str, str]:
    value = secrets.get("monitor_password", "")
    if not value.strip() or value == "CHANGE_ME" or any(c in value for c in "\r\n\0"):
        raise ValueError("monitor_password must be nonblank, non-placeholder, without CR/LF/NUL")
    token = secrets.get("relay_probe_token", "")
    if cfg.relay_probe_enabled:
        if not re.fullmatch(r"[A-Za-z0-9._~-]+", token) or token == "CHANGE_ME":
            raise ValueError("relay_probe_token must be non-placeholder and use the role's allowed characters")
        if not re.fullmatch(r"https?://[^/\s]+(/\S*)?", cfg.relay_probe_url):
            raise ValueError("relay probe needs an HTTP(S) URL")
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", cfg.relay_probe_domain):
            raise ValueError("relay probe needs a domain")
        for address in (cfg.relay_probe_from, cfg.relay_probe_to or cfg.address):
            if not re.fullmatch(r"[^@\s<>]+@[A-Za-z0-9.-]+", address):
                raise ValueError("relay probe needs sender and recipient addresses")
    return value, token


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.mail_monitoring", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    return env


def role_vars(cfg: MailMonitoringConfig) -> dict[str, Any]:
    values = cfg.model_dump(mode="json", exclude={"secrets"})
    values.update(vmail_path=str(cfg.site_path), vmail_user=cfg.user, relay_probe_to=cfg.relay_probe_to or cfg.address)
    return {"mail_monitoring_" + key: value for key, value in values.items()}


def render_role(template: str, cfg: MailMonitoringConfig) -> str:
    return environment().get_template(template).render(**role_vars(cfg))


def mailbox_command(mode: Literal["check", "apply"]) -> str:
    return shlex.join(["runuser", "-u", "postgres", "--", "python3", "-I", "-c", SCRIPT, mode])


@deploy("Deploy mail monitoring mailbox and probe")
def deploy_mail_monitoring(cfg: MailMonitoringConfig, secrets: SecretValues) -> None:
    password, token = validate_secrets(cfg, secrets)
    payload = (
        json.dumps(
            {
                "address": cfg.address,
                "password": password,
                "active": cfg.active,
                "schema_mode": cfg.schema_mode,
                "database": cfg.postgres_database,
            }
        )
        + "\n"
    )
    check = mailbox_command("check")
    state = probe(check, name="Monitor mailbox", stdin=payload)
    # Early read-only validation, including domain and ambiguity, before filesystem operations.
    if state is None:
        verify_probe(check, name="Monitor mailbox prerequisites", stdin=payload)
    if state != "changed=false":
        secret_stdin(name="Reconcile monitor mailbox", command=mailbox_command("apply"), content=SecretContent(payload))
        verify_probe(check, name="Monitor mailbox", expect="changed=false", stdin=payload)
    localpart, domain = cfg.address.lower().split("@")
    mailbox = cfg.site_path / domain / localpart
    for directory in (cfg.site_path / domain, mailbox, mailbox / "cur", mailbox / "new", mailbox / "tmp"):
        files.directory(
            name=f"Ensure monitor Maildir {directory}",
            path=str(directory),
            user=cfg.user,
            group=cfg.vmail_group,
            mode="0700",
        )
    if cfg.cleanup_enabled:
        files.put(
            name="Install monitor cleanup script",
            src=StringIO(render_role("mail-monitoring-cleanup.sh.j2", cfg)),
            dest=str(cfg.cleanup_script_path),
            user="root",
            group="root",
            mode="0755",
        )
        units = [
            systemd_unit(
                cfg.cleanup_service_name + "." + kind, render_role("mail-monitoring-cleanup." + kind + ".j2", cfg)
            )
            for kind in ("service", "timer")
        ]
        service_rollout(cfg.cleanup_service_name + ".timer", units=units)
    name = cfg.relay_probe_service_name
    if not cfg.relay_probe_enabled:
        if host.get_fact(File, path=f"/etc/systemd/system/{name}.timer"):
            systemd.service(name="Stop relay probe timer", service=name + ".timer", running=False, enabled=False)
        removed = [
            files.file(name=f"Remove {name}.{kind}", path=f"/etc/systemd/system/{name}.{kind}", present=False)
            for kind in ("timer", "service")
        ]
        removed.append(files.file(name="Remove relay probe script", path=f"/usr/local/bin/{name}", present=False))
        for remove_directory in (f"/etc/{name}", f"/var/lib/{name}"):
            removed.append(files.directory(name=f"Remove {remove_directory}", path=remove_directory, present=False))
        systemd.daemon_reload(name="Reload removed relay probe units", _if=any_changed(*removed))
        return
    apt.packages(name="Install relay probe curl", packages=["curl"])
    server.group(name="Ensure relay probe group", group=cfg.relay_probe_user, system=True)
    server.user(
        name="Ensure relay probe user",
        user=cfg.relay_probe_user,
        group=cfg.relay_probe_user,
        shell="/usr/sbin/nologin",
        create_home=False,
        system=True,
    )
    files.directory(
        name="Ensure relay token directory", path=f"/etc/{name}", user="root", group=cfg.relay_probe_user, mode="0750"
    )
    secret_file(
        name="Install relay probe token",
        path=f"/etc/{name}/token",
        content=SecretContent(token),
        user=cfg.relay_probe_user,
        group=cfg.relay_probe_user,
        mode="0600",
    )
    files.put(
        name="Install relay probe script",
        src=StringIO(render_role("mailgun-relay-probe.sh.j2", cfg)),
        dest=f"/usr/local/bin/{name}",
        user="root",
        group="root",
        mode="0755",
    )
    units = [
        systemd_unit(name + "." + kind, render_role("mailgun-relay-probe." + kind + ".j2", cfg))
        for kind in ("service", "timer")
    ]
    service_rollout(name + ".timer", units=units)
