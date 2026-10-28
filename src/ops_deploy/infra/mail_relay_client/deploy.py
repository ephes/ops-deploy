from __future__ import annotations

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Command, Which
from pyinfra.operations import server

from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.infra import _monitoring as common

from .config import MailRelayClientConfig


@deploy("Configure system alert mail relay")
def deploy_mail_relay_client(cfg: MailRelayClientConfig) -> None:
    if not cfg.enabled:
        return
    values = cfg.model_dump()
    if cfg.myhostname is None or cfg.myorigin is None:
        fqdn = (host.get_fact(Command, command="hostname -f") or "").strip()
        values["myhostname"] = cfg.myhostname or fqdn
        values["myorigin"] = cfg.myorigin or fqdn
        cfg = MailRelayClientConfig.model_validate(values)
    installed = host.get_fact(DebPackages)
    absent_package = "postfix" not in installed
    absent_tool = not host.get_fact(Which, command="postconf")
    state = probe(
        "if test -e /etc/postfix/main.cf || test -L /etc/postfix/main.cf; then echo present; else echo absent; fi",
        name="Postfix main configuration metadata",
    )
    if state not in ("present", "absent"):
        raise DeployError("Postfix main configuration state is unknown")
    bootstrap = absent_package and absent_tool and state == "absent"
    if state == "absent" and not bootstrap:
        raise DeployError("Existing Postfix installation lacks main.cf; explicit recovery is required")
    # Only initial package bootstrap seeds debconf. No postfix-account fact is
    # requested before the package has created its actual system identity.
    if bootstrap:
        content = (
            "postfix postfix/main_mailer_type select No configuration\n"
            f"postfix postfix/mailname string {cfg.myhostname}\n"
        )
        server.shell(
            name="Seed absent Postfix noninteractive package bootstrap",
            commands=["debconf-set-selections"],
            _stdin=StdinLines(content),
        )
    common.prerequisites(cfg.packages)
    if bootstrap:
        common.bootstrap_postfix(name="Create fresh Postfix main.cf from installed distribution defaults")
    common.configure(
        name="Reconcile only declared Postfix relay settings",
        payload={
            "kind": "relay",
            "files": [],
            "lines": [],
            "postfix": cfg.desired(),
            "units": ["postfix"],
            "restart_units": ["postfix"],
            "reload": False,
        },
    )
