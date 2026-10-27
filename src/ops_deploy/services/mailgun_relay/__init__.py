"""Mailgun-compatible relay, its implementation switch and optional Traefik ingress."""

from ops_deploy.services.mailgun_relay.config import MailgunRelayConfig
from ops_deploy.services.mailgun_relay.deploy import deploy_mailgun_relay

__all__ = ["MailgunRelayConfig", "deploy_mailgun_relay"]
