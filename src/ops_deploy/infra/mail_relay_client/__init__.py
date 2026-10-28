"""Send-only alert mail relay, preserving declared Postfix settings."""

from .config import MailRelayClientConfig
from .deploy import deploy_mail_relay_client

__all__ = ["MailRelayClientConfig", "deploy_mail_relay_client"]
