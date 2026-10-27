"""Native Postfix edge relay with original TLS/auth/greylist/SRS policy."""

from .config import MailRelayConfig
from .deploy import deploy_mail_relay

__all__ = ["MailRelayConfig", "deploy_mail_relay"]
