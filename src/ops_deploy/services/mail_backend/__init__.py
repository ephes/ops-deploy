"""Native Postfix/Dovecot/OpenDKIM backend role."""

from .config import MailBackendConfig
from .deploy import deploy_mail_backend

__all__ = ["MailBackendConfig", "deploy_mail_backend"]
