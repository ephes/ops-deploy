"""Native Rspamd mail spam filtering role."""

from .config import MailSpamConfig
from .deploy import deploy_mail_spam

__all__ = ["MailSpamConfig", "deploy_mail_spam"]
