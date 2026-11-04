"""Removal of the mail infrastructure (port of the ``mail_remove`` role)."""

from ops_deploy.services.mail_remove.remove import MailRemoveConfig, remove_mail

__all__ = ["MailRemoveConfig", "remove_mail"]
