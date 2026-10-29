"""Configure the original mail pull/snapshot policy; never stage or read mail on deploy."""

from pydantic import SecretStr
from pyinfra.api import deploy
from pyinfra.operations import files

from .common import mail_key_input, prerequisites, resource, timer
from .config import MailReplicationConfig
from .offsite import prepare


@deploy("Configure original mail offsite pull")
def deploy_mail_replication(cfg: MailReplicationConfig, key: SecretStr | None = None) -> None:
    if not cfg.enabled:
        return
    material = mail_key_input(key) if cfg.ssh_key_manage else None
    prerequisites(cfg)
    prepare(cfg, material)
    for subdir in (cfg.destination_vmail_subdir, cfg.destination_stage_subdir):
        files.directory(
            name="Original offsite mail destination directory metadata",
            path=cfg.destination_path + "/" + subdir,
            user=cfg.destination_owner,
            group=cfg.destination_group,
            mode=cfg.destination_mode,
        )
    triggers = [resource(cfg, "mail-offsite-replication.sh", cfg.script_path)]
    if cfg.alert_enabled:
        triggers.append(resource(cfg, "mail-offsite-alert.sh", cfg.alert_script_path))
    timer(cfg, "mail-offsite", restart_when=triggers)
