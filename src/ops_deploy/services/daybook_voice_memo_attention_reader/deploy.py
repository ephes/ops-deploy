"""Original guarded provisioner remains managed work, including exact repeats."""

from __future__ import annotations

import json
import shlex
from importlib.resources import files as resources

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import Directory, Link
from pyinfra.facts.server import Command
from pyinfra.operations import files

from ops_deploy.base._common import require_linux
from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin

from .config import DaybookVoiceMemoAttentionReaderConfig, DaybookVoiceMemoAttentionReaderCredentials

PACKAGE = "ops_deploy.services.daybook_voice_memo_attention_reader"


def payload(
    cfg: DaybookVoiceMemoAttentionReaderConfig, credentials: DaybookVoiceMemoAttentionReaderCredentials
) -> SecretContent:
    return SecretContent(
        json.dumps(
            {
                "access_key": credentials.access_key.get_secret_value(),
                "secret_key": credentials.secret_key.get_secret_value(),
                "mc_bin": cfg.mc_bin,
                "alias": cfg.alias,
                "state_dir": cfg.state_dir,
            }
        )
        + "\n"
    )


@deploy("Original dedicated Daybook attention reader access")
def install_daybook_voice_memo_attention_reader(
    cfg: DaybookVoiceMemoAttentionReaderConfig, credentials: DaybookVoiceMemoAttentionReaderCredentials
) -> None:
    require_linux("Daybook attention reader access")
    if host.get_fact(Command, command="/usr/bin/id -u") != "0":
        raise DeployError("Daybook attention reader access requires original root execution")
    directory = host.get_fact(Directory, path=cfg.state_dir)
    if directory is False or host.get_fact(Link, path=cfg.state_dir):
        raise DeployError("Dedicated attention reader state path must be a real directory")
    files.directory(
        name="Create original private attention reader ownership directory",
        path=cfg.state_dir,
        user="root",
        group="root",
        mode="0700",
    )
    helper = cfg.state_dir + "/provision_reader.py"
    files.put(
        name="Install original dedicated attention reader provisioner",
        src=str(resources(PACKAGE).joinpath("files/provision_reader.py")),
        dest=helper,
        user="root",
        group="root",
        mode="0700",
    )
    # Original provision() takes a private lock and can create an absent user.
    # Never execute it as a planning fact or label its repeat read-only.
    # It emits only fixed safe categories and its own changed boolean; pyinfra
    # still records the real managed verification operation on an exact repeat.
    secret_stdin(
        name="Provision and verify original dedicated attention reader permissions",
        command=shlex.join([cfg.python, helper]),
        content=payload(cfg, credentials),
    )
