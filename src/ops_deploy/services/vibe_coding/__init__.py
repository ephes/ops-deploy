"""vibe_coding: a dedicated interactive coding user (port of the ``vibe_coding_deploy`` role).

See :mod:`ops_deploy.services.vibe_coding.deploy` and docs/services/vibe_coding.md.
"""

from ops_deploy.services.vibe_coding.config import Dotfiles, VibeCodingConfig
from ops_deploy.services.vibe_coding.controller import prepare_dotfiles
from ops_deploy.services.vibe_coding.deploy import deploy_vibe_coding
from ops_deploy.services.vibe_coding.render import blockinfile, known_hosts, render, sshd_block

__all__ = [
    "Dotfiles",
    "VibeCodingConfig",
    "blockinfile",
    "deploy_vibe_coding",
    "known_hosts",
    "prepare_dotfiles",
    "render",
    "sshd_block",
]
