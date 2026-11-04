"""chesslab: the Chesslab trainer (port of the chesslab_deploy role and its playbook wiring)."""

from ops_deploy.services.chesslab.deploy import ChesslabConfig, deploy_chesslab
from ops_deploy.services.chesslab.lifecycle import ChesslabBackupConfig, deploy_chesslab_backup

__all__ = ["ChesslabBackupConfig", "ChesslabConfig", "deploy_chesslab", "deploy_chesslab_backup"]
