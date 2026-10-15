"""chesslab: the Chesslab trainer (port of the chesslab_deploy role and its playbook wiring)."""

from ops_deploy.services.chesslab.deploy import ChesslabConfig, deploy_chesslab

__all__ = ["ChesslabConfig", "deploy_chesslab"]
