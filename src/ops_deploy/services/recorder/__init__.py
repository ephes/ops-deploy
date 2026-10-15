"""recorder: podcast recording backend, a static Go binary (port of the recorder_deploy role)."""

from ops_deploy.services.recorder.deploy import (
    CommandResult,
    CommandRunner,
    RecorderConfig,
    build,
    deploy_recorder,
    subprocess_runner,
)

__all__ = ["CommandResult", "CommandRunner", "RecorderConfig", "build", "deploy_recorder", "subprocess_runner"]
