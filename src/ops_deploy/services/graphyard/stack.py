"""graphyard stack: core, Vector, ingress and auth bootstrap in the playbook's order (``deploy-graphyard.yml``)."""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from pyinfra.api import deploy

from ops_deploy.base import RoleConfig
from ops_deploy.core.rsync import RsyncRunner, run_checked, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretValues
from ops_deploy.ops.sync_tree import MANDATORY_EXCLUDES
from ops_deploy.services.graphyard.auth import GraphyardAuthConfig, auth_steps
from ops_deploy.services.graphyard.core import GraphyardConfig, core_steps
from ops_deploy.services.graphyard.ingress import GraphyardIngressConfig, ingress_steps
from ops_deploy.services.graphyard.vector import GraphyardVectorConfig, vector_steps


class GraphyardStackConfig(RoleConfig):
    core: GraphyardConfig
    vector: GraphyardVectorConfig
    ingress: GraphyardIngressConfig
    auth: GraphyardAuthConfig


@deploy("Deploy graphyard")
def deploy_graphyard(
    cfg: GraphyardStackConfig,
    secrets: SecretValues,
    rsync: RsyncRunner = subprocess_rsync_runner,
) -> None:
    """One secrets mapping holds every part's keys (core, ``vector_ingest_token``,
    ``basic_auth_password``/``basic_auth_user``, the bootstrap credentials)."""

    core_steps(cfg.core, secrets, rsync)
    vector_steps(cfg.vector, secrets)
    ingress_steps(cfg.ingress, secrets)
    auth_steps(cfg.auth, secrets, incoming=incoming_provisioning(cfg, rsync))


def incoming_provisioning(cfg: GraphyardStackConfig, rsync: RsyncRunner = subprocess_rsync_runner) -> str | None:
    """The datasource provisioning file the core's source sync installs, if the sync owns it.

    The auth step plans against the file on the host, which the sync may
    replace in the same run.
    """

    path = cfg.auth.grafana_datasource_provisioning_path
    if not path.is_relative_to(cfg.core.site_path):
        return None
    relative = path.relative_to(cfg.core.site_path)
    source = cfg.core.source_path / relative
    if not source.is_file() or rsync_excluded(
        cfg.core.source_path, relative, (*MANDATORY_EXCLUDES, *cfg.core.source_excludes), rsync
    ):
        return None
    return source.read_text(encoding="utf-8")


def rsync_excluded(
    source: Path, relative: PurePosixPath, patterns: Sequence[str], rsync: RsyncRunner = subprocess_rsync_runner
) -> bool:
    """Whether rsync with these ``--exclude`` ``patterns`` leaves ``source/relative`` out.

    Asks the controller's rsync itself (a dry run into an empty directory), so
    the answer follows rsync's own pattern rules.
    """

    with tempfile.TemporaryDirectory(prefix="graphyard-excludes-") as empty:
        argv = ["rsync", "-rl", "--dry-run", "--out-format=%n", *(f"--exclude={p}" for p in patterns)]
        listed = run_checked(rsync, [*argv, f"{source}/", f"{empty}/"]).stdout.splitlines()
    return str(relative) not in listed
