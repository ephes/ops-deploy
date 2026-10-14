"""Node.js from one NodeSource release line (the ``nodejs_install`` role)."""

from __future__ import annotations

import shlex
from io import StringIO
from pathlib import PurePosixPath

from pydantic import Field
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import AbsolutePath, RoleConfig, output
from ops_deploy.helpers import mark_read_only


class NodejsInstallConfig(RoleConfig):
    major: int = Field(default=24, ge=1)
    key_url: str = Field(default="https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key", pattern=r"^https://\S+$")
    keyring: AbsolutePath = "/etc/apt/keyrings/nodesource.asc"
    sources_list: AbsolutePath = "/etc/apt/sources.list.d/nodesource.list"
    preferences: AbsolutePath = "/etc/apt/preferences.d/nodesource"

    @property
    def repo_url(self) -> str:
        return f"https://deb.nodesource.com/node_{self.major}.x"


def sources_line(cfg: NodejsInstallConfig) -> str:
    # One file with one line: a new ``major`` replaces the old release line.
    return f"deb [signed-by={cfg.keyring}] {cfg.repo_url} nodistro main\n"


# Without the pin a distribution Node.js newer than the selected line would
# replace the NodeSource package on the next apt upgrade.
PREFERENCES = "Package: nodejs\nPin: origin deb.nodesource.com\nPin-Priority: 700\n"


@deploy("Install Node.js")
def deploy_nodejs_install(cfg: NodejsInstallConfig) -> None:
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("nodejs_install needs a Debian-family host")

    apt.packages(name="Install ca-certificates", packages=["ca-certificates"], update=True, cache_time=3600)
    files.directory(
        name="Ensure apt keyrings directory",
        path=str(PurePosixPath(cfg.keyring).parent),
        user="root",
        group="root",
        mode="0755",
    )
    # Downloaded once, like the role's get_url without a checksum.
    files.download(
        name="Install NodeSource signing key",
        src=cfg.key_url,
        dest=cfg.keyring,
        user="root",
        group="root",
        mode="0644",
    )
    for path, content, label in (
        (cfg.sources_list, sources_line(cfg), "Configure NodeSource repository"),
        (cfg.preferences, PREFERENCES, "Prefer NodeSource for nodejs"),
    ):
        files.put(name=label, src=StringIO(content), dest=path, user="root", group="root", mode="0644")

    # ``nodejs=<major>.*`` with downgrades allowed, only when the installed
    # package is from another line. The NodeSource package ships npm and
    # replaces a distribution npm in the same transaction.
    status = output("dpkg-query -W -f '${Status} ${Version}' nodejs")
    if not status.startswith(f"install ok installed {cfg.major}."):
        server.shell(
            name=f"Install Node.js {cfg.major}.x",
            commands=[
                "apt-get update -q",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades "
                + shlex.quote(f"nodejs={cfg.major}.*"),
            ],
        )

    check = (
        f'v=$(/usr/bin/node --version) && case "$v" in v{cfg.major}.*) ;; '
        f'*) echo "expected /usr/bin/node v{cfg.major}.x, found $v" >&2; exit 1 ;; esac && /usr/bin/npm --version'
    )
    mark_read_only(server.shell(name=f"Check Node.js is v{cfg.major}.x", commands=[check]))
