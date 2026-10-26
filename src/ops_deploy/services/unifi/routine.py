"""Normal initialized-install package, Mongo configuration and HA convergence."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from importlib.resources import files as resources

from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt, files, server

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import service_rollout
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.ops import secret_file, secret_stdin

from .config import UnifiConfig

PACKAGE = resources("ops_deploy.services.unifi")
# Share the audited private mongosh client without invoking its CLI entry point.
CLIENT = PACKAGE.joinpath("files/preflight.py").read_text().split('if __name__ == "__main__":')[0]
HA = CLIENT + PACKAGE.joinpath("files/ha.py").read_text()
MONGO = PACKAGE.joinpath("files/mongo_config.py").read_text()


def command(source: str, *args: str) -> str:
    return shlex.join(["python3", "-I", "-c", source, *args])


def prepare_routine(cfg: UnifiConfig, stdin: str) -> tuple[bool, bool]:
    selection = cfg.routine
    assert selection is not None
    # Complete all safety probes before scheduling a write. A failed probe is
    # never interpreted as absence or drift.
    mongo = probe(command(MONGO, "check"), name="UniFi MongoDB configuration")
    ha = probe(command(HA, "check"), name="UniFi HA reconciliation", stdin=stdin)
    if mongo not in {"current", "pending"} or ha not in {"current", "pending", "no-site"}:
        raise DeployError("unifi: routine reconciliation probe failed")
    installed = probe(
        "if out=$(dpkg-query -W '-f=${Version}' unifi 2>/dev/null); then printf %s \"$out\"; "
        'else rc=$?; [ "$rc" = 1 ] && [ -z "$out" ] && echo absent; fi',
        name="UniFi package version",
    )
    if not installed:
        raise DeployError("unifi: installed package probe failed")
    server.group(name="Ensure UniFi service group", group="unifi", system=True)
    server.user(
        name="Ensure UniFi service account",
        user="unifi",
        group="unifi",
        home="/home/unifi",
        shell="/usr/sbin/nologin",
        system=True,
        create_home=True,
    )
    files.directory(
        name="Ensure UniFi package cache", path="/home/unifi/cache", user="unifi", group="unifi", mode="0755"
    )
    apt.packages(
        name="Ensure UniFi prerequisites and Java runtime",
        packages=[
            "ca-certificates",
            "apt-transport-https",
            "gnupg",
            "lsb-release",
            "curl",
            "wget",
            "software-properties-common",
            "openjdk-17-jre-headless",
            "whois",
        ],
    )
    files.download(
        name="Ensure MongoDB 8 repository key",
        src="https://www.mongodb.org/static/pgp/server-8.0.asc",
        dest="/usr/share/keyrings/mongodb-server-8.0.asc",
        mode="0644",
        user="root",
        group="root",
    )
    apt.repo(
        name="Ensure MongoDB 8 repository",
        src="deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.asc ] "
        "https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse",
        filename="mongodb-org",
    )
    apt.packages(
        name="Ensure MongoDB packages without patch upgrades",
        packages=["mongodb-org", "mongodb-org-server", "mongodb-org-shell", "mongodb-org-mongos", "mongodb-org-tools"],
    )
    mongo_write = server.shell(
        name="Reconcile UniFi MongoDB configuration",
        commands=[command(MONGO, "apply")],
        _if=lambda: mongo == "pending",
    )
    service_rollout("mongod", restart_when=(mongo_write,))
    verify_probe(command(MONGO, "check"), name="UniFi MongoDB configuration", expect="current")
    return installed.strip() != selection.package_version, installed.strip() == "absent"


def install_selected(
    cfg: UnifiConfig,
    needs_package: bool,
    missing_controller: bool,
    secrets: SecretValues,
) -> OperationMeta:
    selection = cfg.routine
    assert selection is not None
    package_path = f"/var/cache/ops-deploy-unifi/unifi_{selection.package_version}_all.deb"
    if needs_package:
        files.directory(
            name="Ensure protected UniFi package cache",
            path="/var/cache/ops-deploy-unifi",
            user="root",
            group="root",
            mode="0755",
        )
        files.download(
            name="Download selected UniFi package",
            src=selection.package_url,
            dest=package_path,
            sha256sum=selection.package_sha256,
            mode="0644",
            user="root",
            group="root",
        )
    install = PACKAGE.joinpath("files/install_package.py").read_text()
    return secret_stdin(
        name="Install selected UniFi package",
        command=command(install, package_path, selection.package_version, selection.package_sha256),
        content=SecretContent(
            json.dumps(
                {
                    "initialize": missing_controller,
                    "mongodb_password": secrets["mongodb_password"] if missing_controller else "",
                }
            )
        ),
        _if=lambda: needs_package,
    )


@operation()
def reconcile_ha(cfg: UnifiConfig, secrets: SecretValues) -> Generator[StringCommand, None, None]:
    """Evaluate after startup, including when the controller creates its first site."""
    from .deploy import payload

    stdin = payload(cfg, secrets)
    values = json.loads(stdin)
    if not values["create_homeassistant_user"]:
        return
    ha = probe(command(HA, "check"), name="UniFi HA reconciliation after startup", stdin=stdin)
    if ha not in {"current", "pending", "no-site"}:
        raise DeployError("unifi: HA reconciliation probe failed")
    if ha == "no-site":
        return
    if ha == "pending":
        yield StringCommand(command(HA, "apply"), **stdin_arguments(stdin))
    yield from secret_file._inner(
        path="/home/unifi/.homeassistant_unifi_password",
        content=SecretContent(values["homeassistant_password"]),
        user="unifi",
        group="unifi",
        mode="0600",
    )
