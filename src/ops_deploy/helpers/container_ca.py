"""Read-only preconditions for explicitly prepared replacement container stores."""

import shlex
from collections.abc import Iterable
from pathlib import PurePosixPath

from pyinfra.operations import server

from ops_deploy.helpers.checks import mark_read_only


def require_container_ca_stores(root: PurePosixPath, containers: Iterable[str]) -> None:
    """Fail before service changes when an opted-in container store is missing."""
    for container in containers:
        store = root / container
        checks = " && ".join(
            f"test {kind} {shlex.quote(str(store / name))}"
            for kind, name in (("-s", "bundle.pem"), ("-d", "empty"), ("-s", "manifest.json"))
        )
        message = shlex.quote(f"Missing prepared container CA store {store}; run the managed CA preparation play first")
        mark_read_only(
            server.shell(
                name=f"Require prepared CA store {store}", commands=[f"{checks} || {{ echo {message} >&2; exit 1; }}"]
            )
        )
