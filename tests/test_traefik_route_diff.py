"""``--diff`` output of ``traefik_route``: never a basic-auth hash, other routes as before.

pyinfra's ``files.put`` logs a unified diff of the old and new file under
``--diff`` (``just pyinfra-check`` runs ``--dry --diff``). A route file that
holds an htpasswd hash, in the new content or on the host, is written with
``secret_file`` instead, which never shows content. These runs use
``Config(DIFF=True)`` and capture everything pyinfra logs, at debug level, in
both the plan and the execution phase.
"""

import logging
from io import StringIO
from typing import Any

import bcrypt
import pytest
from pydantic import SecretStr
from pyinfra.api import Config, deploy
from pyinfra.operations import files

from ops_deploy.helpers import BasicAuth, TraefikRoute, traefik_route
from ops_deploy.helpers.traefik import RouteRenderer, hash_password, render_route
from ops_deploy.services.chesslab.deploy import render_route as chesslab_route
from ops_deploy.services.native_app.render import render_route as native_app_route
from ops_deploy.services.work_app.deploy import render_route as work_app_route
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

PASSWORD = "diff-fixture-password"
AUTH = BasicAuth(user="admin", password=SecretStr(PASSWORD))
OLD_HASH = hash_password("diff-fixture-old-password")
CURRENT_HASH = hash_password(PASSWORD)
ROUTE_PATH = "/etc/traefik/dynamic/app.yml"
PLAIN = TraefikRoute(name="app", host="app.example.com", app_port=8000)
SECURED = PLAIN.model_copy(update={"basic_auth": AUTH})
RENDERERS: dict[str, RouteRenderer] = {
    "helpers": render_route,
    "native_app": native_app_route,
    "chesslab": chesslab_route,
    "work_app": work_app_route,
}


def run_diff(
    route: TraefikRoute, caplog: pytest.LogCaptureFixture, deployed: str | None = None, **kwargs: Any
) -> FakeRun:
    @deploy("Route")
    def _deploy() -> None:
        traefik_route(route, **kwargs)

    responses = {**fakehost.LINUX, **fakehost.service("traefik.service"), **fakehost.directory("/etc/traefik/dynamic")}
    if deployed is not None:
        responses.update(fakehost.file(ROUTE_PATH, deployed))
    caplog.set_level(logging.DEBUG)
    run = run_deploy_fake(_deploy, responses=responses, pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    return run


def assert_no_hash_logged(caplog: pytest.LogCaptureFixture) -> None:
    assert "$2" not in caplog.text
    assert "$2" not in "".join(str(record.args) for record in caplog.records)


def test_capture_sees_what_files_put_logs(caplog: pytest.LogCaptureFixture) -> None:
    # Guard against a vacuous pass: the same capture shows a hash files.put diffs.
    text = render_route(SECURED, OLD_HASH)

    @deploy("Put")
    def _deploy() -> None:
        files.put(name="Plain put", src=StringIO(text), dest="/etc/app.yml")

    caplog.set_level(logging.DEBUG)
    run = run_deploy_fake(_deploy, responses=dict(fakehost.LINUX), pyinfra_config=Config(DIFF=True))

    assert run.succeeded, run.error
    assert OLD_HASH in caplog.text


@pytest.mark.parametrize("renderer", RENDERERS.values(), ids=RENDERERS.keys())
@pytest.mark.parametrize("scenario", ["fresh", "rotated", "drift"])
def test_basic_auth_route_never_logs_a_hash(
    renderer: RouteRenderer, scenario: str, caplog: pytest.LogCaptureFixture
) -> None:
    # fresh: no file yet; rotated: an old password's hash; drift: the current
    # hash (reused) on another port.
    deployed = {
        "fresh": None,
        "rotated": renderer(SECURED, OLD_HASH),
        "drift": renderer(SECURED.model_copy(update={"app_port": 8001}), CURRENT_HASH),
    }[scenario]

    run = run_diff(SECURED, caplog, deployed, renderer=renderer)

    assert_no_hash_logged(caplog)
    assert run.changed_ops == ["Route | Write Traefik route app", "Route | Restart Traefik for app"]
    assert ROUTE_PATH not in run.uploaded_paths
    written = run.written(ROUTE_PATH).decode()
    (line,) = [line for line in written.splitlines() if '"admin:$2y$05$' in line]
    assert bcrypt.checkpw(PASSWORD.encode(), line.strip()[len('- "admin:') : -1].encode())
    if scenario == "drift":
        assert CURRENT_HASH in line  # reused, not re-hashed


def test_converged_basic_auth_route_is_unchanged_and_silent(caplog: pytest.LogCaptureFixture) -> None:
    run = run_diff(SECURED, caplog, render_route(SECURED, CURRENT_HASH))

    assert_no_hash_logged(caplog)
    assert run.changed_ops == []
    assert run.written_paths == []
    assert "systemctl restart traefik.service" not in run.executed_commands


def test_dropping_basic_auth_does_not_log_the_old_hash(caplog: pytest.LogCaptureFixture) -> None:
    run = run_diff(PLAIN, caplog, render_route(SECURED, OLD_HASH))

    assert_no_hash_logged(caplog)
    assert run.written(ROUTE_PATH).decode() == render_route(PLAIN, None)
    assert ROUTE_PATH not in run.uploaded_paths


def test_route_without_a_hash_still_shows_its_diff(caplog: pytest.LogCaptureFixture) -> None:
    run = run_diff(PLAIN.model_copy(update={"app_port": 9000}), caplog, render_route(PLAIN, None))

    assert "Will modify" in caplog.text
    assert 'url: "http://127.0.0.1:8000"' in caplog.text
    assert 'url: "http://127.0.0.1:9000"' in caplog.text
    assert run.uploaded_paths == [ROUTE_PATH]
    assert run.secret_files == []
    assert "systemctl restart traefik.service" in run.executed_commands


def test_route_without_a_hash_unchanged_is_still_a_no_op(caplog: pytest.LogCaptureFixture) -> None:
    run = run_diff(PLAIN, caplog, render_route(PLAIN, None))

    assert run.changed_ops == []
    assert run.written_paths == []
