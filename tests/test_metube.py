"""Native MeTube config and exact role artifacts, including persistent-path guards."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import jinja2
import pytest
from pydantic import SecretStr

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.core.git_source import SourceTree
from ops_deploy.helpers import BasicAuth
from ops_deploy.services.metube import MetubeConfig, deploy_metube
from ops_deploy.services.metube.deploy import PACKAGE, render, render_env, render_unit, template_vars
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

VENDORED = Path(__file__).parent / "parity/ansible"
AUTH = BasicAuth(user="admin", password=SecretStr("owned-fixture-password"))


def role(template: str, cfg: MetubeConfig, auth: BasicAuth | None = None, auth_hash: str | None = None) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = bool
    env.filters["ternary"] = lambda value, yes, no: yes if value else no
    env.filters["to_json"] = json.dumps
    return env.get_template("metube_deploy__" + template).render(**template_vars(cfg, auth, auth_hash))


@pytest.mark.parametrize("port", [8081, 8083])
def test_env_and_unit_exact_role_parity(port: int) -> None:
    cfg = MetubeConfig(port=port)
    assert render_env(cfg) == role("metube.env.j2", cfg)
    assert render_unit(cfg) == role("metube.service.j2", cfg)


@pytest.mark.parametrize("auth", [None, AUTH])
def test_route_exact_role_parity(auth: BasicAuth | None) -> None:
    cfg = MetubeConfig()
    hashed = "$2y$05$fixture" if auth else None
    assert render(PACKAGE, "metube-traefik.yml.j2", **template_vars(cfg, auth, hashed)) == role(
        "metube-traefik.yml.j2", cfg, auth, hashed
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"site_path": "/"},
        {"env_dir": "/var/lib/metube"},
        {"env_dir": "/srv/metube"},
        {"build_root": "/opt/metube/ui"},
        {"download_dir": "/opt/metube/downloads"},
        {"state_dir": "/var/cache/metube/state"},
        {"home": "/opt"},
        {"temp_dir": "/a/../tmp"},
    ],
)
def test_refuses_source_or_staging_overlap_with_retained_data(changes: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        MetubeConfig(**changes)


def test_stale_candidate_lock_refused_before_any_host_command(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('[[package]]\nname="certifi"\nversion="2026.7.22"\n')
    with (
        patch("ops_deploy.services.metube.deploy.fetch_source", return_value=SourceTree(tmp_path, "a" * 40)),
        pytest.raises(ValueError, match="security floor"),
    ):
        run_deploy_fake(deploy_metube, MetubeConfig(), AUTH, responses=fakehost.LINUX)


def load_pipeline() -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/metube/files/pipeline.py"
    spec = importlib.util.spec_from_file_location("metube_pipeline", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failed_ui_without_browser_is_never_publishable(tmp_path: Path) -> None:
    pipeline = load_pipeline()
    tree = tmp_path / "ui/dist/metube"
    tree.mkdir(parents=True)
    (tree / ".metube-ui-rev").write_text("a" * 40)
    assert not pipeline.ui_good(tmp_path, "a" * 40)
    (tree / "browser").mkdir()
    (tree / "browser/index.html").write_text("<html>owned fixture</html>")
    assert pipeline.ui_good(tmp_path, "a" * 40)
    assert not pipeline.ui_good(tmp_path, "b" * 40)


def test_queue_probe_refuses_pending_without_changing_history() -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    history = {"queue": [], "pending": [{"owned": "fixture"}], "done": []}
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(history).encode())

        def log_message(self, _format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        with pytest.raises(RuntimeError, match="active/queued work"):
            load_pipeline().quiet({"health_url": f"http://127.0.0.1:{server.server_port}/"})
        assert requests == ["/history"]
        assert history["pending"] == [{"owned": "fixture"}]
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_pipeline_failure_stops_live_configuration_and_rollout(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n")
    responses = {
        "apply stage": {"success": False, "stderr": "owned staged build failure"},
        "/usr/local/bin/uv --version": ["uv 0.13.4 (x86_64-unknown-linux-gnu)"],
        "node --version": ["v24.22.1"],
        **fakehost.stat("/usr/local/bin/uvx"),
        **fakehost.LINUX,
    }
    with patch("ops_deploy.services.metube.deploy.fetch_source", return_value=SourceTree(tmp_path, "a" * 40)):
        run = run_deploy_fake(deploy_metube, MetubeConfig(extra_groups=()), AUTH, responses=responses)
    assert not run.succeeded
    commands = run.executed_commands
    assert any("apply stage" in command for command in commands)
    assert not any("apply live" in command for command in commands)
    assert not any("systemctl restart metube" in command for command in commands)
    assert not any(path == "/etc/metube/metube.env" for path, _data in run.uploads)
    assert not any(path == "/etc/traefik/dynamic/metube.yml" for path, _data in run.uploads)


@pytest.mark.parametrize("drift", ["none", "env-content", "env-mode"])
def test_rollout_guard_only_queries_busy_queue_for_actual_live_drift(drift: str) -> None:
    from pyinfra.api import deploy

    from ops_deploy.services.metube.deploy import _rollout_guard, pipeline_config

    cfg = MetubeConfig(extra_groups=())
    env = render_env(cfg) if drift != "env-content" else "owned changed environment\n"
    responses = {
        "status live": ["current"],
        **fakehost.file(str(cfg.env_file), env, mode="-rw-------" if drift == "env-mode" else "-rw-r--r--"),
        **fakehost.file("/etc/systemd/system/metube.service", render_unit(cfg)),
    }

    @deploy("Guard fixture")
    def guard() -> None:
        _rollout_guard(cfg=cfg, data=pipeline_config(cfg, "a" * 40, "b" * 64))

    run = run_deploy_fake(guard, responses=responses)
    assert run.succeeded
    commands = [command for command in run.executed_commands if "quiet live" in command]
    if drift == "none":
        assert commands == []
    else:
        assert len(commands) == 1
        assert "systemctl is-active --quiet metube" in commands[0]
