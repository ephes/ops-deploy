"""The compose_app host scripts, run as shipped (``python3 -I -c <source> <mode>``, request on stdin).

``compose_host.py`` against a temporary directory (owned by the test user),
``qbittorrent_prefs.py`` against a small fake WebUI in qBittorrent 5.2's
dialect (204 logins, a session cookie, host header checks).
"""

from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

from ops_deploy.services.compose_app.state import COMPOSE_HOST, QBITTORRENT

USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name


def run(source: str, mode: str, request: dict[str, Any], **env: str) -> subprocess.CompletedProcess[str]:
    stdin = base64.encodebytes(json.dumps(request).encode()).decode()
    return subprocess.run(
        [sys.executable, "-I", "-c", source, mode],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **env},
    )


@pytest.fixture
def site(tmp_path: Path) -> Path:
    # Resolve /var -> /private/var on macOS: the scripts refuse symlinks on the path.
    return tmp_path.resolve()


def env_request(site: Path, *, uid: str = USER) -> dict[str, Any]:
    return {
        "ids": [["user", uid], ["group", GROUP]],
        "files": [
            {
                "path": str(site / "vpn.env"),
                "mode": "0600",
                "owner": USER,
                "group": GROUP,
                "segments": [
                    ["text", "KEY='x'\nROLE='{\"apikey\":\""],
                    ["host_secret", str(site / "apikey"), 24],
                    ["text", "\"}'\nPUID='"],
                    ["user", uid],
                    ["text", "'\n"],
                ],
            }
        ],
    }


def test_render_probe_changes_nothing_and_apply_creates_the_host_secret_once(site: Path) -> None:
    probe = run(COMPOSE_HOST, "render-probe", env_request(site))
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.splitlines() == [
        f"id user:{USER} {os.getuid()}",
        f"id group:{GROUP} {os.getgid()}",
        f"file {site}/vpn.env differs",
    ]
    assert not (site / "apikey").exists()

    applied = run(COMPOSE_HOST, "render-apply", env_request(site))
    assert applied.returncode == 0, applied.stderr
    assert applied.stdout.splitlines()[-1] == f"file {site}/vpn.env changed"
    key = (site / "apikey").read_text()
    assert key.endswith("\n")
    assert len(key.strip()) == 32
    assert oct((site / "apikey").stat().st_mode & 0o777) == "0o600"
    text = (site / "vpn.env").read_text()
    assert text == f"KEY='x'\nROLE='{{\"apikey\":\"{key.strip()}\"}}'\nPUID='{os.getuid()}'\n"
    assert oct((site / "vpn.env").stat().st_mode & 0o777) == "0o600"
    assert key.strip() not in applied.stdout + applied.stderr

    again = run(COMPOSE_HOST, "render-apply", env_request(site))
    assert again.stdout.splitlines()[-1] == f"file {site}/vpn.env noop"
    assert (site / "apikey").read_text() == key
    assert run(COMPOSE_HOST, "render-probe", env_request(site)).stdout.splitlines()[-1].endswith(" same")


def test_an_existing_host_secret_is_adopted_unchanged(site: Path) -> None:
    (site / "apikey").write_text("adopted-key_0123456789\n")

    run(COMPOSE_HOST, "render-apply", env_request(site))

    assert (site / "apikey").read_text() == "adopted-key_0123456789\n"
    assert '"apikey":"adopted-key_0123456789"' in (site / "vpn.env").read_text()


def test_a_host_secret_an_env_file_cannot_carry_is_refused_without_printing_it(site: Path) -> None:
    (site / "apikey").write_text("bad'key\n")

    result = run(COMPOSE_HOST, "render-apply", env_request(site))

    assert result.returncode == 1
    assert "holds characters an env file cannot carry" in result.stderr
    assert "bad'key" not in result.stderr + result.stdout
    assert not (site / "vpn.env").exists()


def test_a_missing_user_makes_the_probe_differ_and_the_apply_fail(site: Path) -> None:
    probe = run(COMPOSE_HOST, "render-probe", env_request(site, uid="no-such-user-x"))
    assert "id user:no-such-user-x missing" in probe.stdout.splitlines()
    assert probe.stdout.splitlines()[-1].endswith(" differs")

    applied = run(COMPOSE_HOST, "render-apply", env_request(site, uid="no-such-user-x"))
    assert applied.returncode == 1
    assert "no user no-such-user-x" in applied.stderr


def test_a_symlinked_destination_is_refused(site: Path) -> None:
    (site / "elsewhere").write_text("keep\n")
    (site / "vpn.env").symlink_to(site / "elsewhere")

    result = run(COMPOSE_HOST, "render-apply", env_request(site))

    assert result.returncode == 1
    assert "is a symlink" in result.stderr
    assert (site / "elsewhere").read_text() == "keep\n"


def test_the_stamp_records_the_host_ids_and_clears_pending(site: Path) -> None:
    state = site / "state"
    state.mkdir(mode=0o700)
    (state / "pending").touch()

    result = run(
        COMPOSE_HOST,
        "stamp",
        {"state_dir": str(state), "stamp": {"version": 1, "files": {"a": "b"}}, "ids": [["user", USER]]},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "stamp written\n"
    assert json.loads((state / "applied.json").read_text()) == {
        "files": {"a": "b"},
        "ids": {f"user:{USER}": os.getuid()},
        "version": 1,
    }
    assert not (state / "pending").exists()


def test_secret_owners_probe_reports_without_changing_anything(site: Path) -> None:
    secret = site / "app-apikey"
    secret.write_text("value\n")
    secret.chmod(0o640)
    request = {"paths": [str(secret), str(site / "missing-apikey"), str(site / "gone" / "apikey")]}

    result = run(COMPOSE_HOST, "secrets-probe", request)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"secret {secret} differs",
        f"secret {site / 'missing-apikey'} missing",
        f"secret {site / 'gone' / 'apikey'} missing",
    ]
    assert stat.S_IMODE(secret.stat().st_mode) == 0o640
    assert "value" not in result.stdout + result.stderr
    # A missing secret is never created.
    assert run(COMPOSE_HOST, "secrets-apply", {"paths": [str(site / "missing-apikey")]}).stdout == (
        f"secret {site / 'missing-apikey'} missing\n"
    )
    assert not (site / "missing-apikey").exists()


@pytest.mark.parametrize("mode", ["secrets-probe", "secrets-apply"])
def test_secret_owners_refuse_symlinks_on_the_path(site: Path, mode: str) -> None:
    (site / "elsewhere").write_text("keep\n")
    (site / "elsewhere").chmod(0o644)
    (site / "app-apikey").symlink_to(site / "elsewhere")
    (site / "real").mkdir()
    (site / "real" / "apikey").write_text("keep\n")
    (site / "linked").symlink_to(site / "real")

    for path in (site / "app-apikey", site / "linked" / "apikey"):
        result = run(COMPOSE_HOST, mode, {"paths": [str(path)]})
        assert result.returncode == 1
        assert "symlink" in result.stderr or "not a plain directory" in result.stderr
    assert stat.S_IMODE((site / "elsewhere").stat().st_mode) == 0o644


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to root needs root")
def test_secret_owners_apply_sets_root_0600(site: Path) -> None:
    secret = site / "app-apikey"
    secret.write_text("value\n")
    os.chown(secret, 1, 1)
    secret.chmod(0o640)

    assert run(COMPOSE_HOST, "secrets-apply", {"paths": [str(secret)]}).stdout == f"secret {secret} changed\n"
    info = secret.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o600)
    assert run(COMPOSE_HOST, "secrets-probe", {"paths": [str(secret)]}).stdout == f"secret {secret} same\n"


def copy_request(site: Path, wait: int = 1) -> dict[str, Any]:
    return {
        "source": str(site / "ServerConfig.json"),
        "keys": ["APIKey", "ApiKey"],
        "dest": str(site / "jackett.json"),
        "template": {"api_key": "{value}", "url": "http://127.0.0.1:9117", "tracker_first": False, "thread_count": 20},
        "owner": USER,
        "group": GROUP,
        "mode": "0640",
        "wait": wait,
    }


def test_key_copy_waits_for_the_source_then_writes_the_plugin_config(site: Path) -> None:
    assert run(COMPOSE_HOST, "copy-probe", copy_request(site)).stdout == "waiting\n"
    failed = run(COMPOSE_HOST, "copy-apply", copy_request(site))
    assert failed.returncode == 1
    assert "no key in" in failed.stderr

    (site / "ServerConfig.json").write_text(json.dumps({"Port": 9117, "APIKey": "fixturekey0123"}))
    assert run(COMPOSE_HOST, "copy-probe", copy_request(site)).stdout == "differs\n"
    applied = run(COMPOSE_HOST, "copy-apply", copy_request(site))

    assert applied.stdout == "changed\n"
    # The playbook's jackett.json, byte for byte.
    assert (site / "jackett.json").read_text() == (
        "{\n"
        '    "api_key": "fixturekey0123",\n'
        '    "url": "http://127.0.0.1:9117",\n'
        '    "tracker_first": false,\n'
        '    "thread_count": 20\n'
        "}\n"
    )
    assert oct((site / "jackett.json").stat().st_mode & 0o777) == "0o640"
    assert run(COMPOSE_HOST, "copy-probe", copy_request(site)).stdout == "same\n"
    assert run(COMPOSE_HOST, "copy-apply", copy_request(site)).stdout == "noop\n"


# -- qBittorrent ----------------------------------------------------------------


class FakeWebUI:
    """qBittorrent 5.2's WebUI as the script uses it."""

    def __init__(self) -> None:
        self.credentials = ("admin", "TEMP0123")
        self.prefs: dict[str, Any] = {"save_path": "/downloads/", "listen_port": 6881, "upnp": True}
        self.sessions: set[str] = set()
        self.bad_hosts = 0
        self.sets = 0
        self.types: dict[str, str] = {}


@pytest.fixture
def webui() -> Iterator[tuple[FakeWebUI, int]]:
    ui = FakeWebUI()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _authed(self) -> bool:
            return any(f"QBT_SID_8080={sid}" in (self.headers.get("Cookie") or "") for sid in ui.sessions)

        def _reply(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.headers.get("Host") != "localhost":
                ui.bad_hosts += 1
                self._reply(401)
            elif self.path == "/":
                self._reply(200, b"<html>login</html>")
            elif self.path == "/api/v2/app/preferences" and self._authed():
                self._reply(200, json.dumps(ui.prefs).encode())
            else:
                self._reply(403)

        def do_POST(self) -> None:
            form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if self.headers.get("Host") != "localhost":
                ui.bad_hosts += 1
                self._reply(401)
            elif self.path == "/api/v2/auth/login":
                if (form["username"][0], form["password"][0]) == ui.credentials:
                    sid = f"sid{len(ui.sessions)}"
                    ui.sessions.add(sid)
                    self._reply(204, headers={"Set-Cookie": f"QBT_SID_8080={sid}; HttpOnly; path=/; SameSite=Strict"})
                else:
                    self._reply(401)
            elif self.path == "/api/v2/app/setPreferences" and self._authed():
                values = json.loads(form["json"][0])
                ui.sets += 1
                if "web_ui_username" in values:
                    ui.credentials = (values["web_ui_username"], values["web_ui_password"])
                ui.types.update({k: type(v).__name__ for k, v in values.items()})
                ui.prefs.update({k: v for k, v in values.items() if not k.startswith("web_ui_")})
                self._reply(200)
            else:
                self._reply(403)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ui, server.server_address[1]
    finally:
        server.shutdown()


@pytest.fixture
def docker_log(site: Path) -> dict[str, str]:
    """A ``docker`` on PATH whose ``compose logs`` prints qBittorrent's temporary password line."""

    bin_dir = site / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\necho 'The WebUI administrator username is: admin'\n"
        "echo 'A temporary password is provided for this session: TEMP0123'\n"
    )
    docker.chmod(0o755)
    return {"PATH": f"{bin_dir}:{os.environ['PATH']}"}


def qbt_request(port: int, **prefs: Any) -> dict[str, Any]:
    return {
        "port": port,
        "username": "fixture-user",
        "password": "fixture-password-0123",
        "preferences": prefs or {"save_path": "/downloads", "listen_port": 40000, "upnp": False},
        "project": "vpnstack",
        "compose_file": "/srv/compose.yml",
        "service": "client",
        "wait": 5,
    }


def test_first_run_bootstraps_the_credentials_and_sets_the_preferences(
    webui: tuple[FakeWebUI, int], docker_log: dict[str, str]
) -> None:
    ui, port = webui

    probe = run(QBITTORRENT, "probe", qbt_request(port), **docker_log)
    assert probe.stdout == "drift credentials\n"

    applied = run(QBITTORRENT, "apply", qbt_request(port), **docker_log)

    assert applied.returncode == 0, applied.stderr
    assert applied.stdout == "changed\n"
    assert ui.credentials == ("fixture-user", "fixture-password-0123")
    assert ui.prefs == {"save_path": "/downloads", "listen_port": 40000, "upnp": False}
    # Sent as a JSON number (qBittorrent rejects or never matches a string port).
    assert ui.types["listen_port"] == "int"
    # Every request carried Host: localhost (host header validation stays on).
    assert ui.bad_hosts == 0
    for text in ("fixture-password-0123", "TEMP0123"):
        assert text not in applied.stdout + applied.stderr + probe.stdout + probe.stderr


def test_converged_preferences_are_current_and_a_noop(webui: tuple[FakeWebUI, int]) -> None:
    ui, port = webui
    ui.credentials = ("fixture-user", "fixture-password-0123")
    # A trailing slash on a path is no drift.
    ui.prefs = {"save_path": "/downloads/", "listen_port": 40000, "upnp": False, "other": 1}

    assert run(QBITTORRENT, "probe", qbt_request(port)).stdout == "current\n"
    assert run(QBITTORRENT, "apply", qbt_request(port)).stdout == "noop\n"
    assert ui.sets == 0


def test_drift_is_named_by_key_and_corrected(webui: tuple[FakeWebUI, int]) -> None:
    ui, port = webui
    ui.credentials = ("fixture-user", "fixture-password-0123")
    ui.prefs = {"save_path": "/downloads", "listen_port": 6881, "upnp": True}

    assert run(QBITTORRENT, "probe", qbt_request(port)).stdout == "drift listen_port upnp\n"
    assert run(QBITTORRENT, "apply", qbt_request(port)).stdout == "changed\n"
    assert ui.prefs["listen_port"] == 40000


def test_a_webui_that_is_down_fails_the_probe(site: Path) -> None:
    result = run(QBITTORRENT, "probe", qbt_request(1))

    assert result.returncode == 1
    assert "does not answer 200" in result.stderr


def test_probes_before_the_first_deploy_report_differs_for_owners_not_created_yet(site: Path) -> None:
    request = copy_request(site)
    request["owner"] = "no-such-user-x"
    (site / "ServerConfig.json").write_text(json.dumps({"APIKey": "k"}))
    assert run(COMPOSE_HOST, "copy-probe", request).stdout == "differs\n"

    env = env_request(site)
    env["files"][0]["owner"] = "no-such-user-x"
    probe = run(COMPOSE_HOST, "render-probe", env)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.splitlines()[-1].endswith(" differs")
    assert run(COMPOSE_HOST, "copy-apply", request).returncode == 1


def test_the_key_copy_keeps_the_template_order_through_the_deploy_payload(site: Path) -> None:
    from ops_deploy.services.compose_app.state import payload

    request = copy_request(site)
    (site / "ServerConfig.json").write_text(json.dumps({"APIKey": "k"}))
    stdin = payload(request)
    result = subprocess.run(
        [sys.executable, "-I", "-c", COMPOSE_HOST, "copy-apply"],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.stdout == "changed\n", result.stderr
    assert list(json.loads((site / "jackett.json").read_text())) == ["api_key", "url", "tracker_first", "thread_count"]


def test_a_temporary_password_that_fails_is_never_printed(
    webui: tuple[FakeWebUI, int], docker_log: dict[str, str]
) -> None:
    ui, port = webui
    ui.credentials = ("someone", "else-0123")

    result = run(QBITTORRENT, "apply", qbt_request(port), **docker_log)

    assert result.returncode == 1
    assert "the temporary password does not log in" in result.stderr
    for text in ("TEMP0123", "temporary password is provided", "fixture-password-0123"):
        assert text not in result.stdout + result.stderr
