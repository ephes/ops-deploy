"""Unit tests for the individual deploy helpers."""

import http.server
import io
import logging
import shlex
import shutil
import socket
import subprocess
import threading
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any

import bcrypt
import pytest
from pydantic import SecretStr, ValidationError
from pyinfra.api import deploy
from pyinfra.operations import files

from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    django_manage,
    http_check,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.systemd import unit_name
from ops_deploy.helpers.traefik import existing_hash, hash_password, render_route, resolve_hash
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

HOME = PurePosixPath("/home/app")
SITE = PurePosixPath("/home/app/site")


def run(body: Any, responses: dict[str, Any] | None = None) -> FakeRun:
    @deploy("Test")
    def _deploy() -> None:
        body()

    result = run_deploy_fake(_deploy, responses={**fakehost.LINUX, **(responses or {})})
    assert result.succeeded, result.error
    return result


# --- checks -----------------------------------------------------------------


def test_wait_port_runs_one_bash_loop_and_is_read_only() -> None:
    result = run(lambda: wait_port(8000, retries=3, delay=0.5))

    (command,) = result.executed_commands
    assert command.startswith("bash -c 'for i in $(seq 1 3); do (exec 3<>/dev/tcp/127.0.0.1/8000)")
    assert result.ops[0].read_only
    assert result.mutating_changed_ops == []


def test_http_check_accepts_any_listed_status() -> None:
    result = run(lambda: http_check("http://127.0.0.1:8000/health", status=[302, 200], host_header="app.example"))

    (command,) = result.executed_commands
    shell, flag, script = shlex.split(command)
    assert (shell, flag) == ("sh", "-c")
    assert "-H 'Host: app.example' http://127.0.0.1:8000/health" in script
    assert '[ "$code" = 200 ] || [ "$code" = 302 ]' in script
    assert result.ops[0].read_only


@pytest.fixture
def http_server() -> Iterator[int]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302 if self.path == "/redirect" else 200)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _run_locally(op: Any) -> subprocess.CompletedProcess[str]:
    (command,) = run(op).executed_commands
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, check=False)


@pytest.mark.skipif(shutil.which("curl") is None, reason="needs curl")
def test_http_check_script_against_a_real_server(http_server: int) -> None:
    url = f"http://127.0.0.1:{http_server}"

    assert _run_locally(lambda: http_check(f"{url}/", retries=1)).returncode == 0
    assert _run_locally(lambda: http_check(f"{url}/redirect", status=(200, 302), retries=1)).returncode == 0
    failed = _run_locally(lambda: http_check(f"{url}/redirect", retries=2, delay=0))
    assert failed.returncode == 1
    assert f"{url}/redirect answered 302, expected 200" in failed.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_wait_port_script_against_a_real_listener(http_server: int) -> None:
    assert _run_locally(lambda: wait_port(http_server, retries=1)).returncode == 0
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
    failed = _run_locally(lambda: wait_port(closed, retries=2, delay=0))
    assert failed.returncode == 1
    assert f"port 127.0.0.1:{closed} did not open" in failed.stderr


@pytest.mark.parametrize(
    "call",
    [
        lambda: wait_port(0),
        lambda: wait_port(80, host="a;b"),
        lambda: wait_port(80, retries=0),
        lambda: http_check("ftp://x/"),
        lambda: http_check("http://x/$(id)"),
        lambda: http_check("http://x/", status=[]),
        lambda: http_check("http://x/", status=99),
        lambda: http_check("http://x/", host_header="a b"),
        lambda: http_check("http://x/", delay=-1),
    ],
)
def test_check_arguments_are_validated(call: Any) -> None:
    with pytest.raises(ValueError, match="must"):
        call()


def test_plain_ops_are_not_read_only() -> None:
    result = run(lambda: files.directory(name="Make dir", path="/srv/x"))

    assert result.mutating_changed_ops == ["Test | Make dir"]


# --- systemd ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "unit"),
    [("app", "app.service"), ("app.service", "app.service"), ("app-backup.timer", "app-backup.timer")],
)
def test_unit_name(name: str, unit: str) -> None:
    assert unit_name(name) == unit


@pytest.mark.parametrize("name", ["", "a b", "../x", ".service", "x/y"])
def test_unit_name_rejects_invalid(name: str) -> None:
    with pytest.raises(ValueError, match="invalid systemd unit name"):
        unit_name(name)


def test_systemd_unit_writes_root_owned_file() -> None:
    result = run(lambda: systemd_unit("app", "[Unit]\n"))

    assert result.upload("/etc/systemd/system/app.service") == b"[Unit]\n"
    assert "chmod 644 /etc/systemd/system/app.service" in result.executed_commands
    assert "chown root:root /etc/systemd/system/app.service" in result.executed_commands


def _rollout_host(*, unit_content: str, running: bool = True) -> dict[str, Any]:
    return {
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.file("/etc/systemd/system/app.service", unit_content),
        **fakehost.service("app.service", running=running),
    }


def test_rollout_is_a_noop_when_nothing_changed() -> None:
    def body() -> None:
        service_rollout("app", units=[systemd_unit("app", "[Unit]\n")])

    result = run(body, _rollout_host(unit_content="[Unit]\n"))

    assert result.executed_commands == []


def test_rollout_always_restart_restarts_a_converged_service() -> None:
    def body() -> None:
        service_rollout("app", units=[systemd_unit("app", "[Unit]\n")], always_restart=True)

    result = run(body, _rollout_host(unit_content="[Unit]\n"))

    assert result.executed_commands == ["systemctl restart app.service"]


def test_rollout_starts_a_stopped_service_without_restarting_it() -> None:
    def body() -> None:
        service_rollout("app", units=[systemd_unit("app", "[Unit]\nchanged\n")])

    result = run(body, _rollout_host(unit_content="[Unit]\n", running=False))

    commands = result.executed_commands
    assert "systemctl daemon-reload" in commands
    assert "systemctl start app.service" in commands
    assert "systemctl restart app.service" not in commands


def test_rollout_always_restart_is_unconditional_even_after_start() -> None:
    def body() -> None:
        service_rollout("app", always_restart=True)

    result = run(body, fakehost.service("app.service", running=False))

    assert result.op("Test | Restart app.service").changed


def test_rollout_restart_when_triggers_without_daemon_reload() -> None:
    def body() -> None:
        env = files.put(src=io.StringIO("X=1\n"), dest="/home/app/.env")
        service_rollout("app", units=[systemd_unit("app", "[Unit]\n")], restart_when=[env])

    result = run(body, _rollout_host(unit_content="[Unit]\n"))

    assert "systemctl daemon-reload" not in result.executed_commands
    assert result.executed_commands[-1] == "systemctl restart app.service"


# --- users ------------------------------------------------------------------


def test_system_user_creates_group_user_and_directories_in_order() -> None:
    result = run(lambda: system_user("app", home=HOME, directories=[SITE, HOME]))

    commands = result.executed_commands
    assert commands[:2] == ["groupadd -r app", "useradd -d /home/app -s /bin/bash -g app -r -M app"]
    assert [c for c in commands if c.startswith("mkdir")] == ["mkdir -p /home/app", "mkdir -p /home/app/site"]


def test_system_user_is_a_noop_when_present() -> None:
    responses = {
        **fakehost.system_account("app", "/home/app"),
        **fakehost.directory("/home/app", user="app"),
        **fakehost.directory("/home/app/site", user="app"),
    }

    result = run(lambda: system_user("app", home=HOME, directories=[SITE]), responses)

    assert result.executed_commands == []


def test_existing_user_with_other_home_is_left_unchanged_with_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    responses = {
        **fakehost.system_account("app", "/srv/app", shell="/usr/sbin/nologin"),
        **fakehost.directory("/home/app", user="app"),
    }

    with caplog.at_level(logging.WARNING, logger="pyinfra"):
        result = run(lambda: system_user("app", home=HOME), responses)

    assert result.executed_commands == []
    assert not any("usermod" in command for command in result.executed_commands)
    messages = [record.getMessage() for record in caplog.records]
    assert any("existing user app has home '/srv/app', wanted '/home/app'" in m for m in messages)
    assert any("has shell '/usr/sbin/nologin', wanted '/bin/bash'" in m for m in messages)


def test_existing_user_is_only_added_to_a_missing_group() -> None:
    responses = {
        **fakehost.system_account("app", "/home/app"),
        "cat /etc/group": ["root:x:0:", "app:x:999:", "web:x:998:"],
        **fakehost.directory("/home/app", user="app"),
    }

    result = run(lambda: system_user("app", home=HOME, group="web"), responses)

    assert [c for c in result.executed_commands if c.startswith("usermod")] == ["usermod -a -G web app"]
    assert "chown app:app /home/app" not in result.executed_commands


# --- uv / django ------------------------------------------------------------


def test_uv_sync_without_gate_always_runs_as_service_user() -> None:
    venv = fakehost.venv("/home/app/site/.venv")

    result = run(lambda: uv_sync(SITE, user="app", home=HOME), venv)

    assert result.executed_commands == [
        "cd /home/app/site && runuser -u app -- env HOME=/home/app UV_PROJECT_ENVIRONMENT=/home/app/site/.venv "
        "/usr/local/bin/uv sync --frozen --no-dev --no-default-groups"
    ]


def test_uv_sync_gated_on_unchanged_ops_is_skipped_when_venv_exists() -> None:
    venv = fakehost.venv("/home/app/site/.venv")
    unchanged = fakehost.directory("/srv/src")

    def body() -> None:
        src = files.directory(path="/srv/src")
        uv_sync(SITE, user="app", home=HOME, when_changed=[src])

    result = run(body, {**venv, **unchanged})

    assert result.executed_commands == []


def test_django_manage_sources_env_file_on_target() -> None:
    def body() -> None:
        django_manage(
            SITE / "src",
            "migrate",
            "--noinput",
            user="app",
            home=HOME,
            venv=SITE / ".venv",
            env_file=SITE / ".env",
        )

    result = run(body)

    (command,) = result.executed_commands
    assert command == (
        "cd /home/app/site/src && runuser -u app -- env HOME=/home/app sh -c "
        '\'set -a; . /home/app/site/.env; set +a; export PATH=/home/app/site/.venv/bin:"$PATH"; '
        "export VIRTUAL_ENV=/home/app/site/.venv; exec ./manage.py migrate --noinput'"
    )


def test_django_manage_quotes_arguments() -> None:
    def body() -> None:
        django_manage(SITE, "shell", "-c", "print('x'); import os", user="app", home=HOME, venv=SITE / ".venv")

    (command,) = run(body).executed_commands
    runuser_argv = shlex.split(command.split(" && ", 1)[1])
    script = runuser_argv[-1]
    assert runuser_argv[-3:-1] == ["sh", "-c"]
    exec_argv = shlex.split(script[script.index("exec ") :])
    assert exec_argv == ["exec", "./manage.py", "shell", "-c", "print('x'); import os"]


def test_django_manage_needs_a_command() -> None:
    with pytest.raises(ValueError, match="management command"):
        django_manage(SITE, user="app", home=HOME, venv=SITE / ".venv")


# --- traefik ----------------------------------------------------------------

AUTH = BasicAuth(user="admin", password=SecretStr("fixture-password"))
# Output of `htpasswd -nbB admin fixture-password` (Apache 2.4), what the roles deploy.
HTPASSWD_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"


def test_hash_matches_htpasswd_format_and_verifies() -> None:
    hashed = hash_password("fixture-password")

    assert hashed.startswith("$2y$05$")
    assert len(hashed) == 60
    assert bcrypt.checkpw(b"fixture-password", hashed.encode())


def test_hash_from_htpasswd_is_reused() -> None:
    from_htpasswd = HTPASSWD_HASH
    lines = ["    users:", f'          - "admin:{from_htpasswd}"']

    assert existing_hash(lines, "admin") == from_htpasswd
    assert resolve_hash(AUTH, existing_hash(lines, "admin")) == from_htpasswd
    assert existing_hash(lines, "other") is None
    assert existing_hash(None, "admin") is None


def test_malformed_deployed_hash_is_replaced() -> None:
    malformed = "$2y$00$" + "a" * 53
    assert existing_hash([f'  - "admin:{malformed}"'], "admin") == malformed

    fresh = resolve_hash(AUTH, malformed)

    assert bcrypt.checkpw(b"fixture-password", fresh.encode())


def test_stale_hash_is_replaced() -> None:
    stale = hash_password("old-password")

    fresh = resolve_hash(AUTH, stale)

    assert fresh != stale
    assert bcrypt.checkpw(b"fixture-password", fresh.encode())


def test_route_without_auth_has_a_single_secure_router() -> None:
    import yaml

    text = render_route(TraefikRoute(name="app", host="app.example.com", app_port=8000), None)
    routers = yaml.safe_load(text)["http"]["routers"]

    assert set(routers) == {"app-secure", "app-http"}
    assert "auth" not in text


def test_render_route_requires_hash_exactly_with_auth() -> None:
    route = TraefikRoute(name="app", host="app.example.com", app_port=8000, basic_auth=AUTH)
    with pytest.raises(ValueError, match="exactly"):
        render_route(route, None)
    with pytest.raises(ValueError, match="exactly"):
        render_route(route.model_copy(update={"basic_auth": None}), "$2y$05$x")


@pytest.mark.parametrize(
    "override",
    [
        {"name": "App"},
        {"host": "app.example.com`) || Host(`evil"},
        {"internal_ip_ranges": ("not-a-network",)},
        {"internal_ip_ranges": ()},
        {"middlewares": ("a b",)},
        {"app_port": 0},
        {"frame_options": "ALLOW"},
        {"title": "x\rtcp:"},
        {"title": "x\ny"},
    ],
)
def test_route_rejects_unsafe_values(override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TraefikRoute.model_validate({"name": "app", "host": "app.example.com", "app_port": 8000, **override})


@pytest.mark.parametrize("password", ["", "x" * 73])
def test_basic_auth_rejects_unusable_passwords(password: str) -> None:
    with pytest.raises(ValidationError):
        BasicAuth(user="admin", password=SecretStr(password))


def test_traefik_route_with_restart_none_skips_traefik() -> None:
    route = TraefikRoute(name="app", host="app.example.com", app_port=8000)

    result = run(lambda: traefik_route(route, restart="none"), fakehost.service("traefik.service"))

    assert "systemctl restart traefik.service" not in result.executed_commands
    assert result.uploaded_paths == ["/etc/traefik/dynamic/app.yml"]


def test_traefik_route_custom_renderer_receives_hash() -> None:
    route = TraefikRoute(name="app", host="app.example.com", app_port=8000, basic_auth=AUTH)
    seen: list[str | None] = []

    def renderer(r: TraefikRoute, auth_hash: str | None) -> str:
        seen.append(auth_hash)
        return f"custom {r.name}\n"

    result = run(lambda: traefik_route(route, renderer=renderer), fakehost.service("traefik.service"))

    assert result.upload("/etc/traefik/dynamic/app.yml") == b"custom app\n"
    assert seen
    assert all(h is not None and h.startswith("$2y$05$") for h in seen)
    assert "systemctl restart traefik.service" in result.executed_commands
