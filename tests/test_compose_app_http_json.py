"""The ``http_json_settings``/``http_json_items`` host script against a small fake Servarr API.

The fake speaks the parts of Radarr/Sonarr/Prowlarr's v3/v1 API the kinds use:
``X-Api-Key`` auth, a settings object with an ``id``, collections with
``fields`` lists, a ``schema`` endpoint, tags, and passwords masked as
``********`` on reads.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretValues
from ops_deploy.services.compose_app import ComposeAppConfig, HttpJsonItems, HttpJsonSettings
from ops_deploy.services.compose_app.state import HTTP_JSON
from ops_deploy.services.compose_app.steps import _http_json_request
from tests.compose_app_fixtures import stack_config, values

KEY = "fixture-api-key-0123456789"
PASSWORD = "fixture-client-password-0123"
MASK = "********"


def run(mode: str, request: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    stdin = base64.encodebytes(json.dumps(request).encode()).decode()
    return subprocess.run(
        [sys.executable, "-I", "-c", HTTP_JSON, mode],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
        env=dict(os.environ),
    )


class FakeServarr:
    def __init__(self) -> None:
        self.host = {"id": 1, "bindAddress": "*", "authenticationMethod": "none", "username": "", "password": ""}
        self.clients: list[dict[str, Any]] = [
            {
                "id": 7,
                "name": "Keep me",
                "implementation": "Transmission",
                "fields": [{"name": "host", "value": "elsewhere"}],
                "tags": [],
            }
        ]
        self.schema = [
            {
                "id": 0,
                "implementation": "QBittorrent",
                "configContract": "QBittorrentSettings",
                "enable": True,
                "fields": [
                    {"name": "host", "value": "localhost"},
                    {"name": "port", "value": 8080},
                    {"name": "password", "value": ""},
                    {"name": "movieCategory", "value": "radarr"},
                ],
                "tags": [],
            }
        ]
        self.tags: list[dict[str, Any]] = []
        self.writes: list[tuple[str, str]] = []
        self.secrets_seen: dict[str, Any] = {}
        self.queries: list[str] = []

    def masked(self, item: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = json.loads(json.dumps(item))
        if out.get("password"):
            out["password"] = MASK
        for field in out.get("fields", []):
            if field["name"] == "password" and field["value"]:
                field["value"] = MASK
        return out

    def store(self, current: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        """Like Servarr: a masked value keeps the stored one."""

        out: dict[str, Any] = json.loads(json.dumps(body))
        if out.get("password") == MASK:
            out["password"] = current.get("password", "")
        old = {f["name"]: f["value"] for f in current.get("fields", [])}
        for field in out.get("fields", []):
            if field["value"] == MASK:
                field["value"] = old.get(field["name"], "")
        return out


@pytest.fixture
def api() -> Iterator[tuple[FakeServarr, int]]:
    fake = FakeServarr()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _reply(self, status: int, body: Any = None) -> None:
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _authed(self) -> bool:
            return self.headers.get("X-Api-Key") == KEY

        def _body(self) -> Any:
            return json.loads(self.rfile.read(int(self.headers["Content-Length"])))

        def do_GET(self) -> None:
            path = self.path.split("?")[0]
            if not self._authed():
                self._reply(401)
            elif path == "/api/v3/config/host":
                self._reply(200, fake.masked(fake.host))
            elif path == "/api/v3/downloadclient":
                self._reply(200, [fake.masked(c) for c in fake.clients])
            elif path == "/api/v3/downloadclient/schema":
                self._reply(200, fake.schema)
            elif path == "/api/v3/tag":
                self._reply(200, fake.tags)
            else:
                self._reply(404)

        def do_POST(self) -> None:
            path, _, query = self.path.partition("?")
            fake.queries.append(query)
            if not self._authed():
                self._reply(401)
                return
            body = self._body()
            fake.writes.append(("POST", path))
            if path == "/api/v3/downloadclient":
                body["id"] = 100 + len(fake.clients)
                fake.clients.append(body)
                self._reply(201, fake.masked(body))
            elif path == "/api/v3/tag":
                tag = {"id": len(fake.tags) + 1, "label": body["label"]}
                fake.tags.append(tag)
                self._reply(201, tag)
            else:
                self._reply(404)

        def do_PUT(self) -> None:
            path, _, query = self.path.partition("?")
            fake.queries.append(query)
            if not self._authed():
                self._reply(401)
                return
            body = self._body()
            fake.writes.append(("PUT", path))
            if path == "/api/v3/config/host/1":
                fake.host = fake.store(fake.host, body)
                self._reply(202, fake.masked(fake.host))
            elif path.startswith("/api/v3/downloadclient/"):
                item_id = int(path.rsplit("/", 1)[1])
                index = next(i for i, c in enumerate(fake.clients) if c["id"] == item_id)
                fake.clients[index] = fake.store(fake.clients[index], body)
                self._reply(202, fake.masked(fake.clients[index]))
            else:
                self._reply(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fake, server.server_address[1]
    finally:
        server.shutdown()


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    path = tmp_path / "apikey"
    path.write_text(KEY + "\n")
    return path


def base(port: int, keyfile: Path, tmp_path: Path, **extra: Any) -> dict[str, Any]:
    return {
        "name": "fixture step",
        "port": port,
        "prefix": "/api/v3",
        "auth": {"header": "X-Api-Key", "value": {"host_secret": str(keyfile)}},
        "write_only": [],
        "wait": 5,
        "state": str(tmp_path / "state" / "http_json.json"),
        **extra,
    }


def settings_request(port: int, keyfile: Path, tmp_path: Path, **desired: Any) -> dict[str, Any]:
    return base(
        port,
        keyfile,
        tmp_path,
        path="/config/host",
        desired=desired or {"authenticationMethod": "forms", "username": "owner", "password": PASSWORD},
        write_only=["password"],
    )


def items_request(port: int, keyfile: Path, tmp_path: Path, **changes: Any) -> dict[str, Any]:
    item = {
        "name": "qBittorrent",
        "implementation": "QBittorrent",
        "enable": True,
        "fields": {"host": "gluetun", "port": 8080, "password": PASSWORD},
        "tags": ["vpn"],
    }
    item.update(changes)
    return base(
        port,
        keyfile,
        tmp_path,
        path="/downloadclient",
        match="name",
        items=[item],
        schema={"path": "/downloadclient/schema", "key": "implementation"},
        tags_path="/tag",
        force_save=True,
        write_only=["fields.password"],
    )


def quiet(*results: subprocess.CompletedProcess[str]) -> None:
    for result in results:
        for text in (KEY, PASSWORD):
            assert text not in result.stdout + result.stderr


# -- settings ------------------------------------------------------------------


def test_settings_drift_is_named_set_and_then_current(
    api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path
) -> None:
    fake, port = api
    request = settings_request(port, keyfile, tmp_path)

    probe = run("settings-probe", request)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout == "drift authenticationMethod username write_only\n"
    assert fake.writes == []

    applied = run("settings-apply", request)
    assert applied.stdout == "changed\n", applied.stderr
    assert fake.writes == [("PUT", "/api/v3/config/host/1")]
    assert fake.host["password"] == PASSWORD
    assert fake.host["bindAddress"] == "*"

    again = run("settings-probe", request)
    assert again.stdout == "current\n"
    assert run("settings-apply", request).stdout == "noop\n"
    assert len(fake.writes) == 1
    state = (tmp_path / "state" / "http_json.json").read_text()
    assert PASSWORD not in state
    assert (tmp_path / "state" / "http_json.json").stat().st_mode & 0o777 == 0o600
    quiet(probe, applied, again)


def test_a_new_write_only_value_is_drift_and_gets_written(
    api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path
) -> None:
    fake, port = api
    assert run("settings-apply", settings_request(port, keyfile, tmp_path)).returncode == 0

    changed = settings_request(port, keyfile, tmp_path)
    changed["desired"]["password"] = PASSWORD + "-new"

    assert run("settings-probe", changed).stdout == "drift write_only\n"
    assert run("settings-apply", changed).stdout == "changed\n"
    assert fake.host["password"] == PASSWORD + "-new"


# -- items ---------------------------------------------------------------------


def test_a_missing_item_is_created_from_the_schema_with_tags(
    api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path
) -> None:
    fake, port = api
    request = items_request(port, keyfile, tmp_path)

    probe = run("items-probe", request)
    assert probe.stdout == "drift qBittorrent:missing\n", probe.stderr
    assert fake.tags == [], "the probe creates nothing"

    applied = run("items-apply", request)
    assert applied.stdout == "changed\n", applied.stderr
    created = fake.clients[-1]
    assert created["configContract"] == "QBittorrentSettings"
    assert "id" in created
    fields = {f["name"]: f["value"] for f in created["fields"]}
    # Schema defaults kept, desired fields written in.
    assert fields == {"host": "gluetun", "port": 8080, "password": PASSWORD, "movieCategory": "radarr"}
    assert fake.tags == [{"id": 1, "label": "vpn"}]
    assert created["tags"] == [1]
    assert "forceSave=true" in fake.queries
    # The listed item only: the other client stays as it was.
    assert fake.clients[0]["fields"] == [{"name": "host", "value": "elsewhere"}]

    again = run("items-probe", request)
    assert again.stdout == "current\n", again.stderr
    assert run("items-apply", request).stdout == "noop\n"
    quiet(probe, applied, again)


def test_a_differing_field_is_corrected_in_place(api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path) -> None:
    fake, port = api
    assert run("items-apply", items_request(port, keyfile, tmp_path)).returncode == 0
    created_id = fake.clients[-1]["id"]
    fake.clients[-1]["fields"][0]["value"] = "drifted"

    assert run("items-probe", items_request(port, keyfile, tmp_path)).stdout == "drift qBittorrent:fields.host\n"
    assert run("items-apply", items_request(port, keyfile, tmp_path)).stdout == "changed\n"
    assert fake.writes[-1] == ("PUT", f"/api/v3/downloadclient/{created_id}")
    assert {f["name"]: f["value"] for f in fake.clients[-1]["fields"]}["host"] == "gluetun"
    # The masked password was sent back as the mask and kept.
    assert {f["name"]: f["value"] for f in fake.clients[-1]["fields"]}["password"] == PASSWORD


def test_unlisted_items_are_never_touched(api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path) -> None:
    fake, port = api
    run("items-apply", items_request(port, keyfile, tmp_path))
    assert ("PUT", "/api/v3/downloadclient/7") not in fake.writes
    assert all(method != "DELETE" for method, _ in fake.writes)
    assert fake.clients[0]["name"] == "Keep me"


def test_a_missing_key_file_fails_and_names_only_the_path(api: tuple[FakeServarr, int], tmp_path: Path) -> None:
    _, port = api
    result = run("items-probe", items_request(port, tmp_path / "nope", tmp_path))
    assert result.returncode == 1
    assert result.stderr == f"fixture step: host secret {tmp_path / 'nope'} is missing\n"


def test_a_wrong_key_names_method_path_and_status(api: tuple[FakeServarr, int], tmp_path: Path) -> None:
    _, port = api
    wrong = tmp_path / "wrong"
    wrong.write_text("not-the-key")
    result = run("settings-apply", settings_request(port, wrong, tmp_path))
    assert result.returncode == 1
    assert result.stderr == "fixture step: GET /config/host answered 401\n"
    quiet(result)


# -- config and request ----------------------------------------------------------


def step(kind: str = "http_json_items", **changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "kind": kind,
        "name": "Client downloads",
        "port": 18080,
        "prefix": "/api/v3",
        "path": "/downloadclient",
        "auth": {"value": {"host_secret": "/srv/crypt/apps/client/apikey"}},
    }
    if kind == "http_json_items":
        data["items"] = ({"name": "one", "fields": {"password": {"secret": "client_password"}}},)
    else:
        data["desired"] = {"username": "owner", "password": {"secret": "client_password"}}
    data.update(changes)
    return data


def test_secrets_in_items_are_required_and_host_secrets_stay_references() -> None:
    cfg = stack_config(steps=(step(),))
    assert "client_password" in cfg.required_secret_keys
    secrets = values(cfg, client_password="value-client_password")
    item = next(s for s in cfg.steps if isinstance(s, HttpJsonItems))

    request = _http_json_request(cfg, item, secrets)

    assert request["auth"]["value"] == {"host_secret": "/srv/crypt/apps/client/apikey"}
    assert request["items"][0]["fields"]["password"] == "value-client_password"
    assert request["state"] == "/var/lib/ops-deploy/vpnstack/http_json.json"


def test_settings_resolve_secrets_too() -> None:
    cfg = stack_config(steps=(step("http_json_settings"),))
    secrets = values(cfg, client_password="value-client_password")
    settings = next(s for s in cfg.steps if isinstance(s, HttpJsonSettings))
    assert _http_json_request(cfg, settings, secrets)["desired"]["password"] == "value-client_password"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"port": 1234}, "port 1234 is not published"),
        ({"items": ({"fields": {}},)}, "every item needs a literal name"),
        ({"items": ({"name": "a"}, {"name": "a"})}, "items repeat a"),
        ({"path": "/download client"}, "path"),
        ({"path": "/x?forceSave=true"}, "path"),
    ],
)
def test_invalid_steps_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises((ConfigValidationError, ValueError)) as err:
        stack_config(steps=(step(**changes),))
    assert message in str(err.value)


def test_step_names_are_unique() -> None:
    with pytest.raises((ConfigValidationError, ValueError)) as err:
        stack_config(steps=(step(), step()))
    assert "step names repeat" in str(err.value)


def test_the_config_type_accepts_the_schema_key() -> None:
    cfg: ComposeAppConfig = stack_config(
        steps=(step(schema={"path": "/downloadclient/schema"}, tags_path="/tag", write_only=("fields.password",)),)
    )
    item = next(s for s in cfg.steps if isinstance(s, HttpJsonItems))
    assert item.schema_ref is not None
    assert item.schema_ref.key == "implementation"


# -- in the deploy ------------------------------------------------------------------


def _deploy(cfg: ComposeAppConfig, answer: str) -> Any:
    from ops_deploy.services.compose_app import deploy_compose_app
    from ops_deploy.testing import run_deploy_fake
    from tests.compose_app_fixtures import converged

    secrets = values(cfg, client_password="fixture-client-password-0123")
    run = run_deploy_fake(
        deploy_compose_app, cfg, secrets, responses=converged(cfg, secrets, **{"' items-probe )": [answer]})
    )
    assert run.succeeded, run.error
    return run


def test_a_current_probe_writes_nothing_and_drift_runs_the_apply_only() -> None:
    cfg = stack_config(steps=(step(),))

    assert _deploy(cfg, "current").mutating_changed_ops == []

    run = _deploy(cfg, "drift one:missing")
    assert run.mutating_changed_ops == ["Deploy vpnstack | Client downloads"]
    applied = [command for command, _ in run.stdin if command.endswith("' items-apply")]
    assert len(applied) == 1
    # The secret travels on stdin only, never in a command line.
    assert all("fixture-client-password-0123" not in command for command in run.executed_commands)


# -- YAML env references in config files (Recyclarr) ----------------------------------


def test_env_refs_render_as_env_var_tags_and_read_back() -> None:
    import yaml

    from ops_deploy.services.compose_app import ConfigFile, EnvRef
    from ops_deploy.services.compose_app.render import render_config

    config = ConfigFile.model_validate(
        {
            "path": "/srv/crypt/apps/sync/recyclarr.yml",
            "format": "yaml",
            "data": {"radarr": {"main": {"base_url": "http://radarr:7878", "api_key": {"env_var": "RADARR_API_KEY"}}}},
        }
    )
    assert isinstance(config.data["radarr"]["main"]["api_key"], EnvRef)

    text, has_secret = render_config(config, SecretValues(None, {}))  # type: ignore[arg-type]

    assert "api_key: !env_var 'RADARR_API_KEY'\n" in text
    assert not has_secret

    class Loader(yaml.SafeLoader):
        pass

    def env_var(loader: yaml.SafeLoader, node: yaml.Node) -> tuple[str, str]:
        assert isinstance(node, yaml.ScalarNode)
        return ("env", str(loader.construct_scalar(node)))

    Loader.add_constructor("!env_var", env_var)
    assert yaml.load(text, Loader=Loader)["radarr"]["main"]["api_key"] == ("env", "RADARR_API_KEY")


def test_env_refs_need_yaml() -> None:
    from ops_deploy.services.compose_app import ConfigFile

    with pytest.raises(ValueError, match="env_var references need format yaml"):
        ConfigFile.model_validate({"path": "/srv/x.json", "format": "json", "data": {"k": {"env_var": "X"}}})


# -- review round 1 ----------------------------------------------------------------


def test_a_symlinked_key_file_or_parent_is_refused(api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path) -> None:
    _, port = api
    link = tmp_path / "link"
    link.symlink_to(keyfile)
    result = run("settings-probe", settings_request(port, link, tmp_path))
    assert result.returncode == 1
    assert result.stderr == f"fixture step: host secret {link} is a symlink\n"

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "apikey").write_text(KEY)
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir)
    result = run("settings-probe", settings_request(port, linked_dir / "apikey", tmp_path))
    assert result.returncode == 1
    assert "is not a plain directory" in result.stderr
    quiet(result)


def test_strings_compare_exactly_and_path_keys_ignore_one_trailing_slash(
    api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path
) -> None:
    fake, port = api
    fake.host["username"] = "owner"
    fake.host["bindAddress"] = "/srv/"
    request = settings_request(port, keyfile, tmp_path, username="owner/", bindAddress="/srv")
    request["write_only"] = []
    assert run("settings-probe", request).stdout == "drift username bindAddress\n"

    request["path_keys"] = ["bindAddress"]
    assert run("settings-probe", request).stdout == "drift username\n"


def test_write_only_digests_of_different_steps_and_items_never_collide(
    api: tuple[FakeServarr, int], keyfile: Path, tmp_path: Path
) -> None:
    fake, port = api
    first = items_request(port, keyfile, tmp_path, name="VPN:main")
    first["name"] = "Clients"
    assert run("items-apply", first).returncode == 0
    # An existing item "main" whose stored password is wrong; the desired one equals the first's.
    fake.clients.append(
        {
            "id": 50,
            "name": "main",
            "implementation": "QBittorrent",
            "enable": True,
            "fields": [
                {"name": "host", "value": "gluetun"},
                {"name": "port", "value": 8080},
                {"name": "password", "value": "wrong"},
            ],
            "tags": [1],
        }
    )
    second = items_request(port, keyfile, tmp_path, name="main")
    second["name"] = "Clients:VPN"

    # "Clients" + "VPN:main" and "Clients:VPN" + "main" are different keys: the digest is not inherited.
    assert run("items-probe", second).stdout == "drift main:write_only\n"
    assert run("items-apply", second).stdout == "changed\n"
    stored = {f["name"]: f["value"] for f in next(c for c in fake.clients if c["name"] == "main")["fields"]}
    assert stored["password"] == PASSWORD
