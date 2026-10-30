"""Deploy-level scenarios for open_webui against the fake connector."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.helpers import BasicAuth
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.open_webui import OpenWebUIConfig, deploy_open_webui
from ops_deploy.services.open_webui.deploy import (
    installed_probe,
    render_env,
    render_route,
    render_unit,
    security_constraints_text,
    shipped_constraints,
    traefik_config,
    venv_probe,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

PASSWORD = "open-webui-fixture-basic-pw"  # pragma: allowlist secret
AUTH = BasicAuth(user="admin", password=SecretStr(PASSWORD))
_HASH = hash_password(PASSWORD)
SITE = "/opt/open-webui"
VENV = f"{SITE}/.venv"
ENV = f"{SITE}/open-webui.env"
UNIT = "/etc/systemd/system/open-webui.service"
ROUTE = "/etc/traefik/dynamic/open-webui.yml"
CONSTRAINTS = f"{SITE}/.python-security-constraints.txt"
KEY = f"{SITE}/.webui_secret_key"
DATA = "/srv/data/open-webui/data"
P = "Deploy Open WebUI | "
READ_ONLY = [
    f"{P}Require the mount /srv/data",
    f"{P}Port preflight tcp/3000",
    f"{P}Verify Open WebUI environment (before the deploy) certifi/pip trust",
    f"{P}Verify Open WebUI environment certifi/pip trust",
    f"{P}Wait for Open WebUI port to become available",
    f"{P}Check Open WebUI HTTP endpoint",
]


@pytest.fixture
def cfg() -> OpenWebUIConfig:
    return OpenWebUIConfig(
        ollama_base_url="http://ollama.example.test:11434",
        traefik_host="open-webui.example.com",
        data_dir=DATA,
        extra_env={"OFFLINE_MODE": "true", "ENABLE_VERSION_UPDATE_CHECK": "false"},
        mounts_required=("/srv/data",),
    )


def host_facts() -> dict[str, Any]:
    return {**fakehost.UBUNTU}


def converged(cfg: OpenWebUIConfig, **drift: Any) -> dict[str, Any]:
    """Facts of a host where the role (or this deploy) already ran."""

    responses: dict[str, Any] = {
        **host_facts(),
        venv_probe(cfg): ["python=3.11.14"],
        installed_probe(cfg): ["0.7.2"],
        "/usr/local/bin/uv --version": ["uv 0.13.5 (x86_64-unknown-linux-gnu)"],
        **fakehost.stat("/usr/local/bin/uvx"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.accounts({"openwebui": "/home/openwebui"}),
        **fakehost.directory("/home/openwebui", user="openwebui", mode="drwxr-x---"),
        **fakehost.directory(SITE, user="openwebui"),
        **fakehost.directory(DATA, user="openwebui"),
        **fakehost.directory("/var/log/open-webui", user="openwebui"),
        **fakehost.file(ENV, render_env(cfg), mode="-rw-------"),
        **fakehost.file(CONSTRAINTS, security_constraints_text(), user="openwebui"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.file(UNIT, render_unit(cfg)),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(ROUTE, render_route(cfg, traefik_config(cfg, AUTH), _HASH)),
        **fakehost.service("open-webui.service"),
    }
    return {**drift, **{key: value for key, value in responses.items() if key not in drift}}


def deploy(cfg: OpenWebUIConfig, responses: dict[str, Any], basic_auth: BasicAuth | None = AUTH) -> FakeRun:
    run = run_deploy_fake(deploy_open_webui, cfg, basic_auth, responses=responses)
    assert run.succeeded, run.error
    return run


def changed(*names: str) -> list[str]:
    return [f"{P}{name}" for name in names]


def uv_commands(run: FakeRun) -> list[str]:
    return [c for c in run.executed_commands if "/usr/local/bin/uv " in c and "--version" not in c]


def test_converged_host_is_not_changed(cfg: OpenWebUIConfig) -> None:
    run = deploy(cfg, converged(cfg))
    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert uv_commands(run) == []
    assert run.uploads == []
    assert run.stdin == []
    assert not any(KEY in c for c in run.executed_commands)


def test_first_run_installs_everything_in_order(cfg: OpenWebUIConfig) -> None:
    responses = {
        **host_facts(),
        venv_probe(cfg): ["missing"],
    }
    run = deploy(cfg, responses)
    names = run.mutating_changed_ops
    for name in (
        "Ensure group openwebui",
        "Ensure user openwebui",
        "Create home /home/openwebui",
        f"Write {ENV}",
        f"Write the certifi/pip install constraints {CONSTRAINTS}",
        "Install Python 3.11.14 via uv",
        f"Create virtual environment {VENV}",
        "Install Open WebUI 0.7.2 via uv pip",
        "Install systemd unit open-webui.service",
        "Start open-webui.service",
    ):
        assert f"{P}{name}" in names, name
    order = [names.index(f"{P}{n}") for n in ("Ensure user openwebui", f"Write {ENV}", "Install Python 3.11.14 via uv")]
    assert order == sorted(order)
    # Started, not restarted right after.
    assert f"{P}Restart open-webui.service" not in names
    # No preflight verification of an environment that does not exist yet.
    assert f"{P}Verify Open WebUI environment (before the deploy) certifi/pip trust" not in run.changed_ops
    [install] = [c for c in uv_commands(run) if " pip install " in c]
    assert "open-webui==0.7.2" in install
    assert f"--constraints {CONSTRAINTS}" in install
    assert '--constraints "$constraints"' in install
    assert "runuser -u openwebui" in install
    assert "HOME=/home/openwebui" in install
    [(_command, text)] = [(c, s) for c, s in run.stdin if "pip install" in c]
    assert text == shipped_constraints()["0.7.2"]
    [venv] = [c for c in uv_commands(run) if " venv " in c]
    assert "--managed-python --python 3.11.14" in venv
    user = next(c for c in run.executed_commands if "useradd" in c)
    assert "-m" not in user.split()
    assert "/usr/sbin/nologin" in user
    assert "-r" in user.split()


def test_other_version_reinstalls_and_restarts(cfg: OpenWebUIConfig) -> None:
    run = deploy(cfg, converged(cfg, **{installed_probe(cfg): ["0.6.40"]}))
    assert run.mutating_changed_ops == changed("Install Open WebUI 0.7.2 via uv pip", "Restart open-webui.service")
    assert not any(" venv " in c or "python install" in c for c in uv_commands(run))
    assert f"{P}Probe again: Open WebUI 0.7.2 installed" in run.changed_ops


@pytest.mark.parametrize("answer", ["broken", "python=3.12.3", ""])
def test_unusable_venv_is_recreated_and_the_key_and_data_are_kept(cfg: OpenWebUIConfig, answer: str) -> None:
    run = deploy(cfg, converged(cfg, **{venv_probe(cfg): [answer]}))
    assert run.mutating_changed_ops == changed(
        "Install Python 3.11.14 via uv",
        f"Create virtual environment {VENV}",
        "Install Open WebUI 0.7.2 via uv pip",
        "Restart open-webui.service",
    )
    removals = [c for c in run.executed_commands if "rm -" in c and "constraints" not in c]
    assert removals == [f"rm -rf -- {VENV}"]
    assert not any(KEY in c or DATA in c for c in run.executed_commands if "rm " in c)


def test_env_change_restarts_once(cfg: OpenWebUIConfig) -> None:
    changed_cfg = cfg.model_copy(update={"extra_env": {**cfg.extra_env, "OFFLINE_MODE": "false"}})
    run = deploy(changed_cfg, converged(cfg))
    assert run.mutating_changed_ops == changed(f"Write {ENV}", "Restart open-webui.service")
    assert all("OFFLINE_MODE" not in c for c in run.executed_commands)


def test_unit_change_reloads_and_restarts(cfg: OpenWebUIConfig) -> None:
    changed_cfg = cfg.model_copy(update={"systemd_restart_sec": 7})
    run = deploy(changed_cfg, converged(cfg))
    assert run.mutating_changed_ops == changed(
        "Install systemd unit open-webui.service", "Reload systemd for open-webui.service", "Restart open-webui.service"
    )


def test_route_reuses_the_deployed_hash(cfg: OpenWebUIConfig) -> None:
    run = deploy(cfg, converged(cfg))
    assert f"{P}Write Traefik route open-webui" not in run.changed_ops
    rotated = deploy(cfg, converged(cfg), BasicAuth(user="admin", password=SecretStr("another-password")))
    assert rotated.mutating_changed_ops == changed("Write Traefik route open-webui")
    # Traefik picks the file up itself (the role's reload handler); nothing restarts.
    assert not any("traefik" in c and ("restart" in c or "reload" in c) for c in rotated.executed_commands)


def test_existing_home_is_never_changed(cfg: OpenWebUIConfig) -> None:
    run = deploy(cfg, converged(cfg))
    assert not any("/home/openwebui" in c and ("chmod" in c or "chown" in c) for c in run.executed_commands)


def test_port_preflight_comes_first(cfg: OpenWebUIConfig) -> None:
    run = deploy(cfg, converged(cfg, **{"command -v useradd": ["/usr/sbin/useradd"]}))
    ops = [op.name for op in run.ops]
    assert ops[:2] == [f"{P}Require the mount /srv/data", f"{P}Port preflight tcp/3000"]
    preflight = next(c for c in run.executed_commands if "ss -Hltnp" in c)
    assert "0::/system.slice/open-webui.service" in preflight


def test_constraints_file_is_the_floor_role_text() -> None:
    assert security_constraints_text() == "certifi>=2026.10.19\npip>=26.2.2\n"


def test_shipped_constraints_pin_the_version_and_are_public() -> None:
    text = shipped_constraints()["0.7.2"]
    pins = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert len(pins) == 288
    assert all("==" in line and "@" not in line and "://" not in line for line in pins)
    assert "open_webui==0.7.2" in pins
    assert "certifi==2026.10.19" in pins


@pytest.mark.parametrize(
    "fields",
    [
        {"extra_env": {"WEBUI_SECRET_KEY": "x"}},
        {"extra_env": {"OPENAI_API_KEY": "x"}},
        {"extra_env": {"lower": "x"}},
        {"extra_env": {"X": 'a"b'}},
        {"traefik_host": ""},
        {"version": "0.6.0"},
        {"python_version": "3.11"},
        {"mounts_required": ("/mnt/other",)},
        {"venv_path": DATA},
        {"site_dir": f"{SITE}/.venv/x", "venv_path": f"{SITE}/.venv"},
        {"webui_secret_key": "x"},
        {"venv_path": "//opt/open-webui"},
        {"venv_path": "/opt/open-webui/./.venv"},
        {"site_dir": "/opt/open-webui/"},
        {"venv_path": f"{SITE}/.webui_secret_key"},
        {"env_path": f"{SITE}/.webui_secret_key"},
        {"python_security_constraints_path": f"{SITE}/.webui_secret_key"},
        {"env_path": f"{DATA}/open-webui.env"},
        {"python_security_constraints_path": f"{VENV}/constraints.txt"},
        {"env_path": CONSTRAINTS},
        {"env_path": SITE},
        {"venv_path": f"{DATA}/.venv"},
        {"mounts_required": ("//srv/data",)},
        {"uv_install_dir": DATA},
        {"uv_install_dir": f"{VENV}/bin"},
        {"uv_install_dir": SITE},
        {"env_path": "/usr/local/bin/uv"},
        {"package_spec": "open-webui"},
    ],
)
def test_config_refuses(cfg: OpenWebUIConfig, fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        OpenWebUIConfig.model_validate({**cfg.model_dump(), **fields})


def test_basic_auth_rules(cfg: OpenWebUIConfig) -> None:
    with pytest.raises(ValueError, match="basic_auth is required"):
        run_deploy_fake(deploy_open_webui, cfg, None, responses=converged(cfg))
    with pytest.raises(ValueError, match="placeholder"):
        run_deploy_fake(
            deploy_open_webui, cfg, BasicAuth(user="admin", password=SecretStr("CHANGEME")), responses=converged(cfg)
        )
    off = cfg.model_copy(update={"traefik_enabled": False})
    with pytest.raises(ValueError, match="disabled"):
        run_deploy_fake(deploy_open_webui, off, AUTH, responses=converged(cfg))


def test_unmanaged_uv_must_exist(cfg: OpenWebUIConfig) -> None:
    unmanaged = cfg.model_copy(update={"manage_uv": False})
    run = run_deploy_fake(deploy_open_webui, unmanaged, AUTH, responses=converged(cfg))
    assert run.error is not None
    assert "uv not found" in str(run.error)
