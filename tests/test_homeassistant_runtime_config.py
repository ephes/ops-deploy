"""Runtime config interpolation and guards; the rendered units are golden (test_homeassistant_golden)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"user": "ha_test"},
        {"site_path": "/srv/ha", "data_path": "/data/ha", "service_name": "custom-ha"},
        {
            "virtualenv_path": "/opt/ha-venv",
            "matter_server_virtualenv_path": "/opt/matter",
            "matter_server_log_file": "",
        },
    ],
)
def test_default_interpolation_and_round_trip(overrides: dict[str, Any]) -> None:
    cfg = HomeAssistantRuntimeConfig.model_validate(overrides)
    assert cfg.group == overrides.get("user", "homeassistant")
    assert cfg.config_path == cfg.site_path + "/config"
    assert cfg.virtualenv_version_file == cfg.virtualenv_path + "/.ansible-python-version"
    assert cfg.matter_server_virtualenv_version_file == cfg.matter_server_virtualenv_path + "/.ansible-python-version"
    assert cfg.matter_server_storage_path == cfg.data_path + "/matter-server"
    assert HomeAssistantRuntimeConfig.model_validate_json(cfg.model_dump_json()) == cfg


@pytest.mark.parametrize("key", ["site_path", "virtualenv_path", "matter_server_storage_path"])
@pytest.mark.parametrize("bad", ["/", "/srv/../etc", "/srv/ha\nExecStart=/bin/false"])
def test_dangerous_paths_rejected(key: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        HomeAssistantRuntimeConfig.model_validate({key: bad})


def test_matter_original_guards() -> None:
    with pytest.raises(ValidationError, match="Matter package"):
        HomeAssistantRuntimeConfig(manage_matter_server=True, matter_server_package_spec="python-matter-server")
    with pytest.raises(ValidationError, match=r"Python 3\.12"):
        HomeAssistantRuntimeConfig(manage_matter_server=True, python_version="3.11.9")


@pytest.mark.parametrize("path", ["/", "/etc/systemd/system/../../foreign.conf"])
def test_trust_allowlist_rejects_root_and_traversal(path: str) -> None:
    with pytest.raises(ValidationError, match="runtime paths"):
        HomeAssistantRuntimeConfig(uv_system_certs_allowed_dropins=(path,))


def test_trust_allowlist_keeps_exact_declared_paths() -> None:
    path = "/etc/systemd/system/homeassistant.service.d/reviewed.conf"
    assert HomeAssistantRuntimeConfig(uv_system_certs_allowed_dropins=(path,)).uv_system_certs_allowed_dropins == (
        path,
    )


def test_matter_bluetooth_adapter_flag() -> None:
    from ops_deploy.services.homeassistant.render import render_unit

    assert "--bluetooth-adapter" not in render_unit(HomeAssistantRuntimeConfig(), "matter-server")
    unit = render_unit(HomeAssistantRuntimeConfig(matter_server_bluetooth_adapter=0), "matter-server")
    exec_start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert exec_start.endswith("/matter-server.log --bluetooth-adapter 0")


@pytest.mark.parametrize("bad", [-1, "0", True, 1.0])
def test_matter_bluetooth_adapter_rejects_non_ids(bad: Any) -> None:
    with pytest.raises(ValidationError):
        HomeAssistantRuntimeConfig.model_validate({"matter_server_bluetooth_adapter": bad})
