"""Exact ingress route bytes, transaction guard and conditional handler behavior."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.opsgate.ingress import OpsGateIngressConfig, deploy_opsgate_ingress
from ops_deploy.services.opsgate.ingress import render_ingress as render_opsgate
from ops_deploy.services.voxhelm.ingress import VoxhelmIngressConfig, deploy_voxhelm_ingress
from ops_deploy.services.voxhelm.ingress import render_ingress as render_voxhelm
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "mac_ingress"

SPECS = [
    ("opsgate", OpsGateIngressConfig, deploy_opsgate_ingress, render_opsgate),
    ("voxhelm", VoxhelmIngressConfig, deploy_voxhelm_ingress, render_voxhelm),
]


@pytest.mark.parametrize(("name", "config", "deploy", "render"), SPECS)
def test_first_and_repeat_use_guarded_writer_and_handler(name: str, config: Any, deploy: Any, render: Any) -> None:
    cfg = config(traefik_host=f"{name}.example.invalid", backend_url="http://127.0.0.1:8787")
    first = run_deploy_fake(deploy, cfg, responses=fakehost.LINUX)
    assert first.succeeded, first.error
    assert first.uploaded_paths == [cfg.traefik_config_path]
    assert first.upload(cfg.traefik_config_path).decode() == render(cfg)
    assert route_guard_command() in first.executed_commands
    assert any(
        "systemctl reload traefik" in command and "systemctl restart traefik" in command
        for command in first.executed_commands
    )
    responses = {
        **fakehost.LINUX,
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(cfg.traefik_config_path, render(cfg)),
    }
    repeat = run_deploy_fake(deploy, cfg, responses=responses)
    assert repeat.succeeded, repeat.error
    assert not repeat.mutating_changed_ops
    assert not repeat.uploaded_paths
    assert not repeat.executed_commands


@pytest.mark.parametrize(("name", "config", "deploy", "render"), SPECS)
def test_disabled_is_role_noop(name: str, config: Any, deploy: Any, render: Any) -> None:
    result = run_deploy_fake(deploy, config(traefik_enabled=False, backend_url="http://backend.invalid"))
    assert result.succeeded, result.error
    assert not result.changed_ops


@pytest.mark.parametrize(("name", "config", "deploy", "render"), SPECS)
@pytest.mark.parametrize("resolver", ["", "letsencrypt"])
def test_route_is_golden(name: str, config: Any, deploy: Any, render: Any, resolver: str) -> None:
    """The route below ``/etc/traefik/dynamic``: a changed byte reloads Traefik."""

    values: dict[str, Any] = {
        "traefik_host": f"{name}.example.invalid",
        "backend_url": "http://backend.invalid:8787",
        "traefik_cert_resolver": resolver,
    }
    if name == "voxhelm":
        values.update(internal_api_enabled=True, internal_api_allowed_ip_ranges=["100.64.0.0/10"])

    assert_golden(GOLDEN / f"{name}-{resolver or 'default'}.yml", render(config(**values)))


@pytest.mark.parametrize(
    "values",
    [
        {"traefik_host": 'bad"host'},
        {"backend_url": 'http://bad"host'},
        {"allowed_ip_ranges": ["$(id)"]},
        {"allowed_ip_ranges": ["fe80::1%eth`)||Host(`x/128"]},
        {"allowed_ip_ranges": ['fe80::1%"x/128']},
        {"allowed_ip_ranges": ["10.0.0.0/255.0.0.0"]},
        {"traefik_entrypoints": ["true"]},
        {"traefik_config_path": "/etc/traefik/dynamic/../../evil.yml"},
    ],
)
@pytest.mark.parametrize("config", [OpsGateIngressConfig, VoxhelmIngressConfig])
def test_unsafe_inputs_before_connection(config: Any, values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**{"traefik_host": "app.invalid", "backend_url": "http://backend.invalid", **values})


def test_internal_worker_policy_needs_ranges() -> None:
    with pytest.raises(ValidationError):
        VoxhelmIngressConfig(
            traefik_host="vox.invalid", backend_url="http://backend.invalid", internal_api_enabled=True
        )


@pytest.mark.parametrize("field", ["internal_api_allowed_ip_ranges", "internal_api_block_ip_ranges"])
def test_internal_policy_rejects_scoped_addresses(field: str) -> None:
    with pytest.raises(ValidationError):
        VoxhelmIngressConfig(
            **{
                "traefik_host": "vox.invalid",
                "backend_url": "http://backend.invalid",
                field: ("fe80::1%eth0/128",),
            }
        )
