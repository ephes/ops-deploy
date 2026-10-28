"""Fresh interpreters expose import cycles that a warmed pytest process hides."""

from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "first",
    [
        "ops_deploy.services.fractal_monitoring.config",
        "ops_deploy.services.fractal_monitoring.deploy",
        "ops_deploy.services.fractal_monitoring",
        "ops_deploy.infra.tailscale.metrics",
    ],
)
def test_existing_component_can_be_imported_before_tailscale_namespace(first: str) -> None:
    code = (
        "import importlib; importlib.import_module(" + repr(first) + "); "
        "from ops_deploy.infra import TailscaleConfig, TailscaleMetricsConfig, deploy_tailscale; "
        "assert TailscaleConfig(hostname='owned').hostname=='owned'; "
        "assert callable(deploy_tailscale); assert TailscaleMetricsConfig().enabled is False"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_namespace_exports_remain_discoverable_and_resolve_without_cycle() -> None:
    code = (
        "import ops_deploy.infra as infra; "
        "expected={name for name in infra.__all__ "
        "if name.startswith('Tailscale') or name.startswith('deploy_tailscale')}; "
        "assert expected <= set(dir(infra)); "
        "assert all(getattr(infra,name) is getattr(infra,name) for name in expected); "
        "assert 'TailscaleConfig' in expected"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_root_import_defers_only_new_aliases_and_keeps_attribute_errors() -> None:
    code = (
        "import sys; import ops_deploy.infra as infra; "
        "assert 'ops_deploy.infra.tailscale' not in sys.modules; "
        "assert hasattr(infra,'TailscaleConfig'); "
        "assert not hasattr(infra,'not_a_supported_infra_export')"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_star_import_keeps_existing_and_tailscale_exports() -> None:
    code = (
        "from ops_deploy.infra import *; "
        "assert TailscaleConfig(hostname='owned').hostname=='owned'; "
        "assert NetplanConfig is not None and PostgresInstallConfig is not None; "
        "assert callable(deploy_tailscale_metrics) and callable(deploy_traefik)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
