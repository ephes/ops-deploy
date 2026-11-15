"""logyard's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/logyard`` were recorded when these renders
still equalled the retired logyard roles' output (role defaults overlaid by
the playbooks' values); identical bytes mean the next deploy rewrites
nothing and restarts nothing (see tests/goldens.py).
"""

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.logyard import core, ingress, vector
from tests.goldens import assert_golden
from tests.logyard_fixtures import core_config, ingress_config, make_source, vector_config

GOLDEN = Path(__file__).parent / "golden" / "logyard"
CORE_VARIANTS: dict[str, dict[str, Any]] = {
    "defaults": {},
    "playbook": {"health": core.HealthEndpoint(units=({"id": "vector", "unit": "vector.service"},))},
}
CORE_FILES = {
    "loki-config.yml": core.render_loki_config,
    "docker-compose.yml": core.render_compose,
    "logyard.service": core.render_service_unit,
    "grafana-logyard-datasource.yml": core.render_datasource,
    "logyard-health-endpoint.service": core.render_health_unit,
}


@pytest.mark.parametrize("variant", sorted(CORE_VARIANTS))
def test_core_files_are_golden(tmp_path: Path, variant: str) -> None:
    cfg = core_config(make_source(tmp_path), **CORE_VARIANTS[variant])

    for name, render in CORE_FILES.items():
        assert_golden(GOLDEN / "core" / variant / name, render(cfg))


def test_health_units_survive_systemd_verbatim(tmp_path: Path) -> None:
    units = ({"id": "vector", "unit": "vector.service"},)
    cfg = core_config(make_source(tmp_path), health=core.HealthEndpoint(units=units))

    unit = core.render_health_unit(cfg)
    (line,) = [line for line in unit.splitlines() if line.startswith("Environment=LOGYARD_HEALTH_UNITS_B64=")]
    assert json.loads(base64.b64decode(line.partition("=")[2].partition("=")[2])) == list(units)


INGRESS_VARIANTS: dict[str, dict[str, Any]] = {
    "playbook": {},
    "no-resolver-no-redirect": {"traefik_cert_resolver": "", "root_redirect_enabled": False},
}


@pytest.mark.parametrize("variant", sorted(INGRESS_VARIANTS))
def test_ingress_route_is_golden(variant: str) -> None:
    route = ingress.render_route(ingress_config(**INGRESS_VARIANTS[variant]))

    assert_golden(GOLDEN / "ingress" / variant / "traefik-logyard.yml", route)


# Whether the host's Vector supports label template confinement (None: not probed).
VECTOR_VARIANTS: dict[str, bool | None] = {"defaults": None, "old-vector": False}


@pytest.mark.parametrize("variant", sorted(VECTOR_VARIANTS))
def test_vector_fragment_is_golden(variant: str) -> None:
    fragment = vector.render_fragment(vector_config(), VECTOR_VARIANTS[variant])

    assert_golden(GOLDEN / "vector" / variant / "vector.yaml", fragment)


def test_global_fragment_names_the_data_dir() -> None:
    cfg = vector_config(data_dir="/srv/vector")

    assert vector.render_global(cfg) == f"data_dir: {json.dumps('/srv/vector')}\n"
