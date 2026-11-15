"""livekit's host files stay byte for byte what the host has today.

The goldens under ``tests/golden/livekit`` record the route (byte-identical
to the retired livekit_deploy role's), the config files, the compose file
and the unit as compose_app renders them; identical bytes mean the next
deploy rewrites nothing and restarts nothing (see tests/goldens.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ops_deploy.core import SecretValues
from ops_deploy.services.compose_app.render import MANAGED, render_compose, render_config, render_unit
from ops_deploy.services.livekit import LivekitConfig, render_route
from tests.goldens import assert_golden
from tests.livekit_fixtures import livekit_config, values

GOLDEN = Path(__file__).parent / "golden" / "livekit"


@pytest.fixture
def cfg() -> LivekitConfig:
    return livekit_config()


@pytest.fixture
def secrets(cfg: LivekitConfig) -> SecretValues:
    return values(cfg)


def test_host_files_are_golden(cfg: LivekitConfig, secrets: SecretValues) -> None:
    app = cfg.compose_app()
    server, egress = (render_config(c, secrets)[0] for c in app.config_files)

    assert_golden(GOLDEN / "livekit.yml", render_route(cfg))
    assert_golden(GOLDEN / "livekit.yaml", server)
    assert_golden(GOLDEN / "egress.yaml", egress)
    assert_golden(GOLDEN / "docker-compose.yml", render_compose(app))
    assert_golden(GOLDEN / "livekit.service", render_unit(app))


def test_the_route_is_one_public_router_with_forwarded_headers(cfg: LivekitConfig) -> None:
    doc = yaml.safe_load(render_route(cfg))["http"]

    assert list(doc["routers"]) == ["livekit"]
    router = doc["routers"]["livekit"]
    assert router == {
        "rule": "Host(`livekit.example.invalid`)",
        "entryPoints": ["web-secure"],
        "middlewares": ["livekit-headers"],
        "service": "livekit",
        "tls": {},
    }
    assert doc["middlewares"]["livekit-headers"]["headers"]["customRequestHeaders"] == {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "livekit.example.invalid",
    }
    assert doc["services"]["livekit"]["loadBalancer"]["servers"] == [{"url": "http://127.0.0.1:7880"}]


@pytest.mark.parametrize("index", [0, 1])
def test_the_config_files_are_managed_and_hold_secrets(cfg: LivekitConfig, secrets: SecretValues, index: int) -> None:
    ours, has_secret = render_config(cfg.compose_app().config_files[index], secrets)

    assert has_secret
    assert ours.startswith(f"# {MANAGED}\n")


def test_values_yaml_would_retype_stay_strings(cfg: LivekitConfig) -> None:
    # The role writes secrets inside double quotes; the canonical render quotes where YAML needs it.
    tricky = values(cfg, api_key="123", api_secret="yes", redis_password="a: b #c", s3_secret_key="null")
    server, egress = (yaml.safe_load(render_config(c, tricky)[0]) for c in cfg.compose_app().config_files)

    assert server["keys"] == {"123": "yes"}
    assert server["redis"]["password"] == "a: b #c"
    assert server["webhook"]["api_key"] == "123"
    assert (egress["api_key"], egress["api_secret"], egress["s3"]["secret"]) == ("123", "yes", "null")
