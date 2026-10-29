"""Original route parser and bounded target fact composition; no host probes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pyinfra.facts.server import Command

from ops_deploy.services.homeassistant import HomeAssistantDeployConfig
from ops_deploy.services.homeassistant import network_inputs as module


@pytest.mark.parametrize(
    ("raw", "address"),
    [
        ("8.8.8.8 via 192.0.2.1 dev eth0 src 192.0.2.8 uid 0\n    cache\n", "192.0.2.8"),
        ("8.8.8.8 dev eth0 src 192.0.2.9\n8.8.8.8 dev eth1 src 198.51.100.8", "192.0.2.9"),
        ("8.8.8.8 dev eth0", None),
        ("8.8.8.8 dev eth0 src", None),
        ("1.1.1.1 dev eth0 src 192.0.2.8", None),
        ("", None),
        ("RTNETLINK answers: Network is unreachable", None),
    ],
)
def test_original_first_line_src_semantics(raw: str, address: str | None) -> None:
    assert module.route_address(raw) == address


def test_actual_public_config_preserves_source_and_binds_one_fact(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def get_fact(fact: object, **kwargs: object) -> str:
        calls.append((fact, kwargs))
        return "8.8.8.8 via 192.0.2.1 dev eth0 src 192.0.2.8 uid 0\n    cache\n"

    monkeypatch.setattr(module, "host", SimpleNamespace(get_fact=get_fact))
    cfg = HomeAssistantDeployConfig(values={"internal_url": "http://owned.local:10020"})
    result = module.resolve_target_network(cfg)
    assert calls == [(Command, {"command": module.ROUTE_COMMAND})]
    assert result.api.default_ipv4 == result.ingress.default_ipv4 == "192.0.2.8"
    assert cfg.api.default_ipv4 is None
    assert result.values.internal_url == cfg.values.internal_url
    before, after = cfg.model_dump(), result.model_dump()
    for component in ("api", "ingress"):
        after[component]["default_ipv4"] = None
    assert after == before


def test_explicit_fact_never_probes_or_overwrites(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "host", SimpleNamespace(get_fact=lambda *a, **k: pytest.fail("unexpected fact")))
    cfg = HomeAssistantDeployConfig(api={"default_ipv4": "192.0.2.99"}, ingress={"default_ipv4": "198.51.100.9"})
    assert module.resolve_target_network(cfg) is cfg


def test_explicit_none_is_not_overwritten(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "host", SimpleNamespace(get_fact=lambda *a, **k: pytest.fail("unexpected fact")))
    cfg = HomeAssistantDeployConfig(api={"default_ipv4": None}, ingress={"default_ipv4": None})
    assert module.resolve_target_network(cfg) is cfg


def test_explicit_half_none_and_absent_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "host", SimpleNamespace(get_fact=lambda *a, **k: ""))
    cfg = HomeAssistantDeployConfig(ingress={"default_ipv4": None})
    assert module.resolve_target_network(cfg) is cfg
    monkeypatch.setattr(module, "host", SimpleNamespace(get_fact=lambda *a, **k: "8.8.8.8 src 198.51.100.9"))
    result = module.resolve_target_network(cfg)
    assert result.api.default_ipv4 == "198.51.100.9"
    assert result.ingress.default_ipv4 is None
    assert result.ingress is cfg.ingress
    assert result.values is cfg.values
    assert result.custom_component is cfg.custom_component
    assert result.api.model_fields_set == cfg.api.model_fields_set | {"default_ipv4"}
    assert result.ingress.model_fields_set == cfg.ingress.model_fields_set
    assert result.custom_component.model_fields_set == cfg.custom_component.model_fields_set
