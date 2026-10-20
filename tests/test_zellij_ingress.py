"""zellij_ingress: byte parity with the role's template, the route's shape, plans and input refusal.

Parity renders the vendored role template (``tests/parity/ansible/
zellij_ingress_deploy__zellij-traefik.yml.j2``, checked against ops-library by
``test_traefik_parity.test_vendored_templates_match_ops_library``) with a
Jinja2 environment configured like Ansible's ``template`` module, with the
role defaults overlaid by the inputs, and compares bytes with what the deploy
writes. The role variables here are written out independently of
``role_vars()`` so a mapping mistake cannot cancel itself out.
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.zellij_ingress import (
    DEFAULT_ALLOWED_IP_RANGES,
    ZellijIngressConfig,
    deploy_zellij_ingress,
    render_route,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/zellij_ingress/templates"
TEMPLATE = "zellij-traefik.yml.j2"
ROUTE = "/etc/traefik/dynamic/zellij.yml"
DYNAMIC = "/etc/traefik/dynamic"
HOST = "zellij.example.invalid"
TARGET = "https://backend.example.invalid/"
PREFIX = "Deploy Zellij ingress | "

# zellij_ingress_deploy/defaults/main.yml
ROLE_DEFAULTS: dict[str, Any] = {
    "zellij_ingress_traefik_enabled": True,
    "zellij_ingress_traefik_host": "",
    "zellij_ingress_redirect_target": "",
    "zellij_ingress_traefik_entrypoints": ["web-secure"],
    "zellij_ingress_traefik_cert_resolver": "",
    "zellij_ingress_traefik_config_path": "/etc/traefik/dynamic/zellij.yml",
    "zellij_ingress_allowed_ip_ranges": ["127.0.0.1/32", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48"],
}


def config(**overrides: Any) -> ZellijIngressConfig:
    fields: dict[str, Any] = {"traefik_host": HOST, "redirect_target": TARGET, **overrides}
    return ZellijIngressConfig(**fields)


def render_ansible(variables: dict[str, Any]) -> str:
    # ansible.builtin.template defaults: trim_blocks on, lstrip_blocks off, trailing newline kept.
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(f"zellij_ingress_deploy__{TEMPLATE}").render(**{**ROLE_DEFAULTS, **variables})


# (config overrides, the same inputs as role variables)
VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "playbook": (
        {},
        {"zellij_ingress_traefik_host": HOST, "zellij_ingress_redirect_target": TARGET},
    ),
    "cert resolver": (
        {"traefik_cert_resolver": "letsencrypt"},
        {
            "zellij_ingress_traefik_host": HOST,
            "zellij_ingress_redirect_target": TARGET,
            "zellij_ingress_traefik_cert_resolver": "letsencrypt",
        },
    ),
    "entrypoints, one range, http target with port and path": (
        {
            "traefik_entrypoints": ("web-secure", "tailnet_secure"),
            "allowed_ip_ranges": ("10.0.0.0/8",),
            "redirect_target": "http://backend.example.invalid:8082/web/",
        },
        {
            "zellij_ingress_traefik_host": HOST,
            "zellij_ingress_redirect_target": "http://backend.example.invalid:8082/web/",
            "zellij_ingress_traefik_entrypoints": ["web-secure", "tailnet_secure"],
            "zellij_ingress_allowed_ip_ranges": ["10.0.0.0/8"],
        },
    ),
    "everything": (
        {
            "traefik_host": "term.example.invalid",
            "redirect_target": "https://Backend.example.invalid",
            "traefik_entrypoints": ("websecure",),
            "traefik_cert_resolver": "le_dns",
            "traefik_config_path": "/etc/traefik/dynamic/zellij-web.yml",
            "allowed_ip_ranges": ("192.0.2.0/24", "2001:db8::/32", "198.51.100.7/32"),
        },
        {
            "zellij_ingress_traefik_host": "term.example.invalid",
            "zellij_ingress_redirect_target": "https://Backend.example.invalid",
            "zellij_ingress_traefik_entrypoints": ["websecure"],
            "zellij_ingress_traefik_cert_resolver": "le_dns",
            "zellij_ingress_traefik_config_path": "/etc/traefik/dynamic/zellij-web.yml",
            "zellij_ingress_allowed_ip_ranges": ["192.0.2.0/24", "2001:db8::/32", "198.51.100.7/32"],
        },
    ),
}


# -- parity ---------------------------------------------------------------------------


def test_packaged_template_is_the_vendored_role_template() -> None:
    assert (PACKAGED / TEMPLATE).read_bytes() == (VENDORED / f"zellij_ingress_deploy__{TEMPLATE}").read_bytes()


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_route_is_byte_identical_to_the_role(variant: str) -> None:
    overrides, role_variables = VARIANTS[variant]

    ours = render_route(config(**overrides))

    assert ours == render_ansible(role_variables)
    assert ours.startswith("# Managed by Ansible - Traefik configuration for Zellij private redirect ingress\n")
    assert ours.endswith("permanent: false\n")


def test_defaults_are_the_roles() -> None:
    cfg = config()

    assert cfg.traefik_enabled is True
    assert cfg.traefik_entrypoints == ("web-secure",)
    assert cfg.traefik_cert_resolver == ""
    assert cfg.traefik_config_path == ROUTE
    assert list(DEFAULT_ALLOWED_IP_RANGES) == ROLE_DEFAULTS["zellij_ingress_allowed_ip_ranges"]


# -- route shape ----------------------------------------------------------------------


def parsed(cfg: ZellijIngressConfig) -> dict[str, Any]:
    document = yaml.safe_load(render_route(cfg))
    assert set(document) == {"http"}
    http: dict[str, Any] = document["http"]
    return http


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_only_allowlisted_redirect_routers_and_no_backend(variant: str) -> None:
    cfg = config(**VARIANTS[variant][0])
    http = parsed(cfg)

    # No services section: nothing but Traefik's internal no-op service is reachable.
    assert set(http) == {"routers", "middlewares"}
    assert set(http["routers"]) == {"zellij-secure", "zellij-http"}
    allowlist = " || ".join(f"ClientIP(`{network}`)" for network in cfg.allowed_ip_ranges)
    for router in http["routers"].values():
        assert router["rule"] == f"Host(`{cfg.traefik_host}`) && ({allowlist})"
        assert router["service"] == "noop@internal"
        assert router["middlewares"] == ["zellij-redirect-target"]
    assert http["routers"]["zellij-secure"]["entryPoints"] == list(cfg.traefik_entrypoints)
    assert http["routers"]["zellij-http"]["entryPoints"] == ["web"]
    assert "tls" not in http["routers"]["zellij-http"]
    expected_tls = {"certResolver": cfg.traefik_cert_resolver} if cfg.traefik_cert_resolver else {}
    assert http["routers"]["zellij-secure"]["tls"] == expected_tls
    assert http["middlewares"] == {
        "zellij-redirect-target": {
            "redirectRegex": {"regex": ".*", "replacement": cfg.redirect_target, "permanent": False}
        }
    }


# -- plans ----------------------------------------------------------------------------


def converged(cfg: ZellijIngressConfig, content: str | None = None, mode: str = "-rw-r--r--") -> dict[str, Any]:
    return {
        **fakehost.LINUX,
        **fakehost.directory(DYNAMIC),
        **fakehost.file(cfg.traefik_config_path, render_route(cfg) if content is None else content, mode=mode),
    }


def run(cfg: ZellijIngressConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_zellij_ingress, cfg, responses=responses or dict(fakehost.LINUX))
    assert result.succeeded, result.error
    return result


def assert_untouched_services(result: FakeRun) -> None:
    text = "\n".join(result.executed_commands)
    for word in ("systemctl", "service ", "traefik ", "tailscale", "zellij ", "kill", "rm "):
        assert word not in text


def test_first_run_writes_only_the_directory_and_the_route() -> None:
    cfg = config()

    result = run(cfg)

    assert result.uploaded_paths == [ROUTE]
    assert result.upload(ROUTE).decode() == render_route(cfg)
    assert result.mutating_changed_ops == [
        PREFIX + "Ensure Traefik dynamic directory",
        PREFIX + "Write Traefik route zellij",
    ]
    assert "mkdir -p /etc/traefik/dynamic" in result.executed_commands
    assert any("chmod 644" in c and ROUTE in c for c in result.executed_commands)
    assert any("chown root:root" in c and ROUTE in c for c in result.executed_commands)
    assert_untouched_services(result)


def test_second_run_changes_nothing() -> None:
    cfg = config()

    result = run(cfg, converged(cfg))

    assert result.mutating_changed_ops == []
    assert result.uploaded_paths == []
    assert result.executed_commands == []


def test_route_drift_rewrites_only_the_route() -> None:
    cfg = config()
    stale = render_route(config(redirect_target="https://old.example.invalid/"))

    result = run(cfg, converged(cfg, stale))

    assert result.mutating_changed_ops == [PREFIX + "Write Traefik route zellij"]
    assert result.uploaded_paths == [ROUTE]
    assert result.upload(ROUTE).decode() == render_route(cfg)
    assert_untouched_services(result)


def test_mode_drift_is_repaired_without_rewriting_the_content() -> None:
    cfg = config()

    result = run(cfg, converged(cfg, mode="-rw-rw-rw-"))

    assert result.uploaded_paths == []
    assert result.mutating_changed_ops == [PREFIX + "Write Traefik route zellij"]
    assert any("chmod 644" in c and ROUTE in c for c in result.executed_commands)
    assert_untouched_services(result)


def test_custom_path_stays_in_the_dynamic_directory() -> None:
    cfg = config(traefik_config_path="/etc/traefik/dynamic/zellij-web.yml")

    result = run(cfg)

    assert result.uploaded_paths == ["/etc/traefik/dynamic/zellij-web.yml"]


@pytest.mark.parametrize("responses", [None, "deployed"])
def test_disabled_is_a_no_op_not_a_removal(responses: str | None) -> None:
    cfg = config(traefik_enabled=False)
    host = converged(config()) if responses else dict(fakehost.LINUX)

    result = run(cfg, host)

    assert result.ops == []
    assert result.executed_commands == []
    assert result.uploaded_paths == []


def test_disabled_needs_no_host_but_still_a_target() -> None:
    assert ZellijIngressConfig(traefik_enabled=False, redirect_target=TARGET).traefik_host == ""
    with pytest.raises(ValidationError):
        ZellijIngressConfig(traefik_enabled=False, redirect_target="")


# -- refused inputs ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"traefik_host": ""},
        {"traefik_host": "bad host"},
        {"traefik_host": "x.example.invalid`) || Host(`y"},
        {"traefik_host": "x.example.invalid\n"},
        {"traefik_host": "-x.example.invalid"},
        {"redirect_target": ""},
        {"redirect_target": "ftp://backend.example.invalid/"},
        {"redirect_target": "javascript:alert(1)"},
        {"redirect_target": "//backend.example.invalid/"},
        {"redirect_target": "https://user:pw@backend.example.invalid/"},
        {"redirect_target": "https://backend.example.invalid/?a=b"},
        {"redirect_target": "https://backend.example.invalid/#x"},
        {"redirect_target": 'https://backend.example.invalid/"x'},
        {"redirect_target": "https://backend.example.invalid/\\x"},
        {"redirect_target": "https://backend.example.invalid/$1"},
        {"redirect_target": "https://backend.example.invalid/{{ x }}"},
        {"redirect_target": "https://backend.example.invalid/ x"},
        {"redirect_target": "https://backend.example.invalid/\n"},
        {"redirect_target": "https://backend.example.invalid/%0a"},
        {"redirect_target": "https://backend.example.invalid:/"},
        {"redirect_target": "https://backend.example.invalid:0/"},
        {"redirect_target": "https://backend.example.invalid:99999/"},
        {"redirect_target": "https://bad_host/"},
        {"redirect_target": "https:///path"},
        {"traefik_entrypoints": ()},
        {"traefik_entrypoints": ("web secure",)},
        {"traefik_entrypoints": ("web\n- other",)},
        {"traefik_entrypoints": ("true",)},
        {"traefik_entrypoints": ("123",)},
        {"traefik_entrypoints": ("null",)},
        {"traefik_cert_resolver": "le\n      x: y"},
        {"traefik_cert_resolver": "yes"},
        {"traefik_cert_resolver": "a b"},
        {"traefik_config_path": ""},
        {"traefik_config_path": "/etc/traefik/zellij.yml"},
        {"traefik_config_path": "/etc/traefik/dynamic/../traefik.yml"},
        {"traefik_config_path": "/etc/traefik/dynamic/sub/zellij.yml"},
        {"traefik_config_path": "/etc/traefik/dynamic/zellij.yaml"},
        {"traefik_config_path": "/etc/traefik/dynamic/.zellij.yml"},
        {"traefik_config_path": "etc/traefik/dynamic/zellij.yml"},
        {"allowed_ip_ranges": ()},
        {"allowed_ip_ranges": ("not-a-network",)},
        {"allowed_ip_ranges": ("10.0.0.0/33",)},
        {"allowed_ip_ranges": ("10.0.0.0/255.0.0.0",)},
        {"allowed_ip_ranges": ("10.0.0.0/8`) || ClientIP(`0.0.0.0/0",)},
        {"unknown": 1},
    ],
)
def test_config_refuses_unsafe_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**bad)


def test_refusal_does_not_echo_the_value() -> None:
    with pytest.raises(ValidationError) as caught:
        config(redirect_target="https://user:fixture-secret@backend.example.invalid/")

    assert "fixture-secret" not in str(caught.value)


def test_config_is_frozen() -> None:
    cfg = config()

    with pytest.raises(ValidationError):
        cfg.traefik_host = "other.example.invalid"  # type: ignore[misc]
