"""opaq_app files are byte-identical to the opaq_app_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
switching a host between Ansible and ops-deploy rewrites nothing and restarts
nothing.

One filter has no defined output in Ansible: ``union`` builds a set, so the
order of ``DJANGO_ALLOWED_HOSTS`` depends on the controller's hash seed and the
role may rewrite the env file (and restart the app) on a converged host. Here
it keeps order, host name first, which is one of the two orders the role writes.
"""

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.opaq_app import OpaqAppConfig
from ops_deploy.services.opaq_app.deploy import TEMPLATE_PACKAGE, render_env, render_route, upload_token_sha256
from tests.opaq_app_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
SECRETS = {
    "django_secret_key": "opaq-parity-key-" + "abcdefghij" * 4,
    "upload_token": "opaq-parity-upload-token-0123456789abcdef",
}


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["union"] = lambda a, b: list(dict.fromkeys([*a, *b]))
    env.filters["to_json"] = json.dumps
    return env.get_template(f"opaq_app_deploy__{template}").render(**variables)


def role_vars(cfg: OpaqAppConfig, secrets: SecretValues) -> dict[str, Any]:
    return {
        "opaq_app_user": cfg.user,
        "opaq_app_group": cfg.user,
        "opaq_app_site_path": str(cfg.site_path),
        "opaq_app_app_dir": str(cfg.app_dir),
        "opaq_app_data_path": str(cfg.data_path),
        "opaq_app_database_path": str(cfg.database_path),
        "opaq_app_static_root": str(cfg.static_root),
        "opaq_app_env_file": str(cfg.env_path),
        "opaq_app_venv_bin": f"{cfg.venv_path}/bin",
        "opaq_app_workers": cfg.workers,
        "opaq_app_app_host": cfg.app_host,
        "opaq_app_app_port": cfg.app_port,
        "opaq_app_secret_key": secrets["django_secret_key"],
        "opaq_app_upload_token_sha256": upload_token_sha256(secrets),
        "opaq_app_traefik_host": cfg.traefik_host or "",
        "opaq_app_traefik_entrypoint": cfg.traefik_entrypoint,
        "opaq_app_traefik_http_entrypoint": cfg.traefik_http_entrypoint,
        "opaq_app_allowed_networks": list(cfg.allowed_networks),
    }


CONFIGS: list[dict[str, Any]] = [
    {},
    {"workers": 4, "app_port": 10100, "traefik_host": "opaq-next.example.com"},
    {"allowed_networks": ("10.0.0.0/8",), "traefik_entrypoint": "websecure", "traefik_http_entrypoint": "http"},
    {"user": "opaq", "site_path": "/home/opaq/site"},
    {"traefik_enabled": False, "traefik_host": None, "allowed_networks": ()},
]


def make(tmp_path: Path, **overrides: Any) -> tuple[OpaqAppConfig, SecretValues]:
    ref = SecretRef("secrets/prod/opaq_app.yml")
    settings: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": ref,
        "traefik_host": "opaq.example.com",
        "allowed_networks": ("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
    }
    return OpaqAppConfig(**{**settings, **overrides}), SecretValues(ref, SECRETS)


@pytest.mark.parametrize("overrides", CONFIGS)
def test_env_matches_role(tmp_path: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(tmp_path, **overrides)

    assert render_env(cfg, secrets).reveal().decode() == render_ansible("env.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", CONFIGS)
def test_unit_matches_role(tmp_path: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(tmp_path, **overrides)

    ours = render(TEMPLATE_PACKAGE, "opaq-app.service.j2", cfg=cfg)

    assert ours == render_ansible("opaq-app.service.j2", role_vars(cfg, secrets))


@pytest.mark.parametrize("overrides", [c for c in CONFIGS if c.get("traefik_enabled", True)])
def test_route_matches_role(tmp_path: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(tmp_path, **overrides)

    assert render_route(cfg) == render_ansible("traefik.yml.j2", role_vars(cfg, secrets))
