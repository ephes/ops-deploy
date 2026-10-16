"""nyxmon files are byte-identical to the nyxmon_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
switching a host between Ansible and ops-deploy rewrites nothing and restarts
nothing (apart from the Traefik route comments, see docs/concepts/helpers.md).
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.nyxmon import NyxmonConfig
from ops_deploy.services.nyxmon.deploy import TEMPLATE_PACKAGE, render_env
from tests.nyxmon_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
# Every character the role's shell quoting escapes, plus ones it must leave alone.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#'
OPSGATE_TOKEN = "opsgate-fixture-token-0123456789"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
    return env.get_template(f"nyxmon_deploy__{template}").render(**variables)


def role_vars(cfg: NyxmonConfig, secrets: SecretValues, **extra: Any) -> dict[str, Any]:
    site = str(cfg.site_path)
    return {
        "nyxmon_user": cfg.user,
        "nyxmon_group": cfg.user,
        "nyxmon_home": str(cfg.home),
        "nyxmon_site_path": site,
        "nyxmon_django_path": site,
        "nyxmon_venv_bin": f"{site}/.venv/bin",
        "nyxmon_cache_dir": f"{site}/cache",
        "nyxmon_workers": cfg.workers,
        "nyxmon_app_host": cfg.app_host,
        "nyxmon_app_port": cfg.app_port,
        "nyxmon_django_settings_module": cfg.django_settings_module,
        "nyxmon_django_secret_key": secrets["django_secret_key"],
        "nyxmon_django_allowed_hosts": cfg.django_allowed_hosts,
        "nyxmon_django_admin_url": cfg.django_admin_url,
        "nyxmon_django_debug": cfg.django_debug,
        "nyxmon_require_login": cfg.require_login,
        "nyxmon_telegram_bot_token": secrets["telegram_bot_token"],
        "nyxmon_telegram_chat_id": secrets["telegram_chat_id"],
        "nyxmon_notify_consecutive_failures": cfg.notify_consecutive_failures,
        "nyxmon_notify_repeat_interval_seconds": cfg.notify_repeat_interval_seconds,
        "nyxmon_notify_warning_repeat_interval_seconds": cfg.notify_warning_repeat_interval_seconds,
        "nyxmon_processing_lease_seconds": cfg.processing_lease_seconds,
        "nyxmon_check_batch_size": cfg.check_batch_size,
        "nyxmon_opsgate_submit_base_url": cfg.opsgate_submit_base_url,
        "nyxmon_opsgate_submit_token": secrets.get("opsgate_submit_token", ""),
        "nyxmon_opsgate_approval_base_url": cfg.opsgate_approval_url,
        "nyxmon_opsgate_ticket_expires_seconds": cfg.opsgate_ticket_expires_seconds,
        "nyxmon_opsgate_submit_timeout_seconds": cfg.opsgate_submit_timeout_seconds,
        "nyxmon_opsgate_submit_include_warnings": cfg.opsgate_submit_include_warnings,
        **extra,
    }


@pytest.fixture
def source(tmp_path: Path) -> Path:
    return make_source(tmp_path)


def make(source: Path, **overrides: Any) -> tuple[NyxmonConfig, SecretValues]:
    cfg = NyxmonConfig(source_path=source, secrets=SecretRef("secrets/prod/nyxmon.yml"), **overrides)
    assert cfg.secrets is not None
    values = {
        "django_secret_key": AWKWARD,
        "telegram_bot_token": "123456:fixture-bot-token",
        "telegram_chat_id": "-100987654321",
        "basic_auth_password": "fixture-password",
        "opsgate_submit_token": OPSGATE_TOKEN,
    }
    return cfg, SecretValues(cfg.secrets, values)


CONFIGS: list[dict[str, Any]] = [
    {},
    {
        "django_allowed_hosts": "127.0.0.1,nyxmon.example.com",
        "require_login": True,
        "opsgate_submit_base_url": "http://studio.example:8711",
        "opsgate_approval_base_url": "https://opsgate.example.com",
    },
    {"opsgate_submit_base_url": "http://studio.example:8711", "opsgate_submit_include_warnings": True},
    {"django_debug": True, "workers": 2, "app_port": 10100, "site_path": "/srv/nyx/site", "user": "nyx"},
]


@pytest.mark.parametrize("overrides", CONFIGS)
@pytest.mark.parametrize("shell", [False, True])
def test_env_matches_role(source: Path, overrides: dict[str, Any], shell: bool) -> None:
    cfg, secrets = make(source, **overrides)

    ours = render_env(cfg, secrets, shell=shell).reveal().decode()
    role = render_ansible("nyxmon.env.j2", role_vars(cfg, secrets, task_shell_environment=shell))

    assert ours == role


@pytest.mark.parametrize("overrides", CONFIGS)
@pytest.mark.parametrize("template", ["nyxmon.service.j2", "nyxmon-monitor.service.j2"])
def test_units_match_role(source: Path, overrides: dict[str, Any], template: str) -> None:
    cfg, secrets = make(source, **overrides)

    assert render(TEMPLATE_PACKAGE, template, cfg=cfg) == render_ansible(template, role_vars(cfg, secrets))


def test_shell_env_quotes_what_the_role_quotes(source: Path) -> None:
    cfg, secrets = make(source)

    shell = render_env(cfg, secrets, shell=True).reveal().decode()

    assert 'DJANGO_SECRET_KEY="k\\$y\\`with\\"quotes\\\\and(parens)&amp;#"' in shell.splitlines()


@pytest.mark.parametrize(
    "overrides",
    [
        {"agent_rust_version": "0.1.0"},
        {"agent_rust_version": "1.2.3-rc.1", "agent_rust_install_root": "/srv/agents", "site_path": "/srv/nyx/site"},
    ],
)
def test_agent_dropin_matches_role(source: Path, overrides: dict[str, Any]) -> None:
    cfg, secrets = make(source, agent_impl="rust", agent_rust_sha256="0" * 64, **overrides)
    extra = {"nyxmon_agent_rust_binary": f"{cfg.agent_rust_install_root}/{cfg.agent_rust_version}/nyxmon-agent"}

    ours = render(TEMPLATE_PACKAGE, "agent-impl.conf.j2", cfg=cfg)

    assert ours == render_ansible("agent-impl.conf.j2", role_vars(cfg, secrets, **extra))
    assert f"ExecStart={extra['nyxmon_agent_rust_binary']} --db {cfg.site_path}/db.sqlite3 --enable-telegram\n" in ours
