"""nyxmon's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/nyxmon`` were recorded when these renders
still equalled the retired nyxmon_deploy role's output; identical bytes mean
the next deploy rewrites nothing and restarts nothing (see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.nyxmon import NyxmonConfig
from ops_deploy.services.nyxmon.deploy import TEMPLATE_PACKAGE, render_env
from tests.goldens import assert_golden
from tests.nyxmon_fixtures import make_source

GOLDEN = Path(__file__).parent / "golden" / "nyxmon"
# Every character the env file's shell quoting escapes, plus ones it must leave alone.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#'
OPSGATE_TOKEN = "opsgate-fixture-token-0123456789"


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


CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "login-opsgate": {
        "django_allowed_hosts": "127.0.0.1,nyxmon.example.com",
        "require_login": True,
        "opsgate_submit_base_url": "http://studio.example:8711",
        "opsgate_approval_base_url": "https://opsgate.example.com",
    },
    "warning-digest": {"notify_warning_delivery": "digest", "warning_digest_on_calendar": "Fri *-*-* 07:30:00"},
}
UNITS = (
    "nyxmon.service.j2",
    "nyxmon-monitor.service.j2",
    "nyxmon-warning-digest.service.j2",
    "nyxmon-warning-digest.timer.j2",
)


@pytest.mark.parametrize("case", sorted(CASES))
def test_host_files_are_golden(source: Path, case: str) -> None:
    cfg, secrets = make(source, agent_rust_version="0.1.0", agent_rust_sha256="0" * 64, **CASES[case])

    assert_golden(GOLDEN / case / "nyxmon.env", render_env(cfg, secrets, shell=False).reveal().decode())
    assert_golden(GOLDEN / case / "nyxmon.shell.env", render_env(cfg, secrets, shell=True).reveal().decode())
    for template in UNITS:
        assert_golden(GOLDEN / case / template.removesuffix(".j2"), render(TEMPLATE_PACKAGE, template, cfg=cfg))


def test_shell_env_quotes_shell_metacharacters(source: Path) -> None:
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
def test_monitor_unit_starts_the_versioned_rust_agent(source: Path, overrides: dict[str, Any]) -> None:
    # The Python agent fallback is retired (ops-library 2.75.0): the unit itself names the versioned binary.
    cfg, _ = make(source, agent_rust_sha256="0" * 64, **overrides)
    binary = f"{cfg.agent_rust_install_root}/{cfg.agent_rust_version}/nyxmon-agent"

    ours = render(TEMPLATE_PACKAGE, "nyxmon-monitor.service.j2", cfg=cfg)

    assert f"\nExecStart={binary} --db {cfg.site_path}/db.sqlite3 --enable-telegram\n" in ours
    assert "start-agent" not in ours
