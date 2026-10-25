"""The role env is sourced by both release commands and maintenance Bash."""

from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mastodon import MastodonConfig, deploy_mastodon
from ops_deploy.services.mastodon.render import SECRET_KEYS, render_env
from ops_deploy.testing import run_deploy_fake
from tests.test_mastodon import config
from tests.test_mastodon_release_source import release_config


@pytest.mark.parametrize(
    "value",
    [
        "a;b",
        "a|b",
        "a&b",
        "a<b",
        "a>b",
        "a(b)",
        "a'b",
        "a b",
        "a\tb",
        "a\vb",
        "a\fb",
        "~",
        "x:~root",
        'a"b',
        "a\\b",
        "a$b",
        "a`b",
    ],
)
@pytest.mark.parametrize("factory", [config, release_config])
def test_unsafe_secret_rejected_before_any_host_fact_or_operation(
    value: str, factory: Callable[[], MastodonConfig]
) -> None:
    values = dict.fromkeys(SECRET_KEYS, "safe")
    values["smtp_password"] = value
    secret = SecretValues(SecretRef("secrets/test/mastodon.yml"), values)
    with (
        patch("ops_deploy.services.mastodon.deploy.require_linux", side_effect=AssertionError("host fact")) as legacy,
        patch("ops_deploy.services.mastodon.release.require_linux", side_effect=AssertionError("host fact")) as release,
        pytest.raises(ValueError, match="unsupported unquoted literal"),
    ):
        run_deploy_fake(deploy_mastodon, cfg=factory(), secrets=secret, responses={})
    legacy.assert_not_called()
    release.assert_not_called()


@pytest.mark.parametrize("value", ["a;b", "a b", "a'b", "~", "x:~"])
def test_unquoted_smtp_login_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        config(smtp_login=value)


def test_valid_literals_and_quoted_address_keep_exact_bytes() -> None:
    values = dict.fromkeys(SECRET_KEYS, "é:pa~ss={{literal}}")
    cfg = config(smtp_login="é+sender@example.org", smtp_from_address="Sender; ~ Name <sender@example.org>")
    text = render_env(cfg, SecretValues(SecretRef("secrets/test/mastodon.yml"), values)).reveal().decode()
    assert "SMTP_PASSWORD=é:pa~ss={{literal}}\n" in text
    assert 'SMTP_FROM_ADDRESS="Sender; ~ Name <sender@example.org>"\n' in text


def test_actual_maintenance_template_sources_literal_env(tmp_path: Path) -> None:
    import subprocess

    from ops_deploy.services.mastodon.render import render

    cfg = release_config().model_copy(update={"maintenance_tootctl_commands": [], "maintenance_extra_commands": []})
    script = render(cfg, "maintenance.sh.j2")
    # Run the genuine consumer, replacing only its existing-install paths.
    script = script.replace(cfg.site_path + "/.env.production", str(tmp_path / "env"))
    script = script.replace('cd "' + cfg.site_path + '"', 'cd "' + str(tmp_path) + '"')
    marker = tmp_path / "injected"
    bad = "safe; printf injected > " + str(marker)
    (tmp_path / "env").write_text("SMTP_PASSWORD=" + bad + "\n")
    subprocess.run(["/bin/bash", "-c", script], check=True)
    assert marker.exists()  # Demonstrates the consumer boundary, not malformed JSON etc.
    values = dict.fromkeys(SECRET_KEYS, "safe")
    values["smtp_password"] = bad
    with pytest.raises(ValueError, match="unsupported unquoted literal"):
        render_env(cfg, SecretValues(SecretRef("secrets/test/mastodon.yml"), values))
