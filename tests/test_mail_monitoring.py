"""Role render parity and invalid-input protection for monitor provisioning."""

import os
from pathlib import Path

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mail_monitoring import MailMonitoringConfig
from ops_deploy.services.mail_monitoring.deploy import render_role, validate_secrets


def test_all_six_templates_are_packaged() -> None:
    cfg = MailMonitoringConfig(
        address="monitor@example.test",
        relay_probe_enabled=True,
        relay_probe_url="https://relay.example.test",
        relay_probe_domain="mg.example.test",
        relay_probe_from="probe@example.test",
    )
    directory = Path(__file__).parents[1] / "src/ops_deploy/services/mail_monitoring/templates"
    assert len(list(directory.glob("*.j2"))) == 6
    for template in directory.glob("*.j2"):
        assert "{{" not in render_role(template.name, cfg)
    script = render_role("mailgun-relay-probe.sh.j2", cfg)
    assert "curl --config -" in script
    assert "/v3/${domain}/messages" in script


@pytest.mark.parametrize("password", ["", "CHANGE_ME", "fixture\nvalue", "fixture\rvalue", "fixture\0value"])
def test_password_controls_are_refused(password: str) -> None:
    cfg = MailMonitoringConfig(address="monitor@example.test")
    secrets = SecretValues(SecretRef("fixture.yml"), {"monitor_password": password})
    with pytest.raises(ValueError, match="monitor_password"):
        validate_secrets(cfg, secrets)


def test_optional_actual_role_template_bytes() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("OPS_LIBRARY_PATH not set")
    source = Path(library) / "roles/mail_monitoring/templates"
    packaged = Path(__file__).parents[1] / "src/ops_deploy/services/mail_monitoring/templates"
    assert {p.name for p in source.glob("*.j2")} == {p.name for p in packaged.glob("*.j2")}
    for template in source.glob("*.j2"):
        assert template.read_bytes() == (packaged / template.name).read_bytes()
