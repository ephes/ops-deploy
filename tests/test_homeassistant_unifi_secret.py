"""Synthetic host-local secret precedence and original template insertion."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.services.homeassistant.configuration_render import (
    ConfigurationSecretExamples,
    ConfigurationSecrets,
    render_secret_parts,
    render_secrets,
)
from tests.test_homeassistant_configuration_file import HELPER, invoke, payload


@pytest.mark.parametrize(
    ("explicit", "source", "variable", "expected"),
    [
        (" explicit ", "file", "ignored", " explicit "),
        ("", "file", "ignored", "file value"),
        ("", "variable", " variable ", " variable "),
        (" explicit ", "unknown", "ignored", " explicit "),
    ],
)
def test_original_precedence_and_only_file_value_trimmed(
    tmp_path: Path, explicit: str, source: str, variable: str, expected: str
) -> None:
    password = tmp_path / "owned-source"
    password.write_text(" \nfile value\n\t")
    data = {"explicit": explicit, "source": source, "file": str(password), "variable": variable}
    assert HELPER._unifi_password(data) == expected


@pytest.mark.parametrize("source", ["file", "variable", "unknown"])
def test_unresolved_has_no_extra_fallback_or_empty_write(tmp_path: Path, source: str) -> None:
    target = tmp_path / "secrets.yaml"
    request = {
        **payload(target),
        "kind": "secrets",
        "prefix": 'unifi_password: "',
        "suffix": '"\n',
        "unifi": {"explicit": "", "source": source, "file": str(tmp_path / "missing"), "variable": ""},
    }
    code, result = invoke(request)
    assert code == 1
    assert result["effects_started"] is False
    assert not target.exists()


def test_explicit_never_reads_file_and_file_error_does_not_fall_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(path: object) -> bytes:
        raise AssertionError("explicit credential must not read file")

    data = {"explicit": "synthetic", "source": "file", "file": str(tmp_path / "missing"), "variable": "unused"}
    with monkeypatch.context() as patch:
        patch.setattr(HELPER.Path, "read_bytes", forbidden)
        assert HELPER._unifi_password(data) == "synthetic"
    with pytest.raises(ValueError, match="unavailable"):
        HELPER._unifi_password({**data, "explicit": ""})


def test_template_parts_collision_retry_and_protected_halves(monkeypatch: pytest.MonkeyPatch) -> None:
    tokens = iter(["same", "unique"])
    monkeypatch.setattr(secrets, "token_hex", lambda size: next(tokens))
    examples = ConfigurationSecretExamples(mqtt_password=SecretStr("ops-ha-unifi-slot-same"))
    prefix, suffix = render_secret_parts(examples)
    effective = ' synthetic"credential\n '
    assert (
        prefix.get_secret_value() + effective + suffix.get_secret_value()
        == render_secrets(
            ConfigurationSecrets(unifi_password_effective=SecretStr(effective), **examples.model_dump())
        ).get_secret_value()
    )
    assert "slot-same" not in repr((prefix, suffix))
    assert "slot-unique" not in prefix.get_secret_value() + suffix.get_secret_value()


def test_actual_host_file_credential_write_and_repeat_never_exports_secret(tmp_path: Path) -> None:
    source = tmp_path / "owned-source"
    source.write_text(" \nsynthetic private credential\n")
    target = tmp_path / "secrets.yaml"
    prefix, suffix = render_secret_parts(ConfigurationSecretExamples())
    request = {
        **payload(target),
        "kind": "secrets",
        "prefix": prefix.get_secret_value(),
        "suffix": suffix.get_secret_value(),
        "unifi": {"explicit": "", "source": "file", "file": str(source), "variable": ""},
    }
    code, check = invoke({**request, "action": "check"})
    assert code == 0
    assert check["changed"] is True
    assert check["effects_started"] is False
    assert not target.exists()
    code, first = invoke(request)
    assert code == 0
    assert first["body_written"] is True
    assert "synthetic private credential" not in json.dumps(first)
    assert (
        target.read_text()
        == render_secrets(
            ConfigurationSecrets(unifi_password_effective=SecretStr("synthetic private credential"))
        ).get_secret_value()
    )
    assert invoke(request)[1]["changed"] is False


def test_original_non_utf8_file_bytes_survive_template_insertion(tmp_path: Path) -> None:
    source = tmp_path / "owned-source"
    source.write_bytes(b" \xff\n")
    target = tmp_path / "secrets.yaml"
    prefix, suffix = render_secret_parts(ConfigurationSecretExamples())
    request = {
        **payload(target),
        "kind": "secrets",
        "prefix": prefix.get_secret_value(),
        "suffix": suffix.get_secret_value(),
        "unifi": {"explicit": "", "source": "file", "file": str(source), "variable": ""},
    }
    code, result = invoke(request)
    assert code == 0
    assert result["body_written"] is True
    assert target.read_bytes() == prefix.get_secret_value().encode() + b"\xff" + suffix.get_secret_value().encode()
    assert invoke(request)[1]["changed"] is False


def test_invalid_action_does_not_read_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(path: object) -> bytes:
        raise AssertionError("invalid request must not read source")

    monkeypatch.setattr(HELPER.Path, "read_bytes", forbidden)
    with pytest.raises(ValueError, match="unsupported"):
        HELPER.process({"kind": "secrets", "action": "invalid"}, {})
