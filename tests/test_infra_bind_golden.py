"""bind's configuration files stay byte for byte what nameservers have.

``tests/fixtures/bind/<case>.json`` holds a config (with synthetic TSIG keys)
and the distribution; ``tests/golden/bind/<case>/`` the four files rendered
from it (see ``tests/goldens.py``). Identical bytes mean the next deploy
rewrites no file and so does not reload named.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from ops_deploy.infra.bind import BindConfig, render_keys, render_local, render_named_conf, render_options
from ops_deploy.infra.bind.render import builtin_zones_file
from tests.goldens import assert_golden

FIXTURES = Path(__file__).parent / "fixtures" / "bind"
GOLDEN = Path(__file__).parent / "golden" / "bind"
CASE_NAMES = sorted(path.stem for path in FIXTURES.glob("*.json"))


def case(name: str) -> tuple[BindConfig, dict[str, SecretStr], str]:
    """The case's config, the key secrets and the builtin-zones include."""

    data = json.loads((FIXTURES / f"{name}.json").read_text())
    fields: dict[str, Any] = data["config"]
    keys = fields.pop("tsig_keys", [])
    secrets = {key["name"]: SecretStr(key.pop("secret")) for key in keys}
    cfg = BindConfig.model_validate({**fields, "tsig_keys": keys, "zone_files_dir": "/nonexistent"})
    return cfg, secrets, builtin_zones_file(cfg, data["distribution"], data["major_version"])


def rendered(name: str) -> dict[str, str]:
    cfg, secrets, builtin = case(name)
    return {
        "named.conf": render_named_conf(cfg, builtin),
        "named.conf.options": render_options(cfg),
        "named.conf.local": render_local(cfg),
        "named.conf.keys": render_keys(cfg, secrets).reveal().decode(),
    }


def test_cases_cover_the_interesting_inputs() -> None:
    assert CASE_NAMES == ["defaults", "primary", "secondary", "strings"]


@pytest.mark.parametrize("name", CASE_NAMES)
def test_config_files_are_golden(name: str) -> None:
    for file, text in rendered(name).items():
        assert_golden(GOLDEN / name / file, text)


def test_the_cases_exercise_the_branches() -> None:
    primary = rendered("primary")
    assert 'include "/etc/bind/named.conf.root-hints";' in primary["named.conf"]
    assert 'include "/etc/bind/named.conf.keys";' in primary["named.conf"]
    assert 'include "/etc/bind/named.conf.keys";' not in rendered("defaults")["named.conf"]
    assert "update-policy {" in primary["named.conf.local"]
    secondary = rendered("secondary")
    assert "primaries { 192.0.2.1 key" in secondary["named.conf.local"]
    assert 'file "/var/cache/bind/sec/db.absolute";' in secondary["named.conf.local"]
    assert "allow-recursion { none; };" in secondary["named.conf.options"]
    assert "listen-on { 127.0.0.1; };" in rendered("strings")["named.conf.options"]
    assert "algorithm hmac-sha512;" in primary["named.conf.keys"]
