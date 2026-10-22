"""bind's configuration files are byte-identical to what bind_authoritative_deploy writes.

``tests/parity/bind_authoritative_deploy/<case>/`` holds role variables
(``vars.json``, with Ansible's distribution facts) and the four files Ansible
itself rendered from the role's templates with them
(``ansible.builtin.template``, ansible-core 2.21, ops-library main 56564cce,
2.63.2; the role is unchanged up to 06394c81, 2.64.5). Identical bytes mean Ansible and ops-deploy take turns on a
nameserver without rewriting a file, and so without reloading named. The role
templates are also vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``).

With ``OPS_LIBRARY_PATH`` set, the config defaults, the task order and the
dynamic-zone seeding are compared with the role itself.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.infra.bind import BindConfig, render_keys, render_local, render_named_conf, render_options
from ops_deploy.infra.bind.render import builtin_zones_file

PARITY = Path(__file__).parent / "parity"
CASES = PARITY / "bind_authoritative_deploy"
VENDORED = PARITY / "ansible"
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src" / "ops_deploy" / "infra" / "bind" / "templates"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
TEMPLATES = ["bind_macros.j2", "named.conf.j2", "named.conf.keys.j2", "named.conf.local.j2", "named.conf.options.j2"]
CASE_NAMES = sorted(path.name for path in CASES.iterdir() if path.is_dir())


def case(name: str) -> tuple[BindConfig, dict[str, SecretStr], str]:
    """The case's role variables as a config, the key secrets and the builtin-zones include."""

    variables = json.loads((CASES / name / "vars.json").read_text())
    distribution = variables.pop("ansible_distribution")
    major = int(variables.pop("ansible_distribution_major_version"))
    fields: dict[str, Any] = {key.removeprefix("bind_"): value for key, value in variables.items()}
    keys = fields.pop("tsig_keys", [])
    secrets = {key["name"]: SecretStr(key.pop("secret")) for key in keys}
    cfg = BindConfig.model_validate({**fields, "tsig_keys": keys, "zone_files_dir": "/nonexistent"})
    return cfg, secrets, builtin_zones_file(cfg, distribution, major)


def ansible(name: str, file: str) -> str:
    return (CASES / name / file).read_text()


def test_cases_cover_the_interesting_inputs() -> None:
    assert CASE_NAMES == ["defaults", "primary", "secondary", "strings"]


@pytest.mark.parametrize("name", TEMPLATES)
def test_shipped_templates_are_the_vendored_role_templates(name: str) -> None:
    assert (PACKAGE_TEMPLATES / name).read_bytes() == (VENDORED / f"bind_authoritative_deploy__{name}").read_bytes()


@pytest.mark.parametrize("name", CASE_NAMES)
def test_named_conf_matches_ansible(name: str) -> None:
    cfg, _, builtin = case(name)

    assert render_named_conf(cfg, builtin) == ansible(name, "named.conf")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_options_match_ansible(name: str) -> None:
    cfg, _, _ = case(name)

    assert render_options(cfg) == ansible(name, "named.conf.options")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_local_matches_ansible(name: str) -> None:
    cfg, _, _ = case(name)

    assert render_local(cfg) == ansible(name, "named.conf.local")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_keys_match_ansible(name: str) -> None:
    cfg, secrets, _ = case(name)

    assert render_keys(cfg, secrets).reveal().decode() == ansible(name, "named.conf.keys")


def test_the_cases_exercise_the_branches() -> None:
    primary = ansible("primary", "named.conf")
    assert 'include "/etc/bind/named.conf.root-hints";' in primary
    assert 'include "/etc/bind/named.conf.keys";' in primary
    assert 'include "/etc/bind/named.conf.keys";' not in ansible("defaults", "named.conf")
    assert "update-policy {" in ansible("primary", "named.conf.local")
    assert "primaries { 192.0.2.1 key" in ansible("secondary", "named.conf.local")
    assert 'file "/var/cache/bind/sec/db.absolute";' in ansible("secondary", "named.conf.local")
    assert "allow-recursion { none; };" in ansible("secondary", "named.conf.options")
    assert "listen-on { 127.0.0.1; };" in ansible("strings", "named.conf.options")
    assert "algorithm hmac-sha512;" in ansible("primary", "named.conf.keys")


# -- against the role itself (OPS_LIBRARY_PATH) --------------------------------------------


def role_file(*parts: str) -> Any:
    assert OPS_LIBRARY is not None
    return yaml.safe_load(Path(OPS_LIBRARY, "roles", "bind_authoritative_deploy", *parts).read_text())


@needs_ops_library
def test_literal_defaults_match_the_role() -> None:
    defaults = role_file("defaults", "main.yml")
    cfg = BindConfig(zone_files_dir="/x", zones=[{"name": "example.org", "file": "db.example.org"}])
    # Templated or controller-side defaults, checked below or not fields here.
    derived = {"builtin_zones_file", "zone_files_dir", "zones", "allow_query_cache", "tsig_keys", "tsig_keys_file"}
    names = {key.removeprefix("bind_") for key in defaults} - derived
    assert names <= set(BindConfig.model_fields)
    for name in sorted(names):
        ours = getattr(cfg, name)
        if isinstance(ours, tuple):
            ours = list(ours)
        assert ours == defaults[f"bind_{name}"], name
    assert defaults["bind_zones"] == []
    assert defaults["bind_tsig_keys"] == []
    assert defaults["bind_allow_query_cache"] == "{{ bind_recursion_acl }}"
    assert defaults["bind_tsig_keys_file"] == "{{ bind_config_dir }}/named.conf.keys"
    assert "named.conf.root-hints" in defaults["bind_builtin_zones_file"]
    assert "(ansible_distribution_major_version | int) >= 13" in defaults["bind_builtin_zones_file"]


@needs_ops_library
def test_role_task_order_is_the_ported_order() -> None:
    main = role_file("tasks", "main.yml")
    assert [task.get("ansible.builtin.import_tasks") or task.get("ansible.builtin.meta") for task in main] == [
        "validate.yml",
        "packages.yml",
        "config.yml",
        "service.yml",
        "flush_handlers",
        "verify.yml",
    ]
    config = role_file("tasks", "config.yml")
    assert [task["name"] for task in config] == [
        "Ensure BIND config directory exists",
        "Ensure BIND working directory is writable by named",
        "Ensure dynamic zone directory is writable by named",
        "Render TSIG keys",
        "Render named.conf.options",
        "Render named.conf.local",
        "Install zone files",
        "Seed dynamic zone files",
        "Render named.conf",
        "Remove TSIG keys file when no keys are configured",
    ]


@needs_ops_library
def test_the_role_only_seeds_dynamic_zones() -> None:
    seed = next(task for task in role_file("tasks", "config.yml") if task["name"] == "Seed dynamic zone files")
    copy = seed["ansible.builtin.copy"]
    assert copy["force"] is False
    assert copy["owner"] == "{{ bind_service_user }}"
    assert copy["mode"] == "0644"
    assert copy["validate"] == "named-checkzone {{ item.name }} %s"
    install = next(task for task in role_file("tasks", "config.yml") if task["name"] == "Install zone files")
    assert "not (item.dynamic | default(false) | bool)" in install["when"]
