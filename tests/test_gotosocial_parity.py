"""gotosocial files are byte-identical to what the gotosocial_deploy role writes.

``tests/parity/gotosocial_deploy/<case>/`` holds role variables (``vars.json``)
and the four files Ansible itself rendered from the role's templates with them
(``ansible.builtin.template``, ansible-core 2.21, ops-library main 540ede2b,
2.56.0). Identical bytes mean Ansible and ops-deploy take turns on a host
without rewriting ``config.yaml``, the unit, the admin wrapper or the route,
and so without restarting GoToSocial. The role templates are also vendored
under ``tests/parity/ansible`` (checked against ops-library by
``test_traefik_parity.test_vendored_templates_match_ops_library``).

With ``OPS_LIBRARY_PATH`` set, the config defaults and the guarded keys are
compared with the role's ``defaults/main.yml``.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.services.gotosocial import (
    GUARDED_CONFIG_KEYS,
    GotosocialConfig,
    render_admin_wrapper,
    render_config,
    render_route,
    render_unit,
)
from ops_deploy.services.gotosocial.config import ARCH_MAP

PARITY = Path(__file__).parent / "parity"
CASES = PARITY / "gotosocial_deploy"
VENDORED = PARITY / "ansible"
PACKAGE_TEMPLATES = Path(__file__).parents[1] / "src" / "ops_deploy" / "services" / "gotosocial" / "templates"
OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
TEMPLATES = ["config.yaml.j2", "gotosocial-admin.sh.j2", "gotosocial.service.j2", "traefik.yml.j2"]


def case(name: str) -> tuple[GotosocialConfig, SecretStr | None]:
    """The case's role variables as a config (and the SMTP password, a deploy argument)."""

    variables = json.loads((CASES / name / "vars.json").read_text())
    fields = {key.removeprefix("gotosocial_"): value for key, value in variables.items()}
    password = fields.pop("smtp_password", None)
    return GotosocialConfig(**fields), SecretStr(password) if password is not None else None


def ansible(name: str, file: str) -> str:
    return (CASES / name / file).read_text()


CASE_NAMES = sorted(path.name for path in CASES.iterdir() if path.is_dir())


def test_cases_cover_the_interesting_inputs() -> None:
    assert CASE_NAMES == ["defaults", "full", "ipv6"]


@pytest.mark.parametrize("name", TEMPLATES)
def test_shipped_templates_are_the_vendored_role_templates(name: str) -> None:
    assert (PACKAGE_TEMPLATES / name).read_bytes() == (VENDORED / f"gotosocial_deploy__{name}").read_bytes()


@pytest.mark.parametrize("name", CASE_NAMES)
def test_config_matches_ansible(name: str) -> None:
    cfg, password = case(name)

    assert render_config(cfg, password).reveal().decode() == ansible(name, "config.yaml")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_unit_matches_ansible(name: str) -> None:
    cfg, _ = case(name)

    assert render_unit(cfg) == ansible(name, "gotosocial.service")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_admin_wrapper_matches_ansible(name: str) -> None:
    cfg, _ = case(name)

    assert render_admin_wrapper(cfg) == ansible(name, "gotosocial-admin.sh")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_route_matches_ansible(name: str) -> None:
    cfg, _ = case(name)

    assert render_route(cfg) == ansible(name, "traefik.yml")


def test_full_case_merges_extra_config_recursively() -> None:
    cfg, _ = case("full")
    rendered = yaml.safe_load(render_config(cfg, None).reveal())

    assert rendered["cache"] == {"memory-target": "100MiB", "visibility-mem-ratio": 2}
    assert rendered["http-client"] == {"timeout": "30s", "allow-ips": ["10.0.0.0/8"]}


def test_the_ipv6_case_derives_paths_from_the_roots() -> None:
    cfg, _ = case("ipv6")
    config = yaml.safe_load(render_config(cfg, None).reveal())

    assert config["db-address"] == "/srv/gts-data/sqlite.db"
    assert config["web-asset-base-dir"] == "/srv/gts/current/web/assets/"
    assert cfg.release_dir == "/srv/gts/releases/0.22.2"
    assert cfg.layout_marker_path == "/srv/gts-data/.ops-domain-layout"


# -- against the role itself (OPS_LIBRARY_PATH) --------------------------------------------


def role_defaults() -> dict[str, Any]:
    assert OPS_LIBRARY is not None
    path = Path(OPS_LIBRARY, "roles", "gotosocial_deploy", "defaults", "main.yml")
    defaults: dict[str, Any] = yaml.safe_load(path.read_text())
    return defaults


@needs_ops_library
def test_literal_defaults_match_the_role() -> None:
    defaults = role_defaults()
    cfg = GotosocialConfig(host="example.org")
    # Role variables the config holds under the same name; templated ones are derived below.
    derived = {
        "arch_map",
        "arch",
        "download_url",
        "release_dir",
        "current_link",
        "config_path",
        "db_path",
        "storage_dir",
        "cache_dir",
        "layout_marker_path",
        "guarded_config_keys",
        "traefik_host",
        "host",
        "smtp_password",
    }
    names = {key.removeprefix("gotosocial_") for key in defaults} - derived
    assert names <= set(GotosocialConfig.model_fields)
    for name in sorted(names):
        ours = getattr(cfg, name)
        theirs = defaults[f"gotosocial_{name}"]
        if isinstance(ours, tuple):
            ours = list(ours)
        assert ours == theirs, name


@needs_ops_library
def test_derived_defaults_match_the_role() -> None:
    defaults = role_defaults()
    cfg = GotosocialConfig(host="example.org")

    assert defaults["gotosocial_arch_map"] == ARCH_MAP
    assert list(defaults["gotosocial_guarded_config_keys"]) == list(GUARDED_CONFIG_KEYS)
    assert defaults["gotosocial_host"] == "CHANGEME"
    assert defaults["gotosocial_smtp_password"] == ""
    assert defaults["gotosocial_traefik_host"] == "{{ gotosocial_host }}"
    expected = {
        "release_dir": "{{ gotosocial_install_root }}/releases/{{ gotosocial_version }}",
        "current_link": "{{ gotosocial_install_root }}/current",
        "config_path": "{{ gotosocial_config_dir }}/config.yaml",
        "db_path": "{{ gotosocial_data_dir }}/sqlite.db",
        "storage_dir": "{{ gotosocial_data_dir }}/storage",
        "cache_dir": "{{ gotosocial_data_dir }}/.cache",
        "layout_marker_path": "{{ gotosocial_data_dir }}/.ops-domain-layout",
    }
    for name, template in expected.items():
        assert defaults[f"gotosocial_{name}"] == template, name
        rendered = (
            template.replace("{{ gotosocial_install_root }}", cfg.install_root)
            .replace("{{ gotosocial_version }}", cfg.version)
            .replace("{{ gotosocial_config_dir }}", cfg.config_dir)
            .replace("{{ gotosocial_data_dir }}", cfg.data_dir)
        )
        assert getattr(cfg, name) == rendered, name
    url = defaults["gotosocial_download_url"].strip()
    assert url == (
        "{{ gotosocial_download_base_url }}/v{{ gotosocial_version }}/"
        "gotosocial_{{ gotosocial_version }}_linux_{{ gotosocial_arch }}.tar.gz"
    )
    assert cfg.download_url("arm64") == (
        f"{cfg.download_base_url}/v{cfg.version}/gotosocial_{cfg.version}_linux_arm64.tar.gz"
    )


@needs_ops_library
def test_role_task_order_is_the_ported_order() -> None:
    assert OPS_LIBRARY is not None
    main = yaml.safe_load(Path(OPS_LIBRARY, "roles", "gotosocial_deploy", "tasks", "main.yml").read_text())

    assert [task["ansible.builtin.import_tasks"] for task in main] == [
        "validate.yml",
        "packages.yml",
        "user.yml",
        "layout.yml",
        "binary.yml",
        "config.yml",
        "systemd.yml",
        "service.yml",
        "health.yml",
        "layout_record.yml",
        "traefik.yml",
    ]
