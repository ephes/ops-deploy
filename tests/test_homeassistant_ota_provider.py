"""chip-ota-provider-app: pinned, checksum-verified install next to the Matter server."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.services.homeassistant.ota_provider import install_ota_provider, install_script
from ops_deploy.services.homeassistant.ota_provider_config import (
    OTA_PROVIDER_CHECKSUMS,
    OTA_PROVIDER_URL_TEMPLATE,
    OTA_PROVIDER_VERSION,
)
from ops_deploy.services.homeassistant.remove import HomeAssistantRemoveConfig, remove_homeassistant
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/homeassistant"
DEST = "/usr/local/bin/chip-ota-provider-app"
X86 = OTA_PROVIDER_CHECKSUMS["x86-64"]


def cfg(**values: Any) -> HomeAssistantRuntimeConfig:
    return HomeAssistantRuntimeConfig(manage_matter_server=True, **values)


def test_defaults_match_the_ansible_role() -> None:
    defaults = yaml.safe_load((PARITY / "defaults.yml").read_text())
    runtime = HomeAssistantRuntimeConfig()
    for field in ("version", "url_template", "checksums", "path"):
        assert (
            getattr(runtime, "matter_server_ota_provider_" + field)
            == defaults["homeassistant_matter_server_ota_provider_" + field]
        )
    remove = yaml.safe_load((PARITY / "remove/defaults.yml").read_text())
    assert (
        HomeAssistantRemoveConfig().matter_server_ota_provider_path
        == remove["homeassistant_matter_server_ota_provider_path"]
    )
    assert remove["homeassistant_remove_matter_ota_provider"] is True
    # The Ansible task fills the same template; python-matter-server's Dockerfile pins this release.
    tasks = yaml.safe_load((PARITY / "matter_server.yml").read_text())
    (install,) = [task for task in tasks if task["name"] == "Install chip-ota-provider-app"]
    assert install["ansible.builtin.get_url"]["mode"] == "0755"
    assert OTA_PROVIDER_VERSION == "2025.9.0"


@pytest.mark.parametrize(
    "values",
    [
        {"matter_server_ota_provider_version": "2025.10.0"},
        {"matter_server_ota_provider_url_template": "http://example.org/{version}/{arch}"},
        {"matter_server_ota_provider_url_template": "https://example.org/{other}"},
        {"matter_server_ota_provider_url_template": "https://example.org/ {arch}"},
        {"matter_server_ota_provider_checksums": {"x86-64": "not-a-sha"}},
        {"matter_server_ota_provider_checksums": {"riscv64": X86}},
        {"matter_server_ota_provider_path": "/"},
        # python-matter-server looks it up by name on the Matter unit's PATH.
        {"matter_server_ota_provider_path": "/opt/matter/bin/chip-ota-provider-app"},
        {"matter_server_ota_provider_path": "/usr/local/bin/ota-provider"},
    ],
)
def test_invalid_inputs_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        cfg(**values)


def test_new_version_with_its_checksums_accepted() -> None:
    runtime = cfg(
        matter_server_ota_provider_version="2025.10.0",
        matter_server_ota_provider_checksums={"x86-64": "a" * 64},
    )
    assert runtime.matter_server_ota_provider_version == "2025.10.0"


def responses(**extra: Any) -> dict[str, Any]:
    return {**fakehost.LINUX, "uname -m": ["x86_64"], "which curl": ["/usr/bin/curl"], **extra}


def test_missing_binary_is_downloaded_verified_and_staged() -> None:
    run = run_deploy_fake(lambda: install_ota_provider(cfg()), responses=responses())
    assert run.succeeded, run.error
    (command,) = [c for c in run.executed_commands if "curl -fsSL" in c]
    url = OTA_PROVIDER_URL_TEMPLATE.format(version="2025.9.0", arch="x86-64")
    assert url in command
    assert X86 + "'  '\"$tmp/download\" | sha256sum -c --quiet -" in command
    # Verified before it is installed, then renamed over the destination.
    assert command.index("sha256sum -c") < command.index("install -o root -g root -m 0755")
    assert command.endswith(f"mv -fT /usr/local/bin/.chip-ota-provider-app.ops-deploy-new {DEST}")


def test_aarch64_uses_its_own_asset_and_checksum() -> None:
    run = run_deploy_fake(lambda: install_ota_provider(cfg()), responses=responses(**{"uname -m": ["aarch64"]}))
    assert run.succeeded, run.error
    (command,) = [c for c in run.executed_commands if "curl -fsSL" in c]
    assert command.count("chip-ota-provider-app-aarch64") == 1
    assert OTA_PROVIDER_CHECKSUMS["aarch64"] in command


def test_unknown_architecture_refused_before_any_change() -> None:
    run = run_deploy_fake(lambda: install_ota_provider(cfg()), responses=responses(**{"uname -m": ["riscv64"]}))
    assert not run.succeeded
    assert "no pinned checksum for architecture riscv64" in str(run.error)
    assert run.executed_commands == []


def test_pinned_binary_is_kept_and_a_repeat_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    # fakehost hashes the given content; pin that content's sha256.
    content = "binary"
    digest = hashlib.sha256(content.encode()).hexdigest()
    runtime = cfg().model_copy(update={"matter_server_ota_provider_checksums": {"x86-64": digest}})
    run = run_deploy_fake(
        lambda: install_ota_provider(runtime),
        responses=responses(**fakehost.file(DEST, content, mode="-rwxr-xr-x")),
    )
    assert run.succeeded, run.error
    assert not any("curl" in c for c in run.executed_commands)
    assert run.mutating_changed_ops == []


def test_wrong_checksum_or_symlink_is_replaced() -> None:
    for extra in (fakehost.file(DEST, "tampered", mode="-rwxr-xr-x"), fakehost.symlink(DEST, "/opt/old")):
        run = run_deploy_fake(lambda: install_ota_provider(cfg()), responses=responses(**extra))
        assert run.succeeded, run.error
        assert any("curl -fsSL" in c for c in run.executed_commands)


def test_script_refuses_a_bad_download(tmp_path: Path) -> None:
    source = tmp_path / "asset"
    source.write_bytes(b"real")
    dest = tmp_path / "bin/chip-ota-provider-app"
    dest.parent.mkdir()
    dest.write_bytes(b"old")
    script = install_script(source.as_uri(), "0" * 64, str(dest))
    # install -o root needs root; the checksum step fails first.
    result = subprocess.run(["bash", "-c", script], capture_output=True, check=False)
    assert result.returncode != 0
    assert dest.read_bytes() == b"old"
    assert not (dest.parent / ".chip-ota-provider-app.ops-deploy-new").exists()


def test_removal_deletes_the_binary_unless_kept() -> None:
    flags = {name: False for name in HomeAssistantRemoveConfig.model_fields if name.startswith("remove_")}
    for keep in (False, True):
        config = HomeAssistantRemoveConfig(confirm_removal=True, **{**flags, "remove_matter_ota_provider": not keep})
        run = run_deploy_fake(
            remove_homeassistant, config, responses={**fakehost.LINUX, **fakehost.file(DEST, "binary")}
        )
        assert run.succeeded, run.error
        removed = any(DEST in c and "rm" in c for c in run.executed_commands)
        assert removed is not keep


def test_directory_in_place_is_refused() -> None:
    run = run_deploy_fake(lambda: install_ota_provider(cfg()), responses=responses(**fakehost.directory(DEST)))
    assert not run.succeeded
    assert "exists and is not a file" in str(run.error)
    assert run.executed_commands == []


def test_paths_on_the_matter_unit_path_accepted() -> None:
    for path in ("/usr/local/bin/chip-ota-provider-app", "/usr/bin/chip-ota-provider-app"):
        assert cfg(matter_server_ota_provider_path=path).matter_server_ota_provider_path == path


def test_ansible_fallback_guards_match() -> None:
    tasks = yaml.safe_load((PARITY / "matter_server.yml").read_text())
    names = [task["name"] for task in tasks]
    for guard in (
        "Require a pinned chip-ota-provider-app checksum for this architecture",
        "Require chip-ota-provider-app checksums for a non-default version",
        "Require chip-ota-provider-app on the Matter server PATH",
    ):
        assert names.index(guard) < names.index("Install chip-ota-provider-app")
    # A symlink is replaced only by a verified staged file, never deleted first.
    assert not any(
        "chip-ota" in t["name"] and t.get("ansible.builtin.file", {}).get("state") == "absent" for t in tasks
    )
    assert names.index("Stage chip-ota-provider-app to replace a symlink") < names.index(
        "Replace chip-ota-provider-app symlink with the verified file"
    )
    (version_guard,) = [
        t for t in tasks if t["name"] == "Require chip-ota-provider-app checksums for a non-default version"
    ]
    text = version_guard["ansible.builtin.assert"]["that"][0]
    assert f"== '{OTA_PROVIDER_VERSION}'" in text
    assert all(value in text for value in OTA_PROVIDER_CHECKSUMS.values())
