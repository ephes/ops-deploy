"""GPS Timeline and Location Timeline Card: pinned downloads, the host helper and repeat runs.

The helper runs against synthetic archives served from ``file://`` URLs; the
pyinfra tests run the real operations on the local connector twice and check
that the second run changes nothing and asks for no restart.
"""

from __future__ import annotations

import grp
import hashlib
import importlib.util
import io
import json
import os
import pwd
import sys
import tarfile
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.services.homeassistant import HomeAssistantDeployConfig
from ops_deploy.services.homeassistant.pinned_assets import (
    GpsTimelineConfig,
    TimelineCardConfig,
    gps_timeline_payload,
    timeline_card_payload,
)
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

SPEC = importlib.util.spec_from_file_location(
    "owned_pinned_assets", str(files("ops_deploy.services.homeassistant").joinpath("files/pinned_assets.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

VERSION = "0.1.0-beta.3"
TOP = f"gps-timeline-{VERSION}"


def make_archive(path: Path, *, extra: list[tarfile.TarInfo] | None = None, manifest: bool = True) -> str:
    entries = {
        f"{TOP}/README.md": b"readme",
        f"{TOP}/hacs.json": b"{}",
        f"{TOP}/custom_components/gps_timeline/__init__.py": b"# synthetic",
        f"{TOP}/custom_components/gps_timeline/translations/en.json": b"{}",
    }
    if manifest:
        entries[f"{TOP}/custom_components/gps_timeline/manifest.json"] = b'{"version": "0.1.0-beta.3"}'
    with tarfile.open(path, "w:gz") as tar:
        for name in (TOP, f"{TOP}/custom_components", f"{TOP}/custom_components/gps_timeline"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o775
            tar.addfile(info)
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o664
            tar.addfile(info, io.BytesIO(data))
        for info in extra or []:
            tar.addfile(info)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime(tmp_path: Path) -> HomeAssistantRuntimeConfig:
    cfg = HomeAssistantRuntimeConfig(user=pwd.getpwuid(os.getuid()).pw_name, group=grp.getgrgid(os.getgid()).gr_name)
    # pytest's temporary path has underscores; substitute after validating defaults.
    return cfg.model_copy(
        update={
            "site_path": str(tmp_path / "site"),
            "config_path": str(tmp_path / "site/config"),
            "security": cfg.security.model_copy(update={"system_python": sys.executable}),
        }
    )


def component_payload(tmp_path: Path, source: Path, sha: str, action: str) -> dict[str, Any]:
    cfg = runtime(tmp_path)
    item = GpsTimelineConfig(enabled=True, sha256=sha, download_url=SecretStr(source.as_uri()))
    (tmp_path / "site/config/custom_components").mkdir(parents=True, exist_ok=True)
    (tmp_path / "site/downloads").mkdir(parents=True, exist_ok=True)
    value: dict[str, Any] = json.loads(gps_timeline_payload(cfg, item, action).get_secret_value())
    return value


def test_defaults_pin_the_spec_artifacts_and_stay_off() -> None:
    gps, card = GpsTimelineConfig(), TimelineCardConfig()
    assert (gps.enabled, card.enabled) == (False, False)
    assert gps.url() == "https://github.com/iamyacin/gps-timeline/archive/refs/tags/0.1.0-beta.3.tar.gz"
    assert gps.sha256 == "feb29bc1705181aab9146cacf2c7552a70d969042825734af0435000db1ee34e"
    assert card.url() == "https://github.com/iamyacin/timeline_card/releases/download/v1.9.3/timeline_card.js"
    assert card.sha256 == "d81404bc66ef2affcbd701af08a04fcfee199dadfb6b82674576291db50987a5"
    deploy = HomeAssistantDeployConfig()
    assert (deploy.gps_timeline, deploy.timeline_card) == (gps, card)
    cfg = HomeAssistantRuntimeConfig()
    payload = json.loads(gps_timeline_payload(cfg, gps, "check").get_secret_value())
    assert payload["component"] == "/home/homeassistant/site/config/custom_components/gps_timeline"
    assert payload["archive"] == "/home/homeassistant/site/downloads/gps-timeline-0.1.0-beta.3.tar.gz"
    assert payload["member"] == "gps-timeline-0.1.0-beta.3/custom_components/gps_timeline"
    card_payload = json.loads(timeline_card_payload(cfg, card, "check").get_secret_value())
    assert card_payload["dest"] == "/home/homeassistant/site/config/www/timeline_card.js"
    assert (payload["user"], card_payload["group"]) == ("homeassistant", "homeassistant")


@pytest.mark.parametrize("model", [GpsTimelineConfig, TimelineCardConfig])
def test_a_new_version_needs_its_checksum(model: type[GpsTimelineConfig] | type[TimelineCardConfig]) -> None:
    with pytest.raises(ValidationError, match="sha256 together"):
        model(version="9.9.9")
    assert model(version="9.9.9", sha256="a" * 64).version == "9.9.9"
    with pytest.raises(ValidationError):
        model(version="../x", sha256="a" * 64)
    assert "token" not in repr(model(download_url=SecretStr("https://owned.invalid/x?token=synthetic")))


def test_component_install_repeat_and_upgrade(tmp_path: Path) -> None:
    source = tmp_path / "release.tar.gz"
    sha = make_archive(source)
    component = tmp_path / "site/config/custom_components/gps_timeline"
    data = tmp_path / "site/config/gps_timeline"
    data.mkdir(parents=True)
    (data / "gps_timeline.db").write_bytes(b"history")

    assert helper.run(component_payload(tmp_path, source, sha, "check")) == {"success": True, "changed": True}
    assert helper.run(component_payload(tmp_path, source, sha, "apply")) == {"success": True, "changed": True}
    assert sorted(p.name for p in component.iterdir()) == [
        ".ops-pinned-version",
        "__init__.py",
        "manifest.json",
        "translations",
    ]
    assert (component / ".ops-pinned-version").read_text() == f"{VERSION} {sha}\n"
    assert component.stat().st_mode & 0o777 == 0o755
    assert (component / "manifest.json").stat().st_mode & 0o777 == 0o644
    assert not (tmp_path / "site/config/custom_components/README.md").exists()

    for action in ("check", "apply"):
        assert helper.run(component_payload(tmp_path, source, sha, action)) == {"success": True, "changed": False}

    # A drifted installed file is replaced together with the stamp; the data stays.
    (component / "stale.py").write_text("old")
    (component / ".ops-pinned-version").write_text("0.0.1 " + "b" * 64)
    assert helper.run(component_payload(tmp_path, source, sha, "apply")) == {"success": True, "changed": True}
    assert not (component / "stale.py").exists()
    assert (data / "gps_timeline.db").read_bytes() == b"history"
    leftovers = [p.name for p in component.parent.iterdir() if p.name.startswith(".")]
    assert leftovers == []


def test_checksum_mismatch_keeps_the_installed_component(tmp_path: Path) -> None:
    source = tmp_path / "release.tar.gz"
    sha = make_archive(source)
    assert helper.run(component_payload(tmp_path, source, sha, "apply"))["success"]
    component = tmp_path / "site/config/custom_components/gps_timeline"
    before = (component / ".ops-pinned-version").read_text()

    other = tmp_path / "other.tar.gz"
    make_archive(other, manifest=False)
    report = helper.run(component_payload(tmp_path, other, "c" * 64, "apply"))

    assert report == {"success": False, "changed": False, "error": "ValueError"}
    assert (component / ".ops-pinned-version").read_text() == before
    assert (tmp_path / "site/downloads" / f"gps-timeline-{VERSION}.tar.gz").read_bytes() == source.read_bytes()


@pytest.mark.parametrize("kind", ["symlink", "escape", "no-manifest"])
def test_unsafe_or_incomplete_archive_refuses_before_replacement(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "release.tar.gz"
    extra = []
    if kind == "symlink":
        info = tarfile.TarInfo(f"{TOP}/custom_components/gps_timeline/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        extra.append(info)
    elif kind == "escape":
        info = tarfile.TarInfo(f"{TOP}/custom_components/gps_timeline/../../../evil")
        extra.append(info)
    sha = make_archive(source, extra=extra, manifest=kind != "no-manifest")
    component = tmp_path / "site/config/custom_components/gps_timeline"
    component.mkdir(parents=True)
    (component / "keep").write_text("installed")

    report = helper.run(component_payload(tmp_path, source, sha, "apply"))

    assert report["success"] is False
    assert (component / "keep").read_text() == "installed"
    assert [p.name for p in component.parent.iterdir()] == ["gps_timeline"]


def test_card_file_install_repeat_and_metadata(tmp_path: Path) -> None:
    source = tmp_path / "timeline_card.js"
    source.write_bytes(b"customElements.define('x', class {});\n")
    item = TimelineCardConfig(
        enabled=True, sha256=hashlib.sha256(source.read_bytes()).hexdigest(), download_url=SecretStr(source.as_uri())
    )
    cfg = runtime(tmp_path)
    www = tmp_path / "site/config/www"
    www.mkdir(parents=True)

    def call(action: str) -> dict[str, Any]:
        result: dict[str, Any] = helper.run(json.loads(timeline_card_payload(cfg, item, action).get_secret_value()))
        return result

    assert call("check")["changed"] is True
    assert call("apply") == {"success": True, "changed": True}
    dest = www / "timeline_card.js"
    assert dest.read_bytes() == source.read_bytes()
    assert dest.stat().st_mode & 0o777 == 0o644
    stat_before = dest.stat()
    assert call("check") == {"success": True, "changed": False}
    assert call("apply") == {"success": True, "changed": False}
    assert dest.stat().st_ino == stat_before.st_ino
    dest.chmod(0o600)
    assert call("check")["changed"] is True
    assert call("apply") == {"success": True, "changed": True}
    assert dest.stat().st_mode & 0o777 == 0o644
    assert sorted(p.name for p in www.iterdir()) == ["timeline_card.js"]


def test_missing_service_account_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "release.tar.gz"
    sha = make_archive(source)
    payload = component_payload(tmp_path, source, sha, "apply")
    payload["user"] = "no-such-owned-user"
    assert helper.run({**payload, "action": "check"}) == {"success": True, "changed": True}
    assert helper.run(payload) == {"success": False, "changed": False, "error": "KeyError"}


def test_pyinfra_first_run_installs_and_repeat_changes_nothing(tmp_path: Path) -> None:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.pinned_assets import install_pinned_assets
    from ops_deploy.testing.harness import collect_ops

    archive = tmp_path / "release.tar.gz"
    card = tmp_path / "card.js"
    card.write_bytes(b"// synthetic card\n")
    gps = GpsTimelineConfig(enabled=True, sha256=make_archive(archive), download_url=SecretStr(archive.as_uri()))
    timeline = TimelineCardConfig(
        enabled=True, sha256=hashlib.sha256(card.read_bytes()).hexdigest(), download_url=SecretStr(card.as_uri())
    )
    cfg = runtime(tmp_path)
    (tmp_path / "site/config").mkdir(parents=True)
    restarts: list[bool] = []
    metas: list[Any] = []
    for number in (1, 2):
        state = State(Inventory(([("@local", {})], {})), Config())
        metas.clear()
        try:
            connect_all(state)
            add_deploy(state, lambda: metas.extend(install_pinned_assets(cfg, gps, timeline)))
            run_ops(state)
            ops = collect_ops(state, "@local")
            assert all(item.succeeded for item in ops)
            restarts.append(any(meta.did_change() for meta in metas))
            # First run: custom_components, downloads, www and both installs.
            assert sum(item.changed for item in ops) == (5 if number == 1 else 0)
        finally:
            disconnect_all(state)
    assert restarts == [True, False]
    assert (tmp_path / "site/config/www/timeline_card.js").read_bytes() == card.read_bytes()
    assert (tmp_path / "site/config/custom_components/gps_timeline/manifest.json").exists()


def test_disabled_registers_nothing(tmp_path: Path) -> None:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy

    from ops_deploy.services.homeassistant.pinned_assets import install_pinned_assets
    from ops_deploy.testing.harness import collect_ops

    state = State(Inventory(([("@local", {})], {})), Config())
    try:
        connect_all(state)
        result: list[Any] = []
        add_deploy(
            state,
            lambda: result.extend(install_pinned_assets(runtime(tmp_path), GpsTimelineConfig(), TimelineCardConfig())),
        )
        assert result == []
        assert collect_ops(state, "@local") == []
    finally:
        disconnect_all(state)


def test_deploy_restarts_home_assistant_only_through_the_pending_handlers() -> None:
    source = Path(str(files("ops_deploy.services.homeassistant").joinpath("deploy.py"))).read_text()
    assert (
        "for asset in install_pinned_assets(runtime, cfg.gps_timeline, cfg.timeline_card):\n"
        "        pending.homeassistant.append(partial(changed, asset))"
    ) in source
    helper_source = Path(str(files("ops_deploy.services.homeassistant").joinpath("files/pinned_assets.py"))).read_text()
    for untouched in ("configuration.yaml", "automations.yaml", "scripts.yaml"):
        assert untouched not in helper_source


def test_defaults_match_the_ansible_role() -> None:
    import yaml

    role = yaml.safe_load((Path(__file__).parent / "parity/homeassistant/deployment/defaults.yml").read_text())
    gps, card = GpsTimelineConfig(), TimelineCardConfig()
    assert role["homeassistant_gps_timeline_enabled"] is gps.enabled is False
    assert role["homeassistant_timeline_card_enabled"] is card.enabled is False
    assert (role["homeassistant_gps_timeline_version"], role["homeassistant_gps_timeline_sha256"]) == (
        gps.version,
        gps.sha256,
    )
    assert (role["homeassistant_timeline_card_version"], role["homeassistant_timeline_card_sha256"]) == (
        card.version,
        card.sha256,
    )
    assert (
        role["homeassistant_gps_timeline_download_url"].replace("{{ homeassistant_gps_timeline_version }}", gps.version)
        == gps.url()
    )
    assert (
        role["homeassistant_timeline_card_download_url"].replace(
            "{{ homeassistant_timeline_card_version }}", card.version
        )
        == card.url()
    )
    # Both tools write the same stamp, so either sees the other's install as current.
    tasks = (Path(__file__).parent / "parity/homeassistant/deployment/main.yml").read_text()
    assert "gps_timeline.yml" in tasks
    assert helper.STAMP == ".ops-pinned-version"


def test_failed_publication_restores_the_installed_component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "release.tar.gz"
    sha = make_archive(source)
    component = tmp_path / "site/config/custom_components/gps_timeline"
    component.mkdir(parents=True)
    (component / "keep").write_text("installed")
    real_rename = os.rename

    def rename(src: str, dst: str) -> None:
        if ".ops-ha-new-" in os.path.basename(src):
            raise OSError(28, "No space left on device")
        real_rename(src, dst)

    monkeypatch.setattr(helper.os, "rename", rename)
    report = helper.run(component_payload(tmp_path, source, sha, "apply"))

    assert report == {"success": False, "changed": False, "error": "OSError"}
    assert (component / "keep").read_text() == "installed"
    assert [p.name for p in component.parent.iterdir()] == ["gps_timeline"]


def test_failed_publication_and_rollback_keep_the_retired_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "release.tar.gz"
    sha = make_archive(source)
    component = tmp_path / "site/config/custom_components/gps_timeline"
    component.mkdir(parents=True)
    (component / "keep").write_text("installed")
    real_rename = os.rename

    def rename(src: str, dst: str) -> None:
        if os.path.basename(dst) == "gps_timeline":
            raise OSError(28, "No space left on device")
        real_rename(src, dst)

    monkeypatch.setattr(helper.os, "rename", rename)
    report = helper.run(component_payload(tmp_path, source, sha, "apply"))

    assert report["success"] is False
    (retired,) = component.parent.iterdir()
    assert retired.name.startswith(".ops-ha-old-")
    assert (retired / "keep").read_text() == "installed"
