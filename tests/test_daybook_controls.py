"""Fixed production declarations and owned, entirely synthetic host controls."""

from __future__ import annotations

import importlib.resources
import os
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.services.daybook_controls import DaybookControlConfig
from ops_deploy.services.daybook_controls import deploy as control_api
from ops_deploy.testing import run_deploy_fake


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name, package, resource in (
        ("ops_control_filesystem", "daybook_sessions", "resources_host.py"),
        ("ops_control_launchd", "daybook_photos_offload", "photos_controls.py"),
    ):
        module = types.ModuleType(name)
        body = importlib.resources.files("ops_deploy.services." + package).joinpath("files/" + resource).read_text()
        exec(compile(body, name, "exec"), module.__dict__)
        monkeypatch.setitem(sys.modules, name, module)
    module = types.ModuleType("owned_control_helper")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_controls").joinpath("files/controls_host.py").read_text()
    )
    exec(compile(body, "owned_control_helper", "exec"), module.__dict__)
    return module


class Controls:
    def __init__(
        self, *, loaded: bool = True, disabled: bool = False, disable_ok: bool = True, bootout_ok: bool = True
    ) -> None:
        self.service = "gui/501/owned.test"
        self.loaded, self.disabled = loaded, disabled
        self.disable_ok, self.bootout_ok = disable_ok, bootout_ok
        self.calls: list[str] = []

    def snapshot(self, **_kwargs: Any) -> dict[str, bool]:
        return {"domain_available": True, "loaded": self.loaded, "disabled": self.disabled}

    def attempt(self, action: str, service: str) -> bool:
        assert service == self.service
        self.calls.append(action)
        if action == "disable":
            if self.disable_ok:
                self.disabled = True
            return self.disable_ok
        if self.bootout_ok:
            self.loaded = False
        return self.bootout_ok

    def require_quiescent(self) -> None:
        assert self.disabled is True
        assert self.loaded is False


def data(service: str, root: Path, *, confirmed: bool = False) -> dict[str, Any]:
    # Host mechanism fixture deliberately substitutes owned paths/label; public
    # production declaration validation is tested separately below.
    return {
        "service": service,
        "action": "remove" if service == "attention" else "disable",
        "uid": 501,
        "label": "owned.test",
        "home": str(root),
        "confirmed": confirmed,
    }


@pytest.mark.parametrize("service", ["photos", "archive"])
def test_disable_requires_no_approval_and_fixed_owner_label(service: Any) -> None:
    cfg = DaybookControlConfig(service=service, action="disable", owner="jochen")
    assert cfg.home == "/Users/jochen"
    assert cfg.label.startswith("de.wersdoerfer.daybook.")
    assert cfg.confirmed is False


@pytest.mark.parametrize(
    "change",
    [
        {"owner": "root"},
        {"owner": "other\nowner"},
        {"home": "/tmp/other"},
        {"label": "unrelated.service"},
        {"action": "remove"},
    ],
)
def test_original_disable_scope_refuses_overrides(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DaybookControlConfig(**{"service": "photos", "action": "disable", "owner": "jochen", **change})


def test_attention_removal_retains_explicit_boolean_confirmation() -> None:
    for confirmation in (False, "true", 1):
        declaration: dict[str, Any] = {
            "service": "attention",
            "action": "remove",
            "owner": "jochen",
            "confirmed": confirmation,
        }
        with pytest.raises(ValidationError):
            DaybookControlConfig(**declaration)
    assert DaybookControlConfig(service="attention", action="remove", owner="jochen", confirmed=True)


def test_photos_already_disabled_still_performs_original_both_attempts(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    ctl = Controls(loaded=False, disabled=True)
    result = helper.execute(data("photos", tmp_path), controls=ctl)
    assert ctl.calls == ["disable", "bootout"]
    assert result["previously_disabled_unloaded"] is True
    assert result["plist_removed"] is False


@pytest.mark.parametrize("service", ["archive", "attention"])
def test_original_immediate_disable_failure_never_boots_out_or_removes(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, service: str
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501 if service == "archive" else 0)
    ctl = Controls(disable_ok=False)
    with pytest.raises(helper.ControlError):
        helper.execute(data(service, tmp_path, confirmed=True), controls=ctl)
    assert ctl.calls == ["disable"]


def test_photos_disable_failure_still_attempts_bootout(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    ctl = Controls(disable_ok=False)
    with pytest.raises(AssertionError):
        helper.execute(data("photos", tmp_path), controls=ctl)
    assert ctl.calls == ["disable", "bootout"]


def test_attention_removes_only_exact_plist_and_never_opens_private_bodies(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve()
    agents = root / "Library/LaunchAgents"
    agents.mkdir(parents=True)
    plist = agents / "owned.test.plist"
    plist.write_bytes(b"OWNED synthetic plist")
    protected = [root / name for name in ("config.json", "state.sqlite3", "stdout.log", "credentials.json")]
    for path in protected:
        path.write_bytes(b"OWNED preserved private body")
    before = {path: path.stat() for path in protected}
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    original_open = os.open

    def directory_only(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        assert flags & os.O_DIRECTORY, "control may open directories only"
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", directory_only)
    first = helper.execute(data("attention", root, confirmed=True), controls=Controls())
    repeat = helper.execute(data("attention", root, confirmed=True), controls=Controls(loaded=False, disabled=True))
    assert first["plist_removed"] is True
    assert repeat["plist_removed"] is False
    assert not plist.exists()
    assert {path: path.stat() for path in protected} == before


def test_attention_linked_parent_refuses_before_control_attempt(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve()
    (root / "real").mkdir()
    (root / "Library").symlink_to(root / "real", target_is_directory=True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    ctl = Controls()
    with pytest.raises(helper.ControlError):
        helper.execute(data("attention", root, confirmed=True), controls=ctl)
    assert not ctl.calls


def test_archive_wrong_connecting_identity_refuses_before_any_control(
    helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    ctl = Controls()
    with pytest.raises(helper.ControlError):
        helper.execute(data("archive", tmp_path), controls=ctl)
    assert not ctl.calls


@pytest.mark.parametrize("service", ["photos", "archive", "attention"])
def test_actual_SDK_always_managed_and_clears_all_inherited_privilege_switches(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = DaybookControlConfig(
        service=service,
        action="remove" if service == "attention" else "disable",
        owner="fixture",
        confirmed=service == "attention",
    )
    original = FakeConnector.run_shell_command
    calls = []

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(k) in {False, None} for k in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(k) in {"", None} for k in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        calls.append(True)
        return original(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", shell)
    for _ in range(2):
        result = run_deploy_fake(
            control_api.run_daybook_control,
            cfg,
            responses={
                "uname -s": ["Darwin"],
                "/usr/bin/id -u fixture": ["501"],
                "/usr/bin/id -u": ["501" if service == "archive" else "0"],
            },
            _sudo=True,
            _sudo_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
            _su_user="root",
        )
        assert result.succeeded, result.error
        assert len(result.mutating_changed_ops) == 1
        assert result.uploaded_paths == []
    assert calls


@pytest.mark.parametrize(("service", "uid"), [("archive", "0"), ("photos", "501"), ("attention", "501")])
def test_actual_SDK_wrong_connecting_identity_refuses_before_operations(service: Any, uid: str) -> None:
    cfg = DaybookControlConfig(
        service=service,
        action="remove" if service == "attention" else "disable",
        owner="fixture",
        confirmed=service == "attention",
    )
    result = run_deploy_fake(
        control_api.run_daybook_control,
        cfg,
        responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"], "/usr/bin/id -u": [uid]},
    )
    assert not result.succeeded
    assert result.ops == []
    assert result.uploaded_paths == []
