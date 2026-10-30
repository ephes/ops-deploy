"""Original raw-shell ordering and strict fixed system scope."""

from __future__ import annotations

import importlib.resources
import subprocess
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.services.daybook_weeknotes_controls import WeeknotesDisableConfig, disable_weeknotes_schedule
from ops_deploy.testing import run_deploy_fake


@pytest.mark.parametrize("override", [{"label": "other"}, {"plist": "/tmp/other.plist"}])
def test_original_system_label_and_plist_cannot_be_retargeted(override: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        WeeknotesDisableConfig(**override)


@pytest.mark.parametrize("quiet", [False, True])
def test_original_shell_first_and_repeat_preserve_conditional_mutations(quiet: bool) -> None:
    script = (
        importlib.resources.files("ops_deploy.services.daybook_weeknotes_controls")
        .joinpath("files/weeknotes_disable.sh")
        .read_text()
    )
    # This function shadows launchctl only inside the owned child; it never
    # executes launchctl, opens a plist or touches a real service.
    prelude = """
set -u
disabled=$3
loaded=$4
mutations=''
launchctl() {
 case "$1" in
  print-disabled) if [ "$disabled" = 1 ]; then printf '\"%s\" => true\n' "$label"; fi ;;
  disable) disabled=1; mutations="${mutations} disable" ;;
  print) [ "$loaded" = 1 ] || return 113 ;;
  bootout) loaded=0; mutations="${mutations} bootout" ;;
  *) return 99 ;;
 esac
}
trap 'printf "MUTATIONS:%s\n" "$mutations"' EXIT
"""
    result = subprocess.run(
        [
            "/bin/bash",
            "-c",
            prelude + script,
            "--",
            "owned.weeknotes",
            "/owned/weeknotes.plist",
            "1" if quiet else "0",
            "0" if quiet else "1",
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (b"ALREADY_DISABLED" if quiet else b"DISABLED_CHANGED") in result.stdout
    assert (b"MUTATIONS:\n" if quiet else b"MUTATIONS: disable bootout\n") in result.stdout


def test_disable_failure_preserves_original_failure_instead_of_success() -> None:
    body = (
        importlib.resources.files("ops_deploy.services.daybook_weeknotes_controls")
        .joinpath("files/weeknotes_disable.sh")
        .read_text()
    )
    prelude = 'launchctl() { case "$1" in print-disabled) return 0 ;; disable) return 9 ;; *) return 99 ;; esac; };\n'
    result = subprocess.run(
        ["/bin/bash", "-c", prelude + body, "--", "owned.weeknotes", "/owned/weeknotes.plist"],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 9
    assert b"DISABLED" not in result.stdout


def test_actual_sdk_root_connection_all_privilege_fields_and_managed_repeat(monkeypatch: pytest.MonkeyPatch) -> None:
    original = FakeConnector.run_shell_command
    calls = []

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        calls.append(True)
        return original(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", shell)
    for uid in ("0", "0", "501"):
        result = run_deploy_fake(
            disable_weeknotes_schedule,
            WeeknotesDisableConfig(),
            responses={"uname -s": ["Darwin"], "/usr/bin/id -u": [uid]},
            _sudo=True,
            _sudo_user="root",
            _su_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
        )
        assert result.succeeded is (uid == "0")
        assert len(result.mutating_changed_ops) == (1 if uid == "0" else 0)
        assert result.uploaded_paths == []
    assert calls
