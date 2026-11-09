"""Original disabled/retired Voice Memo work convergence and its fixed scope."""

from __future__ import annotations

import importlib.resources
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.services.daybook_voice_memo_work import VoiceMemoWorkConfig, apply_voice_memo_work_state
from ops_deploy.services.daybook_voice_memo_work.config import LABEL
from ops_deploy.services.daybook_voice_memo_work.deploy import disable_command
from ops_deploy.testing import run_deploy_fake

SCRIPT = (
    importlib.resources.files("ops_deploy.services.daybook_voice_memo_work")
    .joinpath("files/voice_memo_work_disable.sh")
    .read_text()
)
ABSENT = f'Could not find service "{LABEL}" in domain for user gui: 501'

# These functions shadow id and launchctl only inside the owned child; nothing
# calls the real launchctl or touches a real LaunchAgent.
PRELUDE = """
fake_domain_rc=$5; loaded=$6; disable_rc=$7; bootout_rc=$8; stays_loaded=$9; absent_message=${10}
set -- "$1" "$2" "$3" "$4"
calls=$(mktemp)
id() { [ "$1" = -u ] && [ "$2" = operator ] && echo 501; }
launchctl() {
 printf ' %s' "$1" >>"$calls"
 case "$1" in
  print)
   case "$2" in
    gui/501) return "$fake_domain_rc" ;;
    gui/501/*)
     if [ "$loaded" = 1 ]; then echo 'state = running'; return 0; fi
     printf '%s\\n' "$absent_message" >&2; return 113 ;;
   esac ;;
  disable) return "$disable_rc" ;;
  bootout) [ "$stays_loaded" = 1 ] || loaded=0; return "$bootout_rc" ;;
  *) return 99 ;;
 esac
}
trap 'printf "CALLS:%s\\n" "$(cat "$calls")"; rm -f "$calls"' EXIT
"""


def run(
    plist: Path,
    *,
    retired: bool = True,
    domain_rc: int = 0,
    loaded: bool = True,
    disable_rc: int = 0,
    bootout_rc: int = 0,
    stays_loaded: bool = False,
    absent: str = ABSENT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/bin/bash",
            "-c",
            PRELUDE + SCRIPT,
            "--",
            "operator",
            LABEL,
            str(plist),
            "true" if retired else "false",
            str(domain_rc),
            "1" if loaded else "0",
            str(disable_rc),
            str(bootout_rc),
            "1" if stays_loaded else "0",
            absent,
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


@pytest.fixture
def plist(tmp_path: Path) -> Path:
    path = tmp_path / "LaunchAgents" / f"{LABEL}.plist"
    path.parent.mkdir()
    path.write_text("<plist/>\n")
    return path


def test_original_owner_label_and_plist_are_fixed() -> None:
    cfg = VoiceMemoWorkConfig(owner="operator", retired=True)
    assert cfg.home == "/Users/operator"
    assert cfg.plist == f"/Users/operator/Library/LaunchAgents/{LABEL}.plist"
    for override in (
        {"owner": "root"},
        {"owner": "CHANGEME"},
        {"owner": "Bad Owner"},
        {"owner": "operator", "home": "/var/root"},
        {"owner": "operator", "label": "other.label"},
        {"owner": "operator", "plist": "/tmp/other.plist"},
        {"owner": "operator", "retired": "yes"},
    ):
        with pytest.raises(ValidationError):
            VoiceMemoWorkConfig(**override)


def test_enabled_scheduler_is_refused() -> None:
    with pytest.raises(ValidationError, match="only the disabled state"):
        VoiceMemoWorkConfig(owner="operator", enabled=True)


def test_command_passes_fixed_path_and_declared_arguments() -> None:
    command = disable_command(VoiceMemoWorkConfig(owner="operator", retired=True))
    assert command.startswith("/usr/bin/env PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash -c ")
    assert command.endswith(f" -- operator {LABEL} /Users/operator/Library/LaunchAgents/{LABEL}.plist true")


def test_loaded_retired_label_is_disabled_booted_out_proven_and_plist_removed(plist: Path) -> None:
    result = run(plist)
    assert result.returncode == 0, result.stderr
    assert "domain=available booted_out=1 plist_removed=1" in result.stdout
    assert "CALLS: print print disable bootout print\n" in result.stdout
    assert not plist.exists()


def test_absent_retired_label_repeat_still_disables_and_proves(plist: Path) -> None:
    plist.unlink()
    result = run(plist, loaded=False)
    assert result.returncode == 0, result.stderr
    assert "domain=available booted_out=0 plist_removed=0" in result.stdout
    assert "CALLS: print print disable print\n" in result.stdout


def test_disabled_not_retired_keeps_the_plist(plist: Path) -> None:
    result = run(plist, retired=False)
    assert result.returncode == 0, result.stderr
    assert "plist_removed=0" in result.stdout
    assert plist.exists()


def test_logged_out_owner_only_persists_the_override(plist: Path) -> None:
    result = run(plist, domain_rc=112)
    assert result.returncode == 0, result.stderr
    assert "domain=logged_out booted_out=0 plist_removed=0" in result.stdout
    assert "CALLS: print disable\n" in result.stdout
    assert plist.exists()


@pytest.mark.parametrize(
    ("options", "calls"),
    [
        ({"domain_rc": 5}, "CALLS: print\n"),
        ({"loaded": False, "absent": "unexpected"}, "CALLS: print print\n"),
        ({"disable_rc": 3}, "CALLS: print print disable\n"),
        ({"bootout_rc": 5}, "CALLS: print print disable bootout\n"),
        ({"stays_loaded": True}, "CALLS: print print disable bootout print\n"),
    ],
)
def test_failures_stop_before_later_steps_and_keep_the_plist(plist: Path, options: dict[str, Any], calls: str) -> None:
    result = run(plist, **options)
    assert result.returncode == 1
    assert "DISABLED" not in result.stdout
    assert calls in result.stdout
    assert plist.exists()


def test_directory_at_the_plist_path_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / f"{LABEL}.plist"
    path.mkdir()
    result = run(path)
    assert result.returncode == 1
    assert "directory" in result.stderr
    assert path.is_dir()


def test_symlink_at_the_plist_path_is_removed_without_following(tmp_path: Path) -> None:
    target = tmp_path / "kept.plist"
    target.write_text("kept\n")
    path = tmp_path / f"{LABEL}.plist"
    path.symlink_to(target)
    result = run(path)
    assert result.returncode == 0, result.stderr
    assert not path.is_symlink()
    assert target.read_text() == "kept\n"


def test_sdk_root_connection_clears_privilege_fields_and_runs_one_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    original = FakeConnector.run_shell_command
    calls = []

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        calls.append(True)
        return original(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", shell)
    for system, uid in (("Darwin", "0"), ("Darwin", "0"), ("Darwin", "501"), ("Linux", "0")):
        result = run_deploy_fake(
            apply_voice_memo_work_state,
            VoiceMemoWorkConfig(owner="operator", retired=True),
            responses={"uname -s": [system], "/usr/bin/id -u": [uid]},
            _sudo=True,
            _sudo_user="root",
            _su_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
        )
        expected = system == "Darwin" and uid == "0"
        assert result.succeeded is expected
        assert len(result.mutating_changed_ops) == (1 if expected else 0)
        assert result.uploaded_paths == []
    assert calls


def test_disabled_branch_matches_the_ops_library_role() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH not set")
    role = Path(source) / "roles/daybook_voice_memo_work_deploy"
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
    assert defaults["daybook_voice_memo_work_launchd_label"] == LABEL
    assert defaults["daybook_voice_memo_work_enabled"] is False
    tasks = yaml.safe_load((role / "tasks/main.yml").read_text())
    names = [task["name"] for task in tasks]
    # The disabled branch this port mirrors, in its original order, ending
    # where the role stops for a disabled job.
    disabled = names[: names.index("Stop after applying disabled Voice Memo work state") + 1]
    assert disabled == [
        "Validate Voice Memo work deployment inputs",
        "Resolve Voice Memo work owner uid",
        "Read disabled Voice Memo work GUI domain",
        "Read disabled Voice Memo work loaded state",
        "Disable Voice Memo work LaunchAgent",
        "Boot out disabled Voice Memo work LaunchAgent",
        "Verify disabled Voice Memo work LaunchAgent is unloaded",
        "Delete the retired Voice Memo work plist",
        "Stop after applying disabled Voice Memo work state",
    ]
    by_name = {task["name"]: task for task in tasks}
    assert by_name["Read disabled Voice Memo work GUI domain"]["failed_when"] == (
        "daybook_voice_memo_work_disabled_domain.rc not in [0, 112]"
    )
    assert by_name["Boot out disabled Voice Memo work LaunchAgent"]["when"] == [
        "not daybook_voice_memo_work_enabled | bool",
        "daybook_voice_memo_work_disabled_domain.rc == 0",
        "daybook_voice_memo_work_disabled_loaded.rc == 0",
    ]
    assert by_name["Delete the retired Voice Memo work plist"]["when"] == [
        "not daybook_voice_memo_work_enabled | bool",
        "daybook_voice_memo_work_retired | bool",
        "daybook_voice_memo_work_disabled_domain.rc == 0",
    ]
