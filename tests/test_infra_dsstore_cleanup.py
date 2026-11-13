"""Nightly .DS_Store cleanup: what the script removes, the units, and the fake-host rollout."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.dsstore_cleanup import (
    SCRIPT_PATH,
    SERVICE,
    SERVICE_PATH,
    TIMER,
    TIMER_PATH,
    DsStoreCleanupConfig,
    deploy_dsstore_cleanup,
    render_script,
    render_service,
    render_timer,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

SCRIPT_FILE = Path(__file__).parents[1] / "src/ops_deploy/infra/files/dsstore_cleanup.sh"
MEDIA = "/fast/media"


def policy(**fields: Any) -> DsStoreCleanupConfig:
    return DsStoreCleanupConfig(**{"paths": (MEDIA,), **fields})


def cleanup(*roots: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT_FILE), *map(str, roots)], capture_output=True, text=True, timeout=30, check=False
    )


# --- the script, run for real on a scratch tree ---------------------------------


def test_script_removes_only_regular_ds_store_files(tmp_path: Path) -> None:
    root = tmp_path / "media"
    (root / "music" / "album").mkdir(parents=True)
    (root / "movies").mkdir()
    removed = [root / ".DS_Store", root / "music" / ".DS_Store", root / "music" / "album" / ".DS_Store"]
    for path in removed:
        path.write_bytes(b"\0\0\0\1Bud1")
    kept_files = [
        root / "music" / "album" / "01.flac",
        root / "movies" / "x.DS_Store",
        root / "movies" / ".DS_Store.bak",
        root / "movies" / "._song.flac",
    ]
    for path in kept_files:
        path.write_text("keep")
    # A directory and a symlink with the name stay, and so does the symlink's target.
    (root / "movies" / "dir").mkdir()
    (root / "movies" / "dir" / ".DS_Store").mkdir()
    outside = tmp_path / "outside" / ".DS_Store"
    outside.parent.mkdir()
    outside.write_text("keep")
    (root / "movies" / ".DS_Store").symlink_to(outside)

    result = cleanup(root)

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"dsstore-cleanup: removed 3 .DS_Store file(s) below {root}\n"
    assert not any(path.exists() for path in removed)
    assert all(path.read_text() == "keep" for path in kept_files)
    assert (root / "movies" / "dir" / ".DS_Store").is_dir()
    assert (root / "movies" / ".DS_Store").is_symlink()
    assert outside.read_text() == "keep"


def test_script_reports_zero_and_is_idempotent(tmp_path: Path) -> None:
    (tmp_path / ".DS_Store").write_text("x")
    assert cleanup(tmp_path).stdout.endswith("removed 1 .DS_Store file(s) below " + str(tmp_path) + "\n")
    second = cleanup(tmp_path)
    assert second.returncode == 0
    assert second.stdout == f"dsstore-cleanup: removed 0 .DS_Store file(s) below {tmp_path}\n"


def test_script_does_not_follow_a_symlinked_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / ".DS_Store").write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(real)
    other = tmp_path / "other"
    other.mkdir()
    (other / ".DS_Store").write_text("x")

    result = cleanup(link, tmp_path / "missing", other)

    # The bad roots fail the run, the good one is still cleaned.
    assert result.returncode == 1
    assert (real / ".DS_Store").exists()
    assert not (other / ".DS_Store").exists()
    assert f"{link} is not a directory, skipped" in result.stderr
    assert f"{tmp_path / 'missing'} is not a directory, skipped" in result.stderr
    assert result.stdout == f"dsstore-cleanup: removed 1 .DS_Store file(s) below {other}\n"


def gnu_find() -> bool:
    try:
        return "GNU" in subprocess.run(["find", "--version"], capture_output=True, text=True, timeout=10).stdout
    except OSError:
        return False


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
# BSD find (macOS) reports a failed -delete but still exits 0; the hosts run GNU find.
@pytest.mark.skipif(not gnu_find(), reason="needs GNU find's exit status for a failed -delete")
def test_script_fails_when_find_reports_errors(tmp_path: Path) -> None:
    (tmp_path / ".DS_Store").write_text("x")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / ".DS_Store").write_text("x")
    locked.chmod(0o500)
    try:
        result = cleanup(tmp_path)
    finally:
        locked.chmod(0o700)
    assert result.returncode == 1
    assert "find reported errors" in result.stderr
    assert "removed 1 .DS_Store file(s)" in result.stderr
    assert not (tmp_path / ".DS_Store").exists()


def test_rendered_script_is_the_shipped_file() -> None:
    assert render_script() == SCRIPT_FILE.read_text()
    assert render_script().startswith("#!/bin/bash\n# Managed by ops-deploy infra.dsstore_cleanup;")


# --- config and units ------------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"paths": ()},
        {"paths": ("relative/media",)},
        {"paths": ("/",)},
        {"paths": ("/fast/media/",)},
        {"paths": ("/fast//media",)},
        {"paths": ("/fast/../etc",)},
        {"paths": ("/fast/./media",)},
        {"paths": ("/fast/my media",)},
        {"paths": ("/fast/%h",)},
        {"paths": ("/fast/$HOME",)},
        {"paths": ("/fast/media\nExecStart=/bin/true",)},
        {"paths": (MEDIA, MEDIA)},
        {"paths": (MEDIA,), "on_calendar": ""},
        {"paths": (MEDIA,), "on_calendar": "daily\nOnBootSec=1"},
        {"paths": (MEDIA,), "state": "disabled"},
        {"paths": (MEDIA,), "randomized_delay": "1h"},
    ],
)
def test_invalid_config_refuses(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DsStoreCleanupConfig.model_validate(fields)


def test_absent_needs_no_paths() -> None:
    assert DsStoreCleanupConfig(state="absent").paths == ()


def test_service_runs_the_script_confined_to_the_paths() -> None:
    cfg = policy(paths=(MEDIA, "/srv/share"))
    unit = render_service(cfg)
    assert unit.startswith("# Managed by ops-deploy infra.dsstore_cleanup;")
    assert "RequiresMountsFor=/fast/media /srv/share\n" in unit
    assert "Type=oneshot\n" in unit
    assert f"ExecStart={SCRIPT_PATH} /fast/media /srv/share\n" in unit
    assert "ProtectSystem=strict\n" in unit
    assert "ReadWritePaths=/fast/media /srv/share\n" in unit
    assert "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER\n" in unit
    assert "[Install]" not in unit


def test_timer_runs_nightly_at_2230_by_default() -> None:
    assert render_timer(policy()) == (
        "# Managed by ops-deploy infra.dsstore_cleanup; local changes are overwritten.\n"
        "[Unit]\nDescription=Nightly removal of macOS .DS_Store files\n\n"
        "[Timer]\nOnCalendar=*-*-* 22:30:00\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    assert "OnCalendar=Sat 21:00\n" in render_timer(policy(on_calendar="Sat 21:00"))


# --- fake-host rollout -------------------------------------------------------------


def host(
    cfg: DsStoreCleanupConfig, *, script: bool = False, units: bool = False, running: bool = False
) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.service(TIMER, running=running, enabled=running),
        **fakehost.directory("/usr/local/sbin"),
        **fakehost.directory("/etc/systemd/system"),
    }
    if script:
        responses.update(fakehost.file(SCRIPT_PATH, render_script(), mode="-rwxr-xr-x"))
    if units:
        responses.update(fakehost.file(SERVICE_PATH, render_service(cfg)))
        responses.update(fakehost.file(TIMER_PATH, render_timer(cfg)))
    return responses


def never_runs_the_cleanup(commands: list[str]) -> None:
    for command in commands:
        assert SERVICE not in command or "systemctl" not in command
        assert "find " not in command
        assert not command.startswith(SCRIPT_PATH)


def test_fresh_host_installs_and_starts_only_the_timer() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses=host(cfg))
    assert run.succeeded, run.error
    assert run.written(SCRIPT_PATH) == render_script().encode()
    assert run.written(SERVICE_PATH) == render_service(cfg).encode()
    assert run.written(TIMER_PATH) == render_timer(cfg).encode()
    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index(f"systemctl start {TIMER}")
    assert f"systemctl enable {TIMER}" in commands
    assert f"systemctl restart {TIMER}" not in commands
    never_runs_the_cleanup(commands)


def test_second_run_is_a_noop() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses=host(cfg, script=True, units=True, running=True))
    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []


def test_new_schedule_reloads_and_restarts_the_timer() -> None:
    cfg = policy(on_calendar="*-*-* 21:00:00")
    responses = host(cfg, script=True, units=True, running=True)
    responses.update(fakehost.file(TIMER_PATH, render_timer(policy())))
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses=responses)
    assert run.succeeded, run.error
    assert run.written_paths == [TIMER_PATH]
    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index(f"systemctl restart {TIMER}")
    never_runs_the_cleanup(commands)


def test_changed_script_touches_no_unit() -> None:
    cfg = policy()
    responses = host(cfg, units=True, running=True)
    responses.update(fakehost.file(SCRIPT_PATH, "old\n", mode="-rwxr-xr-x"))
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses=responses)
    assert run.succeeded, run.error
    assert run.written_paths == [SCRIPT_PATH]
    assert not any(command.startswith("systemctl") for command in run.executed_commands)


def test_absent_stops_the_timer_and_removes_everything() -> None:
    cfg = DsStoreCleanupConfig(state="absent")
    responses = host(policy(), script=True, units=True, running=True)
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses=responses)
    assert run.succeeded, run.error
    commands = run.executed_commands
    assert f"systemctl stop {TIMER}" in commands
    assert f"systemctl disable {TIMER}" in commands
    for path in (TIMER_PATH, SERVICE_PATH, SCRIPT_PATH):
        assert any(path in command and "rm" in command for command in commands)
    assert commands[-1] == "systemctl daemon-reload"


def test_absent_on_a_clean_host_is_a_noop() -> None:
    cfg = DsStoreCleanupConfig(state="absent")
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses=host(cfg))
    assert run.succeeded, run.error
    assert run.executed_commands == []


def test_needs_systemd() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_dsstore_cleanup, cfg, responses={**host(cfg), "cat /proc/1/comm": ["init"]})
    assert not run.succeeded
    assert "systemd" in str(run.error)
