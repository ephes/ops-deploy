"""mail_backend: Dovecot waits, bounded, for the synchronised clock at start."""

from __future__ import annotations

from typing import Any

import pytest
from pyinfra.api import deploy

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.helpers.probes import probe_command
from ops_deploy.services.mail_backend import MailBackendConfig
from ops_deploy.services.mail_backend.deploy import (
    DOVECOT_TIME_SYNC_DROPIN,
    LOADED_PRE,
    TIME_WAIT_SYNC,
    dovecot_time_sync,
    render_dovecot_time_sync,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost


@deploy("dovecot time sync")
def step(cfg: MailBackendConfig) -> None:
    dovecot_time_sync(cfg)


def cfg(**changes: Any) -> MailBackendConfig:
    return MailBackendConfig(domains=("example.test",), **changes)


def binary(mode: str = "-rwxr-xr-x") -> dict[str, Any]:
    return fakehost.stat(TIME_WAIT_SYNC, mode=mode)


LOADED = (
    f"DropInPaths={DOVECOT_TIME_SYNC_DROPIN}\n"
    "ExecStartPre={ path=/usr/bin/timeout ; argv[]=/usr/bin/timeout 60 /usr/lib/systemd/systemd-time-wait-sync ;"
    " ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
)


def test_dropin_bounds_the_wait_and_ignores_its_failure() -> None:
    text = render_dovecot_time_sync(60)

    assert "[Service]\nExecStartPre=-/usr/bin/timeout 60 /usr/lib/systemd/systemd-time-wait-sync\n" in text


def test_first_run_installs_the_dropin_and_reloads_systemd_without_a_restart() -> None:
    run = run_deploy_fake(step, cfg(), responses={**fakehost.LINUX, **binary()})

    assert run.succeeded, run.error
    assert run.upload(DOVECOT_TIME_SYNC_DROPIN).decode() == render_dovecot_time_sync(60)
    assert "systemctl daemon-reload" in run.executed_commands
    assert not any("restart" in c for c in run.executed_commands)


def test_converged_host_changes_nothing() -> None:
    responses = {
        **fakehost.LINUX,
        **binary(),
        **fakehost.directory("/etc/systemd/system/dovecot.service.d"),
        **fakehost.file(DOVECOT_TIME_SYNC_DROPIN, render_dovecot_time_sync(60)),
        probe_command(LOADED_PRE): [LOADED],
    }
    run = run_deploy_fake(step, cfg(), responses=responses)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []


def test_loaded_state_is_read_from_systemctl_show() -> None:
    from ops_deploy.services.mail_backend.deploy import loaded_wait_current

    assert loaded_wait_current(LOADED, 60)
    assert not loaded_wait_current(LOADED, 30)
    assert not loaded_wait_current("DropInPaths=\nExecStartPre=", 60)
    assert loaded_wait_current("DropInPaths=\nExecStartPre=", 0)
    assert not loaded_wait_current(LOADED, 0)
    # A probe that failed is never current; another unit's use of the binary
    # without our drop-in does not count as ours.
    assert not loaded_wait_current(None, 0)
    assert not loaded_wait_current(None, 60)
    other = "DropInPaths=/etc/systemd/system/dovecot.service.d/50-admin.conf\nExecStartPre={ argv[]=" + TIME_WAIT_SYNC
    assert loaded_wait_current(other, 0)


def test_zero_removes_the_dropin() -> None:
    responses = {**fakehost.LINUX, **fakehost.file(DOVECOT_TIME_SYNC_DROPIN, render_dovecot_time_sync(60))}
    run = run_deploy_fake(step, cfg(dovecot_time_sync_wait_seconds=0), responses=responses)

    assert run.succeeded, run.error
    assert any(c.startswith("rm -f") and DOVECOT_TIME_SYNC_DROPIN in c for c in run.executed_commands)
    assert "systemctl daemon-reload" in run.executed_commands


def test_missing_wait_binary_stops_before_any_change() -> None:
    run = run_deploy_fake(step, cfg(), responses=dict(fakehost.LINUX))

    assert not run.succeeded
    assert "is not an executable file" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize("seconds", [-1, 81])
def test_the_wait_stays_below_the_start_timeout(seconds: int) -> None:
    with pytest.raises(ConfigValidationError, match="dovecot_time_sync_wait_seconds"):
        cfg(dovecot_time_sync_wait_seconds=seconds)


@pytest.mark.parametrize("mode", ["drwxr-xr-x", "-rw-r--r--"])
def test_a_directory_or_non_executable_wait_binary_is_refused(mode: str) -> None:
    run = run_deploy_fake(step, cfg(), responses={**fakehost.LINUX, **binary(mode)})

    assert not run.succeeded
    assert "is not an executable file" in str(run.error)


def test_a_reload_still_owed_from_an_earlier_run_is_done() -> None:
    # The file is current but systemd still runs an older wait.
    responses = {
        **fakehost.LINUX,
        **binary(),
        **fakehost.directory("/etc/systemd/system/dovecot.service.d"),
        **fakehost.file(DOVECOT_TIME_SYNC_DROPIN, render_dovecot_time_sync(60)),
        probe_command(LOADED_PRE): [LOADED.replace("timeout 60", "timeout 30")],
    }
    run = run_deploy_fake(step, cfg(), responses=responses)

    assert run.succeeded, run.error
    assert run.uploads == []
    assert "systemctl daemon-reload" in run.executed_commands
