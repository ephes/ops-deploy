"""``journald_config``: byte parity with the role's template, handler gating and validation."""

import os
import subprocess
from pathlib import Path
from typing import Any

import jinja2
import pytest
from pydantic import ValidationError

from ops_deploy.base import JournaldConfig, deploy_journald_config, journald_config
from ops_deploy.base.journald_config import (
    ACTIVE_CHECK,
    DEFAULT_DROPIN,
    MANAGED_KEYS,
    STAT_KIND,
    render_journald_dropin,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.test_base_headless_mode import SYSTEMD

VENDORED = Path(__file__).parent / "parity" / "ansible"
DIR = "/etc/systemd/journald.conf.d"
RESTART = "systemctl restart systemd-journald"
FLUSH = "journalctl --flush"
CHECK = "journald config | Check systemd-journald is running"


def render_ansible(role_vars: dict[str, Any]) -> str:
    """The role's template, rendered as Ansible's ``template`` module does.

    ``journald_config_managed_settings`` is the role's ``vars/main.yml`` map,
    built from the same role variables in the same order.
    """

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    defaults = {f"journald_config_{name}": "" for name in MANAGED_KEYS} | {"journald_config_storage": "persistent"}
    merged = defaults | role_vars
    managed = {key: merged[f"journald_config_{name}"] for name, key in MANAGED_KEYS.items()}
    template = env.get_template("journald_config__journald.conf.j2")
    return template.render(
        journald_config_managed_settings=managed,
        journald_config_extra_settings=merged.get("journald_config_extra_settings", {}),
    )


# Role variables (without the ``journald_config_`` prefix), as an inventory would pass them.
CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "retention limits, integer file count": {
        "system_max_use": "16G",
        "system_max_file_size": "512M",
        "system_max_files": 2000,
        "max_retention_sec": "21day",
    },
    "every field and ordered extras": {
        "storage": "volatile",
        "system_max_use": "1.5G",
        "system_keep_free": "2G",
        "system_max_file_size": "64M",
        "system_max_files": 0,
        "max_retention_sec": "1.5day",
        "max_file_sec": "1w 2d12h",
        "extra_settings": {"Compress": True, "Seal": False, "RateLimitBurst": 20000, "RateLimitIntervalSec": "30s"},
    },
    "empty storage, extras only": {"storage": "", "extra_settings": {"SplitMode": "uid", "MaxLevelStore": 6.5}},
    "numeric sizes": {"system_max_use": 1024, "system_keep_free": 1.5},
}


@pytest.mark.parametrize("role_vars", CASES.values(), ids=CASES.keys())
def test_drop_in_matches_the_role_template(role_vars: dict[str, Any]) -> None:
    cfg = JournaldConfig(**role_vars)

    assert render_journald_dropin(cfg) == render_ansible({f"journald_config_{k}": v for k, v in role_vars.items()})


def test_retention_drop_in_lines() -> None:
    cfg = JournaldConfig(**CASES["retention limits, integer file count"])

    assert render_journald_dropin(cfg).splitlines()[4:] == [
        "[Journal]",
        "Storage=persistent",
        "SystemMaxUse=16G",
        "SystemMaxFileSize=512M",
        "SystemMaxFiles=2000",
        "MaxRetentionSec=21day",
    ]


def kinds(directory: str, dropin: str) -> dict[str, Any]:
    """The deploy's C-locale ``stat -c %F`` probe: the drop-in directory's and the drop-in's file type."""

    return {STAT_KIND: [directory, dropin]}


# A systemd host without the directory or the drop-in.
FRESH = {**SYSTEMD, **kinds("missing", "missing")}


def converged(cfg: JournaldConfig, *, mode: str = "-rw-r--r--", user: str = "root") -> dict[str, Any]:
    return {
        **SYSTEMD,
        **kinds("directory", "regular file"),
        **fakehost.directory(DIR),
        **fakehost.file(cfg.dropin_path, render_journald_dropin(cfg), user=user, mode=mode),
    }


RETENTION = JournaldConfig(**CASES["retention limits, integer file count"])


def test_first_run_writes_the_drop_in_then_restarts_and_flushes() -> None:
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses=FRESH)

    assert run.succeeded, run.error
    assert run.upload(DEFAULT_DROPIN) == render_journald_dropin(RETENTION).encode()
    commands = run.executed_commands
    assert f"mkdir -p {DIR}" in commands
    assert f"chmod 755 {DIR}" in commands or f"chmod 0755 {DIR}" in commands
    # Restart, flush and the check come after the drop-in, in the handlers' order.
    assert commands[-3:] == [RESTART, FLUSH, ACTIVE_CHECK]
    assert run.mutating_changed_ops == [
        f"journald config | Ensure {DIR}",
        f"journald config | Write {DEFAULT_DROPIN}",
        "journald config | Restart systemd-journald",
        "journald config | Flush journal to persistent storage",
    ]


def test_converged_host_neither_restarts_nor_flushes() -> None:
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses=converged(RETENTION))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    # Only the read-only state check runs.
    assert run.executed_commands == [ACTIVE_CHECK]
    assert run.changed_ops == [CHECK]
    assert run.op(CHECK).read_only


def test_content_drift_rewrites_restarts_and_flushes() -> None:
    old = JournaldConfig(system_max_use="4G")
    responses = {**converged(old), **fakehost.directory(DIR)}

    run = run_deploy_fake(deploy_journald_config, RETENTION, responses=responses)

    assert run.succeeded, run.error
    assert run.upload(DEFAULT_DROPIN) == render_journald_dropin(RETENTION).encode()
    assert run.executed_commands[-3:] == [RESTART, FLUSH, ACTIVE_CHECK]


def test_mode_drift_alone_counts_as_a_change_as_with_the_role() -> None:
    # Ansible's template reports an attribute change as changed and notifies.
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses=converged(RETENTION, mode="-rw-rw-rw-"))

    assert run.succeeded, run.error
    assert run.uploads == []
    assert run.executed_commands == [f"chmod 644 {DEFAULT_DROPIN}", RESTART, FLUSH, ACTIVE_CHECK]


def test_restart_off_writes_without_restart_or_flush() -> None:
    cfg = RETENTION.model_copy(update={"restart_on_change": False})

    run = run_deploy_fake(deploy_journald_config, cfg, responses=FRESH)

    assert run.succeeded, run.error
    assert RESTART not in run.executed_commands
    assert FLUSH not in run.executed_commands
    assert run.executed_commands[-1] == ACTIVE_CHECK


@pytest.mark.parametrize("storage", ["volatile", "auto", "none", ""])
def test_flush_only_for_persistent_storage(storage: str) -> None:
    run = run_deploy_fake(deploy_journald_config, JournaldConfig(storage=storage), responses=FRESH)

    assert run.succeeded, run.error
    assert run.executed_commands[-2:] == [RESTART, ACTIVE_CHECK]
    assert FLUSH not in run.executed_commands


def test_absent_removes_the_drop_in_and_restarts_without_flush() -> None:
    responses = {
        **SYSTEMD,
        **kinds("directory", "regular file"),
        **fakehost.file(DEFAULT_DROPIN, render_journald_dropin(RETENTION)),
    }

    run = run_deploy_fake(deploy_journald_config, JournaldConfig(state="absent"), responses=responses)

    assert run.succeeded, run.error
    assert run.executed_commands == [f"rm -f {DEFAULT_DROPIN}", RESTART, ACTIVE_CHECK]
    assert run.uploads == []


def test_absent_without_a_drop_in_changes_nothing() -> None:
    run = run_deploy_fake(deploy_journald_config, JournaldConfig(state="absent"), responses=FRESH)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.executed_commands == [ACTIVE_CHECK]


@pytest.mark.parametrize(
    "fields",
    [
        {"system_max_use": "16 GB", "extra_settings": {"SystemMaxUse": "1G"}},
        {"extra_settings": {"Compress": None}},
        {"storage": True, "system_max_files": [1], "max_retention_sec": None},
        {"extra_settings": "not a mapping"},
    ],
    ids=repr,
)
def test_absent_ignores_settings_as_the_role_does(fields: dict[str, Any]) -> None:
    # The role skips its settings validation for ``absent``; nothing is rendered.
    cfg = JournaldConfig(state="absent", **fields)

    assert cfg.extra_settings == {}
    assert cfg.storage == "persistent"


def test_absent_still_checks_the_path_and_unknown_fields() -> None:
    with pytest.raises(ValidationError, match=r"journald\.conf\.d"):
        JournaldConfig(state="absent", dropin_path="/etc/systemd/journald.conf")
    with pytest.raises(ValidationError):
        JournaldConfig(state="absent", vacuum=True)  # type: ignore[call-arg]


def symlinked() -> dict[str, Any]:
    return {
        **SYSTEMD,
        **kinds("directory", "symbolic link"),
        **fakehost.directory(DIR),
        **fakehost.symlink(DEFAULT_DROPIN, "/srv/elsewhere.conf"),
    }


def test_symlinked_drop_in_is_replaced_not_followed() -> None:
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses=symlinked())

    assert run.succeeded, run.error
    # The link itself goes first; the upload then creates a regular file.
    assert run.executed_commands[0] == f"rm -f {DEFAULT_DROPIN}"
    assert run.upload(DEFAULT_DROPIN) == render_journald_dropin(RETENTION).encode()
    assert run.executed_commands[-3:] == [RESTART, FLUSH, ACTIVE_CHECK]
    assert "/srv/elsewhere.conf" not in "\n".join(run.executed_commands)


def test_symlinked_drop_in_is_unlinked_for_absent() -> None:
    run = run_deploy_fake(deploy_journald_config, JournaldConfig(state="absent"), responses=symlinked())

    assert run.succeeded, run.error
    assert run.executed_commands == [f"rm -f {DEFAULT_DROPIN}", RESTART, ACTIVE_CHECK]


@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("kind", ["directory", "fifo", "socket"])
def test_refuses_a_drop_in_that_is_not_a_file(state: str, kind: str) -> None:
    responses = {**SYSTEMD, **kinds("directory", kind)}

    run = run_deploy_fake(deploy_journald_config, JournaldConfig(state=state), responses=responses)

    assert f"is a {kind}, not a regular file or symlink" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize("kind", ["symbolic link", "regular file"])
def test_refuses_a_drop_in_directory_that_is_not_a_directory(kind: str) -> None:
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses={**SYSTEMD, **kinds(kind, "missing")})

    assert f"{DIR} is a {kind}, not a directory" in str(run.error)
    assert run.executed_commands == []


def test_refuses_when_the_file_types_cannot_be_read() -> None:
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses=SYSTEMD)

    assert "could not read the file types" in str(run.error)
    assert run.executed_commands == []


# A GNU ``stat`` stand-in that, like the real one, prints translated ``%F``
# names unless the effective message locale (LC_ALL, then LC_MESSAGES, then
# LANG) is C.
GERMAN_STAT = f"""#!/bin/sh
[ "$1 $2" = "-c %F" ] || exit 2
case "${{LC_ALL:-${{LC_MESSAGES:-${{LANG:-}}}}}}" in
  C|POSIX) dir=directory file="regular file" ;;
  *) dir=Verzeichnis file="reguläre Datei" ;;
esac
case "$3" in
  {DIR}) echo "$dir" ;;
  {DEFAULT_DROPIN}) echo "$file" ;;
  *) exit 1 ;;
esac
"""


@pytest.mark.parametrize("state", ["present", "absent"])
def test_file_types_are_read_in_the_c_locale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    stat = tmp_path / "stat"
    stat.write_text(GERMAN_STAT, encoding="utf-8")
    stat.chmod(0o755)
    env = {"PATH": f"{tmp_path}:{os.environ['PATH']}", "LANG": "de_DE.UTF-8", "LC_ALL": "de_DE.UTF-8"}

    def sh(command: str) -> str:
        return subprocess.run(["sh", "-c", command], env=env, capture_output=True, text=True, check=True).stdout

    # The host's own locale translates the names the deploy matches.
    assert sh(f"stat -c %F {DIR}") == "Verzeichnis\n"
    probes: list[str] = []

    def output(command: str) -> str:
        probes.append(command)
        return sh(f"{command} 2>/dev/null || true").strip()

    monkeypatch.setattr(journald_config, "output", output)
    cfg = RETENTION if state == "present" else JournaldConfig(state="absent")
    run = run_deploy_fake(deploy_journald_config, cfg, responses=SYSTEMD)

    assert run.succeeded, run.error
    # One probe, the C locale set for both of its stat calls.
    assert len(probes) == 1
    assert probes[0].count(STAT_KIND) == 2
    # The existing regular file is rewritten or removed, not refused.
    if state == "present":
        assert run.upload(DEFAULT_DROPIN) == render_journald_dropin(RETENTION).encode()
    else:
        assert run.executed_commands == [f"rm -f {DEFAULT_DROPIN}", RESTART, ACTIVE_CHECK]


def test_custom_drop_in_path() -> None:
    cfg = JournaldConfig(dropin_path=f"{DIR}/70-local.conf")

    run = run_deploy_fake(deploy_journald_config, cfg, responses=FRESH)

    assert run.succeeded, run.error
    assert run.uploaded_paths == [f"{DIR}/70-local.conf"]


def test_refuses_non_systemd_host() -> None:
    run = run_deploy_fake(deploy_journald_config, RETENTION, responses={**fakehost.LINUX, "cat /proc/1/comm": ["init"]})

    assert "requires a systemd-managed host" in str(run.error)
    assert run.executed_commands == []


def test_active_check_fails_unless_active() -> None:
    assert ACTIVE_CHECK.startswith("state=$(systemctl is-active systemd-journald || true);")
    assert '[ "$state" = active ]' in ACTIVE_CHECK


# The role's Molecule scenario: refused and accepted values.
@pytest.mark.parametrize(
    "fields",
    [
        {"extra_settings": {"SystemMaxUse": "1G"}},
        {"extra_settings": {"Storage": "auto"}},
        {"system_max_use": "16 GB"},
        {"extra_settings": {"Compress": "yes\rSystemMaxUse=1M"}},
        {"extra_settings": {"Compress": "yes\nSystemMaxUse=1M"}},
        {"extra_settings": {"Compress": "a\x00b"}},
        {"extra_settings": {"Compress": "tab\there"}},
        {"max_retention_sec": "1.51.5day"},
        {"max_file_sec": "forever"},
        {"system_max_files": "-1"},
        {"system_max_files": "1.5"},
        {"system_max_files": True},
        {"system_max_use": "1.5.5G"},
        {"system_keep_free": "16g"},
        {"storage": "disk"},
        {"storage": True},
        {"extra_settings": {"compress": True}},
        {"extra_settings": {"Rate-Limit": 1}},
        {"extra_settings": {"Compress": None}},
        {"extra_settings": {"Compress": ["yes"]}},
        {"extra_settings": {"Compress": {"a": 1}}},
        {"extra_settings": {1: "x"}},
        # Python's ``$`` takes one trailing newline; the port does not.
        {"system_max_use": "16G\n"},
        {"max_retention_sec": "21day\n"},
        {"system_max_files": "2000\n"},
        {"extra_settings": {"Compress\n": True}},
        {"system_max_use": None},
    ],
    ids=repr,
)
def test_refuses_values_the_role_refuses(fields: dict[Any, Any]) -> None:
    with pytest.raises(ValidationError):
        JournaldConfig(**fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"system_max_use": "1.5G", "system_max_files": 0, "max_retention_sec": "1.5day", "max_file_sec": "1w 2d12h"},
        {"max_retention_sec": "2weeks 3days", "max_file_sec": "55s500ms"},
        {"max_retention_sec": "1h30", "max_file_sec": " 1month "},
        {"max_retention_sec": "3600"},
        {"system_max_use": "16G", "system_keep_free": "0", "system_max_file_size": "512"},
        {"extra_settings": {"ForwardToSyslog": False, "RateLimitBurst": 0}},
    ],
    ids=repr,
)
def test_accepts_values_the_role_accepts(fields: dict[str, Any]) -> None:
    JournaldConfig(**fields)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/systemd/journald.conf",
        "/etc/systemd/journald.conf.d/60-ops-library",
        "/etc/systemd/journald.conf.d/sub/60.conf",
        "/run/systemd/journald.conf.d/60.conf",
        "/etc/systemd/journald.conf.d/.conf",
        "/etc/systemd/journald.conf.d/60\n.conf",
        "/etc/systemd/journald.conf.d/60.conf\n",
    ],
)
def test_refuses_drop_in_paths_outside_conf_d(path: str) -> None:
    with pytest.raises(ValidationError, match=r"journald\.conf\.d"):
        JournaldConfig(dropin_path=path)


def test_refuses_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        JournaldConfig(vacuum=True)  # type: ignore[call-arg]
