"""Execute incident preflight against unsupported layouts and failed prerequisites."""

import os
import subprocess
from pathlib import Path

import pytest

from ops_deploy.services import mastodon_upgrade


def installation(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    source = Path(mastodon_upgrade.__file__).parent / "files" / "upgrade.sh"
    site = tmp_path / "site"
    site.mkdir()
    (site / ".env.production").write_text("DB_NAME=mastodon\n")
    units = tmp_path / "units"
    units.mkdir()
    for unit in ("web", "sidekiq", "streaming", "maintenance"):
        (units / f"mastodon-{unit}.service").write_text("Environment=RBENV_VERSION=4.0.5\nEnvironment=PATH=/bin\n")
    maintenance = tmp_path / "maintenance"
    maintenance.touch()
    script = tmp_path / "upgrade.sh"
    script.write_text(
        source.read_text()
        .replace("/home/mastodon/live", str(site))
        .replace("/etc/systemd/system", str(units))
        .replace("/usr/local/bin/mastodon-maintenance", str(maintenance))
    )
    commands = {
        "id": "echo 0",
        "sudo": 'while :; do case "$1" in -u) shift 2;; -H) shift;; *) break;; esac; done; exec "$@"',
        "git": 'case "$*" in *status*) exit "${GIT_FAIL:-0}";; *) echo v4.6.9;; esac',
        "df": "printf 'Avail\\n30000000000\\n'",
        "systemctl": """echo "$*" >> "$CALL_LOG"
case "$*" in
  *is-enabled*) exit "${TIMER_FAIL:-0}";;
  *'is-active --quiet mastodon-maintenance.service'*) exit "${MAINTENANCE_RESULT:-3}";;
  *) exit 0;;
esac""",
        "curl": """echo "$*" >> "$CALL_LOG"
case "$*" in
  *10042*) test "${FAIL_PORT:-}" != 10042 || exit 7; echo '{"version":"4.6.9"}';;
  *10043*) test "${FAIL_PORT:-}" != 10043 || exit 7; echo OK;;
esac""",
    }
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in commands.items():
        executable = bindir / name
        executable.write_text(f"#!/bin/bash\n{body}\n")
        executable.chmod(0o755)
    call_log = tmp_path / "calls"
    return script, {**os.environ, "PATH": f"{bindir}:/usr/bin:/bin", "CALL_LOG": str(call_log)}, call_log


def preflight(script: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script), "preflight", "example.test"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("git_fails", [False, True])
def test_preflight_stops_for_maintenance_or_unreadable_git(tmp_path: Path, git_fails: bool) -> None:
    script, env, call_log = installation(tmp_path)
    result = preflight(script, {**env, "GIT_FAIL": "42" if git_fails else "0", "MAINTENANCE_RESULT": "0"})
    if git_fails:
        assert result.returncode == 42
        assert not call_log.exists(), "A failed Git check must stop before service operations"
    else:
        assert result.returncode == 1
        assert "Maintenance is running" in result.stderr
        assert "stop" not in call_log.read_text()


@pytest.mark.parametrize("failure", ["timer", "10042", "10043", "database"])
def test_preflight_refuses_unsupported_layout_before_mutation(tmp_path: Path, failure: str) -> None:
    script, env, call_log = installation(tmp_path)
    if failure == "timer":
        env["TIMER_FAIL"] = "1"
    elif failure == "database":
        (tmp_path / "site" / ".env.production").write_text("DB_NAME=another_database\n")
    else:
        env["FAIL_PORT"] = failure
    result = preflight(script, env)
    assert result.returncode != 0
    assert "stop" not in call_log.read_text()


def test_supported_layout_passes_read_only_preflight(tmp_path: Path) -> None:
    script, env, call_log = installation(tmp_path)
    result = preflight(script, env)
    assert result.returncode == 0, result.stderr
    calls = call_log.read_text()
    assert "is-enabled --quiet mastodon-maintenance.timer" in calls
    assert "10042/api/v2/instance" in calls
    assert "10043/api/v1/streaming/health" in calls
    assert "stop" not in calls
