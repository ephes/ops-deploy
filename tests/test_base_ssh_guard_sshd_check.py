"""ssh_guard's ``sshd -t``/``sshd -T`` check, run with ``sh`` against a stub ``sshd``.

The stub prints what a given OpenSSH release prints for ``sshd -T``; the
drop-in is a file in a temporary directory, so nothing outside it is touched.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from ops_deploy.base import SshGuardConfig
from ops_deploy.base.ssh_guard import validate_command

STUB_SSHD = """#!/bin/sh
case "$1" in
-t) exit "${SSHD_T_STATUS:-0}" ;;
-T) cat "$SSHD_T_OUTPUT" ;;
esac
"""
# OpenSSH 10.0 prints the PerSourcePenalties times as integers, 10.3 with six decimals.
PENALTIES_10_0 = (
    "persourcepenalties crash:90 authfail:300 noauth:1 grace-exceeded:10 refuseconnection:10 max:600 min:15 "
    "max-sources4:65536 max-sources6:65536 overflow:permissive overflow6:permissive"
)
PENALTIES_10_3 = (
    "persourcepenalties crash:90.000000 authfail:300.000000 noauth:1.000000 grace-exceeded:10.000000 "
    "refuseconnection:10.000000 max:600.000000 min:15.000000 max-sources4:65536 max-sources6:65536 "
    "overflow:permissive overflow6:permissive"
)


FULL = SshGuardConfig(
    per_source_max_startups="05",
    max_auth_tries="04",
    max_startups="010:30:100",
    per_source_net_block_size="32:064",
    per_source_penalties="authfail:5m max:600 overflow:permissive max-sources4:065536",
)


def check(
    tmp_path: Path, effective: str, *, sshd_t: int = 0, cfg: SshGuardConfig | None = None
) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "sshd"
    stub.write_text(STUB_SSHD)
    stub.chmod(0o755)
    output = tmp_path / "sshd-T.txt"
    output.write_text(effective + "\n")
    dropin = tmp_path / "99-ssh-guard.conf"
    dropin.write_text("# drop-in\n")
    cfg = (cfg or FULL).model_copy(update={"sshd_dropin_path": str(dropin)})
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SSHD_T_OUTPUT": str(output),
        "SSHD_T_STATUS": str(sshd_t),
    }
    result = subprocess.run(["sh", "-c", validate_command(cfg)], env=env, capture_output=True, text=True, timeout=30)
    return result, dropin


GOOD = "persourcemaxstartups 5\nmaxauthtries 4\nmaxstartups 10:30:100\npersourcenetblocksize 32:64"


@pytest.mark.parametrize("penalties", [PENALTIES_10_0, PENALTIES_10_3], ids=["openssh-10.0", "openssh-10.3"])
def test_effective_values_as_each_release_prints_them_pass(tmp_path: Path, penalties: str) -> None:
    result, dropin = check(tmp_path, f"{GOOD}\n{penalties}")

    assert result.returncode == 0, result.stderr
    assert dropin.exists()


@pytest.mark.parametrize(
    ("effective", "message"),
    [
        (
            f"{GOOD.replace('persourcemaxstartups 5', 'persourcemaxstartups 7')}\n{PENALTIES_10_3}",
            "persourcemaxstartups 5",
        ),
        (f"{GOOD}\n{PENALTIES_10_3.replace('authfail:300.000000', 'authfail:5.000000')}", "lacks authfail:300"),
        (
            f"{GOOD}\n{PENALTIES_10_0.replace('overflow:permissive ', 'overflow:deny-all ')}",
            "lacks overflow:permissive",
        ),
        (f"{GOOD}\npersourcepenalties no", "lacks authfail:300"),
        (GOOD, "lacks authfail:300"),
    ],
    ids=["shadowed directive", "other time", "other mode", "penalties off", "no penalties line"],
)
def test_other_effective_values_remove_the_dropin(tmp_path: Path, effective: str, message: str) -> None:
    result, dropin = check(tmp_path, effective)

    assert result.returncode == 1
    assert message in result.stderr
    assert not dropin.exists()


def test_a_failing_syntax_check_removes_the_dropin(tmp_path: Path) -> None:
    result, dropin = check(tmp_path, f"{GOOD}\n{PENALTIES_10_0}", sshd_t=1)

    assert result.returncode == 1
    assert "Invalid sshd config" in result.stderr
    assert not dropin.exists()


# R1b-like drop-in on OpenSSH 9.6 (no penalties): per-source limits plus the two auth directives.
AUTH = SshGuardConfig(
    per_source_net_block_size="32:64",
    password_authentication="no",
    permit_root_login="prohibit-password",
)
AUTH_GOOD = "persourcemaxstartups 5\npersourcenetblocksize 32:64\npasswordauthentication no"


@pytest.mark.parametrize(
    "printed",
    ["permitrootlogin without-password", "permitrootlogin prohibit-password"],
    ids=["openssh-9.6", "openssh-10.3"],
)
def test_auth_values_as_each_release_prints_them_pass(tmp_path: Path, printed: str) -> None:
    result, dropin = check(tmp_path, f"{AUTH_GOOD}\n{printed}", cfg=AUTH)

    assert result.returncode == 0, result.stderr
    assert dropin.exists()


@pytest.mark.parametrize(
    ("effective", "message"),
    [
        (f"{AUTH_GOOD}\npermitrootlogin yes", "does not show: permitrootlogin prohibit-password"),
        (f"{AUTH_GOOD}\npermitrootlogin forced-commands-only", "does not show: permitrootlogin prohibit-password"),
        (AUTH_GOOD, "does not show: permitrootlogin prohibit-password"),
        (
            f"{AUTH_GOOD.replace('passwordauthentication no', 'passwordauthentication yes')}\n"
            "permitrootlogin without-password",
            "does not show: passwordauthentication no",
        ),
    ],
    ids=["root login shadowed", "other root mode", "no root line", "password shadowed"],
)
def test_shadowed_auth_values_remove_the_dropin(tmp_path: Path, effective: str, message: str) -> None:
    result, dropin = check(tmp_path, effective, cfg=AUTH)

    assert result.returncode == 1
    assert message in result.stderr
    assert not dropin.exists()
