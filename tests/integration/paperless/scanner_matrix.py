"""Owned scanner password, ACL, mount and SSH mechanisms; no physical scanner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ops_deploy.services.paperless.commands import host_command, scanner_password_payload


def password(harness: Any) -> None:
    # Inspect only the declared synthetic account. Its verifier never reaches
    # evidence; only the algorithm category and comparison booleans do.
    text = harness.command("getent", "shadow", harness.CFG.scanner_username).stdout
    verifier = text.split(":")[1]
    yescrypt = verifier.startswith("$y$")
    del text, verifier
    # Ubuntu's real chpasswd/PAM policy supplies the new verifier; do not change
    # login.defs or global authentication settings to obtain a desired result.
    rotated = harness.CREDS.model_copy(update={"scanner_password": harness.value()})
    result = harness.deploy("scanner-password-change", creds=rotated)
    assert len(result["managed"]) == 1
    assert "scanner password" in result["managed"][0].lower()
    text = harness.command("getent", "shadow", harness.CFG.scanner_username).stdout
    new_yescrypt = text.split(":")[1].startswith("$y$")
    del text
    assert new_yescrypt, "owned Ubuntu PAM did not generate yescrypt; do not claim that qualification"
    payload = scanner_password_payload(harness.CFG, rotated, apply=False)
    actual = harness.command("sh", "-c", host_command("scanner_password"), stdin=payload)
    wrong = harness.command(
        "sh",
        "-c",
        host_command("scanner_password"),
        stdin=scanner_password_payload(harness.CFG, harness.CREDS, apply=False),
    )
    assert actual.stdout.strip() == "current"
    assert wrong.stdout.strip() == "pending"
    harness.deploy("scanner-password-repeat", creds=rotated, zero=True)
    harness.write(
        "yescrypt-comparison.json",
        {
            "prior_yescrypt": yescrypt,
            "updated_yescrypt": new_yescrypt,
            "correct_password_current": True,
            "wrong_password_pending": True,
        },
    )
    harness.deploy("scanner-password-declared-restore")
    harness.deploy("scanner-password-restored-repeat", zero=True)


def acl(harness: Any) -> None:
    consume = Path(harness.CFG.external_storage_root) / "consume"
    child = consume / "owned-acl-parent"
    assert not child.exists()
    harness.command("runuser", "-u", harness.CFG.username, "--", "mkdir", str(child))
    harness.command("setfacl", "-m", "d:u:nobody:r-x,d:m:r-x", str(child))
    before = harness.command("getfacl", "-cp", str(child)).stdout
    result = harness.deploy("scanner-default-acl-repair")
    after = harness.command("getfacl", "-cp", str(child)).stdout
    assert "default:user:nobody:r-x" in after
    assert "default:user:scanner:rwx" in after
    assert "default:mask::rwx" in after
    assert any("default ACL" in name for name in result["managed"])
    inherited = child / "owned-inherited"
    harness.command("runuser", "-u", harness.CFG.username, "--", "mkdir", str(inherited))
    harness.command("runuser", "-u", harness.CFG.scanner_username, "--", "test", "-w", str(inherited))
    harness.write(
        "acl-effective-permissions.json",
        {
            "before": before,
            "after": after,
            "unrelated_nobody_preserved": True,
            "new_child_scanner_writable": True,
            "scope": "default ACL inheritance, not new access ACLs on old dirs",
        },
    )
    harness.deploy("scanner-default-acl-repeat", zero=True)
    inherited.rmdir()
    child.rmdir()


def mount(harness: Any) -> None:
    target = harness.CFG.sftp_chroot_dir + "/inbox"
    harness.command("umount", target)
    result = harness.deploy("scanner-missing-bind-recovery")
    assert len(result["managed"]) == 1
    assert "fstab and bind mount" in result["managed"][0]
    harness.deploy("scanner-bind-repeat", zero=True)


def invalid_ssh(harness: Any) -> None:
    target = Path("/etc/ssh/sshd_config.d/sftp-scanner.conf")
    before = target.read_bytes(), target.stat().st_ino, target.stat().st_mtime_ns, target.stat().st_ctime_ns
    pid = harness.command("systemctl", "show", "ssh", "-p", "MainPID", "--value").stdout
    result = harness.command(
        "sh",
        "-c",
        host_command("scanner_ssh"),
        stdin=json.dumps({"content": "UnknownOwnedFixtureDirective yes\n", "apply": True}),
        check=False,
    )
    assert result.returncode != 0
    after = target.read_bytes(), target.stat().st_ino, target.stat().st_mtime_ns, target.stat().st_ctime_ns
    assert before == after
    assert harness.command("systemctl", "show", "ssh", "-p", "MainPID", "--value").stdout == pid
    assert not list(target.parent.glob(".paperless-scanner-ssh-*"))
    harness.write(
        "invalid-ssh-candidate.json",
        {
            "exit": result.returncode,
            "target_exact": True,
            "ssh_pid_exact": True,
            "owned_temporary_cleanup": True,
            "scope": "actual helper refusal, ephemeral staging is not zero I/O",
        },
    )
