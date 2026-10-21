"""``files/smtp_config_sync.py``, run the way the deploy runs it (``python3 -I -c``, request on stdin).

The file and its owner are local here (the current user and group stand in
for vaultwarden); the script itself is what runs on the host.
"""

import grp
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.vaultwarden import VaultwardenConfig
from ops_deploy.services.vaultwarden.deploy import SMTP_SYNC, smtp_settings

OWNER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
ADMIN_TOKEN = "vaultwarden-fixture-admin-token-in-config-json"
CFG = VaultwardenConfig(
    domain="https://vault.example.com",
    smtp_host="localhost",
    smtp_from="vault@example.com",
    smtp_accept_invalid_certs=True,
    smtp_accept_invalid_hostnames=True,
)
SETTINGS = smtp_settings(CFG)
# What the admin panel leaves: its own layout, other keys, secrets among them.
SAVED: dict[str, Any] = {
    "domain": "https://vault.example.com",
    "admin_token": ADMIN_TOKEN,
    "smtp_password": "vaultwarden-fixture-smtp-password",
    "signups_allowed": False,
    "smtp_debug": True,
    "smtp_host": "mail.example.org",
    "smtp_port": 25,
    "org_name": "Müller",
}


def run(path: Path, action: str, settings: dict[str, Any] | None = None) -> subprocess.CompletedProcess[str]:
    request = {
        "path": str(path),
        "owner": OWNER,
        "group": GROUP,
        "settings": SETTINGS if settings is None else settings,
    }
    return subprocess.run(
        [sys.executable, "-I", "-c", SMTP_SYNC, action],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def nice_json(value: Any) -> str:
    """The bytes Ansible's ``to_nice_json`` writes (see the parity test for the role's task)."""

    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


def write(path: Path, text: str, mode: int = 0o600) -> None:
    path.write_text(text, encoding="utf-8")
    # A new file may take its directory's group (BSD); the request names ours.
    os.chown(path, -1, os.getgid())
    path.chmod(mode)


@pytest.fixture
def config(tmp_path: Path) -> Path:
    return tmp_path / "config.json"


def test_the_source_has_no_backslash() -> None:
    # It travels on a command line; a fish login shell rewrites backslash pairs.
    assert "\\" not in SMTP_SYNC


def test_absent_file_is_reported_and_never_created(config: Path) -> None:
    for action in ("check", "apply"):
        result = run(config, action)
        assert (result.returncode, result.stdout) == (0, "absent\n")
    assert not config.exists()


def test_differing_settings_are_merged_and_every_other_key_kept(config: Path) -> None:
    write(config, json.dumps(SAVED, indent=2))

    assert run(config, "check").stdout == "pending\n"
    result = run(config, "apply")

    assert (result.returncode, result.stdout) == (0, "rewritten\n")
    merged = {**SAVED, **SETTINGS}
    assert config.read_text(encoding="utf-8") == nice_json(merged)
    assert json.loads(config.read_text())["admin_token"] == ADMIN_TOKEN
    assert json.loads(config.read_text())["smtp_debug"] is True  # not managed unless configured
    assert config.stat().st_mode & 0o777 == 0o600
    assert run(config, "check").stdout == "current\n"
    assert not [p for p in config.parent.iterdir() if p.name != "config.json"]


def test_semantically_equal_settings_in_another_layout_are_current(config: Path) -> None:
    text = json.dumps({**SAVED, **SETTINGS}, indent=2)
    write(config, text)

    assert run(config, "check").stdout == "current\n"
    assert run(config, "apply").stdout == "current\n"
    assert config.read_text() == text


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("smtp_port", "587"),
        ("smtp_port", 587.0),
        ("smtp_accept_invalid_certs", 1),
        ("smtp_accept_invalid_hostnames", "true"),
    ],
)
def test_a_value_of_another_json_type_is_pending(config: Path, key: str, value: Any) -> None:
    write(config, nice_json({**SAVED, **SETTINGS, key: value}))

    assert run(config, "check").stdout == "pending\n"
    run(config, "apply")
    assert json.loads(config.read_text())[key] == SETTINGS[key]
    assert type(json.loads(config.read_text())[key]) is type(SETTINGS[key])


def test_only_the_mode_is_fixed_when_the_content_is_current(config: Path) -> None:
    text = nice_json({**SAVED, **SETTINGS})
    write(config, text, mode=0o644)
    inode = config.stat().st_ino

    assert run(config, "check").stdout == "pending\n"
    assert run(config, "apply").stdout == "owner and mode fixed\n"
    assert config.stat().st_mode & 0o777 == 0o600
    assert config.stat().st_ino == inode
    assert config.read_text() == text


def test_smtp_debug_is_written_when_configured(config: Path) -> None:
    write(config, nice_json(SAVED))

    run(config, "apply", {**SETTINGS, "smtp_debug": False})

    assert json.loads(config.read_text())["smtp_debug"] is False


def test_rewrite_escapes_non_ascii_like_to_nice_json(config: Path) -> None:
    write(config, json.dumps(SAVED, ensure_ascii=False))

    run(config, "apply")

    assert '"org_name": "M\\u00fcller"' in config.read_text()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"admin_token": "' + ADMIN_TOKEN + '", ', "is not valid JSON"),
        ('["' + ADMIN_TOKEN + '"]', "is not a JSON object"),
        (b"\xff\xfe".decode("latin-1") + ADMIN_TOKEN, "is not valid JSON"),
    ],
)
def test_unusable_content_fails_without_quoting_it(config: Path, content: str, message: str) -> None:
    config.write_bytes(content.encode("latin-1"))

    for action in ("check", "apply"):
        result = run(config, action)
        assert result.returncode == 1
        assert message in result.stderr
        assert ADMIN_TOKEN not in result.stdout + result.stderr
    assert config.read_bytes() == content.encode("latin-1")


def test_a_symlink_is_refused(config: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    write(target, nice_json(SAVED))
    config.symlink_to(target)

    result = run(config, "apply")

    assert result.returncode == 1
    assert "symlink" in result.stderr
    assert target.read_text() == nice_json(SAVED)


def test_a_fifo_is_refused_without_waiting_for_a_writer(config: Path) -> None:
    os.mkfifo(config)

    for action in ("check", "apply"):
        result = run(config, action)
        assert result.returncode == 1
        assert "not a regular file" in result.stderr


def test_a_directory_is_refused(config: Path) -> None:
    config.mkdir()

    result = run(config, "check")

    assert result.returncode == 1
    assert "not a regular file" in result.stderr


def test_check_prints_one_word_and_never_the_content(config: Path) -> None:
    write(config, json.dumps(SAVED))

    result = run(config, "check")

    assert result.stdout == "pending\n"
    assert result.stderr == ""


def test_unknown_owner_fails(config: Path) -> None:
    write(config, json.dumps(SAVED))
    request = {"path": str(config), "owner": "ops-deploy-no-such-user", "group": GROUP, "settings": SETTINGS}

    result = subprocess.run(
        [sys.executable, "-I", "-c", SMTP_SYNC, "apply"],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "owner ops-deploy-no-such-user does not exist" in result.stderr
    assert config.read_text() == json.dumps(SAVED)
