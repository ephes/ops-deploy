"""``_echoport_runner.registration``: the own steps of the unifi-backup and minecraft-java-backup playbooks.

register-unifi-backup.yml writes the runner's MongoDB login
(``/etc/echoport-backups/unifi-mongodb.json``, root ``0600`` in a root
``0700`` directory) and then proves it with ``mongodump --archive=/dev/null``
("Validate MongoDB backup credentials and auth DB"). The port runs that check
with the file's text on stdin and the password on mongodump's stdin: while
planning when mongodump is installed (a refused login stops the run before
any write), and as a read-only step right after the file. The password is on
no command line.

register-minecraft-java-backup.yml refuses when ``/usr/local/bin/mcrcon`` is
missing ("Ensure mcrcon is installed"); the port refuses while planning.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services._echoport_runner.registration import (
    CredentialFile,
    RequiredFile,
    RunnerRegistration,
    credential_check_command,
    install_registration,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests import test_echoport_runner_registration as a1

# The playbook's `copy: content:`, unchanged.
UNIFI_CONTENT = """{
  "host": {{ unifi_echoport_backup_mongodb_host | to_json }},
  "port": {{ unifi_echoport_backup_mongodb_port | int }},
  "database": {{ unifi_echoport_backup_mongodb_database | to_json }},
  "username": {{ unifi_echoport_backup_mongodb_username | to_json }},
  "password": {{ unifi_echoport_backup_mongodb_password | to_json }},
  "auth_db": {{ unifi_echoport_backup_mongodb_auth_db | to_json }}
}
"""
PASSWORD = "fixture-mongo-pass-0123456789"  # pragma: allowlist secret
SECRETS = {
    "unifi_echoport_backup_mongodb_database": "unifi",
    "unifi_echoport_backup_mongodb_username": "unifi",
    "unifi_echoport_backup_mongodb_password": PASSWORD,
    "unifi_echoport_backup_mongodb_auth_db": "admin",
}
PATH = "/etc/echoport-backups/unifi-mongodb.json"
WRITTEN = (
    '{\n  "host": "127.0.0.1",\n  "port": 27017,\n  "database": "unifi",\n  "username": "unifi",\n'
    f'  "password": "{PASSWORD}",\n  "auth_db": "admin"\n}}\n'
)
PLAN_CHECK = "command -v mongodump"
MCRCON = RequiredFile(
    path="/usr/local/bin/mcrcon",
    message="mcrcon not found at /usr/local/bin/mcrcon. Deploy minecraft_java first.",
)


def login_file(**changes: Any) -> CredentialFile:
    values: dict[str, Any] = {
        "path": PATH,
        "template": UNIFI_CONTENT,
        "variables": {"unifi_echoport_backup_mongodb_host": "127.0.0.1", "unifi_echoport_backup_mongodb_port": 27017},
        "secrets": tuple(SECRETS),
        "check": "mongodump",
        **changes,
    }
    return CredentialFile(**values)


def unifi(**changes: Any) -> RunnerRegistration:
    return a1.registration("unifi-backup", credential_files=(login_file(),), **changes)


def converged_unifi(cfg: RunnerRegistration, answer: str = "credentials-valid") -> dict[Any, Any]:
    return {
        **a1.converged(cfg),
        **fakehost.directory("/etc/echoport-backups", mode="drwx------"),
        **fakehost.file(PATH, WRITTEN, mode="-rw-------"),
        PLAN_CHECK: answer.splitlines(),
    }


def run_unifi(cfg: RunnerRegistration, responses: dict[Any, Any]) -> Any:
    return run_deploy_fake(
        lambda: install_registration(cfg, secret_key=a1.SECRET, credentials=SECRETS), responses=responses
    )


def assert_no_password(fake: Any) -> None:
    for leaked in (PASSWORD, "0123456789"):
        assert leaked not in fake.all_text()
    for command, _ in fake.stdin:
        assert PASSWORD not in command


def test_the_login_file_is_what_the_playbooks_copy_writes() -> None:
    assert login_file().content(SECRETS) == WRITTEN


def test_a_converged_unifi_host_gets_no_mutating_operation_and_the_check_reads_stdin() -> None:
    cfg = unifi()
    fake = run_unifi(cfg, converged_unifi(cfg))

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    checks = [stdin for command, stdin in fake.stdin if "mongodump" in command]
    # The plan-time probe and the step after the file, both with the file's text on stdin.
    assert checks == [WRITTEN, WRITTEN]
    assert_no_password(fake)


def test_the_check_step_follows_the_login_file_in_the_playbooks_order() -> None:
    cfg = unifi()
    responses = {**a1.converged(cfg), PLAN_CHECK: ["credentials-unchecked"]}
    fake = run_unifi(cfg, responses)

    assert fake.succeeded, fake.error
    names = [name.removeprefix("Echoport backup runner registration | ") for name in fake.changed_ops]
    write = names.index(f"Write {PATH}")
    assert names[write - 1] == "Ensure directory /etc/echoport-backups"
    assert names[write + 1] == f"Validate the login of {PATH} (mongodump)"
    assert f"Validate the login of {PATH} (mongodump)" not in fake.mutating_changed_ops
    assert_no_password(fake)


def test_a_login_mongodump_refuses_stops_before_any_write() -> None:
    cfg = unifi()
    answer = "Enter password:\nFailed: can't create session: Authentication failed.\ncredentials-refused"
    fake = run_unifi(cfg, converged_unifi(cfg, answer))

    message = a1.refused(fake)
    assert message.startswith(f"{PATH}: the mongodump check refused the login")
    assert "Authentication failed" in message
    assert_no_password(fake)


def test_a_check_needs_a_json_login_with_every_key() -> None:
    template = UNIFI_CONTENT.replace(',\n  "auth_db": {{ unifi_echoport_backup_mongodb_auth_db | to_json }}', "")
    secrets = tuple(name for name in SECRETS if name != "unifi_echoport_backup_mongodb_auth_db")
    with pytest.raises(ValueError, match="the mongodump check reads a JSON object with auth_db, database"):
        login_file(template=template, secrets=secrets)
    assert login_file(template=template, secrets=secrets, check=None).check is None


def test_the_check_puts_the_password_on_mongodumps_stdin_only(tmp_path: Path) -> None:
    seen = tmp_path / "seen.json"
    fake = tmp_path / "mongodump"
    fake.write_text(
        f"#!{sys.executable}\nimport json, sys\n"
        f"json.dump({{'argv': sys.argv[1:], 'stdin': sys.stdin.read()}}, open({str(seen)!r}, 'w'))\n"
        "sys.exit(0 if 'unifi' in sys.argv[3] else 1)\n"
    )
    fake.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    command = credential_check_command("mongodump")

    ok = subprocess.run(["sh", "-c", command], input=WRITTEN, env=env, capture_output=True, text=True, check=False)

    assert ok.returncode == 0, ok.stderr
    recorded = json.loads(seen.read_text())
    assert recorded["argv"] == [
        "--host=127.0.0.1",
        "--port=27017",
        "--db=unifi",
        "--username=unifi",
        "--authenticationDatabase=admin",
        "--archive=/dev/null",
        "--gzip",
    ]
    assert recorded["stdin"] == PASSWORD + "\n"
    assert PASSWORD not in command
    other = WRITTEN.replace('"database": "unifi"', '"database": "other"')
    refused = subprocess.run(["sh", "-c", command], input=other, env=env, capture_output=True, text=True, check=False)
    assert refused.returncode == 1


def test_minecraft_refuses_without_mcrcon_before_any_write() -> None:
    cfg = a1.registration("minecraft-java-backup", required_files=(MCRCON,))
    responses = {**a1.converged(cfg), "test -e /usr/local/bin/mcrcon": ["missing"]}
    fake = run_deploy_fake(a1.deploy(cfg), responses=responses)

    assert a1.refused(fake) == MCRCON.message


def test_a_converged_minecraft_host_with_mcrcon_gets_no_mutating_operation() -> None:
    cfg = a1.registration("minecraft-java-backup", required_files=(MCRCON,))
    responses = {**a1.converged(cfg), "test -e /usr/local/bin/mcrcon": ["present"]}
    fake = run_deploy_fake(a1.deploy(cfg), responses=responses)

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []


@pytest.mark.parametrize("name", ["unifi-backup", "minecraft-java-backup"])
def test_the_forked_runners_render_the_recorded_scripts(name: str) -> None:
    # A1's runners loop leaves these two out; they render from ops-deploy's own templates now.
    a1.test_the_runner_renders_as_ansible_rendered_it(name)
