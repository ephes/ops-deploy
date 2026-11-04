"""The mail_remove port; synthetic services, packages, paths and database state only (no mail data)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.services._lifecycle.apt_purge import PACKAGES
from ops_deploy.services.mail_remove import MailRemoveConfig, remove_mail
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/mail/remove"
APT = (
    "env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o Dpkg::Options::=--force-confdef"
    " -o Dpkg::Options::=--force-confold --purge remove --"
)
PSQL = "cd / && runuser -u postgres -- psql -X -q -t -A -v ON_ERROR_STOP=1 -d postgres -c "
# What just remove-one mail passes both plays: every component, the role's other defaults.
EVERYTHING = {"backend": True, "relay": True, "spam": True}


def role(name: str) -> Any:
    return yaml.safe_load((PARITY / name).read_text())


def confirmed(**values: Any) -> MailRemoveConfig:
    return MailRemoveConfig(confirm=True, **{**EVERYTHING, **values})


def host(
    *paths: str, installed: tuple[str, ...] = (), load: str = "loaded", database: str = "state=", role_: str = "state="
) -> dict[str, Any]:
    observed = dict(success=load != "not-found", enabled=True, active="active", load=load)
    responses: dict[str, Any] = {
        "import json, subprocess, sys": [json.dumps(observed)],
        "dpkg-query": [json.dumps(list(installed))],
        "pg_database": [database],
        "pg_roles": [role_],
        "postqueue -p": ["Mail queue is empty"],
        **fakehost.LINUX,
        **fakehost.system_account("vmail", "/mnt/cryptdata/vmail"),
    }
    for path in paths:
        responses.update(fakehost.directory(path))
    return responses


def commands(run: Any) -> list[str]:
    return [command for command in run.executed_commands if "import json, subprocess" not in command]


def test_fixtures_are_the_recorded_role_files() -> None:
    manifest = json.loads((PARITY / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (PARITY / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()


def test_defaults_are_the_roles() -> None:
    defaults = role("defaults.yml")
    cfg = MailRemoveConfig()
    for field in (
        "confirm",
        "backend",
        "relay",
        "spam",
        "purge_packages",
        "remove_configs",
        "remove_state",
        "remove_data",
        "remove_vmail_user",
        "drop_database",
        "drop_db_user",
        "db_force_disconnect",
        "postgres_database",
        "postgres_user",
        "postgres_become_user",
    ):
        assert getattr(cfg, field) == defaults["mail_remove_" + field], field
    for field in ("vmail_path", "backup_path", "vmail_user", "vmail_group"):
        assert getattr(cfg, field) == defaults["mail_" + field]
    for kind in ("backend", "relay", "spam"):
        assert list(getattr(cfg, f"{kind}_services")) == defaults[f"mail_remove_{kind}_services"]
        assert list(getattr(cfg, f"packages_{kind}")) == defaults[f"mail_remove_packages_{kind}"]
        assert list(getattr(cfg, f"config_paths_{kind}")) == defaults[f"mail_remove_config_paths_{kind}"]
        assert list(getattr(cfg, f"state_paths_{kind}")) == defaults[f"mail_remove_state_paths_{kind}"]
    assert defaults["mail_remove_data_paths"] == ["{{ mail_vmail_path }}", "{{ mail_backup_path }}"]


def test_role_task_order_is_the_ported_one() -> None:
    tasks = role("tasks.yml")
    modules = [next(key for key in task if key.startswith(("ansible.", "community."))) for task in tasks]
    assert modules == [
        "ansible.builtin.assert",
        "ansible.builtin.set_fact",
        "ansible.builtin.command",  # postqueue -p
        "ansible.builtin.debug",  # queue warning
        "ansible.builtin.service_facts",
        "ansible.builtin.set_fact",  # present services only
        "ansible.builtin.systemd",
        "ansible.builtin.apt",
        "ansible.builtin.file",  # configs
        "ansible.builtin.file",  # state
        "ansible.builtin.file",  # data
        "ansible.builtin.user",
        "ansible.builtin.group",
        "community.postgresql.postgresql_db",
        "community.postgresql.postgresql_user",
        "ansible.builtin.debug",
    ]
    assert tasks[6]["ansible.builtin.systemd"] == {"name": "{{ item }}", "state": "stopped", "enabled": False}
    assert tasks[6]["failed_when"] is False
    assert tasks[7]["ansible.builtin.apt"] == {
        "name": "{{ mail_remove_target_packages | unique }}",
        "state": "absent",
        "purge": True,
    }
    assert tasks[11]["ansible.builtin.user"]["remove"] == "{{ mail_remove_remove_data | bool }}"
    assert tasks[13]["community.postgresql.postgresql_db"]["force"] == "{{ mail_remove_db_force_disconnect | bool }}"
    assert all(tasks[index]["become_user"] == "{{ mail_remove_postgres_become_user }}" for index in (13, 14))


def test_confirmation_and_a_component_precede_every_probe() -> None:
    for cfg in (MailRemoveConfig(**EVERYTHING), MailRemoveConfig(confirm=True)):
        run = run_deploy_fake(remove_mail, cfg)
        assert not run.succeeded
        assert "not confirmed or no components" in str(run.error)
        assert not run.events
        assert not run.ops


@pytest.mark.parametrize(
    "values",
    [{"vmail_path": "/"}, {"backup_path": "/mnt"}, {"config_paths_spam": ("/etc/../x",)}, {"vmail_user": "root"}],
)
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"removal paths|root cannot"):
        confirmed(**values)


def test_invalid_database_names_are_refused() -> None:
    with pytest.raises(ValueError, match="pattern"):
        confirmed(postgres_database='mail"; DROP')


def test_component_targets_are_the_roles_unions() -> None:
    cfg = confirmed()
    assert cfg.target_services == ("postfix", "dovecot", "opendkim", "postgrey", "rspamd")
    assert cfg.target_packages[-4:] == ("libsasl2-modules", "postgrey", "sasl2-bin", "rspamd")
    assert len(cfg.target_packages) == len(set(cfg.target_packages)) == 14
    assert cfg.target_config_paths == ("/etc/postfix", "/etc/dovecot", "/etc/opendkim", "/etc/postgrey", "/etc/rspamd")
    assert cfg.target_state_paths == (
        "/var/spool/postfix",
        "/var/lib/postfix",
        "/var/lib/dovecot",
        "/var/lib/opendkim",
        "/var/lib/postgrey",
        "/var/lib/rspamd",
        "/var/log/rspamd",
    )
    relay = MailRemoveConfig(confirm=True, relay=True)
    assert relay.target_services == ("postfix", "postgrey")
    assert relay.target_packages == ("postfix", "postgrey", "libsasl2-modules", "sasl2-bin")


def test_the_recipes_removal_keeps_data_accounts_and_database() -> None:
    cfg = confirmed()
    paths = (*cfg.target_config_paths, *cfg.target_state_paths, cfg.vmail_path, cfg.backup_path)
    run = run_deploy_fake(
        remove_mail, cfg, responses=host(*paths, installed=("postfix", "dovecot-core", "rspamd"), database="state=1")
    )
    assert run.succeeded, run.error
    executed = commands(run)
    stops = [
        command for name in cfg.target_services for command in (f"systemctl disable {name}", f"systemctl stop {name}")
    ]
    assert executed == [
        *stops,
        f"{APT} postfix dovecot-core rspamd",
        *(f"rm -rf {path}" for path in (*cfg.target_config_paths, *cfg.target_state_paths)),
    ]


def test_every_flag_removes_data_account_database_and_role() -> None:
    cfg = confirmed(
        remove_data=True, remove_vmail_user=True, drop_database=True, drop_db_user=True, db_force_disconnect=True
    )
    run = run_deploy_fake(
        remove_mail, cfg, responses=host(cfg.vmail_path, cfg.backup_path, database="state=1", role_="state=1")
    )
    assert run.succeeded, run.error
    assert commands(run)[-6:] == [
        f"rm -rf {cfg.vmail_path}",
        f"rm -rf {cfg.backup_path}",
        "userdel -r vmail",
        "groupdel vmail",
        PSQL + """'DROP DATABASE "mail" WITH (FORCE)'""",
        PSQL + """'DROP USER "mail"'""",
    ]


def test_absent_units_packages_and_database_change_nothing() -> None:
    cfg = confirmed(drop_database=True, drop_db_user=True)
    run = run_deploy_fake(remove_mail, cfg, responses=host(load="not-found"))
    assert run.succeeded, run.error
    assert commands(run) == []


def test_kept_home_and_plain_drop_without_force() -> None:
    cfg = confirmed(remove_vmail_user=True, drop_database=True, purge_packages=False)
    run = run_deploy_fake(remove_mail, cfg, responses=host(database="state=1"))
    assert run.succeeded, run.error
    assert commands(run)[-3:] == ["userdel vmail", "groupdel vmail", PSQL + """'DROP DATABASE "mail"'"""]


def test_unreadable_database_or_package_state_fails() -> None:
    run = run_deploy_fake(remove_mail, confirmed(drop_database=True), responses=host(database="error"))
    assert not run.succeeded
    assert "DROP" not in "\n".join(commands(run))
    run = run_deploy_fake(remove_mail, confirmed(), responses={**host(), "dpkg-query": {"success": False}})
    assert not run.succeeded
    assert "apt-get" not in "\n".join(commands(run))


def test_service_failures_are_ignored() -> None:
    run = run_deploy_fake(remove_mail, confirmed(), responses={"systemctl stop": {"success": False}, **host()})
    assert run.error is None


def test_a_non_empty_queue_warns(caplog: pytest.LogCaptureFixture) -> None:
    responses = {**host(), "postqueue -p": ["-Queue ID-  --Size--", "ABC123  42"]}
    run = run_deploy_fake(remove_mail, confirmed(), responses=responses)
    assert run.succeeded, run.error
    assert "Mail queue is not empty" in caplog.text
    caplog.clear()
    run_deploy_fake(remove_mail, MailRemoveConfig(confirm=True, spam=True), responses=responses)
    assert "Mail queue" not in caplog.text


def fake_dpkg(tmp_path: Path, stdout: str, stderr: str, code: int) -> dict[str, str]:
    script = tmp_path / "dpkg-query"
    script.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"sys.stdout.write({stdout!r}); sys.stderr.write({stderr!r}); sys.exit({code})\n"
    )
    script.chmod(0o700)
    return {**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]}


@pytest.mark.parametrize(
    ("stdout", "stderr", "code", "result"),
    [
        ("postfix\tinstalled\nrspamd\tconfig-files\n", "", 0, ["postfix", "rspamd"]),
        ("postfix\tnot-installed\n", "dpkg-query: no packages found matching rspamd\n", 1, []),
        ("postfix\tinstalled\n", "", 0, None),  # rspamd unaccounted for
        ("other\tinstalled\nrspamd\tinstalled\n", "", 0, None),
        ("", "", 2, None),
    ],
)
def test_package_probe_matches_the_apt_modules_selection(
    tmp_path: Path, stdout: str, stderr: str, code: int, result: list[str] | None
) -> None:
    env = fake_dpkg(tmp_path, stdout, stderr, code)
    done = subprocess.run(
        [sys.executable, "-I", "-B", "-c", PACKAGES, "postfix", "rspamd"], env=env, capture_output=True, text=True
    )
    if result is None:
        assert done.returncode != 0
    else:
        assert done.returncode == 0, done.stderr
        assert json.loads(done.stdout) == result
