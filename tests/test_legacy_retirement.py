"""services.legacy_retirement: synthetic host states, archives in a temporary directory only."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.legacy_retirement import LegacyRetirementConfig, RetiredDatabase, retire_legacy
from ops_deploy.services.legacy_retirement.retire import _archive
from ops_deploy.testing import run_deploy_fake

ROOT = "/var/backups/legacy-retirement"
ROUTE = "/etc/traefik/dynamic/app.traefik.yml"
PREFIX = "Retire legacy accounts and services | "


def config(**values: Any) -> LegacyRetirementConfig:
    defaults: dict[str, Any] = {
        "archive_dir": ROOT,
        "accounts": ("alice", "app"),
        "units": ("app.service", "app.web.service"),
        "paths": (ROUTE,),
        "databases": (RetiredDatabase(name="app", owner="app"),),
        "protected_accounts": ("keeper",),
    }
    return LegacyRetirementConfig(**{**defaults, **values})


def account(user: str, *, uid: int = 1100, processes: int = 0, **values: Any) -> dict[str, Any]:
    return {
        "present": True,
        "uid": uid,
        "group": True,
        "home": f"/home/{user}",
        "home_exists": True,
        "home_link": False,
        "mail": False,
        "processes": processes,
        "linger": False,
        "crontab": False,
        **values,
    }


def absent(user: str, **values: Any) -> dict[str, Any]:
    return account(user, **{"present": False, "uid": None, "group": False, "home_exists": False, **values})


def archives(value: bool) -> dict[str, bool]:
    return dict.fromkeys(config().archives(), value)


def archive_of(path: str) -> str:
    return f"{ROOT}/{config().source_archive(path)}"


def unit(name: str, *, active: str = "inactive", enabled: str = "disabled", dropin: bool = False) -> dict[str, Any]:
    return {
        "LoadState": "loaded",
        "ActiveState": active,
        "UnitFileState": enabled,
        "FragmentPath": f"/etc/systemd/system/{name}",
        "DropInPaths": f"/etc/systemd/system/{name}.d/99-x.conf" if dropin else "",
        "file": True,
        "dropin_dir": dropin,
    }


def present(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "accounts": {"alice": account("alice"), "app": account("app", mail=True)},
        "units": {
            "app.service": unit("app.service", enabled="enabled"),
            "app.web.service": unit("app.web.service", dropin=True),
        },
        "groups": {},
        "paths": {ROUTE: True},
        "archives": archives(False),
        "postgres": True,
        "databases": {"app": {"exists": True, "owner_exists": True, "connections": 0, "owner_other_databases": []}},
    }
    state.update(overrides)
    return state


def gone() -> dict[str, Any]:
    missing = {
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "UnitFileState": "",
        "FragmentPath": "",
        "DropInPaths": "",
        "file": False,
        "dropin_dir": False,
    }
    return present(
        accounts={"alice": absent("alice"), "app": absent("app")},
        units={"app.service": missing, "app.web.service": missing},
        paths={ROUTE: False},
        archives=archives(True),
        databases={"app": {"exists": False, "owner_exists": False, "connections": 0, "owner_other_databases": []}},
    )


def run(state: dict[str, Any], cfg: LegacyRetirementConfig | None = None) -> Any:
    responses = {
        "uname -s": ["Linux"],
        "cat /proc/1/comm": ["systemd"],
        "legacy-retirement-probe": [json.dumps(state)],
        f"test -e {ROUTE}": ["yes"] if state["paths"].get(ROUTE) else [],
    }
    return run_deploy_fake(retire_legacy, cfg or config(), responses=responses)


@pytest.mark.parametrize(
    "values",
    [
        {"archive_dir": "/var/backups"},
        {"archive_dir": "/var/backups/a/b"},
        {"archive_dir": "/tmp/legacy"},
        {"archive_dir": "/var/backups/../tmp"},
        {"accounts": ("root",)},
        {"accounts": ("postgres",)},
        {"accounts": ("keeper",)},
        {"accounts": ("alice", "alice")},
        {"paths": ("/etc/x",)},
        {"paths": ("/usr/lib",)},
        {"paths": ("/opt",)},
        {"groups": ("sudo",)},
        {"groups": ("root",)},
        {"groups": ("g", "g")},
        {"paths": ("/home/alice/site",)},
        {"paths": ("/etc/systemd/system/app.service",)},
        {"paths": (ROOT + "/home-alice.tar.gz",)},
        {"paths": ("/etc/traefik/../shadow/x",)},
        {"units": ("app",)},
        {"min_uid": 999},
        {"accounts": (), "units": (), "paths": (), "databases": ()},
    ],
)
def test_config_refusals(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**values)


@pytest.mark.parametrize(
    ("name", "owner"), [("postgres", "app"), ("template1", "app"), ("app", "postgres"), ("App", "app"), ("a;b", "app")]
)
def test_database_refusals(name: str, owner: str) -> None:
    with pytest.raises(ValidationError):
        RetiredDatabase(name=name, owner=owner)


def test_archives_everything_before_the_first_removal() -> None:
    result = run(present())
    assert result.succeeded, result.error
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    expected = [
        f"Root-only archive directory {ROOT}",
        *(
            f"Archive {path} to {archive_of(path)}"
            for path in (
                "/etc/systemd/system/app.service",
                "/etc/systemd/system/app.web.service",
                "/etc/systemd/system/app.web.service.d",
                ROUTE,
            )
        ),
        f"Dump PostgreSQL database app to {ROOT}/postgres-app.dump",
        f"Archive /home/alice to {ROOT}/home-alice.tar.gz",
        f"Archive /home/app and /var/mail/app to {ROOT}/home-app.tar.gz",
        "Disable app.service",
        "Remove /etc/systemd/system/app.service",
        "Remove /etc/systemd/system/app.web.service",
        "Remove /etc/systemd/system/app.web.service.d",
        "Reload systemd after the unit removal",
        "Reset the failed state of app.service",
        "Reset the failed state of app.web.service",
        f"Check the archive of {ROUTE}",
        f"Remove {ROUTE}",
        "Drop PostgreSQL database app",
        "Drop PostgreSQL role app",
        "Remove user alice, /home/alice and its mail spool",
        "Remove user app, /home/app and its mail spool",
    ]
    assert [name.split(" (")[0] if name.startswith("Root-only") else name for name in names] == expected
    commands = "\n".join(result.executed_commands)
    assert "tar --numeric-owner --acls --xattrs -czpf" in commands
    assert "chmod 0600" in commands
    assert "pkill" not in commands
    assert "kill " not in commands
    assert "systemctl stop" not in commands
    assert result.fish_unsafe_commands == []


def test_removal_commands_check_the_archive_and_processes_again() -> None:
    result = run(present())
    commands = result.executed_commands
    joined = "\n".join(commands)

    def index(fragment: str) -> int:
        return next(number for number, command in enumerate(commands) if fragment in command)

    assert "ps -u alice -o pid=" in joined
    assert f"test -s {ROOT}/home-alice.tar.gz && userdel -- alice" in joined
    assert f"test -s {ROOT}/postgres-app.dump" in joined
    assert "pg_stat_activity" in joined
    assert "DROP DATABASE IF EXISTS app" in joined
    assert "DROP ROLE IF EXISTS app" in joined
    unit_file = "/etc/systemd/system/app.service"
    assert f"test -s {archive_of(unit_file)} && rm -rf -- {unit_file}" in joined
    assert "systemctl show -p ActiveState --value -- app.service" in joined
    assert "test -e /var/lib/systemd/linger/alice" in joined
    assert "test -e /var/spool/cron/crontabs/alice" in joined
    assert "ln -- " in joined
    assert "mv " not in joined
    assert index("home-alice.tar.gz.partial") < index("userdel -- alice")
    assert index("postgres-app.dump.partial") < index("DROP DATABASE")
    assert index(f"{archive_of(ROUTE).rsplit('/', 1)[1]}.partial") < index(f"rm -rf {ROUTE}")


def test_converged_host_changes_nothing() -> None:
    result = run(gone())
    assert result.succeeded, result.error
    assert result.ops == []
    assert result.executed_commands == []


def test_existing_archives_are_kept_and_removal_resumes() -> None:
    state = present(archives=archives(True))
    result = run(state)
    assert result.succeeded, result.error
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    assert not any(name.startswith(("Archive ", "Dump ")) for name in names)
    assert "Remove user alice, /home/alice and its mail spool" in names


@pytest.mark.parametrize(
    ("state", "message"),
    [
        (
            present(accounts={"alice": account("alice", processes=2), "app": absent("app")}),
            "alice has running processes",
        ),
        (present(accounts={"alice": account("alice", uid=999), "app": absent("app")}), "below 1000"),
        (present(accounts={"alice": account("alice", home="/srv/alice"), "app": absent("app")}), "not /home/alice"),
        (present(accounts={"alice": account("alice", linger=True), "app": absent("app")}), "lingering"),
        (
            present(accounts={"alice": account("alice", home_exists=False, home_link=True), "app": absent("app")}),
            "symbolic link",
        ),
        (
            present(accounts={"alice": absent("alice", home_link=True), "app": absent("app")}),
            "symbolic link",
        ),
        (present(accounts={"alice": account("alice", crontab=True), "app": absent("app")}), "crontab"),
        (
            present(
                units={"app.service": unit("app.service", active="active"), "app.web.service": unit("app.web.service")}
            ),
            "app.service is active",
        ),
        (
            present(
                units={
                    "app.service": {**unit("app.service"), "FragmentPath": "/lib/systemd/system/app.service"},
                    "app.web.service": unit("app.web.service"),
                }
            ),
            "not a unit file",
        ),
        (
            present(
                databases={"app": {"exists": True, "owner_exists": True, "connections": 1, "owner_other_databases": []}}
            ),
            "open connections",
        ),
        (
            present(
                databases={
                    "app": {"exists": True, "owner_exists": True, "connections": 0, "owner_other_databases": ["x"]}
                }
            ),
            "owns other databases",
        ),
        (present(postgres=False, databases={}), "no PostgreSQL"),
    ],
)
def test_refusals_change_nothing(state: dict[str, Any], message: str) -> None:
    result = run(state)
    assert not result.succeeded
    assert message in str(result.error)
    assert result.executed_commands == []


def test_unreadable_state_changes_nothing() -> None:
    responses = {
        "uname -s": ["Linux"],
        "cat /proc/1/comm": ["systemd"],
        "legacy-retirement-probe": ["", "ops-deploy-probe-failed"],
    }
    result = run_deploy_fake(retire_legacy, config(), responses=responses)
    assert not result.succeeded
    assert "Cannot read the legacy retirement state" in str(result.error)
    assert result.executed_commands == []


def test_archive_command_writes_a_private_checked_tarball(tmp_path: Path) -> None:
    source = tmp_path / "home" / "alice"
    source.mkdir(parents=True)
    (source / "notes.txt").write_text("synthetic")
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    cfg = LegacyRetirementConfig.model_construct(archive_dir=str(archive))
    command = _archive(cfg, "home-alice.tar.gz", [str(source)])
    subprocess.run(["sh", "-c", command], check=True, timeout=60)
    written = archive / "home-alice.tar.gz"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert sorted(os.listdir(archive)) == ["home-alice.tar.gz"]
    listing = subprocess.run(["tar", "-tzf", str(written)], check=True, capture_output=True, text=True).stdout
    assert str(source / "notes.txt").lstrip("/") in listing
    # An existing archive is never replaced.
    assert subprocess.run(["sh", "-c", command], timeout=60).returncode != 0
    assert sorted(os.listdir(archive)) == ["home-alice.tar.gz"]


def test_a_newly_listed_path_is_archived_although_others_are() -> None:
    known = archives(True)
    known[config().source_archive(ROUTE)] = False
    state = present(archives=known)
    result = run(state)
    assert result.succeeded, result.error
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    assert names.count(f"Archive {ROUTE} to {archive_of(ROUTE)}") == 1
    assert sum(name.startswith("Archive ") for name in names) == 1
    assert names.index(f"Archive {ROUTE} to {archive_of(ROUTE)}") < names.index(f"Remove {ROUTE}")


def test_an_interrupted_account_removal_resumes() -> None:
    state = gone()
    state["accounts"]["alice"] = absent("alice", home_exists=True, group=True)
    result = run(state)
    assert result.succeeded, result.error
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    assert names[0].startswith("Root-only archive directory")
    assert names[1:] == ["Remove user alice, /home/alice and its mail spool"]
    joined = "\n".join(result.executed_commands)
    assert "userdel" not in joined
    assert f"test -s {ROOT}/home-alice.tar.gz && rm -rf -- /home/alice /var/mail/alice" in joined
    assert "groupdel -- alice" in joined


def test_an_interrupted_account_without_its_archive_is_archived_first() -> None:
    state = gone()
    state["accounts"]["alice"] = absent("alice", home_exists=True)
    state["archives"]["home-alice.tar.gz"] = False
    result = run(state)
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    assert names[1:] == [
        f"Archive /home/alice to {ROOT}/home-alice.tar.gz",
        "Remove user alice, /home/alice and its mail spool",
    ]


def test_publication_never_replaces_an_archive_that_appeared(tmp_path: Path) -> None:
    from ops_deploy.services.legacy_retirement.retire import _publish

    partial, final = tmp_path / ".a.partial", tmp_path / "a"
    partial.write_text("new")
    final.write_text("old")
    assert subprocess.run(["sh", "-c", _publish(str(partial), str(final))], timeout=10).returncode != 0
    assert final.read_text() == "old"


def group(
    *, exists: bool = True, gid: int = 1200, members: tuple[str, ...] = (), primary_of: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {"exists": exists, "gid": gid if exists else None, "members": list(members), "primary_of": list(primary_of)}


def test_opt_application_directories_are_allowed() -> None:
    assert config(paths=("/opt/app",)).paths == ("/opt/app",)
    assert config(paths=("/srv/app",)).paths == ("/srv/app",)


def test_a_group_is_removed_after_its_retired_members() -> None:
    cfg = config(groups=("courses",))
    state = present(groups={"courses": group(members=("alice",))})
    result = run(state, cfg)
    assert result.succeeded, result.error
    names = [op.name.removeprefix(PREFIX) for op in result.ops]
    assert names[-1] == "Remove group courses"
    assert names.index("Remove user alice, /home/alice and its mail spool") < names.index("Remove group courses")
    gone_state = gone()
    gone_state["groups"] = {"courses": group(exists=False)}
    assert run(gone_state, cfg).ops == []


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (group(members=("alice", "keeper")), "still has accounts keeper"),
        (group(primary_of=("bob",)), "still has accounts bob"),
        (group(gid=100), "below 1000"),
    ],
)
def test_a_group_still_in_use_is_refused(value: dict[str, Any], message: str) -> None:
    result = run(present(groups={"courses": value}), config(groups=("courses",)))
    assert not result.succeeded
    assert message in str(result.error)
    assert result.executed_commands == []
