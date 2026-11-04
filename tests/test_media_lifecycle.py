"""MeTube, Jellyfin and Navidrome backup and restore: plans, and the host program against tmp dirs.

The host program runs for real here (tar, chown, the vendored preserver);
``systemctl``, ``rsync`` (a ``cp -a`` stand-in) and ``findmnt`` are stubs on
``PATH`` that log their calls.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pwd
import shlex
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services._lifecycle import media_lifecycle
from ops_deploy.services.jellyfin import (
    JellyfinBackupConfig,
    JellyfinRestoreConfig,
    deploy_jellyfin_backup,
    deploy_jellyfin_restore,
)
from ops_deploy.services.metube import (
    MetubeBackupConfig,
    MetubeRestoreConfig,
    deploy_metube_backup,
    deploy_metube_restore,
)
from ops_deploy.services.navidrome import (
    NavidromeBackupConfig,
    NavidromeRestoreConfig,
    deploy_navidrome_backup,
    deploy_navidrome_restore,
)
from ops_deploy.testing import FakeRun, run_deploy_fake

STAMP = "20261104T120000"
TIME = {"date +%Y%m%dT%H%M%S": [STAMP]}
ME = pwd.getpwuid(os.getuid()).pw_name
GID = str(os.getgid())


def payload_of(result: FakeRun, action: str) -> tuple[str, dict[str, Any]]:
    ((command, stdin),) = [(c, s) for c, s in result.stdin if shlex.split(c)[-1] == action]
    return command, json.loads(stdin)


def names(result: FakeRun) -> list[str]:
    return [op.split(" | ", 1)[1] for op in result.changed_ops]


# --- plans -------------------------------------------------------------------


def test_defaults_are_the_shared_role_defaults() -> None:
    metube, jellyfin, navidrome = MetubeBackupConfig(), JellyfinBackupConfig(), NavidromeBackupConfig()

    assert (metube.root, metube.state_dir, metube.env_file, metube.service_unit) == (
        "/opt/backups/metube",
        "/var/lib/metube",
        "/etc/metube/metube.env",
        "/etc/systemd/system/metube.service",
    )
    assert (jellyfin.service_unit, jellyfin.config_dir, jellyfin.retain) == (
        "/lib/systemd/system/jellyfin.service",
        "/etc/jellyfin",
        7,
    )
    assert (navidrome.config_path, navidrome.bin_path, navidrome.stop_service) == (
        "/etc/navidrome.toml",
        "/opt/navidrome/navidrome",
        True,
    )
    assert MetubeRestoreConfig().staging_dir == "/tmp/metube-restore"
    assert JellyfinRestoreConfig().staging_dir == "/tmp/jellyfin-restore"
    assert NavidromeRestoreConfig().staging_dir == "/tmp/navidrome-restore"


def test_metube_backup_plan_checks_the_mount_runs_one_program_fetches_then_prunes(tmp_path: Path) -> None:
    cfg = MetubeBackupConfig(prefix="nightly", local_dir=tmp_path / "local", required_mount="/opt/backups")

    result = run_deploy_fake(deploy_metube_backup, cfg, responses=TIME)

    assert result.succeeded, result.error
    _, payload = payload_of(result, "backup")
    directory = f"/opt/backups/metube/nightly-{STAMP}"
    assert (payload["dir"], payload["archive"]) == (directory, f"{directory}.tar.gz")
    assert payload["version"] == [
        "/opt/metube/venv/bin/python3",
        "-c",
        "import yt_dlp, sys; print(getattr(yt_dlp,'__version__','unknown'))",
    ]
    assert payload["copies"] == [
        ["tree", 0, "/var/lib/metube", "state", True],
        ["file", 1, "/etc/metube/metube.env", "config/metube.env", False],
        ["file", 2, "/etc/systemd/system/metube.service", "systemd/metube.service", False],
        ["file", 3, "/etc/traefik/dynamic/metube.yml", "traefik/metube.yml", False],
    ]
    assert payload["manifest"][:2] == [["timestamp", STAMP], ["archive", f"nightly-{STAMP}.tar.gz"]]
    assert (payload["stop"], payload["unit"], payload["generate_manifest"]) == (True, "metube", True)
    _, retention = payload_of(result, "retain")
    assert retention == {
        "service": "metube",
        "root": "/opt/backups/metube",
        "prefix": "nightly",
        "extension": "tar.gz",
        "retain": 7,
        "create_archive": True,
        "prune_dirs": True,
    }
    steps = names(result)
    assert steps[0] == "Require /opt/backups below /opt/backups/metube"
    assert steps.index("Fetch the MeTube backup archive") < steps.index("Keep the newest 7 nightly MeTube backups")
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "local" / f"nightly-{STAMP}.tar.gz").stat().st_mode & 0o777 == 0o600


def test_jellyfin_and_navidrome_backups_take_their_roles_sources() -> None:
    jellyfin = run_deploy_fake(deploy_jellyfin_backup, JellyfinBackupConfig(fetch_local=False), responses=TIME)
    navidrome = run_deploy_fake(
        deploy_navidrome_backup, NavidromeBackupConfig(fetch_local=False, include_logs=False), responses=TIME
    )

    _, j = payload_of(jellyfin, "backup")
    _, n = payload_of(navidrome, "backup")
    assert payload_of(jellyfin, "retain")[1]["prune_dirs"] is True
    assert payload_of(navidrome, "retain")[1]["prune_dirs"] is False
    assert j["version"] == ["dpkg-query", "-W", "-f=${Version}", "jellyfin"]
    assert [copy[3] for copy in j["copies"]] == [
        "data",
        "config",
        "systemd/jellyfin.service",
        "traefik/jellyfin.yml",
        "logs",
    ]
    assert j["copies"][4][4] is False  # logs never with --delete
    assert [key for key, _ in j["manifest"]] == [
        "timestamp",
        "archive",
        "data_dir",
        "config_dir",
        "service_unit",
        "traefik_config",
        "log_dir",
    ]
    assert j["missing"] == "Required Jellyfin path missing: {path}"
    assert n["version"] == ["/opt/navidrome/navidrome", "--version"]
    assert [copy[3] for copy in n["copies"]] == [
        "data",
        "config/navidrome.toml",
        "systemd/navidrome.service",
        "traefik/navidrome.yml",
    ]
    assert ["config", "/etc/navidrome.toml"] in n["manifest"]
    assert "Fetch the Jellyfin backup archive" not in names(jellyfin)


def test_backup_without_retention_or_archive_plans_no_fetch_or_prune() -> None:
    cfg = MetubeBackupConfig(retain=0, create_archive=False)

    result = run_deploy_fake(deploy_metube_backup, cfg, responses=TIME)

    assert result.succeeded, result.error
    assert names(result) == [f"Back up MeTube into /opt/backups/metube/manual-{STAMP}"]


def test_restores_of_routes_in_the_dynamic_directory_wait_for_the_transaction_lock() -> None:
    metube = run_deploy_fake(deploy_metube_restore, MetubeRestoreConfig(archive="manual-1.tar.gz"))
    jellyfin = run_deploy_fake(deploy_jellyfin_restore, JellyfinRestoreConfig())
    elsewhere = run_deploy_fake(deploy_jellyfin_restore, JellyfinRestoreConfig(traefik_config_path="/srv/route.yml"))

    for result, action in ((metube, "restore-metube"), (jellyfin, "restore-jellyfin")):
        command, _ = payload_of(result, action)
        assert command.startswith(route_guard_command() + " && python3 -I -c ")
    command, _ = payload_of(elsewhere, "restore-jellyfin")
    assert command.startswith("python3 ")
    _, payload = payload_of(metube, "restore-metube")
    assert payload["route_guard"] == shlex.split(route_guard_command())
    assert payload_of(elsewhere, "restore-jellyfin")[1]["route_guard"] == []
    assert (payload["archive"], payload["staging"], payload["enabled"]) == (
        "manual-1.tar.gz",
        "/tmp/metube-restore",
        True,
    )


def test_navidrome_restore_needs_confirmation_before_any_step() -> None:
    result = run_deploy_fake(deploy_navidrome_restore, NavidromeRestoreConfig())

    assert not result.succeeded
    assert "not confirmed" in str(result.error)
    assert result.fact_commands == []
    assert result.stdin == []


def test_confirmed_navidrome_restore_runs_the_quarantine_program_without_the_route_guard() -> None:
    result = run_deploy_fake(deploy_navidrome_restore, NavidromeRestoreConfig(confirm=True, archive="/x/a.tar.gz"))

    assert result.succeeded, result.error
    command, payload = payload_of(result, "restore-navidrome")
    assert command.startswith("python3 -I -c ")
    assert payload["state_root"] == "/var/lib/ops-deploy/navidrome"
    assert payload["archive"] == "/x/a.tar.gz"


@pytest.mark.parametrize(
    "override",
    [
        {"data_dir": "/srv/navidrome"},
        {"cache_dir": "/var/cache/navidrome"},
        {"staging_dir": "/tmp/other"},
        {"config_path": "/etc/other.toml"},
        {"traefik_config_path": "/etc/traefik/dynamic/x.yml"},
        {"user": "music"},
        {"state_root": "/var/lib/other"},
    ],
)
def test_navidrome_recovery_refuses_non_canonical_paths(override: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        NavidromeRestoreConfig(confirm=True, **override)


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (MetubeBackupConfig, {"root": "/opt/backups"}),
        (MetubeBackupConfig, {"root": "/opt/backups/../etc"}),
        (MetubeBackupConfig, {"root": "/opt/backups/metube", "required_mount": "/srv"}),
        (MetubeRestoreConfig, {"staging_dir": "/tmp"}),
        (MetubeRestoreConfig, {"state_dir": "/var/lib"}),
        (MetubeRestoreConfig, {"archive": "../../etc/shadow.tar.gz"}),
        (JellyfinRestoreConfig, {"config_dir": "/etc"}),
        (JellyfinRestoreConfig, {"archive": "x; rm -rf /"}),
    ],
)
def test_configs_refuse_shared_or_unsafe_paths(model: Any, values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        model(**values)


# --- host program ------------------------------------------------------------

STUBS = {
    "systemctl": 'if [ "$1" = show ]; then [ -n "${STUB_FAIL_SHOW:-}" ] && exit 1; '
    'echo "LoadState=${STUB_LOAD:-loaded}"; '
    'echo "ActiveState=${STUB_ACTIVE:-active}"; exit 0; fi\n'
    '[ -n "${STUB_FAIL_RELOAD:-}" ] && [ "$1" = reload ] && exit 1\n'
    '[ -n "${STUB_FAIL_STOP:-}" ] && [ "$1" = stop ] && exit 1\n'
    '[ -n "${STUB_FAIL_START:-}" ] && [ "$1" = start ] && exit 1\nexit 0',
    # rsync -a [--delete] SRC/ DST/: a copy that keeps modes is enough here.
    "rsync": 'for a in "$@"; do case "$a" in -*) ;; *) set -- "$@" "$a";; esac; done\n'
    'n=$#; src="${@:n-1:1}"; dst="${@:n:1}"; mkdir -p "$dst" && cp -pR "$src". "$dst"',
    "findmnt": 'echo \'{"filesystems": [{"target": "/"}]}\'',
}


@pytest.fixture
def stubs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    flags = tmp_path / "flags"
    flags.mkdir()
    for name, body in STUBS.items():
        path = bin_dir / name
        header = f'for f in {flags}/*; do [ -f "$f" ] && export "$(basename "$f")=$(cat "$f")"; done\n'
        path.write_text(f'#!/bin/bash\n{header}echo "{name} $*" >> {log}\n{body}\n')
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    log.write_text("")
    return log


def flag(tmp_path: Path, name: str, value: str = "1") -> None:
    (tmp_path / "flags" / name).write_text(value)


def calls(log: Path, command: str = "systemctl") -> list[str]:
    return [line for line in log.read_text().splitlines() if line.startswith(command + " ") and " show " not in line]


def host() -> Any:
    path = media_lifecycle.FILES / "media_lifecycle_host.py"
    spec = importlib.util.spec_from_file_location("media_lifecycle_host_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.PRESERVE_SOURCE = (media_lifecycle.FILES / "preserve.py").read_text()  # type: ignore[attr-defined]
    spec.loader.exec_module(module)
    # System files and recovery directories belong to the test's own account here.
    for name, value in {"ROOT_USER": ME, "ROOT_GROUP": GID, "TRUSTED_UID": os.getuid()}.items():
        setattr(module, name, value)
    return module


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def metube_live(base: Path, marker: str) -> dict[str, Path]:
    live = {
        "state": base / "var/lib/metube",
        "env": write(base / "etc/metube/metube.env", f"ENV={marker}\n"),
        "unit": write(base / "etc/systemd/system/metube.service", f"[Unit] {marker}\n"),
        "route": write(base / "etc/traefik/dynamic/metube.yml", f"route: {marker}\n"),
    }
    write(live["state"] / "queue.json", marker)
    return live


def metube_backup(base: Path, live: dict[str, Path], **extra: Any) -> dict[str, Any]:
    root = base / "backups/metube"
    directory = f"{root}/manual-{STAMP}"
    cfg = {
        "service": "metube",
        "label": "MeTube",
        "root": str(root),
        "dir": directory,
        "archive": f"{directory}.tar.gz",
        "owner": ME,
        "group": GID,
        "dir_mode": "0700",
        "file_mode": "0600",
        "stop": True,
        "unit": "metube",
        "create_archive": True,
        "version": [str(base / "missing/python3"), "-c", "pass"],
        "subdirs": ["state", "config", "systemd", "traefik"],
        "checks": [
            [str(live["state"]), True, "State directory"],
            [str(live["env"]), True, "Env file"],
            [str(live["unit"]), False, "Service unit"],
            [str(live["route"]), False, "Traefik config"],
        ],
        "missing": "Required path missing for backup: {label} ({path})",
        "copies": [
            ["tree", 0, str(live["state"]), "state", True],
            ["file", 1, str(live["env"]), "config/metube.env", False],
            ["file", 2, str(live["unit"]), "systemd/metube.service", False],
            ["file", 3, str(live["route"]), "traefik/metube.yml", False],
        ],
        "generate_manifest": True,
        "manifest": [
            ["timestamp", STAMP],
            ["archive", f"manual-{STAMP}.tar.gz"],
            ["state_dir", str(live["state"])],
        ],
    }
    cfg.update(extra)
    return cfg


def test_backup_copies_with_the_service_stopped_and_packs_the_role_layout(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "one")
    root = tmp_path / "backups/metube"
    write(root / "old.tar.gz", "x", 0o644)
    write(root / ".hidden.tar.gz", "x", 0o644)

    host().backup(metube_backup(tmp_path, live))

    directory = root / f"manual-{STAMP}"
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "old.tar.gz").stat().st_mode & 0o777 == 0o600
    assert (root / ".hidden.tar.gz").stat().st_mode & 0o777 == 0o644
    assert (directory / "state/queue.json").read_text() == "one"
    assert (directory / "config/metube.env").stat().st_mode & 0o777 == 0o600
    assert (directory / "manifest.yml").read_text() == (
        f'version: ""\ntimestamp: "{STAMP}"\narchive: "manual-{STAMP}.tar.gz"\nstate_dir: "{live["state"]}"\n'
    )
    assert calls(stubs) == ["systemctl stop metube", "systemctl daemon-reload", "systemctl start metube"]
    archive = root / f"manual-{STAMP}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as packed:
        members = packed.getnames()
    assert f"manual-{STAMP}" not in members
    assert sorted(members) == sorted(
        f"manual-{STAMP}/{name}"
        for name in (
            "state",
            "config",
            "systemd",
            "traefik",
            "manifest.yml",
            "state/queue.json",
            "config/metube.env",
            "systemd/metube.service",
            "traefik/metube.yml",
        )
    )
    assert not list(root.glob(".*.partial"))


def test_backup_leaves_a_stopped_service_stopped_and_skips_missing_optional_files(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "one")
    live["route"].unlink()
    flag(tmp_path, "STUB_ACTIVE", "inactive")

    host().backup(metube_backup(tmp_path, live))

    assert calls(stubs) == []
    assert not (tmp_path / f"backups/metube/manual-{STAMP}/traefik/metube.yml").exists()


def test_backup_refuses_a_missing_mandatory_path_before_stopping(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "one")
    live["env"].unlink()

    module = host()
    with pytest.raises(module.Failure, match=r"Required path missing for backup: Env file \("):
        module.backup(metube_backup(tmp_path, live))

    assert calls(stubs) == []


def test_backup_starts_the_service_again_when_a_copy_fails(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "one")
    cfg = metube_backup(tmp_path, live)
    cfg["copies"][1][2] = str(tmp_path / "gone.env")  # exists in checks, gone when copied

    with pytest.raises(FileNotFoundError):
        host().backup(cfg)

    assert calls(stubs)[-2:] == ["systemctl daemon-reload", "systemctl start metube"]


def test_retain_keeps_the_newest_archives_of_the_prefix(tmp_path: Path) -> None:
    root = tmp_path / "root"
    for index in range(4):
        path = write(root / f"manual-{index}.tar.gz", "x")
        os.utime(path, (time.time() - 100 + index, time.time() - 100 + index))
    write(root / "other-0.tar.gz", "x")
    (root / "manual-dir").mkdir()

    host().retain(
        {
            "root": str(root),
            "prefix": "manual",
            "extension": "tar.gz",
            "retain": 2,
            "create_archive": True,
            "prune_dirs": True,
        }
    )

    assert sorted(path.name for path in root.iterdir()) == [
        "manual-2.tar.gz",
        "manual-3.tar.gz",
        "manual-dir",
        "other-0.tar.gz",
    ]


def metube_restore(base: Path, live: dict[str, Path], archive: str) -> dict[str, Any]:
    return {
        "service": "metube",
        "label": "MeTube",
        "root": str(base / "backups/metube"),
        "archive": archive,
        "extension": "tar.gz",
        "staging": str(base / "staging"),
        "no_payload": "Could not locate payload directory",
        "cleanup": True,
        "restart": True,
        "stop_service": True,
        "unit": "metube",
        "enabled": True,
        "user": ME,
        "group": GID,
        "service_unit": str(live["unit"]),
        "state_dir": str(live["state"]),
        "env_dir": str(live["env"].parent),
        "env_file": str(live["env"]),
        "traefik_config_path": str(live["route"]),
        "route_guard": [],
    }


def test_metube_restore_keeps_a_pre_restore_copy_and_restores_every_piece(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "old")
    host().backup(metube_backup(tmp_path, live))
    metube_live(tmp_path, "new")
    stubs.write_text("")

    host().restore_metube(metube_restore(tmp_path, live, "latest"))

    assert (live["state"] / "queue.json").read_text() == "old"
    assert live["env"].read_text() == "ENV=old\n"
    assert live["env"].stat().st_mode & 0o777 == 0o644
    assert live["route"].read_text() == "route: old\n"
    (copy,) = live["state"].parent.glob("metube.pre-restore-*")
    assert (copy / "queue.json").read_text() == "new"
    assert calls(stubs) == [
        "systemctl stop metube",
        "systemctl daemon-reload",
        "systemctl reload traefik",
        "systemctl enable metube",
        "systemctl restart metube",
    ]
    assert not (tmp_path / "staging").exists()


def test_restore_without_archives_or_with_a_missing_one_fails_before_any_change(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "new")
    (tmp_path / "backups/metube").mkdir(parents=True)

    module = host()
    with pytest.raises(module.Failure, match="No MeTube backup archives found in"):
        module.restore_metube(metube_restore(tmp_path, live, "latest"))
    with pytest.raises(module.Failure, match=r"MeTube restore archive not found: .*/backups/metube/nope\.tar\.gz"):
        module.restore_metube(metube_restore(tmp_path, live, "nope.tar.gz"))

    assert calls(stubs) == []
    assert (live["state"] / "queue.json").read_text() == "new"


def test_restore_refuses_two_payload_directories_before_stopping(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "old")
    host().backup(metube_backup(tmp_path, live))
    (tmp_path / "staging/stale-payload").mkdir(parents=True)
    stubs.write_text("")

    module = host()
    with pytest.raises(module.Failure, match="More than one payload directory"):
        module.restore_metube(metube_restore(tmp_path, live, f"manual-{STAMP}.tar.gz"))

    assert calls(stubs) == []


def test_restore_refuses_a_payload_without_state(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "old")
    archive = tmp_path / "backups/metube/bare.tar.gz"
    (tmp_path / "bare/payload/config").mkdir(parents=True)
    archive.parent.mkdir(parents=True)
    with tarfile.open(archive, "w:gz") as packed:
        packed.add(tmp_path / "bare/payload", "payload")

    module = host()
    with pytest.raises(module.Failure, match="MeTube state directory missing inside archive"):
        module.restore_metube(metube_restore(tmp_path, live, "bare.tar.gz"))

    assert calls(stubs) == []


def jellyfin_live(base: Path, marker: str) -> dict[str, Path]:
    live = {
        "data": base / "var/lib/jellyfin",
        "config": base / "etc/jellyfin",
        "logs": base / "var/log/jellyfin",
        "unit": write(base / "lib/systemd/system/jellyfin.service", f"[Unit] {marker}\n"),
        "route": write(base / "etc/traefik/dynamic/jellyfin.yml", f"route: {marker}\n"),
    }
    write(live["data"] / "library.db", marker)
    write(live["config"] / "system.xml", marker)
    write(live["logs"] / "log.txt", marker)
    return live


def jellyfin_archive(base: Path, live: dict[str, Path]) -> None:
    root = base / "backups/jellyfin"
    directory = f"{root}/manual-{STAMP}"
    host().backup(
        {
            "service": "jellyfin",
            "label": "Jellyfin",
            "root": str(root),
            "dir": directory,
            "archive": f"{directory}.tar.gz",
            "owner": ME,
            "group": GID,
            "dir_mode": "0700",
            "file_mode": "0600",
            "stop": True,
            "unit": "jellyfin",
            "create_archive": True,
            "version": ["true"],
            "subdirs": ["data", "config", "systemd", "traefik", "logs"],
            "checks": [
                [str(live["data"]), True, "Data directory"],
                [str(live["config"]), True, "Config directory"],
                [str(live["unit"]), False, "Service unit"],
                [str(live["route"]), False, "Traefik config"],
                [str(live["logs"]), False, "Log directory"],
            ],
            "missing": "Required Jellyfin path missing: {path}",
            "copies": [
                ["tree", 0, str(live["data"]), "data", True],
                ["tree", 1, str(live["config"]), "config", True],
                ["file", 2, str(live["unit"]), "systemd/jellyfin.service", False],
                ["file", 3, str(live["route"]), "traefik/jellyfin.yml", False],
                ["tree", 4, str(live["logs"]), "logs", False],
            ],
            "generate_manifest": False,
            "manifest": [],
        }
    )


def test_jellyfin_restore_keeps_data_and_config_copies_and_tolerates_a_failed_traefik_reload(
    tmp_path: Path, stubs: Path
) -> None:
    live = jellyfin_live(tmp_path, "old")
    jellyfin_archive(tmp_path, live)
    jellyfin_live(tmp_path, "new")
    flag(tmp_path, "STUB_FAIL_RELOAD")
    stubs.write_text("")

    host().restore_jellyfin(
        {
            "service": "jellyfin",
            "label": "Jellyfin",
            "root": str(tmp_path / "backups/jellyfin"),
            "archive": "latest",
            "extension": "tar.gz",
            "staging": str(tmp_path / "staging"),
            "no_payload": "Unable to locate payload directory inside restore archive",
            "cleanup": True,
            "restart": True,
            "stop_service": True,
            "unit": "jellyfin",
            "user": ME,
            "group": GID,
            "service_unit": str(live["unit"]),
            "data_dir": str(live["data"]),
            "config_dir": str(live["config"]),
            "log_dir": str(live["logs"]),
            "traefik_config_path": str(live["route"]),
            "route_guard": [],
        }
    )

    assert (live["data"] / "library.db").read_text() == "old"
    assert (live["config"] / "system.xml").read_text() == "old"
    assert len(list(live["data"].parent.glob("jellyfin.pre-restore-*"))) == 1
    assert len(list(live["config"].parent.glob("jellyfin.pre-restore-*"))) == 1
    assert calls(stubs) == [
        "systemctl stop jellyfin",
        "systemctl daemon-reload",
        "systemctl daemon-reload",
        "systemctl enable jellyfin",
        "systemctl restart jellyfin",
        "systemctl reload traefik",
    ]


def navidrome_live(base: Path, marker: str) -> dict[str, Path]:
    live = {
        "data": base / "var/lib/navidrome",
        "cache": base / "var/lib/navidrome/cache",
        "logs": base / "var/log/navidrome",
        "config": write(base / "etc/navidrome.toml", f"config {marker}\n"),
        "unit": write(base / "etc/systemd/system/navidrome.service", f"[Unit] {marker}\n"),
        "route": write(base / "etc/traefik/dynamic/navidrome.yml", f"route: {marker}\n"),
    }
    write(live["data"] / "navidrome.db", marker)
    write(live["logs"] / "log.txt", marker)
    return live


def navidrome_archive(base: Path, live: dict[str, Path]) -> None:
    root = base / "backups/navidrome"
    directory = f"{root}/manual-{STAMP}"
    host().backup(
        {
            "service": "navidrome",
            "label": "Navidrome",
            "root": str(root),
            "dir": directory,
            "archive": f"{directory}.tar.gz",
            "owner": ME,
            "group": GID,
            "dir_mode": "0700",
            "file_mode": "0600",
            "stop": False,
            "unit": "navidrome",
            "create_archive": True,
            "version": ["true"],
            "subdirs": ["data", "config", "systemd", "traefik", "logs"],
            "checks": [
                [str(live["data"]), True, "Data directory"],
                [str(live["config"]), True, "Config file"],
                [str(live["unit"]), False, "Service unit"],
                [str(live["route"]), False, "Traefik config"],
                [str(live["logs"]), False, "Log directory"],
            ],
            "missing": "Required Navidrome path missing: {path}",
            "copies": [
                ["tree", 0, str(live["data"]), "data", True],
                ["file", 1, str(live["config"]), "config/navidrome.toml", False],
                ["file", 2, str(live["unit"]), "systemd/navidrome.service", False],
                ["file", 3, str(live["route"]), "traefik/navidrome.yml", False],
                ["tree", 4, str(live["logs"]), "logs", False],
            ],
            "generate_manifest": True,
            "manifest": [],
        }
    )


def navidrome_restore(base: Path, live: dict[str, Path]) -> dict[str, Any]:
    state = base / "var/lib/ops-deploy/navidrome"
    state.mkdir(parents=True, exist_ok=True)
    return {
        "service": "navidrome",
        "label": "Navidrome",
        "root": str(base / "backups/navidrome"),
        "archive": "latest",
        "extension": "tar.gz",
        "staging": str(base / "staging"),
        "no_payload": "Unable to locate payload directory inside restore archive",
        "cleanup": True,
        "restart": True,
        "unit": "navidrome",
        "user": ME,
        "group": GID,
        "data_dir": str(live["data"]),
        "cache_dir": str(live["cache"]),
        "log_dir": str(live["logs"]),
        "config_path": str(live["config"]),
        "service_unit": str(live["unit"]),
        "traefik_config_path": str(live["route"]),
        "state_root": str(state),
    }


@pytest.fixture
def navidrome_host(tmp_path: Path) -> Any:
    module = host()
    state = tmp_path / "var/lib/ops-deploy/navidrome"
    module.recovery_ancestors = lambda base: [str(tmp_path / "var"), str(tmp_path / "var/lib"), str(state.parent), base]
    return module


def test_navidrome_recovery_keeps_canonical_files_live_and_quarantines_archived_ones(
    tmp_path: Path, stubs: Path, navidrome_host: Any
) -> None:
    live = navidrome_live(tmp_path, "old")
    navidrome_archive(tmp_path, live)
    navidrome_live(tmp_path, "new")
    stubs.write_text("")

    navidrome_host.restore_navidrome(navidrome_restore(tmp_path, live))

    assert (live["data"] / "navidrome.db").read_text() == "old"
    for path in ("config", "unit", "route"):
        assert "new" in live[path].read_text()
    (attempt,) = (tmp_path / "var/lib/ops-deploy/navidrome/restored").iterdir()
    assert attempt.name.startswith("restore-")
    assert (tmp_path / "var/lib/ops-deploy/navidrome/restored").stat().st_mode & 0o777 == 0o700
    current = attempt / "current"
    assert sorted(path.name for path in current.iterdir()) == ["navidrome.service", "navidrome.toml", "navidrome.yml"]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in current.iterdir())
    assert (current / "navidrome.toml").read_text() == "config new\n"
    assert (attempt / "archived/config/navidrome.toml").read_text() == "config old\n"
    assert (attempt / "archived/systemd/navidrome.service").read_text() == "[Unit] old\n"
    assert (attempt / "archived/traefik/navidrome.yml").read_text() == "route: old\n"
    assert calls(stubs) == [
        "systemctl stop navidrome",
        "systemctl daemon-reload",
        "systemctl daemon-reload",
        "systemctl enable navidrome",
        "systemctl restart navidrome",
    ]
    assert not (tmp_path / "staging").exists()


@pytest.mark.parametrize(
    "conflict", ["pending", "restart", "staging", "unsafe-parent", "linked-config", "writable-route"]
)
def test_navidrome_recovery_refuses_before_any_capture(
    tmp_path: Path, stubs: Path, navidrome_host: Any, conflict: str
) -> None:
    live = navidrome_live(tmp_path, "old")
    navidrome_archive(tmp_path, live)
    cfg = navidrome_restore(tmp_path, live)
    state = Path(cfg["state_root"])
    if conflict in ("pending", "restart"):
        (state / conflict).write_text("")
    elif conflict == "staging":
        (tmp_path / "staging").mkdir()
    elif conflict == "unsafe-parent":
        (state / "restored").mkdir(mode=0o755)
        (state / "restored").chmod(0o755)
    elif conflict == "linked-config":
        target = write(tmp_path / "elsewhere.toml", "x")
        live["config"].unlink()
        live["config"].symlink_to(target)
    else:
        live["route"].chmod(0o666)
    stubs.write_text("")

    with pytest.raises(navidrome_host.Failure):
        navidrome_host.restore_navidrome(cfg)

    assert calls(stubs) == []
    restored = state / "restored"
    assert not restored.exists() or not any(restored.iterdir())
    assert (live["data"] / "navidrome.db").read_text() == "old"


def test_the_encoded_program_runs_through_bash_with_the_payload_on_stdin(tmp_path: Path) -> None:
    root = tmp_path / "root"
    for index in range(3):
        path = write(root / f"manual-{index}.tar.gz", "x")
        os.utime(path, (1000 + index, 1000 + index))
    payload = {"root": str(root), "prefix": "manual", "extension": "tar.gz", "retain": 1, "create_archive": True}
    payload["prune_dirs"] = True

    result = subprocess.run(
        ["bash", "-c", media_lifecycle._command("retain")],
        input=json.dumps(payload) + "\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in root.iterdir()) == ["manual-2.tar.gz"]


def test_a_failing_step_exits_non_zero_with_the_roles_message(tmp_path: Path) -> None:
    payload = {
        "service": "metube",
        "label": "MeTube",
        "root": str(tmp_path),
        "archive": "latest",
        "extension": "tar.gz",
    }

    result = subprocess.run(
        ["bash", "-c", media_lifecycle._command("restore-metube")],
        input=json.dumps(payload) + "\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert f"metube restore-metube: No MeTube backup archives found in {tmp_path}" in result.stderr


def test_without_archives_navidrome_prunes_no_directories_but_metube_does(tmp_path: Path) -> None:
    root = tmp_path / "root"
    for index in range(3):
        (root / f"manual-{index}").mkdir(parents=True)
        os.utime(root / f"manual-{index}", (1000 + index, 1000 + index))
    cfg = {"root": str(root), "prefix": "manual", "extension": "tar.gz", "retain": 1, "create_archive": False}

    host().retain({**cfg, "prune_dirs": False})
    assert len(list(root.iterdir())) == 3
    host().retain({**cfg, "prune_dirs": True})
    assert [path.name for path in root.iterdir()] == ["manual-2"]


def test_a_stopped_traefik_is_started_and_a_held_route_lock_stops_before_the_route(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "old")
    host().backup(metube_backup(tmp_path, live))
    metube_live(tmp_path, "new")
    flag(tmp_path, "STUB_ACTIVE", "inactive")
    stubs.write_text("")

    host().restore_metube(metube_restore(tmp_path, live, "latest"))

    assert "systemctl start traefik" in calls(stubs)
    assert "systemctl reload traefik" not in calls(stubs)

    metube_live(tmp_path, "newer")
    cfg = metube_restore(tmp_path, live, "latest")
    cfg["route_guard"] = ["false"]
    module = host()
    with pytest.raises(module.subprocess.CalledProcessError):
        module.restore_metube(cfg)
    assert live["route"].read_text() == "route: newer\n"


def test_stop_follows_the_systemd_module(tmp_path: Path, stubs: Path) -> None:
    module = host()
    for active, stopped in (("active", True), ("deactivating", True), ("reloading", False), ("inactive", False)):
        flag(tmp_path, "STUB_ACTIVE", active)
        assert module.stop("metube") is stopped
    flag(tmp_path, "STUB_LOAD", "not-found")
    with pytest.raises(module.Failure, match="Could not find the requested service metube"):
        module.stop("metube")
    assert calls(stubs) == ["systemctl stop metube", "systemctl stop metube"]


def test_created_parents_take_the_owner_and_mode_and_matching_ones_are_left_alone(tmp_path: Path) -> None:
    module = host()
    target = tmp_path / "a" / "b" / "c"

    module.ensure_dir(str(target), ME, GID, "0750")

    assert [(tmp_path / p).stat().st_mode & 0o777 for p in ("a", "a/b", "a/b/c")] == [0o750] * 3
    before = target.stat().st_ctime_ns
    time.sleep(0.01)
    module.ensure_dir(str(target), ME, GID, "0750")
    assert target.stat().st_ctime_ns == before


def test_an_unreadable_unit_is_never_taken_as_stopped(tmp_path: Path, stubs: Path) -> None:
    module = host()
    flag(tmp_path, "STUB_FAIL_SHOW")

    with pytest.raises(module.Failure, match="Service is in unknown state: jellyfin"):
        module.stop("jellyfin")
    module.reload_traefik()  # tolerated, as the role's failed_when: false

    assert calls(stubs) == []


def test_a_failed_stop_keeps_its_message_when_the_start_fails_too(tmp_path: Path, stubs: Path) -> None:
    live = metube_live(tmp_path, "one")
    flag(tmp_path, "STUB_LOAD", "not-found")
    flag(tmp_path, "STUB_FAIL_START")
    module = host()

    with pytest.raises(module.Failure, match="Could not find the requested service metube"):
        module.backup(metube_backup(tmp_path, live))

    assert calls(stubs)[-1] == "systemctl start metube"
