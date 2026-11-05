"""Mastodon backup and restore: planned operations and the host scripts against fake PostgreSQL tools.

The script tests run the planned scripts with bash in a temporary tree. The
PostgreSQL tools, ``systemctl`` and ``bundle`` are recording stand-ins on
``PATH``: a "database" is a file ``<name>.db`` below ``$PGDATA_DIR``, a dump is
``PGDMP`` plus that file's content. Nothing here reads a real secret.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mastodon import (
    MastodonBackupConfig,
    MastodonRestoreConfig,
    backup_restore,
    deploy_mastodon_backup,
    deploy_mastodon_restore,
)
from ops_deploy.services.mastodon.backup_restore import FILES, manifest
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.lifecycle_scripts import assignments, calls, repack, run_script

SHARED = Path(__file__).parent / "parity/mastodon/remove/shared-defaults.yml"
STAMP = "20261104T120000"
LATER = "20261104T130000"
# A fixture password with the characters the passfile escapes.
PASSWORD = "fixture:pass\\word"
SECRETS = SecretValues(SecretRef("secrets/staging/mastodon.yml"), {"postgres_password": PASSWORD})
SERVICES = ["mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx"]


def responses(stamp: str = STAMP) -> dict[str, Any]:
    return {"date +%Y%m%dT%H%M%S": [stamp], **fakehost.LINUX}


def body(result: FakeRun) -> tuple[str, str]:
    """The bash script of the ``secret_stdin`` operation and the stdin it got."""

    ((command, stdin),) = result.stdin
    assert command in result.executed_commands
    assert command.startswith("bash -c ")
    return shlex.split(command)[2], stdin


def backup(cfg: MastodonBackupConfig, secrets: SecretValues | None = SECRETS, stamp: str = STAMP) -> FakeRun:
    return run_deploy_fake(deploy_mastodon_backup, cfg, secrets, responses=responses(stamp))


def restore(cfg: MastodonRestoreConfig, secrets: SecretValues | None = SECRETS) -> FakeRun:
    return run_deploy_fake(deploy_mastodon_restore, cfg, secrets, responses=fakehost.LINUX)


# -- defaults and validation ------------------------------------------------------


def test_defaults_are_the_shared_roles() -> None:
    shared = yaml.safe_load(SHARED.read_text())
    b = MastodonBackupConfig()
    r = MastodonRestoreConfig()
    assert b.root == r.root == shared["mastodon_backup_root"] == "/opt/backups/mastodon"
    assert b.prefix == shared["mastodon_backup_prefix"]
    assert b.retain == shared["mastodon_backup_retain"]
    assert b.retain_all_prefixes is shared["mastodon_backup_retain_all_prefixes"]
    assert b.media_rsync_excludes == tuple(shared["mastodon_backup_media_rsync_excludes"])
    assert (b.dir_mode, b.file_mode) == (shared["mastodon_backup_dir_mode"], shared["mastodon_backup_file_mode"])
    assert (b.backup_owner, b.backup_group) == (shared["mastodon_backup_owner"], shared["mastodon_backup_group"])
    assert b.postgres_compress == shared["mastodon_backup_postgres_compress"]
    assert b.postgres_format == shared["mastodon_backup_postgres_format"]
    for flag in ("stop_services", "include_media", "include_env", "include_systemd", "include_traefik"):
        assert getattr(b, flag) is shared[f"mastodon_backup_{flag}"]
    assert b.include_nginx is shared["mastodon_backup_include_nginx"]
    assert b.generate_manifest is shared["mastodon_backup_generate_manifest"]
    assert b.use_delete is shared["mastodon_backup_use_delete"]
    assert b.create_archive is shared["mastodon_backup_create_archive"]
    assert b.fetch_local is shared["mastodon_backup_fetch_local"]
    assert r.archive == shared["mastodon_restore_archive"]
    assert r.staging_dir == shared["mastodon_restore_staging_dir"]
    for flag in ("cleanup", "restart", "stop_services", "run_migrations"):
        assert getattr(r, flag) is shared[f"mastodon_restore_{flag}"]
    # The empty-media guard is on by default.
    assert r.empty_media_confirmed is False
    assert r.postgres_become_user == shared["mastodon_postgres_become_user"] == "postgres"
    assert (r.postgres_host, r.postgres_port) == (shared["mastodon_postgres_host"], shared["mastodon_postgres_port"])
    assert r.postgres_database == shared["mastodon_postgres_database"]
    assert r.postgres_user == shared["mastodon_postgres_user"]
    # mastodon_restore's own defaults.
    assert r.safety_root == "/var/backups/mastodon-pre-restore"
    assert r.media_safety == "/home/mastodon/media-pre-restore"
    assert r.rbenv == shared["mastodon_rbenv_root"].replace("{{ mastodon_home_path }}", "/home/mastodon")
    assert list(r.services) == SERVICES
    assert r.systemd_unit_dir == shared["mastodon_systemd_unit_dir"]


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_restore_defaults_are_the_role_file() -> None:
    role = Path(os.environ["OPS_LIBRARY_PATH"], "roles/mastodon_restore/defaults/main.yml")
    defaults = yaml.safe_load(role.read_text())
    r = MastodonRestoreConfig()
    assert defaults["mastodon_restore_safety_root"] == r.safety_root
    assert defaults["mastodon_restore_media_safety_root"] == "{{ mastodon_home_path }}/media-pre-restore"
    assert defaults["mastodon_restore_postgres_dump_binary"] == r.postgres_dump_binary
    assert defaults["mastodon_restore_postgres_psql_binary"] == r.postgres_psql_binary
    assert defaults["mastodon_restore_empty_media_confirmed"] is r.empty_media_confirmed


def test_connection_flags_follow_the_role() -> None:
    r = MastodonRestoreConfig()
    assert r.conn_args() == ("--host=localhost", "--port=5432", "--username=mastodon")
    assert r.admin_args() == ("--port=5432",)
    remote = MastodonRestoreConfig(postgres_host="db.internal", postgres_port=None)
    assert remote.conn_args() == ("--host=db.internal", "--username=mastodon")
    assert remote.admin_args() == ("--host=db.internal",)


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/opt/backups/mastodon/a.tar.gz", "a b.tar.gz", "x.tar.zst"])
def test_restore_archive_must_be_a_name_below_the_root(archive: str) -> None:
    with pytest.raises(ValidationError):
        MastodonRestoreConfig(archive=archive)


@pytest.mark.parametrize(
    "values",
    [
        {"staging_dir": "/opt/backups"},
        {"staging_dir": "/opt/backups/mastodon"},
        {"staging_dir": "/home/mastodon/live/tmp"},
        {"staging_dir": "/var/backups"},
        {"staging_dir": "/etc/systemd/system/x"},
        {"staging_dir": "/home"},
        {"media_safety_root": "/home/mastodon/live/public/system/pre"},
        {"media_safety_root": "/home/mastodon/live/public"},
        {"staging_dir": "/var/tmp/x/../y"},
    ],
)
def test_restore_paths_that_overlap_are_refused(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        MastodonRestoreConfig.model_validate(values)


def test_backup_root_must_lie_apart_from_the_site() -> None:
    with pytest.raises(ValidationError):
        MastodonBackupConfig(root="/home/mastodon/live/backups")


# -- planned operations -----------------------------------------------------------


def test_backup_plans_one_script_with_the_password_on_stdin(tmp_path: Path) -> None:
    cfg = MastodonBackupConfig(local_dir=tmp_path / "local")

    result = backup(cfg)

    assert result.succeeded, result.error
    script, stdin = body(result)
    assert stdin == f"{PASSWORD}\n"
    assert PASSWORD not in result.all_text()
    values = assignments(script)
    assert values["DIR"] == f"/opt/backups/mastodon/manual-{STAMP}"
    assert values["DUMP"] == f"/opt/backups/mastodon/manual-{STAMP}/database/mastodon.dump"
    assert values["PG_BECOME"] == "root"
    assert values["SERVICES"] == "(mastodon-web mastodon-sidekiq mastodon-streaming mastodon-nginx)"
    assert values["EXCLUDES"] == "('/cache/***')"
    assert result.changed_ops == [
        f"Mastodon backup | Back up Mastodon into /opt/backups/mastodon/manual-{STAMP}",
        f"Mastodon backup | Ensure {tmp_path / 'local'} (0700)",
        "Mastodon backup | Fetch the backup archive",
        "Mastodon backup | Restrict the local archive copy (0600)",
        "Mastodon backup | Keep the newest 7 Mastodon backups",
    ]
    prune = result.executed_commands[-1]
    assert assignments(prune)["GLOB"] == "manual-*"
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700


def test_backup_retain_all_prefixes_and_no_pruning() -> None:
    every = backup(MastodonBackupConfig(fetch_local=False, retain_all_prefixes=True, prefix="pre-upgrade"))
    assert every.succeeded, every.error
    assert assignments(every.executed_commands[-1])["GLOB"] == "*"
    kept = backup(MastodonBackupConfig(fetch_local=False, retain=0))
    assert kept.succeeded, kept.error
    assert len(kept.executed_commands) == 1


def test_backup_without_secrets_sends_an_empty_line() -> None:
    result = backup(MastodonBackupConfig(fetch_local=False), secrets=None)

    assert result.succeeded, result.error
    assert body(result)[1] == "\n"


@pytest.mark.parametrize("action", ["backup", "restore"])
def test_password_with_a_line_break_is_refused(action: str) -> None:
    broken = SecretValues(SecretRef("secrets/staging/mastodon.yml"), {"postgres_password": "a\nb"})

    if action == "backup":
        result = backup(MastodonBackupConfig(fetch_local=False), secrets=broken)
    else:
        result = restore(MastodonRestoreConfig(), secrets=broken)

    assert "cannot contain line breaks" in str(result.error)
    assert result.executed_commands == []


def test_manifest_matches_the_role_content() -> None:
    cfg = MastodonBackupConfig()

    text = manifest(cfg, stamp=STAMP, version="")

    assert text.splitlines()[5] == 'media_rsync_excludes: ["/cache/***"]'
    assert yaml.safe_load(text) == {
        "version": "",
        "timestamp": STAMP,
        "archive": f"manual-{STAMP}.tar.gz",
        "database_dump": "mastodon.dump",
        "media_root": "/home/mastodon/live/public/system",
        "media_rsync_excludes": ["/cache/***"],
        "env_file": "/home/mastodon/live/.env.production",
        "traefik_config": "/etc/traefik/dynamic/mastodon.yml",
        "nginx_config": "/etc/mastodon/nginx.conf",
    }


def test_restore_plans_one_labelled_script() -> None:
    result = restore(MastodonRestoreConfig(archive="manual-1.tar.gz"))

    assert result.succeeded, result.error
    script, stdin = body(result)
    assert stdin == f"{PASSWORD}\n"
    assert PASSWORD not in result.all_text()
    values = assignments(script)
    assert values["ARCHIVE"] == "manual-1.tar.gz"
    assert values["CONN_ARGS"] == "(--host=localhost --port=5432 --username=mastodon)"
    assert values["ADMIN_ARGS"] == "(--port=5432)"
    assert values["SAFETY_DIR"].startswith("/var/backups/mastodon-pre-restore/2")
    assert values["SAFETY_DIR"].endswith("Z")
    assert values["MEDIA_SAFETY"] == "/home/mastodon/media-pre-restore/" + values["SAFETY_DIR"].rsplit("/", 1)[1]
    assert values["PG_BECOME"] == "postgres"
    assert values["EMPTY_MEDIA_CONFIRMED"] == "0"
    assert result.changed_ops == ["Mastodon restore | Restore Mastodon", "Mastodon restore | Show the restore report"]
    assert result.function_calls == ["report"]
    dry = restore(MastodonRestoreConfig(dry_run=True))
    assert dry.changed_ops == [
        "Mastodon restore | Restore Mastodon (dry run)",
        "Mastodon restore | Show the restore report",
    ]


def test_the_restore_report_is_logged_without_verbosity(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # pyinfra prints a command's output only at -vvv; the report logs it at INFO.
    class Done:
        stdout_lines = (
            "Restore archive: /opt/backups/mastodon/manual-1.tar.gz",
            "Components: database=yes, media=EMPTY",
        )

    monkeypatch.setattr(backup_restore, "host", SimpleNamespace(print_prefix="[staging] "))
    with caplog.at_level(logging.INFO, logger="pyinfra"):
        backup_restore.report(Done())  # type: ignore[arg-type]

    assert [r.getMessage() for r in caplog.records if r.name == "pyinfra" and r.levelno == logging.INFO] == [
        "[staging] Restore archive: /opt/backups/mastodon/manual-1.tar.gz",
        "[staging] Components: database=yes, media=EMPTY",
    ]


# -- the host scripts ---------------------------------------------------------------

GNUBIN = Path("/opt/homebrew/opt/coreutils/libexec/gnubin")
PATH = f"{GNUBIN}:{os.environ['PATH']}" if GNUBIN.is_dir() else os.environ["PATH"]


def _tools() -> bool:
    if shutil.which("rsync", path=PATH) is None:
        return False
    probe = subprocess.run(
        ["bash", "-c", "stat -c %Y . && printf 'a\\0' | tail -z -n +1 && cp --version"],
        capture_output=True,
        env={"PATH": PATH},
    )
    return probe.returncode == 0


needs_tools = pytest.mark.skipif(not _tools(), reason="needs GNU stat, tail, cp and rsync, as on the Linux targets")

FAKE_TOOL = r"""#!/usr/bin/env bash
set -euo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "$*" >>"$LOG"
if [ -n "${PGPASSFILE:-}" ]; then
    printf '%s\n' "$PGPASSFILE" >>"$LOG.passfiles"
    cat "$PGPASSFILE" >>"$LOG.pgpass"
fi
args=("$@")
db="" file="" list=0
for ((i = 0; i < ${#args[@]}; i++)); do
    case ${args[i]} in
        --dbname=*) db=${args[i]#--dbname=} ;;
        --file=*) file=${args[i]#--file=} ;;
        --file) file=${args[i + 1]}; i=$((i + 1)) ;;
        --list) list=1 ;;
        --*) ;;
        *) last=${args[i]} ;;
    esac
done
valid() { [ "$(head -n 1 "$1")" = PGDMP ]; }
case $name in
    pg_dump)
        [ -z "${PG_DUMP_FAILS:-}" ] || exit 1
        [ -n "$db" ] || db=$last
        [ -e "$PGDATA_DIR/$db.db" ] || { echo "pg_dump: database \"$db\" does not exist" >&2; exit 1; }
        { echo PGDMP; cat "$PGDATA_DIR/$db.db"; } >"$file"
        ;;
    pg_restore)
        dump=$last
        valid "$dump" || { echo "pg_restore: input file does not appear to be a valid archive" >&2; exit 1; }
        if [ "$list" = 1 ]; then
            echo ";"
            [ -n "${NO_TABLE_DATA:-}" ] || echo "4123; 0 16385 TABLE DATA public statuses mastodon"
        elif [ -n "$db" ]; then
            if [ -n "${PG_RESTORE_FAILS_FOR:-}" ] && [[ $dump == *"$PG_RESTORE_FAILS_FOR"* ]]; then
                [ -z "${ACTIVE_AFTER_FAILURE:-}" ] || echo active >"$LOG.state"
                echo "pg_restore: error: could not execute query" >&2
                exit 1
            fi
            tail -n +2 "$dump" >"$PGDATA_DIR/$db.db"
        fi
        ;;
    psql)
        if [ -n "${PSQL_FAILS:-}" ]; then echo "psql: error: connection refused" >&2; exit 2; fi
        [ -e "$PGDATA_DIR/$db.db" ] || { echo "psql: error: FATAL:  database \"$db\" does not exist" >&2; exit 2; }
        echo 1
        ;;
    dropdb) rm -f "$PGDATA_DIR/$last.db" ;;
    createdb)
        [ ! -e "$PGDATA_DIR/$last.db" ] || { echo "createdb: database exists" >&2; exit 1; }
        : >"$PGDATA_DIR/$last.db"
        ;;
    systemctl) ;;
    bundle) [ -z "${MIGRATE_FAILS:-}" ] || exit 1 ;;
esac
"""

# The parent shell's systemctl and runuser (child bash processes use the PATH stand-ins).
STUBS = r"""
runuser() { printf 'runuser %s\n' "$*" >>"$LOG"; shift 3; "$@"; }
systemctl() {
    printf 'systemctl %s\n' "$*" >>"$LOG"
    case $1 in
        stop) [ -z "${SYSTEMCTL_STOP_FAILS:-}" ] ;;
        is-active) if [ -e "$LOG.state" ]; then cat "$LOG.state"; else printf 'inactive\n'; fi ;;
        show) printf 'loaded\n' ;;
        *) return 0 ;;
    esac
}
"""


def tools(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name in ("pg_dump", "pg_restore", "psql", "dropdb", "createdb", "systemctl"):
        path = bin_dir / name
        path.write_text(FAKE_TOOL)
        path.chmod(0o755)
    return bin_dir


def make_site(p: dict[str, Path], marker: str) -> None:
    media = p["site"] / "public" / "system"
    for sub in ("accounts/avatars", "cache/remote"):
        (media / sub).mkdir(parents=True, exist_ok=True)
    (media / "accounts" / "avatars" / "me.png").write_text(f"{marker}\n")
    (media / "cache" / "remote" / "x.png").write_text(f"{marker}\n")
    (p["site"] / ".env.production").write_text(f"MARKER={marker}\n")
    (p["pgdata"] / "mastodon.db").write_text(f"rows {marker}\n")


def tree(tmp_path: Path) -> dict[str, Path]:
    names = ("site", "etc", "units", "backups", "staging", "safety", "msafety", "pgdata", "rbenv", "home")
    p = {name: tmp_path / name for name in names}
    for name in ("etc", "units", "pgdata", "home"):
        p[name].mkdir()
    (p["rbenv"] / "bin").mkdir(parents=True)
    bundle = p["rbenv"] / "bin" / "bundle"
    bundle.write_text(FAKE_TOOL)
    bundle.chmod(0o755)
    make_site(p, "original")
    for name in SERVICES:
        (p["units"] / f"{name}.service").write_text(f"[Service]\n# {name}\n")
    (p["etc"] / "mastodon.yml").write_text("http: {}\n")
    (p["etc"] / "nginx.conf").write_text("events {}\n")
    return p


def site(p: dict[str, Path]) -> dict[str, Any]:
    return {
        "site_path": str(p["site"]),
        "env_file": str(p["site"] / ".env.production"),
        "media_path": str(p["site"] / "public" / "system"),
        "systemd_units": tuple(str(p["units"] / f"{name}.service") for name in SERVICES),
        "traefik_config_path": str(p["etc"] / "mastodon.yml"),
        "nginx_config_path": str(p["etc"] / "nginx.conf"),
    }


def env(p: dict[str, Path], tmp_path: Path, **extra: str) -> dict[str, str]:
    return {"PATH": f"{tools(tmp_path)}:{PATH}", "PGDATA_DIR": str(p["pgdata"]), **extra}


def take_backup(p: dict[str, Path], tmp_path: Path, *, stamp: str = STAMP, **extra: Any) -> Path:
    cfg = MastodonBackupConfig(root=str(p["backups"]), fetch_local=False, retain=0, **site(p), **extra)
    result = backup(cfg, stamp=stamp)
    assert result.succeeded, result.error
    script, stdin = body(result)
    done = run_script(script, FILES / "backup.sh", tmp_path, stubs=STUBS, stdin=stdin, **env(p, tmp_path))
    assert done.returncode == 0, done.stderr
    return p["backups"] / f"manual-{stamp}"


def restore_script(p: dict[str, Path], **extra: Any) -> tuple[str, str]:
    cfg = MastodonRestoreConfig(
        root=str(p["backups"]),
        staging_dir=str(p["staging"]),
        safety_root=str(p["safety"]),
        media_safety_root=str(p["msafety"]),
        systemd_unit_dir=str(p["units"]),
        home_path=str(p["home"]),
        rbenv_root=str(p["rbenv"]),
        **site(p),
        **extra,
    )
    return body(restore(cfg))


def run_restore(p: dict[str, Path], tmp_path: Path, *, stubs: str = "", env_extra: Any = None, **extra: Any) -> Any:
    script, stdin = restore_script(p, **extra)
    (tmp_path / "calls.log").unlink(missing_ok=True)
    return run_script(
        script,
        FILES / "restore.sh",
        tmp_path,
        stubs=STUBS + stubs,
        stdin=stdin,
        **env(p, tmp_path, **(env_extra or {})),
    )


def events(tmp_path: Path) -> list[str]:
    """The recorded calls without the ``runuser`` wrappers (their commands are recorded too)."""

    return [line for line in calls(tmp_path) if not line.startswith("runuser ")]


def media(p: dict[str, Path]) -> Path:
    return p["site"] / "public" / "system"


def live_files(p: dict[str, Path]) -> dict[str, str]:
    """The live media's files (relative path: content)."""

    return {path.relative_to(media(p)).as_posix(): path.read_text() for path in media(p).rglob("*") if path.is_file()}


def safety_dirs(p: dict[str, Path]) -> list[Path]:
    return sorted(p["safety"].iterdir()) if p["safety"].exists() else []


@needs_tools
def test_backup_script_writes_the_role_layout(tmp_path: Path) -> None:
    p = tree(tmp_path)
    (p["backups"]).mkdir()
    old = p["backups"] / "old.tar.gz"
    old.write_text("x")
    old.chmod(0o644)

    directory = take_backup(p, tmp_path)

    assert (directory / "database" / "mastodon.dump").read_text() == "PGDMP\nrows original\n"
    assert (directory / "media" / "accounts" / "avatars" / "me.png").exists()
    assert not (directory / "media" / "cache" / "remote").exists()
    assert (directory / "config" / "mastodon.env").read_text() == "MARKER=original\n"
    assert sorted(path.name for path in (directory / "systemd").iterdir()) == sorted(f"{s}.service" for s in SERVICES)
    assert (directory / "traefik" / "mastodon.yml").read_text() == "http: {}\n"
    assert (directory / "nginx" / "nginx.conf").read_text() == "events {}\n"
    meta = yaml.safe_load((directory / "manifest.yml").read_text())
    assert meta["timestamp"] == STAMP
    assert meta["version"] == ""  # no VERSION file: the role's empty stdout
    assert not (directory / "manifest.yml.new").exists()
    archive = p["backups"] / f"manual-{STAMP}.tar.gz"
    assert archive.stat().st_mode & 0o777 == 0o600
    assert old.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as tar:
        assert {name.split("/")[0] for name in tar.getnames()} == {f"manual-{STAMP}"}
    log = events(tmp_path)
    stops = [f"systemctl stop {s}" for s in SERVICES]
    starts = [f"systemctl start {s}" for s in SERVICES]
    assert log[:4] == stops
    assert log[4].startswith("pg_dump --host=localhost --port=5432 --username=mastodon --format=custom --compress=9")
    assert log[5:] == ["systemctl daemon-reload", *starts]
    # The password went through a private passfile only, removed afterwards.
    assert (tmp_path / "calls.log.pgpass").read_text() == "*:*:*:*:fixture\\:pass\\\\word\n"
    (passfile,) = (tmp_path / "calls.log.passfiles").read_text().split()
    assert "/mastodon_backup-pgpass-" in passfile
    assert not Path(passfile).exists()


@needs_tools
def test_backup_script_reads_the_version_file(tmp_path: Path) -> None:
    p = tree(tmp_path)
    (p["site"] / "VERSION").write_text(" 4.7.4\n")

    directory = take_backup(p, tmp_path)

    assert yaml.safe_load((directory / "manifest.yml").read_text())["version"] == "4.7.4"


@needs_tools
@pytest.mark.parametrize("failure", ["dump", "env"])
def test_backup_script_starts_the_services_again_after_a_failure(tmp_path: Path, failure: str) -> None:
    p = tree(tmp_path)
    if failure == "env":
        (p["site"] / ".env.production").unlink()
    cfg = MastodonBackupConfig(root=str(p["backups"]), fetch_local=False, retain=0, **site(p))
    script, stdin = body(backup(cfg))

    extra = {"PG_DUMP_FAILS": "1"} if failure == "dump" else {}
    done = run_script(script, FILES / "backup.sh", tmp_path, stubs=STUBS, stdin=stdin, **env(p, tmp_path, **extra))

    assert done.returncode != 0
    log = events(tmp_path)
    assert log[-5:] == ["systemctl daemon-reload", *(f"systemctl start {s}" for s in SERVICES)]
    assert not (p["backups"] / f"manual-{STAMP}.tar.gz").exists()


@needs_tools
def test_backup_script_without_stopping_or_media(tmp_path: Path) -> None:
    p = tree(tmp_path)

    directory = take_backup(p, tmp_path, stop_services=False, include_media=False, storage_driver="local")

    assert list((directory / "media").iterdir()) == []
    assert not any(line.startswith("systemctl") for line in events(tmp_path))


def prune_command(root: Path, **extra: Any) -> str:
    cfg = MastodonBackupConfig(root=str(root), fetch_local=False, **extra)
    result = backup(cfg)
    assert result.succeeded, result.error
    return result.executed_commands[-1]


@needs_tools
@pytest.mark.parametrize("all_prefixes", [False, True])
def test_prune_script_keeps_the_newest_by_mtime(tmp_path: Path, all_prefixes: bool) -> None:
    root = tmp_path / "backups"
    root.mkdir()
    names = ["manual-1", "manual-2", "manual-3", "pre-upgrade-1", ".hidden"]
    for age, name in enumerate(names):
        (root / name).mkdir()
        (root / f"{name}.tar.gz").write_text("x")
        for path in (root / name, root / f"{name}.tar.gz"):
            os.utime(path, (1_000_000_000 - age * 100, 1_000_000_000 - age * 100))

    command = prune_command(root, retain=2, retain_all_prefixes=all_prefixes)
    done = run_script(command, FILES / "prune.sh", tmp_path, PATH=PATH)

    assert done.returncode == 0, done.stderr
    left = sorted(path.name for path in root.iterdir())
    if all_prefixes:
        kept = [".hidden", "manual-1", "manual-2"]
        assert left == sorted([*kept, *(f"{name}.tar.gz" for name in kept)])
    else:
        expected = ["manual-1", "manual-2", "pre-upgrade-1", ".hidden"]
        assert left == sorted([*expected, *(f"{name}.tar.gz" for name in expected)])


@needs_tools
def test_restore_script_puts_the_backup_back_with_safety_copies(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")
    (media(p) / "accounts" / "new.png").write_text("new\n")
    (p["units"] / "mastodon-web.service").write_text("[Service]\n# changed\n")

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows original\n"
    assert not (media(p) / "accounts" / "new.png").exists()
    assert (media(p) / "accounts" / "avatars" / "me.png").read_text() == "original\n"
    # The backup left the cache out; the restore keeps the live one.
    assert (media(p) / "cache" / "remote" / "x.png").read_text() == "changed\n"
    assert "Media excludes: /cache/*** (from the archive's manifest.yml);" in done.stdout
    assert (p["site"] / ".env.production").read_text() == "MARKER=original\n"
    assert (p["units"] / "mastodon-web.service").read_text() == "[Service]\n# mastodon-web\n"
    (safety,) = safety_dirs(p)
    assert (safety / "database" / "mastodon.dump").read_text() == "PGDMP\nrows changed\n"
    assert (p["msafety"] / safety.name / "accounts" / "new.png").read_text() == "new\n"
    assert (p["msafety"] / safety.name / "accounts" / "avatars" / "me.png").read_text() == "changed\n"
    copies = safety / "files"
    assert (copies / str(p["site"] / ".env.production").lstrip("/")).read_text() == "MARKER=changed\n"
    assert len((safety / "files.manifest").read_text().splitlines()) == 3 + len(SERVICES)
    assert not p["staging"].exists()
    log = events(tmp_path)
    stops = [f"systemctl stop {s}" for s in SERVICES]
    assert log.index("systemctl stop mastodon-web") < min(i for i, line in enumerate(log) if line.startswith("dropdb"))
    assert all(line in log for line in stops)
    db = [line.split()[0] for line in log if line.split()[0] in ("psql", "pg_dump", "dropdb", "createdb")]
    assert db == ["psql", "pg_dump", "dropdb", "createdb"]
    assert any(line.startswith("bundle exec rails db:migrate") for line in log)
    assert log[-3:] == [
        "systemctl daemon-reload",
        "systemctl enable mastodon-nginx",
        "systemctl restart mastodon-nginx",
    ]
    assert "Pre-restore database dump:" in done.stdout
    for passfile in (tmp_path / "calls.log.passfiles").read_text().split():
        assert not Path(passfile).exists()


@needs_tools
def test_restore_script_dry_run_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")

    done = run_restore(p, tmp_path, dry_run=True)

    assert done.returncode == 0, done.stderr
    assert "Dry run" in done.stdout
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    log = events(tmp_path)
    assert [line for line in log if line.startswith("pg_restore")] == [
        f"pg_restore --list {p['staging']}/manual-{STAMP}/database/mastodon.dump",
        f"pg_restore --file=/dev/null {p['staging']}/manual-{STAMP}/database/mastodon.dump",
    ]
    assert not any(line.startswith(("systemctl", "psql", "pg_dump", "dropdb", "createdb")) for line in log)
    assert safety_dirs(p) == []
    assert not p["staging"].exists()


def empty_media_backup(p: dict[str, Path], tmp_path: Path, *, skeleton: bool = False) -> Path:
    """A backup taken without media (its media/ is empty), the live media changed afterwards."""

    directory = take_backup(p, tmp_path, include_media=False)
    if skeleton:
        # Directories only still hold no media file.
        (directory / "media" / "accounts" / "avatars").mkdir(parents=True)
        repack(directory)
    make_site(p, "changed")
    return directory


@needs_tools
@pytest.mark.parametrize("skeleton", [False, True])
def test_restore_script_refuses_an_empty_media_archive_before_anything_stops(tmp_path: Path, skeleton: bool) -> None:
    p = tree(tmp_path)
    empty_media_backup(p, tmp_path, skeleton=skeleton)

    done = run_restore(p, tmp_path)

    assert done.returncode != 0
    assert "refused before anything was stopped or changed" in done.stderr
    assert "MASTODON_RESTORE_EMPTY_MEDIA_CONFIRMED=true" in done.stderr
    assert "media=EMPTY" in done.stdout
    assert not any(line.startswith(("systemctl", "psql", "pg_dump", "dropdb", "createdb")) for line in events(tmp_path))
    assert (media(p) / "accounts" / "avatars" / "me.png").read_text() == "changed\n"
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    assert safety_dirs(p) == []
    assert not p["msafety"].exists()
    assert not p["staging"].exists()


@needs_tools
@pytest.mark.parametrize("confirmed", [False, True])
def test_restore_script_dry_run_reports_an_empty_media_archive(tmp_path: Path, confirmed: bool) -> None:
    p = tree(tmp_path)
    empty_media_backup(p, tmp_path)

    done = run_restore(p, tmp_path, dry_run=True, empty_media_confirmed=confirmed)

    assert done.returncode == 0, done.stderr
    assert "media=EMPTY" in done.stdout
    assert "Media excludes: /cache/*** (from the archive's manifest.yml)" in done.stdout
    assert f"deletes the 1 file(s) outside them in the live media {media(p)}" in done.stdout
    assert ("A restore refuses this archive" in done.stdout) is not confirmed
    assert "Dry run" in done.stdout
    assert not any(line.startswith("systemctl") for line in events(tmp_path))
    assert (media(p) / "accounts" / "avatars" / "me.png").read_text() == "changed\n"


@needs_tools
def test_restore_script_restores_a_confirmed_empty_media_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)
    empty_media_backup(p, tmp_path)

    done = run_restore(p, tmp_path, empty_media_confirmed=True)

    assert done.returncode == 0, done.stderr + done.stdout
    assert "confirmed with empty_media_confirmed" in done.stdout
    # The role's behaviour: the live media outside the excludes is emptied,
    # the snapshot keeps it; the excluded cache stays.
    assert live_files(p) == {"cache/remote/x.png": "changed\n"}
    (safety,) = safety_dirs(p)
    assert (p["msafety"] / safety.name / "accounts" / "avatars" / "me.png").read_text() == "changed\n"
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows original\n"


@needs_tools
@pytest.mark.parametrize("case", ["s3", "no-media-dir"])
def test_restore_script_without_local_media_needs_no_confirmation(tmp_path: Path, case: str) -> None:
    p = tree(tmp_path)
    directory = empty_media_backup(p, tmp_path)
    extra: dict[str, Any] = {}
    if case == "s3":
        extra["storage_driver"] = "s3"
    else:
        (directory / "media").rmdir()
        repack(directory)

    done = run_restore(p, tmp_path, **extra)

    assert done.returncode == 0, done.stderr + done.stdout
    assert "media=no" in done.stdout
    assert "holds no files" not in done.stdout + done.stderr
    assert (media(p) / "accounts" / "avatars" / "me.png").read_text() == "changed\n"


@needs_tools
def test_restore_script_a_failing_media_check_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    directory = empty_media_backup(p, tmp_path)
    (directory / "media").rmdir()
    (directory / "media").write_text("not a directory\n")
    repack(directory)

    done = run_restore(p, tmp_path, empty_media_confirmed=True)

    assert done.returncode != 0
    assert "cannot read the archive's media/" in done.stderr
    assert not any(line.startswith(("systemctl", "psql", "pg_dump", "dropdb", "createdb")) for line in events(tmp_path))
    assert (media(p) / "accounts" / "avatars" / "me.png").read_text() == "changed\n"
    assert not p["staging"].exists()


@needs_tools
def test_restore_script_media_with_files_needs_no_confirmation(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)

    done = run_restore(p, tmp_path, dry_run=True)

    assert done.returncode == 0, done.stderr
    assert "media=yes" in done.stdout
    assert "holds no files" not in done.stdout


@needs_tools
@pytest.mark.parametrize("break_dump", ["no-header", "no-table-data"])
def test_restore_script_refuses_a_bad_dump_before_anything_stops(tmp_path: Path, break_dump: str) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)
    extra = {}
    if break_dump == "no-header":
        (directory / "database" / "mastodon.dump").write_text("garbage\n")
        repack(directory)
    else:
        extra = {"NO_TABLE_DATA": "1"}
    make_site(p, "changed")

    done = run_restore(p, tmp_path, env_extra=extra)

    assert done.returncode != 0
    assert not any(line.startswith("systemctl") for line in events(tmp_path))
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    assert not p["staging"].exists()


@needs_tools
def test_restore_script_a_failed_stop_drops_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")

    done = run_restore(p, tmp_path, env_extra={"SYSTEMCTL_STOP_FAILS": "1"})

    assert done.returncode != 0
    assert "aborted before anything was dropped or overwritten (Stop mastodon-web before restore)" in done.stderr
    assert not any(line.startswith(("dropdb", "pg_dump")) for line in events(tmp_path))
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"


@needs_tools
def test_restore_script_rolls_back_after_a_failed_restore(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")
    (media(p) / "accounts" / "new.png").write_text("new\n")

    done = run_restore(p, tmp_path, env_extra={"PG_RESTORE_FAILS_FOR": str(p["staging"])})

    assert done.returncode != 0
    assert "Mastodon restore failed (Restore PostgreSQL dump)." in done.stderr
    assert "Database rollback: done." in done.stderr
    assert "Media and config rollback: done." in done.stderr
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    assert (media(p) / "accounts" / "new.png").read_text() == "new\n"
    assert (p["site"] / ".env.production").read_text() == "MARKER=changed\n"
    log = events(tmp_path)
    assert not any(line.startswith(("systemctl start", "systemctl restart")) for line in log)
    assert not p["staging"].exists()


@needs_tools
def test_restore_script_a_failed_migration_rolls_back_media_and_files(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")
    (media(p) / "accounts" / "new.png").write_text("new\n")

    done = run_restore(p, tmp_path, env_extra={"MIGRATE_FAILS": "1"})

    assert done.returncode != 0
    assert "(Run migrations after restore)" in done.stderr
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    assert (media(p) / "accounts" / "new.png").read_text() == "new\n"
    assert (media(p) / "accounts" / "avatars" / "me.png").read_text() == "changed\n"
    assert (p["site"] / ".env.production").read_text() == "MARKER=changed\n"


@needs_tools
def test_restore_script_rolls_nothing_back_while_a_service_runs(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")

    done = run_restore(p, tmp_path, env_extra={"PG_RESTORE_FAILS_FOR": str(p["staging"]), "ACTIVE_AFTER_FAILURE": "1"})

    assert done.returncode != 0
    assert "NOTHING was rolled back" in done.stderr
    assert "Database rollback: skipped." in done.stderr
    # The failed restore left the recreated (empty) database; nothing restored the safety dump.
    assert (p["pgdata"] / "mastodon.db").read_text() == ""


@needs_tools
def test_restore_script_without_a_live_database_skips_the_safety_dump(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["pgdata"] / "mastodon.db").unlink()

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows original\n"
    assert "Pre-restore database dump: none (no live database)" in done.stdout
    assert not any(line.startswith("pg_dump") for line in events(tmp_path))


@needs_tools
def test_restore_script_stops_on_another_database_error(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)

    done = run_restore(p, tmp_path, env_extra={"PSQL_FAILS": "1"})

    assert done.returncode != 0
    assert "connection refused" in done.stderr
    assert not any(line.startswith("systemctl") for line in events(tmp_path))


@needs_tools
def test_restore_script_latest_is_the_newest_archive(tmp_path: Path) -> None:
    p = tree(tmp_path)
    old = take_backup(p, tmp_path)
    os.utime(p["backups"] / f"{old.name}.tar.gz", (1_000_000_000, 1_000_000_000))
    take_backup(p, tmp_path, stamp=LATER)

    done = run_restore(p, tmp_path, dry_run=True)

    assert done.returncode == 0, done.stderr
    assert f"Restore archive: {p['backups']}/manual-{LATER}.tar.gz" in done.stdout


@needs_tools
def test_restore_script_without_archives_names_the_root(tmp_path: Path) -> None:
    p = tree(tmp_path)

    done = run_restore(p, tmp_path)

    assert done.returncode == 1
    assert f"No Mastodon backup archives found in {p['backups']}" in done.stderr


@needs_tools
def test_restore_script_a_held_route_lock_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["etc"] / "mastodon.yml").write_text("changed: 1\n")
    make_site(p, "changed")

    done = run_restore(p, tmp_path, stubs="ROUTE_GUARD=(false)\n")

    assert done.returncode == 1
    assert "holds its lock" in done.stderr
    assert not any(line.startswith("systemctl") for line in events(tmp_path))
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"


@needs_tools
def test_restore_script_a_route_lock_taken_later_restores_the_rest_and_fails(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["etc"] / "mastodon.yml").write_text("changed: 1\n")
    make_site(p, "changed")
    later = 'guard() { [ -e "$LOG.guard" ] && return 1; : >"$LOG.guard"; }\nROUTE_GUARD=(guard)\n'

    done = run_restore(p, tmp_path, stubs=later)

    assert done.returncode == 1
    assert "was not restored" in done.stderr
    assert (p["etc"] / "mastodon.yml").read_text() == "changed: 1\n"
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows original\n"
    assert "systemctl restart mastodon-web" in events(tmp_path)
    assert "Database rollback" not in done.stderr


@needs_tools
def test_restore_script_refuses_an_existing_media_snapshot(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    script, stdin = restore_script(p)
    stamp = assignments(script)["MEDIA_SAFETY"].rsplit("/", 1)[1]
    (p["msafety"] / stamp).mkdir(parents=True)
    make_site(p, "changed")

    done = run_script(script, FILES / "restore.sh", tmp_path, stubs=STUBS, stdin=stdin, **env(p, tmp_path))

    assert done.returncode != 0
    assert "media safety directory already exists" in done.stderr
    assert "aborted before anything was dropped" in done.stderr
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"


def test_archives_and_safety_copies_must_lie_outside_the_media() -> None:
    for field in ("root", "safety_root"):
        with pytest.raises(ValidationError, match="must lie apart"):
            MastodonRestoreConfig.model_validate({field: "/home/mastodon/live/public/system/x"})


@needs_tools
def test_restore_script_an_unreadable_unit_state_must_still_stop(tmp_path: Path) -> None:
    # `systemctl show` fails and every unit still runs: the stop check fails closed.
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")
    (tmp_path / "calls.log.state").write_text("active\n")
    unreadable = (
        'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; '
        "case $1 in show) return 1 ;; is-active) echo active ;; esac; }\n"
    )

    done = run_restore(p, tmp_path, stubs=unreadable)

    assert done.returncode != 0
    assert "(Confirm mastodon-web is stopped)" in done.stderr
    assert "systemctl stop mastodon-web" in events(tmp_path)
    assert not any(line.startswith(("dropdb", "pg_dump")) for line in events(tmp_path))
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"


def _route_failure(tmp_path: Path, stubs: str = "") -> tuple[dict[str, Path], Any]:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")
    (p["etc"] / "mastodon.yml").write_text("changed: 1\n")
    return p, run_restore(p, tmp_path, stubs=stubs, env_extra={"MIGRATE_FAILS": "1"})


@needs_tools
def test_restore_script_rolls_back_a_route_it_wrote_behind_the_guard(tmp_path: Path) -> None:
    counted = 'guard() { printf "guard\\n" >>"$LOG"; }\nROUTE_GUARD=(guard)\n'

    p, done = _route_failure(tmp_path, counted)

    assert done.returncode != 0
    assert "Traefik route rollback: done." in done.stderr
    assert (p["etc"] / "mastodon.yml").read_text() == "changed: 1\n"
    # Before the stop, before the write and before the rollback.
    assert events(tmp_path).count("guard") == 3


@needs_tools
def test_restore_script_leaves_the_route_while_a_transaction_holds_the_lock(tmp_path: Path) -> None:
    # Free for the first check and the write, held when the rollback comes.
    later = 'guard() { local n; n=$(cat "$LOG.n" 2>/dev/null || echo 0); echo $((n + 1)) >"$LOG.n"; [ "$n" -lt 2 ]; }\n'

    p, done = _route_failure(tmp_path, later + "ROUTE_GUARD=(guard)\n")

    assert done.returncode != 0
    assert "Traefik route rollback: not rolled back: a Traefik transaction holds its lock" in done.stderr
    assert (p["etc"] / "mastodon.yml").read_text() == "http: {}\n"
    assert (p["site"] / ".env.production").read_text() == "MARKER=changed\n"


@needs_tools
def test_restore_script_reports_a_failed_files_rollback(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")
    broken = tmp_path / "bin-broken"
    broken.mkdir()
    rsync = broken / "rsync"
    # The restore's rsync works; the rollback's (--checksum) fails.
    real = shutil.which("rsync", path=PATH)
    rsync.write_text(
        "#!/usr/bin/env bash\n"
        'case " $* " in *" --checksum "*) echo "rsync: broken" >&2; exit 23 ;; esac\n'
        f'exec {real} "$@"\n'
    )
    rsync.chmod(0o755)

    done = run_restore(p, tmp_path, env_extra={"MIGRATE_FAILS": "1", "PATH": f"{broken}:{tools(tmp_path)}:{PATH}"})

    assert done.returncode != 0
    assert "Database rollback: done." in done.stderr
    assert "Media and config rollback: FAILED: rsync: broken" in done.stderr


@needs_tools
def test_restore_script_without_a_live_database_needs_no_database_rollback(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    (p["pgdata"] / "mastodon.db").unlink()

    done = run_restore(p, tmp_path, env_extra={"MIGRATE_FAILS": "1"})

    assert done.returncode != 0
    assert "Database rollback: not needed (no live database before the restore)." in done.stderr
    assert "Safety dump: none." in done.stderr


@pytest.mark.parametrize("exclude", ["a\\*b", "foo\\", 'a"b', "a\nb"])
def test_excludes_that_would_break_the_manifest_or_fish_are_refused(exclude: str) -> None:
    with pytest.raises(ValidationError):
        MastodonBackupConfig(media_rsync_excludes=(exclude,))


def test_unusual_excludes_plan_fish_safe_commands() -> None:
    result = backup(MastodonBackupConfig(fetch_local=False, media_rsync_excludes=("/cache/*.tmp", "it's [x]")))

    assert result.succeeded, result.error
    assert result.fish_unsafe_commands == []


@pytest.mark.parametrize("staging", ["/tmp", "/var/tmp", "/srv"])
def test_restore_staging_must_be_a_directory_of_its_own(staging: str) -> None:
    with pytest.raises(ValidationError, match="directory of its own"):
        MastodonRestoreConfig(staging_dir=staging)


@needs_tools
def test_restore_script_stops_a_running_unit_whose_file_is_gone(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    gone = (
        'systemctl() { printf "systemctl %s\\n" "$*" >>"$LOG"; case $1 in '
        "show) echo not-found ;; "
        'is-active) if [ -e "$LOG.stopped" ]; then echo inactive; else echo active; fi ;; '
        'stop) : >"$LOG.stopped" ;; esac; }\n'
    )

    done = run_restore(p, tmp_path, stubs=gone, run_migrations=False)

    assert done.returncode == 0, done.stderr
    log = events(tmp_path)
    assert "systemctl stop mastodon-web" in log
    assert log.index("systemctl stop mastodon-web") < next(i for i, line in enumerate(log) if line.startswith("dropdb"))


@needs_tools
def test_restore_script_a_failed_safety_dump_drops_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)
    make_site(p, "changed")

    done = run_restore(p, tmp_path, env_extra={"PG_DUMP_FAILS": "1"})

    assert done.returncode != 0
    assert "aborted before anything was dropped or overwritten (Take safety dump of the live database)" in done.stderr
    assert not any(line.startswith(("dropdb", "systemctl start", "systemctl restart")) for line in events(tmp_path))
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    assert not p["staging"].exists()


@needs_tools
def test_restore_script_without_cleanup_keeps_the_staging_directory(tmp_path: Path) -> None:
    p = tree(tmp_path)
    take_backup(p, tmp_path)

    done = run_restore(p, tmp_path, dry_run=True, cleanup=False)

    assert done.returncode == 0, done.stderr
    assert (p["staging"] / f"manual-{STAMP}" / "database" / "mastodon.dump").exists()


# -- media excludes (the manifest's media_rsync_excludes) -----------------------------


def cache_only_backup(p: dict[str, Path], tmp_path: Path, **extra: Any) -> Path:
    """A backup of a live media that holds only the remote-media cache: its media/ is empty."""

    shutil.rmtree(media(p) / "accounts")
    directory = take_backup(p, tmp_path, **extra)
    assert [path for path in (directory / "media").rglob("*") if not path.is_dir()] == []
    (media(p) / "cache" / "remote" / "y.png").write_text("fetched later\n")
    return directory


def set_manifest(directory: Path, text: str | None) -> None:
    """Replace (or with ``None`` remove) the backup's manifest.yml and pack it again."""

    manifest_file = directory / "manifest.yml"
    if text is None:
        manifest_file.unlink()
    else:
        manifest_file.write_text(text)
    repack(directory)


def without_excludes_line(directory: Path) -> str:
    lines = (directory / "manifest.yml").read_text().splitlines(keepends=True)
    return "".join(line for line in lines if not line.startswith("media_rsync_excludes:"))


@needs_tools
def test_restore_script_cache_only_media_needs_no_confirmation_and_keeps_the_cache(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cache_only_backup(p, tmp_path)
    (p["pgdata"] / "mastodon.db").write_text("rows changed\n")

    dry = run_restore(p, tmp_path, dry_run=True)

    assert dry.returncode == 0, dry.stderr
    assert "media=EMPTY" in dry.stdout
    assert f"neither does the live media {media(p)}: the media restore deletes no file." in dry.stdout
    assert "refuses" not in dry.stdout

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    assert "refused" not in done.stderr
    assert live_files(p) == {"cache/remote/x.png": "original\n", "cache/remote/y.png": "fetched later\n"}
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows original\n"


@needs_tools
@pytest.mark.parametrize("dry_run", [False, True])
def test_restore_script_refuses_while_live_files_outside_the_excludes_would_go(tmp_path: Path, dry_run: bool) -> None:
    p = tree(tmp_path)
    cache_only_backup(p, tmp_path)
    (media(p) / "accounts" / "avatars").mkdir(parents=True)
    (media(p) / "accounts" / "avatars" / "me.png").write_text("uploaded\n")
    (media(p) / "media_attachments").mkdir()
    (media(p) / "media_attachments" / "link").symlink_to("../accounts/avatars/me.png")
    (p["pgdata"] / "mastodon.db").write_text("rows changed\n")

    done = run_restore(p, tmp_path, dry_run=dry_run)

    assert "media=EMPTY" in done.stdout
    text = f"deletes the 2 file(s) outside them in the live media {media(p)}"
    if dry_run:
        assert done.returncode == 0, done.stderr
        assert text in done.stdout
        assert "A restore refuses this archive unless empty_media_confirmed" in done.stdout
    else:
        assert done.returncode != 0
        assert "refused before anything was stopped or changed" in done.stderr
        assert text in done.stderr
    assert not any(line.startswith(("systemctl", "psql", "pg_dump", "dropdb", "createdb")) for line in events(tmp_path))
    assert live_files(p)["accounts/avatars/me.png"] == "uploaded\n"
    assert (p["pgdata"] / "mastodon.db").read_text() == "rows changed\n"
    assert not p["staging"].exists()


@needs_tools
def test_restore_script_keeps_every_excluded_pattern(tmp_path: Path) -> None:
    p = tree(tmp_path)
    (media(p) / "imports").mkdir()
    (media(p) / "imports" / "a.part").write_text("partial\n")
    directory = take_backup(p, tmp_path, media_rsync_excludes=("/cache/***", "/imports/*.part"))
    assert 'media_rsync_excludes: ["/cache/***", "/imports/*.part"]' in (directory / "manifest.yml").read_text()
    (media(p) / "imports" / "b.part").write_text("partial\n")
    (media(p) / "imports" / "c.txt").write_text("not excluded\n")

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    assert "Media excludes: /cache/***, /imports/*.part (from the archive's manifest.yml);" in done.stdout
    files = live_files(p)
    assert files["imports/a.part"] == files["imports/b.part"] == "partial\n"
    assert "imports/c.txt" not in files
    assert files["cache/remote/x.png"] == "original\n"


@needs_tools
@pytest.mark.parametrize("manifest_case", ["no-manifest", "no-line", "empty-list"])
def test_restore_script_without_excludes_restores_as_before(tmp_path: Path, manifest_case: str) -> None:
    p = tree(tmp_path)
    directory = take_backup(p, tmp_path)
    text = {
        "no-manifest": None,
        "no-line": without_excludes_line(directory),
        "empty-list": without_excludes_line(directory) + "media_rsync_excludes: []\n",
    }[manifest_case]
    set_manifest(directory, text)
    make_site(p, "changed")

    done = run_restore(p, tmp_path)

    assert done.returncode == 0, done.stderr + done.stdout
    reason = "the archive has no manifest.yml" if text is None else "the archive's manifest.yml lists none"
    deletes = "the restore deletes every live media file the archive lacks."
    assert f"Media excludes: none ({reason}); {deletes}" in done.stdout
    # Without excludes, rsync --delete removes the live cache the archive lacks.
    assert live_files(p) == {"accounts/avatars/me.png": "original\n"}


@needs_tools
def test_restore_script_without_a_manifest_counts_the_cache(tmp_path: Path) -> None:
    # No manifest, no excludes: the live cache counts and the guard refuses (fail closed).
    p = tree(tmp_path)
    set_manifest(cache_only_backup(p, tmp_path), None)

    done = run_restore(p, tmp_path)

    assert done.returncode != 0
    assert f"deletes the 2 file(s) outside them in the live media {media(p)}" in done.stderr
    assert not any(line.startswith("systemctl") for line in events(tmp_path))
    assert set(live_files(p)) == {"cache/remote/x.png", "cache/remote/y.png"}


@needs_tools
@pytest.mark.parametrize(
    "line",
    [
        'media_rsync_excludes: "/cache/***"',
        "media_rsync_excludes: [/cache/***]",
        "media_rsync_excludes: ['/cache/***']",
        'media_rsync_excludes: ["/cache/***",]',
        'media_rsync_excludes: ["/cache/***" "/x"]',
        'media_rsync_excludes: ["/cache/\\u002a**"]',
        'media_rsync_excludes: [""]',
        "media_rsync_excludes: null",
        "media_rsync_excludes:",
        'media_rsync_excludes: ["/cache/***"]\nmedia_rsync_excludes: []',
        "manifest.yml is a directory",
    ],
)
def test_restore_script_stops_on_unreadable_excludes(tmp_path: Path, line: str) -> None:
    p = tree(tmp_path)
    directory = cache_only_backup(p, tmp_path)
    if line == "manifest.yml is a directory":
        (directory / "manifest.yml").unlink()
        (directory / "manifest.yml").mkdir()
        repack(directory)
    else:
        set_manifest(directory, without_excludes_line(directory) + line + "\n")

    for dry_run in (True, False):
        done = run_restore(p, tmp_path, dry_run=dry_run, empty_media_confirmed=True)

        assert done.returncode != 0
        assert "Mastodon restore stopped before anything was stopped or changed:" in done.stderr
        assert "manifest.yml" in done.stderr
        assert "Components:" not in done.stdout
        assert not any(line.startswith(("systemctl", "psql", "pg_dump", "dropdb")) for line in events(tmp_path))
        assert set(live_files(p)) == {"cache/remote/x.png", "cache/remote/y.png"}
        assert not p["staging"].exists()


@needs_tools
def test_restore_script_a_failing_live_media_count_changes_nothing(tmp_path: Path) -> None:
    p = tree(tmp_path)
    cache_only_backup(p, tmp_path)
    shutil.rmtree(media(p))
    media(p).write_text("not a directory\n")

    done = run_restore(p, tmp_path, empty_media_confirmed=True)

    assert done.returncode != 0
    assert f"cannot read the live media {media(p)}" in done.stderr
    assert not any(line.startswith(("systemctl", "psql", "pg_dump", "dropdb")) for line in events(tmp_path))
    assert not p["staging"].exists()
