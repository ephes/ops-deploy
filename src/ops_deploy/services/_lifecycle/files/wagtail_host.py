"""wagtail_backup and wagtail_restore on the host; ops-library's preserver is supplied verbatim.

Run as root with one JSON payload on stdin (the database passwords travel only
there). ``backup``: the role's directories, archive restriction, stop/dump/start
block, manifest and archive. ``retain``: the role's pruning, after the fetch.
``restore``: the role's selection, validation, block, rescue and always.
"""

import fnmatch
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ARCHIVE_PATTERNS = ("*.tar", "*.tar.*", "*.tgz")
TRAILER = "-- PostgreSQL database dump complete"


class Failure(Exception):
    """A role ``fail``/``assert``: its message ends the run."""


def preserver():
    namespace = {"__name__": "original_restore_preserve"}
    exec(compile(PRESERVE_SOURCE, "original_preserve.py", "exec"), namespace)  # noqa: F821
    return namespace


def say(message):
    print(message, flush=True)


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def identity(value, group=False):
    if value.isdecimal():
        return int(value)
    return grp.getgrnam(value).gr_gid if group else pwd.getpwnam(value).pw_uid


def ensure_dir(path, owner, group, mode):
    """``file: state=directory``: owner, group and mode on ``path`` and on every directory it creates.

    Attributes that already match are left alone, as the module leaves them.
    """

    if os.path.lexists(path) and not os.path.isdir(path):
        raise Failure(f"{path} exists and is not a directory")
    attributes = identity(owner), identity(group, group=True), int(mode, 8)
    missing = []
    current = os.path.abspath(path)
    while not os.path.lexists(current):
        missing.append(current)
        current = os.path.dirname(current)
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        set_attributes(directory, *attributes)
    set_attributes(path, *attributes)


def set_attributes(path, uid, gid, mode):
    details = os.stat(path)
    if (details.st_uid, details.st_gid) != (uid, gid):
        os.chown(path, uid, gid)
    if stat.S_IMODE(details.st_mode) != mode:
        os.chmod(path, mode)


def visible(root, kind):
    """``find`` with its defaults: direct entries, no hidden names, ``file``/``directory`` without following links."""

    try:
        entries = list(os.scandir(root))
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
        if entry.name.startswith("."):
            continue
        if (entry.is_file if kind == "file" else entry.is_dir)(follow_symlinks=False):
            found.append(entry)
    return found


def newest_first(entries):
    return sorted(entries, key=lambda entry: entry.stat(follow_symlinks=False).st_mtime, reverse=True)


def restrict_archives(root):
    for entry in visible(root, "file"):
        if any(fnmatch.fnmatch(entry.name, pattern) for pattern in ARCHIVE_PATTERNS):
            if stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) != 0o600:
                os.chmod(entry.path, 0o600)
                say(f"Restricted {entry.path} to 0600")


def running(unit):
    """Whether ``systemd: state=stopped`` would stop ``unit``; an unknown unit fails as the module does."""

    shown = subprocess.run(
        ["systemctl", "show", "--property=LoadState", "--property=ActiveState", unit], capture_output=True, text=True
    )
    values = dict(line.partition("=")[::2] for line in shown.stdout.splitlines() if "=" in line)
    if shown.returncode != 0 or not values.get("ActiveState"):
        # The systemd module fails closed too; never treat an unreadable unit as stopped.
        raise Failure(f"Service is in unknown state: {unit} ({shown.stderr.strip() or 'no ActiveState'})")
    if values.get("LoadState") == "not-found":
        raise Failure(f"Could not find the requested service {unit}: host")
    state = values.get("ActiveState", "")
    # Ansible's systemd ``stopped`` changes a running or deactivating unit.
    return state in ("active", "activating", "deactivating")


def pg_env(user, host, port, *, passfile=None, password=None, database=None):
    """The role's ``PG*`` environment; nothing inherited."""

    env = {"PATH": os.environ.get("PATH", PATH)}
    if host:
        env["PGHOST"] = host
    if port:
        env["PGPORT"] = port
    env["PGUSER"] = user
    if passfile:
        env["PGPASSFILE"] = passfile
    if password:
        env["PGPASSWORD"] = password
    if database:
        env["PGDATABASE"] = database
    return env


def as_user(user, argv):
    return ["runuser", "-u", user, "--", *argv]


# --- backup ------------------------------------------------------------------


def dump(cfg):
    """``postgresql_db: state=dump`` to ``<db>.sql.gz`` as the become user (pg_dump piped through pigz or gzip)."""

    argv = ["pg_dump", cfg["database"]]
    if cfg["host"]:
        argv.append("--host=" + cfg["host"])
    if cfg["port"]:
        argv.append("--port=" + cfg["port"])
    argv.append("--username=" + cfg["user"])
    argv += cfg["target_opts"]
    compressor = "pigz" if shutil.which("pigz") else "gzip"
    script = 'set -euo pipefail; "$@" | ' + compressor + ' > "$WAGTAIL_DUMP_TARGET"'
    env = pg_env(cfg["user"], "", "", password=cfg["password"] or None)
    env["WAGTAIL_DUMP_TARGET"] = cfg["dump"]
    # The role's no_log: only the exit status of a failing dump is reported.
    run(as_user(cfg["become_user"], ["bash", "-c", script, "pg_dump", *argv]), env=env, cwd="/", capture_output=True)


def manifest(cfg):
    return (
        f'service: "{cfg["service"]}"\n'
        f'timestamp: "{cfg["timestamp"]}"\n'
        f'archive: "{os.path.basename(cfg["archive"])}"\n'
        f'database_dump: "{os.path.basename(cfg["dump"])}"\n'
        "postgres:\n"
        f'  database: "{cfg["database"]}"\n'
        f'  host: "{cfg["host"]}"\n'
        f"  port: {cfg['port']}\n"
        f'  user: "{cfg["user"]}"\n'
    )


def write_archive(directory, destination):
    """``archive: format=gz`` of one directory: its contents below its name, as the module walks them.

    Written to a hidden name and renamed, so a failed run never leaves a
    partial archive that ``latest`` would pick.
    """

    root = os.path.dirname(directory) + "/"
    partial = os.path.join(os.path.dirname(destination), "." + os.path.basename(destination) + ".partial")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle, tarfile.open(fileobj=handle, mode="w|gz") as archive:
            for current, dirs, files in os.walk(directory, topdown=True):
                for name in dirs + files:
                    full = os.path.join(current, name)
                    archive.add(full, full[len(root) :], recursive=False)
        os.chmod(partial, 0o600)
        os.replace(partial, destination)
    except BaseException:
        if os.path.lexists(partial):
            os.unlink(partial)
        raise


def backup(cfg):
    owner, group, mode = cfg["owner"], cfg["group"], cfg["dir_mode"]
    for path in (cfg["root"], cfg["dir"], cfg["dir"] + "/database"):
        ensure_dir(path, owner, group, mode)
    restrict_archives(cfg["root"])
    stopped = False
    try:
        if cfg["stop_service"]:
            # ``state=stopped`` stops (and reports a change for) a running or deactivating unit only.
            if running(cfg["unit"]):
                stopped = True  # also when stopping fails, as the role's ``is failed``
                run(["systemctl", "stop", cfg["unit"]])
        dump(cfg)
    finally:
        if cfg["stop_service"] and stopped:
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "start", cfg["unit"]])
    if cfg["generate_manifest"]:
        path = cfg["dir"] + "/manifest.yml"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(manifest(cfg))
        os.chown(path, identity(owner), identity(group, group=True))
        os.chmod(path, int(cfg["file_mode"], 8))
    if cfg["create_archive"]:
        write_archive(cfg["dir"], cfg["archive"])
    say("Wagtail backup stored at " + (cfg["archive"] if cfg["create_archive"] else cfg["dir"]))


def remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.unlink(path)
    say(f"Removed {path}")


def retain(cfg):
    keep = cfg["retain"]
    if keep <= 0:
        return
    if cfg["create_archive"]:
        pattern = f"{cfg['prefix']}-*.{cfg['extension']}"
        archives = [entry for entry in visible(cfg["root"], "file") if fnmatch.fnmatch(entry.name, pattern)]
        for entry in newest_first(archives)[keep:]:
            remove(entry.path)
    directories = [entry for entry in visible(cfg["root"], "directory") if fnmatch.fnmatch(entry.name, cfg["prefix"] + "-*")]
    for entry in newest_first(directories)[keep:]:
        remove(entry.path)


# --- restore -----------------------------------------------------------------


def select(cfg):
    root, archive = cfg["root"], cfg["archive"]
    if archive == "latest":
        pattern = "*." + cfg["extension"]
        candidates = [entry for entry in visible(root, "file") if fnmatch.fnmatch(entry.name, pattern)]
        if not candidates:
            raise Failure(f"No Wagtail backup archives found in {root}")
        selected = newest_first(candidates)[0].path
    else:
        selected = archive if archive.startswith("/") else root + "/" + archive
    if not os.path.exists(selected):
        raise Failure(f"Wagtail restore archive not found: {selected}")
    return selected


def psql_admin(cfg, sql, database):
    """One statement through ``psql`` as the become user with the admin login (``postgresql_db``/``_privs``)."""

    env = pg_env(cfg["admin_user"], cfg["host"], cfg["port"], password=cfg["admin_password"] or None, database=database)
    result = run(
        as_user(cfg["become_user"], ["psql", "--no-psqlrc", "-At", "-v", "ON_ERROR_STOP=1", "--command=" + sql]),
        env=env,
        cwd="/",
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def database_exists(cfg):
    query = f"SELECT 1 FROM pg_database WHERE datname = '{cfg['database']}'"
    return psql_admin(cfg, query, "postgres") == "1"


def drop_database(cfg):
    """``postgresql_db: state=absent force=true``."""

    if not database_exists(cfg):
        return
    name = cfg["database"]
    if int(psql_admin(cfg, "SHOW server_version_num", "postgres")) >= 130000:
        psql_admin(cfg, f'DROP DATABASE "{name}" WITH (FORCE)', "postgres")
        return
    psql_admin(
        cfg,
        "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity "
        f"WHERE pg_stat_activity.datname = '{name}' AND pid <> pg_backend_pid()",
        "postgres",
    )
    psql_admin(cfg, f'DROP DATABASE "{name}"', "postgres")


def create_database(cfg):
    """``postgresql_db: state=present owner=<user>``."""

    name, owner = cfg["database"], cfg["user"]
    if not database_exists(cfg):
        psql_admin(cfg, f'CREATE DATABASE "{name}" OWNER "{owner}"', "postgres")
        return
    current = psql_admin(cfg, f"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{name}'", "postgres")
    if current != owner:
        psql_admin(cfg, f'ALTER DATABASE "{name}" OWNER TO "{owner}"', "postgres")


def pgpass_line(password):
    return "*:*:*:*:" + password.replace("\\", "\\\\").replace(":", "\\:")


def manage(cfg, command):
    """The role's ``manage.py`` shell task as the site user with its env file sourced."""

    script = f'set -a\n. "{cfg["env_path"]}"\nset +a\n"{cfg["python"]}" "{cfg["manage_py"]}" {command}\n'
    env = {
        "PATH": os.environ.get("PATH", PATH),
        "HOME": pwd.getpwnam(cfg["site_user"]).pw_dir,
        "DJANGO_SETTINGS_MODULE": cfg["settings"],
    }
    run(as_user(cfg["site_user"], ["bash", "-c", script]), env=env, cwd=cfg["site_path"])


def systemctl_state(unit, restart):
    run(["systemctl", "restart" if restart else "start", unit])


def restore(cfg):
    keep = preserver()
    selected = select(cfg)
    say(f"Selected restore source: {selected}")
    keep["check_layout"]([cfg["site_path"], cfg["staging"]], [selected])
    is_archive = os.path.isfile(selected)
    staging = cfg["staging"]
    if is_archive:
        if os.path.lexists(staging):
            remove(staging)
        os.makedirs(staging, mode=0o700)
        os.chmod(staging, 0o700)
        run(["tar", "--extract", "-C", staging, "-z", "-f", selected])
        payloads = sorted(entry.path for entry in visible(staging, "directory"))
        if not payloads:
            raise Failure("Unable to locate payload directory inside restore archive")
        if len(payloads) > 1:
            raise Failure(f"More than one payload directory under {staging}: {', '.join(payloads)}; nothing restored")
        payload = payloads[0]
    else:
        payload = selected
    dump_path = f"{payload}/database/{cfg['database']}.sql.gz"
    if not os.path.exists(dump_path):
        raise Failure("Database dump missing inside archive")
    run(
        [
            "bash",
            "-c",
            'set -euo pipefail\ngzip -t "$DUMP"\n'
            'gzip -dc "$DUMP" | tail -n 10 | grep -Fx -- ' + "'" + TRAILER + "'",
        ],
        env={"PATH": os.environ.get("PATH", PATH), "DUMP": dump_path},
        stdout=subprocess.DEVNULL,
    )
    if cfg["dry_run"]:
        say("wagtail_restore_dry_run=true - skipping service stop and database restore")
    else:
        keep["preflight"](cfg["site_path"], empty=False)
        # The role stops the units first and only then fails "Require existing
        # Wagtail site for safety dump", leaving them down; refuse up front.
        if not os.path.isdir(cfg["site_path"]):
            raise Failure(f"Wagtail site directory not found: {cfg['site_path']}; nothing was stopped or restored")
        apply(cfg, keep, dump_path)
    if cfg["cleanup"] and is_archive:
        remove(staging)


def apply(cfg, keep, dump_path):
    state = {
        "touched": False,
        "safety": False,
        "replaced": False,
        "recovered": False,
        "failed": "none",
        "preserved": {},
        "size": "dump incomplete",
    }
    units = [cfg["unit"], *cfg["extra_units"]]
    passdir = None
    step = "Allocate private PostgreSQL passfile directory"
    try:
        try:
            passfile = None
            if cfg["password"]:
                passdir = tempfile.mkdtemp(prefix="wagtail_restore-pgpass-")
                passfile = passdir + "/pgpass"
                step = "Render PostgreSQL passfile"
                descriptor = os.open(passfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "w") as handle:
                    handle.write(pgpass_line(cfg["password"]))
            env = pg_env(cfg["user"], cfg["host"], cfg["port"], passfile=passfile, database=cfg["database"])
            if cfg["stop_service"]:
                step = "Stop auxiliary Wagtail units before restore"
                for unit in cfg["extra_units"]:
                    run(["systemctl", "stop", unit])
                step = "Stop Wagtail service before restore"
                run(["systemctl", "stop", cfg["unit"]])
            step = "Keep Wagtail site pre-restore copy"
            state["preserved"] = keep["preserve"](cfg["site_path"], empty=False)
            step = "Require existing Wagtail site for safety dump"
            if state["preserved"].get("path") is None:
                raise Failure("Assertion failed")
            step = "Take and verify live database safety dump"
            safety = dict(env, SAFETY_DIR=state["preserved"]["path"])
            result = run(["bash", "-c", SAFETY_DUMP], env=safety, capture_output=True, text=True)
            state["safety"] = True
            state["size"] = result.stdout.split()[0]
            state["touched"] = True
            step = "Drop Wagtail database"
            drop_database(cfg)
            step = "Recreate Wagtail database"
            create_database(cfg)
            step = "Restore PostgreSQL dump in one transaction"
            run(
                [
                    "bash",
                    "-c",
                    'set -euo pipefail\ngzip -dc "$DUMP" | psql --no-psqlrc --single-transaction -v ON_ERROR_STOP=1',
                ],
                env=dict(env, DUMP=dump_path),
                # The role's no_log: a failing row would print table data.
                capture_output=True,
            )
            state["replaced"] = True
            step = "Ensure database privileges"
            psql_admin(cfg, f'GRANT ALL ON DATABASE "{cfg["database"]}" TO "{cfg["user"]}"', cfg["database"])
            for wanted, name, command in (
                (cfg["run_migrations"], "Run migrations after restore", "migrate"),
                (cfg["collectstatic"], "Collect static files after restore", "collectstatic --noinput"),
                (cfg["update_index"], "Update Wagtail search index after restore", "update_index"),
            ):
                if wanted:
                    step = name
                    manage(cfg, command)
            step = "Start Wagtail service after restore"
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", cfg["unit"]])
            systemctl_state(cfg["unit"], cfg["restart"])
            if cfg["stop_service"]:
                step = "Start auxiliary Wagtail units after restore"
                for unit in cfg["extra_units"]:
                    systemctl_state(unit, cfg["restart"])
        except Exception as error:
            say(f"{step} failed: {error}")
            state["failed"] = step
            if state["touched"] and cfg["stop_service"]:
                for unit in units:
                    run(["systemctl", "stop", unit])
            if state["safety"] and state["touched"] and not state["replaced"]:
                drop_database(cfg)
                create_database(cfg)
                recovery = pg_env(cfg["user"], cfg["host"], cfg["port"], passfile=passfile)
                run(
                    [
                        "pg_restore",
                        "--single-transaction",
                        "--exit-on-error",
                        "--dbname=" + cfg["database"],
                        state["preserved"]["path"] + "/database.pre-restore.dump",
                    ],
                    env=recovery,
                    capture_output=True,
                )
                state["recovered"] = True
            raise Failure(
                f"Wagtail restore failed at {state['failed']}. "
                f"SQL replacement committed: {state['replaced']}; "
                f"database recovery completed: {state['recovered']}. "
                f"Inspect services and retained copy {state['preserved']} before starting them."
            ) from None
    finally:
        if passdir is not None:
            shutil.rmtree(passdir, ignore_errors=True)
        say(
            f"Failed task: {state['failed']}; database touched: {state['touched']}; "
            f"SQL replacement committed: {state['replaced']}; "
            f"database recovery completed: {state['recovered']}. "
            f"Retained copy {state['preserved']}; size including database dump: {state['size']} bytes. "
            "Owner prunes copies by hand."
        )


SAFETY_DUMP = """set -euo pipefail
required="$(psql --no-psqlrc -At --command='SELECT pg_database_size(current_database())')"
available="$(df -PB1 "$SAFETY_DIR" | awk 'NR==2 {print $4}')"
test "$available" -ge "$((required + required / 10 + 16777216))"
test ! -e "$SAFETY_DIR/database.pre-restore.dump"
test ! -L "$SAFETY_DIR/database.pre-restore.dump"
pg_dump --format=custom --file="$SAFETY_DIR/database.pre-restore.dump"
pg_restore --list "$SAFETY_DIR/database.pre-restore.dump" > /dev/null
pg_restore --file=/dev/null "$SAFETY_DIR/database.pre-restore.dump"
chmod 600 "$SAFETY_DIR/database.pre-restore.dump"
du -sb "$SAFETY_DIR"
"""

ACTIONS = {"backup": backup, "retain": retain, "restore": restore}


def main(action):
    cfg = json.loads(sys.stdin.readline())
    try:
        ACTIONS[action](cfg)
    except (Failure, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"wagtail {action}: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__" and len(sys.argv) == 2:
    raise SystemExit(main(sys.argv[1]))
