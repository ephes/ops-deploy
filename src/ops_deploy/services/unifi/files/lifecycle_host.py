"""The UniFi backup and restore roles on the host (``unifi_backup``, ``unifi_restore``).

Run as root with one JSON payload on stdin; the MongoDB credentials are part
of it and never reach a command line or an environment. ``backup``: the
role's validation, archive restriction, disk check, ``mongodump`` while
UniFi runs, the stop/copy/start block, ``metadata.yml``,
``manifest.sha256`` and the archive. ``restore``: archive selection and
validation (all a dry run does), then the safety backup, the restore, its
verification, the rollback from the safety backup when either fails, and the
cleanup (``restore_pilot_internal``'s scaffold).

``mongodump`` and ``mongorestore`` read the credentials from a
``--config`` file (``0600`` in a private ``0700`` directory below
``credentials_dir``, removed afterwards); ``mongosh`` reads its script,
password included, on stdin. Tool output is shown with the password
replaced by ``********``.
"""

import grp
import hashlib
import json
import math
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import quote

# Owners of the backups and system files (tests substitute their own account).
ROOT_USER = "root"
ROOT_GROUP = "root"
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SUBDIRS = ("database", "data", "autobackups", "logs", "config", "systemd", "traefik")
ARCHIVE_PATTERNS = (".tar", ".tgz")
EXTENSION = ".tar.gz"
# ``find -mtime -7``: autobackups younger than seven days.
AUTOBACKUP_AGE = 7 * 86400
HTTP_CODES = ("200", "302", "303")
# A unit from before the credential argument file, with the URI (password) inline.
INLINE_URI = b"mongodb://"
RESTORE_METHODS = (
    "restore_methods:\n"
    "    automated: MongoDB import + data directory rsync\n"
    "    semi_manual: Extract .unf from autobackups/, upload via web UI\n"
)


class Failure(Exception):
    """A role ``fail``/``assert``: its message ends the run."""


def say(message):
    print(message, flush=True)


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, **kwargs)


def sleep(seconds):
    if seconds:
        time.sleep(seconds)


def identity(value, group=False):
    if isinstance(value, int) or value.isdecimal():
        return int(value)
    return grp.getgrnam(value).gr_gid if group else pwd.getpwnam(value).pw_uid


def set_attributes(path, uid, gid, mode):
    details = os.lstat(path)
    if (details.st_uid, details.st_gid) != (uid, gid):
        os.chown(path, uid, gid, follow_symlinks=False)
    if stat.S_IMODE(details.st_mode) != mode:
        os.chmod(path, mode)


def ensure_dir(path, owner, group, mode):
    """``file: state=directory``: owner, group and mode on ``path`` and every directory it creates."""

    if os.path.islink(path) or (os.path.lexists(path) and not os.path.isdir(path)):
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


def write_private(path, text, mode=0o600):
    """A new file (never an existing one or a link), private from its first byte."""

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
        os.fchmod(handle.fileno(), mode)


def copy_into(source, destination, mode=0o600):
    """A copy of ``source`` into the backup directory (``ROOT_USER``, ``mode``)."""

    with open(source, "rb") as handle:
        content = handle.read()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        os.fchown(handle.fileno(), identity(ROOT_USER), identity(ROOT_GROUP, group=True))
        os.fchmod(handle.fileno(), mode)


def replace_file(source, destination, owner, group, mode):
    """``copy: remote_src=true`` onto a live path: written aside with its final owner and mode, then renamed.

    An identical file is left alone. Returns whether anything changed.
    """

    with open(source, "rb") as handle:
        content = handle.read()
    uid, gid = identity(owner), identity(group, group=True)
    try:
        details = os.lstat(destination)
    except FileNotFoundError:
        details = None
    if details is not None and stat.S_ISREG(details.st_mode):
        with open(destination, "rb") as handle:
            same = handle.read() == content
        if same and (details.st_uid, details.st_gid, stat.S_IMODE(details.st_mode)) == (uid, gid, mode):
            return False
    descriptor, partial = tempfile.mkstemp(prefix=".ops-deploy-", dir=os.path.dirname(destination))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
        os.replace(partial, destination)
    except BaseException:
        if os.path.lexists(partial):
            os.unlink(partial)
        raise
    return True


def require_tools(names):
    """The roles install their packages (rsync, tar, the MongoDB tools); this program refuses without them."""

    missing = sorted({name for name in names if shutil.which(name) is None})
    if missing:
        raise Failure(f"Missing on the host: {', '.join(missing)}. Nothing was changed.")


def remove_tree(path):
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


# --- systemd -----------------------------------------------------------------


def unit_state(unit):
    """``LoadState`` and ``ActiveState`` of ``unit``; an unreadable unit fails (never taken for stopped)."""

    shown = subprocess.run(
        ["systemctl", "show", "--property=LoadState", "--property=ActiveState", unit],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    values = dict(line.partition("=")[::2] for line in shown.stdout.splitlines() if "=" in line)
    if shown.returncode != 0 or not values.get("ActiveState"):
        raise Failure(f"Cannot read the state of {unit} ({shown.stderr.strip() or 'no ActiveState'})")
    return values.get("LoadState", ""), values["ActiveState"]


def wait_active(unit, attempts, delay):
    """The roles' ``until: ActiveState == 'active'``: ``attempts`` checks, ``delay`` seconds apart."""

    state = ""
    for attempt in range(attempts):
        state = unit_state(unit)[1]
        if state == "active":
            return
        if attempt + 1 < attempts:
            sleep(delay)
    raise Failure(f"{unit} is not active ({state}) after {attempts} checks")


# --- MongoDB -----------------------------------------------------------------


def reachable(host, port, timeout=1.0):
    """``wait_for: state=started timeout=1``."""

    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except OSError:
        return False
    return True


class Mongo:
    """The MongoDB tools with the payload's credentials, which never reach argv or the environment.

    Entered, it holds a private directory below ``credentials_dir``: the
    ``--config`` file of ``mongodump``/``mongorestore`` (the URI with user,
    password and authentication database) and ``mongosh``'s own ``HOME``.
    Leaving removes it.
    """

    def __init__(self, cfg):
        mongo, credentials = cfg["mongodb"], cfg.get("credentials") or {}
        self.host, self.port, self.database = mongo["host"], int(mongo["port"]), mongo["database"]
        self.username = credentials.get("username", "")
        self.password = credentials.get("password", "")
        self.auth_db = credentials.get("auth_db", "")
        self.parent = cfg["credentials_dir"]
        self.directory = None

    def __enter__(self):
        if not self.password:
            raise Failure("The MongoDB password is missing; nothing was changed")
        self.directory = tempfile.mkdtemp(prefix="ops-unifi-mongo-", dir=self.parent)
        uri = "mongodb://{}:{}@{}:{}/?authSource={}".format(
            quote(self.username, safe=""),
            quote(self.password, safe=""),
            self.host,
            self.port,
            quote(self.auth_db, safe=""),
        )
        # JSON strings are YAML double-quoted strings.
        write_private(self.config, "uri: " + json.dumps(uri) + "\n")
        settings = os.path.join(self.home, ".mongodb", "mongosh")
        os.makedirs(settings, mode=0o700)
        write_private(
            os.path.join(settings, "config"),
            json.dumps({"disableLogging": True, "enableTelemetry": False, "updateURL": ""}),
        )
        return self

    def __exit__(self, *_exc):
        if self.directory is not None:
            shutil.rmtree(self.directory, ignore_errors=True)
            self.directory = None

    @property
    def config(self):
        return os.path.join(self.directory, "tools.yml")

    @property
    def home(self):
        return os.path.join(self.directory, "home")

    def environment(self):
        return {"HOME": self.home, "PATH": os.environ.get("PATH") or DEFAULT_PATH, "LC_ALL": "C"}

    def redact(self, text):
        for secret in sorted({self.password, quote(self.password, safe=""), json.dumps(self.password)[1:-1]}, key=len):
            if len(secret) >= 4:
                text = text.replace(secret, "********")
        return text

    def tail(self, result):
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        return self.redact(" | ".join(lines[-3:])) or f"exit status {result.returncode}"

    def tool(self, binary, *args, attempts=1, delay=0):
        """``binary --config=<private file> args``; ``attempts`` tries, ``delay`` seconds apart."""

        detail = ""
        for attempt in range(1, attempts + 1):
            result = subprocess.run(
                [binary, "--config=" + self.config, *args],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                env=self.environment(),
            )
            if result.returncode == 0:
                return
            detail = self.tail(result)
            if attempt < attempts:
                say(f"{binary} failed (attempt {attempt} of {attempts}): {detail}; retrying in {delay}s")
                sleep(delay)
        raise Failure(f"{binary} failed: {detail}")

    def drop_database(self):
        """``db.getSiblingDB(<database>).dropDatabase()`` through mongosh, its script on stdin."""

        script = (
            'if (config.get("disableLogging") !== true || config.get("enableTelemetry") !== false) quit(19);\n'
            f"const a = db.getSiblingDB({json.dumps(self.auth_db)});\n"
            f"if (!a.auth({json.dumps(self.username)}, {json.dumps(self.password)})) quit(20);\n"
            f"const r = db.getSiblingDB({json.dumps(self.database)}).dropDatabase();\n"
            "if (!r || r.ok !== 1) quit(21);\n"
            'print("OPS_UNIFI_DROPPED");\n'
        )
        result = subprocess.run(
            ["mongosh", "--quiet", "--norc", "--host", self.host, "--port", str(self.port), "--file", "/dev/stdin"],
            input=script,
            capture_output=True,
            text=True,
            env=self.environment(),
        )
        if result.returncode != 0 or "OPS_UNIFI_DROPPED" not in result.stdout.splitlines():
            raise Failure(f"mongosh could not drop the {self.database} database: {self.tail(result)}")
        say(f"Dropped the MongoDB database {self.database}")

    def restore(self, dump, cfg):
        """The role's drop (``drop_database``) and ``mongorestore`` (three retries, five seconds apart)."""

        if cfg["drop_database"]:
            self.drop_database()
        timing = cfg["timing"]
        self.tool(
            "mongorestore",
            "--db=" + self.database,
            "--dir=" + dump,
            *(["--drop"] if cfg["mongorestore_drop"] else []),
            attempts=timing["mongorestore_attempts"],
            delay=timing["mongorestore_delay"],
        )
        say(f"Restored the MongoDB database {self.database} from {dump}")


# --- backup ------------------------------------------------------------------


def restrict_archives(root):
    """Every archive directly in the root (non-hidden regular files) owner-only, as the role does each run."""

    for entry in os.scandir(root):
        if entry.name.startswith(".") or not entry.is_file(follow_symlinks=False):
            continue
        if entry.name.endswith(ARCHIVE_PATTERNS) or ".tar." in entry.name:
            if stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) != 0o600:
                os.chmod(entry.path, 0o600)
                say(f"Restricted {entry.path} to 0600")


def tree_size(path):
    """``du -sb``: the apparent size of ``path`` and everything below it."""

    total = os.lstat(path).st_size
    for current, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                total += os.lstat(os.path.join(current, name)).st_size
            except FileNotFoundError:
                continue
    return total


def disk_check(data, root, ratio):
    size = tree_size(data) if os.path.exists(data) else 0
    details = os.statvfs(root)
    available = details.f_bavail * details.f_frsize
    required = math.ceil(size * ratio)
    if available < required:
        raise Failure(
            f"Not enough space under {root}. Available={available} bytes, required={required} bytes "
            f"(data size {size} bytes with {ratio}x overhead)."
        )


def installed_version():
    """``dpkg-query -W -f='${Version}' unifi`` (empty when the package is not installed)."""

    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "unifi"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def scalar(value):
    """A YAML scalar as ``to_nice_yaml`` writes it for these values."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    plain = re.fullmatch(r"[A-Za-z0-9/][A-Za-z0-9._/@+-]*", value)
    special = value.lower() in {"true", "false", "yes", "no", "on", "off", "null", "y", "n"}
    number = re.fullmatch(r"[-+]?([0-9][0-9_]*|[0-9]*\.[0-9]+|[0-9]+\.[0-9]*)([eE][-+]?[0-9]+)?", value)
    if plain and not special and not number:
        return value
    return json.dumps(value)


def metadata_text(cfg, version):
    """``metadata.yml`` as the role writes it (``to_nice_yaml``: sorted keys)."""

    values = {
        "data_path": cfg["paths"]["data"],
        "host": cfg["host"],
        "include_autobackups": cfg["include"]["autobackups"],
        "include_logs": cfg["include"]["logs"],
        "mongodb_database": cfg["database"],
        "mongodb_port": cfg["mongodb_port"],
        "service_stopped": cfg["stop_service"],
        "timestamp": cfg["stamp"],
        "unifi_version": version or "unknown",
    }
    lines = [f"{key}: {scalar(value)}\n" for key, value in values.items()]
    lines.insert(6, RESTORE_METHODS)
    return "".join(lines)


def manifest_name(relative):
    """``sha256sum``'s file name field, with its escaping of backslashes and newlines."""

    if "\\" in relative or "\n" in relative:
        return True, relative.replace("\\", "\\\\").replace("\n", "\\n")
    return False, relative


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(directory):
    """``find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256``."""

    found = []
    for current, _dirs, files in os.walk(directory):
        for name in files:
            full = os.path.join(current, name)
            relative = "./" + os.path.relpath(full, directory)
            if relative == "./manifest.sha256" or not stat.S_ISREG(os.lstat(full).st_mode):
                continue
            found.append((relative, full))
    lines = []
    for relative, full in sorted(found, key=lambda item: item[0].encode()):
        escaped, name = manifest_name(relative)
        lines.append(("\\" if escaped else "") + f"{sha256(full)}  {name}\n")
    write_private(os.path.join(directory, "manifest.sha256"), "".join(lines))


def write_archive(root, name):
    """``tar -C <root> -czf <name>.tar.gz <name>``, written aside and renamed, owner-only from the start.

    A failed run never leaves a partial archive that ``latest`` would pick.
    """

    final = os.path.join(root, name + EXTENSION)
    partial = os.path.join(root, f".{name}{EXTENSION}.partial")
    if os.path.lexists(final):
        raise Failure(f"{final} already exists")
    previous = os.umask(0o077)
    try:
        run(["tar", "-C", root, "-czf", partial, name])
        os.chmod(partial, 0o600)
        os.replace(partial, final)
    except BaseException:
        if os.path.lexists(partial):
            os.unlink(partial)
        raise
    finally:
        os.umask(previous)
    return final


def restrict_tree(path, dir_mode=0o700, file_mode=0o600):
    """The dump's directories ``dir_mode`` and files ``file_mode`` (root's), links untouched."""

    uid, gid = identity(ROOT_USER), identity(ROOT_GROUP, group=True)
    for current, dirs, files in os.walk(path):
        set_attributes(current, uid, gid, dir_mode)
        for name in files:
            full = os.path.join(current, name)
            if stat.S_ISREG(os.lstat(full).st_mode):
                set_attributes(full, uid, gid, file_mode)


def rsync(source, destination, *, delete, exclude=None):
    options = ["-a", *(["--delete"] if delete else []), *([f"--exclude={exclude}"] if exclude else [])]
    run(["rsync", *options, source + "/", destination + "/"])


def copy_autobackups(source, destination):
    """The role's copy of ``*.unf`` younger than seven days; its failures do not stop the backup."""

    try:
        now = time.time()
        for current, _dirs, files in os.walk(source):
            for name in sorted(files):
                full = os.path.join(current, name)
                details = os.lstat(full)
                if name.endswith(".unf") and stat.S_ISREG(details.st_mode) and now - details.st_mtime < AUTOBACKUP_AGE:
                    copy_into(full, os.path.join(destination, name))
    except OSError as error:
        say(f"Copying the autobackups failed (tolerated, as in the role): {error}")


def backup(cfg, mongo):
    """The ``unifi_backup`` role; returns what it took.

    ``cfg["safety"]``: the restore's pre-restore backup, which works on a
    fresh installation too (a missing data directory or database is reported
    as nothing to snapshot) and dumps MongoDB whenever it is reachable.
    """

    safety, unit, paths, include = cfg["safety"], cfg["unit"], cfg["paths"], cfg["include"]
    root, directory = cfg["root"], cfg["dir"]
    present = {name: os.path.exists(path) for name, path in paths.items()}
    required = [("data", "UniFi data directory"), ("db", "UniFi MongoDB directory")]
    optional = {
        "logs": ("logs", "UniFi logs directory"),
        "system_properties": ("system_properties", "system.properties"),
        "keystore": ("keystore", "UniFi keystore"),
        "env": ("env_file", ".env file"),
        "traefik": ("traefik", "Traefik dynamic config"),
    }
    required += [optional[flag] for flag in optional if include[flag]]
    if not safety:
        for name, description in required:
            if not present[name]:
                raise Failure(f"{description} ({paths[name]}) is missing")
    _load, active = unit_state(unit)
    running = active == "active"
    dump = False
    if cfg["mongodb_backup"]:
        if running or safety:
            if not reachable(mongo.host, mongo.port):
                raise Failure(
                    f"MongoDB at {mongo.host}:{mongo.port} is not reachable"
                    + (": no safety backup, nothing was changed" if safety else f" while {unit} runs: no backup")
                )
            dump = True
        else:
            say(
                f"WARNING: {unit} is not running ({active}): no MongoDB dump, as with the role. "
                "This backup holds the files only; a restore from it leaves the database as it is."
            )
    require_tools(
        ["systemctl", "rsync"] + (["tar"] if cfg["create_archive"] else []) + (["mongodump"] if dump else [])
    )
    ensure_dir(root, ROOT_USER, ROOT_GROUP, "0700")
    restrict_archives(root)
    if cfg["disk_check"]:
        disk_check(paths["data"], root, cfg["disk_overhead_ratio"])
    version = installed_version()
    os.mkdir(directory, 0o700)
    try:
        return write_backup(cfg, mongo, directory, present, running, dump, version)
    except BaseException:
        # A half-written snapshot (it can hold the dump and the JVM argument
        # file) never stays behind; retention would not know it.
        remove_tree(directory)
        say(f"Removed the incomplete snapshot {directory}")
        raise


def write_backup(cfg, mongo, directory, present, running, dump, version):
    """The backup below its fresh ``directory``: dump, copy (UniFi stopped), metadata, manifest, archive."""

    safety, unit, paths, include, root = cfg["safety"], cfg["unit"], cfg["paths"], cfg["include"], cfg["root"]
    ensure_dir(directory, ROOT_USER, ROOT_GROUP, "0700")
    for name in SUBDIRS:
        ensure_dir(os.path.join(directory, name), ROOT_USER, ROOT_GROUP, "0700")
    taken = {"dir": directory, "database": "skipped", "data": present["data"]}
    if dump:
        # While UniFi runs, before it is stopped (the role's order).
        mongo.tool("mongodump", "--db=" + mongo.database, "--out=" + os.path.join(directory, "database"))
        dumped = os.path.join(directory, "database", mongo.database)
        if os.path.isdir(dumped):
            restrict_tree(os.path.join(directory, "database"))
            taken["database"] = "dumped"
            say(f"Dumped the MongoDB database {mongo.database}")
        elif safety:
            taken["database"] = "absent"
            say(f"The MongoDB database {mongo.database} does not exist: nothing to snapshot (fresh installation)")
        else:
            raise Failure(f"mongodump finished but wrote no {dumped}")
    stopping = cfg["stop_service"] and running
    failure = None
    try:
        if stopping:
            run(["systemctl", "stop", unit])
            sleep(cfg["stop_pause"])
        if present["data"]:
            rsync(paths["data"], os.path.join(directory, "data"), delete=cfg["use_delete"], exclude="db/*")
        elif safety:
            say(f"The data directory {paths['data']} does not exist: nothing to snapshot (fresh installation)")
        if include["autobackups"] and present["autobackup"]:
            copy_autobackups(paths["autobackup"], os.path.join(directory, "autobackups"))
        if include["logs"] and present["logs"]:
            try:
                rsync(paths["logs"], os.path.join(directory, "logs"), delete=cfg["use_delete"])
            except subprocess.CalledProcessError as error:
                say(f"Copying the logs failed (tolerated, as in the role): {error}")
        copies = [
            (include["system_properties"], "system_properties", "config/system.properties"),
            (include["keystore"], "keystore", "config/keystore"),
            (include["env"], "env_file", "config/unifi.env"),
            (True, "unit_file", "systemd/unifi.service"),
            (True, "jvm_args", "systemd/mongodb.jvmargs"),
            (include["traefik"], "traefik", "traefik/unifi.yml"),
        ]
        for wanted, name, below in copies:
            if wanted and present[name]:
                copy_into(paths[name], os.path.join(directory, below))
    except BaseException as error:
        failure = error
        raise
    finally:
        if stopping:
            try:
                run(["systemctl", "start", unit])
                wait_active(unit, cfg["timing"]["start_attempts"], cfg["timing"]["start_delay"])
                say(f"{unit} is active again")
            except (Failure, subprocess.CalledProcessError) as error:
                if failure is None:
                    raise
                # Keep the first failure; report both.
                say(f"Starting {unit} after the failed copy failed too: {error}")
    write_private(os.path.join(directory, "metadata.yml"), metadata_text(cfg, version))
    if cfg["generate_checksums"]:
        write_manifest(directory)
    if cfg["create_archive"]:
        archive = write_archive(root, cfg["name"])
        say(f"UniFi backup complete: {archive}")
    else:
        say(f"UniFi backup complete: {directory}")
    return taken


# --- restore -----------------------------------------------------------------


def below(root, path):
    """Whether ``path`` resolves strictly below ``root``, through no hidden name."""

    real_root, real = os.path.realpath(root), os.path.realpath(path)
    if real == real_root or not real.startswith(real_root + os.sep):
        return False
    return not any(part.startswith(".") for part in os.path.relpath(real, real_root).split(os.sep))


def select(cfg):
    """``latest`` (the newest ``*.tar.gz`` directly in the root, by mtime), a name below the root (the
    directory or file of that name first, then ``<name>.tar.gz``, the role's order) or an absolute path
    below the root. Archives are ``.tar.gz`` files, snapshots directories; links are refused."""

    root, archive = cfg["root"], cfg["archive"]
    if not os.path.isdir(root):
        raise Failure(f"No UniFi archives found under {root} (it does not exist)")
    if archive == "latest":
        candidates = [
            entry
            for entry in os.scandir(root)
            if not entry.name.startswith(".") and entry.name.endswith(EXTENSION) and entry.is_file(follow_symlinks=False)
        ]
        if not candidates:
            raise Failure(f"No UniFi archives found under {root}")
        checked = [max(candidates, key=lambda entry: entry.stat(follow_symlinks=False).st_mtime).path]
    elif archive.startswith("/"):
        checked = [archive]
    else:
        checked = [os.path.join(root, archive), os.path.join(root, archive + EXTENSION)]
    for path in checked:
        if not os.path.lexists(path):
            continue
        if os.path.islink(path) or not below(root, path):
            raise Failure(f"{path} is a link or not below {root}; nothing was changed")
        if os.path.isdir(path):
            return path, False
        if os.path.isfile(path) and path.endswith(EXTENSION):
            return path, True
        raise Failure(f"{path} is neither a .tar.gz archive nor a snapshot directory")
    raise Failure(f'Unable to locate UniFi restore artifact "{archive}". Checked: {", ".join(checked)}')


def payload_directory(path):
    """The archive's single top-level directory, after refusing members that could escape the extraction."""

    tops = set()
    links = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name[2:] if member.name.startswith("./") else member.name
            parts = [part for part in name.split("/") if part not in ("", ".")]
            if not parts:
                continue
            if name.startswith("/") or ".." in parts:
                raise Failure(f"Archive member {member.name!r} escapes the extraction directory")
            if member.isdev() or member.isfifo():
                raise Failure(f"Archive member {member.name!r} is a device or FIFO")
            for depth in range(1, len(parts)):
                if "/".join(parts[:depth]) in links:
                    raise Failure(f"Archive member {member.name!r} lies below a link of the archive")
            if member.issym() or member.islnk():
                target = member.linkname
                resolved = os.path.normpath(os.path.join(os.path.dirname(name) if member.issym() else "", target))
                if target.startswith("/") or resolved == ".." or resolved.startswith("../"):
                    raise Failure(f"Archive member {member.name!r} links outside the archive")
                links.add("/".join(parts))
            tops.add(parts[0])
    if len(tops) != 1:
        raise Failure(f"The archive must hold exactly one top-level directory, found: {', '.join(sorted(tops))}")
    return tops.pop()


def stage(cfg, selected, is_archive):
    """The snapshot directory: ``selected`` itself, or the archive unpacked into a fresh scratch directory."""

    if not is_archive:
        return selected, None
    ensure_dir(cfg["work_dir"], ROOT_USER, ROOT_GROUP, "0700")
    scratch = tempfile.mkdtemp(prefix="unifi-", dir=cfg["work_dir"])
    try:
        top = payload_directory(selected)
        run(["tar", "-C", scratch, "-xzf", selected])
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    return os.path.join(scratch, top), scratch


def parse_metadata(text):
    """The top-level scalars of ``metadata.yml`` (quotes removed)."""

    values = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*$", line)
        if not match:
            continue
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[match.group(1)] = value
    return values


def manifest_entries(text):
    for line in text.splitlines():
        if not line.strip():
            continue
        escaped = line.startswith("\\")
        if escaped:
            line = line[1:]
        expected, separator, name = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise Failure(f"Invalid line in manifest.sha256: {line!r}")
        if escaped:
            name = re.sub(r"\\(.)", lambda match: "\n" if match.group(1) == "n" else match.group(1), name)
        yield expected, name


def verify_checksums(snapshot):
    """``sha256sum --check manifest.sha256`` in the snapshot (every listed file, none outside it)."""

    count = 0
    bad = []
    with open(os.path.join(snapshot, "manifest.sha256")) as handle:
        text = handle.read()
    for expected, name in manifest_entries(text):
        relative = name[2:] if name.startswith("./") else name
        parts = relative.split("/")
        if relative.startswith("/") or ".." in parts:
            raise Failure(f"manifest.sha256 names a file outside the snapshot: {name!r}")
        full = os.path.join(snapshot, relative)
        try:
            ok = stat.S_ISREG(os.lstat(full).st_mode) and sha256(full) == expected
        except FileNotFoundError:
            ok = False
        if not ok:
            bad.append(name)
        count += 1
    if bad:
        raise Failure(f"Checksum validation failed for {len(bad)} file(s): {', '.join(bad[:5])}")
    return count


def major(version):
    match = re.match(r"^([0-9]+)", version or "")
    return match.group(1) if match else ""


def validate(cfg, snapshot):
    """The role's validation: metadata, checksums, major version; and what the snapshot holds."""

    if not os.path.isdir(snapshot):
        raise Failure(f"Snapshot directory {snapshot} does not exist.")
    metadata = os.path.join(snapshot, "metadata.yml")
    if not os.path.isfile(metadata):
        raise Failure(f"metadata.yml not found in snapshot {snapshot}")
    with open(metadata) as handle:
        meta = parse_metadata(handle.read())
    checked = None
    if cfg["validate_checksums"]:
        if not os.path.isfile(os.path.join(snapshot, "manifest.sha256")):
            raise Failure(f"Checksum validation enabled, but manifest.sha256 is missing in {snapshot}")
        checked = verify_checksums(snapshot)
    backup_version = meta.get("unifi_version", "unknown")
    installed = installed_version()
    if cfg["check_version"]:
        ours, theirs = major(backup_version), major(installed)
        if ours and theirs and ours != theirs:
            raise Failure(
                f"Backup version {backup_version} (major {ours}) does not match installed version {installed} "
                f"(major {theirs}). Install a compatible UniFi release before restoring."
            )
    unit = os.path.join(snapshot, "systemd", "unifi.service")
    legacy = False
    if os.path.isfile(unit):
        with open(unit, "rb") as handle:
            legacy = INLINE_URI in handle.read()
    return {
        "meta": meta,
        "checked": checked,
        "installed": installed,
        "dump": os.path.isdir(os.path.join(snapshot, "database", cfg["mongodb"]["database"])),
        "data": os.path.isdir(os.path.join(snapshot, "data")),
        "unit": os.path.isfile(unit),
        "legacy_unit": legacy,
        "jvm_args": os.path.isfile(os.path.join(snapshot, "systemd", "mongodb.jvmargs")),
        "traefik": os.path.isfile(os.path.join(snapshot, "traefik", "unifi.yml")),
    }


def plan(cfg, selected, snapshot, info):
    meta, paths = info["meta"], cfg["paths"]
    database = cfg["mongodb"]["database"]
    _load, active = unit_state(cfg["unit"])
    lines = [
        f"artifact: {selected}" + (f" (unpacked into {os.path.dirname(snapshot)})" if snapshot != selected else ""),
        "backup: unifi_version={} timestamp={} host={}".format(
            meta.get("unifi_version", "unknown"), meta.get("timestamp", "?"), meta.get("host", "?")
        ),
        f"installed UniFi: {info['installed'] or 'not installed'}"
        + (" (major versions checked)" if cfg["check_version"] else " (version check off)"),
        "checksums: "
        + (f"{info['checked']} files match manifest.sha256" if info["checked"] is not None else "not validated"),
        f"service: {cfg['unit']} is {active}",
    ]
    if not cfg["include_mongodb"]:
        lines.append("database: not restored (include_mongodb is off)")
    elif info["dump"]:
        lines.append(
            f"database: drop {database} and mongorestore database/{database}"
            if cfg["drop_database"]
            else f"database: mongorestore database/{database} over the live database"
        )
    else:
        lines.append(f"database: the backup has no database/{database}; MongoDB stays as it is")
    lines.append(
        f"data: data/ -> {paths['data']} (rsync --delete, db/ kept), owned by {cfg['unifi_user']}:{cfg['unifi_group']}"
        if info["data"]
        else "data: the backup has no data/ directory; a restore is refused"
    )
    if info["legacy_unit"]:
        lines.append("unit: the archived unit carries an inline MongoDB URI; the live unit stays")
    else:
        lines.append(f"unit: systemd/unifi.service -> {paths['unit_file']}" if info["unit"] else "unit: unchanged")
    lines.append(
        f"JVM argument file: -> {paths['jvm_args']} (root:{cfg['jvm_args_group']} 0640)"
        if info["jvm_args"]
        else "JVM argument file: unchanged"
    )
    lines.append(f"route: traefik/unifi.yml -> {paths['traefik']}" if info["traefik"] else "route: unchanged")
    safety = cfg["safety"]
    if safety:
        mongo = cfg["mongodb"]
        parts = [
            "the database" if reachable(mongo["host"], int(mongo["port"])) else "no database (MongoDB not reachable)",
            "the data directory"
            if os.path.exists(paths["data"])
            else "no data directory (absent: nothing to snapshot)",
        ]
        lines.append(f"safety backup: {safety['dir']} with {' and '.join(parts)}")
        lines.append(
            "on failure: rollback from the safety backup" if cfg["rollback_on_failure"] else "on failure: no rollback"
        )
    else:
        lines.append("safety backup: none (no rollback)")
    say("UniFi restore plan:\n" + "\n".join("  " + line for line in lines))


def chown_tree(path, user, group):
    """Owner and group on ``path`` (resolved) and everything below it, links themselves, never followed."""

    uid, gid = identity(user), identity(group, group=True)
    top = os.path.realpath(path)
    for current, dirs, files in os.walk(top):
        for full in [current] + [os.path.join(current, name) for name in dirs + files]:
            details = os.lstat(full)
            if (details.st_uid, details.st_gid) != (uid, gid):
                os.chown(full, uid, gid, follow_symlinks=False)


def system_files(cfg, source):
    """The unit, JVM argument file and route of ``source`` (a snapshot) onto their live paths."""

    paths = cfg["paths"]
    unit = os.path.join(source, "systemd", "unifi.service")
    if os.path.isfile(unit):
        with open(unit, "rb") as handle:
            legacy = INLINE_URI in handle.read()
        if legacy:
            say(
                f"WARNING: {unit} carries an inline MongoDB URI (the layout before the credential argument "
                f"file): the live {paths['unit_file']} stays. `just deploy-one unifi` manages the unit."
            )
        elif replace_file(unit, paths["unit_file"], ROOT_USER, ROOT_GROUP, 0o644):
            say(f"Restored {paths['unit_file']}")
    jvm_args = os.path.join(source, "systemd", "mongodb.jvmargs")
    if os.path.isfile(jvm_args):
        if cfg["manage_jvm_args_dir"]:
            ensure_dir(os.path.dirname(paths["jvm_args"]), ROOT_USER, cfg["jvm_args_group"], "0750")
        if replace_file(jvm_args, paths["jvm_args"], ROOT_USER, cfg["jvm_args_group"], 0o640):
            say(f"Restored {paths['jvm_args']}")
    route = os.path.join(source, "traefik", "unifi.yml")
    if os.path.isfile(route):
        if cfg["route_guard"]:
            run(cfg["route_guard"])
        if replace_file(route, paths["traefik"], ROOT_USER, ROOT_GROUP, 0o644):
            say(f"Restored {paths['traefik']}")


def sync_data(source, cfg):
    """``rsync -a --delete <snapshot>/data/ <data>/``; the files of every ``db/`` (never in a backup) stay."""

    # The backup's own exclude (``db/*`` at any depth, the role's): what a
    # backup never holds stays live.
    rsync(source, cfg["paths"]["data"], delete=True, exclude="db/*")


def verify(cfg, mongo):
    """The role's verify.yml: active, MongoDB reachable and readable, the web interface answering."""

    timing, unit = cfg["timing"], cfg["unit"]
    wait_active(unit, timing["active_attempts"], timing["active_delay"])
    if cfg["verify_mongodb"]:
        if not reachable(mongo.host, mongo.port):
            say(f"Skipping MongoDB verification because {mongo.host}:{mongo.port} is unreachable.")
        else:
            mongo.tool(
                "mongodump",
                "--db=" + mongo.database,
                "--archive=/dev/null",
                "--gzip",
                attempts=timing["dump_attempts"],
                delay=timing["dump_delay"],
            )
    if cfg["verify_http"]:
        code = ""
        for attempt in range(timing["http_attempts"]):
            result = subprocess.run(
                ["curl", "-q", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", cfg["health_url"]],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            code = result.stdout.strip()
            if code in HTTP_CODES:
                break
            if attempt + 1 < timing["http_attempts"]:
                sleep(timing["http_delay"])
        else:
            raise Failure(f"{cfg['health_url']} did not answer with 200, 302 or 303 (last: {code or 'no answer'})")
    say(f"{unit} is active, MongoDB answers and {cfg['health_url']} responds")


def apply(cfg, snapshot, info, mongo):
    unit = cfg["unit"]
    run(["systemctl", "stop", unit])
    sleep(cfg["stop_pause"])
    if cfg["include_mongodb"]:
        dump = os.path.join(snapshot, "database", mongo.database)
        if info["dump"]:
            mongo.restore(dump, cfg)
        else:
            say(f"MongoDB dump not found at {dump}. Backup was likely created without MongoDB dump. Skipping.")
    sync_data(os.path.join(snapshot, "data"), cfg)
    chown_tree(cfg["paths"]["data"], cfg["unifi_user"], cfg["unifi_group"])
    system_files(cfg, snapshot)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", unit])


def rollback(cfg, taken, mongo):
    """The role's rollback.yml: the safety backup's database, data and system files, then verify.

    What the safety backup found absent (fresh installation) stays as restored.
    """

    unit, safety_dir = cfg["unit"], taken["dir"]
    run(["systemctl", "stop", unit])
    if cfg["include_mongodb"]:
        dump = os.path.join(safety_dir, "database", mongo.database)
        if taken["database"] == "dumped" and os.path.isdir(dump):
            mongo.restore(dump, cfg)
        else:
            say(
                f"MongoDB safety snapshot not found at {dump} ({taken['database']}). "
                "Skipping MongoDB rollback replay: the database stays as restored."
            )
    if taken["data"]:
        sync_data(os.path.join(safety_dir, "data"), cfg)
    else:
        say(f"The data directory was absent before the restore: {cfg['paths']['data']} stays as restored")
    system_files(cfg, safety_dir)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", unit])
    verify(cfg, mongo)


def restore_tools(cfg, info):
    """What the restore, its safety backup, verification and rollback run."""

    names = ["systemctl", "rsync"]
    if cfg["safety"]:
        names += ["mongodump"]
    if cfg["include_mongodb"] and (info["dump"] or cfg["safety"]):
        names += ["mongorestore"] + (["mongosh"] if cfg["drop_database"] else [])
    if cfg["verify_mongodb"]:
        names += ["mongodump"]
    if cfg["verify_http"]:
        names += ["curl"]
    return names


def restore(cfg, mongo):
    require_tools(["tar"])
    selected, is_archive = select(cfg)
    snapshot, scratch = stage(cfg, selected, is_archive)
    try:
        info = validate(cfg, snapshot)
        # The dry run fails too when the restore would.
        require_tools(restore_tools(cfg, info))
        plan(cfg, selected, snapshot, info)
        if cfg["dry_run"]:
            say("Dry run: the artifact is valid; UniFi, MongoDB, its data, unit and route were not touched.")
            return
        recover(cfg, snapshot, info, mongo)
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)
        try:
            os.rmdir(cfg["work_dir"])
        except OSError:
            pass


def recover(cfg, snapshot, info, mongo):
    """The scaffold's prepare, restore, verify, rescue (rollback) and always (cleanup) phases."""

    unit = cfg["unit"]
    load, _active = unit_state(unit)
    if load != "loaded":
        raise Failure(f"{unit} is not installed ({load}): deploy UniFi first. Nothing was changed.")
    if not info["data"]:
        raise Failure(f"The backup holds no data/ directory ({snapshot}/data). Nothing was changed.")
    if cfg["include_mongodb"] and info["dump"] and not reachable(mongo.host, mongo.port):
        raise Failure(f"MongoDB at {mongo.host}:{mongo.port} is not reachable. Nothing was changed.")
    safety_dir = taken = None
    if cfg["safety"]:
        taken = backup(cfg["safety"], mongo)
        safety_dir = taken["dir"]
        say(f"Safety backup: {safety_dir} (database: {taken['database']}, data directory: {taken['data']})")
    succeeded = False
    try:
        try:
            apply(cfg, snapshot, info, mongo)
            verify(cfg, mongo)
        except BaseException as error:
            if not (cfg["rollback_on_failure"] and taken):
                raise
            say(f"UniFi restore failed: {mongo.redact(str(error))}. Rolling back from {safety_dir}.")
            try:
                rollback(cfg, taken, mongo)
            except BaseException as again:
                say(
                    f"Rollback failed too: {mongo.redact(str(again))}. {unit} may be stopped. Restore "
                    f"{os.path.basename(safety_dir)} once the cause is fixed."
                )
            else:
                say(f"Rolled back: {unit} runs from the safety backup again.")
            raise Failure(f"UniFi restore failed: {error}") from error
        succeeded = True
        say(f"UniFi restored from {snapshot}")
    finally:
        if safety_dir is not None:
            if succeeded and cfg["cleanup_safety_backup"]:
                remove_tree(safety_dir)
                say(f"Removed the safety backup {safety_dir}")
            elif not succeeded:
                say(f"Safety backup retained at {safety_dir} due to restore failure.")


def main(action):
    os.umask(0o022)
    cfg = json.loads(sys.stdin.readline())
    mongo = Mongo(cfg)
    try:
        if action == "backup":
            with mongo:
                backup(cfg["backup"], mongo)
        elif action == "restore" and cfg["dry_run"]:
            restore(cfg, mongo)
        elif action == "restore":
            with mongo:
                restore(cfg, mongo)
        else:
            raise Failure(f"unknown action {action}")
    except (Failure, ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"unifi {action}: {mongo.redact(str(error))}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__" and len(sys.argv) == 2:
    raise SystemExit(main(sys.argv[1]))
