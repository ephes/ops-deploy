"""A read-only InfluxDB token for the daily observability check (``services.obs_daily``).

Run by the deploy as root: ``python3 -I -c <this> MODE URL ORG BUCKET CONTAINER TOKEN_FILE GROUP DESCRIPTION``.

- ``check`` prints ``present`` when ``TOKEN_FILE`` holds a working token
  that cannot read authorizations (no operator token), whose authorization
  is the one recorded with it (second line of
  ``TOKEN_FILE``; token and ID are installed by one rename), is active,
  is described ``DESCRIPTION`` and may only read ``BUCKET``, the file is
  ``root:GROUP 0640``, and no other authorization described ``DESCRIPTION``
  exists; ``missing`` when the token does not work; ``stale`` otherwise.
- ``ensure`` keeps such a token (repairing the file mode and deleting the
  other authorizations of this deployment). Otherwise it creates an
  authorization that may only read ``BUCKET`` (``influx auth create
  --read-bucket`` in ``CONTAINER``, whose CLI holds the operator login),
  checks the new token from a synced temporary file that also holds its ID,
  installs the pair (one rename, directory synced) and only then deletes the other
  authorizations described ``DESCRIPTION``. Authorizations are told apart by
  ID, never by comparing token text (InfluxDB may hash tokens).

The token is never printed or passed on a command line. The source has no
backslashes: it travels as a ``-c`` argument through a possibly fish root shell.
"""

import fcntl
import grp
import hmac
import stat
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

mode, url, org, bucket, container, token_file, group, description = sys.argv[1:9]


def trusted(path):
    """Every existing directory above path belongs to root and is not group- or world-writable."""
    current = os.path.dirname(path)
    while True:
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            st = None
        if st is not None and (st.st_uid != 0 or st.st_mode & 0o022):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


if not trusted(token_file):
    sys.exit("the token file's directories are not root-only: " + token_file)


def narrow(path):
    """The token sees no authorizations: a read-only bucket token, not an operator's.

    InfluxDB answers a bucket-only token with 200 and an empty list (it filters out what the
    token may not read), an older one with 401/403; any listed authorization means more rights.
    """
    token = (lines_of(path) + [""])[0]
    request = urllib.request.Request(
        url.rstrip("/") + "/api/v2/authorizations", headers={"Authorization": "Token " + token}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code in (401, 403, 404)
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("authorizations") == []


def lines_of(path):
    """The token file's lines: the token, then its authorization ID (one file, renamed as a whole)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding="utf-8") as handle:
            return handle.read().split()
    except OSError:
        return []


def works(path):
    token = (lines_of(path) + [""])[0]
    if not token:
        return False
    query = "from(bucket: " + json.dumps(bucket) + ") |> range(start: -1h) |> limit(n: 1)"
    request = urllib.request.Request(
        url.rstrip("/") + "/api/v2/query?" + urllib.parse.urlencode({"org": org}),
        data=query.encode(),
        method="POST",
        headers={"Authorization": "Token " + token, "Content-Type": "application/vnd.flux"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read()
    except urllib.error.HTTPError as error:
        if error.code in (401, 403, 404):
            return False
        raise
    return True


def influx(*args):
    done = subprocess.run(
        ["docker", "exec", container, "influx", *args, "--json"], capture_output=True, text=True, timeout=60
    )
    if done.returncode != 0:
        sys.exit("influx " + args[0] + " " + args[1] + " failed with exit status " + str(done.returncode))
    return json.loads(done.stdout)


def file_ok():
    """The token file is root:GROUP 0640 and a regular file, as the Nyxmon user needs it."""
    try:
        st = os.lstat(token_file)
    except OSError:
        return False
    gid = grp.getgrnam(group).gr_gid
    return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == gid and stat.S_IMODE(st.st_mode) == 0o640


def read_id():
    """The authorization ID stored with the token (second line); the pair is installed by one rename."""
    found = lines_of(token_file)
    return found[1] if len(found) > 1 else ""


def bucket_id():
    buckets = influx("bucket", "list", "--org", org, "--name", bucket)
    if len(buckets) != 1:
        sys.exit("expected exactly one bucket named " + bucket + ", found " + str(len(buckets)))
    return buckets[0]["id"]


def managed(auths, auth_id, wanted_bucket, token):
    """auth_id is this deployment's active, bucket-read-only authorization AND the credential is its token.

    The binding needs the token in the authorization list; where InfluxDB hashes tokens and lists
    none, it cannot be established and the token is rotated (a newly created one is known).
    """
    for auth in auths:
        if auth.get("id") == auth_id and auth_id:
            listed = auth.get("token") or ""
            if not token or not listed or not hmac.compare_digest(listed, token):
                return False
            permissions = auth.get("permissions") or []
            suffix = "/buckets/" + wanted_bucket
            read_only = all(isinstance(p, str) and p.startswith("read:") and p.endswith(suffix) for p in permissions)
            active = auth.get("status", "active") == "active"
            return auth.get("description") == description and active and bool(permissions) and read_only
    return False


def strays(auths, keep_id):
    return [auth["id"] for auth in auths if auth.get("description") == description and auth.get("id") != keep_id]


def sync_write(path, text, mode, gid):
    tmp = path + "." + str(os.getpid()) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text + chr(10))
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(tmp, 0, gid)
    os.chmod(tmp, mode)
    return tmp


def sync_dir():
    dir_fd = os.open(os.path.dirname(token_file), os.O_RDONLY)
    os.fsync(dir_fd)
    os.close(dir_fd)


if mode == "check":
    # Present only when the installed token works, is this deployment's read-only authorization
    # (by the recorded ID, never by comparing token text), has the right file mode, and no other
    # authorization of this deployment is left (an interrupted rotation).
    if not works(token_file):
        print("missing")
        sys.exit(0)
    auths = influx("auth", "list")
    current = read_id()
    token = (lines_of(token_file) + [""])[0]
    ok = file_ok() and narrow(token_file) and managed(auths, current, bucket_id(), token) and not strays(auths, current)
    print("present" if ok else "stale")
    sys.exit(0)
if mode != "ensure":
    sys.exit("mode must be check or ensure")

# One rotation per token file at a time; the lock sits next to it in the root-only directory.
lock_fd = os.open(token_file + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
fcntl.flock(lock_fd, fcntl.LOCK_EX)
gid = grp.getgrnam(group).gr_gid
wanted = bucket_id()
auths = influx("auth", "list")
if any(not auth.get("token") for auth in auths):
    # Without listed tokens the installed credential cannot be bound to its authorization, and
    # every check would rotate it again: refuse before creating anything.
    sys.exit("InfluxDB lists authorizations without their tokens (token hashing?); obs_daily needs them listed")
current = read_id()
# A probe can fail on a passing InfluxDB hiccup: keep a working token that is ours and read-only,
# but finish a cleanup an earlier rotation may have left undone.
if works(token_file) and narrow(token_file) and managed(auths, current, wanted, (lines_of(token_file) + [""])[0]):
    if not file_ok():
        # works() opened it with O_NOFOLLOW: a regular file, not a link.
        os.chown(token_file, 0, gid)
        os.chmod(token_file, 0o640)
    for stray in strays(auths, current):
        influx("auth", "delete", "--id", stray)
    print("present")
    sys.exit(0)
created = influx("auth", "create", "--org", org, "--read-bucket", wanted, "--description", description)
token = created.get("token") if isinstance(created, dict) else None
new_id = created.get("id") if isinstance(created, dict) else None
if not token or not new_id:
    sys.exit("influx auth create returned no token or id")
tmp = token_file + "." + str(os.getpid()) + ".tmp"
try:
    tmp = sync_write(token_file, token + chr(10) + new_id, 0o640, gid)
    # The replacement must work before it is installed and before the old authorizations go.
    usable = works(tmp) and narrow(tmp)
except BaseException:
    usable = False
if not usable:
    # Leave nothing behind: neither the temporary file nor a second active grant.
    if os.path.lexists(tmp):
        os.unlink(tmp)
    influx("auth", "delete", "--id", new_id)
    sys.exit("the new read-only InfluxDB token cannot query " + bucket + " or can do more than that")
# Token and ID travel together: one rename installs the pair.
os.replace(tmp, token_file)
sync_dir()
for stray in strays(influx("auth", "list"), new_id):
    influx("auth", "delete", "--id", stray)
print("created")
