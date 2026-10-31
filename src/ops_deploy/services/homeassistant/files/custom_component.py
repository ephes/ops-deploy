"""Original named component/archive operations; stdin payload, fixed reports.

No recursive component content inspection. A stamp mismatch intentionally removes
then extracts in place, matching the original role's partial-failure behavior.
"""

import base64
import codecs
import gzip
import hashlib
import json
import netrc
import os
import pwd
import grp
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

from ha_cc_patch import apply as apply_patch, expected_stamp, needs_patch, prepare


def checksum(path):
    try:
        with open(path, "rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except FileNotFoundError:
        return None


def metadata_current(path, uid, gid, mode):
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return False
    # Linux cannot set symlink permissions. Original Ansible returns unchanged
    # after temporarily chmod'ing/restoring its target; avoid that target write.
    mode_current = stat.S_IMODE(current.st_mode) == mode or (
        stat.S_ISLNK(current.st_mode) and not hasattr(os, "lchmod")
    )
    return current.st_uid == uid and current.st_gid == gid and mode_current


def ownership(path, uid, gid):
    changed = False
    current = os.lstat(path)
    # Original set_fs_attributes uses lchown, including extracted link entries.
    if current.st_uid != uid:
        os.lchown(path, uid, -1)
        changed = True
    if current.st_gid != gid:
        os.lchown(path, -1, gid)
        changed = True
    return changed


def metadata(path, uid, gid, mode):
    changed = ownership(path, uid, gid)
    current = os.lstat(path)
    if stat.S_IMODE(current.st_mode) != mode:
        if hasattr(os, "lchmod"):
            os.lchmod(path, mode)
            changed = stat.S_IMODE(os.lstat(path).st_mode) != stat.S_IMODE(current.st_mode) or changed
        elif not stat.S_ISLNK(current.st_mode):
            os.chmod(path, mode)
            changed = True
    return changed


def request_for(url, force=False):
    """Original declared get_url defaults: proxy/TLS, challenge auth, netrc.

    Credentials stay host-local; neither URLs nor request errors are printed.
    No Ansible runtime is used. Only task-selected default transport options,
    not the unrelated get_url module's entire option surface, are exposed here.
    """
    parsed = urllib.parse.urlsplit(url)
    headers = {"User-Agent": "ansible-httpget", "Accept-Encoding": "gzip"}
    if force:
        headers["Cache-Control"] = "no-cache"
    handlers = [urllib.request.HTTPCookieProcessor()]
    if parsed.scheme != "ftp":
        if parsed.username:
            username = urllib.parse.unquote(parsed.username)
            password = urllib.parse.unquote(parsed.password or "")
            authority = parsed.netloc.split("@", 1)[1]
            url = urllib.parse.urlunsplit(parsed._replace(netloc=authority))
            passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passwords.add_password(None, authority, username, password)
            handlers += [urllib.request.HTTPBasicAuthHandler(passwords), urllib.request.HTTPDigestAuthHandler(passwords)]
        elif parsed.hostname:
            try:
                auth = netrc.netrc(os.environ.get("NETRC")).authenticators(parsed.hostname)
            except OSError:
                auth = None
            if auth and auth[0] and auth[2]:
                value = auth[0] + ":" + auth[2]
                headers["Authorization"] = "Basic " + base64.b64encode(value.encode()).decode()
    return urllib.request.Request(url, headers=headers), urllib.request.build_opener(*handlers)


def download(payload, uid, gid, report):
    destination = payload["archive"]
    wanted = payload["sha256"]
    observed = checksum(destination)
    if observed == wanted:
        report["effects_started"] = not metadata_current(destination, uid, gid, 0o644)
        report["changed"] = metadata(destination, uid, gid, 0o644)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".ops-ha-cc-", dir=os.path.dirname(destination))
    try:
        report["effects_started"] = True  # Owned staging file exists, even on failure.
        with os.fdopen(descriptor, "wb") as output:
            # Original get_url default per-request socket timeout is ten seconds.
            request, opener = request_for(payload["url"], force=observed is not None)
            with opener.open(request, timeout=10) as response:
                source = gzip.GzipFile(fileobj=response) if response.headers.get("Content-Encoding") == "gzip" else response
                shutil.copyfileobj(source, output)
        if checksum(temporary) != wanted:
            raise ValueError("checksum mismatch")
        # Verify BEFORE the atomic destination replacement. A failed transfer or
        # checksum never replaces an existing destination, unlike files.download.
        os.replace(temporary, destination)
        report["archive_replaced"] = True
        metadata(destination, uid, gid, 0o644)
        report["changed"] = True
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def needs_install(payload):
    try:
        with open(payload["stamp"], encoding="utf-8") as handle:
            actual = handle.read().strip()
    except (OSError, UnicodeError):
        return True
    return actual != expected_stamp(payload["version"], payload["sha256"]) or needs_patch(
        payload["component"], payload["version"], payload["sha256"]
    )


def extract(payload, report):
    # Verify the known candidate before replacing any installed tree. Installed
    # patch drift itself selects reconciliation, never a new admission refusal.
    desired_patch = prepare(payload["archive"], payload["version"], payload["sha256"])
    component = payload["component"]
    report["effects_started"] = True
    if os.path.islink(component) or (os.path.lexists(component) and not os.path.isdir(component)):
        os.unlink(component)
        report["component_removed"] = True
    elif os.path.isdir(component):
        shutil.rmtree(component)
        report["component_removed"] = True
    # Exact original GNU tar arguments from Ansible's TgzArchive.unarchive.
    # Captured command output contains public code paths, but remains unexported.
    completed = subprocess.run(
        [
            "tar", "--extract", "-C", payload["parent"], "-z", "--show-transformed-names",
            "--strip-components=2",
            "custom-conversation-" + payload["version"] + "/custom_components/custom_conversation",
            "--owner=" + payload["user"], "--group=" + payload["group"], "-f", payload["archive"],
        ],
        cwd=payload["parent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env={**os.environ, "LANG": "C", "LC_ALL": "C", "LC_MESSAGES": "C"},
    )
    if completed.returncode:
        raise RuntimeError("archive extraction failed")
    report["extracted"] = True
    # GNU tar ignores --owner/--group on extraction. Original unarchive follows
    # it with a declared-member ownership pass plus each top folder; retain that
    # pass, not a recursive walk that could touch unrelated existing children.
    listed = subprocess.run(
        ["tar", "--list", "-C", payload["parent"], "-z", "--show-transformed-names",
         "--strip-components=2",
         "custom-conversation-" + payload["version"] + "/custom_components/custom_conversation",
         "-f", payload["archive"]],
        cwd=payload["parent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env={**os.environ, "LANG": "C", "LC_ALL": "C", "LC_MESSAGES": "C", "LANGUAGE": "C"},
    )
    if listed.returncode:
        raise RuntimeError("archive listing failed")
    uid, gid = pwd.getpwnam(payload["user"]).pw_uid, grp.getgrnam(payload["group"]).gr_gid
    folders = []
    for raw in listed.stdout.splitlines():
        name = codecs.escape_decode(raw)[0].decode("utf-8", "surrogateescape")
        if name.startswith("/"):
            name = name[1:]
        ownership(os.path.join(payload["parent"], name), uid, gid)
        if "/" in name:
            folder = name.split("/", 1)[0]
            if folder not in folders:
                folders.append(folder)
    for folder in folders:
        ownership(os.path.join(payload["parent"], folder), uid, gid)
    apply_patch(component, desired_patch)
    report["changed"] = True


def run(payload):
    report = {"success": False, "changed": False, "effects_started": False,
              "archive_replaced": False, "component_removed": False, "extracted": False}
    try:
        action = payload["action"]
        if action == "check-install":
            report["changed"] = needs_install(payload)
        elif action == "extract":
            if needs_install(payload):
                extract(payload, report)
        elif action in {"check-archive", "download"}:
            uid = pwd.getpwnam(payload["user"]).pw_uid
            gid = grp.getgrnam(payload["group"]).gr_gid
            if action == "check-archive":
                report["changed"] = checksum(payload["archive"]) != payload["sha256"] or not metadata_current(
                    payload["archive"], uid, gid, 0o644
                )
            else:
                download(payload, uid, gid, report)
        else:
            raise ValueError("unknown action")
        report["success"] = True
    except Exception as exc:
        report["error"] = type(exc).__name__
    return report


if __name__ == "__main__":
    value = run(json.load(sys.stdin))
    print(json.dumps(value))
    raise SystemExit(0 if value["success"] else 1)
