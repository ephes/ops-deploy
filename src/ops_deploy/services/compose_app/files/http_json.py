"""Declarative JSON API state (Servarr apps): ``probe`` reports drift, ``apply`` reconciles.

Run as root: ``python3 -I -c <this file> settings-probe|settings-apply|items-probe|items-apply``;
the request is JSON, base64-encoded on stdin. Values may be literals or
``{"host_secret": "<path>"}``: a file on this host (an app's API key) read
here and never sent anywhere else; it is reached without following symlinks
and must be a regular file. A missing file fails the step.

- ``settings``: one object (``GET <path>``, ``PUT <path>/<id>``), compared as
  a subset of ``desired``.
- ``items``: a list (``GET <path>``); every item in ``items`` exists, matched
  by ``match``, with the desired subset: ``POST <path>`` when missing (starting
  from the ``schema`` entry whose ``schema.key`` equals the item's, when given),
  ``PUT <path>/<id>`` when it differs. Items that are not listed are never
  touched or deleted.

Servarr shapes: ``fields`` in a desired item is a mapping ``name -> value``,
compared with and written into the API's ``[{"name", "value"}]`` list;
``tags`` given as labels are mapped to ids through ``tags_path`` (missing
tags are created there).

Values compare exactly; ``path_keys`` (``path``) ignore one trailing slash,
as Servarr returns directories with one.

``write_only`` keys (``password``, ``fields.apiKey``) are values the API
masks on reads: they are left out of the comparison. Their desired values
are tracked as a digest in ``state`` (a file on this host); a changed or
missing digest is drift, and the next write sends them.

Prints ``current`` or ``drift <names>`` (probe), ``changed`` or ``noop``
(apply). Errors name the method, the path and the status code; no value or
response body is ever printed. The probe only reads.
"""

import base64
import errno
import hashlib
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
MASK = "********"


class Fail(Exception):
    pass


def open_dir(path):
    """A descriptor of the absolute directory ``path``, reached without following symlinks."""

    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    for part in [p for p in path.split("/") if p]:
        try:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise Fail(path + " is not a plain directory") from None
            raise
        os.close(fd)
        fd = child
    return fd


def read_secret(path):
    """The stripped text of the regular file ``path``, reached and opened without following symlinks."""

    parent, _, name = path.rpartition("/")
    if not name or not path.startswith("/"):
        raise Fail("host secret " + path + " is not an absolute file path")
    try:
        dfd = open_dir(parent or "/")
    except FileNotFoundError:
        raise Fail("host secret " + path + " is missing") from None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        except FileNotFoundError:
            raise Fail("host secret " + path + " is missing") from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise Fail("host secret " + path + " is a symlink") from None
            raise
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Fail("host secret " + path + " is not a regular file")
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    text = b"".join(chunks).decode("utf-8", "replace").strip()
    if not text:
        raise Fail("host secret " + path + " is empty")
    return text


def host_value(value):
    """``value`` with ``{"host_secret": path}`` leaves read from their files."""

    if isinstance(value, dict):
        if set(value) == {"host_secret"}:
            return read_secret(value["host_secret"])
        return {key: host_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [host_value(item) for item in value]
    return value


class Api:
    def __init__(self, req):
        self.base = "http://127.0.0.1:" + str(req["port"]) + req.get("prefix", "")
        auth = req["auth"]
        self.headers = {auth["header"]: host_value(auth["value"]), "Accept": "application/json"}

    def call(self, method, path, body=None, *, query=""):
        data = None if body is None else json.dumps(body).encode()
        headers = dict(self.headers)
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path + query, data=data, headers=headers, method=method)
        try:
            with OPENER.open(req, timeout=30) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw.decode("utf-8")) if raw.strip() else None)
        except urllib.error.HTTPError as err:
            return err.code, None
        except (urllib.error.URLError, OSError, ValueError):
            return None, None

    def get(self, path):
        status, body = self.call("GET", path)
        if status != 200:
            raise Fail("GET " + path + " answered " + str(status))
        return body

    def send(self, method, path, body, query=""):
        status, answer = self.call(method, path, body, query=query)
        if status not in (200, 201, 202):
            raise Fail(method + " " + path + " answered " + str(status))
        return answer

    def wait(self, path, seconds):
        deadline = time.monotonic() + seconds
        while True:
            status, _ = self.call("GET", path)
            if status == 200:
                return
            if status in (401, 403):
                raise Fail("GET " + path + " answered " + str(status))
            if time.monotonic() > deadline:
                raise Fail("GET " + path + " did not answer 200 within " + str(seconds) + " s")
            time.sleep(2)


# -- comparison --------------------------------------------------------------------


def split(dotted):
    return dotted.split(".", 1) if "." in dotted else [dotted, None]


def fields_map(item):
    return {f.get("name"): f.get("value") for f in item.get("fields") or [] if isinstance(f, dict)}


def same(current, desired, path_like=False):
    """Equal; a ``path_like`` key ignores one trailing slash (APIs return directories with one)."""

    if path_like and isinstance(desired, str) and isinstance(current, str) and desired != "/":
        return current.rstrip("/") == desired.rstrip("/")
    if isinstance(desired, list) and isinstance(current, list):
        return sorted(map(json.dumps, current)) == sorted(map(json.dumps, desired))
    return current == desired


def visible_drift(current, desired, write_only, path_keys=()):
    """Desired keys (``fields.<name>`` for Servarr fields) whose current value differs."""

    skip = set(write_only)
    paths = set(path_keys)
    keys = []
    for key, value in desired.items():
        if key == "fields":
            have = fields_map(current)
            for name, item in value.items():
                full = "fields." + name
                if full not in skip and not same(have.get(name), item, full in paths):
                    keys.append(full)
        elif key not in skip and not same(current.get(key), value, key in paths):
            keys.append(key)
    return keys


def write_only_values(desired, write_only):
    values = {}
    for name in write_only:
        top, sub = split(name)
        if sub is None:
            if top in desired:
                values[name] = desired[top]
        elif top == "fields" and sub in (desired.get("fields") or {}):
            values[name] = desired["fields"][sub]
    return values


def digest(values):
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def merged(base, desired):
    """``base`` (the current object or a schema entry) with the desired subset written in."""

    out = json.loads(json.dumps(base))
    for key, value in desired.items():
        if key == "fields":
            fields = out.setdefault("fields", [])
            index = {f.get("name"): f for f in fields if isinstance(f, dict)}
            for name, item in value.items():
                if name in index:
                    index[name]["value"] = item
                else:
                    fields.append({"name": name, "value": item})
        else:
            out[key] = value
    return out


# -- write-only digests ------------------------------------------------------------


class State:
    """``{name: digest}`` of the write-only values last written, in ``path`` (root 0600)."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as handle:
                self.data = json.load(handle)
        except (OSError, ValueError):
            self.data = {}

    @staticmethod
    def key(*parts):
        """An unambiguous key for a step (and item): JSON, so no name can collide with another."""

        return json.dumps([str(p) for p in parts])

    def stale(self, key, values):
        return bool(values) and self.data.get(key) != digest(values)

    def record(self, key, values):
        if values:
            self.data[key] = digest(values)

    def save(self):
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, sort_keys=True)
        os.replace(tmp, self.path)


# -- tags --------------------------------------------------------------------------


def tag_ids(api, tags_path, labels, *, create):
    """Ids of ``labels`` (created when missing and ``create``); ``None`` for a missing one otherwise."""

    known = {t.get("label"): t.get("id") for t in api.get(tags_path) or []}
    ids = []
    for label in labels:
        if label not in known:
            if not create:
                return None
            made = api.send("POST", tags_path, {"label": label})
            known[label] = (made or {}).get("id")
            if known[label] is None:
                raise Fail("POST " + tags_path + " returned no id")
        ids.append(known[label])
    return ids


def with_tags(api, req, desired, *, create):
    if "tags" not in desired or not req.get("tags_path"):
        return desired
    if not all(isinstance(t, str) for t in desired["tags"]):
        return desired
    ids = tag_ids(api, req["tags_path"], desired["tags"], create=create)
    out = dict(desired)
    out["tags"] = ids if ids is not None else ["missing tag"]
    return out


# -- settings ------------------------------------------------------------------------


def settings(req, apply):
    api = Api(req)
    path = req["path"]
    if apply:
        api.wait(path, req["wait"])
    desired = host_value(req["desired"])
    state = State(req["state"])
    secret = write_only_values(desired, req["write_only"])
    current = api.get(path)
    names = visible_drift(current, desired, req["write_only"], req.get("path_keys", ()))
    if state.stale(State.key(req["name"]), secret):
        names.append("write_only")
    if not apply:
        print("drift " + " ".join(names) if names else "current")
        return
    if not names:
        print("noop")
        return
    target = path + "/" + str(current["id"]) if "id" in current else path
    api.send("PUT", target, merged(current, desired))
    after = api.get(path)
    left = visible_drift(after, desired, req["write_only"], req.get("path_keys", ()))
    if left:
        raise Fail("settings did not apply: " + " ".join(left))
    state.record(State.key(req["name"]), secret)
    state.save()
    print("changed")


# -- items ---------------------------------------------------------------------------


def items(req, apply):
    api = Api(req)
    path = req["path"]
    match = req["match"]
    if apply:
        api.wait(path, req["wait"])
    state = State(req["state"])
    query = "?forceSave=true" if req.get("force_save") else ""
    existing = {i.get(match): i for i in api.get(path) or [] if isinstance(i, dict)}
    schema = None
    names = []
    changed = False
    for raw in req["items"]:
        desired = host_value(raw)
        key = desired[match]
        label = str(key)
        secret = write_only_values(desired, req["write_only"])
        stale = state.stale(State.key(req["name"], label), secret)
        current = existing.get(key)
        resolved = with_tags(api, req, desired, create=apply)
        if current is None:
            names.append(label + ":missing")
        else:
            drift = visible_drift(current, resolved, req["write_only"], req.get("path_keys", ()))
            names += [label + ":" + d for d in drift]
            if stale:
                names.append(label + ":write_only")
        if not apply:
            continue
        if current is None:
            base = {}
            if req.get("schema"):
                if schema is None:
                    schema = api.get(req["schema"]["path"]) or []
                skey = req["schema"]["key"]
                base = next((s for s in schema if s.get(skey) == resolved.get(skey)), None)
                if base is None:
                    raise Fail("GET " + req["schema"]["path"] + " has no entry for " + label)
                base = {k: v for k, v in base.items() if k != "id"}
            api.send("POST", path, merged(base, resolved), query)
        elif drift or stale:
            api.send("PUT", path + "/" + str(current["id"]), merged(current, resolved), query)
        else:
            continue
        changed = True
        state.record(State.key(req["name"], label), secret)
    if not apply:
        print("drift " + " ".join(names) if names else "current")
        return
    after = {i.get(match): i for i in api.get(path) or [] if isinstance(i, dict)}
    left = []
    for raw in req["items"]:
        desired = with_tags(api, req, host_value(raw), create=False)
        found = after.get(desired[match])
        if found is None:
            left.append(str(desired[match]) + ":missing")
        else:
            left += [str(desired[match]) + ":" + d for d in visible_drift(found, desired, req["write_only"], req.get("path_keys", ()))]
    if left:
        raise Fail("items did not apply: " + " ".join(left))
    if changed:
        state.save()
    print("changed" if changed else "noop")


def main():
    mode = sys.argv[1]
    req = json.loads(base64.b64decode(sys.stdin.read()))
    try:
        kind, _, action = mode.partition("-")
        if kind == "settings" and action in ("probe", "apply"):
            settings(req, action == "apply")
        elif kind == "items" and action in ("probe", "apply"):
            items(req, action == "apply")
        else:
            raise Fail("unknown mode " + mode)
    except Fail as exc:
        sys.stderr.write(req.get("name", "http_json") + ": " + str(exc) + "\n")
        sys.exit(1)


main()
