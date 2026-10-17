"""qBittorrent WebUI credentials and preferences: ``probe`` reports drift, ``apply`` reconciles.

Run as root: ``python3 -I -c <this file> probe|apply``; the request is JSON,
base64-encoded on stdin (port, username, password, preferences, and for the
first-run bootstrap the compose project, file and service whose log holds the
temporary password). Ported from ops-control's torrent playbook:

- the WebUI is asked with ``Host: localhost`` (host header validation stays on);
- a login succeeds with 204 and no body (qBittorrent 5.2+) or 200 ``Ok.`` (older);
- when the desired login fails, the temporary password from the container
  log logs in as ``admin`` and sets the desired credentials;
- the preferences are compared as a subset (strings without a trailing
  slash), set when they differ, and compared again.

Prints ``current`` or ``drift <keys>`` (probe; ``credentials`` when the
desired login fails), ``changed`` or ``noop`` (apply). Errors name the
endpoint and the status code; no value or response body is ever printed.
The probe only reads (a login opens a session, nothing else).
"""

import base64
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TEMP_PASSWORD = re.compile(r"session: ([A-Za-z0-9]+)")


class Fail(Exception):
    pass


class WebUI:
    def __init__(self, port):
        self.base = "http://127.0.0.1:" + str(port)
        self.cookie = None

    def call(self, path, form=None):
        body = None if form is None else urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(self.base + path, data=body, headers={"Host": "localhost"})
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with OPENER.open(req, timeout=15) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as err:
            return err.code, b"", err.headers
        except (urllib.error.URLError, OSError):
            return None, b"", None

    def ready(self):
        return self.call("/")[0] == 200

    def login(self, username, password):
        status, body, headers = self.call("/api/v2/auth/login", {"username": username, "password": password})
        if not (status == 204 or (status == 200 and body.strip() == b"Ok.")):
            return False
        cookies = headers.get_all("Set-Cookie") or []
        if not cookies:
            raise Fail("POST /api/v2/auth/login set no session cookie")
        self.cookie = cookies[0].split(";", 1)[0].strip()
        return True

    def preferences(self):
        status, body, _ = self.call("/api/v2/app/preferences")
        if status != 200:
            raise Fail("GET /api/v2/app/preferences answered " + str(status))
        return json.loads(body.decode("utf-8"))

    def set_preferences(self, values):
        status, _, _ = self.call("/api/v2/app/setPreferences", {"json": json.dumps(values)})
        if status != 200:
            raise Fail("POST /api/v2/app/setPreferences answered " + str(status))


def norm(value):
    return value.rstrip("/") if isinstance(value, str) and value != "/" else value


def drift(desired, current):
    return sorted(key for key, value in desired.items() if norm(current.get(key)) != norm(value))


def temporary_password(req):
    argv = ["docker", "compose", "-p", req["project"], "-f", req["compose_file"], "logs", "--tail=500", req["service"]]
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    found = TEMP_PASSWORD.findall(result.stdout.decode("utf-8", "replace"))
    if not found:
        raise Fail("no temporary password in the " + req["service"] + " log")
    return found[-1]


def probe(req):
    ui = WebUI(req["port"])
    if not ui.ready():
        raise Fail("the WebUI does not answer 200 at /")
    if not ui.login(req["username"], req["password"]):
        print("drift credentials")
        return
    keys = drift(req["preferences"], ui.preferences())
    print("drift " + " ".join(keys) if keys else "current")


def apply(req):
    ui = WebUI(req["port"])
    deadline = time.monotonic() + req["wait"]
    while not ui.ready():
        if time.monotonic() > deadline:
            raise Fail("the WebUI did not answer 200 at / within " + str(req["wait"]) + " s")
        time.sleep(1)
    changed = False
    if not ui.login(req["username"], req["password"]):
        if not ui.login("admin", temporary_password(req)):
            raise Fail("the temporary password does not log in")
        ui.set_preferences({"web_ui_username": req["username"], "web_ui_password": req["password"]})
        ui.cookie = None
        if not ui.login(req["username"], req["password"]):
            raise Fail("the WebUI credentials did not apply")
        changed = True
    if drift(req["preferences"], ui.preferences()):
        ui.set_preferences(req["preferences"])
        keys = drift(req["preferences"], ui.preferences())
        if keys:
            raise Fail("preferences did not apply: " + " ".join(keys))
        changed = True
    print("changed" if changed else "noop")


def main():
    mode = sys.argv[1]
    req = json.loads(base64.b64decode(sys.stdin.read()))
    try:
        if mode == "probe":
            probe(req)
        elif mode == "apply":
            apply(req)
        else:
            raise Fail("unknown mode " + mode)
    except Fail as exc:
        sys.stderr.write("qbittorrent_preferences: " + str(exc) + "\n")
        sys.exit(1)


main()
