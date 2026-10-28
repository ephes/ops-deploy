"""Bounded target-local Tailscale metadata/preferences; never emit raw status/prefs.

The native qualification binds LocalAPI's sanitized Prefs result to Tailscale
1.104.2/c3430f0d2b8a1d646ad3ae867e3470bac07f1fe0. Only CorpDNS/RouteAll leave
this process. No state file, private key, peer list or user profile is exported.
"""

import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

MAX_REPLY = 1024 * 1024


class Refused(Exception):
    pass


def command(argv):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused("native Tailscale command unavailable or timed out") from error
    if len(proc.stdout) > MAX_REPLY or len(proc.stderr) > MAX_REPLY:
        raise Refused("native command exceeded bounded output")
    # A failing status can describe a genuine non-running backend (exit1).
    if proc.returncode not in (0, 1):
        raise Refused("native Tailscale command failed")
    return proc.returncode, proc.stdout


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, path):
        # Exact LocalAPI Host value, required by the native anti-rebinding check.
        super().__init__("local-tailscaled.sock", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        try:
            self.sock.connect(self.path)
        except BaseException:
            self.sock.close()
            raise


def socket_metadata(path):
    target = Path(path)
    for parent in target.parents:
        try:
            link = parent.lstat()
            info = parent.stat()
        except FileNotFoundError:
            continue
        if (
            link.st_uid != 0
            or info.st_uid != 0
            or not stat.S_ISDIR(info.st_mode)
            or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)
        ):
            raise Refused("Tailscale LocalAPI socket ancestor is untrusted")
    try:
        info = target.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise Refused("Tailscale LocalAPI socket is not the root-owned native socket")
    return True


def selected_prefs(path):
    if not socket_metadata(path):
        raise Refused("Tailscale LocalAPI socket unavailable")
    conn = LocalConnection(path)
    try:
        conn.request("GET", "/localapi/v0/prefs")
        reply = conn.getresponse()
        if reply.status != 200:
            raise Refused("Tailscale LocalAPI preference read failed")
        body = reply.read(MAX_REPLY + 1)
        if len(body) > MAX_REPLY:
            raise Refused("Tailscale LocalAPI exceeded bounded reply")
        value = json.loads(body)
        del body
        if not isinstance(value, dict) or any(type(value.get(key)) is not bool for key in ("CorpDNS", "RouteAll")):
            raise Refused("Tailscale selected preference schema is unsupported")
        selected = {key: value[key] for key in ("CorpDNS", "RouteAll")}
        del value
        return selected
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise Refused("Tailscale LocalAPI preference read unavailable or malformed") from error
    finally:
        conn.close()


def cli(config, *arguments):
    return [config["binary"], "--socket=" + config["socket"], *arguments]


def inspect(config):
    binary = config["binary"]
    code, text = command(cli(config, "version"))
    if code or not text.strip() or len(text) > 4096:
        raise Refused("native Tailscale version could not be established")
    version = text.splitlines()[0].strip()
    if not version or any(not (char.isalnum() or char in ".-+") for char in version):
        raise Refused("native Tailscale version answered unexpectedly")
    present = socket_metadata(config["socket"])
    code, text = command(cli(config, "status", "--json"))
    try:
        status = json.loads(text)
    except ValueError as error:
        if code == 1 and not text.strip() and not present:
            return {"version": version, "backend": "Unavailable", "selected": None, "needed": None, "available": False}
        raise Refused("Tailscale backend status is malformed") from error
    del text
    if not isinstance(status, dict) or not isinstance(status.get("BackendState"), str):
        raise Refused("Tailscale backend state is unavailable")
    backend = status["BackendState"]
    del status  # No peer/user profile from the status reaches the controller.
    if code and backend == "Running":
        raise Refused("Tailscale backend result contradicts its state")
    selected = selected_prefs(config["socket"]) if backend == "Running" else None
    desired = {"CorpDNS": config["accept_dns"], "RouteAll": config["accept_routes"]}
    if any(type(value) is not bool for value in desired.values()):
        raise Refused("desired Tailscale preferences must be booleans")
    return {
        "available": True,
        "version": version,
        "backend": backend,
        "selected": selected,
        "needed": selected is not None and selected != desired,
    }


def main():
    if os.geteuid() != 0:
        raise Refused("Tailscale metadata/preferences require the existing root connection")
    mode = sys.argv[1]
    if mode not in ("check", "verify", "ipv4", "apply-prefs", "join", "force-join"):
        raise Refused("unknown Tailscale metadata action")
    config = json.load(sys.stdin)
    before = inspect(config)
    if not before["available"] and mode != "check":
        raise Refused("native Tailscale daemon still unavailable after service prerequisite")
    if mode == "ipv4":
        code, text = command(cli(config, "ip", "-4"))
        rows = text.splitlines()
        if code or not rows:
            raise Refused("native Tailscale IPv4 address unavailable")
        address = ipaddress.IPv4Address(rows[0].strip())
        print(json.dumps({"address": str(address)}))
        return
    changed = False
    if (
        mode in ("join", "force-join")
        and (before["backend"] != "Running" or mode == "force-join")
        and not config["manual_up"]
    ):
        key = config.get("auth_key")
        if (
            not isinstance(key, str)
            or not key
            or key.lower() in ("changeme", "placeholder", "example")
            or any(ord(c) < 32 for c in key)
        ):
            raise Refused("non-manual join requires a non-placeholder private auth key")
        descriptor, path = tempfile.mkstemp(suffix=".tailscale-auth-key")
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(key)
            # The only durable credential material is this private one-use
            # 0600 target-local file, matching the original native join role.
            del key
            argv = cli(
                config,
                "up",
                "--hostname=" + config["hostname"],
                "--accept-dns=" + str(config["accept_dns"]).lower(),
                "--accept-routes=" + str(config["accept_routes"]).lower(),
            )
            if config["exit_node"]:
                argv.append("--exit-node=" + config["exit_node"])
            if config["advertise_exit_node"]:
                argv.append("--advertise-exit-node")
            argv.extend(config["args_extra"])
            argv.append("--auth-key=file:" + path)
            try:
                result = subprocess.run(argv, capture_output=True, timeout=120)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise Refused("native private-file Tailscale join unavailable or timed out") from error
            if result.returncode:
                # Never relay native stderr: it may contain user/credential
                # details. Exit failure remains visible and fatal.
                raise Refused("native private-file Tailscale join failed")
        finally:
            os.unlink(path)
        after = inspect(config)
        if after["backend"] != "Running":
            raise Refused("native Tailscale join did not reach Running")
        changed = True
    elif mode == "apply-prefs" and before["needed"]:
        desired = [
            "--accept-dns=" + str(config["accept_dns"]).lower(),
            "--accept-routes=" + str(config["accept_routes"]).lower(),
        ]
        code, _ = command(cli(config, "set", *desired))
        if code:
            raise Refused("Tailscale preference update failed")
        changed = True
        after = inspect(config)
        if after["backend"] != "Running" or after["needed"]:
            raise Refused("Tailscale preference update did not converge")
    else:
        after = before
    print(json.dumps({**after, "changed": changed}))


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        print(
            json.dumps(
                {"refused": str(error) if isinstance(error, Refused) else "native Tailscale metadata/payload failed"}
            )
        )
        raise SystemExit(2) from None
