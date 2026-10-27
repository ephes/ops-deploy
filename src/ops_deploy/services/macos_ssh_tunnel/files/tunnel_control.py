#!/usr/bin/env python3
"""Control one user LaunchAgent and check its forwarded HTTPS endpoint."""

from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=20)


class Tunnel:
    def __init__(self, config: dict):
        # Ansible before 2.19 can serialize templated numbers as JSON strings.
        self.config = dict(config)
        self.config["local_port"] = int(config["local_port"])
        self.config["health_status"] = int(config["health_status"])
        if not isinstance(config["ignore_ssl_errors"], bool):
            raise ValueError("ignore_ssl_errors must be a JSON boolean")
        self.domain = f"gui/{os.getuid()}"
        self.service = f"{self.domain}/{config['label']}"

    def loaded(self) -> bool:
        return run("/bin/launchctl", "print", self.service, check=False).returncode == 0

    def stop(self) -> None:
        # Disable before unloading so logout/login cannot undo an explicit stop.
        run("/bin/launchctl", "disable", self.service)
        if self.loaded():
            # bootout can report an in-progress/already-unloaded race. The
            # observed final state, rather than that exit code alone, decides.
            run("/bin/launchctl", "bootout", self.service, check=False)
            deadline = time.monotonic() + 10
            while self.loaded():
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Tunnel did not unload; inspect launchctl status."
                    )
                time.sleep(0.1)
        print("Tunnel stopped; automatic login start is disabled.")

    def start(self) -> None:
        if self.loaded():
            run("/bin/launchctl", "enable", self.service)
            print("Tunnel is already loaded. Use check to verify backend reachability.")
            return
        # Never adopt or kill an existing listener, even if it looks like SSH.
        with socket.socket() as listener:
            # Match OpenSSH: TIME_WAIT from earlier traffic is not a listener.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.config["local_port"]))
        run("/bin/launchctl", "enable", self.service)
        try:
            run("/bin/launchctl", "bootstrap", self.domain, self.config["plist"])
        except Exception:
            run("/bin/launchctl", "disable", self.service, check=False)
            raise
        print("Tunnel started; it will reconnect while enabled, including after login.")

    def restart(self) -> None:
        self.stop()
        # stop waits for launchd to unload, then allow its listener to drain.
        for attempt in range(30):
            try:
                self.start()
                return
            except OSError:
                if attempt == 29:
                    raise
                time.sleep(0.1)

    def status(self) -> None:
        result = run("/bin/launchctl", "print", self.service, check=False)
        print(result.stdout or result.stderr, end="")
        print(f"SSH log: {self.config['stderr_log']}")
        if result.returncode:
            raise RuntimeError("Tunnel is not loaded. Run start first.")

    def check(self, transport_only: bool = False) -> None:
        if not self.loaded():
            raise RuntimeError("Tunnel is not loaded. Run start first.")
        print("LaunchAgent: loaded")
        host = self.config["https_host"]
        if not transport_only:
            routing_error = (
                f"Hostname routing is not ready: {host} "
                "must resolve only to 127.0.0.1. "
                "Run hosts setup; use check --transport-only to test SSH."
            )
            try:
                addresses = {a[4][0] for a in socket.getaddrinfo(host, None)}
            except socket.gaierror as exc:
                raise RuntimeError(routing_error) from exc
            if addresses != {"127.0.0.1"}:
                raise RuntimeError(routing_error)
            print("Hostname routing: loopback")
        if self.config["ignore_ssl_errors"]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            print("TLS: certificate verification DISABLED by configuration")
        else:
            context = ssl.create_default_context(
                cafile=self.config.get("ca_file") or None
            )
        # Connect directly to loopback regardless of proxy environment variables.
        # SNI and HTTP Host retain the upstream hostname, not localhost.
        with socket.create_connection(
            ("127.0.0.1", self.config["local_port"]), 10
        ) as raw:
            with context.wrap_socket(raw, server_hostname=host) as stream:
                stream.sendall(
                    f"GET {self.config['health_path']} HTTP/1.1\r\n"
                    f"Host: {host}:{self.config['local_port']}\r\n"
                    "Connection: close\r\n\r\n".encode("ascii")
                )
                response = http.client.HTTPResponse(stream)
                response.begin()
                status = response.status
                response.close()
        if status != self.config["health_status"]:
            raise RuntimeError(f"HTTPS health check returned HTTP {status}")
        print(f"HTTPS through SSH: HTTP {status}")
        if transport_only:
            print("Transport only: local hostname routing was NOT checked.")
        print("This checks connectivity, not application signing credentials.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "action", choices=["start", "stop", "restart", "status", "check"]
    )
    parser.add_argument("--transport-only", action="store_true")
    args = parser.parse_args()
    if args.transport_only and args.action != "check":
        parser.error("--transport-only applies only to check")
    try:
        config = json.loads(args.config.read_text())
        tunnel = Tunnel(config)
        # Serialize interactive lifecycle actions. launchd owns the SSH process;
        # this lock does not need to span that process's lifetime.
        with args.config.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == "check":
                tunnel.check(args.transport_only)
            else:
                getattr(tunnel, args.action)()
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
        http.client.HTTPException,
    ) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr.strip(), file=sys.stderr)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
