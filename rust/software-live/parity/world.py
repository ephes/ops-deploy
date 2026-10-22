"""The container world of the software-live parity harness (PLAN.md 6.2).

The ``collect`` cases run the Python program and the Rust binary on one
real host: a throwaway ``ubuntu:24.04`` or ``debian:13`` container after
``software-live-apt/container/setup-world.sh`` (the image's real APT lists
plus the fake repositories, ``docker-clean`` removed, 13.6). This module
builds the rest of that host:

- a fake ELF ``traefik`` (``parity/fakeproc.c``, printing ``Version:
  3.7.9``) installed at ``/usr/local/bin/traefik`` and started as a
  process, whose PID a ``systemctl`` shim early in ``PATH`` reports as the
  ``MainPID`` of ``traefik.service``;
- a fake ELF ``postgres`` at ``/usr/lib/postgresql/17/bin/postgres``
  (``postgres (PostgreSQL) 17.6``), started as a process with its PID in
  ``/var/run/postgresql/17-main.pid``, and a ``/usr/bin/pg_lsclusters``
  shim printing what the case sets;
- the upstream servers: ``api.github.com`` and ``endoflife.date`` resolve
  to 127.0.0.1 through ``/etc/hosts``, where an HTTPS server answers with a
  certificate of a throwaway CA added to the container's system trust
  store (``update-ca-certificates``). Both programs keep their real URLs,
  their real TLS stacks and the system store; no test-only override exists
  in either program.

Everything is undone in ``close()``. Run as root in a throwaway container
only: it changes ``/etc/hosts``, the trust store and ``/usr``.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

PARITY = Path(__file__).resolve().parent
UPSTREAM_HOSTS = ("api.github.com", "endoflife.date")
HOSTS_FILE = Path("/etc/hosts")
CA_TARGET = Path("/usr/local/share/ca-certificates/software-live-parity.crt")
TRAEFIK = Path("/usr/local/bin/traefik")
OTHER_TRAEFIK = Path("/usr/bin/traefik")
TRAEFIK_VERSION = "3.7.9"
PG_MAJOR = "17"
PG_VERSION = "17.6"
POSTGRES = Path(f"/usr/lib/postgresql/{PG_MAJOR}/bin/postgres")
PG_LSCLUSTERS = Path("/usr/bin/pg_lsclusters")
PG_RUN = Path("/var/run/postgresql")
PG_PID = PG_RUN / f"{PG_MAJOR}-main.pid"
CLUSTER_MAIN = f"{PG_MAJOR} main 5432 online postgres /var/lib/postgresql/{PG_MAJOR}/main /var/log/postgresql/postgresql-{PG_MAJOR}-main.log"
CLUSTER_EXTRA = "16 legacy 5433 down postgres /var/lib/postgresql/16/legacy /var/log/postgresql/postgresql-16-legacy.log"

RELEASE_PATH = "/repos/traefik/traefik/releases/latest"
UPSTREAM_RELEASE = {
    "tag_name": "v3.7.10",
    "name": "v3.7.10",
    "draft": False,
    "prerelease": False,
}
# endoflife.date answers as of the parity runs (2026): the first cycle is the
# newest; a malformed cycle is skipped by both programs.
LIFECYCLE = {
    "ubuntu": [
        {
            "cycle": "26.04",
            "codename": "Resolute Raccoon",
            "lts": True,
            "releaseDate": "2026-04-23",
            "support": "2031-05-29",
            "eol": "2036-04-23",
            "latest": "26.04",
        },
        {
            "cycle": "25.10",
            "lts": False,
            "releaseDate": "2025-10-09",
            "support": "2026-07-09",
            "eol": "2026-07-09",
            "latest": "25.10",
        },
        {"cycle": "24.10", "eol": "not a date"},
        {
            "cycle": "24.04",
            "codename": "Noble Numbat",
            "lts": True,
            "releaseDate": "2024-04-25",
            "support": "2029-05-31",
            "eol": "2034-04-25",
            "latest": "24.04.3",
        },
    ],
    "debian": [
        {
            "cycle": "13",
            "codename": "Trixie",
            "releaseDate": "2025-08-09",
            "support": "2028-08-09",
            "eol": "2030-06-30",
            "latest": "13.1",
        },
        {"cycle": 12.5, "eol": "2026-06-10"},
        {
            "cycle": "12",
            "codename": "Bookworm",
            "releaseDate": "2023-06-10",
            "support": "2026-06-10",
            "eol": "2028-06-30",
            "latest": "12.12",
        },
    ],
    "postgresql": [
        {
            "cycle": "18",
            "releaseDate": "2025-09-25",
            "eol": "2030-11-14",
            "latest": "18.1",
        },
        {
            "cycle": PG_MAJOR,
            "releaseDate": "2024-09-26",
            "eol": "2029-11-08",
            "latest": "17.7",
        },
        {
            "cycle": "16",
            "releaseDate": "2023-09-14",
            "eol": "2028-11-09",
            "latest": "16.11",
        },
    ],
}

SYSTEMCTL_SHIM = """#!/bin/sh
# software-live parity: `systemctl show traefik.service --property=MainPID --value`
if [ "$#" -eq 4 ] && [ "$1" = show ] && [ "$2" = traefik.service ] \\
    && [ "$3" = --property=MainPID ] && [ "$4" = --value ]; then
    exec cat {state}/traefik.mainpid
fi
echo "systemctl shim: unsupported arguments: $*" >&2
exit 1
"""
PG_LSCLUSTERS_SHIM = """#!/bin/sh
# software-live parity: `pg_lsclusters --no-header`
if [ "$#" -eq 1 ] && [ "$1" = --no-header ]; then
    exec cat {state}/pg_lsclusters
fi
echo "pg_lsclusters shim: unsupported arguments: $*" >&2
exit 1
"""


class WorldError(Exception):
    pass


def os_release() -> dict[str, str]:
    values = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key] = value.strip().strip('"')
    return values


def in_container() -> bool:
    return (
        Path("/.dockerenv").exists()
        or os.environ.get("SOFTWARE_LIVE_APT_CONTAINER") == "yes"
    )


def check(argv: list[str], **kwargs: Any) -> None:
    result = subprocess.run(
        argv, capture_output=True, text=True, check=False, **kwargs
    )  # noqa: S603
    if result.returncode != 0:
        raise WorldError(
            f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()}"
        )


class Upstream:
    """GitHub and endoflife.date on 127.0.0.1:443 (TLS with the throwaway CA)."""

    def __init__(self, cert: Path, key: Path) -> None:
        self.mode = "ok"  # ok | error | garbage
        self.requests: list[str] = []
        self.lock = threading.Lock()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        upstream = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                host = self.headers.get("Host", "").split(":")[0]
                status, body = upstream.answer(host, self.path)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self) -> tuple[socket.socket, Any]:
                sock, address = self.socket.accept()
                sock.settimeout(10)
                return context.wrap_socket(sock, server_side=True), address

            def handle_error(self, request: Any, client_address: Any) -> None:
                pass

        self.server = Server(("127.0.0.1", 443), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def answer(self, host: str, path: str) -> tuple[int, bytes]:
        with self.lock:
            self.requests.append(f"{host}{path}")
            mode = self.mode
        if host == "api.github.com" and path == RELEASE_PATH:
            body = UPSTREAM_RELEASE
        elif (
            host == "endoflife.date"
            and path.startswith("/api/")
            and path.endswith(".json")
        ):
            product = path[len("/api/") : -len(".json")]
            if product not in LIFECYCLE:
                return 404, b'{"error": "not found"}'
            body = LIFECYCLE[product]
        else:
            return 404, b'{"error": "not found"}'
        if mode == "error":
            return 503, b'{"message": "unavailable"}'
        if mode == "garbage":
            return 200, b"<html>not json</html>"
        return 200, json.dumps(body).encode()

    def take_requests(self) -> list[str]:
        with self.lock:
            taken, self.requests = self.requests, []
        return taken

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class World:
    def __init__(self, work: Path) -> None:
        if os.geteuid() != 0 or not in_container():
            raise WorldError(
                "the collect world runs as root in a throwaway container only"
            )
        self.work = work
        self.state = work / "world"
        self.shims = work / "shims"
        self.binaries = work / "binaries"
        self.release = os_release()
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self.undo: list[tuple[str, Any]] = []
        self.upstream: Upstream | None = None
        self.hosts_backup: bytes | None = None

    # ---------------------------------------------------------------- setup

    def setup(self) -> None:
        for path in (
            TRAEFIK,
            OTHER_TRAEFIK,
            POSTGRES,
            PG_LSCLUSTERS,
            PG_PID,
            CA_TARGET,
        ):
            if path.exists() or path.is_symlink():
                raise WorldError(f"{path} exists: not a fresh container")
        for directory in (self.state, self.shims, self.binaries):
            directory.mkdir(parents=True)
        self.build(
            "traefik-3.7.9",
            f"Version:      {TRAEFIK_VERSION}\nCodename:     parity\nGo version:   go1.25.3\n",
        )
        self.build(
            "traefik-3.7.8",
            "Version:      3.7.8\nCodename:     parity\nGo version:   go1.25.3\n",
        )
        self.build(
            "postgres", f"postgres (PostgreSQL) {PG_VERSION} (parity {PG_VERSION}-1)\n"
        )
        self.shim(self.shims / "systemctl", SYSTEMCTL_SHIM)
        self.install_traefik("traefik-3.7.9")
        self.undo.append(("rm", TRAEFIK))
        POSTGRES.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.binaries / "postgres", POSTGRES)
        POSTGRES.chmod(0o755)
        self.undo.append(("rm", POSTGRES))
        PG_RUN.mkdir(parents=True, exist_ok=True)
        self.undo.append(("rm", PG_PID))
        self.set_clusters(f"{CLUSTER_MAIN}\n{CLUSTER_EXTRA}\n")
        self.undo.append(("rm", PG_LSCLUSTERS))
        self.start_traefik()
        self.start_postgres()
        self.trust()
        self.resolve()

    def build(self, name: str, version_text: str) -> None:
        define = "-DVERSION_TEXT=" + json.dumps(version_text)
        check(
            [
                "gcc",
                "-O2",
                "-o",
                str(self.binaries / name),
                define,
                str(PARITY / "fakeproc.c"),
            ]
        )

    def shim(self, path: Path, template: str) -> None:
        path.write_text(template.replace("{state}", str(self.state)), encoding="utf-8")
        path.chmod(0o755)

    def install_traefik(self, name: str | None) -> None:
        """Replace /usr/local/bin/traefik by rename (a running image stays the old inode)."""
        if name is None:
            TRAEFIK.unlink(missing_ok=True)
            return
        staged = TRAEFIK.with_name(".traefik-parity")
        shutil.copyfile(self.binaries / name, staged)
        staged.chmod(0o755)
        os.replace(staged, TRAEFIK)

    def start_traefik(self) -> None:
        self.stop("traefik")
        self.processes["traefik"] = subprocess.Popen(  # noqa: S603 - the fake server
            [str(TRAEFIK)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.set_main_pid(self.processes["traefik"].pid)
        self.wait_exe(self.processes["traefik"].pid, TRAEFIK)

    def start_postgres(self) -> None:
        self.stop("postgres")
        process = subprocess.Popen(  # noqa: S603 - the fake server
            [str(POSTGRES)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.processes["postgres"] = process
        self.wait_exe(process.pid, POSTGRES)
        PG_PID.write_text(
            f"{process.pid}\n/var/lib/postgresql/{PG_MAJOR}/main\n", encoding="ascii"
        )

    @staticmethod
    def wait_exe(pid: int, path: Path) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if os.readlink(f"/proc/{pid}/exe") == str(path):
                    return
            except OSError:
                pass
            time.sleep(0.01)
        raise WorldError(f"{path} did not start")

    def stop(self, name: str) -> None:
        process = self.processes.pop(name, None)
        if process is not None:
            process.kill()
            process.wait(timeout=10)

    def set_main_pid(self, pid: int) -> None:
        (self.state / "traefik.mainpid").write_text(f"{pid}\n", encoding="ascii")

    def set_clusters(self, text: str | None) -> None:
        """The output of the pg_lsclusters shim; None removes the shim (not installed)."""
        if text is None:
            PG_LSCLUSTERS.unlink(missing_ok=True)
            return
        (self.state / "pg_lsclusters").write_text(text, encoding="utf-8")
        if not PG_LSCLUSTERS.exists():
            self.shim(PG_LSCLUSTERS, PG_LSCLUSTERS_SHIM)

    def trust(self) -> None:
        tls = self.work / "tls"
        tls.mkdir()
        (tls / "ca.cnf").write_text(
            "[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n"
            "[dn]\nCN = software-live parity CA\n"
            "[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n",
            encoding="ascii",
        )
        (tls / "leaf.cnf").write_text(
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = api.github.com\n",
            encoding="ascii",
        )
        (tls / "leaf.ext").write_text(
            "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\n"
            "extendedKeyUsage = serverAuth\nsubjectAltName = DNS:api.github.com,DNS:endoflife.date\n"
            "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n",
            encoding="ascii",
        )
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        check(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                *ec,
                "-config",
                "ca.cnf",
                "-days",
                "2",
                "-keyout",
                "ca.key",
                "-out",
                "ca.crt",
            ],
            cwd=tls,
        )
        check(
            [
                "openssl",
                "req",
                "-new",
                *ec,
                "-config",
                "leaf.cnf",
                "-keyout",
                "leaf.key",
                "-out",
                "leaf.csr",
            ],
            cwd=tls,
        )
        check(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-set_serial",
                "4242",
                "-days",
                "2",
                "-extfile",
                "leaf.ext",
                "-out",
                "leaf.crt",
            ],
            cwd=tls,
        )
        CA_TARGET.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tls / "ca.crt", CA_TARGET)
        self.undo.append(("untrust", CA_TARGET))
        check(["update-ca-certificates"])
        self.upstream = Upstream(tls / "leaf.crt", tls / "leaf.key")

    def resolve(self) -> None:
        self.hosts_backup = HOSTS_FILE.read_bytes()
        line = "127.0.0.1 " + " ".join(UPSTREAM_HOSTS) + "  # software-live parity\n"
        prefix = (
            b"" if self.hosts_backup.endswith(b"\n") or not self.hosts_backup else b"\n"
        )
        # /etc/hosts is a bind mount in Docker: rewrite it in place.
        with HOSTS_FILE.open("ab") as stream:
            stream.write(prefix + line.encode("ascii"))
        for host in UPSTREAM_HOSTS:
            addresses = {
                info[4][0]
                for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            }
            if addresses != {"127.0.0.1"}:
                raise WorldError(
                    f"{host} resolves to {sorted(addresses)}, not 127.0.0.1"
                )

    # ---------------------------------------------------------------- use

    def env(self) -> dict[str, str]:
        """The environment both programs run with (no proxy variables)."""
        return {
            "PATH": f"{self.shims}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "TMPDIR": "/tmp",
            "HOME": "/root",
        }

    def policy(self, **changes: Any) -> dict[str, Any]:
        distro = self.release["ID"]
        policy: dict[str, Any] = {
            "host": "parity",
            "traefik": {
                "expected": True,
                "unit": "traefik.service",
                "binary_path": str(TRAEFIK),
                "desired_version": TRAEFIK_VERSION,
            },
            "os": {
                "expected_id": distro,
                "product": distro,
                "desired_cycle": self.release["VERSION_ID"],
            },
            "postgresql": {
                "expected": True,
                "desired_major": PG_MAJOR,
                "cluster": "main",
                "port": 5432,
            },
            "apt_max_age_seconds": 172800,
        }
        for key, value in changes.items():
            section, _, field = key.partition("__")
            if field:
                policy[section][field] = value
            else:
                policy[section] = value
        return policy

    # ---------------------------------------------------------------- teardown

    def close(self) -> None:
        errors = []
        for name in list(self.processes):
            try:
                self.stop(name)
            except Exception as exc:  # noqa: BLE001 - undo as much as possible
                errors.append(f"stop {name}: {exc}")
        if self.upstream is not None:
            self.upstream.close()
        if self.hosts_backup is not None:
            with HOSTS_FILE.open("wb") as stream:
                stream.write(self.hosts_backup)
        for action, path in reversed(self.undo):
            try:
                if action == "rm":
                    path.unlink(missing_ok=True)
                elif action == "untrust":
                    path.unlink(missing_ok=True)
                    check(["update-ca-certificates", "--fresh"])
            except Exception as exc:  # noqa: BLE001 - undo as much as possible
                errors.append(f"{action} {path}: {exc}")
        if errors:
            raise WorldError("; ".join(errors))


def kill_all(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.send_signal(signal.SIGKILL)
            process.wait(timeout=10)
