"""Synthetic existing Thread dataset on loopback; no radio/network commissioning."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def dataset() -> str:
    # Public, synthetic test values only. Types are MeshCoP TLVs consumed by
    # python-otbr-api3.0.0. Existing dataset deliberately avoids creation/enable.
    values = {
        0: bytes.fromhex("00000f"),
        1: bytes.fromhex("1234"),
        2: bytes.fromhex("1122334455667788"),
        3: b"OwnedNative",
        4: b"A" * 16,
        5: b"B" * 16,
        7: bytes.fromhex("fd00112233445566"),
        12: bytes.fromhex("02a0f7f8"),
        14: bytes.fromhex("0000000000010000"),
        53: bytes.fromhex("0004001fffe0"),
    }
    return b"".join(bytes((kind, len(value))) + value for kind, value in values.items()).hex()


class OtbrServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port: int):
        super().__init__(("127.0.0.1", port), Handler)
        self.guard = threading.Lock()
        self.reads = 0
        self.writes = 0


class Handler(BaseHTTPRequestHandler):
    server: OtbrServer

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def reply(self, data: Any, *, status: int = 200, plain: bool = False) -> None:
        body = (str(data) if plain else json.dumps(data)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain" if plain else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/owned/status":
            with self.server.guard:
                self.reply({"reads": self.server.reads, "writes": self.server.writes})
            return
        with self.server.guard:
            self.server.reads += 1
        if self.path == "/api/actions":
            self.reply([])
        elif self.path == "/.well-known/thread/br-rest":
            self.reply({"api": {"version": "1.0.0"}})
        elif self.path == "/node/ba-id":
            self.reply("00112233445566778899aabbccddeeff")
        elif self.path == "/node/ext-address":
            self.reply("1122334455667788")
        elif self.path == "/node/coprocessor/version":
            self.reply("OPENTHREAD/owned-native-synthetic")
        elif self.path == "/node/dataset/active" and self.headers.get("Accept") == "text/plain":
            self.reply(dataset(), plain=True)
        else:
            self.reply({"error": "unsupported-owned-route"}, status=404)

    def do_PUT(self) -> None:
        with self.server.guard:
            self.server.writes += 1
        self.reply({"error": "owned-existing-dataset-must-not-be-mutated"}, status=405)

    do_POST = do_PUT
    do_DELETE = do_PUT


if __name__ == "__main__":
    with OtbrServer(18082) as server:
        server.serve_forever()
