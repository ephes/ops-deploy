"""Synthetic loopback Wyoming1.10.2 Describe/Info; no audio or hardware claim."""

from __future__ import annotations

import json
import socket
import socketserver
import threading
from typing import Any


def artifact(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "attribution": {"name": "Owned fixture", "url": "http://127.0.0.1/"},
        "installed": True,
        "description": "Synthetic protocol fixture",
        "version": "1",
    }


INFO = {
    "asr": [{**artifact("owned-native-stt"), "models": [{**artifact("owned-native-stt-model"), "languages": ["en"]}]}],
    "tts": [{**artifact("owned-native-tts"), "voices": [{**artifact("owned-native-voice"), "languages": ["en"]}]}],
}


class WyomingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, port: int):
        super().__init__(("127.0.0.1", port), Handler)
        self.guard = threading.Lock()
        self.describe_count = 0
        self.unexpected_count = 0

    def handle_error(self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any) -> None:
        # Never print payloads or peer details. The count remains observable.
        with self.guard:
            self.unexpected_count += 1


class Handler(socketserver.StreamRequestHandler):
    server: WyomingServer

    def handle(self) -> None:
        self.request.settimeout(15)
        for _ in range(32):
            header = self.rfile.readline(65537)
            if not header:
                return
            if len(header) > 65536:
                raise ValueError("oversized owned Wyoming header")
            value = json.loads(header)
            data_length = value.get("data_length", 0)
            payload_length = value.get("payload_length", 0)
            if type(data_length) is not int or not 0 <= data_length <= 65536 or payload_length:
                raise ValueError("unsupported owned Wyoming payload")
            if data_length:
                data = self.rfile.read(data_length)
                if len(data) != data_length:
                    raise ValueError("incomplete owned Wyoming data")
                json.loads(data)
            if value.get("type") == "select-program":
                continue
            if value.get("type") != "describe":
                raise ValueError("owned Wyoming fixture supports describe only")
            with self.server.guard:
                self.server.describe_count += 1
            # The protocol accepts inline data as well as data_length frames.
            self.wfile.write((json.dumps({"type": "info", "version": "1.10.2", "data": INFO}) + "\n").encode())
            self.wfile.flush()


if __name__ == "__main__":
    with WyomingServer(10300) as server:
        server.serve_forever()
