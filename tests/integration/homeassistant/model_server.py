"""Owned loopback model protocol only: fixed synthetic response, no prompt logs."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MODEL = "owned-native-model"


class ModelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port: int):
        super().__init__(("127.0.0.1", port), Handler)
        self.guard = threading.Lock()
        self.calls = {"models": 0, "completions": 0, "streaming": 0}
        self.fault = "normal"


class Handler(BaseHTTPRequestHandler):
    server: ModelServer

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Never retain request URL, headers, credentials or prompt body.

    def reply(self, body: Any, code: int = 200) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path == "/owned/status":
            with self.server.guard:
                self.reply(dict(self.server.calls))
            return
        if self.path not in {"/models", "/v1/models"}:
            self.reply({"error": "unknown-owned-route"}, 404)
            return
        with self.server.guard:
            self.server.calls["models"] += 1
            fault = self.server.fault
        if fault == "unauthorized":
            self.reply({"error": {"message": "owned refusal", "type": "authentication_error"}}, 401)
        else:
            self.reply(
                {"object": "list", "data": [{"id": MODEL, "object": "model", "created": 0, "owned_by": "owned"}]}
            )

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024 * 1024:
                raise ValueError
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, TypeError):
            self.reply({"error": "invalid-owned-request"}, 400)
            return
        if self.path == "/owned/fault":
            if set(body) != {"mode"} or body["mode"] not in {"normal", "unauthorized", "empty"}:
                self.reply({"error": "invalid-owned-fault"}, 400)
                return
            with self.server.guard:
                self.server.fault = body["mode"]
            self.reply({"selected": True})
            return
        if self.path not in {"/chat/completions", "/v1/chat/completions"}:
            self.reply({"error": "unknown-owned-route"}, 404)
            return
        if body.get("model") != MODEL or not isinstance(body.get("messages"), list):
            self.reply({"error": {"message": "unknown owned model or input", "type": "invalid_request_error"}}, 400)
            return
        stream = body.get("stream") is True
        with self.server.guard:
            self.server.calls["completions"] += 1
            self.server.calls["streaming"] += int(stream)
            fault = self.server.fault
        if fault == "unauthorized":
            self.reply({"error": {"message": "owned refusal", "type": "authentication_error"}}, 401)
            return
        text = "" if fault == "empty" else "OK"
        metadata = {"id": "chatcmpl-owned", "created": 0, "model": MODEL}
        if not stream:
            self.reply(
                {
                    **metadata,
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": text, "refusal": None},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            )
            return
        chunks = [
            {"role": "assistant", "content": ""},
            {"content": text},
            {},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        for index, delta in enumerate(chunks):
            event = {
                **metadata,
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "index": 0,
                        "delta": delta,
                        "finish_reason": "stop" if index == 2 else None,
                    }
                ],
            }
            self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


if __name__ == "__main__":
    with ModelServer(18081) as server:
        server.serve_forever()
