#!/usr/bin/env python3
"""Minimal read-only HTTP server managed by Ansible."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class StaticHandler(SimpleHTTPRequestHandler):
    timeout = 10

    def list_directory(self, path):
        self.send_error(404, "Directory listing is disabled")
        return None

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        super().end_headers()

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}", flush=True)


if __name__ == "__main__":
    handler = partial(StaticHandler, directory="/srv/static-sites/static-site")
    server = ThreadingHTTPServer(("127.0.0.1", 10061), handler)
    server.serve_forever()
