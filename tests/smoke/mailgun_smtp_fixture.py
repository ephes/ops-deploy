# mypy: ignore-errors
"""Owned loopback SMTP/STARTTLS/AUTH sink. Only synthetic fixture messages enter it."""

import base64
import json
import pathlib
import socket
import socketserver
import ssl
import sys


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        tls = False
        authenticated = False
        sender = None
        recipients = []

        def reply(line):
            self.wfile.write((line + "\r\n").encode())
            self.wfile.flush()

        reply("220 localhost owned fixture")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode().rstrip("\r\n")
            verb, _, args = text.partition(" ")
            verb = verb.upper()
            if verb == "EHLO":
                reply("250-localhost")
                if not tls:
                    reply("250-STARTTLS")
                reply("250-AUTH PLAIN")
                reply("250 8BITMIME")
            elif verb == "STARTTLS":
                reply("220 begin TLS")
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(ROOT / "cert.pem"), str(ROOT / "key.pem"))
                try:
                    self.connection = context.wrap_socket(self.connection, server_side=True)
                except (ssl.SSLError, ConnectionError):
                    return
                self.rfile = self.connection.makefile("rb")
                self.wfile = self.connection.makefile("wb")
                tls = True
            elif verb == "AUTH":
                if not tls:
                    reply("538 TLS required")
                else:
                    method, _, data = args.partition(" ")
                    if not data:
                        reply("334 ")
                        data = self.rfile.readline().strip().decode()
                    authenticated = method.upper() == "PLAIN" and base64.b64decode(data).split(b"\0")[-2:] == [
                        b"fixture@example.test",
                        b"fixture-pass",
                    ]
                    reply("235 authenticated" if authenticated else "535 invalid fixture credentials")
            elif verb == "MAIL":
                sender = args
                recipients = []
                reply("250 sender" if authenticated else "530 authentication required")
            elif verb == "RCPT":
                scenario = (ROOT / "scenario").read_text().strip()
                if scenario == "temporary":
                    reply("450 fixture temporary rejection")
                elif scenario == "permanent":
                    reply("550 fixture permanent rejection")
                else:
                    recipients.append(args)
                    reply("250 recipient")
            elif verb == "DATA":
                reply("354 data")
                data = []
                while True:
                    line = self.rfile.readline()
                    if line in (b".\r\n", b""):
                        break
                    data.append(line[1:] if line.startswith(b"..") else line)
                with (ROOT / "records.jsonl").open("a") as output:
                    output.write(
                        json.dumps(
                            {
                                "sender": sender,
                                "recipients": recipients,
                                "tls": tls,
                                "auth": authenticated,
                                "data": b"".join(data).decode(),
                            }
                        )
                        + "\n"
                    )
                reply("250 queued-owned-fixture")
            elif verb == "QUIT":
                reply("221 bye")
                return
            elif verb in ("RSET", "NOOP"):
                reply("250 ok")
            else:
                reply("500 unsupported fixture command")


if __name__ == "__main__":
    ROOT = pathlib.Path(sys.argv[1])

    class Server(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET
        allow_reuse_address = True
        daemon_threads = True

    with Server(("127.0.0.1", int(sys.argv[2])), Handler) as server:
        server.serve_forever()
