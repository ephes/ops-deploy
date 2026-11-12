"""Syntactically valid PEM blocks for the NFS/tlshd tests (not real keys or certificates)."""

from __future__ import annotations

from pydantic import SecretStr

from ops_deploy.base.tlshd import TlshdConfig


def block(label: str, filler: str) -> str:
    body = "\n".join([f"MII{filler}" + "A" * 61] * 3)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


CA = block("CERTIFICATE", "Bca")
SERVER_CERT = block("CERTIFICATE", "Bsv")
CLIENT_CERT = block("CERTIFICATE", "Bcl")
# The key filler is a marker the leak assertions search for.
KEY_MARKER = "KeyMarkerZq"
KEY = block("PRIVATE" + " KEY", KEY_MARKER)


def tls(role: str = "server") -> TlshdConfig:
    return TlshdConfig.model_validate(
        {
            "role": role,
            "ca_certificate": CA,
            "certificate": SERVER_CERT if role == "server" else CLIENT_CERT,
            "private_key": SecretStr(KEY),
        }
    )
