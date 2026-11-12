"""``tlshd`` (``ktls-utils``) for NFS over RPC-with-TLS, trusting one private CA only.

The kernel does RPC-with-TLS itself; ``tlshd`` performs the TLS handshake of
every new connection and hands the session to kernel TLS. ``tlshd`` 0.9 (the
only noble version) has no trust-store option and checks peers against the
system CA bundle, so stock it would accept a certificate from any public CA. A
drop-in binds the private CA file over ``/etc/ssl/certs/ca-certificates.crt``
in ``tlshd``'s own mount namespace: ``tlshd`` alone sees a bundle holding only
that CA, the system bundle stays untouched. Key files must be regular files
(``tlshd`` refuses symlinks). See ``docs/base.md#tlshd``.
"""

from __future__ import annotations

import re
import shlex
from io import StringIO
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd
from ops_deploy.base._packages import install_packages
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.systemd import UNIT_DIR
from ops_deploy.ops import secret_file

SERVICE = "tlshd.service"
PACKAGE = "ktls-utils"
CONFIG_PATH = "/etc/tlshd.conf"
TLSHD_DIR = "/etc/tlshd"
CA_PATH = f"{TLSHD_DIR}/nfs-ca.pem"
SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
DROPIN_DIR = str(UNIT_DIR / f"{SERVICE}.d")
DROPIN_PATH = f"{DROPIN_DIR}/trust.conf"
HEADER = "# Managed by ops-deploy base.tlshd; local changes are overwritten.\n"

_BASE64_LINES = r"(?:[A-Za-z0-9+/=]+\n)+"
_CERTIFICATE = re.compile(rf"-----BEGIN CERTIFICATE-----\n{_BASE64_LINES}-----END CERTIFICATE-----")
# PKCS#8, SEC1 (EC) or PKCS#1 (RSA), unencrypted: tlshd has no passphrase.
_PRIVATE_KEY = re.compile(rf"-----BEGIN ((?:EC |RSA )?)PRIVATE KEY-----\n{_BASE64_LINES}-----END \1PRIVATE KEY-----")


def pem(text: str) -> str:
    """The file content: the block without surrounding whitespace, one final newline."""

    return text.strip() + "\n"


class TlshdConfig(RoleConfig):
    """One side of the handshake: its certificate and key, and the CA that signed the peer's."""

    role: Literal["server", "client"]
    # PEM, the private CA: the only trust anchor tlshd gets.
    ca_certificate: str
    # PEM, this host's leaf certificate.
    certificate: str
    # PEM, this host's private key; only ever written with secret_file.
    private_key: SecretStr

    @field_validator("ca_certificate", "certificate")
    @classmethod
    def _one_certificate(cls, value: str) -> str:
        if not _CERTIFICATE.fullmatch(value.strip()):
            raise ValueError("must be exactly one PEM certificate")
        return value

    @field_validator("private_key")
    @classmethod
    def _one_private_key(cls, value: SecretStr) -> SecretStr:
        # The message never names the value.
        if not _PRIVATE_KEY.fullmatch(value.get_secret_value().strip()):
            raise ValueError("must be exactly one unencrypted PEM private key")
        return value

    @model_validator(mode="after")
    def _ca_is_not_the_leaf(self) -> TlshdConfig:
        if pem(self.ca_certificate) == pem(self.certificate):
            raise ValueError("the CA certificate and the leaf certificate must differ")
        return self

    @property
    def certificate_path(self) -> str:
        return f"{TLSHD_DIR}/{self.role}.pem"

    @property
    def key_path(self) -> str:
        return f"{TLSHD_DIR}/{self.role}.key"


def render_config(cfg: TlshdConfig) -> str:
    """``/etc/tlshd.conf``: only this side's section, no debug logging."""

    return (
        f"{HEADER}[authenticate.{cfg.role}]\nx509.certificate={cfg.certificate_path}\nx509.private_key={cfg.key_path}\n"
    )


def render_dropin() -> str:
    return f"{HEADER}[Service]\nBindReadOnlyPaths={CA_PATH}:{SYSTEM_BUNDLE}\n"


def trust_check_command() -> str:
    """Inside the running tlshd's mount namespace the system bundle is the private CA file."""

    unit = shlex.quote(SERVICE)
    return (
        f'pid=$(systemctl show -p MainPID --value {unit}) && [ "$pid" -gt 0 ] && '
        f'nsenter -t "$pid" -m -- cmp -s {shlex.quote(SYSTEM_BUNDLE)} {shlex.quote(CA_PATH)} || '
        f'{{ echo "tlshd does not see {CA_PATH} as its only trust bundle" >&2; exit 1; }}'
    )


def tlshd_operations(cfg: TlshdConfig) -> None:
    """The tlshd operations, for use inside another ``@deploy`` (the NFS deploys)."""

    require_linux("tlshd")
    require_systemd("tlshd")
    install_packages([PACKAGE], what="tlshd")
    files.directory(name=f"Ensure {TLSHD_DIR}", path=TLSHD_DIR, user="root", group="root", mode="0755")
    # secret_file for all three: atomic, and it refuses a symlink or other
    # non-regular file in place. The certificates are public; the key is not.
    written = [
        secret_file(
            name=f"Install {CA_PATH}",
            path=CA_PATH,
            content=SecretContent(pem(cfg.ca_certificate)),
            user="root",
            group="root",
            mode="0644",
        ),
        secret_file(
            name=f"Install {cfg.certificate_path}",
            path=cfg.certificate_path,
            content=SecretContent(pem(cfg.certificate)),
            user="root",
            group="root",
            mode="0600",
        ),
        secret_file(
            name=f"Install {cfg.key_path}",
            path=cfg.key_path,
            content=SecretContent(pem(cfg.private_key.get_secret_value())),
            user="root",
            group="root",
            mode="0600",
        ),
        files.put(
            name=f"Install {CONFIG_PATH}",
            src=StringIO(render_config(cfg)),
            dest=CONFIG_PATH,
            user="root",
            group="root",
            mode="0644",
        ),
    ]
    files.directory(name=f"Ensure {DROPIN_DIR}", path=DROPIN_DIR, user="root", group="root", mode="0755")
    dropin = files.put(
        name=f"Install {SERVICE} trust drop-in",
        src=StringIO(render_dropin()),
        dest=DROPIN_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    systemd.daemon_reload(name=f"Reload systemd for {SERVICE}", _if=any_changed(dropin))
    systemd.service(name=f"Enable {SERVICE}", service=SERVICE, running=None, enabled=True)
    # The package starts tlshd on install, before its configuration exists:
    # restart whenever a file it reads changed, also right after the install.
    server.shell(
        name=f"Restart {SERVICE}",
        commands=[f"systemctl restart {SERVICE}"],
        _if=any_changed(dropin, *written),
    )
    systemd.service(name=f"Start {SERVICE}", service=SERVICE, running=True)
    mark_read_only(server.shell(name=f"Check {SERVICE} trusts {CA_PATH} only", commands=[trust_check_command()]))


@deploy("tlshd for NFS over TLS")
def deploy_tlshd(cfg: TlshdConfig) -> None:
    tlshd_operations(cfg)
