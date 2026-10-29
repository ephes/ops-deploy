"""postsrsd 1.x/2.x selection and the 2.x socketmap health check.

postsrsd 1.x reads ``/etc/default/postsrsd`` and answers Postfix ``tcp:``
lookup tables. postsrsd 2.x (Ubuntu 26.04 ships 2.0.11) reads
``/etc/postsrsd.conf`` and answers only ``socketmap:`` tables, so the relay
renders one or the other by the package's major version: the installed one, or
apt's candidate when the package is not installed yet.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Mapping

from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe
from ops_deploy.services.mail_relay.config import MailRelayConfig
from ops_deploy.services.mail_relay.render import SRS_SOCKET, PostsrsdMajor

CANDIDATE_COMMAND = "env LC_ALL=C apt-cache policy postsrsd"
# Characters that need no quoting in postsrsd.conf strings (libconfuse).
_CONF_WORD = re.compile(r"[\w.-]+")
_CONF_PATH = re.compile(r"/[\w./-]+")
# The health check's foreign sender: reserved, never routable names (RFC 2606/6761).
PROBE_LOCAL_PART = "ops-deploy-srs-probe"
PROBE_DOMAINS = ("srs-probe.invalid", "srs-probe.example", "srs-probe.test", "srs-probe.localhost")


def postsrsd_major(version: str) -> PostsrsdMajor:
    """Major version of a Debian ``postsrsd`` version (epoch and revision ignored)."""

    match = re.match(r"(?:\d+:)?(\d+)\.", version)
    major = int(match[1]) if match else 0
    if major == 1:
        return 1
    if major == 2:
        return 2
    raise DeployError(f"postsrsd {version!r} is neither 1.x nor 2.x; no relay configuration for it")


def candidate_version(policy: str) -> str | None:
    """The ``Candidate:`` of ``apt-cache policy`` output, ``None`` when apt knows none."""

    for line in policy.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "Candidate":
            value = value.strip()
            return None if value in {"", "(none)"} else value
    return None


def planned_major(installed: Mapping[str, Iterable[str]]) -> tuple[PostsrsdMajor, bool]:
    """The postsrsd major to configure, and whether apt still has to install it.

    An installed package is never upgraded by this deploy, so its version
    decides. Otherwise apt's candidate decides; when apt knows none (empty
    package lists before the deploy's own ``apt update``) the 1.x layout stays
    the plan and the check after the install refuses a different major.
    """

    versions = set(installed.get("postsrsd", ()))
    if versions:
        majors = {postsrsd_major(version) for version in versions}
        if len(majors) != 1:
            raise DeployError("postsrsd is installed in more than one major version")
        return majors.pop(), False
    policy = probe(CANDIDATE_COMMAND, name="postsrsd apt candidate")
    candidate = candidate_version(policy or "")
    return (postsrsd_major(candidate) if candidate else 1), True


def probe_sender(cfg: MailRelayConfig, excluded: Iterable[str]) -> str:
    """A sender postsrsd must rewrite: outside the SRS domain and every exclusion (and their subdomains)."""

    own = {domain.strip(".").lower() for domain in (cfg.srs_domain, *excluded)}
    for domain in PROBE_DOMAINS:
        if not any(domain == name or domain.endswith("." + name) for name in own):
            return f"{PROBE_LOCAL_PART}@{domain}"
    raise ValueError("every SRS health probe domain is excluded from rewriting; no postsrsd 2.x check possible")


def check_socketmap_inputs(cfg: MailRelayConfig, excluded: tuple[str, ...]) -> None:
    """Refuse settings postsrsd 2.x cannot express or would silently ignore."""

    defaults = MailRelayConfig.model_fields
    for field in ("srs_listen_addr", "srs_forward_port", "srs_reverse_port"):
        if getattr(cfg, field) != defaults[field].default:
            raise ValueError(f"postsrsd 2.x has no tcp: lookup tables; {field} applies to postsrsd 1.x only")
    if not all(_CONF_WORD.fullmatch(domain) for domain in (cfg.srs_domain, *excluded)):
        raise ValueError("postsrsd 2.x SRS domains must be plain domain names")
    if not _CONF_PATH.fullmatch(cfg.srs_secret_file):
        raise ValueError("postsrsd 2.x needs a plain absolute SRS secret file path")
    probe_sender(cfg, excluded)


_INSTALLED_MAJOR = """import subprocess,sys
v=subprocess.run(['dpkg-query','-W','-f=${Version}','postsrsd'],capture_output=True,text=True).stdout.strip()
ok=v.split(':',1)[-1].split('.',1)[0]==sys.argv[1]
msg='installed postsrsd '+(v or 'none')+' is not the planned '+sys.argv[1]+'.x'
None if ok else print(msg+'; nothing was configured, run the deploy again',file=sys.stderr)
sys.exit(not ok)
"""


def verify_installed_major(major: PostsrsdMajor) -> OperationMeta:
    """Read-only: the postsrsd apt just installed has the major the plan rendered for."""

    return mark_read_only(
        server.shell(
            name="Verify the installed postsrsd major version",
            commands=[shlex.join(["python3", "-I", "-c", _INSTALLED_MAJOR, str(major)])],
        )
    )


# A socketmap client (netstring requests, postsrsd keeps the connection open
# for keep-alive, so read exactly one reply). Retries while postsrsd (re)starts.
_SOCKETMAP_CHECK = """import socket,sys,time
path,probe,domain,own=sys.argv[1:5]
def ask(name,key):
    q=(name+' '+key).encode()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(5);s.connect(path);s.sendall(str(len(q)).encode()+b':'+q+b',');data=b''
        while True:
            head,sep,rest=data.partition(b':')
            if sep and head.isdigit() and len(rest)>int(head):
                return rest[:int(head)].decode()
            chunk=s.recv(4096)
            if not chunk:
                raise OSError('short socketmap reply')
            data+=chunk
for attempt in range(30):
    try:
        fwd=ask('forward',probe);break
    except OSError:
        time.sleep(1)
else:
    print('postsrsd socketmap '+path+' does not answer',file=sys.stderr);sys.exit(1)
ok=fwd.startswith('OK SRS0=') and fwd.lower().endswith('@'+domain.lower())
ok=ok and ask('reverse',fwd[3:])=='OK '+probe
ok=ok and ask('forward','postmaster@'+own).startswith('NOTFOUND')
ok=ok and ask('forward','postmaster@probe.'+own).startswith('NOTFOUND')
None if ok else print('postsrsd socketmap round trip failed',file=sys.stderr)
sys.exit(not ok)
"""


def verify_socketmap(cfg: MailRelayConfig, excluded: tuple[str, ...]) -> OperationMeta:
    """Read-only: postsrsd 2.x rewrites a foreign sender into the SRS domain and back,
    and leaves an own domain and its subdomains alone."""

    sender = probe_sender(cfg, excluded)
    argv = ["python3", "-I", "-c", _SOCKETMAP_CHECK, str(SRS_SOCKET), sender, cfg.srs_domain, excluded[0]]
    return mark_read_only(server.shell(name="Verify relay SRS socketmap round trip", commands=[shlex.join(argv)]))
