"""Read-only rollout checks: ``wait_port`` and ``http_check``.

pyinfra reports every shell operation that ran as "changed", so a health check
would make a converged second run look like it changed something. The checks
here register their operation hash as read-only; :func:`is_read_only` lets the
test harness and the smoke run report them separately from mutating changes.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable
from weakref import WeakKeyDictionary

from pyinfra.api import State
from pyinfra.api.operation import OperationMeta
from pyinfra.context import ctx_state
from pyinfra.operations import server

_READ_ONLY: WeakKeyDictionary[State, set[str]] = WeakKeyDictionary()

_HOST_PATTERN = re.compile(r"^[A-Za-z0-9.:\[\]-]+$")
# No whitespace, quotes, ``$``, backticks or backslashes: the URL is echoed in a message.
_URL_PATTERN = re.compile(r"^https?://[^\s'\"$`\\]+$")


def mark_read_only(meta: OperationMeta) -> OperationMeta:
    """Tag ``meta``'s operation as read-only in the current deploy state."""

    # ``pyinfra.context.state`` is a proxy; key on the State it points to.
    state = ctx_state.get()
    if state is None:
        raise RuntimeError("mark_read_only must be called inside a deploy")
    _READ_ONLY.setdefault(state, set()).add(meta._hash)
    return meta


def is_read_only(state: State, op_hash: str) -> bool:
    """Whether the operation ``op_hash`` was tagged with :func:`mark_read_only`."""

    return op_hash in _READ_ONLY.get(state, ())


def wait_port(
    port: int,
    *,
    host: str = "127.0.0.1",
    retries: int = 30,
    delay: float = 1,
    name: str | None = None,
) -> OperationMeta:
    """Wait until ``host:port`` accepts TCP connections (bash ``/dev/tcp``)."""

    _check_retries(retries, delay)
    if not 0 < port < 65536:
        raise ValueError("port must be between 1 and 65535")
    if not _HOST_PATTERN.match(host):
        raise ValueError("host must be a hostname or IP address")
    probe = f"(exec 3<>/dev/tcp/{host}/{port}) 2>/dev/null"
    script = (
        f"for i in $(seq 1 {retries}); do {probe} && exit 0; sleep {delay}; done; "
        f"echo 'port {host}:{port} did not open' >&2; exit 1"
    )
    return mark_read_only(
        server.shell(
            name=name or f"Wait for port {host}:{port}",
            commands=[f"bash -c {shlex.quote(script)}"],
        )
    )


def http_check(
    url: str,
    *,
    status: int | Iterable[int] = 200,
    host_header: str | None = None,
    retries: int = 10,
    delay: float = 1,
    timeout: float = 5,
    name: str | None = None,
) -> OperationMeta:
    """Poll ``url`` with curl on the target until it answers with ``status``.

    Redirects are not followed, so ``status`` may be a 3xx code.
    """

    _check_retries(retries, delay)
    if not _URL_PATTERN.match(url):
        raise ValueError("url must be an http(s) URL without whitespace, quotes, $, ` or \\")
    expected = sorted({status} if isinstance(status, int) else set(status))
    if not expected or not all(100 <= code <= 599 for code in expected):
        raise ValueError("status must be one or more HTTP status codes")
    curl = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout)]
    if host_header is not None:
        if not _HOST_PATTERN.match(host_header):
            raise ValueError("host_header must be a hostname")
        curl += ["-H", f"Host: {host_header}"]
    curl.append(url)
    matches = " || ".join(f'[ "$code" = {code} ]' for code in expected)
    script = (
        f"for i in $(seq 1 {retries}); do "
        f"code=$({shlex.join(curl)} 2>/dev/null); "
        f"if {matches}; then exit 0; fi; sleep {delay}; done; "
        f'echo "{url} answered ${{code:-nothing}}, expected {"/".join(map(str, expected))}" >&2; exit 1'
    )
    return mark_read_only(
        server.shell(
            name=name or f"Check {url}",
            commands=[f"sh -c {shlex.quote(script)}"],
        )
    )


def _check_retries(retries: int, delay: float) -> None:
    if retries < 1:
        raise ValueError("retries must be at least 1")
    if delay < 0:
        raise ValueError("delay must not be negative")
