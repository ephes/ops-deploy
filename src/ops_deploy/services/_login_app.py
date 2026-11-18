"""Checks shared by small Django apps on loopback behind a Traefik allowlist and their own login.

Used by ``opaq_app`` and ``haushalt``: the port preflight before any change,
the ``/healthz`` check, and the route checks after the deploy (an anonymous
request from the controller is sent to the login; a request from the host's
own LAN address is refused by the allowlist).
"""

from __future__ import annotations

import re
import shlex
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Generator
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field
from pyinfra.api import FunctionCommand, OperationError, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers import mark_read_only

# Fetch ``url`` (verifying the certificate or not) without following redirects:
# (status, Location header).
Fetcher = Callable[[str, bool], tuple[int, str]]


class RouteChecks(BaseModel):
    """What the deploy checks about the published route.

    ``controller_login`` (production): the controller itself requests
    ``https://<host>/`` and must be sent to the login. ``refused_address``: a
    request from the host to that address (its LAN address) must be refused
    with 403 by the allowlist. ``verify_tls`` off is for hosts with a
    self-signed default certificate.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    controller_login: bool = False
    login_retries: int = Field(default=20, ge=1, le=200)
    login_delay: float = Field(default=3, ge=0, le=60)
    refused_address: Annotated[str, Field(pattern=r"^[0-9A-Fa-f.:]+$")] | None = None
    verify_tls: bool = True


def urllib_fetch(url: str, verify: bool) -> tuple[int, str]:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: object, **kwargs: object) -> None:
            return None

    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(url, timeout=10) as response:
            return response.status, response.headers.get("Location", "")
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Location", "")


def await_login(url: str, fetch: Fetcher, verify: bool, retries: int, delay: float) -> None:
    seen = "nothing"
    for _ in range(retries):
        try:
            status, location = fetch(url, verify)
        except OSError as error:
            seen = type(error).__name__
        else:
            seen = str(status)
            if status == 302:
                if re.search(r"/login/\?next=/$", location):
                    return
                seen = "a redirect away from the login"
        time.sleep(delay)
    raise OperationError(f"an anonymous request to {url} answered {seen}, not the login redirect")


@operation()
def _controller_login(
    url: str, fetch: Fetcher, verify: bool, retries: int, delay: float
) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(await_login, (url, fetch, verify, retries, delay), {})


def controller_login_check(traefik_host: str, checks: RouteChecks, fetch: Fetcher) -> OperationMeta:
    """Read-only: the controller's anonymous request to ``https://<host>/`` must reach the login."""

    return mark_read_only(
        _controller_login(
            name="Check an anonymous request is sent to the login",
            url=f"https://{traefik_host}/",
            fetch=fetch,
            verify=checks.verify_tls,
            retries=checks.login_retries,
            delay=checks.login_delay,
        )
    )


def refused_check(traefik_host: str, checks: RouteChecks) -> OperationMeta:
    """Read-only: a request from the host to ``checks.refused_address`` must get 403."""

    assert checks.refused_address is not None
    curl = [
        "curl",
        "--silent",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--max-time",
        "10",
        "--resolve",
        f"{traefik_host}:443:{checks.refused_address}",
    ]
    if not checks.verify_tls:
        curl.append("--insecure")
    curl.append(f"https://{traefik_host}/login/")
    # Traefik's file provider picks the route up a moment after it is written.
    script = (
        f"for i in $(seq 1 20); do code=$({shlex.join(curl)} || true); "
        '[ "$code" = 403 ] && exit 0; sleep 3; done; '
        'echo "a request from the host answered ${code:-nothing}, expected 403" >&2; exit 1'
    )
    return mark_read_only(
        server.shell(
            name="Check the allowlist refuses the host's own address", commands=[f"sh -c {shlex.quote(script)}"]
        )
    )


def port_preflight(service_name: str, app_port: int) -> OperationMeta:
    """Nothing but ``<service_name>.service`` may listen on the app port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback``: a TCP listener
    on the port at a loopback or wildcard address fails the deploy unless every
    process behind it runs in the service's unit. Read-only; runs before any
    change. ``SKIP_PREFLIGHT_PORTS`` has no effect on the pyinfra path.
    """

    unit = f"{service_name}.service"
    script = (
        f"out=$(ss -Hltnp 'sport = :{app_port}') || exit 1; "
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        'case "${local%:*}" in 127.0.0.1|0.0.0.0|"[::1]"|"[::]"|"*"|"[::ffff:127.0.0.1]") ;; *) continue ;; esac; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        f"grep -qx '0::/system.slice/{unit}' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        '[ "$bad" = 0 ] || echo "port in use: $local $users" >&2; '
        'done; [ "$bad" = 0 ]; }'
    )
    return mark_read_only(
        server.shell(name=f"Port preflight tcp/{app_port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def health_check(app_host: str, app_port: int) -> OperationMeta:
    """Read-only: ``/healthz`` on loopback must answer ``ok`` with 200 (retried)."""

    url = f"http://{app_host}:{app_port}/healthz"
    script = (
        "for i in $(seq 1 20); do "
        f"body=$(curl -sS --max-time 5 -w '|%{{http_code}}' {shlex.quote(url)} 2>/dev/null); "
        '[ "$body" = "ok|200" ] && exit 0; sleep 3; done; '
        f'echo "{url} did not answer ok" >&2; exit 1'
    )
    return mark_read_only(server.shell(name=f"Check {url}", commands=[f"sh -c {shlex.quote(script)}"]))
