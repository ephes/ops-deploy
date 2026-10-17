"""Read-only checks through Traefik, run with curl on the host: URL checks and the CSRF origin check."""

from __future__ import annotations

import shlex

from pyinfra.operations import server

from ops_deploy.helpers import mark_read_only
from ops_deploy.services.django_site.config import DjangoSiteConfig, UrlCheck

# A POST with the session's CSRF token and the site's Origin must reach the
# view (400 for the empty body) instead of being refused (403). ``$base`` is
# the site, ``$path`` the session endpoint.
CSRF_CHECK = """\
set -e
jar=$(mktemp); body=$(mktemp); trap 'rm -f "$jar" "$body"' EXIT
session=$(curl -fsS -c "$jar" "$base$path")
token=$(printf '%s' "$session" | python3 -c 'import json, sys; print(json.load(sys.stdin)["csrfToken"])')
[ -n "$token" ] || { echo "No CSRF token from $base$path" >&2; exit 1; }
status=$(curl -sS -o "$body" -w '%{http_code}' -b "$jar" -H 'Content-Type: application/json' \
-H "Origin: $base" -H "X-CSRFToken: $token" --data '{}' "$base$path")
[ "$status" = 400 ] || { echo "Expected CSRF-accepted validation failure (400) for $base, got $status" >&2; exit 1; }
"""


def url_check_script(url: str, check: UrlCheck) -> str:
    """curl ``url`` until it answers ``check.status`` (and its body has ``check.contains``)."""

    curl = ["curl", "-sS", "-o", '"$body"', "-w", "'%{http_code}'", "--max-time", "10"]
    if check.follow:
        curl.append("-L")
    contains = "".join(f' && grep -qF -e {shlex.quote(s)} "$body"' for s in check.contains)
    expected = f"{check.status} with the expected content" if check.contains else str(check.status)
    return (
        "body=$(mktemp); trap 'rm -f \"$body\"' EXIT; "
        f"for i in $(seq 1 {check.retries}); do "
        # A transfer curl did not complete (timeout, truncation) never counts.
        f"if code=$({' '.join(curl)} {shlex.quote(url)} 2>/dev/null) && "
        f'[ "$code" = {check.status} ]{contains}; then exit 0; fi; sleep {check.delay}; done; '
        f'echo "{url} answered ${{code:-nothing}}, expected {expected}" >&2; exit 1'
    )


def public_checks(cfg: DjangoSiteConfig) -> None:
    base = f"https://{cfg.route.fqdn}"
    for check in cfg.checks.public:
        url = f"{base}{check.path}"
        script = url_check_script(url, check)
        mark_read_only(server.shell(name=f"Check {url}", commands=[f"sh -c {shlex.quote(script)}"]))
    if cfg.checks.csrf_path:
        csrf = f"base={shlex.quote(base)}; path={shlex.quote(cfg.checks.csrf_path)}; {CSRF_CHECK}"
        mark_read_only(server.shell(name=f"Check the CSRF origin of {base}", commands=[csrf]))
