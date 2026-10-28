"""Read-only checks of the software-live endpoint, on the host (as ``ansible.builtin.uri`` ran there).

``verify URL HOST``: the playbook's post-tasks: an anonymous request gets 401;
an authenticated one gets schema 2 from ``HOST`` with a fresh observation of
the OS and PostgreSQL.

``shadow PRODUCTION_URL SHADOW_URL``: ops-control's
``tasks/software-live-shadow-check.yml``: the shadow refuses anonymous
requests as production does, and its authenticated body equals the
production body fetched before or after it, except ``meta.age_seconds``.

stdin: the user name, then the password (one line each). No proxy is used.
"""

import base64
import copy
import json
import sys
import urllib.error
import urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch(url, auth=None):
    """(status, headers, parsed JSON or None)."""

    request = urllib.request.Request(url)
    if auth is not None:
        request.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    try:
        with OPENER.open(request, timeout=30) as response:
            status, headers, body = response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        status, headers, body = error.code, error.headers, error.read()
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    return status, headers, data


def verify(url, host, auth):
    status = fetch(url)[0]
    if status != 401:
        sys.exit(f"{url} answered an anonymous request with {status}, expected 401")
    status, _, data = fetch(url, auth)
    if status != 200 or not isinstance(data, dict):
        sys.exit(f"{url} answered the authenticated request with {status}, expected 200 and JSON")
    summary = data.get("summary") or {}
    problems = [
        what
        for what, ok in (
            ("schema_version == 2", data.get("schema_version") == 2),
            (f"host == {host}", data.get("host") == host),
            ("summary.fresh", bool(summary.get("fresh"))),
            ("os.observed", bool((data.get("os") or {}).get("observed"))),
            ("postgresql.observed", bool((data.get("postgresql") or {}).get("observed"))),
        )
        if not ok
    ]
    if problems:
        sys.exit(f"{url} does not report a fresh observation from {host}: {', '.join(problems)} failed")


def comparable(body):
    if not isinstance(body, dict):
        return None
    body = copy.deepcopy(body)
    if isinstance(body.get("meta"), dict):
        body["meta"]["age_seconds"] = None
    return body


def shadow(production, shadow_url, auth):
    status, headers, data = fetch(shadow_url)
    authenticated = [fetch(url, auth) for url in (production, shadow_url, production)]
    bodies = [response[2] for response in authenticated]
    meta = bodies[1].get("meta") if isinstance(bodies[1], dict) else None
    ok = (
        status == 401
        and (headers.get("WWW-Authenticate") or "") == 'Basic realm="software-live"'
        and data == {"error": "unauthorized"}
        and all(response[0] == 200 for response in authenticated)
        and None not in bodies
        and isinstance(meta, dict)
        and "age_seconds" in meta
        and "max_age_seconds" in meta
        and len(meta) == 2
        and comparable(bodies[1]) in (comparable(bodies[0]), comparable(bodies[2]))
    )
    if not ok:
        sys.exit(
            f"The shadow endpoint {shadow_url} does not answer as the production endpoint: anonymous requests "
            'must get 401 {"error": "unauthorized"} with realm "software-live", and the authenticated body must '
            "equal the production body before or after it, except meta.age_seconds."
        )


if __name__ == "__main__":
    user = sys.stdin.readline().rstrip("\n")
    password = sys.stdin.readline().rstrip("\n")
    credentials = f"{user}:{password}"
    if sys.argv[1] == "verify":
        verify(sys.argv[2], sys.argv[3], credentials)
    else:
        shadow(sys.argv[2], sys.argv[3], credentials)
