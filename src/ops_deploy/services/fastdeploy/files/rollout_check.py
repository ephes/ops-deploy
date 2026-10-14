"""Check FastDeploy's DB-backed auth with a short-lived user token.

Run with FastDeploy's own interpreter and the site directory as working
directory, as the service user. It combines the fastdeploy_deploy role's
mint_validation_token.py with its ``uri`` check: FastDeploy's own
``create_access_token`` signs the token with the SECRET_KEY of its settings
(the site's ``.env``), and the token is used and dropped in this process, so
it never appears on a command line, in output or on the controller.

stdin: a JSON object ``{"user", "ttl_seconds", "url", "retries", "delay"}``.
Succeeds once ``url`` answers 200 with a JSON body whose ``name`` is ``user``.
"""

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import timedelta

sys.path.insert(0, "src")

from deploy.auth import create_access_token  # noqa: E402

request = json.load(sys.stdin)
token = create_access_token(
    {"user": request["user"], "type": "user"},
    timedelta(seconds=int(request["ttl_seconds"])),
)
outcome = "no answer"
for attempt in range(int(request["retries"])):
    if attempt:
        time.sleep(float(request["delay"]))
    check = urllib.request.Request(request["url"], headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(check, timeout=10) as response:
            body = json.load(response)
    except urllib.error.HTTPError as exc:
        outcome = f"HTTP {exc.code}"
        continue
    except (OSError, ValueError) as exc:
        outcome = type(exc).__name__
        continue
    if isinstance(body, dict) and body.get("name") == request["user"]:
        print("validated")
        sys.exit(0)
    outcome = "HTTP 200 for another user"
sys.exit(f"FastDeploy auth check failed after {request['retries']} attempts: {outcome}")
