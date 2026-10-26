"""Wait for the local controller API, not its HTTP-200 startup page."""
import json
import subprocess
import sys
import time

URL = "https://127.0.0.1:8443/status"


def ready(status, value):
    meta = value.get("meta") if isinstance(value, dict) else None
    return status == 200 and isinstance(meta, dict) and meta.get("rc") == "ok" and meta.get("up") is True


def wait_ready(timeout, url=URL):
    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        request_timeout = min(5, remaining)
        try:
            # Retain the role's self-signed local TLS policy. -q disables curlrc;
            # without -L, redirects cannot inherit that policy. Both curl and
            # the subprocess are bounded, including a stalled response body.
            response = subprocess.run(
                ["curl", "-q", "-kfsS", "--max-time", str(request_timeout),
                 "--write-out", "\n%{http_code}", url],
                capture_output=True, text=True, timeout=request_timeout,
            )
            if response.returncode == 0:
                body, status = response.stdout.rsplit("\n", 1)
                if ready(int(status), json.loads(body)):
                    return True
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    return False


if __name__ == "__main__":
    if not wait_ready(float(sys.argv[1])):
        print("UniFi API did not become ready", file=sys.stderr)
        raise SystemExit(1)
