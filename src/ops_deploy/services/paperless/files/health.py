"""Paperless readiness: one known same-origin schema redirect, then HTTP 200.

Only status and the expected redirect path are returned. Response bodies,
credentials and arbitrary redirect destinations are never read or followed.
"""

import http.client
import json
import signal
import ssl
import sys
import time

SCHEMA_PATH = "/api/schema/view/"


def inspect_endpoint(port, *, host_header=None, tls=False, timeout=10):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid Paperless readiness port")
    scheme = "https" if tls else "http"
    origin = f"{scheme}://127.0.0.1:{port}"
    headers = {"Host": host_header} if host_header else {}
    if host_header and (not isinstance(host_header, str) or any(c in host_header for c in "\r\n\0")):
        raise ValueError("invalid readiness Host header")

    def request(path):
        if tls:
            # Used only by the separate loopback route/status observer, not a
            # certificate-validity assertion or an external request.
            connection = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=timeout, context=ssl._create_unverified_context()
            )
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            location = response.getheader("Location")
            if location is not None and len(location) > 2048:
                raise ValueError("Paperless redirect exceeds bound")
            return response.status, location
        finally:
            connection.close()

    initial, location = request("/api/")
    if initial == 200:
        if location is not None:
            raise ValueError("Paperless readiness returned an unexpected redirect header")
        return {"initial_status": initial, "location": None, "redirect_target": None, "final_status": 200}
    if initial != 302 or not location:
        raise ValueError("Paperless readiness returned an unexpected status")
    if location not in {"schema/view/", SCHEMA_PATH, origin + SCHEMA_PATH}:
        raise ValueError("Paperless readiness returned an unexpected redirect")
    final, extra_location = request(SCHEMA_PATH)
    if final != 200 or extra_location is not None:
        raise ValueError("Paperless schema readiness did not return final200")
    return {"initial_status": initial, "location": location, "redirect_target": SCHEMA_PATH, "final_status": final}


def alarm(_signum, _frame):
    raise TimeoutError("Paperless readiness attempt exceeded deadline")


def main():
    data = json.load(sys.stdin)
    if not isinstance(data, dict) or set(data) != {"port"}:
        raise ValueError("invalid Paperless readiness request")
    signal.signal(signal.SIGALRM, alarm)
    for attempt in range(10):
        signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            result = inspect_endpoint(data["port"])
        except (OSError, ValueError, http.client.HTTPException):
            result = None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if result is not None:
            print(json.dumps(result))
            return 0
        if attempt < 9:
            time.sleep(6)
    print("Paperless HTTP readiness failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, http.client.HTTPException):
        print("Paperless HTTP readiness failed", file=sys.stderr)
        raise SystemExit(1) from None
