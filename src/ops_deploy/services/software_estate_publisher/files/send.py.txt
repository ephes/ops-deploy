#!/usr/bin/env python3
"""Send existing local inventory reports once. Never collect or execute remotely."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import re
import signal
import ssl
import time
from contextlib import contextmanager
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import outbox

MAX_REPLY = 4096
STATE_LIMIT = 65536
RETRY_SECONDS = 3600
MAX_RETRY_SECONDS = 86400


class RunDeadline(Exception):
    pass


@contextmanager
def deadline(seconds):
    def expired(signum, frame):
        raise RunDeadline()

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def endpoint_url(value, allow_loopback_http=False):
    if not value.isascii() or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("invalid endpoint")
    url = urlsplit(value)
    if (
        not url.hostname
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or not url.path.endswith("/v1/inventory")
    ):
        raise ValueError("expected an inventory endpoint without credentials or query")
    if url.scheme != "https" and not (
        allow_loopback_http
        and url.scheme == "http"
        and url.hostname in ("127.0.0.1", "::1")
    ):
        raise ValueError("HTTPS required; loopback HTTP requires explicit test flag")
    if url.port is not None and url.port == 0:
        raise ValueError("invalid endpoint port")
    return url


def retry_delay(value, now):
    try:
        delay = int(value)
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delay = math.ceil(parsed.timestamp() - now)
        except (TypeError, ValueError, OverflowError):
            delay = RETRY_SECONDS
    return min(MAX_RETRY_SECONDS, max(RETRY_SECONDS, delay))


def post(url, credential, body, identifier, timeout):
    """No proxy environment or redirect handling; never print a peer response."""
    connection: http.client.HTTPConnection
    if url.scheme == "https":
        connection = http.client.HTTPSConnection(
            url.hostname,
            url.port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=timeout)
    try:
        connection.request(
            "POST",
            url.path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + credential,
            },
        )
        response = connection.getresponse()
        if response.status == 429 or 500 <= response.status <= 599:
            return (
                "retry",
                f"http_{response.status}",
                retry_delay(response.getheader("Retry-After"), time.time()),
            )
        if response.status != 200:
            return "blocked", f"http_{response.status}", 0
        if (
            response.getheader("Content-Type", "").split(";")[0].strip()
            != "application/json"
        ):
            return "blocked", "invalid_ack", 0
        data = response.read(MAX_REPLY + 1)
        if len(data) > MAX_REPLY:
            return "blocked", "invalid_ack", 0
        try:
            ack = json.loads(data)
        except (ValueError, UnicodeError, RecursionError):
            return "blocked", "invalid_ack", 0
        if (
            not isinstance(ack, dict)
            or ack.get("status") != "stored"
            or ack.get("snapshot_id") != identifier
            or not isinstance(ack.get("duplicate"), bool)
        ):
            return "blocked", "invalid_ack", 0
        return "stored", "duplicate" if ack["duplicate"] else "created", 0
    except ssl.SSLCertVerificationError:
        return "blocked", "tls_verification_failed", 0
    except (OSError, http.client.HTTPException):
        return "retry", "network_error", RETRY_SECONDS
    finally:
        connection.close()


def read_state(spool):
    try:
        state = json.loads(outbox.private_read(spool / ".delivery.json", STATE_LIMIT))
    except FileNotFoundError:
        return {}
    if not isinstance(state, dict) or len(state) > outbox.MAX_REPORTS:
        raise ValueError("invalid delivery state; preserve files and repair locally")
    for identifier, item in state.items():
        if (
            not isinstance(item, dict)
            or set(item) != {"fingerprint", "status", "reason", "retry_at"}
            or not isinstance(item.get("fingerprint"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["fingerprint"])
            or item.get("status") not in ("blocked", "retry")
            or not isinstance(item.get("reason"), str)
            or not re.fullmatch(r"[a-z0-9_]{1,64}", item["reason"])
            or not isinstance(item.get("retry_at"), (int, float))
            or isinstance(item.get("retry_at"), bool)
            or not 0 <= item["retry_at"] <= time.time() + MAX_RETRY_SECONDS + 300
            or str(UUID(identifier)) != identifier
        ):
            raise ValueError(
                "invalid delivery state; preserve files and repair locally"
            )
    return state


def send_reports(
    spool,
    endpoint,
    credential_file,
    *,
    allow_loopback_http=False,
    retry_blocked=False,
    retry_now=False,
    timeout=30,
):
    url = endpoint_url(endpoint, allow_loopback_http)
    credential_file = Path(credential_file).absolute()
    outbox.private_directory(credential_file.parent)
    credential = outbox.private_read(credential_file, 4096).decode("ascii").rstrip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", credential):
        raise ValueError("invalid credential file")
    # Persist only a hash, never the endpoint or bearer credential.
    scope = hashlib.sha256((endpoint + "\0" + credential).encode()).digest()
    outcomes = []
    with outbox.locked(spool) as spool:
        paths = outbox.entries(spool)
        report_count = sum(outbox.report_id(path.name) is not None for path in paths)
        if report_count > outbox.MAX_REPORTS:
            raise ValueError(
                "outbox over capacity; preserve files and reconcile locally"
            )
        state = read_state(spool)
        present = {p.stem for p in paths}
        state = {key: item for key, item in state.items() if key in present}
        for path in paths:
            try:
                identifier = outbox.report_id(path.name)
                if identifier is None:
                    raise ValueError("invalid report filename")
                body = outbox.private_read(path, outbox.MAX_BYTES)
            except (OSError, ValueError):
                outcomes.append({"status": "blocked", "reason": "unsafe_outbox_entry"})
                continue
            fingerprint = hashlib.sha256(scope + body).hexdigest()
            prior = state.get(identifier, {})
            if prior.get("fingerprint") == fingerprint:
                if prior.get("status") == "blocked" and not retry_blocked:
                    outcomes.append(
                        {
                            "snapshot_id": identifier,
                            "status": "blocked",
                            "reason": prior["reason"],
                        }
                    )
                    continue
                if (
                    prior.get("status") == "retry"
                    and not retry_now
                    and prior["retry_at"] > time.time()
                ):
                    outcomes.append(
                        {
                            "snapshot_id": identifier,
                            "status": "waiting",
                            "reason": prior["reason"],
                        }
                    )
                    continue
            try:
                report = json.loads(body)
                if (
                    not isinstance(report, dict)
                    or report.get("snapshot_id") != identifier
                ):
                    raise ValueError("invalid report identity")
            except (ValueError, UnicodeError, RecursionError):
                result, reason, delay = "blocked", "invalid_report", 0
            else:
                result, reason, delay = post(url, credential, body, identifier, timeout)
            if result == "stored":
                # Cooperative writers share the lock; also refuse an unexpected edit.
                if outbox.private_read(path, outbox.MAX_BYTES) != body:
                    raise ValueError("report changed during delivery; retained")
                path.unlink()
                outbox.sync_directory(spool)
                state.pop(identifier, None)
            else:
                state[identifier] = {
                    "fingerprint": fingerprint,
                    "status": result,
                    "reason": reason,
                    "retry_at": time.time() + delay,
                }
            outbox.atomic_state(spool, state)
            outcomes.append(
                {"snapshot_id": identifier, "status": result, "reason": reason}
            )
    return outcomes


def run_timeout(value):
    number = int(value)
    if not 1 <= number <= 600:
        raise argparse.ArgumentTypeError(
            "run timeout must be between 1 and 600 seconds"
        )
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spool", required=True, type=Path)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--credential-file", required=True, type=Path)
    parser.add_argument(
        "--allow-loopback-http", action="store_true", help="Local tests only"
    )
    parser.add_argument(
        "--retry-blocked",
        action="store_true",
        help="Retry retained rejections after local correction",
    )
    parser.add_argument(
        "--retry-now",
        action="store_true",
        help="Override transient backoff after local recovery",
    )
    parser.add_argument(
        "--run-timeout", type=run_timeout, default=120, metavar="1..600"
    )
    args = parser.parse_args()
    try:
        with deadline(args.run_timeout):
            outcomes = send_reports(
                args.spool,
                args.endpoint,
                args.credential_file,
                allow_loopback_http=args.allow_loopback_http,
                retry_blocked=args.retry_blocked,
                retry_now=args.retry_now,
            )
        print(json.dumps({"reports": outcomes}))
        return int(any(item["status"] != "stored" for item in outcomes))
    except RunDeadline:
        print('{"error":"run_deadline_exceeded"}')
    except (OSError, ValueError, TypeError, RecursionError):
        # Exception messages may contain paths, peer input or credentials.
        print('{"error":"local_configuration_or_state_error"}')
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
