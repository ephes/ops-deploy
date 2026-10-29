"""Original trust-maintenance URI health check with status/count output only."""

import json
import signal
import ssl
import sys
import time
import urllib.request


class HealthDeadline(Exception):
    pass


def _expired(signum, frame):
    raise HealthDeadline()


def run(payload, transport, report):
    # URI's default timeout is30; retry count adds to the initial attempt.
    context = ssl._create_unverified_context()
    for attempt in range(max(0, payload['retries']) + 1):
        report['attempts'] += 1
        try:
            headers = {'User-Agent': 'ansible-httpget'}
            url, opener = transport(payload['url'], headers, context)
            request = urllib.request.Request(url, headers=headers, method='GET')
            with opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise RuntimeError('unexpected status')
            report['success'] = True
            return
        except HealthDeadline:
            raise
        except Exception:
            # The original until/retries task retries every failed URI attempt,
            # including malformed HTTP responses and transport/auth errors.
            if attempt >= max(0, payload['retries']):
                raise
            time.sleep(payload['delay'])


def main(transport):
    report = {'success': False, 'attempts': 0}
    previous_handler = None
    previous_timer = None
    try:
        payload = json.load(sys.stdin)
        previous_handler = signal.signal(signal.SIGALRM, _expired)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, payload['deadline_seconds'])
        run(payload, transport, report)
    except Exception:
        # Never surface URL credentials, selected NETRC values or response bodies.
        report['success'] = False
    finally:
        if previous_timer is not None:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        if previous_handler is not None:
            signal.signal(signal.SIGALRM, previous_handler)
    print(json.dumps(report))
    return 0 if report['success'] else 1
