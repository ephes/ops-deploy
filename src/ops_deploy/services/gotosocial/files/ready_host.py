"""Wait for GoToSocial's readiness endpoint (host side, python3 -I): the role's health.yml.

The role polls ``GET /readyz`` with ``ansible.builtin.uri`` (Python), so the
host needs no curl; neither does this check. Argument: JSON with ``url``,
``retries``, ``delay`` and ``timeout``. Exits 0 on HTTP 200; otherwise prints
the last answer (a status code or an error class, never a body) and exits 1.
"""
import json
import sys
import time
import urllib.error
import urllib.request


def main(cfg):
    # Loopback only: never through a proxy from the environment.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    last = 'nothing'
    for attempt in range(cfg['retries']):
        try:
            with opener.open(cfg['url'], timeout=cfg['timeout']) as response:
                if response.status == 200:
                    return 0
                last = str(response.status)
        except urllib.error.HTTPError as exc:
            last = str(exc.code)
        except Exception as exc:
            last = type(exc).__name__
        if attempt + 1 < cfg['retries']:
            time.sleep(cfg['delay'])
    print(cfg['url'] + ' answered ' + last + ', expected 200', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main(json.loads(sys.argv[1])))
