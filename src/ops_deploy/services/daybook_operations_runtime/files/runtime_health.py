"""Original managed CLI health for empty/nonempty stores, no response exports.

The APP may read its own Journal and its binding GET may expire authority. Raw
responses, delivery records and errors stay in host memory. The agent receives
only success/count or a fixed failure category, never record or response bodies.
"""

import base64
import json
import os
import re
import subprocess
import sys
import time

from ops_daybook_observer import MAX_INPUT, NativeProbes, observe
from ops_daybook_stop import STATUS_CAPTURE, STATUS_FRAME


class HealthError(RuntimeError):
    pass


def healthy(rc, payload):
    if rc != 0:
        return False
    if not isinstance(payload, dict) or type(payload.get('enabled')) is not bool or not isinstance(payload.get('status'), str):
        raise HealthError('runtime_health_response_invalid')
    # EXACT original verify.yml predicate. Remote enabled/needs_operator/expiry
    # are not local profile-enabled or Journal readability and add no refusal.
    return payload['enabled'] and payload['status'] != 'unreadable'


class NativeHealth(NativeProbes):
    def wait_metadata(self, probe):
        # Ansible 2.21 task_executor includes the initial attempt PLUS retries.
        # Preserve that exact declared budget for each original metadata stage.
        retries, delay = self.data['verify_retries'], self.data['poll_delay']
        if type(retries) is not int or retries < 1 or type(delay) is not int or delay < 0:
            raise HealthError('runtime_health_polling_invalid')
        result = (False, None)
        for attempt in range(retries + 1):
            result = probe()
            if result[0]:
                return result
            if attempt < retries:
                time.sleep(delay)
        return result

    def health(self):
        data = self.data
        label = 'gui/' + str(self.account.pw_uid) + '/' + data['label']

        def keeper():
            loaded = self.run(['/bin/launchctl', 'print', label])
            if loaded.returncode not in {0, 113}:
                raise HealthError('runtime_health_launchd_unavailable')
            if loaded.returncode == 113:
                return False, None
            # Raw launchd may contain environment values. Retain only command
            # equality and PID in memory, exactly the existing metadata rails.
            listing = loaded.stdout.decode('utf-8', 'replace')
            arguments = re.search(r'(?ms)^\s*arguments = \{\n(.*?)^\s*\}', listing)
            current = arguments is not None and [line.strip() for line in arguments[1].splitlines() if line.strip()] == data['expected_argv']
            pid = re.search(r'(?m)^\s*pid = ([1-9][0-9]*)\s*$', listing)
            return current and pid is not None, int(pid[1]) if pid else None

        def serving():
            result = self.run(['/usr/bin/pgrep', '-u', data['user'], '-f', '[o]perations serve'])
            if result.returncode not in {0, 1}:
                raise HealthError('runtime_health_supervisor_unavailable')
            return result.returncode == 0, None

        def session():
            result = self.run([data['host_tmux'], '-L', data['host_socket'], 'has-session', '-t', '=supervisor'],
                              user=True, extra={'TMUX_TMPDIR': data['host_tmpdir']})
            # Exit 1 is nonreadiness, including a possible sudo-context denial,
            # so it consumes the bounded budget and still fails if persistent.
            # Other tool exit codes are unavailable immediately; no failure is
            # treated as success and no raw stderr is exported.
            if result.returncode not in {0, 1}:
                raise HealthError('runtime_health_session_unavailable')
            return result.returncode == 0, None

        # Same original order and independent per-stage startup budgets. No
        # executor CLI call is made/retried here; those follow readiness once.
        loaded, pid = self.wait_metadata(keeper)
        if not loaded or not self.wait_metadata(serving)[0]:
            return False, pid
        if data['mode'] == 'host' and not self.wait_metadata(session)[0]:
            return False, pid
        return True, pid

    def ready(self):
        state = observe(self.data, self)
        if not all(state[key] for key in ('enabled', 'source_current', 'resources_current', 'healthy')):
            raise HealthError('runtime_health_resources_not_current')

    def client(self, binding):
        data = self.data
        app = [data['python'], '-I', '-c', 'from daybook.cli import main; raise SystemExit(main())',
               'operations', 'status', '--policy', data['policy'], '--policy-owner', data['owner'], '--binding', binding]
        argv = [data['python'], '-I', '-c', STATUS_CAPTURE, *app]
        if os.geteuid() != self.account.pw_uid:
            argv = ['/usr/bin/sudo', '-H', '-S', '-n', '-i', '-u', data['user'], '--', *argv]
        # Original GUI/login context and application network bounds. No invented
        # whole-command deadline/retry or monitor/executor-purpose substitution.
        result = subprocess.run(argv, capture_output=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        if result.returncode:
            raise HealthError('runtime_health_cli_failed')
        try:
            _, separator, framed = result.stdout.rpartition(STATUS_FRAME)
            if not separator:
                raise ValueError()
            raw = base64.b64decode(framed.split(b'\n', 1)[0], validate=True)
            payload = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
            raise HealthError('runtime_health_response_invalid') from None
        if not healthy(result.returncode, payload):
            raise HealthError('runtime_health_local_unreadable_or_disabled')
        # No raw status/record/server object is retained or returned.


def verify(data, driver=None):
    driver = driver or NativeHealth(data)
    driver.ready()
    sources = data['status_sources']
    if not isinstance(sources, list) or not sources or len(sources) != len(set(sources)):
        raise HealthError('runtime_health_sources_invalid')
    for binding in sources:
        driver.client(binding)
    return {'verified': True, 'managed_cli_calls': len(sources)}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError()
        print(json.dumps(verify(json.loads(raw)), sort_keys=True))
    except Exception as error:
        category = str(error) if isinstance(error, HealthError) else 'runtime_health_unavailable'
        print(category, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
