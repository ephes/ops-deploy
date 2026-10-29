"""Original MANAGED update preflight. Application status can read its Journal
and expire binding authority. Only sanitized operational metadata is returned;
no signals, bootout, source replacement or record/response bodies are exported.
"""

import dataclasses
import json
import sys

from ops_daybook_guards import RuntimeGuardError, require_stop_prerequisites, require_stop_ready
from ops_daybook_observer import MAX_INPUT, ObservationError
from ops_daybook_stop import NativeStop, StopError


class NativePreflight(NativeStop):
    def label(self):
        result = super().label()
        if result.returncode == 113:
            expected = ('Could not find service "' + self.data['label'] + '" in domain').encode()
            if expected not in (result.stderr or b''):
                raise StopError('runtime_preflight_label_unavailable')
        return result


def original_preflight(data, driver=None):
    driver = driver or NativePreflight(data)
    state = driver.snapshot()
    require_stop_prerequisites(driver.cfg, state)
    driver.window(state.running)
    # Original preflight retry count is zero: query every named executor source
    # once, with original Journal/binding-expiry effects, never as facts.
    sources = tuple(driver.source(binding) for binding in driver.cfg.status_sources)
    require_stop_ready(driver.cfg, dataclasses.replace(state, sources=sources), preflight=True)
    return {'ready': True, 'running': state.running, 'managed_cli_calls': len(sources), 'stopped': False}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise StopError('runtime_preflight_request_too_large')
        print(json.dumps(original_preflight(json.loads(raw)), sort_keys=True))
    except Exception as error:
        message = str(error) if isinstance(error, (RuntimeGuardError, ObservationError, StopError)) else 'runtime_preflight_unavailable'
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
