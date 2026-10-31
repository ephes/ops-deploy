"""Original service-user STT registry wait; selected input stays on stdin."""
import json
import sys
import time
from pathlib import Path


def wait(payload):
    attempts = 0
    for attempt in range(max(0, payload['retries']) + 1):
        attempts += 1
        try:
            document = json.loads(Path(payload['registry']).read_text())
            entities = document.get('data', {}).get('entities', [])
            if any(entry.get('entity_id') == payload['entity_id'] for entry in entities):
                return {'success': True, 'attempts': attempts}
        except Exception:
            # Original command has failed_when:false while retrying; the
            # subsequent explicit task fails if its final exit is still nonzero.
            pass
        if attempt < max(0, payload['retries']):
            time.sleep(max(0, payload['delay']))
    return {'success': False, 'attempts': attempts}


if __name__ == '__main__':
    result = wait(json.load(sys.stdin))
    print(json.dumps(result))
    raise SystemExit(0 if result['success'] else 1)
