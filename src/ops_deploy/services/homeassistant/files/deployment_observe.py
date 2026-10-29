"""Bounded normal-role prerequisite/selection metadata; no API or body export."""
import json
import sys
from pathlib import Path


def observe(payload):
    path = Path(payload['path'])
    if payload['kind'] == 'uv':
        return {'exists': path.exists()}
    if payload['kind'] != 'custom':
        raise ValueError('unknown observation')
    if not path.exists():
        return {'count': 0}
    value = json.loads(path.read_bytes())
    entries = (value.get('data') or {}).get('entries') or []
    return {'count': sum(entry.get('domain') == 'custom_conversation' for entry in entries)}


def main():
    try:
        result = observe(json.load(sys.stdin))
    except Exception:
        print(json.dumps({'success': False}))
        return 1
    print(json.dumps({'success': True, **result}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
