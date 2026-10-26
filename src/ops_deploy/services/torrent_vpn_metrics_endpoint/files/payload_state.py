"""Read-only validity/freshness check for an existing collector payload."""
import json
from pathlib import Path
import sys
import time

try:
    value = json.loads(Path(sys.argv[1]).read_text())
    stamp = value['ts']
    valid = (
        isinstance(value, dict)
        and type(stamp) is int
        and 0 <= time.time() - stamp <= int(sys.argv[2])
        and isinstance(value['topology'], dict)
        and isinstance(value['vpn'], dict)
        and type(value['error']) is bool
    )
except (OSError, ValueError, KeyError, TypeError):
    valid = False
print('present' if valid else 'invalid')
