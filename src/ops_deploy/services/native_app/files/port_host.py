"""Read-only listener checks. Wait for binding, but never tolerate a foreign listener."""
import json
from pathlib import Path
import re
import subprocess
import sys
import time

cfg = json.loads(sys.argv[1])
for attempt in range(100 if cfg['required'] else 1):
    result = subprocess.run(['ss', '-H', '-lntp', 'sport = :' + str(cfg['port'])], capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()
    for line in lines:
        if line.split()[3] != '127.0.0.1:' + str(cfg['port']):
            raise SystemExit('native listener has an unexpected bind address')
        pids = re.findall(r'pid=(\d+)', line)
        if not pids or any(not any(cfg['unit'] + '.service' in line.split(':', 2)[-1].split('/') for line in Path('/proc/' + pid + '/cgroup').read_text().splitlines()) for pid in pids):
            raise SystemExit('native port belongs to another unit')
    if lines or not cfg['required']:
        print('ready')
        break
    time.sleep(0.2)
else:
    raise SystemExit('native listener is absent after bounded startup wait')
