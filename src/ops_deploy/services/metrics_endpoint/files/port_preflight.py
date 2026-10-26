"""Read-only IPv4 bind collision check, allowing the existing endpoint unit."""
import json
from pathlib import Path
import re
import subprocess
import sys

cfg = json.loads(sys.argv[1])
port = str(cfg['port'])
addresses = {cfg['bind'], '0.0.0.0', '*', '[::]', '::'}
if cfg['bind'] == '127.0.0.1':
    addresses.update({'[::1]', '::1'})
result = subprocess.run(['ss', '-H', '-lntp', 'sport = :' + port], capture_output=True, text=True, check=True)
for line in result.stdout.splitlines():
    local = line.split()[3]
    address, _, _ = local.rpartition(':')
    if address not in addresses:
        continue
    pids = re.findall(r'pid=(\d+)', line)
    if not pids or any(not any(cfg['unit'] in item.split(':', 2)[-1].split('/') for item in Path('/proc/' + pid + '/cgroup').read_text().splitlines()) for pid in pids):
        raise SystemExit('metrics endpoint port belongs to another process')
print('ready')
