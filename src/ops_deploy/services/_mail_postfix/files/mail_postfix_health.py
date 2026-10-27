"""Postfix's systemd wrapper may be active with MainPID=0; check the master."""
import os
from pathlib import Path
import subprocess
import sys

try:
    def setting(name):
        result = subprocess.run(['postconf', '-h', name], capture_output=True, text=True, timeout=5)
        if result.returncode or result.stderr:
            raise RuntimeError('Postfix process setting failed')
        return result.stdout.strip()

    directory = Path(setting('process_id_directory'))
    if not directory.is_absolute():
        directory = Path(setting('queue_directory')) / directory
    pid = int((directory / 'master.pid').read_text().split()[0])
    if pid < 2 or os.readlink('/proc/'+str(pid)+'/exe') != '/usr/lib/postfix/sbin/master':
        raise RuntimeError('Postfix master identity differs')
    os.kill(pid, 0)
except Exception:
    print('Actual Postfix master process check failed', file=sys.stderr)
    raise SystemExit(1) from None
