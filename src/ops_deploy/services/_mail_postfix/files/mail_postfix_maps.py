"""Compare the role's simple hash-map sources to native postmap listings."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def source_entries(text):
    entries = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = line.split(None, 1)
        if len(fields) != 2 or line[0].isspace():
            raise ValueError('unsupported role map source format')
        key, value = fields
        key = key.lower()
        if key in entries:
            raise ValueError('duplicate role map key')
        entries[key] = value.strip()
    return entries


def current(path):
    if not path.is_absolute() or '..' in path.parts or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('invalid role map source')
    desired = source_entries(path.read_text())
    compiled = Path(str(path)+'.db')
    try:
        info = compiled.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('invalid compiled role map')
    proc = subprocess.run(['postmap', '-s', 'hash:'+str(path)], capture_output=True, text=True, timeout=15)
    if proc.returncode or proc.stderr:
        raise RuntimeError('native Postfix map inspection failed')
    return source_entries(proc.stdout) == desired


def remember(marker):
    if not re.fullmatch(r'/var/lib/ops-deploy/mail-core/[a-z][a-z0-9-]*\.(?:restart|reload)', marker):
        raise ValueError('invalid map restart marker')
    path = Path(marker)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)


def main():
    data = json.load(sys.stdin)
    paths = [Path(path) for path in data['paths']]
    pending = [path for path in paths if not current(path)]
    if sys.argv[1] == 'check':
        print('pending' if pending else 'current')
    elif sys.argv[1] == 'apply':
        for path in pending:
            remember(data['restart_marker'])
            proc = subprocess.run(['postmap', str(path)], capture_output=True, timeout=15)
            if proc.returncode or not current(path):
                raise RuntimeError('native Postfix map compilation failed')
    else:
        raise ValueError('invalid map action')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Mail Postfix map operation failed; protected details withheld', file=sys.stderr)
        raise SystemExit(1) from None
