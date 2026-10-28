"""Original optional pre-quiesce aggregate, explicitly managed app work.

The original application may read its ledger. Only owned fixtures exercise it
until a real transition/source/window packet specifically authorizes the call.
No application/ledger call belongs to available() or another status fact.
"""

import json
import os
import pathlib
import re
import stat
import subprocess
import sys

from ops_daybook_observer import NativeProbes
from ops_inbox_python import require_root_inputs


def available(data):
    """Declared metadata only, no UV/interpreter/application/credential calls."""
    try:
        if os.geteuid() != 0:
            return False
        account = NativeProbes(data).account
        if account.pw_uid != data['uid'] or account.pw_dir != data['home']:
            return False
        require_root_inputs(data)
        for name in ('python', 'policy'):
            info = pathlib.Path(data[name]).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                    or info.st_mode & 0o022):
                return False
        return bool(os.access(data['python'], os.X_OK))
    except Exception:
        # Original report is best effort, never a new safety/refusal guard.
        return False


def report(data):
    if not available(data):
        return {'reported': False}
    try:
        argv = ['/bin/launchctl', 'asuser', str(data['uid']), '/usr/bin/sudo', '-u', data['user'],
                '/usr/bin/env', 'HOME=' + data['home'], 'DAYBOOK_VOICE_MEMOS_POLICY=' + data['policy'],
                data['python'], '-I', '-c', 'from daybook.cli import main; raise SystemExit(main())',
                'voice-memos', 'status', '--summary-only']
        # Exact original context and application bounds; no invented whole-call
        # timeout or retries. Raw streams remain private memory, never logs.
        result = subprocess.run(argv, cwd=data['checkout'], capture_output=True,
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
            return {'reported': False}
        found = re.search(rb'"long_in_flight_count"[^0-9a-z-]{0,4}([0-9]+)', result.stdout)
        if found is None or len(found[1]) > 20:
            return {'reported': False}
        return {'reported': True, 'long_in_flight_count': int(found[1])}
    except Exception:
        return {'reported': False}


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)
        if action == 'available':
            result = {'available': available(data)}
        elif action == 'report':
            result = report(data)
        else:
            raise ValueError()
    except Exception:
        result = {'available': False} if action == 'available' else {'reported': False}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
