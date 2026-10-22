"""Is a UniFi restart owed? (host side, python3 -I, read-only)

Prints ``inactive`` (the unit is not active: the start step covers it),
``owed`` (the Java argument file or the unit changed after the
running process started: an earlier run wrote it and failed before its
restart) or ``current``. The process start is the unit's
``ActiveEnterTimestamp`` in microseconds (UTC); file times are compared with
their full precision, so a write in the same second as the start still counts.
Argument: JSON with ``unit`` and ``paths``. Any other failure exits 1.
"""
import datetime
import json
import os
import subprocess
import sys


def systemctl(*args):
    result = subprocess.run(
        ['systemctl', *args], capture_output=True, text=True, env={'LC_ALL': 'C', 'PATH': os.environ.get('PATH', '')}
    )
    return result.returncode, result.stdout.strip()


def started_at(text):
    """``ActiveEnterTimestamp`` as printed with ``--timestamp=us+utc``: 'Wed 2026-10-21 05:00:00.123456 UTC'."""
    parts = text.split()
    if len(parts) != 4 or parts[3] != 'UTC':
        raise ValueError('unexpected ActiveEnterTimestamp')
    moment = datetime.datetime.strptime(parts[1] + ' ' + parts[2], '%Y-%m-%d %H:%M:%S.%f')
    return moment.replace(tzinfo=datetime.timezone.utc)


def decide(active, timestamp, mtimes_ns):
    """The answer for an ``is-active`` state, the timestamp text and the files' mtimes (ns)."""
    if active != 'active':
        return 'inactive'
    start = started_at(timestamp)
    start_ns = (start - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(
        microseconds=1
    ) * 1000
    return 'owed' if any(mtime > start_ns for mtime in mtimes_ns) else 'current'


def main(cfg):
    _, active = systemctl('is-active', cfg['unit'])
    if active != 'active':
        return decide(active, '', [])
    code, timestamp = systemctl('show', '--timestamp=us+utc', '-p', 'ActiveEnterTimestamp', '--value', cfg['unit'])
    if code != 0:
        raise ValueError('systemctl show failed')
    mtimes = [os.lstat(path).st_mtime_ns for path in cfg['paths'] if os.path.lexists(path)]
    return decide(active, timestamp, mtimes)


if __name__ == '__main__':
    try:
        print(main(json.loads(sys.argv[1])))
    except Exception as exc:
        print('restart probe failed: ' + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
