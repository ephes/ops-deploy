"""Owned hdparm block reconciliation; check never opens a block device.

An unchanged block does not attest drive state. Immediate application is only
for an actual block change. A failed physical apply is not transactional;
explicit operator reassertion is the documented recovery path.
"""
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

PATH = pathlib.Path('/etc/hdparm.conf')
BEGIN = '# BEGIN ANSIBLE MANAGED BLOCK: hdparm_tune'
END = '# END ANSIBLE MANAGED BLOCK: hdparm_tune'


def candidate(original, block):
    lines = original.splitlines(keepends=True)
    starts = [n for n, line in enumerate(lines) if line.rstrip('\r\n') == BEGIN]
    ends = [n for n, line in enumerate(lines) if line.rstrip('\r\n') == END]
    if not starts and not ends:
        return original + ('\n' if original and not original.endswith('\n') else '') + BEGIN+'\n'+block+END+'\n'
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError('ambiguous hdparm managed block')
    return ''.join(lines[:starts[0]+1]) + block + ''.join(lines[ends[0]:])


def main():
    request = json.load(sys.stdin)
    if sys.argv[1] not in ('check', 'apply'):
        raise ValueError('invalid hdparm action')
    try:
        st = PATH.lstat()
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise ValueError('hdparm configuration is not a regular file')
    original = PATH.read_text() if st is not None else ''
    desired = candidate(original, request['block'])
    if desired == original:
        print(json.dumps({'state': 'current', 'physical_state': 'not_queried'}))
        return
    if sys.argv[1] == 'check':
        print(json.dumps({'state': 'pending', 'physical_state': 'not_queried'}))
        return
    fd, temporary = tempfile.mkstemp(prefix='.hdparm.ops-deploy.', dir=str(PATH.parent))
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(desired)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), stat.S_IMODE(st.st_mode) if st else 0o644)
            os.fchown(handle.fileno(), st.st_uid if st else 0, st.st_gid if st else 0)
        if st is not None:
            for key in os.listxattr(PATH):
                os.setxattr(temporary, key, os.getxattr(PATH, key))
            actual = PATH.lstat()
            if (actual.st_ino, actual.st_size, actual.st_mtime_ns) != (st.st_ino, st.st_size, st.st_mtime_ns):
                raise ValueError('hdparm config changed concurrently')
        os.replace(temporary, PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if request['apply_now']:
        # Same role order: all APM, then acoustic, then spindown commands.
        for field, flag in (('apm', '-B'), ('acoustic_management', '-M'), ('spindown_time', '-S')):
            for device in request['devices']:
                if device.get(field) is not None:
                    subprocess.run(['hdparm', flag, str(device[field]), device['device']], check=True, capture_output=True)
    print(json.dumps({'state': 'applied', 'physical_state': 'application_attempted' if request['apply_now'] else 'not_queried'}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Persistent hdparm reconciliation or changed-block application failed; hardware state is not attested', file=sys.stderr)
        sys.exit(1)
