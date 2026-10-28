"""Sanoid config/timer reconciler. No ZFS/Sanoid executable is invoked.

The small restart-owed record survives interruption after known writes. It is
not a statement about dataset/hardware state. Unit checks inspect metadata only.
"""
import configparser
import fcntl
import grp
import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import tempfile

STATE = pathlib.Path('/var/lib/ops-deploy/sanoid')


def regular(path):
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('symlink in managed Sanoid path')
        if part == path and not stat.S_ISREG(info.st_mode):
            raise ValueError('nonregular managed Sanoid file')


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def unit(name):
    raw = run(['systemctl', 'show', name, '--property=LoadState,ActiveState,UnitFileState,NeedDaemonReload'])
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    if not values.get('LoadState'):
        raise ValueError('unknown systemd unit state')
    return values


def matches(path, content, uid, gid, mode):
    regular(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        return False
    return path.read_text() == content and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode)


def write(path, content, uid=0, gid=0, mode=0o644):
    regular(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.sanoid-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            os.fchown(output.fileno(), uid, gid)
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def desired(request):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(request['config'])
    if not parser.sections():
        raise ValueError('empty Sanoid policy')
    rows = [(pathlib.Path(request['config_path']), request['config'],
             pwd.getpwnam(request['config_owner']).pw_uid, grp.getgrnam(request['config_group']).gr_gid,
             int(request['config_mode'], 8))]
    if request['manage_systemd']:
        rows += [(pathlib.Path('/etc/systemd/system') / request[key+'_name'], request[key], 0, 0, 0o644)
                 for key in ('service', 'timer')]
    return rows


def pending(request, rows):
    changed = any(not matches(*row) for row in rows)
    regular(STATE / 'restart-owed.json')
    if (STATE / 'restart-owed.json').exists():
        expected = {'service': request['service_name'], 'timer': request['timer_name'],
                    'manage_systemd': request['manage_systemd']}
        if json.loads((STATE / 'restart-owed.json').read_text()) != expected:
            raise ValueError('Sanoid restart debt belongs to different unit settings')
        changed = True
    if request['manage_systemd']:
        timer = unit(request['timer_name'])
        service = unit(request['service_name'])
        if (timer.get('LoadState') != 'loaded' or timer.get('UnitFileState') != 'enabled'
                or timer.get('ActiveState') != 'active' or timer.get('NeedDaemonReload') == 'yes'
                or service.get('NeedDaemonReload') == 'yes'):
            changed = True
        if request['disable_package_timers']:
            for name in ('sanoid.timer', 'sanoid-prune.timer'):
                values = unit(name)
                if values['LoadState'] != 'not-found' and (values.get('ActiveState') == 'active'
                        or values.get('UnitFileState') == 'enabled'):
                    changed = True
    return changed


def apply(request, rows):
    # Validate candidate units before installing any policy or owed record. The
    # native verifier never starts the oneshot and never runs its ExecStart.
    if request['manage_systemd']:
        with tempfile.TemporaryDirectory(prefix='sanoid-verify-', dir='/run') as temporary:
            paths = []
            for key in ('service', 'timer'):
                path = pathlib.Path(temporary) / request[key+'_name']
                path.write_text(request[key])
                paths.append(str(path))
            run(['systemd-analyze', 'verify', *paths])
    debt = STATE / 'restart-owed.json'
    regular(debt)
    # Persist before any managed file, allowing an interrupted write/reload to
    # recover even when the next invocation sees byte-current files.
    write(debt, json.dumps({'service': request['service_name'], 'timer': request['timer_name'],
                            'manage_systemd': request['manage_systemd']}), mode=0o600)
    for row in rows:
        if not matches(*row):
            write(*row)
    if request['manage_systemd']:
        if request['disable_package_timers']:
            for name in ('sanoid.timer', 'sanoid-prune.timer'):
                if unit(name)['LoadState'] != 'not-found':
                    run(['systemctl', 'disable', '--now', name])
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', request['timer_name']])
        # Restart the timer only; never start/restart its Sanoid oneshot.
        run(['systemctl', 'restart', request['timer_name']])
        actual = unit(request['timer_name'])
        if actual.get('ActiveState') != 'active' or actual.get('UnitFileState') != 'enabled':
            raise ValueError('Sanoid timer did not become active and enabled')
    debt.unlink()


def main():
    request = json.load(sys.stdin)
    if sys.argv[1] not in ('check', 'apply'):
        raise ValueError('unknown Sanoid action')
    rows = desired(request)
    if sys.argv[1] == 'check':
        print('pending' if pending(request, rows) else 'current')
        return
    # Only the managed apply opens/creates its serialization lock.
    regular(STATE / 'lock')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE / 'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if pending(request, rows):
            apply(request, rows)
        if pending(request, rows):
            raise ValueError('Sanoid state remains pending')
    print('current')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Sanoid configuration/timer reconciliation failed; no manual snapshot run was attempted', file=sys.stderr)
        sys.exit(1)
