"""Known alert relay/SMART/ZED configuration, no hardware health commands.

Read-only state checks never run smartctl, scrub, spindown or the collectors.
Apply changes only owned settings/files and keeps small known rollout debt for
retry after a configuration write. No generic runtime-state attestation marker.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

STATE = Path('/var/lib/ops-deploy/monitoring-infra')
KINDS = {'relay', 'smartd', 'zed'}


def safe(path, optional=False):
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            if optional:
                continue
            raise
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('symlink in managed monitoring configuration')
        if part == path and not stat.S_ISREG(info.st_mode):
            raise ValueError('nonregular monitoring configuration')


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=45).stdout.strip()


def read(path):
    safe(path, optional=True)
    if Path(path).exists() and Path(path).stat().st_size>16*1024*1024:raise ValueError('oversized managed monitoring configuration')
    return Path(path).read_text() if Path(path).exists() else None


def line(text, expression, desired):
    lines = (text or '').splitlines(keepends=True)
    found = [n for n, item in enumerate(lines) if re.search(expression, item)]
    if found:
        lines[found[-1]] = desired + '\n'
    else:
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines.append(desired + '\n')
    return ''.join(lines)


def rows(v):
    items = list(v['files'])
    for edit in v.get('lines', []):
        text = read(edit['path'])
        for change in edit['values']:
            text = line(text, change['regex'], change['value'])
        items.append({'path': edit['path'], 'content': text, 'mode': edit['mode']})
    return items


def matches(row):
    if read(row['path']) != row['content']:
        return False
    if row['mode'] is None:
        return True
    info = Path(row['path']).stat()
    return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, row['mode'])


def write(row):
    path = Path(row['path']);safe(path, optional=True)
    info = path.stat() if path.exists() else None
    mode = row['mode'] if row['mode'] is not None else (stat.S_IMODE(info.st_mode) if info else 0o644)
    owner = (0, 0) if row['mode'] is not None or info is None else (info.st_uid, info.st_gid)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.ops-deploy-monitoring-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(row['content']);stream.flush();os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode);os.fchown(stream.fileno(), *owner)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def unit(name):
    text = run(['systemctl', 'show', name, '--property=LoadState,ActiveState,UnitFileState'])
    value = dict(row.split('=', 1) for row in text.splitlines() if '=' in row)
    if value.get('LoadState') not in ('loaded', 'not-found'):
        raise ValueError('unknown monitoring unit state')
    return value


def pending_units(v):
    for name in v['units']:
        value = unit(name)
        if value.get('LoadState') != 'loaded' or value.get('ActiveState') != 'active' or value.get('UnitFileState') != 'enabled':
            return True
    if v['kind'] == 'relay':
        status = subprocess.run(['postfix', 'status'], capture_output=True, text=True, timeout=15)
        if status.returncode:
            return True
    return False


def postfix_changes(v):
    return {key: value for key, value in v.get('postfix', {}).items() if run(['postconf', '-h', key]) != value}


def debt_path(v):
    return STATE / (v['kind'] + '-restart-owed.json')


def get_debt(v):
    text = read(debt_path(v))
    if text is None:return None
    value = json.loads(text)
    if (not isinstance(value, dict) or set(value) != {'restart_units', 'reload'}
            or not isinstance(value['restart_units'], list) or not set(value['restart_units']) <= set(v['restart_units'])
            or type(value['reload']) is not bool):
        raise ValueError('unknown monitoring rollout debt')
    return value


def pending(v):
    if v['kind'] == 'relay' and shutil.which('postconf') is None:
        found = subprocess.run(['dpkg-query', '-W', '-f=${db:Status-Status}', 'postfix'], capture_output=True, text=True)
        if found.returncode == 0 and found.stdout.strip() != 'installed':
            return True
        if found.returncode == 1 and 'no packages found matching postfix' in found.stderr:
            return True
        raise ValueError('Postfix package/tool state is unknown')
    return any(not matches(row) for row in rows(v)) or bool(postfix_changes(v)) or get_debt(v) is not None or pending_units(v)


def validate_units(desired):
    units = [row for row in desired if row['path'].startswith('/etc/systemd/system/')]
    if units:
        with tempfile.TemporaryDirectory(prefix='monitoring-units-', dir='/run') as directory:
            paths = []
            for row in units:
                path = Path(directory) / Path(row['path']).name
                path.write_text(row['content']);paths.append(str(path))
            run(['systemd-analyze', 'verify', *paths])


def apply(v):
    if v['kind'] == 'relay' and shutil.which('postconf') is None:
        raise ValueError('Postfix prerequisites unavailable after package operation')
    desired = rows(v)
    changes = [row for row in desired if not matches(row)]
    postfix = postfix_changes(v)
    previous = get_debt(v)
    restart = set(previous['restart_units']) if previous else set()
    reload_needed = bool(previous and previous['reload'])
    if postfix or any(row.get('restart', True) for row in changes):
        restart.update(v['restart_units'])
    reload_needed = reload_needed or any(row['path'].startswith('/etc/systemd/system/') for row in changes)
    if changes or postfix:
        validate_units(changes)
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        write({'path': str(debt_path(v)), 'content': json.dumps({'restart_units': sorted(restart), 'reload': reload_needed})+'\n', 'mode': 0o600})
        for row in changes:write(row)
        if postfix:run(['postconf', '-e', *[key+'='+value for key, value in postfix.items()]])
    if reload_needed:run(['systemctl', 'daemon-reload'])
    for name in sorted(restart - set(v['units'])):
        run(['systemctl', 'restart', name])
    if v['kind'] == 'relay':
        if postfix_changes(v):raise ValueError('declared relay settings did not converge before daemon start')
        run(['postfix', 'check'])
    for name in v['units']:
        value = unit(name)
        if value.get('UnitFileState') != 'enabled':run(['systemctl', 'enable', name])
        if name in restart:run(['systemctl', 'restart', name])
        elif value.get('ActiveState') != 'active':run(['systemctl', 'start', name])
        elif v['kind'] == 'relay' and name == 'postfix' and subprocess.run(['postfix', 'status'], capture_output=True, timeout=15).returncode:
            run(['systemctl', 'restart', name])
    # No scrub service, smartctl query or spindown helper is invoked here.
    if pending_units(v):raise ValueError('monitoring services did not converge')
    path = debt_path(v)
    if path.exists():path.unlink()


def bootstrap():
    target = Path('/etc/postfix/main.cf')
    safe(target, optional=True)
    if target.exists():return  # A concurrently created configuration is never replaced.
    source = Path('/usr/share/postfix/main.cf.debian');safe(source)
    content = source.read_bytes()
    descriptor, temporary = tempfile.mkstemp(prefix='.main.cf-bootstrap-', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content);stream.flush();os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644);os.fchown(stream.fileno(), 0, 0)
        try:os.link(temporary, target)
        except FileExistsError:pass
    finally:os.unlink(temporary)


def main():
    if sys.argv[1] == 'bootstrap':bootstrap();return
    v = json.load(sys.stdin)
    if v['kind'] not in KINDS or sys.argv[1] not in ('check', 'apply'):
        raise ValueError('invalid monitoring action')
    if sys.argv[1] == 'check':
        print('pending' if pending(v) else 'current');return
    safe(STATE / 'lock', optional=True)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        os.chmod(STATE / 'lock', 0o600);fcntl.flock(lock, fcntl.LOCK_EX)
        apply(v)
    print('current')


if __name__ == '__main__':
    try:main()
    except Exception:
        print('Monitoring configuration/rollout failed; known debt retained after managed writes', file=sys.stderr)
        sys.exit(1)
