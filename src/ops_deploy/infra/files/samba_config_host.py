"""Preserving Samba configuration and a small durable restart-owed record.

Candidate testparm runs before managed writes; unrelated includes/globals stay.
No share data is opened. Restart only consumes known config debt, deduplicated
for a whole share batch. Runtime state is never inferred from a config hash.
"""
import fcntl
import json
import os
import pathlib
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

STATE = pathlib.Path('/var/lib/ops-deploy/samba')
BEGIN = '# BEGIN ANSIBLE MANAGED - vfs_fruit global settings'
END = '# END ANSIBLE MANAGED - vfs_fruit global settings'


def safe(path):
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('symlink in managed Samba path')
        if part == path and not stat.S_ISREG(info.st_mode):
            raise ValueError('nonregular managed Samba file')


def read(path):
    safe(path)
    return path.read_text() if path.exists() else None


def matches(path, text):
    original = read(path)
    if original != text:
        return False
    st = path.stat()
    return (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (0, 0, 0o644)


def candidate(original, request):
    text = request['base'] if original is None else original
    lines = text.splitlines(keepends=True)
    global_lines = [i for i, line in enumerate(lines) if re.fullmatch(r'\s*\[global\]\s*', line, re.I)]
    if len(global_lines) != 1:
        raise ValueError('expected one global Samba section')
    # An include can leave Samba's parser inside its final share section.
    # New includes therefore belong after all textual global directives. Never
    # move an existing include: deployed configurations retain their exact order.
    paths = {fragment['path'] for fragment in request['fragments']}
    include = re.compile(r'^\s*include\s*=\s*(.*?)\s*$', re.I)
    if original is None:
        # The vendored cf3 base template put its generated include too early.
        # Relocate only that generated operand, preserving the original resource.
        lines = [line for line in lines if not ((match := include.fullmatch(line.rstrip('\r\n')))
                                               and match[1] in paths)]
    global_index = next(i for i, line in enumerate(lines) if re.fullmatch(r'\s*\[global\]\s*', line, re.I))
    for fragment in request['fragments']:
        path = fragment['path']
        if not any((match := include.fullmatch(line.rstrip('\r\n'))) and match[1] == path for line in lines):
            end = next((i for i in range(global_index+1, len(lines)) if re.match(r'^\s*\[', lines[i])), len(lines))
            if end and not lines[end-1].endswith('\n'):
                lines[end-1] += '\n'
            lines.insert(end, '   include = '+path+'\n')
    if request.get('fruit') is not None:
        starts = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == BEGIN]
        ends = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == END]
        block = BEGIN+'\n'+request['fruit']+END+'\n'
        if not starts and not ends:
            lines.insert(global_lines[0]+1, block)
        elif len(starts) == len(ends) == 1 and starts[0] < ends[0]:
            lines[starts[0]:ends[0]+1] = [block]
        else:
            raise ValueError('ambiguous managed fruit block')
    return ''.join(lines)


def rows(request):
    path = pathlib.Path(request['config'])
    return [(path, candidate(read(path), request))] + [(pathlib.Path(row['path']), row['content']) for row in request['fragments']]


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


def unit(name):
    raw = run(['systemctl', 'show', name, '--property=LoadState,ActiveState,UnitFileState'])
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    if not values.get('LoadState'):
        raise ValueError('unknown Samba service state')
    return values


def config_pending(request, desired):
    return any(not matches(path, text) for path, text in desired)


def rollout_pending(request):
    debt = read(STATE / 'restart-owed.json')
    if debt is not None:
        parsed = json.loads(debt)
        if parsed != {'units': ['smbd', 'nmbd']}:
            raise ValueError('unknown Samba restart debt')
    pending = debt is not None or request['service_state'] == 'restarted'
    for name in ('smbd', 'nmbd'):
        values = unit(name)
        if values['LoadState'] == 'not-found':
            pending = True
        elif values['LoadState'] != 'loaded':
            raise ValueError('unknown Samba service load state')
        expected = 'inactive' if request['service_state'] == 'stopped' else 'active'
        if values.get('ActiveState') != expected or (values.get('UnitFileState') == 'enabled') != request['service_enabled']:
            pending = True
    return pending


def write(path, text, mode=0o644):
    safe(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.ops-deploy-samba-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchown(handle.fileno(), 0, 0)
            os.fchmod(handle.fileno(), mode)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate(desired):
    with tempfile.TemporaryDirectory(prefix='samba-candidate-', dir='/run') as temporary:
        paths = {}
        for n, (path, text) in enumerate(desired[1:]):
            staged = pathlib.Path(temporary) / ('share-'+str(n)+'.conf')
            staged.write_text(text)
            paths[str(path)] = str(staged)
        text = desired[0][1]
        # Rewrite only the declared include operands to staged candidate files;
        # preserve all unowned include statements and other configuration.
        for original, staged in paths.items():
            text = re.sub(r'(?im)^(\s*include\s*=\s*)'+re.escape(original)+r'(\s*)$',
                          lambda m: m[1]+staged+m[2], text)
        config = pathlib.Path(temporary) / 'smb.conf'
        config.write_text(text)
        run(['testparm', '-s', str(config)])


def configure(request, desired):
    if not config_pending(request, desired):
        return
    validate(desired)
    write(STATE / 'restart-owed.json', json.dumps({'units': ['smbd', 'nmbd']}), mode=0o600)
    for path, text in desired:
        if not matches(path, text):
            write(path, text)
    # Validate actual includes again; keep debt if interrupted or a peer wrote
    # incompatible config. Do not restart a daemon with an invalid candidate.
    run(['testparm', '-s', request['config']])


def rollout(request):
    run(['testparm', '-s', request['config']])
    debt = read(STATE / 'restart-owed.json') is not None
    for name in ('smbd', 'nmbd'):
        values = unit(name)
        wanted_enabled = request['service_enabled']
        if (values.get('UnitFileState') == 'enabled') != wanted_enabled:
            run(['systemctl', 'enable' if wanted_enabled else 'disable', name])
        if request['service_state'] == 'stopped':
            if values.get('ActiveState') != 'inactive':
                run(['systemctl', 'stop', name])
        elif debt or request['service_state'] == 'restarted':
            run(['systemctl', 'restart', name])
        elif values.get('ActiveState') != 'active':
            run(['systemctl', 'start', name])
    if request['service_state'] != 'stopped':
        for attempt in range(30):
            try:
                with socket.create_connection(('127.0.0.1', 445), timeout=1):
                    break
            except OSError:
                if attempt == 29:
                    raise
                time.sleep(1)
    debtpath = STATE / 'restart-owed.json'
    if debtpath.exists():
        debtpath.unlink()


def main():
    request = json.load(sys.stdin)
    action = sys.argv[1]
    desired = rows(request)
    if action == 'check':
        print('pending' if config_pending(request, desired) else 'current')
        return
    if action == 'rollout-check':
        print('pending' if rollout_pending(request) or config_pending(request, desired) else 'current')
        return
    if action not in ('apply', 'rollout'):
        raise ValueError('invalid Samba configuration action')
    safe(STATE / 'lock')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE / 'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == 'apply':
            configure(request, rows(request))
        else:
            if config_pending(request, rows(request)):
                raise ValueError('Samba config changed before rollout')
            if rollout_pending(request):
                rollout(request)
    print('current')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Samba configuration validation/reconciliation failed; restart debt is retained after managed writes', file=sys.stderr)
        sys.exit(1)
