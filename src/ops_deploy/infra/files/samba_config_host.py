"""Preserving Samba configuration and a small durable restart-owed record.

Candidate testparm runs before managed writes; unrelated includes/globals stay,
except that owned and snippet-directory includes move to the end of [global]
(so later globals are not parsed into the last included share) and distro
guest settings (map to guest other than never, usershare allow guests) are
commented out.
No share data is opened. Restart only consumes known config debt, deduplicated
for a whole share batch. Runtime state is never inferred from a config hash.
A batch that changes only share snippets (smb.conf itself current) owes a
config reload (smbcontrol all reload-config) instead of a restart, so open
sessions such as a running Time Machine backup survive; a recorded restart
debt is never downgraded to a reload.
"""
import fcntl
import json
import os
import pathlib
import posixpath
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

STATE = pathlib.Path('/var/lib/ops-deploy/samba')
BEGIN = '# BEGIN ANSIBLE MANAGED - vfs_fruit global settings'
RESTART_DEBT = {'units': ['smbd', 'nmbd']}
RELOAD_DEBT = {'units': ['smbd', 'nmbd'], 'action': 'reload-config'}
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


FRUIT_GLOBAL = {'fruit:aapl', 'fruit:nfs_aces', 'fruit:copyfile', 'fruit:model'}
SECTION = re.compile(r'^\s*\[')
INCLUDE = re.compile(r'^\s*include\s*=\s*(.*?)\s*$', re.I)
# Guest settings the distro smb.conf ships that must never take effect: the
# managed shares refuse guests (owner decision 2026-11-13). Lines are kept as
# a marked comment so the change stays visible and is applied only once.
GUEST_OFF = '# ops-deploy: no guest access: '
GUEST = {'maptoguest': lambda value: value != 'never',
         'usershareallowguests': lambda value: value in ('yes', 'true', '1', 'on')}


def directive(line):
    text = line.strip()
    return bool(text) and not text.startswith(('#', ';'))


def global_body(lines):
    """Return (header, end): [global]'s line index and its first line after."""
    headers = [i for i, line in enumerate(lines) if re.fullmatch(r'\s*\[global\]\s*', line, re.I)]
    if len(headers) != 1:
        raise ValueError('expected one global Samba section')
    end = next((i for i in range(headers[0]+1, len(lines)) if SECTION.match(lines[i])), len(lines))
    return headers[0], end


def candidate(original, request):
    text = request['base'] if original is None else original
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith('\n'):
        lines[-1] += '\n'
    header, end = global_body(lines)
    for i in range(header+1, end):
        if directive(lines[i]) and '=' in lines[i]:
            key, value = lines[i].split('=', 1)
            check = GUEST.get(''.join(key.split()).casefold())
            if check and check(value.strip().casefold()):
                lines[i] = GUEST_OFF+lines[i].strip()+'\n'
    if request.get('fruit') is not None:
        starts = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == BEGIN]
        ends = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == END]
        block = BEGIN+'\n'+request['fruit']+END+'\n'
        if not starts and not ends:
            lines.insert(header+1, block)
        elif len(starts) == len(ends) == 1 and starts[0] < ends[0]:
            lines[starts[0]:ends[0]+1] = [block]
        else:
            raise ValueError('ambiguous managed fruit block')
        lines = ''.join(lines).splitlines(keepends=True)
    # Once the includes below move, the managed block really is [global]: it
    # may then only hold fruit's global-only options, or every share would
    # start loading vfs_fruit. An older block (share options from before the
    # Time Machine snippet carried them) is replaced only by the Time Machine
    # deploy; any other deploy refuses until that has run.
    starts = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == END]
    for start, stop in zip(starts, ends):
        for line in lines[start+1:stop]:
            if directive(line) and ''.join(line.split('=', 1)[0].split()).casefold() not in FRUIT_GLOBAL:
                raise ValueError('managed fruit block holds share options; deploy samba_timemachine first')
    # An include leaves Samba's parser inside the last section of the included
    # file, so every global line after it belongs to that share. Owned includes
    # and every include of the managed snippet directory therefore move to the
    # end of [global] (directly before the next section header), in their
    # existing order; new owned includes follow them. Other includes and all
    # other lines stay where they are.
    paths = [fragment['path'] for fragment in request['fragments']]
    snippets = request.get('snippet_dir')
    header, end = global_body(lines)

    def movable(operand):
        return operand in paths or (snippets is not None and posixpath.dirname(operand) == snippets.rstrip('/'))

    moved = [match[1] for i in range(header+1, end)
             if (match := INCLUDE.fullmatch(lines[i].rstrip('\r\n'))) and movable(match[1])]
    lines = [line for i, line in enumerate(lines)
             if not (header < i < end and (match := INCLUDE.fullmatch(line.rstrip('\r\n'))) and movable(match[1]))]
    present = {match[1] for line in lines if (match := INCLUDE.fullmatch(line.rstrip('\r\n')))}
    moved += [path for path in paths if path not in present and path not in moved]
    header, end = global_body(lines)
    lines[end:end] = ['   include = '+path+'\n' for path in moved]
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


def owed():
    """Return None, 'restart' or 'reload' from the durable debt record."""
    raw = read(STATE / 'restart-owed.json')
    if raw is None:
        return None
    parsed = json.loads(raw)
    if parsed == RESTART_DEBT:
        return 'restart'
    if parsed == RELOAD_DEBT:
        return 'reload'
    raise ValueError('unknown Samba restart debt')


def rollout_pending(request):
    debt = owed()
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
    # smb.conf itself (globals, includes, the fruit block) needs a restart;
    # share snippets alone are applied by a reload. Never downgrade a debt.
    path, text = desired[0]
    restart = owed() == 'restart' or not matches(path, text)
    write(STATE / 'restart-owed.json', json.dumps(RESTART_DEBT if restart else RELOAD_DEBT), mode=0o600)
    for path, text in desired:
        if not matches(path, text):
            write(path, text)
    # Validate actual includes again; keep debt if interrupted or a peer wrote
    # incompatible config. Do not restart a daemon with an invalid candidate.
    run(['testparm', '-s', request['config']])


def rollout(request):
    run(['testparm', '-s', request['config']])
    debt = owed()
    for name in ('smbd', 'nmbd'):
        values = unit(name)
        wanted_enabled = request['service_enabled']
        if (values.get('UnitFileState') == 'enabled') != wanted_enabled:
            run(['systemctl', 'enable' if wanted_enabled else 'disable', name])
        if request['service_state'] == 'stopped':
            if values.get('ActiveState') != 'inactive':
                run(['systemctl', 'stop', name])
        elif debt == 'restart' or request['service_state'] == 'restarted':
            run(['systemctl', 'restart', name])
        elif values.get('ActiveState') != 'active':
            run(['systemctl', 'start', name])
    if debt == 'reload' and request['service_state'] == 'started':
        # Running daemons re-read smb.conf; new tree connects use the new share
        # options, existing sessions are kept (they keep theirs until reconnect).
        run(['smbcontrol', 'all', 'reload-config'])
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
    except Exception as error:
        # The ValueErrors here carry no config or secret content.
        reason = ': '+str(error) if isinstance(error, ValueError) else ''
        print('Samba configuration validation/reconciliation failed'+reason+'; restart debt is retained after managed writes', file=sys.stderr)
        sys.exit(1)
