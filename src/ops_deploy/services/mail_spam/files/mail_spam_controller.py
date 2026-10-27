"""Stable native Rspamd controller credential; protected stdin, fixed output only."""
import errno
import fcntl
import grp
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time


def run(args, replies):
    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(slave, termios.TCSANOW, attrs)

    def child():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}
    proc = subprocess.Popen(['/usr/bin/rspamadm', 'pw', *args], stdin=slave, stdout=slave, stderr=slave, preexec_fn=child, env=env)
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 15
    pending = list(replies)
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], .1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
                while pending and pending[0][0] in output:
                    _, value = pending.pop(0)
                    os.write(master, value.encode() + b'\n')
            if len(output) > 65536:
                raise RuntimeError('bounded output exceeded')
        if proc.poll() is None:
            
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return -99, bytes(output), False
        return proc.returncode, bytes(output), not pending
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        os.close(master)


MARKER = '__OPS_DEPLOY_STABLE_CONTROLLER_PASSWORD__'


def check(stored, password):
    code, output, terminal = run(['--check'], [(b'Enter encrypted pa', stored), (b'Enter passphrase:', password)])
    lines = output.strip().splitlines()
    if terminal and code == 0 and lines[-1:] == [b'password correct']:
        return 'current'
    if terminal and code == 1 and lines[-1:] == [b'password incorrect']:
        return 'pending'
    raise RuntimeError('controller credential could not be established')


def encrypt(password):
    code, output, terminal = run(['--encrypt'], [(b'Enter passphrase:', password)])
    matches = re.findall(rb'\$[A-Za-z0-9]+\$[^\s]+', output)
    if code or not terminal or len(matches) != 1:
        raise RuntimeError('controller credential creation failed')
    stored = matches[0].decode()
    if check(stored, password) != 'current':
        raise RuntimeError('controller credential creation verification failed')
    return stored


def existing(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, None
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError('controller configuration is not a regular file')
    content = path.read_text()
    matches = re.findall(r'^password = "([^"\r\n]+)";$', content, re.MULTILINE)
    if len(matches) > 1 or ('password' in content and not matches):
        raise RuntimeError('controller credential format is ambiguous')
    return content, matches[0] if matches else None


def restart_owed(marker):
    path = Path(marker)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid restart marker')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)


def main():
    data = json.load(sys.stdin)
    path = Path(data['path'])
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid controller path')
    password = data['password']
    if not isinstance(password, str) or not password or len(password.encode()) > 1024 or any(c in password for c in '\r\n\0'):
        raise ValueError('invalid controller credential')
    template = data['content']
    if template.count(MARKER) != 1:
        raise ValueError('invalid controller template')
    old, stored = existing(path)
    credential = check(stored, password) if stored is not None else 'pending'
    desired = template.replace(MARKER, stored) if credential == 'current' else None
    # A parser/tool failure above aborts before a marker, hash or file write.
    pending = credential != 'current' or old != desired
    if sys.argv[1] == 'check':
        print('pending' if pending else 'current')
    elif sys.argv[1] == 'apply':
        if pending:
            restart_owed(data['restart_marker'])
            if credential != 'current':
                stored = encrypt(password)
            desired = template.replace(MARKER, stored)
            descriptor, temporary = tempfile.mkstemp(prefix='.mail-controller-', dir=path.parent)
            try:
                with os.fdopen(descriptor, 'w') as stream:
                    stream.write(desired)
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.fchown(stream.fileno(), pwd.getpwnam('_rspamd').pw_uid, grp.getgrnam('_rspamd').gr_gid)
                    os.fchmod(stream.fileno(), 0o644)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    else:
        raise ValueError('invalid controller action')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Mail spam controller operation failed; protected details withheld', file=sys.stderr)
        raise SystemExit(1) from None
