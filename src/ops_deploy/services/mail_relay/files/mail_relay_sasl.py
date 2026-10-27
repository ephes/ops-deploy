"""Cyrus SASL credential reconciliation, protected stdin and fixed output only."""
import ctypes as c
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def check(path, username, password, realm):
    lib = c.CDLL('libsasl2.so.2')
    option_type = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_char_p, c.c_char_p, c.POINTER(c.c_char_p), c.POINTER(c.c_uint))
    log_type = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_int, c.c_char_p)
    values = {b'pwcheck_method': b'auxprop', b'auxprop_plugin': b'sasldb', b'sasldb_path': str(path).encode(), b'auto_transition': b'no'}

    @option_type
    def option(context, plugin, name, result, length):
        value = values.get(name)
        if value is None:
            return -1
        result[0] = value
        if length:
            length[0] = len(value)
        return 0

    @log_type
    def log(context, level, message):
        return 0

    class Callback(c.Structure):
        _fields_ = [('id', c.c_ulong), ('proc', c.c_void_p), ('context', c.c_void_p)]

    callbacks = (Callback * 3)(Callback(1, c.cast(option, c.c_void_p), None), Callback(2, c.cast(log, c.c_void_p), None), Callback(0, None, None))
    lib.sasl_server_init.argtypes = [c.POINTER(Callback), c.c_char_p]
    lib.sasl_server_new.argtypes = [c.c_char_p] * 5 + [c.POINTER(Callback), c.c_uint, c.POINTER(c.c_void_p)]
    lib.sasl_checkpass.argtypes = [c.c_void_p, c.c_char_p, c.c_uint, c.c_char_p, c.c_uint]
    lib.sasl_dispose.argtypes = [c.POINTER(c.c_void_p)]
    if lib.sasl_server_init(callbacks, b'ops-deploy-mail') != 0:
        raise RuntimeError('native SASL initialization failed')
    conn = c.c_void_p()
    if lib.sasl_server_new(b'smtp', realm, realm, None, None, callbacks, 0, c.byref(conn)) != 0:
        lib.sasl_done()
        raise RuntimeError('native SASL connection initialization failed')
    try:
        return lib.sasl_checkpass(conn, username, len(username), password, len(password))
    finally:
        lib.sasl_dispose(c.byref(conn))
        lib.sasl_done()


def store_state(path, user, realm):
    result = subprocess.run(['sasldblistusers2', '-f', str(path)], capture_output=True)
    if result.returncode or result.stderr:
        return 'unknown'
    lines = result.stdout.splitlines()
    # The listing has only identity/property metadata. Never print it.
    if any(b': ' not in line for line in lines):
        return 'unknown'
    return 'present' if user + b'@' + realm + b': userPassword' in lines else 'absent'



def state(path, user, password, realm):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return 'pending-create'
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError('invalid credential store')
    catalog = store_state(path, user, realm)
    if catalog == 'unknown':
        raise RuntimeError('credential store could not be established')
    result = check(path, user, password, realm)
    if catalog == 'present' and result == 0:
        return 'current'
    if catalog == 'present' and result == -13:
        return 'pending-password'
    if catalog == 'absent' and result == -20:
        return 'pending-create'
    raise RuntimeError('credential state could not be established')


def restart_owed(marker):
    if not re.fullmatch(r'/var/lib/ops-deploy/mail-core/[a-z][a-z0-9-]*\.(?:restart|reload)', marker):
        raise ValueError('invalid mail restart marker')
    path = Path(marker)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)


def main():
    payload = json.load(sys.stdin)
    path = Path(payload['path'])
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid credential path')
    for key in ('user', 'realm'):
        if not isinstance(payload[key], str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', payload[key]):
            raise ValueError('invalid credential identity')
    password = payload['password']
    if not isinstance(password, str) or not password or len(password.encode()) > 4096 or any(char in password for char in '\r\n\0'):
        raise ValueError('invalid credential input')
    user = payload['user'].encode()
    realm = payload['realm'].encode()
    before = state(path, user, password.encode(), realm)
    mode = sys.argv[1]
    if mode == 'check':
        print(before)
    elif mode == 'apply':
        if before != 'current':
            restart_owed(payload['restart_marker'] if before == 'pending-create' else payload['reload_marker'])
            result = subprocess.run(['saslpasswd2', '-p', '-c', '-f', str(path), '-u', payload['realm'], payload['user']], input=(password+'\n').encode(), capture_output=True, timeout=15)
            if result.returncode or state(path, user, password.encode(), realm) != 'current':
                raise RuntimeError('credential update failed')
            print('created' if before == 'pending-create' else 'updated')
    else:
        raise ValueError('unknown credential action')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Mail relay SASL operation failed; protected details withheld', file=sys.stderr)
        raise SystemExit(1) from None
