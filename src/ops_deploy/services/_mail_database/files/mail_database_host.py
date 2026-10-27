"""Protected-stdin mail DB foundation; stdout is only fixed state markers.

No verifier, password, identifier or PostgreSQL diagnostic is emitted. This
host-side helper owns no app catalogs and never changes DB/schema ownership.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import sys


def sql(text, database=None):
    argv = ['runuser', '-u', cfg['admin_user'], '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-p', str(cfg['port']), '-d', database or 'postgres']
    result = subprocess.run(argv, input=text, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('mail database query failed')
    return result.stdout.strip()


def verifier(password, salt, iterations=4096):
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    stored = hashlib.sha256(hmac.digest(salted, b'Client Key', 'sha256')).digest()
    server = hmac.digest(salted, b'Server Key', 'sha256')
    encode = lambda value: base64.b64encode(value).decode()
    return f'SCRAM-SHA-256${iterations}:{encode(salt)}${encode(stored)}:{encode(server)}'


def role_state():
    value = sql(f"SELECT json_build_array(rolcanlogin, rolpassword)::text FROM pg_authid WHERE rolname='{cfg['role']}';")
    if not value:
        return False, False, False
    login, stored = json.loads(value)
    if not stored or not stored.startswith('SCRAM-SHA-256$'):
        raise RuntimeError('existing mail credential format is not qualified')
    try:
        _, params, keys = stored.split('$')
        count, salt = params.split(':')
        count = int(count)
        if not 1 <= count <= 1_000_000:
            raise ValueError()
        decoded_salt = base64.b64decode(salt, validate=True)
        if not 1 <= len(decoded_salt) <= 1024:
            raise ValueError()
        stored_key, server_key = [base64.b64decode(value, validate=True) for value in keys.split(':')]
        if len(stored_key) != 32 or len(server_key) != 32:
            raise ValueError()
        expected = verifier(cfg['password'], decoded_salt, count)
        expected_stored, expected_server = [base64.b64decode(value, validate=True) for value in expected.split('$')[2].split(':')]
    except (ValueError, TypeError):
        raise RuntimeError('existing mail credential is malformed') from None
    stored_matches = hmac.compare_digest(stored_key, expected_stored)
    server_matches = hmac.compare_digest(server_key, expected_server)
    if stored_matches != server_matches:
        raise RuntimeError('existing mail credential has inconsistent derived keys')
    return True, bool(login), stored_matches and server_matches


def main():
    global cfg
    cfg = json.load(sys.stdin)
    for key in ('name', 'role', 'admin_user'):
        if not isinstance(cfg[key], str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,62}', cfg[key]):
            raise ValueError('invalid mail DB identifier')
    if type(cfg['port']) is not int or not 0 < cfg['port'] < 65536:
        raise ValueError('invalid mail DB port')
    mode = sys.argv[1]
    if mode.startswith('role-'):
        password = cfg['password']
        if not isinstance(password, str) or not password or not password.isascii() or any(c in password for c in '\r\n\0'):
            raise ValueError('invalid mail DB password')
        exists, login, matches = role_state()
        current = login and matches
        if mode == 'role-check':
            print('current' if current else 'pending')
        elif mode == 'role-apply':
            if not current:
                if exists and matches:
                    sql(f'ALTER ROLE "{cfg["role"]}" WITH LOGIN;')
                else:
                    secret = verifier(password, secrets.token_bytes(16))
                    sql(f"""{'ALTER' if exists else 'CREATE'} ROLE "{cfg['role']}" WITH LOGIN PASSWORD '{secret}';""")
            _, login, matches = role_state()
            if not (login and matches):
                raise RuntimeError('mail role verification failed')
        else:
            raise ValueError('invalid action')
    elif mode in ('database-check', 'database-apply'):
        exists = sql(f"SELECT 1 FROM pg_database WHERE datname='{cfg['name']}';") == '1'
        if mode == 'database-check':
            print('current' if exists else 'pending')
        elif not exists:
            sql(f'CREATE DATABASE "{cfg["name"]}";')
    elif mode == 'require':
        if sql(f"SELECT 1 FROM pg_database WHERE datname='{cfg['name']}';") != '1':
            raise RuntimeError('required mail database is missing')
        if sql(f"SELECT 1 FROM pg_roles WHERE rolname='{cfg['role']}' AND rolcanlogin;") != '1':
            raise RuntimeError('required mail login role is missing')
        for privilege in cfg.get('required_privileges', []):
            if privilege not in ('CONNECT', 'CREATE', 'TEMPORARY'):
                raise ValueError('invalid required privilege')
            if sql(f"SELECT has_database_privilege('{cfg['role']}', '{cfg['name']}', '{privilege}');") != 't':
                raise RuntimeError('required mail database privilege is missing')
        print('current')
    else:
        raise ValueError('invalid mail database action')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Mail database operation failed; protected details withheld', file=sys.stderr)
        raise SystemExit(1) from None
