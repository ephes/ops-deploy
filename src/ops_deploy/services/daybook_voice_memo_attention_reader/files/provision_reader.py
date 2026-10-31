#!/usr/bin/env python3
"""Fail-closed provisioning of one fixed MinIO prefix reader; secrets on stdin."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

POLICY_NAME = 'daybook-voice-memo-attention-read'
POLICY = {'Version': '2012-10-17', 'Statement': [
    {'Effect': 'Allow', 'Action': ['s3:ListBucket'], 'Resource': ['arn:aws:s3:::obsidian'],
     'Condition': {'StringEquals': {'s3:prefix': ['Inbox/Voice Memos/']}}},
    {'Effect': 'Allow', 'Action': ['s3:GetObject'],
     'Resource': ['arn:aws:s3:::obsidian/Inbox/Voice Memos/*']},
]}


class Refused(RuntimeError):
    """A fixed safe category, never raw MinIO output or credential values."""


def normalized_policy(value):
    if not isinstance(value, dict) or set(value) != {'Version', 'Statement'}:
        raise Refused('unexpected_policy_schema')
    if value['Version'] != POLICY['Version'] or not isinstance(value['Statement'], list):
        raise Refused('unexpected_policy_schema')
    statements = []
    for statement in value['Statement']:
        if not isinstance(statement, dict):
            raise Refused('unexpected_policy_schema')
        item = dict(statement)
        item.pop('Sid', None)
        for key in ('Action', 'Resource'):
            values = item.get(key)
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise Refused('unexpected_policy_schema')
            item[key] = sorted(values)
        if 'Condition' in item:
            condition = item['Condition']
            if not isinstance(condition, dict) or set(condition) != {'StringEquals'}:
                raise Refused('unexpected_policy_condition')
            equals = condition['StringEquals']
            if not isinstance(equals, dict) or set(equals) != {'s3:prefix'}:
                raise Refused('unexpected_policy_condition')
            prefix = equals['s3:prefix']
            if isinstance(prefix, str):
                prefix = [prefix]
            if not isinstance(prefix, list) or not all(isinstance(v, str) for v in prefix):
                raise Refused('unexpected_policy_condition')
            item['Condition'] = {'StringEquals': {'s3:prefix': sorted(prefix)}}
        statements.append(json.dumps(item, sort_keys=True))
    return sorted(statements)


def credentials(value):
    if not isinstance(value, dict) or set(value) != {'access_key', 'secret_key', 'mc_bin', 'alias', 'state_dir'}:
        raise Refused('invalid_request')
    access, secret = value['access_key'], value['secret_key']
    if (not isinstance(access, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{15,127}', access)
            or not isinstance(secret, str) or not 32 <= len(secret) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in secret)):
        raise Refused('invalid_credentials')
    if (not isinstance(value['alias'], str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value['alias'])
            or not isinstance(value['mc_bin'], str) or not Path(value['mc_bin']).is_absolute()
            or not isinstance(value['state_dir'], str) or not Path(value['state_dir']).is_absolute()):
        raise Refused('invalid_paths')
    return {'access_fingerprint': hashlib.sha256(access.encode()).hexdigest(),
            'secret_fingerprint': hashlib.sha256(secret.encode()).hexdigest(),
            'policy': POLICY_NAME, 'version': 1}


class MC:
    def __init__(self, binary, alias):
        self.binary, self.alias = binary, alias

    def call(self, command, *, identity=None, policy=None, path=None, stdin=None, missing=None):
        args = [self.binary, 'admin', *command.split(), '--json', self.alias]
        if policy:
            args.append(policy)
        if path:
            args.append(str(path))
        if identity:
            args.extend(['--user', identity] if command.startswith('policy ') else [identity])
        result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=30)
        if command in ('user add', 'policy create', 'policy attach'):
            if result.returncode != 0:
                raise Refused('mc_operation_failed')
            return {'status': 'success'}
        try:
            value = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise Refused('invalid_mc_response') from exc
        if not isinstance(value, dict):
            raise Refused('invalid_mc_response')
        if result.returncode != 0:
            error = value.get('error', {})
            code = error.get('cause', {}).get('error', {}).get('Code') if isinstance(error, dict) else None
            if missing and code == missing:
                return None
            raise Refused('mc_operation_failed')
        if value.get('status') != 'success':
            raise Refused('invalid_mc_success')
        return value


def verify_policy(info):
    try:
        current = info['policyInfo']['Policy']
    except (KeyError, TypeError) as exc:
        raise Refused('unexpected_policy_schema') from exc
    if normalized_policy(current) != normalized_policy(POLICY):
        raise Refused('existing_policy_differs')


def verify_identity(mc, access, user):
    if (user.get('accessKey') != access or user.get('userStatus') != 'enabled'
            or user.get('memberOf', []) != [] or user.get('policyName') != POLICY_NAME):
        raise Refused('existing_identity_differs')
    result = mc.call('policy entities', identity=access)
    try:
        data = result['result']
        mappings = data.get('userMappings', [])
        if (data.get('groupMappings', []) or len(mappings) != 1
                or mappings[0].get('user') != access or mappings[0].get('policies') != [POLICY_NAME]):
            raise Refused('unexpected_policy_attachments')
    except (KeyError, TypeError, AttributeError) as exc:
        raise Refused('unexpected_mapping_schema') from exc


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())


def _provision(request, mc=None):
    fingerprint = credentials(request)
    directory = Path(request['state_dir'])
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise Refused('unsafe_ownership_directory')
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Refused('unsafe_ownership_directory')
    marker = directory / 'identity.json'
    owned = marker.exists() or marker.is_symlink()
    if owned:
        info = marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise Refused('unsafe_ownership_marker')
        if json.loads(marker.read_text()) != fingerprint:
            raise Refused('credentials_changed_requires_recovery')
    mc = mc or MC(request['mc_bin'], request['alias'])
    policy = mc.call('policy info', policy=POLICY_NAME, missing='XMinioAdminNoSuchPolicy')
    if policy is not None:
        verify_policy(policy)
    user = mc.call('user info', identity=request['access_key'], missing='XMinioAdminNoSuchUser')
    if user is not None:
        if not owned:
            raise Refused('existing_identity_not_owned')
        verify_identity(mc, request['access_key'], user)
        if policy is None:
            raise Refused('owned_policy_missing')
        return {'changed': False, 'category': 'exact_reader_verified'}
    if owned:
        raise Refused('owned_identity_missing')
    if policy is None:
        policy_path = directory / 'policy.json'
        if policy_path.exists():
            if policy_path.is_symlink() or json.loads(policy_path.read_text()) != POLICY:
                raise Refused('local_policy_differs')
        else:
            private_write(policy_path, POLICY)
        mc.call('policy create', policy=POLICY_NAME, path=policy_path)
        verify_policy(mc.call('policy info', policy=POLICY_NAME))
    # Only the proven-absent fresh identity is added. Never upsert owned users.
    mc.call('user add', stdin=request['access_key'] + '\n' + request['secret_key'] + '\n')
    mc.call('policy attach', policy=POLICY_NAME, identity=request['access_key'])
    verify_policy(mc.call('policy info', policy=POLICY_NAME))
    verify_identity(mc, request['access_key'], mc.call('user info', identity=request['access_key']))
    private_write(marker, fingerprint)
    return {'changed': True, 'category': 'exact_reader_created'}


def provision(request, mc=None):
    credentials(request)
    directory = Path(request['state_dir'])
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise Refused('unsafe_ownership_directory')
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Refused('unsafe_ownership_directory')
    fd = os.open(directory / 'provision.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise Refused('unsafe_lock')
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _provision(request, mc)


def main():
    os.umask(0o077)
    try:
        raw = sys.stdin.read(8193)
        if len(raw) > 8192:
            raise Refused('request_too_large')
        result = provision(json.loads(raw))
    except (Refused, ValueError, OSError, subprocess.SubprocessError, TypeError, KeyError):
        print(json.dumps({'changed': False, 'category': 'reader_provisioning_refused'}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
