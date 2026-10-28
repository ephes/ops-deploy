"""Native tdbsam admission, names/flags-only inventory and add-only insertion.

No update/enable/password setter runs against the actual backend. New SAMU
material travels only over private child pipes and a private ephemeral tmpfs
candidate database. The native RID allocator is nontransactional: failed or
racing creation can consume a RID, but cannot overwrite an existing account.
"""
import fcntl
import json
import os
import pathlib
import stat
import struct
import subprocess
import sys

FACTORY = r'''
import json,os,pathlib,subprocess,sys,tempfile
from samba.samba3 import passdb,param
from samba.dcerpc import security
v=json.load(sys.stdin)
os.umask(0o077)
lp=param.get_context();lp.load(v['config']);passdb.set_smb_config(v['config'])
# This child creates only the candidate passdb. Parent has established the
# existing machine identity before spawning it; never generate a new identity.
passdb.set_secrets_dir(lp.get('private dir'))
with tempfile.TemporaryDirectory(prefix='ops-deploy-samu-',dir='/run') as temporary:
 path=temporary+'/passdb.tdb'
 p=subprocess.run(['pdbedit','-s',v['config'],'-b','tdbsam:'+path,'-a','-t','-u',v['name'],'-c','[U]'],
                  input=v['password']+'\n'+v['password']+'\n',text=True,capture_output=True)
 if p.returncode:sys.exit(1)
 os.chmod(path,0o600)
 backend=passdb.PDB('tdbsam:'+path);account=backend.getsampwnam(v['name'])
 def encode(value):
  if isinstance(value,security.dom_sid):return {'sid':str(value)}
  if isinstance(value,bytes):return {'bytes':value.hex()}
  if value is None or isinstance(value,(str,int,list)):return value
  raise TypeError('unsupported native account property')
 print(json.dumps({key:encode(getattr(account,key)) for key in v['fields']}))
'''


def safe(path, missing=False):
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('symlink in Samba state path')
        if part == path and not stat.S_ISREG(info.st_mode):
            raise ValueError('nonregular Samba state file')



def identity(lp):
    """Validate only the public local SID record, without native auto-generation.

    Samba's get_global_sam_sid can generate/persist a SID when it is missing.
    A file named secrets.tdb alone is not proof of an established identity.
    Qualified Samba4.19 stores a fixed-size native dom_sid record (68 bytes).
    No existing credential record is requested or exported.
    """
    import tdb
    path = pathlib.Path(lp.get('private dir')) / 'secrets.tdb'
    safe(path)
    key = ('SECRETS/SID/' + lp.get('netbios name').upper()).encode()
    database = tdb.Tdb(str(path), flags=os.O_RDONLY)
    try:
        raw = database.get(key)
    finally:
        database.close()
    if raw is None or len(raw) != 68 or raw[0] != 1 or raw[1] != 4 or int.from_bytes(raw[2:8], 'big') != 5:
        raise ValueError('missing or unsupported local Samba identity')
    components = struct.unpack('<15I', raw[8:])
    if components[0] != 21 or any(components[4:]):
        raise ValueError('invalid local Samba identity')
    return 'S-1-5-' + '-'.join(str(value) for value in components[:4])


def context(config):
    from samba.samba3 import passdb, param
    import tdb
    config = pathlib.Path(config)
    safe(config)
    lp = param.get_context()
    lp.load(str(config))
    passdb.set_smb_config(str(config))
    spec = lp.get('passdb backend')
    if isinstance(spec, list):
        spec = ' '.join(spec)
    if spec != 'tdbsam':
        raise ValueError('only the qualified native tdbsam backend is supported')
    local_sid = identity(lp)  # before any PDB constructor could initialize missing identity
    path = pathlib.Path(lp.get('private dir')) / 'passdb.tdb'
    safe(path, missing=True)
    if not path.exists():
        return lp, passdb, path, None, local_sid
    # PDB has no working read-only constructor argument in Samba 4.19. Refuse
    # unknown/old schema before its constructor can migrate an existing DB.
    database = tdb.Tdb(str(path), flags=os.O_RDONLY)
    try:
        if database.get(b'INFO/version\0') != struct.pack('<I', 4) or database.get(b'INFO/minor_version\0') != struct.pack('<I', 0):
            raise ValueError('unknown tdbsam schema')
        keys = database.keys()
        users = {key[5:-1].decode('utf-8') for key in keys if key.startswith(b'USER_') and key.endswith(b'\0')}
    finally:
        database.close()
    backend = passdb.PDB('tdbsam')
    rows = backend.search_users(0)
    names = {row['account_name'] for row in rows}
    if len(names) != len(rows) or names != users:
        raise ValueError('incomplete native Samba account inventory')
    # No credential fields are requested or exported from existing accounts.
    return lp, passdb, path, {row['account_name']: int(row['acct_flags']) for row in rows}, local_sid


def missing(config, names):
    lp, passdb, path, accounts, local_sid = context(config)
    return [name for name in names if accounts is None or name not in accounts]


def create(config, credentials):
    from samba.dcerpc import security
    lp, passdb, path, accounts, local_sid = context(config)
    wanted = [row for row in credentials if accounts is None or row['name'] not in accounts]
    if not wanted:
        return
    # Require an established machine SID/secret database. Never silently
    # regenerate identity for a damaged existing installation.
    secrets = pathlib.Path(lp.get('private dir')) / 'secrets.tdb'
    safe(secrets)
    sid = local_sid
    passdb.set_secrets_dir(lp.get('private dir'))
    backend = passdb.PDB('tdbsam')
    if str(passdb.get_global_sam_sid()) != sid:
        raise ValueError('local Samba identity changed concurrently')
    fields = tuple(key for key in dir(passdb.Samu) if not key.startswith('_') and key != 'plaintext_passwd')
    for row in wanted:
        # Native insert below is the final race arbiter. Recheck avoids needless
        # allocation for another invocation that completed while we waited.
        if row['name'] in {item['account_name'] for item in backend.search_users(0)}:
            continue
        request = dict(row, config=config, fields=fields)
        result = subprocess.run([sys.executable, '-I', '-c', FACTORY], input=json.dumps(request),
                                text=True, capture_output=True, check=True)
        values = json.loads(result.stdout)
        account = passdb.Samu()
        rid = backend.new_rid()  # managed mutation, not rolled back on failure
        values['user_sid'] = {'sid': sid + '-' + str(rid)}
        for key, value in values.items():
            # This upstream derived property's C setter is deliberately absent.
            if value is None or key == 'pass_must_change_time':
                continue
            if isinstance(value, dict):
                value = security.dom_sid(value['sid']) if 'sid' in value else bytes.fromhex(value['bytes'])
            setattr(account, key, value)
        def encode(value):
            if isinstance(value, security.dom_sid):
                return {'sid': str(value)}
            if isinstance(value, bytes):
                return {'bytes': value.hex()}
            return value
        if any(encode(getattr(account, key)) != value for key, value in values.items()):
            raise ValueError('native candidate did not roundtrip')
        # Native backend insertion refuses an existing name. Never substitute
        # pdbedit -a or update_sam_account here: both can rotate existing users.
        backend.add_sam_account(account)
    if not {row['name'] for row in credentials} <= {item['account_name'] for item in backend.search_users(0)}:
        raise ValueError('missing account after native admission')


def main():
    request = json.load(sys.stdin)
    names = request['names']
    if len(names) != len(set(names)):
        raise ValueError('duplicate Samba account request')
    if sys.argv[1] == 'check':
        try:
            import samba  # Native binding availability only, no backend constructor.
            available = True
        except ImportError:
            available = False
        if not available or not pathlib.Path(request['config']).exists():
            # A package-absent first deployment is pending, not evidence that
            # any existing account is absent. Apply must inventory after apt.
            if pathlib.Path('/var/lib/samba/private/passdb.tdb').exists():
                raise ValueError('existing Samba database requires working native inventory')
            print(json.dumps({'state': 'prerequisites', 'missing': names}))
        else:
            print(json.dumps({'state': 'known', 'missing': missing(request['config'], names)}))
        return
    if sys.argv[1] != 'apply':
        raise ValueError('invalid Samba account action')
    credentials = request['credentials']
    if {row['name'] for row in credentials} != set(names):
        raise ValueError('credentials must match the admitted name set')
    for row in credentials:
        password = row['password']
        if not isinstance(password, str) or not password or any(c in password for c in '\n\r\0'):
            raise ValueError('invalid Samba password')
    # Serialization is our own create scope; native add-only also refuses
    # duplicates created by administrators outside this lock.
    lockpath = pathlib.Path('/run/ops-deploy-samba-accounts.lock')
    safe(lockpath, missing=True)
    with open(lockpath, 'a') as lock:
        os.chmod(lockpath, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        create(request['config'], credentials)
    print('current')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never log exceptions from native tools or candidate SAM material.
        print('Native Samba account admission failed; existing credentials were not updated', file=sys.stderr)
        sys.exit(1)
