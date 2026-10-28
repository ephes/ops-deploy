"""Reconcile one cached monitoring endpoint; all credentials remain on stdin.

Checks inspect cached reports, configuration and daemon metadata only. Collection
is an explicit managed apply action, never a dry-plan probe. Known restart/refresh
debt survives a partial write so the next deploy cannot mistake fresh old JSON
for a successfully installed collector.
"""
import base64
import fcntl
import grp
import hashlib
import json
import math
import os
import pwd
import re
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen


def regular(path, optional=False):
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        try: info = part.lstat()
        except FileNotFoundError:
            if optional: continue
            raise
        if stat.S_ISLNK(info.st_mode): raise ValueError('managed path is a symlink')
        if part == path and not stat.S_ISREG(info.st_mode): raise ValueError('managed path is not regular')



def admit(paths):
    # Only explicit path/ancestor metadata, no children or credential/cache bodies.
    for row in paths:
        path=Path(row['path'])
        for part in [*reversed(path.parents),path]:
            try:info=part.lstat()
            except FileNotFoundError:
                if part==path and row.get('required'):raise ValueError('required existing exporter unavailable')
                continue
            if stat.S_ISLNK(info.st_mode):
                if part==path and row['kind']=='legacy':continue
                raise ValueError('linked monitoring path refused')
            directory=part!=path or row['kind']=='directory'
            if directory and not stat.S_ISDIR(info.st_mode):raise ValueError('monitoring ancestor is not a directory')
            if not directory and not stat.S_ISREG(info.st_mode):raise ValueError('monitoring path is not regular')
            if part==path and str(path).endswith('.tmp') and info.st_nlink!=1:
                raise ValueError('shared collector scratch inode refused')


def run(argv, stdin=None, timeout=45):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, check=True, timeout=timeout).stdout.strip()


def file_same(row):
    regular(row['path'], optional=True)
    try:
        info = Path(row['path']).stat()
        if info.st_size > 16 * 1024 * 1024: raise ValueError('oversized managed configuration')
        return (Path(row['path']).read_text() == row['content'] and
                (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                (0, grp.getgrnam(row.get('group', 'root')).gr_gid, row['mode']))
    except (FileNotFoundError, KeyError): return False


def write(row):
    path = Path(row['path']); regular(path, optional=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.monitoring-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(row['content']); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), row['mode'])
            os.fchown(stream.fileno(), 0, grp.getgrnam(row.get('group', 'root')).gr_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)



def account_current(v):
    try:group=grp.getgrnam(v['group']);user=pwd.getpwnam(v['user'])
    except KeyError:return False
    return user.pw_gid==group.gr_gid and user.pw_shell=='/usr/sbin/nologin'


def account_apply(v):
    # NSS UID/GID/shell metadata stays inside this process. Never query shadow,
    # return account records, set a password or create/enforce a home directory.
    try:grp.getgrnam(v['group'])
    except KeyError:
        try:run(['groupadd','--system',v['group']])
        except subprocess.CalledProcessError:grp.getgrnam(v['group'])
    try:pwd.getpwnam(v['user'])
    except KeyError:
        try:run(['useradd','--system','--no-create-home','--gid',v['group'],'--shell','/usr/sbin/nologin',v['user']])
        except subprocess.CalledProcessError:pwd.getpwnam(v['user'])
    group=grp.getgrnam(v['group']);user=pwd.getpwnam(v['user'])
    args=[]
    if user.pw_gid!=group.gr_gid:args+=['--gid',v['group']]
    if user.pw_shell!='/usr/sbin/nologin':args+=['--shell','/usr/sbin/nologin']
    if args:run(['usermod',*args,v['user']])
    if not account_current(v):raise ValueError('endpoint account metadata did not converge')


def schema_valid(value, rules, assert_true=True):
    for rule in rules:
        try:
            item = value
            for key in rule['path']: item = item[key]
        except (KeyError, TypeError): return False
        numeric = type(item) in (int, float) and math.isfinite(item)
        valid = {'mapping': isinstance(item, dict), 'sequence': isinstance(item, list),
                 'boolean': type(item) is bool, 'boolean_or_none': item is None or type(item) is bool,
                 'number': numeric, 'number_or_none': item is None or numeric}[rule['kind']]
        if not valid or (assert_true and rule.get('equals_true') and item is not True): return False
    return True


def cache_current(v):
    path = Path(v['json_path']); regular(path, optional=True)
    try:
        info = path.stat()
        if info.st_size > 16 * 1024 * 1024: raise ValueError('oversized metrics cache')
        age = time.time() - info.st_mtime
        if not 0 <= age < v['freshness_sec']: return False
        value = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError): return False
    if not isinstance(value, dict): return False
    # Both original HTTP servers derive freshness from the report's mtime.
    value['meta'] = {'age_seconds': age}
    return schema_valid(value, v['schema'], assert_true=False)


def auth_current(v):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,254}',v['auth_user']):raise ValueError('invalid endpoint username')
    path = v['htpasswd_path']; regular(path, optional=True)
    if not Path(path).exists(): return False
    found = subprocess.run(['htpasswd', '-viB', path, v['auth_user']], input=v['password']+'\n',
                           capture_output=True, text=True, timeout=15)
    if found.returncode == 0: return True
    if found.returncode in (3,6): return False  # Mismatch or missing validated username; never illegal username.
    raise ValueError('credential verification failed; existing file left intact')


def auth_metadata(v):
    try:
        info = Path(v['htpasswd_path']).stat()
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, grp.getgrnam(v['group']).gr_gid, 0o640)
    except (FileNotFoundError, KeyError): return False


def unit(name):
    text = run(['systemctl', 'show', name, '--property=LoadState,ActiveState,UnitFileState,NextElapseUSecRealtime,NextElapseUSecMonotonic'])
    value = dict(row.split('=', 1) for row in text.splitlines() if '=' in row)
    if value.get('LoadState') not in ('loaded', 'not-found'): raise ValueError('unknown unit state')
    return value


def armed(value):
    return any(value.get(key, '').strip().lower() not in ('', '0', 'infinity', 'n/a')
               for key in ('NextElapseUSecRealtime', 'NextElapseUSecMonotonic'))


def units_current(v):
    for name in (v['service'], v['timer']):
        value = unit(name)
        if (value.get('LoadState'), value.get('ActiveState'), value.get('UnitFileState')) != ('loaded', 'active', 'enabled'):
            return False
        if name == v['timer'] and not armed(value): return False
    return True


def debt(v):
    path = Path(v['debt']); regular(path, optional=True)
    if not path.exists(): return None
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or set(value) != {'refresh', 'restart', 'timer', 'reload'} or
            any(type(item) is not bool for item in value.values())): raise ValueError('unknown rollout debt')
    return value


def pending(v):
    changed = any(not file_same(row) for row in v['files'])
    # Package absence is a legitimate first-install plan; an existing credential
    # file without its native verifier is never admitted as safely replaceable.
    if not Path('/usr/bin/htpasswd').exists():
        regular(v['htpasswd_path'], optional=True)
        if Path(v['htpasswd_path']).exists(): raise ValueError('native credential verifier unavailable')
        return True
    return changed or not auth_current(v) or not auth_metadata(v) or debt(v) is not None or not cache_current(v) or not units_current(v)


def validate_units(changed):
    units = [row for row in changed if row['path'].startswith('/etc/systemd/system/')]
    if units:
        for row in units:
            for text in row['content'].splitlines():
                if text.startswith('OnCalendar='):
                    run(['systemd-analyze','calendar',text.split('=',1)[1]])
        with tempfile.TemporaryDirectory(prefix='monitoring-unit-', dir='/run') as directory:
            names = []
            for row in units:
                path = Path(directory) / Path(row['path']).name; path.write_text(row['content']); names.append(str(path))
            run(['systemd-analyze', 'verify', *names])


def apply(v):
    admit(v['paths'])
    changed = [row for row in v['files'] if not file_same(row)]
    auth = not auth_current(v)
    old = debt(v) or dict(refresh=False, restart=False, timer=False, reload=False)
    desired = dict(old)
    desired['refresh'] |= any(row.get('refresh', False) for row in changed) or not cache_current(v)
    desired['restart'] |= auth or any(row.get('restart', False) for row in changed)
    desired['timer'] |= any(row.get('timer', False) for row in changed)
    desired['reload'] |= any(row['path'].startswith('/etc/systemd/system/') for row in changed)
    entry=run(['htpasswd','-niB',v['auth_user']],v['password']+'\n',timeout=15) if auth else None
    validate_units(changed)
    write(dict(path=v['debt'], content=json.dumps(desired)+'\n', mode=0o600))
    for row in changed: write(row)
    if auth:
        # Generate privately in memory; never argv/environment/output or an exported verifier.
        write(dict(path=v['htpasswd_path'], content=entry+'\n', mode=0o640, group=v['group']))
    elif not auth_metadata(v):
        os.chown(v['htpasswd_path'], 0, grp.getgrnam(v['group']).gr_gid); os.chmod(v['htpasswd_path'], 0o640)
    if desired['reload']: run(['systemctl', 'daemon-reload'])
    if desired['refresh']:
        run(['systemctl', 'start', v['collector']], timeout=v['collector_timeout'])
        if not cache_current(v): raise ValueError('collector did not produce fresh compatible cached metrics')
    name=v['timer'];state=unit(name)
    if state.get('UnitFileState')!='enabled':run(['systemctl','enable',name])
    if desired['timer'] or (state.get('ActiveState')=='active' and not armed(state)):
        run(['systemctl','restart',name])
    elif state.get('ActiveState')!='active':run(['systemctl','start',name])
    for _ in range(6):
        timer=unit(name)
        if timer.get('ActiveState')=='active' and armed(timer):break
        time.sleep(2)
    timer=unit(name)
    if timer.get('ActiveState')!='active' or not armed(timer) or not cache_current(v) or not auth_current(v):
        raise ValueError('cached resources or timer did not converge')
    # Keep known HTTP restart debt until implementation selection and its single
    # HTTP start/restart finish successfully in the next operation.


def finish_pending(v):
    value=unit(v['service'])
    return (debt(v) is not None or v['force_restart'] or value.get('LoadState')!='loaded'
            or value.get('ActiveState')!='active' or value.get('UnitFileState')!='enabled')


def finish(v):
    admit(v['paths'])
    previous=debt(v)
    if any(not file_same(row) for row in v['files']) or not auth_current(v):
        raise ValueError('cached endpoint inputs changed before HTTP rollout')
    if v['force_restart']:
        previous=previous or dict(refresh=False,restart=False,timer=False,reload=False)
        previous['restart']=True
        write(dict(path=v['debt'],content=json.dumps(previous)+'\n',mode=0o600))
    value=unit(v['service'])
    if value.get('UnitFileState')!='enabled':run(['systemctl','enable',v['service']])
    restart=v['force_restart'] or bool(previous and previous['restart'])
    if value.get('ActiveState')!='active':run(['systemctl','start',v['service']])
    elif restart:run(['systemctl','restart',v['service']])
    if not units_current(v):raise ValueError('selected endpoint did not converge')
    path=Path(v['debt'])
    if path.exists():path.unlink()


def mc_current(v):
    path=Path('/usr/local/bin/mc');regular(path,optional=True)
    if not path.exists():return False
    if path.stat().st_size>64*1024*1024:raise ValueError('oversized mc executable')
    return hashlib.sha256(path.read_bytes()).hexdigest()==v['mc_sha256']


def install_mc(v):
    path=Path('/usr/local/bin/mc');regular(path,optional=True)
    if not mc_current(v):
        fd, temporary=tempfile.mkstemp(prefix='.monitoring-mc-',dir=path.parent)
        try:
            with os.fdopen(fd,'wb') as stream, urlopen(v['mc_url'],timeout=120) as response:
                digest=hashlib.sha256();size=0
                while chunk:=response.read(1024*1024):
                    size+=len(chunk)
                    if size>64*1024*1024:raise ValueError('oversized mc download')
                    stream.write(chunk);digest.update(chunk)
                if digest.hexdigest()!=v['mc_sha256']:raise ValueError('mc checksum mismatch')
                stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o755);os.fchown(stream.fileno(),0,0)
            os.replace(temporary,path)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
    else:
        info=path.stat()
        if stat.S_IMODE(info.st_mode)!=0o755:os.chmod(path,0o755)


def lag_cache_current(v):
    from datetime import datetime
    for job in v['jobs']:
        name=job.get('name') or job['bucket'].replace('-','_')
        root=Path(job.get('monitor_state_dir') or '/var/lib/minio-replication-monitor/'+name)
        path=root/'status.json';regular(path,optional=True)
        try:
            if path.stat().st_size>1024*1024:raise ValueError('oversized lag status')
            value=json.loads(path.read_text())
            age=time.time()-datetime.fromisoformat(value['checked_at'].replace('Z','+00:00')).timestamp()
            if not 0<=age<v['freshness_sec']:return False
            if (value.get('job_name'),value.get('bucket'),value.get('destination_endpoint'))!=(name,job['bucket'],v['destination_endpoint']):return False
            if value.get('level') not in ('ok','warning','critical'):return False
            # Recent critical/probe-error status is retained; do not poll until a
            # favourable outcome or reset the existing parity grace marker.
        except (FileNotFoundError,ValueError,KeyError,TypeError):return False
        regular(root/'parity.marker',optional=True)
        if not (root/'parity.marker').exists():return False
    return True


def lag_pending(v):
    return (any(not file_same(row) for row in v['files']) or not mc_current(v)
            or stat.S_IMODE(Path('/usr/local/bin/mc').stat().st_mode)!=0o755
            or Path('/usr/local/bin/minio-replication-lag-probe.sh').exists() or Path('/usr/local/bin/minio-replication-lag-probe.sh').is_symlink()
            or debt(v) is not None or not lag_cache_current(v))


def lag_apply(v):
    admit(v['paths'])
    changed=[row for row in v['files'] if not file_same(row)]
    previous=debt(v) or dict(refresh=False,restart=False,timer=False,reload=False)
    asset=not mc_current(v)
    desired=dict(refresh=previous['refresh'] or bool(changed) or asset or not lag_cache_current(v),
                 restart=False,timer=previous['timer'] or any(row.get('timer',False) for row in changed),
                 reload=previous['reload'] or any(row['path'].startswith('/etc/systemd/system/') for row in changed))
    validate_units(changed)
    write(dict(path=v['debt'],content=json.dumps(desired)+'\n',mode=0o600))
    install_mc(v)
    for row in changed:write(row)
    legacy=Path('/usr/local/bin/minio-replication-lag-probe.sh')
    if legacy.is_symlink():legacy.unlink()
    elif legacy.exists():regular(legacy);legacy.unlink()
    if desired['reload']:run(['systemctl','daemon-reload'])
    if desired['refresh']:
        # The original inline task tolerates a critical/nonzero monitor result;
        # that result remains in the report and Nyxmon markers. Tool launch or
        # malformed/missing state is not replaced with fabricated success.
        result=subprocess.run(['systemctl','start',v['service']],capture_output=True,text=True,timeout=600)
        if result.returncode:print('Lag probe nonzero result retained under original failure-tolerant policy',file=sys.stderr)
    state=unit(v['timer'])
    if state.get('UnitFileState')!='enabled':run(['systemctl','enable',v['timer']])
    if desired['timer']:run(['systemctl','restart',v['timer']])
    elif state.get('ActiveState')!='active':run(['systemctl','start',v['timer']])
    final=unit(v['timer'])
    if final.get('ActiveState')!='active' or final.get('UnitFileState')!='enabled':raise ValueError('lag timer did not converge')
    Path(v['debt']).unlink()


def http(v):
    credential = base64.b64encode((v['username']+':'+v['password']).encode()).decode()
    request = Request(v['url'], headers={'Authorization':'Basic '+credential})
    with urlopen(request, timeout=v['timeout']) as response:
        if response.status != 200:raise ValueError('cached endpoint did not answer 200')
        raw = response.read(16*1024*1024+1)
        if len(raw)>16*1024*1024:raise ValueError('oversized endpoint response')
    value=json.loads(raw)
    if not isinstance(value, dict) or not schema_valid(value,v['schema']):
        raise ValueError('cached endpoint schema is incompatible')
    age=value.get('meta',{}).get('age_seconds')
    if type(age) not in (int,float) or not math.isfinite(age) or not 0<=age<600:
        raise ValueError('cached endpoint is stale')
    print('current')


def main():
    v = json.load(sys.stdin)
    if sys.argv[1] == 'account-check':print('current' if account_current(v) else 'pending');return
    if sys.argv[1] == 'account-apply':account_apply(v);print('current');return
    if sys.argv[1] == 'admit':admit(v['paths']);print('current');return
    if sys.argv[1] == 'http':http(v);return
    if sys.argv[1] == 'check':
        answer=lag_pending(v) or not (unit(v['timer']).get('ActiveState')=='active' and unit(v['timer']).get('UnitFileState')=='enabled') if v.get('kind')=='lag' else pending(v)
        print('pending' if answer else 'current');return
    if sys.argv[1] == 'finish-check':print('pending' if finish_pending(v) else 'current');return
    if sys.argv[1] not in ('apply','finish'):raise ValueError('unknown endpoint action')
    lock = Path(v['debt']).parent / 'lock'; regular(lock, optional=True)
    lock.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with lock.open('a') as stream:
        os.chmod(lock, 0o600); fcntl.flock(stream, fcntl.LOCK_EX)
        if sys.argv[1]=='finish':finish(v)
        elif v.get('kind')=='lag':lag_apply(v)
        else:apply(v)
    print('current')


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Cached monitoring endpoint failed; credential material suppressed and rollout debt retained', file=sys.stderr)
        sys.exit(1)
