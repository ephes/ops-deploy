"""Run the two original management commands without exporting secret-bearing output."""
import json
import os
import re
import shlex
import subprocess
import sys


def run(request):
    if set(request) != {'user','site','venv','config_dir','action'}:
        raise ValueError('operations_management_request_invalid')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',request['user']):
        raise ValueError('operations_management_request_invalid')
    for field in ('site','venv','config_dir'):
        value=request[field]
        if not isinstance(value,str) or not value.startswith('/') or '..' in value.split('/') or any(c in value for c in '\r\n\x00'):
            raise ValueError('operations_management_request_invalid')
    if request['action']=='migrate':arguments=['migrate','--noinput']
    elif request['action']=='provision':arguments=['provision_operations',request['config_dir']+'/profiles.json']
    else:raise ValueError('operations_management_request_invalid')
    argv=[request['venv']+'/bin/python',request['site']+'/services/operations_api/manage.py',*arguments]
    # Match management.yml: the service-user shell sources the0600 companion;
    # values never enter the root controller task environment or sudo argv.
    command='set -a\n. '+shlex.quote(request['config_dir']+'/environment.shell')+'\nset +a\nexec '+shlex.join(argv)
    result=subprocess.run(['/usr/sbin/runuser','-u',request['user'],'--','/bin/sh','-c',command],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600)
    if result.returncode:
        categories=re.findall(rb'operations_(?:storage_unavailable|configuration_unreadable|configuration_invalid)',result.stderr)
        return {'ok':False,'category':categories[0].decode() if categories else 'management_command_failed'}
    return {'ok':True,'category':'operations_management_succeeded','action':request['action'],
            'original_changed':b'Applying ' in result.stdout or b'changed' in result.stdout}


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384 or os.geteuid()!=0:raise ValueError('operations_management_request_invalid')
        result=run(json.loads(raw))
    except Exception:
        result={'ok':False,'category':'management_command_failed'}
    print(json.dumps(result,sort_keys=True))
    sys.exit(0 if result['ok'] else 1)
