"""The ansible.posix.acl recursive rX change test, without modifying ACLs.

As acl_changed in ansible.posix 2.2.0: any changed line requires the role's
recursive update. An unchanged directory does not hide a changed descendant.
"""
import os
import shutil
import subprocess
import sys

path, user = sys.argv[1:]
if not os.path.exists(path):
    print('changed=false')
    raise SystemExit(0)
if shutil.which('setfacl') is None:
    print('changed=true')
    raise SystemExit(0)
result = subprocess.run(['setfacl', '--test', '-m', 'user:' + user + ':rX', '--recursive', path], capture_output=True, text=True, check=True)
lines = [line.strip() for line in result.stdout.splitlines() if not line.startswith('#')]
if lines and not lines[-1]:
    lines.pop()
print('changed=true' if any(not line.endswith('*,*') for line in lines) else 'changed=false')
