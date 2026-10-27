#!/usr/bin/env bash
# Owns one disposable GitHub VM. Never run against inventory.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
[[ ! -e /opt/postfixadmin && ! -e /opt/snappymail && ! -e /opt/mail-web-fixture ]]
[[ ! -e /var/lib/mail-web-fixture && ! -e /var/tmp/mail-web-owned-vm.json ]]
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
unset OPS_DEPLOY_PATH OPS_LIBRARY_PATH
export IMPLEMENTATION_ROOT
EVIDENCE=/var/tmp/mail-web-evidence
install -d -m 0700 "$EVIDENCE"
"$CONTROLLER_PYTHON" - <<'PY'
import hashlib,importlib.metadata,json,os,subprocess,sysconfig
from pathlib import Path
import ops_deploy
selected=os.environ['IMPLEMENTATION_SHA']
source=Path(os.environ['IMPLEMENTATION_ROOT'])
installed=Path(ops_deploy.__file__).resolve().parent
dist=importlib.metadata.distribution('ops-deploy')
direct=json.loads(dist.read_text('direct_url.json'))
assert direct.get('vcs_info',{}).get('commit_id')==selected
assert not direct.get('dir_info',{}).get('editable',False)
assert installed == (Path(sysconfig.get_paths()["purelib"])/"ops_deploy").resolve()
assert not installed.is_relative_to(source/"src")
tracked=subprocess.check_output(['git','-C',str(source),'ls-tree','-r','--name-only',selected,'src/ops_deploy/'],text=True).splitlines()
assert tracked
expected_names={name.removeprefix('src/ops_deploy/') for name in tracked}
actual_names={str(path.relative_to(installed)) for path in installed.rglob('*') if path.is_file() and '__pycache__' not in path.parts}
assert actual_names==expected_names
resources={}
for name in tracked:
    relative=name.removeprefix('src/ops_deploy/')
    expected=subprocess.check_output(['git','-C',str(source),'show',selected+':'+name])
    actual=(installed/relative).read_bytes()
    assert actual==expected,name
    resources[relative]=hashlib.sha256(actual).hexdigest()
Path('/var/tmp/mail-web-evidence/installed-artifact.json').write_text(json.dumps({'implementation_sha':selected,'harness_sha':os.environ['HARNESS_SHA'],'direct_url':direct,'installed_root':str(installed),'resources':resources},indent=2))
fd=os.open('/var/tmp/mail-web-owned-vm.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as stream:
    json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':open('/etc/machine-id').read().strip()},stream)
PY
export DEBIAN_FRONTEND=noninteractive
apt-get update
# The API itself installs PHP/FPM/extensions. These are fixture infrastructure.
apt-get install -y --no-install-recommends nginx postgresql python3-psycopg2 dovecot-imapd postfix ca-certificates openssl strace fish
fish -c true  # Initialize only the owned fixture login shell before no-write observations.
systemctl start postgresql nginx
# Independent existing site participates in candidate validation and survives it.
cat > /etc/nginx/conf.d/mail-web-unrelated.conf <<'NGINX'
server { listen 127.0.0.1:8099; location / { return 200 'owned unrelated site'; } }
NGINX
nginx -t
systemctl reload nginx
"$CONTROLLER_PYTHON" "$HERE/harness.py" "$EVIDENCE"
