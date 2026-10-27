#!/usr/bin/env bash
# Owned GitHub Ubuntu VM or its isolated Debian13 systemd guest, never inventory.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(cat /proc/1/comm) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
. /etc/os-release
[[ ($ID == ubuntu && $VERSION_ID == 24.04) || ($ID == debian && $VERSION_ID == 13) ]]
[[ ! -e /opt/os-apt-fixture && ! -e /var/tmp/os-apt-owned-vm.json ]]
[[ ! -e /etc/systemd/system/fixture-apt.service && ! -e /etc/systemd/system/fixture-apt-endpoint.service ]]
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
unset OPS_DEPLOY_PATH OPS_LIBRARY_PATH VIRTUAL_ENV
export IMPLEMENTATION_ROOT
EVIDENCE=/var/tmp/os-apt-evidence
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
Path('/var/tmp/os-apt-evidence/installed-artifact.json').write_text(json.dumps({'implementation_sha':selected,'harness_sha':os.environ['HARNESS_SHA'],'direct_url':direct,'installed_root':str(installed),'resources':resources},indent=2))
fd=os.open('/var/tmp/os-apt-owned-vm.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as stream:
    json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':open('/etc/machine-id').read().strip()},stream)
PY

# Fixture bootstrap only. No apt/package commands run on inventory.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends fish apache2-utils python3 python3-apt sudo util-linux ca-certificates git
"$UV_BIN" pip install --python "$CONTROLLER_PYTHON" ansible==14.5.0
install -d -m 0755 /opt/os-apt-fixture
# Actual immutable role and dependencies for Ansible coexistence.
install -d /opt/os-apt-fixture/collections/ansible_collections/local
git clone https://github.com/ephes/ops-library.git /opt/os-apt-fixture/collections/ansible_collections/local/ops_library
git -C /opt/os-apt-fixture/collections/ansible_collections/local/ops_library checkout --detach cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641
"$CONTROLLER_PYTHON" "$HERE/harness.py" "$EVIDENCE"
