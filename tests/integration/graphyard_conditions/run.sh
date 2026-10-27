#!/usr/bin/env bash
# Owns only a disposable GitHub VM and synthetic Graphyard state.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
[[ ! -e /opt/graphyard-conditions-fixture && ! -e /var/tmp/graphyard-conditions-owned-vm.json ]]
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
unset OPS_DEPLOY_PATH OPS_LIBRARY_PATH
export IMPLEMENTATION_ROOT
EVIDENCE=/var/tmp/graphyard-conditions-evidence
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
Path('/var/tmp/graphyard-conditions-evidence/installed-artifact.json').write_text(json.dumps({'implementation_sha':selected,'harness_sha':os.environ['HARNESS_SHA'],'direct_url':direct,'installed_root':str(installed),'resources':resources},indent=2))
fd=os.open('/var/tmp/graphyard-conditions-owned-vm.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as stream:
    json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':open('/etc/machine-id').read().strip()},stream)
PY

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends fish strace
fish -c true
"$UV_BIN" pip install --python "$CONTROLLER_PYTHON" ansible-core==2.19.3
FIXTURE=/opt/graphyard-conditions-fixture
install -d -m 0755 "$FIXTURE"
git clone https://github.com/ephes/graphyard.git "$FIXTURE/source"
git -C "$FIXTURE/source" checkout --detach 19181987d888ffa750c32c6e68e15dd469fbc2d0
(cd "$FIXTURE/source" && "$UV_BIN" sync --locked --no-dev --python /usr/bin/python3)
useradd --system --home-dir "$FIXTURE" --shell /bin/bash graphyard-fixture
chown -R graphyard-fixture:graphyard-fixture "$FIXTURE"
"$CONTROLLER_PYTHON" "$HERE/harness.py" "$EVIDENCE"
