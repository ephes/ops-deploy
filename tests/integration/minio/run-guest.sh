#!/usr/bin/env bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(uname -m) == x86_64 && $(cat /proc/1/comm) == systemd ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]]
[[ ! -e /etc/default/minio && ! -e /etc/systemd/system/minio.service && ! -e /var/lib/minio ]]
[[ ! -e /var/tmp/minio-owned-guest.json && ! -e /opt/minio-fixture ]]
[[ -z $(env | grep -Ei '(token|secret|ssh_auth|github_api|actions_runtime)' || true) ]]
cd /opt/controller
git config --global --add safe.directory /opt/controller
[[ $(git rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ -z $(git config --local --get-regexp 'credential|extraheader|insteadof' || true) ]]
uv sync --locked --no-dev --python 3.13
uv pip install --python .venv/bin/python --no-deps --reinstall "ops-deploy @ git+https://github.com/ephes/ops-deploy.git@$IMPLEMENTATION_SHA"
uv venv --python 3.13 /opt/minio-ansible
uv pip install --python /opt/minio-ansible/bin/python ansible==14.5.0
install -d -m 0700 /var/tmp/minio-evidence
.venv/bin/python - <<'PY'
import hashlib,importlib.metadata,json,os,subprocess,sysconfig
from pathlib import Path
import ops_deploy
source=Path('/opt/controller');selected=os.environ['IMPLEMENTATION_SHA']
installed=Path(ops_deploy.__file__).resolve().parent
direct=json.loads(importlib.metadata.distribution('ops-deploy').read_text('direct_url.json'))
assert direct['vcs_info']['commit_id']==selected and not direct.get('dir_info',{}).get('editable',False)
assert installed==(Path(sysconfig.get_paths()['purelib'])/'ops_deploy').resolve()
assert not installed.is_relative_to(source/'src')
paths=subprocess.check_output(['git','ls-tree','-r','--name-only',selected,'src/ops_deploy/'],text=True).splitlines()
expected={p.removeprefix('src/ops_deploy/') for p in paths}
actual={str(p.relative_to(installed)) for p in installed.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
assert actual==expected
resources={}
for path in paths:
 relative=path.removeprefix('src/ops_deploy/')
 data=(installed/relative).read_bytes()
 assert data==subprocess.check_output(['git','show',selected+':'+path]),relative
 resources[relative]=hashlib.sha256(data).hexdigest()
artifacts={}
for name,sha in {'minio':'2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4','mc':'01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891'}.items():
 path=Path('/opt/minio-artifacts')/name
 assert hashlib.sha256(path.read_bytes()).hexdigest()==sha
 path.chmod(0o755)
 artifacts[name]={'sha256':sha,'size':path.stat().st_size,'version':subprocess.check_output([str(path),'--version'],text=True)}
Path('/var/tmp/minio-evidence/installed-artifact.json').write_text(json.dumps({'implementation_sha':selected,'direct_url':direct,'installed_root':str(installed),'resources':resources,'artifacts':artifacts,'scope':'native x86 Ubuntu24 systemd userspace on owned GitHub VM shared kernel; no emulation'},indent=2))
with open('/var/tmp/minio-owned-guest.json','x') as stream:json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':Path('/etc/machine-id').read_text().strip()},stream)
PY
install -d -m 0700 /opt/minio-fixture
install -d /opt/minio-fixture/collections/ansible_collections/local
git clone https://github.com/ephes/ops-library.git /opt/minio-fixture/collections/ansible_collections/local/ops_library
git -C /opt/minio-fixture/collections/ansible_collections/local/ops_library checkout --detach d88c3286b2fb58a8799663d6c1f3a9d6061af37b
.venv/bin/python tests/integration/minio/harness.py /var/tmp/minio-evidence
