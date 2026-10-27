#!/usr/bin/env bash
# Owns one disposable GitHub-hosted Ubuntu 24.04 x86 VM. Never run against inventory.
# Everything is synthetic: a LUKS loop file, its passphrase, the Open WebUI admin
# and the basic auth password are generated here and never leave the VM.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
if id openwebui >/dev/null 2>&1; then
  echo "Refusing an existing openwebui account" >&2
  exit 1
fi
[[ ! -e /mnt/cryptdata && ! -e /opt/open-webui && ! -e /dev/mapper/cryptdata && ! -e /root/.luks-key-cryptdata ]]
[[ ! -e /etc/systemd/system/open-webui.service && ! -e /etc/traefik && ! -e /var/tmp/linuxev-owned-vm.json ]]
if grep -q cryptdata /etc/crypttab /etc/fstab 2>/dev/null; then
  echo "Refusing a VM that already records cryptdata" >&2
  exit 1
fi
if ss -Hltn 'sport = :3000' | grep -q .; then
  echo "Refusing a VM with a listener on port 3000" >&2
  exit 1
fi
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
unset OPS_DEPLOY_PATH OPS_LIBRARY_PATH VIRTUAL_ENV
export IMPLEMENTATION_ROOT
EVIDENCE=/var/tmp/linuxev-evidence
install -d -m 0700 "$EVIDENCE"

# The installed controller package is the exact Git commit, not an editable checkout.
"$CONTROLLER_PYTHON" - <<'PY'
import hashlib, importlib.metadata, json, os, subprocess, sysconfig
from pathlib import Path
import ops_deploy
selected = os.environ['IMPLEMENTATION_SHA']
source = Path(os.environ['IMPLEMENTATION_ROOT'])
installed = Path(ops_deploy.__file__).resolve().parent
dist = importlib.metadata.distribution('ops-deploy')
direct = json.loads(dist.read_text('direct_url.json'))
assert direct.get('vcs_info', {}).get('commit_id') == selected, direct
assert not direct.get('dir_info', {}).get('editable', False)
assert installed == (Path(sysconfig.get_paths()['purelib']) / 'ops_deploy').resolve()
assert not installed.is_relative_to(source / 'src')
tracked = subprocess.check_output(
    ['git', '-C', str(source), 'ls-tree', '-r', '--name-only', selected, 'src/ops_deploy/'], text=True
).splitlines()
assert tracked
expected = {name.removeprefix('src/ops_deploy/') for name in tracked}
actual = {str(p.relative_to(installed)) for p in installed.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
assert actual == expected, sorted(actual ^ expected)
resources = {}
for name in tracked:
    relative = name.removeprefix('src/ops_deploy/')
    blob = subprocess.check_output(['git', '-C', str(source), 'show', selected + ':' + name])
    data = (installed / relative).read_bytes()
    assert data == blob, name
    resources[relative] = hashlib.sha256(data).hexdigest()
Path('/var/tmp/linuxev-evidence/installed-artifact.json').write_text(json.dumps(
    {'implementation_sha': selected, 'harness_sha': os.environ['HARNESS_SHA'], 'direct_url': direct,
     'installed_root': str(installed), 'resource_count': len(resources), 'resources': resources}, indent=2))
fd = os.open('/var/tmp/linuxev-owned-vm.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump({'run': os.environ['GITHUB_RUN_ID'], 'machine': open('/etc/machine-id').read().strip()}, stream)
PY

export DEBIAN_FRONTEND=noninteractive
apt-get update
# Fixture infrastructure only; the deploys install cryptsetup themselves.
apt-get install -y --no-install-recommends strace fish e2fsprogs util-linux curl ca-certificates cryptsetup-bin
fish -c true
modprobe dm_crypt || true
# Room for the Open WebUI wheels (torch and the CUDA libraries) on the root filesystem.
avail=$(df --output=avail -B1G / | tail -n 1 | tr -d ' ')
if (( avail < 30 )); then
  rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup /opt/hostedtoolcache/CodeQL
fi
df -h / > "$EVIDENCE/disk.txt"
{
  echo "kernel=$(uname -r)"
  echo "os=$PRETTY_NAME"
  echo "cryptsetup=$(cryptsetup --version)"
  echo "systemd=$(systemctl --version | head -n 1)"
} > "$EVIDENCE/platform.txt"
"$CONTROLLER_PYTHON" "$HERE/harness.py" "$EVIDENCE"
