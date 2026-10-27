#!/usr/bin/env bash
# This owns a disposable GitHub VM, never an inventory host.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
[[ ! -e /etc/unbound && ! -e /etc/ddns && ! -e /var/lib/ddns ]]
[[ ! -e /var/tmp/dns-routine-owned-vm.json && ! -e /opt/dns-routine-fixture ]]
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
[[ $(git -C "${ROLE_SOURCE:?}" rev-parse HEAD) == 56495f751c1c664ad9ff2be73403e23efda02621 ]]
[[ -x ${ANSIBLE_PLAYBOOK:?} ]]
EVIDENCE=/var/tmp/dns-routine-evidence
install -d -m 0700 "$EVIDENCE"
"$CONTROLLER_PYTHON" - <<'PY'
import json,os
fd=os.open('/var/tmp/dns-routine-owned-vm.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as f:
    json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':open('/etc/machine-id').read().strip()},f)
PY
# Record only executable identity, never arbitrary process argv or environment.
"$CONTROLLER_PYTHON" - "$EVIDENCE" <<'PYIDENTITY'
import hashlib,json,os,sys
from pathlib import Path
observed=[]
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():
        continue
    try:
        if (proc/'comm').read_text().strip() != 'dns-resolver':
            continue
        executable=(proc/'exe').resolve(strict=True)
        observed.append({'pid':int(proc.name),'exe':str(executable),
                         'sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
                         'uid':proc.stat().st_uid,'cgroup':(proc/'cgroup').read_text()})
    except FileNotFoundError:
        continue
Path(sys.argv[1],'preexisting-resolver-identity.json').write_text(json.dumps(observed,indent=2))
if observed:
    raise SystemExit('Owned fixture has an extra port-53 resolver; identity retained, no process terminated')
PYIDENTITY
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 iproute2 iptables bind9 strace
systemctl disable --now named
# Fixture-only observer records transient listener owners; never controls them.
(
  while true; do
    date --iso-8601=ns
    ss -H -lntup 'sport = :53'
    sleep 0.2
  done
) > "$EVIDENCE/listeners-53.log" 2>&1 &
listener_observer=$!
trap 'kill "$listener_observer" 2>/dev/null || true; wait "$listener_observer" 2>/dev/null || true' EXIT
"$CONTROLLER_PYTHON" "$HERE/harness.py" "$EVIDENCE"
