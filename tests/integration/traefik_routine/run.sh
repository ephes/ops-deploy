#!/usr/bin/env bash
# Owned disposable hosted VM only; never an inventory host.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
[[ ! -e /etc/traefik && ! -e /usr/local/bin/traefik && ! -e /usr/bin/traefik ]]
[[ ! -e /var/lib/traefik-transactions && ! -e /var/lib/traefik-transport ]]
[[ ! -e /etc/systemd/system/traefik.service ]]
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
EVIDENCE=/var/tmp/traefik-routine-evidence
install -d -m 0700 "$EVIDENCE"
"${CONTROLLER_PYTHON:?}" - <<'PY'
import json,os
fd=os.open('/var/tmp/traefik-routine-owned-vm.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as f:
    json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':open('/etc/machine-id').read().strip()},f)
PY
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 logrotate openssl nginx ufw strace
"${CONTROLLER_PYTHON:?}" "$HERE/harness.py" "$EVIDENCE"
