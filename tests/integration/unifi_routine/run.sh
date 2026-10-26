#!/usr/bin/env bash
# Only disposable GitHub-hosted Ubuntu x86 VMs; never an inventory host.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
if id unifi >/dev/null 2>&1; then
  echo "Refusing existing UniFi account" >&2
  exit 1
fi
[[ ! -e /usr/lib/unifi && ! -e /etc/systemd/system/unifi.service ]]
[[ ! -e /var/lib/mongodb && ! -e /var/lib/unifi && ! -e /etc/mongod.conf ]]
[[ ! -e /usr/sbin/policy-rc.d ]]
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
EVIDENCE=/var/tmp/unifi-routine-evidence
install -d -m 0700 "$EVIDENCE"
"${CONTROLLER_PYTHON:?}" - <<'PY'
import json, os
fd=os.open('/var/tmp/unifi-routine-owned-vm.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as f:
    json.dump({'run':os.environ['GITHUB_RUN_ID'],'machine':open('/etc/machine-id').read().strip()},f)
PY
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 logrotate whois
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc -o /usr/share/keyrings/mongodb-server-8.0.asc
printf '%s\n' 'deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.asc ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse' > /etc/apt/sources.list.d/mongodb-org.list
apt-get update
apt-get install -y mongodb-org=8.0.34 mongodb-org-server=8.0.34 mongodb-org-shell=8.0.34 mongodb-org-mongos=8.0.34 mongodb-org-tools=8.0.34 mongodb-org-database=8.0.34 mongodb-org-database-tools-extra=8.0.34
"${CONTROLLER_PYTHON:?}" "$HERE/harness.py" "$EVIDENCE"
