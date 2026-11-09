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
EVIDENCE=/var/tmp/mail-web-evidence
install -d -m 0700 "$EVIDENCE"
"$CONTROLLER_PYTHON" - <<'PY'
import json,os
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
