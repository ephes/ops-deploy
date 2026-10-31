#!/usr/bin/env bash
set -euo pipefail
export OPS_LIBRARY_PATH=/opt/homeassistant-fixture/collections/ansible_collections/local/ops_library
unset OPS_DEPLOY_PATH
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(uname -m) == x86_64 && $(cat /proc/1/comm) == systemd ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${HOMEASSISTANT_OWNED_ID:?} =~ ^homeassistant-[0-9]+-[0-9]+$ ]]
[[ ${HOMEASSISTANT_FIXTURE_CASE:?} == current ]]
[[ $(cat /etc/ops-homeassistant-owned-id) == "$HOMEASSISTANT_OWNED_ID" ]]
[[ -z $(env | grep -Ei '(token|secret|ssh_auth|github_api|actions_runtime)' || true) ]]
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]]
[[ ! -e /home/homeassistant && ! -e /var/tmp/homeassistant-owned-guest.json && ! -e /opt/controller ]]
install -d -m 0700 /var/tmp/homeassistant-evidence
printf '%s\n' 'public GitHub VM / Ubuntu24 systemd userspace / shared host kernel / no KVM claim' > /var/tmp/homeassistant-evidence/native-scope.txt
git clone --no-checkout https://github.com/ephes/ops-deploy.git /opt/controller
git -C /opt/controller checkout --detach "$IMPLEMENTATION_SHA"
cd /opt/controller
[[ $(git rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ -z $(git config --local --get-regexp 'credential|extraheader|insteadof' || true) ]]
cmp /opt/homeassistant-run-guest.sh tests/integration/homeassistant/run-guest.sh
uv sync --locked --no-dev --python 3.13
uv pip install --python .venv/bin/python --no-deps --reinstall "ops-deploy @ git+https://github.com/ephes/ops-deploy.git@$IMPLEMENTATION_SHA"
.venv/bin/python tests/integration/homeassistant/verify-installed.py
uv venv --python 3.13 /opt/homeassistant-ansible
uv pip install --python /opt/homeassistant-ansible/bin/python ansible==14.5.0 ansible-core==2.21.5
install -d -m 0700 /opt/homeassistant-fixture
install -d /opt/homeassistant-fixture/collections/ansible_collections/local
git clone https://github.com/ephes/ops-library.git /opt/homeassistant-fixture/collections/ansible_collections/local/ops_library
git -C /opt/homeassistant-fixture/collections/ansible_collections/local/ops_library checkout --detach 73928436a5e6fcee81fc16835087f599366fa46a
[[ $(git -C "$OPS_LIBRARY_PATH" rev-parse HEAD) == 73928436a5e6fcee81fc16835087f599366fa46a ]]
# Single current original-stage diagnostic; no typed/full application matrix.
.venv/bin/python -m tests.integration.homeassistant.diagnose_wyoming
