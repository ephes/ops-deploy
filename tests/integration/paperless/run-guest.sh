#!/usr/bin/env bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(uname -m) == x86_64 && $(cat /proc/1/comm) == systemd ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${PAPERLESS_OWNED_ID:?} =~ ^paperless-[0-9]+-[0-9]+$ ]]
[[ ${PAPERLESS_FIXTURE_CASE:?} == current || $PAPERLESS_FIXTURE_CASE == upgrade ]]
[[ $(cat /etc/ops-paperless-owned-id) == "$PAPERLESS_OWNED_ID" ]]
[[ -z $(env | grep -Ei '(token|secret|ssh_auth|github_api|actions_runtime)' || true) ]]
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]]
[[ ! -e /home/paperless && ! -e /var/tmp/paperless-owned-guest.json && ! -e /opt/controller ]]
install -d -m 0700 /var/tmp/paperless-evidence
printf '%s\n' 'public GitHub VM / Ubuntu24 systemd userspace / shared host kernel / no KVM claim' > /var/tmp/paperless-evidence/native-scope.txt
git clone --no-checkout https://github.com/ephes/ops-deploy.git /opt/controller
git -C /opt/controller checkout --detach "$IMPLEMENTATION_SHA"
cd /opt/controller
[[ $(git rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ -z $(git config --local --get-regexp 'credential|extraheader|insteadof' || true) ]]
cmp /opt/paperless-run-guest.sh tests/integration/paperless/run-guest.sh
uv sync --locked --no-dev --python 3.13
uv pip install --python .venv/bin/python --no-deps --reinstall "ops-deploy @ git+https://github.com/ephes/ops-deploy.git@$IMPLEMENTATION_SHA"
.venv/bin/python tests/integration/paperless/verify-installed.py
uv venv --python 3.13 /opt/paperless-ansible
uv pip install --python /opt/paperless-ansible/bin/python ansible==14.5.0
install -d -m 0700 /opt/paperless-fixture
install -d /opt/paperless-fixture/collections/ansible_collections/local
git clone https://github.com/ephes/ops-library.git /opt/paperless-fixture/collections/ansible_collections/local/ops_library
git -C /opt/paperless-fixture/collections/ansible_collections/local/ops_library checkout --detach d88c3286b2fb58a8799663d6c1f3a9d6061af37b
.venv/bin/python -m tests.integration.paperless.harness
