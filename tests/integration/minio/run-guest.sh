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
.venv/bin/python tests/integration/minio/verify-installed.py github-hosted
install -d -m 0700 /opt/minio-fixture
install -d /opt/minio-fixture/collections/ansible_collections/local
git clone https://github.com/ephes/ops-library.git /opt/minio-fixture/collections/ansible_collections/local/ops_library
git -C /opt/minio-fixture/collections/ansible_collections/local/ops_library checkout --detach d88c3286b2fb58a8799663d6c1f3a9d6061af37b
.venv/bin/python tests/integration/minio/harness.py /var/tmp/minio-evidence
