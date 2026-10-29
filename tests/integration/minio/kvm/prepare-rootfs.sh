#!/usr/bin/env bash
# Public dependency/bootstrap preparation only; no MinIO or fixture execution.
set -euo pipefail
SHA=${1:?}; OWNED_ID=${2:?}
COMPONENT=${3:-normal}
case "$COMPONENT" in normal|policy-rollback) ;; *) exit 2 ;; esac
[[ $SHA =~ ^[0-9a-f]{40}$ && $OWNED_ID =~ ^[0-9a-f]{16}$ ]]
[[ $(uname -m) == x86_64 && $(id -u) == 0 ]]
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -z ${SSH_AUTH_SOCK:-} ]]
cd /opt/controller
[[ $(git rev-parse HEAD) == "$SHA" ]]
[[ -z $(git config --local --get-regexp 'credential|extraheader|insteadof' || true) ]]
python3 -m venv /opt/bootstrap
/opt/bootstrap/bin/pip install uv==0.13.5
/opt/bootstrap/bin/uv sync --locked --no-dev --python 3.13
/opt/bootstrap/bin/uv pip install --python .venv/bin/python --no-deps --reinstall "ops-deploy @ git+https://github.com/ephes/ops-deploy.git@$SHA"
/opt/bootstrap/bin/uv venv --python 3.13 /opt/minio-ansible
/opt/bootstrap/bin/uv pip install --python /opt/minio-ansible/bin/python ansible==14.5.0
git -c credential.helper= clone https://github.com/ephes/ops-library.git /opt/minio-library
git -C /opt/minio-library checkout --detach d88c3286b2fb58a8799663d6c1f3a9d6061af37b
printf '%s\n' "$SHA" > /etc/ops-minio-implementation
printf '%s\n' "$OWNED_ID" > /etc/ops-minio-owned-id
printf '%s\n' "$COMPONENT" > /etc/ops-minio-component
printf '/dev/vda / ext4 defaults 0 1\n' > /etc/fstab
rm -f /.dockerenv /run/.containerenv
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
cat > /etc/systemd/system/ops-minio-fixture.service <<'UNIT'
[Unit]
Description=Owned offline MinIO fixture
Requires=dev-sr0.device
After=local-fs.target dev-sr0.device
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/controller/tests/integration/minio/kvm/guest-entry.sh
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
UNIT
ln -s /etc/systemd/system/ops-minio-fixture.service /etc/systemd/system/multi-user.target.wants/ops-minio-fixture.service
