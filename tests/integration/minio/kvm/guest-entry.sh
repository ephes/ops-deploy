#!/usr/bin/env bash
set -euo pipefail
install -d -m 0700 /var/tmp/minio-evidence
finish() {
    local result=$?
    printf '{"exit":%s}\n' "$result" > /var/tmp/minio-evidence/guest-exit.json
    sync
    systemctl poweroff
}
trap finish EXIT
[[ $(id -u) == 0 && $(uname -m) == x86_64 && $(cat /proc/1/comm) == systemd ]]
[[ $(systemd-detect-virt --vm) == kvm ]]
[[ -z ${GITHUB_ACTIONS:-} && -z ${RUNNER_ENVIRONMENT:-} ]]
[[ -z $(env | grep -Ei '(token|secret|ssh_auth|github_api|actions_runtime)' || true) ]]
IMPLEMENTATION_SHA=$(cat /etc/ops-minio-implementation)
MINIO_OWNED_ID=$(cat /etc/ops-minio-owned-id)
[[ $IMPLEMENTATION_SHA =~ ^[0-9a-f]{40}$ && $MINIO_OWNED_ID =~ ^[0-9a-f]{16}$ ]]
grep -Eq "(^| )ops_minio_owned=$MINIO_OWNED_ID( |$)" /proc/cmdline
[[ ! -e /etc/default/minio && ! -e /etc/systemd/system/minio.service && ! -e /var/lib/minio ]]
[[ ! -e /opt/minio-fixture && ! -e /opt/minio-artifacts ]]
python3 - <<'PY'
import json,subprocess
from pathlib import Path
interfaces=json.loads(subprocess.check_output(['ip','-j','address']))
assert {row['ifname'] for row in interfaces}=={'lo'}
Path('/var/tmp/minio-evidence/network.json').write_text(json.dumps(interfaces))
PY
mount -o ro /dev/sr0 /mnt
[[ $(find /mnt -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 ]]
install -d -m 0700 /opt/minio-artifacts
cp /mnt/minio /mnt/mc /opt/minio-artifacts/
umount /mnt
export IMPLEMENTATION_SHA MINIO_OWNED_ID
cd /opt/controller
.venv/bin/python tests/integration/minio/verify-installed.py kvm-owned
install -d /opt/minio-fixture/collections/ansible_collections/local
mv /opt/minio-library /opt/minio-fixture/collections/ansible_collections/local/ops_library
.venv/bin/python tests/integration/minio/harness.py /var/tmp/minio-evidence
