#!/usr/bin/env bash
# No mount, network, socket, privileged mode or SYS_ADMIN is needed here.
set -euo pipefail
[[ ${MINIO_OWNED_ID:?} =~ ^[0-9a-f]{16}$ && -c /dev/kvm ]]
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -z ${SSH_AUTH_SOCK:-} ]]
[[ $(stat -c %s /work/rootfs.raw) == 8589934592 ]]
[[ $(find /input -mindepth 1 -maxdepth 1 -type f | wc -l) == 2 ]]
genisoimage -quiet -R -V MINIO_INPUT -o /work/input.iso /input
exec python3 /tooling.py
