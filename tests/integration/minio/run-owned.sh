#!/usr/bin/env bash
# Owned GitHub x86 VM, isolated Ubuntu24 systemd userspace; no inventory mounts.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} ]]
SOURCE=$(git rev-parse --show-toplevel)
[[ $(git rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ -z $(git config --local --get-regexp 'credential|extraheader|insteadof' || true) ]]
ARTIFACTS=${MINIO_FIXTURE_ARTIFACTS:?}
EVIDENCE=${MINIO_FIXTURE_EVIDENCE:?}
mkdir -p "$EVIDENCE"
python3 - "$ARTIFACTS" <<'PY'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1])
expected={'minio':'2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4','mc':'01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891'}
assert {p.name for p in root.iterdir()}==set(expected)
for name,sha in expected.items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==sha
PY
NAME="ops-owned-minio-${GITHUB_RUN_ID}"
! docker inspect "$NAME" >/dev/null 2>&1
cleanup() {
    docker logs "$NAME" > "$EVIDENCE/guest-init.log" 2>&1 || true
    docker inspect "$NAME" > "$EVIDENCE/guest-inspect.json" 2>/dev/null || true
    docker cp "$NAME:/var/tmp/minio-evidence/." "$EVIDENCE/" 2>/dev/null || true
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if docker inspect "$NAME" >/dev/null 2>&1; then
        echo 'Owned guest cleanup failed' >&2
        exit 1
    fi
}
trap cleanup EXIT
# Public build instructions, no source/data/socket/credential bind mounts.
docker build -t "ops-owned-minio:${GITHUB_RUN_ID}" -f tests/integration/minio/Dockerfile tests/integration/minio
docker image inspect "ops-owned-minio:${GITHUB_RUN_ID}" ubuntu:24.04 > "$EVIDENCE/images.json"
docker run -d --name "$NAME" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock "ops-owned-minio:${GITHUB_RUN_ID}"
for attempt in $(seq 1 60); do
    if docker exec "$NAME" systemctl is-system-running | grep -Eq 'running|degraded'; then break; fi
    sleep 1
done
docker exec "$NAME" mkdir -p /opt/controller /opt/minio-artifacts
docker cp "$SOURCE/." "$NAME:/opt/controller/"
docker cp "$ARTIFACTS/minio" "$NAME:/opt/minio-artifacts/minio"
docker cp "$ARTIFACTS/mc" "$NAME:/opt/minio-artifacts/mc"
docker cp "${UV_BIN:?}" "$NAME:/usr/local/bin/uv"
# Explicit allowlist. No Actions runtime tokens, GH auth, SSH agent or inventory
# credentials pass into the guest or its public-source/controller installation.
docker exec "$NAME" env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root LANG=C.UTF-8 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_RUN_ID="$GITHUB_RUN_ID" IMPLEMENTATION_SHA="$IMPLEMENTATION_SHA" \
    bash /opt/controller/tests/integration/minio/run-guest.sh
