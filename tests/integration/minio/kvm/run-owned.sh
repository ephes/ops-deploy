#!/usr/bin/env bash
# Explicit inventory-host tooling boundary; this does not claim GitHub provenance.
set -euo pipefail
[[ $(id -u) == 0 && $(uname -m) == x86_64 && -c /dev/kvm ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${MINIO_OWNED_ID:?} =~ ^[0-9a-f]{16}$ ]]
[[ -z ${GITHUB_ACTIONS:-} && -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -z ${SSH_AUTH_SOCK:-} ]]
MINIO_COMPONENT=${MINIO_COMPONENT:-normal}
case "$MINIO_COMPONENT" in normal|policy-rollback) ;; *) exit 2 ;; esac
ROOT="/tmp/ops-owned-minio-kvm-$MINIO_OWNED_ID"
[[ ${MINIO_FIXTURE_ROOT:?} == "$ROOT" && -d $ROOT && ! -L $ROOT ]]
[[ $(stat -c '%u:%g:%a' "$ROOT") == 0:0:700 ]]
mkdir "$ROOT/claim"
mkdir -m 0700 "$ROOT/evidence" "$ROOT/docker-config"
export DOCKER_CONFIG="$ROOT/docker-config" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
NAME="ops-owned-minio-kvm-$MINIO_OWNED_ID"
IMAGE="ops-owned-minio-kvm:$MINIO_OWNED_ID"
! docker inspect "$NAME" >/dev/null 2>&1
! docker image inspect "$IMAGE" >/dev/null 2>&1
[[ -z $(docker container ls -aq --filter "label=io.ops.minio.fixture=$MINIO_OWNED_ID") ]]
[[ -z $(docker image ls -aq --filter "label=io.ops.minio.fixture=$MINIO_OWNED_ID") ]]
cleanup() {
    local result=$? failures=0
    trap - EXIT
    docker inspect "$NAME" > "$ROOT/evidence/tooling-inspect.json" 2>/dev/null || true
    docker logs "$NAME" > "$ROOT/evidence/tooling.log" 2>&1 || true
    if docker inspect "$NAME" >/dev/null 2>&1; then
        docker cp "$NAME:/evidence/." - 2>/dev/null | \
            python3 "$ROOT/source/tests/integration/minio/kvm/collect-evidence.py" \
            "$ROOT/evidence" || failures=1
    fi
    local containers
    containers=$(docker container ls -aq --filter "label=io.ops.minio.fixture=$MINIO_OWNED_ID")
    if [[ -n $containers ]]; then docker rm -f $containers >/dev/null 2>&1 || true; fi
    for _attempt in $(seq 1 8); do
        local images
        images=$(docker image ls -aq --filter "label=io.ops.minio.fixture=$MINIO_OWNED_ID")
        [[ -n $images ]] || break
        # Every selected image has this fresh ownership label, including stages.
        docker image rm $images >/dev/null 2>&1 || true
    done
    if [[ -n $(docker container ls -aq --filter "label=io.ops.minio.fixture=$MINIO_OWNED_ID") ]]; then failures=1; fi
    if [[ -n $(docker image ls -aq --filter "label=io.ops.minio.fixture=$MINIO_OWNED_ID") ]]; then failures=1; fi
    printf '{"job_exit":%s,"owned_cleanup_failures":%s}\n' "$result" "$failures" > "$ROOT/evidence/cleanup.json"
    rm -rf "$ROOT/source" "$ROOT/artifacts" "$ROOT/docker-config"
    [[ $failures == 0 ]] || result=1
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}')
python3 - "$ROOT" "$DOCKER_ROOT" <<'PY'
import hashlib,json,shutil,sys
from pathlib import Path
root=Path(sys.argv[1]);artifacts=root/'artifacts'
assert shutil.disk_usage(root).free>=512*1024**2
assert Path(sys.argv[2]).is_absolute()
assert shutil.disk_usage(sys.argv[2]).free>=32*1024**3
available=int(next(line for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')).split()[1])
assert available>=6*1024**2
expected={'minio':(110977208,'2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4'),'mc':(30535864,'01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891')}
assert {p.name for p in artifacts.iterdir()}==set(expected)
for name,(size,digest) in expected.items():
 p=artifacts/name
 assert not p.is_symlink() and p.is_file() and p.stat().st_size==size
 assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
(root/'evidence/bounds.json').write_text(json.dumps({'guest_vcpus':2,'guest_memory_mib':4096,'guest_disk_bytes':8589934592,'tooling_memory_limit':'5g','tooling_cpus':2,'guest_network':'none','device':'/dev/kvm','host_mounts':[],'host_ports':[],'privileged':False,'sys_admin':False,'host_apt_changes':False},indent=2))
PY
git -c credential.helper= clone https://github.com/ephes/ops-deploy.git "$ROOT/source" > "$ROOT/evidence/clone.log" 2>&1
git -C "$ROOT/source" checkout --detach "$IMPLEMENTATION_SHA" >> "$ROOT/evidence/clone.log" 2>&1
[[ $(git -C "$ROOT/source" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
# The classic builder has removable labelled intermediate images, not shared
# BuildKit caches requiring broad prune. If unavailable, fail before guest launch.
DOCKER_BUILDKIT=0 timeout --signal=TERM --kill-after=20s 40m docker build --force-rm --no-cache --memory 5g --memory-swap 5g --cpu-period 100000 --cpu-quota 200000 \
    --build-arg "OWNED_ID=$MINIO_OWNED_ID" --build-arg "IMPLEMENTATION_SHA=$IMPLEMENTATION_SHA" \
    --build-arg "MINIO_COMPONENT=$MINIO_COMPONENT" \
    -t "$IMAGE" "$ROOT/source/tests/integration/minio/kvm" > "$ROOT/evidence/build.log" 2>&1
docker image inspect "$IMAGE" > "$ROOT/evidence/image.json"
docker create --name "$NAME" --label "io.ops.minio.fixture=$MINIO_OWNED_ID" \
    --network none --device /dev/kvm --cap-drop ALL --security-opt no-new-privileges \
    --cpus 2 --memory 5g --memory-swap 5g --pids-limit 256 \
    --log-driver local --log-opt max-size=20m --log-opt max-file=1 --log-opt compress=false \
    -e "MINIO_OWNED_ID=$MINIO_OWNED_ID" "$IMAGE" >/dev/null
docker cp "$ROOT/artifacts" "$NAME:/input"
docker start "$NAME" >/dev/null
timeout --signal=TERM --kill-after=20s 50m docker wait "$NAME" > "$ROOT/evidence/container-exit"
[[ $(cat "$ROOT/evidence/container-exit") == 0 ]]
