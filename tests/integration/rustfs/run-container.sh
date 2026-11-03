#!/usr/bin/env bash
# Real pyinfra deploys of RustFS into a throwaway Ubuntu 24.04 systemd container.
# Usage: run-container.sh RUSTFS_BINARY EVIDENCE_DIR
#   RUSTFS_BINARY: the extracted pinned release executable for the Docker host's
#   architecture (the harness refuses any other digest).
# Container, image and volume names carry the slug and this PID; everything is
# removed on exit. No socket, credential or inventory is mounted; /mnt/cryptdata
# is an owned anonymous volume so it is a real mount point inside the guest.
set -euo pipefail
binary=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
evidence=$(mkdir -p "$2" && cd "$2" && pwd)
source=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
name="ops-rustfs-svc-it-$$"
image="ops-rustfs-svc-it:$$"
cleanup() {
    docker logs "$name" > "$evidence/guest-init.log" 2>&1 || true
    docker cp "$name:/var/tmp/rustfs-evidence/." "$evidence/" 2>/dev/null || true
    docker rm -f -v "$name" >/dev/null 2>&1 || true
    docker image rm "$image" >/dev/null 2>&1 || true
    if docker inspect "$name" >/dev/null 2>&1; then echo "cleanup of $name failed" >&2; exit 1; fi
}
trap cleanup EXIT
docker build -q -t "$image" "$(dirname "${BASH_SOURCE[0]}")" >/dev/null
docker run -d --name "$name" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --mount type=volume,dst=/mnt/cryptdata \
    "$image" >/dev/null
for _ in $(seq 1 60); do
    if docker exec "$name" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded'; then break; fi
    sleep 1
done
docker exec "$name" mkdir -p /opt/controller /opt/rustfs-artifact /var/tmp/rustfs-evidence
COPYFILE_DISABLE=1 tar -C "$source" --no-xattrs --exclude=.venv --exclude=.git --exclude=.mypy_cache --exclude=__pycache__ -cf - . \
    | docker exec -i "$name" tar -C /opt/controller -xf -
docker cp "$binary" "$name:/opt/rustfs-artifact/rustfs"
docker exec "$name" env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
    UV_PROJECT_ENVIRONMENT=/opt/venv sh -c \
    'cd /opt/controller && uv sync --locked --quiet --no-dev && exec /opt/venv/bin/python tests/integration/rustfs/harness.py /opt/rustfs-artifact/rustfs /var/tmp/rustfs-evidence'
