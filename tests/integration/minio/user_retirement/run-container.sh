#!/usr/bin/env bash
# Listed-user retirement against a real MinIO server and client in a throwaway container.
# Usage: run-container.sh MINIO_BINARY MC_BINARY EVIDENCE_DIR (linux binaries of the container's arch).
# Everything the run writes stays on tmpfs apart from the evidence directory; no network to the
# outside is used after the dependency install, no socket or credential is mounted.
set -euo pipefail
minio=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
mc=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
evidence=$(cd "$3" && pwd)
source=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
image=${MINIO_RETIREMENT_IMAGE:-ghcr.io/astral-sh/uv:python3.12-bookworm-slim}
exec docker run --rm --read-only \
    --tmpfs /tmp:rw,exec,size=2g --tmpfs /root:size=256m --tmpfs /run \
    -v "$source:/src:ro" -v "$minio:/opt/minio:ro" -v "$mc:/opt/mc:ro" -v "$evidence:/evidence" \
    -e UV_CACHE_DIR=/tmp/uv-cache -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
    "$image" bash -c '
        set -euo pipefail
        mkdir /tmp/source
        tar -C /src --exclude=.venv --exclude=.git --exclude=.mypy_cache --exclude=__pycache__ -cf - . | tar -C /tmp/source -xf -
        cd /tmp/source
        uv sync --locked --quiet --no-dev
        exec /tmp/venv/bin/python tests/integration/minio/user_retirement/harness.py /opt/minio /opt/mc /evidence
    '
