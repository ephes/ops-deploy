#!/usr/bin/env bash
# Privileged systemd userspace ONLY on a fresh disposable public GitHub VM.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ ${GITHUB_REPOSITORY:-} == ephes/ops-deploy && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ && ${GITHUB_RUN_ATTEMPT:?} =~ ^[0-9]+$ ]]
[[ ${HOMEASSISTANT_FIXTURE_CASE:?} == current || $HOMEASSISTANT_FIXTURE_CASE == upgrade ]]
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -z ${SSH_AUTH_SOCK:-} ]]
SOURCE=$(git rev-parse --show-toplevel)
[[ $(git rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
git diff --exit-code --quiet HEAD
[[ -z $(git config --local --get-regexp 'credential|extraheader|insteadof' || true) ]]
[[ $("${UV_BIN:?}" --version) == 'uv 0.13.4'* ]]
UV_RESOLVED=$(readlink -f "$UV_BIN")
[[ -f $UV_RESOLVED && -x $UV_RESOLVED ]]
OWNED_ID="homeassistant-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
NAME="ops-owned-$OWNED_ID"
IMAGE="ops-owned-homeassistant:$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
EVIDENCE=${HOMEASSISTANT_FIXTURE_EVIDENCE:?}
[[ ! -e $EVIDENCE ]]
mkdir -m 0700 -p "$EVIDENCE"
! docker container inspect "$NAME" >/dev/null 2>&1
! docker image inspect "$IMAGE" >/dev/null 2>&1
cleanup() {
    original_rc=$?
    trap - EXIT
    docker logs "$NAME" > "$EVIDENCE/guest-init.log" 2>&1 || true
    docker inspect "$NAME" > "$EVIDENCE/guest-inspect.json" 2>/dev/null || true
    collection_rc=0
    if timeout 30s docker exec "$NAME" python3 /opt/homeassistant-evidence.py > "$EVIDENCE/collection-manifest.json" 2> "$EVIDENCE/collection-error.log"; then
        timeout 120s docker cp "$NAME:/var/tmp/homeassistant-evidence/." "$EVIDENCE/" 2> "$EVIDENCE/collection-copy.log" || collection_rc=$?
    else
        collection_rc=$?
    fi
    docker rm -f "$NAME" > "$EVIDENCE/container-cleanup.log" 2>&1 || true
    docker image rm "$IMAGE" > "$EVIDENCE/image-cleanup.log" 2>&1 || true
    cleanup_rc=0
    if docker container inspect "$NAME" >/dev/null 2>&1 || docker image inspect "$IMAGE" >/dev/null 2>&1; then cleanup_rc=1; fi
    printf '{"run_exit":%s,"collection_exit":%s,"cleanup_exit":%s}\n' "$original_rc" "$collection_rc" "$cleanup_rc" > "$EVIDENCE/runner-exit.json"
    if [[ $cleanup_rc -ne 0 ]]; then exit "$cleanup_rc"; fi
    if [[ $original_rc -eq 0 && $collection_rc -ne 0 ]]; then exit "$collection_rc"; fi
    exit "$original_rc"
}
trap cleanup EXIT
# GitHub documents14GB standard storage, not40GiB free. Record actual checkout
# and Docker capacity.12GiB is an admission floor, not a claimed measured peak:
# a larger original dependency install must fail honestly, never omit packages.
DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}')
df -Pk "$SOURCE" "$DOCKER_ROOT" > "$EVIDENCE/initial-capacity.txt"
awk 'NR > 1 && $4 < 12582912 {failed=1} END {exit failed}' "$EVIDENCE/initial-capacity.txt"
timeout 15m docker build --label "ops.owned=$OWNED_ID" -t "$IMAGE" \
    -f "$SOURCE/tests/integration/homeassistant/Dockerfile" "$SOURCE/tests/integration/homeassistant"
# BuildKit may cache the base by digest without creating a local Ubuntu tag.
# The full build log records its resolved digest; inspect only our owned image.
docker image inspect "$IMAGE" > "$EVIDENCE/images.json"
docker run -d --name "$NAME" --label "ops.owned=$OWNED_ID" \
    --privileged --cgroupns=private --cpus=2 --memory=6g --memory-swap=6g --pids-limit=2048 \
    --log-driver=local --log-opt=max-size=20m --log-opt=max-file=1 --log-opt=compress=false \
    --tmpfs /run --tmpfs /run/lock "$IMAGE"
ready=0
for attempt in $(seq 1 60); do
    if docker exec "$NAME" systemctl is-system-running | grep -Eq '^(running|degraded)$'; then ready=1; break; fi
    sleep 1
done
[[ $ready == 1 ]]
docker cp "$SOURCE/tests/integration/homeassistant/run-guest.sh" "$NAME:/opt/homeassistant-run-guest.sh"
docker cp "$SOURCE/tests/integration/homeassistant/evidence.py" "$NAME:/opt/homeassistant-evidence.py"
docker cp "$UV_RESOLVED" "$NAME:/usr/local/bin/uv"
docker exec "$NAME" env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    sh -c 'test ! -e /etc/ops-homeassistant-owned-id && printf "%s\n" "$1" > /etc/ops-homeassistant-owned-id' sh "$OWNED_ID"
# Only these explicit non-secret fields enter the guest. No host binds/ports,
# agent socket, checkout credentials, Actions runtime token or inventory data.
GUEST_DEADLINE=100m
timeout "$GUEST_DEADLINE" docker exec "$NAME" env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root LANG=C.UTF-8 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
    HOMEASSISTANT_FIXTURE_CASE="$HOMEASSISTANT_FIXTURE_CASE" \
    HOMEASSISTANT_OWNED_ID="$OWNED_ID" IMPLEMENTATION_SHA="$IMPLEMENTATION_SHA" \
    bash /opt/homeassistant-run-guest.sh
