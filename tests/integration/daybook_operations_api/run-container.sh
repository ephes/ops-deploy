#!/usr/bin/env bash
# Fixed-path fixture in a fresh container; never mount host authorization.
set -euo pipefail
[[ "$GITHUB_ACTIONS" == true && "$RUNNER_ENVIRONMENT" == github-hosted ]]
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ && "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]
[[ "$IMPLEMENTATION_SHA" =~ ^[0-9a-f]{40}$ ]]
name="daybook-operations-api-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
image="$name:fixture"
export_parent="$RUNNER_TEMP/$name"
# Refuse collisions without removing any preexisting object.
if docker container inspect "$name" >/dev/null 2>&1; then exit 64; fi
if docker image inspect "$image" >/dev/null 2>&1; then exit 64; fi
mkdir -m 700 "$export_parent"
container_id=""
image_id=""
volume_names=""
cleanup() {
    rc=$?
    trap - EXIT
    cleanup_ok=true
    if [[ -n "$container_id" ]]; then
        docker container rm -fv "$container_id" || cleanup_ok=false
        if docker container inspect "$container_id" >/dev/null 2>&1; then cleanup_ok=false; fi
    fi
    for volume in $volume_names; do
        if docker volume inspect "$volume" >/dev/null 2>&1; then cleanup_ok=false; fi
    done
    if [[ -n "$image_id" ]]; then
        docker image rm "$image" || cleanup_ok=false
        if docker image inspect "$image" >/dev/null 2>&1; then cleanup_ok=false; fi
    fi
    printf '{"fixture_exit":%s,"owned_container_and_image_tag_removed":%s}\n' "$rc" "$cleanup_ok" > "$export_parent/container-cleanup.json"
    [[ "$cleanup_ok" == true ]] || rc=1
    exit "$rc"
}
trap cleanup EXIT
docker build --tag "$image" --file tests/integration/daybook_operations_api/Dockerfile tests/integration/daybook_operations_api
image_id=$(docker image inspect --format '{{.Id}}' "$image")
container_id=$(docker create --name "$name" \
    --mount "type=bind,source=$PWD,target=/source,readonly" \
    --mount "type=bind,source=$export_parent,target=/evidence" \
    -e GITHUB_ACTIONS=true -e RUNNER_ENVIRONMENT=github-hosted \
    -e GITHUB_RUN_ID -e IMPLEMENTATION_SHA -e UV_PYTHON=3.13 \
    "$image" bash -euc '
        mkdir /workspace
        cp -R /source/. /workspace/
        cd /workspace
        unset OPS_DEPLOY_PATH OPS_LIBRARY_PATH VIRTUAL_ENV
        uv sync --locked --no-dev
        uv pip install --python .venv/bin/python --no-deps --reinstall "ops-deploy @ git+https://github.com/ephes/ops-deploy.git@$IMPLEMENTATION_SHA"
        .venv/bin/python tests/integration/daybook_operations_api/management_fixture.py
    ')
volume_names=$(docker container inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}' "$container_id")
for volume in $volume_names; do [[ "$volume" =~ ^[a-f0-9]{64}$ ]]; done
docker start --attach "$container_id"
