#!/usr/bin/env bash
# Layer 3 (rust/echoport-command-guard/PLAN.md 7.6): the Python, Rust and
# shadow forced commands end to end through sshd, in a container per host
# distribution (parity/e2e/layer3_sshd.py; the Python guard is mounted
# read-only). Needs Docker; changes nothing outside the containers.
#
#   rust/echoport-command-guard/parity/e2e/run-layer3.sh [ubuntu2404] [debian13]
#
# ECHOPORT_E2E_SUFFIX is appended to the image and container names (parallel
# runs); extra arguments for the script go into ECHOPORT_L3_ARGS (e.g.
# "--only rsync").
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../.." && pwd)
guard="$(cd "$workspace/.." && pwd)/roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py"
suffix=${ECHOPORT_E2E_SUFFIX:-}
read -r -a extra <<< "${ECHOPORT_L3_ARGS:-}"
distros=("$@")
if [ ${#distros[@]} -eq 0 ]; then
    distros=(ubuntu2404 debian13)
fi

status=0
for distro in "${distros[@]}"; do
    case "$distro" in
        ubuntu2404) base=ubuntu:24.04 ;;
        debian13) base=debian:13 ;;
        *) echo "unknown distribution: $distro (ubuntu2404, debian13)" >&2; exit 2 ;;
    esac
    name="echoport-command-guard-l3-${distro}${suffix}"
    docker build --quiet --file "$here/Dockerfile" --build-arg "BASE=$base" \
        --target layer3 --tag "$name" "$workspace" > /dev/null
    echo "== $distro ($base)"
    if ! docker run --rm --name "$name" -v "$guard":/e2e/guard.py:ro "$name" \
        python3 -I /e2e/layer3_sshd.py --guard /e2e/guard.py \
        --binary /usr/local/bin/echoport-command-guard --policies /e2e/policies \
        --runner /e2e/runner.jsonl --stub /e2e/stub-tool.sh ${extra[@]+"${extra[@]}"}; then
        status=1
    fi
done
exit "$status"
