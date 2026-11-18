#!/usr/bin/env bash
# Lean measurements (rust/echoport-command-guard/PLAN.md 8.3): the Rust and the
# Python guard in the Layer-3 container of each host distribution
# (parity/e2e/lean.py; the Python guard is mounted read-only). Prints a
# Markdown report; exits 1 when the Rust guard exceeds a budget. Needs Docker;
# changes nothing outside the containers. The numbers that count come from
# an x86_64 machine: the `rust` CI workflow runs this script when it is
# started by hand (workflow_dispatch).
#
#   rust/echoport-command-guard/parity/e2e/run-lean.sh [ubuntu2404] [debian13]
#
# ECHOPORT_E2E_SUFFIX is appended to the image and container names (parallel
# runs); extra arguments for the script go into ECHOPORT_LEAN_ARGS (e.g.
# "--runs 50").
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../.." && pwd)
guard="$(cd "$workspace/.." && pwd)/roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py"
suffix=${ECHOPORT_E2E_SUFFIX:-}
read -r -a extra <<< "${ECHOPORT_LEAN_ARGS:-}"
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
    if ! docker run --rm --name "${name}-lean" -v "$guard":/e2e/guard.py:ro "$name" \
        python3 -I /e2e/lean.py --guard /e2e/guard.py \
        --binary /usr/local/bin/echoport-command-guard --policies /e2e/policies \
        ${extra[@]+"${extra[@]}"}; then
        status=1
    fi
done
exit "$status"
