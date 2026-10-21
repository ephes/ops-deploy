#!/usr/bin/env bash
# Layer 2, filesystem part (rust/echoport-command-guard/PLAN.md 7.5): build
# the probe and run parity/e2e/layer2_realpath.py as root in a container per
# host distribution. Needs Docker; changes nothing outside the containers.
#
#   rust/echoport-command-guard/parity/e2e/run-layer2.sh [ubuntu2404] [debian13]
#
# ECHOPORT_E2E_SUFFIX is appended to the image and container names (parallel
# runs); extra arguments for the script go into ECHOPORT_L2_ARGS
# (e.g. "--random 2000 --seed 7").
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../.." && pwd)
suffix=${ECHOPORT_E2E_SUFFIX:-}
# (The `${extra[@]+...}` form below keeps an empty array safe under `set -u`
# in macOS's Bash 3.2.)
read -r -a extra <<< "${ECHOPORT_L2_ARGS:-}"
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
    name="echoport-command-guard-l2-${distro}${suffix}"
    docker build --quiet --file "$here/Dockerfile" --build-arg "BASE=$base" \
        --target layer2 --tag "$name" "$workspace" > /dev/null
    echo "== $distro ($base)"
    if ! docker run --rm --name "$name" "$name" \
        python3 -I /e2e/layer2_realpath.py --probe /usr/local/bin/env-probe ${extra[@]+"${extra[@]}"}; then
        status=1
    fi
done
exit "$status"
