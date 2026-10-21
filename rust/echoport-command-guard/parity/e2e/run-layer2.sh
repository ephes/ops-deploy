#!/usr/bin/env bash
# Layer 2 (rust/echoport-command-guard/PLAN.md 7.5): build the probe and the
# guard, then run as root in a container per host distribution
# parity/e2e/layer2_realpath.py (the filesystem layer against CPython) and
# parity/e2e/layer2_decide.py (Python's check() against `--decide` on real
# trees; the Python guard is mounted read-only). Needs Docker; changes
# nothing outside the containers.
#
#   rust/echoport-command-guard/parity/e2e/run-layer2.sh [ubuntu2404] [debian13]
#
# ECHOPORT_E2E_SUFFIX is appended to the image and container names (parallel
# runs); extra arguments go into ECHOPORT_L2_ARGS for layer2_realpath.py
# (e.g. "--random 2000 --seed 7") and ECHOPORT_L2_DECIDE_ARGS for
# layer2_decide.py (e.g. "--random 1000 --seed 7").
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../.." && pwd)
guard="$(cd "$workspace/.." && pwd)/roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py"
suffix=${ECHOPORT_E2E_SUFFIX:-}
# (The `${extra[@]+...}` form below keeps an empty array safe under `set -u`
# in macOS's Bash 3.2.)
read -r -a extra <<< "${ECHOPORT_L2_ARGS:-}"
read -r -a decide_extra <<< "${ECHOPORT_L2_DECIDE_ARGS:-}"
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
    if ! docker run --rm --name "$name" -v "$guard":/e2e/guard.py:ro "$name" \
        python3 -I /e2e/layer2_decide.py --guard /e2e/guard.py \
        --binary /usr/local/bin/echoport-command-guard --policies /e2e/policies \
        ${decide_extra[@]+"${decide_extra[@]}"}; then
        status=1
    fi
done
exit "$status"
