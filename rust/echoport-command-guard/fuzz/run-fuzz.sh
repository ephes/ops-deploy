#!/usr/bin/env bash
# Run the cargo-fuzz targets of echoport-command-guard in a container
# (PLAN.md 7.4). Needs Docker; changes nothing outside the container but the
# corpus (fuzz/corpus/<target>/, mounted) and, on a find, fuzz/artifacts/.
#
#   rust/echoport-command-guard/fuzz/run-fuzz.sh [seconds] [target...]
#
# Defaults: 3600 seconds for each of the four targets, all at the same time
# (one container each). ECHOPORT_E2E_SUFFIX is appended to the image, volume
# and container names. After a run, `run-fuzz.sh cmin [target...]` minimises
# the corpus before it is committed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../.." && pwd)
suffix=${ECHOPORT_E2E_SUFFIX:-}
image="echoport-command-guard-fuzz${suffix}"
volume="echoport-command-guard-fuzz-target${suffix}"
all=(prefilter_tokens check policy py_repr)

mode=run
seconds=3600
if [ "${1:-}" = cmin ]; then
    mode=cmin
    shift
elif [ -n "${1:-}" ] && [ "${1#*[!0-9]}" = "$1" ]; then
    seconds=$1
    shift
fi
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    targets=("${all[@]}")
fi

docker build --quiet --tag "$image" "$here" > /dev/null
run() {
    local name=$1
    shift
    docker run --rm --name "$name" -v "$workspace":/work -v "$volume":/target \
        -w /work/echoport-command-guard "$image" bash -c "$*"
}
cargo_fuzz='cargo +"$FUZZ_TOOLCHAIN" fuzz'
run "${image}-build" "$cargo_fuzz build --debug-assertions --target-dir /target"

pids=()
for target in "${targets[@]}"; do
    mkdir -p "$here/corpus/$target"
    if [ "$mode" = cmin ]; then
        run "${image}-${target}" "$cargo_fuzz cmin --debug-assertions --target-dir /target $target fuzz/corpus/$target"
        continue
    fi
    run "${image}-${target}" "$cargo_fuzz run --debug-assertions --target-dir /target $target fuzz/corpus/$target \
        -- -max_total_time=$seconds -max_len=8192 -rss_limit_mb=2048 -print_final_stats=1" \
        > "$here/run-$target.log" 2>&1 &
    pids+=("$!")
done
status=0
for pid in ${pids[@]+"${pids[@]}"}; do
    wait "$pid" || status=1
done
for target in "${targets[@]}"; do
    [ "$mode" = run ] && { echo "== $target"; tail -n 20 "$here/run-$target.log"; }
done
exit "$status"
