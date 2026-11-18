#!/bin/bash
# Local run of the `software-live-apt` CI job (software-live PLAN.md 7.4):
# for each variant (default: both), a throwaway container of its image with
# a copy of rust/ (without rust/target), container/deps.sh, then
# container/run.sh. Needs Docker; on an arm64 Docker VM the images are the
# arm64 builds of the same releases (CI runs x86_64). Toolchains and the
# cargo registry are kept in the named volumes <prefix>-<arch>-rustup
# and <prefix>-<arch>-cargo. SOFTWARE_LIVE_APT_PLATFORM=linux/amd64 runs the
# x86_64 images (Rosetta, rust/README.md).
#
#   container/docker-check.sh [ubuntu24.04] [debian13]
#
# SOFTWARE_LIVE_APT_CHECK_NAME sets the prefix of the container and volume
# names (default software-live-apt-check).
set -euo pipefail

repo=$(cd "$(dirname "$0")/../../.." && pwd)
prefix=${SOFTWARE_LIVE_APT_CHECK_NAME:-software-live-apt-check}
# The platform of the containers (default: the Docker engine's own, e.g.
# linux/arm64 on a Mac); the toolchain volumes are kept per architecture.
platform=${SOFTWARE_LIVE_APT_PLATFORM:-$(docker version -f '{{.Server.Os}}/{{.Server.Arch}}')}
arch=${platform#*/}
variants=("$@")
if [ ${#variants[@]} -eq 0 ]; then
    variants=(ubuntu24.04 debian13)
fi

for variant in "${variants[@]}"; do
    case "$variant" in
        ubuntu24.04) image=ubuntu:24.04 ;;
        debian13) image=debian:13 ;;
        *)
            echo "docker-check.sh: unknown variant $variant (ubuntu24.04, debian13)" >&2
            exit 2
            ;;
    esac
    echo "=== software-live-apt in $image"
    docker run --rm --platform "$platform" --name "${prefix}-${variant}-$$" \
        -v "$repo:/src:ro" \
        -v "${prefix}-${arch}-rustup:/root/.rustup" \
        -v "${prefix}-${arch}-cargo:/root/.cargo" \
        -e SOFTWARE_LIVE_APT_CONTAINER=yes \
        "$image" bash -euo pipefail -c '
            mkdir /work
            tar -C /src --exclude=./rust/target -cf - ./rust | tar -C /work -xf -
            /work/rust/software-live-apt/container/deps.sh
            /work/rust/software-live-apt/container/run.sh'
done
