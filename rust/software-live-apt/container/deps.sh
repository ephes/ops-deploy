#!/bin/bash
# Build and test dependencies of software-live-apt inside a variant image
# (ubuntu:24.04, debian:13; software-live PLAN.md 7.1, 7.4): libapt-pkg-dev
# and a C++ compiler for rust-apt, python3-apt for the python-apt oracle,
# apt-utils (apt-ftparchive) for the fake repositories, binutils for the
# NEEDED/GLIBC check, and rustup (pinned release, sha256 checked; the
# toolchain itself comes from rust/rust-toolchain.toml).
#
# Used by the `software-live-apt` job of .github/workflows/rust.yml and by
# container/docker-check.sh. Runs as root in a throwaway container only.
set -euo pipefail

if [ ! -f /.dockerenv ] && [ "${SOFTWARE_LIVE_APT_CONTAINER:-}" != yes ]; then
    echo "deps.sh: refusing to run outside a container" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    apt-utils binutils ca-certificates curl g++ gcc git libapt-pkg-dev \
    libc6-dev python3 python3-apt

RUSTUP_VERSION=1.29.1
case "$(uname -m)" in
    x86_64)
        triple=x86_64-unknown-linux-gnu
        sha256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71 # pragma: allowlist secret
        ;;
    aarch64)
        triple=aarch64-unknown-linux-gnu
        sha256=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433 # pragma: allowlist secret
        ;;
    *)
        echo "deps.sh: unsupported machine $(uname -m)" >&2
        exit 1
        ;;
esac
if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
    # rustup-init acts by its file name.
    tmp=$(mktemp -d)
    init="$tmp/rustup-init"
    curl --proto '=https' --tlsv1.2 -sSfL -o "$init" \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init"
    echo "${sha256}  ${init}" | sha256sum --check
    chmod 0755 "$init"
    "$init" -y --no-modify-path --profile minimal --default-toolchain none
    rm -rf "$tmp"
fi
