#!/usr/bin/env bash
# Build echoport-command-guard from this checkout into a release-layout
# archive (the binary and LICENSE at its root) for the role's molecule
# scenarios (rust/echoport-command-guard/PLAN.md 6.2, S6):
#
#   rust/echoport-command-guard/parity/e2e/build-local-archive.sh <dest.tar.gz>
#
# The binary is built in a Debian 12 container (Dockerfile, target
# local-archive) for the Docker host's architecture, so it runs in the
# molecule instances; the real release (x86_64) comes from rust-release.yml.
# Needs Docker with BuildKit. Changes nothing outside the build cache and
# <dest.tar.gz>.
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <dest.tar.gz>" >&2
    exit 2
fi
dest=$1
here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf -- "$out"' EXIT

docker build --quiet --file "$here/Dockerfile" --target local-archive \
    --output "type=local,dest=$out" "$workspace" > /dev/null
mkdir -p "$(dirname "$dest")"
mv -f -- "$out/echoport-command-guard-local.tar.gz" "$dest"
echo "$dest"
