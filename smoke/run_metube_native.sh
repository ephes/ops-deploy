#!/usr/bin/env bash
# Dedicated owned fixture only; packages this checkout and a reviewed source commit.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_repo="${1:?provide the maintained MeTube source checkout}"
source_commit="${2:?provide the reviewed source commit}"
export SMOKE_VM=metube-native-20261027
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
"$here/smoke/vm.sh" up
"$here/smoke/vm.sh" ssh 'install -d -m0755 /srv/metube-fixture/source /srv/metube-fixture/ops-deploy'
git -C "$source_repo" archive "$source_commit" | "$here/smoke/vm.sh" ssh 'tar -xf - -C /srv/metube-fixture/source'
tar -C "$here" -czf "$scratch/package.tar.gz" src pyproject.toml uv.lock README.md LICENSE smoke/metube_native_fixture.py
"$here/smoke/vm.sh" ssh 'tar -xzf - -C /srv/metube-fixture/ops-deploy' < "$scratch/package.tar.gz"
"$here/smoke/vm.sh" ssh 'cd /srv/metube-fixture/ops-deploy && uv run --locked python smoke/metube_native_fixture.py'
