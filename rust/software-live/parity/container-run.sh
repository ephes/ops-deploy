#!/bin/bash
# The software-live parity harness inside one variant image (PLAN.md 6.2),
# after software-live-apt/container/deps.sh: the release builds of
# software-live and software-live-apt installed root-owned side by side in
# /opt/software-live-parity (the collector runs the helper next to its own
# executable, PLAN.md 5.2), the fake APT world of
# software-live-apt/container/setup-world.sh (unless an earlier step of the
# same container made it), then parity/run_parity.py with the image's
# python3 and python-apt as the oracle's interpreter. Arguments go to
# run_parity.py (e.g. --section endpoint -v).
#
# Used by the `software-live-apt` job of .github/workflows/rust.yml (after
# container/run.sh) and by parity/docker-parity.sh. Runs as root in a
# throwaway container only: the harness changes /etc/hosts, the trust
# store, /usr and the APT configuration.
set -euo pipefail

if [ ! -f /.dockerenv ] && [ "${SOFTWARE_LIVE_APT_CONTAINER:-}" != yes ]; then
    echo "container-run.sh: refusing to run outside a container" >&2
    exit 1
fi

rust=$(cd "$(dirname "$0")/../.." && pwd)
cd "$rust"
export PATH="$HOME/.cargo/bin:$PATH"

rustup toolchain install
echo "== release builds (software-live, software-live-apt)"
cargo build --release --locked -p software-live -p software-live-apt
install -d -m 0755 -o root -g root /opt/software-live-parity
install -m 0755 -o root -g root target/release/software-live target/release/software-live-apt \
    /opt/software-live-parity/

if [ ! -d /srv/apt-world/repos ]; then
    echo "== fake APT world"
    bash software-live-apt/container/setup-world.sh
fi

echo "== parity harness ($(python3 --version))"
python3 -I software-live/parity/run_parity.py --binary /opt/software-live-parity/software-live "$@"
