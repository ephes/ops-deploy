#!/bin/bash
# The checks of software-live-apt inside one variant image (software-live
# PLAN.md 7.1, 7.4, 13.6), after container/deps.sh: clippy and the unit
# tests, the release build with its GLIBC ceiling and NEEDED allowlist,
# `--version`, then the fake APT world and the comparison with python-apt.
# Used by the `software-live-apt` job of .github/workflows/rust.yml and by
# container/docker-check.sh. Runs as root in a throwaway container only:
# setup-world.sh rewrites the container's APT configuration.
set -euo pipefail

rust=$(cd "$(dirname "$0")/../.." && pwd)
cd "$rust"
export PATH="$HOME/.cargo/bin:$PATH"

. /etc/os-release
case "$ID $VERSION_ID" in
    "ubuntu 24.04") glibc_max=2.39 libapt=libapt-pkg.so.6.0 ;;
    "debian 13") glibc_max=2.41 libapt=libapt-pkg.so.7.0 ;;
    *)
        echo "run.sh: $ID $VERSION_ID is not a software-live-apt variant" >&2
        exit 1
        ;;
esac

rustup toolchain install
rustc --version
python3 --version

echo "== clippy and tests (software-live-apt)"
cargo clippy -p software-live-apt --all-targets --locked -- -D warnings
cargo test -p software-live-apt --locked

echo "== release build, GLIBC <= ${glibc_max}, NEEDED glibc/libgcc_s/${libapt}/libstdc++"
cargo build --release --locked -p software-live-apt
bin="$rust/target/release/software-live-apt"
if [ "$(uname -m)" = x86_64 ]; then
    python3 -I scripts/release_checks.py glibc-floor --max "$glibc_max" \
        --allow "$libapt" --allow libstdc++.so.6 "$bin"
else
    # A local run on an arm64 Docker VM: the same check with the arm64
    # loader allowed (releases are x86_64, whose loader is in the base list).
    objdump -T -p "$bin" | python3 -I -c '
import sys
sys.path.insert(0, "scripts")
import release_checks as c
allowed = c.BASE_NEEDED | {sys.argv[2], "libstdc++.so.6", "ld-linux-aarch64.so.1"}
print("glibc", c.check_glibc(sys.stdin.read(), sys.argv[1], allowed))
' "$glibc_max" "$libapt"
fi
"$bin" --version
echo "stripped size: $(stat -c %s "$bin") bytes (budget 2 MiB, PLAN.md 10)"

echo "== fake APT world and python-apt comparison"
bash software-live-apt/container/setup-world.sh
python3 -I software-live-apt/container/compare.py \
    --helper "$bin" --oracle "$rust/../roles/software_live/files/software_live.py"
