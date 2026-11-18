# ops-deploy development tasks

default:
    @just --list

# Install the locked dev environment
sync:
    uv sync --locked

# pytest-xdist workers: half the CPUs (rounded down, at least 1), so several
# suites can share a machine; PYTEST_JOBS overrides (a number, or auto for one per CPU)
half_cpus := `n=$(( $(getconf _NPROCESSORS_ONLN) / 2 )); [ "$n" -ge 1 ] || n=1; echo "$n"`
jobs := env("PYTEST_JOBS", half_cpus)

# Bytecode for the suite and the Python children it starts: on (an unset PYTHONDONTWRITEBYTECODE),
# but outside the tree (PYTHONPYCACHEPREFIX, default ~/.cache/ops-deploy/pycache). Without it,
# collection alone recompiles the package (~10 s) and every child Python recompiles what it imports.
pycache := "env -u PYTHONDONTWRITEBYTECODE PYTHONPYCACHEPREFIX=\"${PYTHONPYCACHEPREFIX:-${XDG_CACHE_HOME:-$HOME/.cache}/ops-deploy/pycache}\""

# Run the test suite in parallel (pytest-xdist, idle workers steal tests); serial, e.g. with --pdb: just test -n 0
test *args:
    {{pycache}} uv run --locked pytest -n {{jobs}} --dist worksteal {{args}}

# Run only the test files the working-tree change (git diff HEAD + untracked) can affect;
# a fast inner loop, not a gate: run `just test` or `just check` before each commit.
# Why each file is selected: uv run python scripts/affected_tests.py --explain
test-changed *args:
    #!/usr/bin/env sh
    set -eu
    selected=$(uv run --locked python scripts/affected_tests.py)
    case $selected in
        NONE) echo "test-changed: no change against HEAD"; exit 0 ;;
        ALL) echo "test-changed: the change reaches core, project or widely used files: whole suite"; exec just test {{args}} ;;
    esac
    echo "test-changed: $(printf '%s\n' "$selected" | wc -l | tr -d ' ') test files"
    # One repo-relative path per line, none with spaces: split on purpose.
    exec {{pycache}} uv run --locked pytest -n {{jobs}} --dist worksteal $selected {{args}}

# Run mypy (strict)
typecheck:
    uv run --locked mypy

# Run ruff lint and format check
lint:
    uv run --locked ruff check .
    uv run --locked ruff format --check .

# Apply ruff fixes and formatting
fmt:
    uv run --locked ruff check --fix .
    uv run --locked ruff format .

# Build the documentation (fails on warnings)
docs:
    uv run --locked mkdocs build --strict

# Serve the documentation locally
docs-serve:
    uv run --locked mkdocs serve

# Echoport's RustFS account provisioner against a RustFS 1.0.4 container (needs Docker)
test-echoport-rustfs:
    ECHOPORT_RUSTFS_DOCKER=1 uv run --locked pytest -q tests/test_echoport_rustfs_account_docker.py

# RustFS replication and its monitor between two local RustFS 1.0.4 servers (no Docker)
test-rustfs-replication binary:
    RUSTFS_BINARY={{binary}} uv run --locked pytest -q tests/test_rustfs_replication_local.py

# Check the code-line cap on helpers + ops + core (docs/development.md)
size-cap:
    uv run --locked python scripts/size_cap.py

# Everything CI runs
check: lint typecheck test size-cap docs

# --- Rust workspace (rust/, moved from ops-library; rust/README.md) ---------------
# Not part of `just check`: these need rustup's cargo first in PATH (the toolchain
# of rust/rust-toolchain.toml), cargo-deny 0.20.2, uv (Pythons 3.12 to 3.14),
# htpasswd, and Docker for rust-check-apt and rust-release. A change under rust/
# runs rust-check (and rust-check-apt when it touches software-live or its apt
# helper) before it is pushed.

# The Rust workspace checks: fmt, clippy, tests, cargo-deny, apt isolation, script tests, oracle fixture drift, parity
rust-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cd rust
    want=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
    if ! cargo --version | grep -q "^cargo ${want} "; then
        echo "rust-check: $(cargo --version) is not the pinned ${want}; put rustup's cargo (~/.cargo/bin) first in PATH" >&2
        exit 1
    fi
    # The guard's tokeniser tests run the Python guard under production's Python.
    ECHOPORT_ORACLE_PYTHON=$(uv python find --no-project 3.12)
    export ECHOPORT_ORACLE_PYTHON
    # Package names only (validated by the script): word-split on purpose.
    excludes=$(cargo metadata --format-version 1 --no-deps --locked | python3 -I scripts/ci_excludes.py)
    cargo fmt --check
    cargo clippy --workspace $excludes --all-targets --locked -- -D warnings
    cargo test --workspace $excludes --locked
    cargo deny --locked check
    metadata=$(mktemp)
    trap 'rm -f "$metadata"' EXIT
    cargo metadata --format-version 1 --locked --all-features > "$metadata"
    python3 -I scripts/release_checks.py apt-isolation --metadata "$metadata"
    python3 -I -m unittest discover -s scripts -p 'test_*.py'
    uv run --python 3.12 --no-project python -I -m unittest discover -s software-live/parity -p 'test_*.py'
    # Fixture drift against the frozen oracles (rust/oracle): the guard under the
    # hosts' Pythons, metrics-httpd rendered under 3.14 (the ops-library venv's)
    # and its stdlib families under 3.12 and 3.13, software-live under 3.14.
    uv run --python 3.12 --no-project python -I echoport-command-guard/parity/gen_fixtures.py check
    uv run --python 3.13 --no-project python -I echoport-command-guard/parity/gen_fixtures.py check
    uv run --python 3.14 --no-project --with jinja2 --with pyyaml python -I metrics-httpd/fixtures/generate.py check
    uv run --python 3.12 --no-project python -I metrics-httpd/fixtures/generate.py check --stdlib-only
    uv run --python 3.13 --no-project python -I metrics-httpd/fixtures/generate.py check --stdlib-only
    uv run --python 3.14 --no-project python -I software-live/fixtures/generate.py --check
    cd ..
    just rust-parity-metrics-httpd

# metrics-httpd parity: the binary side by side with the rendered Python endpoints (CPython 3.12, htpasswd)
rust-parity-metrics-httpd:
    #!/usr/bin/env bash
    set -euo pipefail
    (cd rust && cargo build --locked -p metrics-httpd)
    python=$(uv python find --no-project 3.12)
    uv run --locked python rust/metrics-httpd/parity/run_parity.py --binary rust/target/debug/metrics-httpd --python "$python"
    cd rust/metrics-httpd
    uv run --python 3.12 --no-project python -I -m unittest discover -s parity -p 'test_*.py'
    uv run --python 3.13 --no-project python -I -m unittest discover -s parity -p 'test_*.py'

# software-live-apt and the software-live parity harness in ubuntu:24.04 and debian:13 containers (Docker)
rust-check-apt *variants:
    rust/software-live-apt/container/docker-check.sh {{variants}}
    rust/software-live/parity/docker-parity.sh {{variants}}

# Local release build of a crate's current version in linux/amd64 containers (publishes nothing; rust/README.md)
rust-release crate *args:
    python3 -I rust/scripts/release.py build {{crate}} {{args}}

# Tag and publish what `just rust-release <crate>` built as a GitHub release of ops-deploy
rust-release-publish crate *args:
    python3 -I rust/scripts/release.py publish {{crate}} {{args}}

# Publish the releases built in ops-library (rust/releases.json) again on ops-deploy, byte for byte
rust-release-import-old *args:
    python3 -I rust/scripts/release.py import-old {{args}}

# Create/start and provision the lima smoke VM (idempotent)
smoke-up:
    smoke/vm.sh up

# Deploy toyweb to the smoke VM twice and run the secret_file fault tests
smoke *args: smoke-up
    #!/usr/bin/env bash
    set -euo pipefail
    settings="$(smoke/vm.sh env)"
    set -a
    eval "$settings"
    set +a
    test -n "${SMOKE_SSH_HOST:-}"
    uv run --locked pytest tests/smoke {{args}}

# Root shell on the smoke VM (or run a command there)
smoke-ssh *args:
    smoke/vm.sh ssh {{args}}

# Delete the smoke VM and its SSH key
smoke-down:
    smoke/vm.sh down
