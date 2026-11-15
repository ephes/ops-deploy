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

# Run the test suite in parallel (pytest-xdist, each test file on one worker); serial, e.g. with --pdb: just test -n 0
test *args:
    uv run --locked pytest -n {{jobs}} --dist loadfile {{args}}

# Run the suite with the ops-library parity and role-oracle tests (OPS_LIBRARY_PATH, default ../ops-library).
# Uses its own .venv-parity: the locked environment plus ansible-core, which the oracle tests import.
test-parity *args:
    #!/usr/bin/env sh
    set -eu
    library=$(cd "${OPS_LIBRARY_PATH:-../ops-library}" && pwd -P)
    echo "OPS_LIBRARY_PATH=$library ($(git -C "$library" rev-parse --short HEAD)$(test -z "$(git -C "$library" status --porcelain)" || echo ', dirty'))"
    # UV_PROJECT_ENVIRONMENT only for the sync: tests that run uv themselves must not inherit it.
    UV_PROJECT_ENVIRONMENT=.venv-parity uv sync --locked --inexact --quiet
    uv pip install --quiet --python .venv-parity/bin/python 'ansible-core==2.21.5'
    OPS_LIBRARY_PATH="$library" exec .venv-parity/bin/python -m pytest -n {{jobs}} --dist loadfile {{args}}

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
