# ops-deploy development tasks

default:
    @just --list

# Install the locked dev environment
sync:
    uv sync --locked

# Run the test suite
test *args:
    uv run --locked pytest {{args}}

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
