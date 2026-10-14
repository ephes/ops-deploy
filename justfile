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

# Everything CI runs
check: lint typecheck test docs
