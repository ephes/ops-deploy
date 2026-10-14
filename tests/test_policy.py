"""Source-level guards for the secret-safety rules."""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "ops_deploy"
SOURCES = sorted(PACKAGE.rglob("*.py"))


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_no_sudo_global_argument(path: Path) -> None:
    # pyinfra stages _sudo uploads as plaintext in /tmp; deploys connect as the
    # needed user instead.
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = [
        f"{path.name}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword) and node.arg in {"_sudo", "_sudo_user", "_su_user", "_doas"}
    ]
    assert offenders == []


def test_sources_were_found() -> None:
    assert len(SOURCES) > 5
