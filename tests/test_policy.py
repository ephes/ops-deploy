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


REVEAL_ALLOWED = {PACKAGE / "core" / "secrets.py", PACKAGE / "ops" / "secret_file.py"}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_secret_content_is_only_revealed_by_secret_file(path: Path) -> None:
    # Secret bytes reach a host only through secret_file (stdin, 0600 temp, rename),
    # never through files.put/files.template or a command line.
    if path in REVEAL_ALLOWED:
        return
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = [
        f"{path.name}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "reveal"
    ]
    assert offenders == []


def test_sources_were_found() -> None:
    assert len(SOURCES) > 5
