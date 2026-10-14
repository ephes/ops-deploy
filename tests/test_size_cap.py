"""The size-cap script counts only code lines and enforces the cap."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "size_cap.py"


@pytest.fixture(scope="module")
def size_cap() -> ModuleType:
    spec = importlib.util.spec_from_file_location("size_cap", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_counts_code_but_not_docstrings_comments_or_blanks(size_cap: ModuleType) -> None:
    source = '''"""Module docstring
spanning two lines."""

# a comment
import os  # trailing comment


class A:
    """Class docstring."""

    def f(self) -> str:
        """Function docstring."""
        text = """not a docstring
        but code"""
        return text
'''
    # import, class, def, the two-line string assignment, return
    assert size_cap.code_lines(source) == 6


def test_code_after_a_docstring_on_the_same_line_counts(size_cap: ModuleType) -> None:
    assert size_cap.code_lines('def f():\n    """docs"""; return 1\n') == 2
    assert size_cap.code_lines('def f(): """docs"""; return 1\n') == 1


def test_current_tree_is_under_the_cap(size_cap: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    assert size_cap.main([]) == 0
    assert "total" in capsys.readouterr().out


def test_exceeding_the_cap_fails(size_cap: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    assert size_cap.main(["--cap", "10"]) == 1
    assert "size cap exceeded" in capsys.readouterr().err
