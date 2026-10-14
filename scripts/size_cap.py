"""Check the size cap on the shared layer (helpers + ops + core).

A code line is a physical line that carries at least one Python token other
than a comment, and is not part of a docstring (the first string statement of
a module, class or function). Blank lines, comments and docstrings are free:
the rendered documentation is built from them. Only ``*.py`` files count;
templates do not.

Usage: ``python scripts/size_cap.py [--cap N]``; exits 1 above the cap.
"""

from __future__ import annotations

import argparse
import ast
import io
import sys
import tokenize
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "ops_deploy"
LAYERS = ("helpers", "ops", "core")
DEFAULT_CAP = 1500
_SKIP = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}


def docstring_spans(tree: ast.Module) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """(start, end) positions of module, class and function docstring expressions."""

    spans: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                end = (first.end_lineno or first.lineno, first.end_col_offset or 0)
                spans.append(((first.lineno, first.col_offset), end))
    return spans


def code_lines(source: str) -> int:
    spans = docstring_spans(ast.parse(source))
    lines: set[int] = set()
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        # Every token of a docstring expression (parentheses, concatenated parts) is documentation.
        if token.type in _SKIP or any(start <= token.start < end for start, end in spans):
            continue
        # A docstring statement's NEWLINE or ``;`` alone does not make a line code.
        if token.type == tokenize.OP and token.string == ";" and token.start[0] not in lines:
            continue
        lines.update(range(token.start[0], token.end[0] + 1))
    return len(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cap", type=int, default=DEFAULT_CAP)
    args = parser.parse_args(argv)
    total_lines = total_code = 0
    for layer in LAYERS:
        layer_lines = layer_code = 0
        for path in sorted((PACKAGE / layer).rglob("*.py")):
            source = path.read_text()
            layer_lines += len(source.splitlines())
            layer_code += code_lines(source)
        print(f"{layer:<8} {layer_lines:>5} lines {layer_code:>5} code lines")
        total_lines += layer_lines
        total_code += layer_code
    print(f"{'total':<8} {total_lines:>5} lines {total_code:>5} code lines (cap {args.cap})")
    if total_code > args.cap:
        print(f"size cap exceeded by {total_code - args.cap} code lines", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
