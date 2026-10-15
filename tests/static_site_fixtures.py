"""A minimal generated site for the static_site tests."""

from __future__ import annotations

from pathlib import Path

FILES = {"index.html": "<p>benchpack registry snapshot</p>\n", "report.md": "# Report\n", "snapshot.json": "{}\n"}


def make_source(root: Path, **extra: str) -> Path:
    source = root / "site"
    source.mkdir()
    for name, text in {**FILES, **extra}.items():
        (source / name).write_text(text)
    return source
