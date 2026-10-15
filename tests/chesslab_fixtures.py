"""A minimal chesslab (chess) checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "pyproject.toml": "[project]\nname = 'chesslab'\n",
    "uv.lock": "version = 1\n",
    "src/chesslab/__init__.py": "",
    "src/chesslab/djangoapp/settings.py": "DEBUG = False\n",
}


def make_source(root: Path) -> Path:
    source = root / "chess"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
