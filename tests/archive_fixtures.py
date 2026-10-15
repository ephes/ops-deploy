"""A minimal archive checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "src/django/manage.py": "# manage\n",
    "src/django/config/settings/production.py": "DEBUG = False\n",
    "src/archive/__init__.py": "",
    "pyproject.toml": "[project]\nname = 'archive'\n",
    "uv.lock": "version = 1\n",
    "README.md": "# archive\n",
}


def make_source(root: Path) -> Path:
    source = root / "archive"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
