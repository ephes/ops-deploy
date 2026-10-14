"""A minimal nyxmon checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "src/django/manage.py": "# manage\n",
    "src/django/config/settings.py": "DEBUG = False\n",
    "src/nyxmon/__init__.py": "",
    "src/nyxboard/__init__.py": "",
    "pyproject.toml": "[project]\nname = 'nyxmon'\n",
    "uv.lock": "version = 1\n",
    "README.md": "# nyxmon\n",
}


def make_source(root: Path) -> Path:
    source = root / "nyxmon"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
