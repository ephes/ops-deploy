"""A minimal heis checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "manage.py": "# manage\n",
    "pyproject.toml": "[project]\nname = 'heis'\n",
    "uv.lock": "version = 1\n",
    "config/__init__.py": "",
    "config/wsgi.py": "application = None\n",
    "config/settings/production.py": "DEBUG = False\n",
}


def make_source(root: Path) -> Path:
    source = root / "heis"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
