"""A minimal echoport checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "src/django/manage.py": "# manage\n",
    "src/django/config/settings/production.py": "DEBUG = False\n",
    "src/backups/__init__.py": "",
    "src/backups/models.py": "# models\n",
    "pyproject.toml": "[project]\nname = 'echoport'\n",
    "uv.lock": "version = 1\n",
    "README.md": "# echoport\n",
}


def make_source(root: Path) -> Path:
    source = root / "echoport"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
