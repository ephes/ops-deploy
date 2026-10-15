"""A minimal work-ledger checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "manage.py": "#!/usr/bin/env python\nimport sys\n",
    "pyproject.toml": "[project]\nname = 'work-ledger'\n",
    "uv.lock": "version = 1\n",
    "src/config/__init__.py": "",
    "src/config/wsgi.py": "application = None\n",
    "ledger/items.yml": "items: []\n",
}


def make_source(root: Path) -> Path:
    source = root / "work-ledger"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
