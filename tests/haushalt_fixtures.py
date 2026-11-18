"""A minimal daybook checkout with services/haushalt for haushalt deploy tests (synthetic content only)."""

from pathlib import Path

SOURCE_FILES = {
    "services/haushalt/web/manage.py": "# manage\n",
    "services/haushalt/web/site_config/settings.py": "DEBUG = False\n",
    "services/haushalt/web/money/views.py": "# views\n",
    "services/haushalt/pyproject.toml": "[project]\nname = 'haushalt'\n",
    "services/haushalt/uv.lock": "version = 1\n",
    "services/haushalt/.python-version": "3.14\n",
    "pyproject.toml": "[project]\nname = 'daybook'\n",
}


def make_source(root: Path) -> Path:
    source = root / "daybook"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
