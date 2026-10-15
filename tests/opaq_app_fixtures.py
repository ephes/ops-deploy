"""A minimal daybook checkout for opaq_app deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "services/opaq_app/manage.py": "# manage\n",
    "services/opaq_app/opaq_app/settings.py": "DEBUG = False\n",
    "src/daybook/opaq_site.py": "# site\n",
    "src/daybook/__init__.py": "",
    "pyproject.toml": "[project]\nname = 'daybook'\n",
    "uv.lock": "version = 1\n",
}


def make_source(root: Path) -> Path:
    source = root / "daybook"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
