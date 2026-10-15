"""A minimal daybook checkout for weeknotes.home deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "pyproject.toml": "[project]\nname = 'daybook'\n",
    "uv.lock": "version = 1\n",
    "services/weeknotes_home/manage.py": "",
    "services/weeknotes_home/weeknotes_home/settings.py": "DEBUG = False\n",
    "src/daybook/cli.py": "",
}


def make_source(root: Path) -> Path:
    source = root / "daybook"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
