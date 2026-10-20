"""A minimal homelab checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "manage.py": "#!/usr/bin/env python\n",
    "pyproject.toml": "[project]\nname = 'homelab'\n",
    "uv.lock": "version = 1\n",
    "src/config/__init__.py": "",
    "src/config/settings/production.py": "DEBUG = False\n",
}


def make_source(root: Path, *, media: bool = False) -> Path:
    source = root / "homelab"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    if media:
        logos = source / "media" / "services" / "logos"
        logos.mkdir(parents=True)
        (logos / "app.png").write_bytes(b"png")
    return source
