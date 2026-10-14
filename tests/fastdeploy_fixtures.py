"""A minimal FastDeploy checkout for deploy tests."""

from pathlib import Path

SOURCE_FILES = {
    "commands.py": "# commands\n",
    "pyproject.toml": "[project]\nname = 'fastdeploy'\n",
    "uv.lock": "version = 1\n",
    "src/deploy/__init__.py": "",
    "services/.exists_in_git": "",
    "frontend/package.json": '{"name": "frontend"}\n',
    "frontend/package-lock.json": "{}\n",
    "frontend/src/main.ts": "console.log('hi')\n",
}


def make_source(root: Path) -> Path:
    source = root / "fastdeploy"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
