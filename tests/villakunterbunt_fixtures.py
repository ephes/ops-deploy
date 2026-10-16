"""A minimal Django plus Next.js tree for deploy tests."""

from pathlib import Path

MIDDLEWARE_PROD = "export function middleware() {}\n"

SOURCE_FILES = {
    "package.json": '{"name": "app"}\n',
    "package-lock.json": "{}\n",
    "nextjs/middleware.ts": "import { jwtVerify } from 'jose';\n",
    "nextjs/middleware.prod.ts": MIDDLEWARE_PROD,
    "nextjs/content/home.json": "{}\n",
    "django/manage.py": "# manage\n",
    "django/pyproject.toml": "[project]\nname = 'app'\n",
    "django/uv.lock": "version = 1\n",
    "django/config/wsgi.py": "application = None\n",
}


def make_source(root: Path) -> Path:
    source = root / "app"
    for name, content in SOURCE_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source
