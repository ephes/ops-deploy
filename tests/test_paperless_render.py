"""Original Ansible template bytes and actual shell environment interpretation."""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from ops_deploy.services.paperless.config import PaperlessConfig, PaperlessCredentials
from ops_deploy.services.paperless.render import render

FIXTURES = Path(__file__).parent / "parity/paperless"
MANIFEST = json.loads((FIXTURES / "templates-source.json").read_text())


@pytest.mark.parametrize("case", MANIFEST["cases"])
@pytest.mark.parametrize("template", MANIFEST["templates"])
def test_actual_original_template_parity(case: str, template: str) -> None:
    root = FIXTURES / case
    cfg = PaperlessConfig.model_validate_json((root / "config.json").read_text())
    credentials = PaperlessCredentials.model_validate_json((root / "synthetic-inputs.json").read_text())
    assert render(template, cfg, credentials) == (root / (template + ".rendered")).read_text()


def test_templates_preserve_checksum_bound_original_source() -> None:
    root = Path(__file__).parents[1] / "src/ops_deploy/services/paperless/templates"
    assert {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in root.glob("*.j2")} == MANIFEST[
        "templates"
    ]


@pytest.mark.parametrize("case", MANIFEST["cases"])
def test_original_bash_environment_reader_preserves_values(case: str, tmp_path: Path) -> None:
    root = FIXTURES / case
    cfg = PaperlessConfig.model_validate_json((root / "config.json").read_text())
    credentials = PaperlessCredentials.model_validate_json((root / "synthetic-inputs.json").read_text())
    # Synthetic values only. Avoid secret-looking temporary filenames that the
    # independent review sandbox intentionally prevents reading/removing.
    env_file = tmp_path / "synthetic-paperless.conf"
    env_file.write_text(render("paperless.env.j2", cfg, credentials))
    code = "import json,os;print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('PAPERLESS_')}))"
    command = f"set -a; . {shlex.quote(str(env_file))}; set +a; {shlex.join([sys.executable, '-c', code])}"
    result = subprocess.run(["bash", "-euc", command], check=True, capture_output=True, text=True)
    values = json.loads(result.stdout)
    assert values["PAPERLESS_SECRET_KEY"] == credentials.secret_key.get_secret_value()
    assert values["PAPERLESS_DBPASS"] == credentials.postgres_password.get_secret_value()
    assert values["PAPERLESS_FILENAME_FORMAT"] == cfg.filename_format
    assert values["PAPERLESS_IGNORE_DATES"] == ",".join(cfg.ignore_dates)
    if case == "authenticated-redis":
        assert values["PAPERLESS_REDIS"] == "redis://:synthetic%3A%40%2F%26%3F%25@localhost:6379/0"
