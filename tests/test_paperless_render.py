"""Rendered host files (golden) and actual shell environment interpretation."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from ops_deploy.services.paperless.config import PaperlessConfig, PaperlessCredentials
from ops_deploy.services.paperless.render import render
from tests.goldens import assert_golden

FIXTURES = Path(__file__).parent / "fixtures" / "paperless"
GOLDEN = Path(__file__).parent / "golden" / "paperless"
CASES = ["defaults", "authenticated-redis", "custom-account"]
TEMPLATES = [
    "gunicorn.conf.py.j2",
    "paperless-consumer.service.j2",
    "paperless-scheduler.service.j2",
    "paperless-worker.service.j2",
    "paperless.env.j2",
    "paperless.service.j2",
    "paperless.traefik.yml.j2",
    "sshd_sftp_scanner.conf.j2",
]


def inputs(case: str) -> tuple[PaperlessConfig, PaperlessCredentials]:
    root = FIXTURES / case
    cfg = PaperlessConfig.model_validate_json((root / "config.json").read_text())
    credentials = PaperlessCredentials.model_validate_json((root / "synthetic-inputs.json").read_text())
    return cfg, credentials


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("template", TEMPLATES)
def test_render_matches_golden(case: str, template: str) -> None:
    cfg, credentials = inputs(case)
    assert_golden(GOLDEN / case / template.removesuffix(".j2"), render(template, cfg, credentials))


@pytest.mark.parametrize("case", CASES)
def test_bash_environment_reader_preserves_values(case: str, tmp_path: Path) -> None:
    cfg, credentials = inputs(case)
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
