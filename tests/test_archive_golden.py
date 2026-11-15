"""archive's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/archive`` were recorded when these renders
still equalled the retired archive_deploy role's output (with ops-control's
playbook values); identical bytes mean the next deploy rewrites nothing and
restarts nothing (see tests/goldens.py).
"""

from pathlib import Path

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.archive import ArchiveConfig
from ops_deploy.services.archive.deploy import render_env, render_role, resolve
from tests.archive_fixtures import make_source
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "archive"
# Every character the env file's shell quoting escapes, plus ones it must leave alone.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#0123456789'
DOMAIN = "archive.home.example.invalid"


def make(tmp_path: Path, secrets: dict[str, str]) -> tuple[ArchiveConfig, SecretValues]:
    ref = SecretRef("secrets/prod/archive.yml")
    # ops-control's archive_config(): the playbook's literal values and _resolved defaults.
    cfg = ArchiveConfig(
        source_path=make_source(tmp_path),
        secrets=ref,
        traefik_host=DOMAIN,
        django_allowed_hosts=("127.0.0.1", DOMAIN),
        django_csrf_trusted_origins=(f"https://{DOMAIN}",),
        media_storage_backend="storages.backends.s3.S3Storage",
        media_storage_location="/home/archive/site/archive-media",
        media_storage_bucket_name="archive-media",
        media_storage_endpoint_url="http://127.0.0.1:9001",
        media_storage_access_key_id="archive-media",
    )
    values = SecretValues(ref, secrets)
    return resolve(cfg, values), values


BASE = {
    "django_secret_key": AWKWARD,
    "api_token": "api-token-0123456789abcdefgh",
    "summary_api_key": "summary-key-0123456789abcdefgh",
    "admin_username": "archive",
    "admin_password": "admin-password",
    "media_storage_secret_access_key": "s3$secret`0123",
}
VARIANTS = {
    "playbook-defaults": BASE,
    "secrets-settings": {
        **BASE,
        "summary_api_base": "https://llm.example.invalid/v1",
        "summary_model": "gpt-5-mini",
        "transcription_api_key": "transcription-key-0123456789",
        "transcription_model": "whisper-1",
        "media_storage_backend": "django.core.files.storage.FileSystemStorage",
        "media_storage_location": "/srv/archive-media",
        "media_storage_bucket_name": "other-bucket",
        "media_storage_region_name": "eu-1",
        "media_storage_access_key_id": "other-key",
        "media_storage_addressing_style": "virtual",
    },
}


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_host_files_are_golden(tmp_path: Path, variant: str) -> None:
    cfg, values = make(tmp_path, VARIANTS[variant])
    golden = GOLDEN / variant

    assert_golden(golden / "archive.env", render_env(cfg, values, shell=False).reveal().decode())
    assert_golden(golden / "archive.shell.env", render_env(cfg, values, shell=True).reveal().decode())
    for template in ("archive.service.j2", "archive-metadata-worker.service.j2", "archive.traefik.yml.j2"):
        assert_golden(golden / template.removesuffix(".j2"), render_role(template, cfg, values))


def test_shell_env_quotes_shell_metacharacters(tmp_path: Path) -> None:
    cfg, values = make(tmp_path, BASE)

    shell = render_env(cfg, values, shell=True).reveal().decode()

    assert 'DJANGO_SECRET_KEY="k\\$y\\`with\\"quotes\\\\and(parens)&amp;#0123456789"' in shell
