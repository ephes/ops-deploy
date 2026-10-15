"""archive files are byte-identical to the archive_deploy role's output.

The deploy ships the role's templates unchanged; this renders the vendored
copies (``tests/parity/ansible/archive_deploy__*``, checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
with the variables ``deploy-archive.yml`` passes, the way Ansible's
``template`` module does, and compares with what the deploy writes.
"""

from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.archive import ArchiveConfig
from ops_deploy.services.archive.deploy import render_env, render_role, resolve
from tests.archive_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/archive/templates"
# Every character the role's shell quoting escapes, plus ones it must leave alone.
AWKWARD = 'k$y`with"quotes\\and(parens)&amp;#0123456789'
DOMAIN = "archive.home.example.invalid"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(f"archive_deploy__{template}").render(**variables)


def playbook_vars(secrets: dict[str, str], **extra: Any) -> dict[str, Any]:
    """Role defaults overlaid with deploy-archive.yml's role vars (and its defaults)."""

    site = "/home/archive/site"
    summary_base = secrets.get("summary_api_base", "https://api.openai.com/v1")
    return {
        "archive_user": "archive",
        "archive_group": "archive",
        "archive_home": "/home/archive",
        "archive_site_path": site,
        "archive_django_path": f"{site}/src/django",
        "archive_venv_bin": f"{site}/.venv/bin",
        "archive_env_path": f"{site}/.env",
        "archive_db_path": f"{site}/db.sqlite3",
        "archive_static_root": f"{site}/staticfiles",
        "archive_app_host": "127.0.0.1",
        "archive_app_port": 10041,
        "archive_workers": 2,
        "archive_metadata_worker_interval": 10,
        "archive_metadata_worker_limit": 10,
        "archive_metadata_request_timeout": 15,
        "archive_summary_request_timeout": 60,
        "archive_transcription_request_timeout": 300,
        "archive_django_settings_module": "config.settings.production",
        "archive_django_debug": False,
        "archive_django_secret_key": secrets["django_secret_key"],
        "archive_django_allowed_hosts": ["127.0.0.1", DOMAIN],
        "archive_django_csrf_trusted_origins": [f"https://{DOMAIN}"],
        "archive_api_token": secrets["api_token"],
        "archive_summary_api_key": secrets["summary_api_key"],
        "archive_summary_api_base": summary_base,
        "archive_summary_model": secrets.get("summary_model", "gpt-4o-mini"),
        "archive_transcription_api_key": secrets.get("transcription_api_key", secrets["summary_api_key"]),
        "archive_transcription_api_base": secrets.get("transcription_api_base", summary_base),
        "archive_transcription_model": secrets.get("transcription_model", "gpt-4o-mini-transcribe"),
        "archive_media_storage_backend": secrets.get("media_storage_backend", "storages.backends.s3.S3Storage"),
        "archive_media_storage_location": secrets.get("media_storage_location", f"{site}/archive-media"),
        "archive_media_storage_base_url": "",
        "archive_media_storage_bucket_name": secrets.get("media_storage_bucket_name", "archive-media"),
        "archive_media_storage_endpoint_url": secrets.get("media_storage_endpoint_url", "http://127.0.0.1:9001"),
        "archive_media_storage_region_name": secrets.get("media_storage_region_name", ""),
        "archive_media_storage_access_key_id": secrets.get("media_storage_access_key_id", "archive-media"),
        "archive_media_storage_secret_access_key": secrets["media_storage_secret_access_key"],
        "archive_media_storage_addressing_style": secrets.get("media_storage_addressing_style", "path"),
        "archive_traefik_host": DOMAIN,
        "archive_traefik_entrypoints": ["web-secure"],
        "archive_traefik_cert_resolver": "",
        "archive_traefik_middlewares": [],
        **extra,
    }


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
    "playbook defaults": BASE,
    "settings in the secrets file": {
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


@pytest.mark.parametrize("secrets", VARIANTS.values(), ids=VARIANTS.keys())
def test_env_files_are_byte_identical(tmp_path: Path, secrets: dict[str, str]) -> None:
    cfg, values = make(tmp_path, secrets)
    role = playbook_vars(secrets)

    assert render_env(cfg, values, shell=False).reveal().decode() == render_ansible("archive.env.j2", role)
    shell = render_ansible("archive.env.j2", {**role, "task_shell_environment": True})
    assert render_env(cfg, values, shell=True).reveal().decode() == shell
    assert 'DJANGO_SECRET_KEY="k\\$y\\`with\\"quotes\\\\and(parens)&amp;#0123456789"' in shell


@pytest.mark.parametrize(
    "template", ["archive.service.j2", "archive-metadata-worker.service.j2", "archive.traefik.yml.j2"]
)
def test_units_and_route_are_byte_identical(tmp_path: Path, template: str) -> None:
    cfg, values = make(tmp_path, BASE)

    assert render_role(template, cfg, values) == render_ansible(template, playbook_vars(BASE))


def test_packaged_templates_are_the_role_templates() -> None:
    for packaged in PACKAGED.glob("*.j2"):
        assert packaged.read_text() == (VENDORED / f"archive_deploy__{packaged.name}").read_text()
