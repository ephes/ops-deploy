"""Deploy-level scenarios for archive against the fake connector."""

import hashlib
import re
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.services.archive import ArchiveConfig, EchoportTarget, MinioBootstrap, deploy_archive
from ops_deploy.services.archive.deploy import _django_hash, admin_current, render_env, render_role, resolve
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.archive_fixtures import make_source

SITE = "/home/archive/site"
SECRET_VALUES = {
    "django_secret_key": "archive-fixture-django-key-0123456789",
    "api_token": "archive-fixture-api-token-0123456789",
    "summary_api_key": "archive-fixture-summary-key-0123456789",
    "admin_username": "archive-fixture-admin",
    "admin_password": "archive-fixture-admin-password",
    "admin_email": "admin@example.invalid",
}
S3_SECRETS = {
    "media_storage_secret_access_key": "archive-fixture-s3-secret-0123",
    "minio_root_user": "archive-fixture-minio-root",
    "minio_root_password": "archive-fixture-minio-root-password",
}
UNITS = {
    "archive": "/etc/systemd/system/archive.service",
    "archive-metadata-worker": "/etc/systemd/system/archive-metadata-worker.service",
}
ROUTE = "/etc/traefik/dynamic/archive.yml"
UV_SYNC = (
    f"cd {SITE} && runuser -u archive -- env HOME=/home/archive UV_PROJECT_ENVIRONMENT={SITE}/.venv "
    "/usr/local/bin/uv sync --no-dev --python 3.12"
)
ITEMIZED_CHANGE = [">f.st...... src/django/manage.py"]
ADMIN_PROBE = "One line per staff"
MINIO_PROBE = "minio-probe /usr/local/bin/mc"
MEDIA_PROBE = f"{SITE}/archive-media probe"
ECHOPORT_PROBE = '"apply":false'
RETIRED_PROBE = "ls /etc/systemd/system/archive-quote-classifier.timer"
READ_ONLY = [
    "Deploy archive | Wait for port 127.0.0.1:10041",
    "Deploy archive | Check http://127.0.0.1:10041/",
]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def admin_line(username: str, email: str, password: str, flags: str = "11") -> str:
    encoded = "pbkdf2_sha256$1000$fixturesalt"
    full = _django_hash(password, encoded)
    assert full is not None
    return f"{digest(username)} {digest(email)} {flags} {encoded} {digest(full)}"


def make_cfg(tmp_path: Path, **overrides: Any) -> ArchiveConfig:
    return ArchiveConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/archive.yml"),
        traefik_host="archive.example.invalid",
        django_allowed_hosts=("127.0.0.1", "archive.example.invalid"),
        django_csrf_trusted_origins=("https://archive.example.invalid",),
        **overrides,
    )


def s3_cfg(tmp_path: Path, **overrides: Any) -> ArchiveConfig:
    return make_cfg(
        tmp_path,
        media_storage_backend="storages.backends.s3.S3Storage",
        media_storage_bucket_name="archive-media",
        media_storage_endpoint_url="http://127.0.0.1:9001",
        media_storage_access_key_id="archive-media",
        minio=MinioBootstrap(),
        echoport=EchoportTarget(),
        **overrides,
    )


@pytest.fixture
def cfg(tmp_path: Path) -> ArchiveConfig:
    return make_cfg(tmp_path)


def values(cfg: ArchiveConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    base = {**SECRET_VALUES, **(S3_SECRETS if cfg.media_storage_backend.endswith("S3Storage") else {})}
    return SecretValues(cfg.secrets, {**base, **changes})


def converged(cfg: ArchiveConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where archive is fully deployed; ``drift`` overrides file content by path."""

    cfg = resolve(cfg, secrets)
    content = {
        f"{SITE}/.env": render_env(cfg, secrets, shell=False).reveal().decode(),
        f"{SITE}/.env.shell": render_env(cfg, secrets, shell=True).reveal().decode(),
        UNITS["archive"]: render_role("archive.service.j2", cfg, secrets),
        UNITS["archive-metadata-worker"]: render_role("archive-metadata-worker.service.j2", cfg, secrets),
        ROUTE: render_role("archive.traefik.yml.j2", cfg, secrets),
    }
    content.update(drift)
    responses: dict[str, Any] = {**fakehost.LINUX, **fakehost.system_account("archive", "/home/archive")}
    for path in ("", "/site", "/site/staticfiles"):
        responses.update(fakehost.directory(f"/home/archive{path}", user="archive"))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        private = path.endswith((".env", ".env.shell"))
        owner = "archive" if path.startswith(SITE) else "root"
        responses.update(fakehost.file(path, text, user=owner, mode="-rw-------" if private else "-rw-r--r--"))
    responses.update(fakehost.venv(f"{SITE}/.venv"))
    responses.update(fakehost.deb_installed("python3", "python3-venv", "sqlite3", "rsync"))
    for unit in ("archive.service", "archive-metadata-worker.service", "traefik.service"):
        responses.update(fakehost.service(unit))
    responses[ADMIN_PROBE] = [
        "3 objects imported automatically (use -v 2 for details).",
        admin_line(secrets["admin_username"], secrets.get("admin_email", ""), secrets["admin_password"]),
    ]
    responses[MINIO_PROBE] = ["ok"]
    responses[MEDIA_PROBE] = ["archive_media_already_migrated"]
    responses["echo installed"] = ["installed"]
    responses[ECHOPORT_PROBE] = ["unchanged"]
    return responses


def deploy(
    cfg: ArchiveConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_archive, cfg, secrets, rsync=rsync or RecordingRsyncRunner(), responses=responses or fakehost.LINUX
    )
    assert run.succeeded, run.error
    return run


def changed_names(run: FakeRun) -> set[str]:
    return {name.removeprefix("Deploy archive | ") for name in run.mutating_changed_ops}


def test_first_run_installs_everything(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    commands = run.executed_commands
    assert "useradd -d /home/archive -s /bin/bash -g archive -r -M archive" in commands
    assert UV_SYNC in commands
    migrate = next(c for c in commands if "manage.py migrate --noinput" in c)
    collect = next(c for c in commands if "manage.py collectstatic --noinput" in c)
    admin = next(c for c in commands if "ensure_admin_user" in c)
    start = commands.index("systemctl start archive.service")
    assert commands.index(UV_SYNC) < commands.index(migrate) < commands.index(collect) < commands.index(admin) < start
    assert start < commands.index("systemctl start archive-metadata-worker.service")
    assert "systemctl restart archive.service" not in commands
    # Like the role: python manage.py in src/django with .env.shell, as the service user.
    assert migrate.startswith(f"cd {SITE}/src/django && runuser -u archive -- ")
    assert f". {SITE}/.env.shell" in migrate
    assert f"exec {SITE}/.venv/bin/python manage.py migrate" in migrate
    # Env files and admin credentials only travel on stdin.
    stdin = dict(run.stdin)
    assert len(stdin) == 3
    assert stdin[admin] == (
        f"{SECRET_VALUES['admin_username']}\n{SECRET_VALUES['admin_email']}\n{SECRET_VALUES['admin_password']}\n"
    )
    assert not any(path.endswith((".env", ".env.shell")) for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    # Filesystem storage, no MinIO or Echoport configured.
    assert not any("minio" in c or "echoport" in c.lower() for c in commands)


def test_second_run_changes_nothing_mutating(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []


def test_s3_second_run_changes_nothing_mutating(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.stdin == []
    # The probes ran, read-only, with no secret on their command lines.
    facts = "\n".join(run.fact_commands)
    for probe in (MINIO_PROBE, MEDIA_PROBE, ECHOPORT_PROBE, ADMIN_PROBE):
        assert probe in facts


def test_code_change_syncs_deps_migrates_and_restarts(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    assert changed_names(run) == {
        "Sync archive source",
        "uv sync /home/archive/site",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart archive.service",
        "Restart archive-metadata-worker.service",
    }
    argv = next(a for a in rsync.calls if "--dry-run" not in a)
    assert "--delete" in argv
    assert "--chown=archive:archive" in argv
    for exclude in ("db.sqlite3*", "archive-media/", "staticfiles/", ".env", "/.env.shell", ".venv"):
        assert f"--exclude={exclude}" in argv


def test_secret_rotation_rewrites_env_and_restarts(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    rotated = values(cfg, django_secret_key="archive-fixture-django-key-rotated-0123")
    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert changed_names(run) == {
        "Write .env",
        "Write .env.shell",
        "manage.py migrate --noinput",
        "manage.py collectstatic --noinput",
        "Restart archive.service",
        "Restart archive-metadata-worker.service",
    }


def test_admin_password_rotation_only_updates_the_admin(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, values(cfg, admin_password="archive-fixture-new-password"), converged(cfg, secrets))

    assert changed_names(run) == {"Ensure archive admin user"}


def test_worker_unit_change_reloads_and_restarts_only_the_worker(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{UNITS["archive-metadata-worker"]: "[Unit]\n"}))

    assert changed_names(run) == {
        "Install systemd unit archive-metadata-worker.service",
        "Reload systemd for archive-metadata-worker.service",
        "Restart archive-metadata-worker.service",
    }


def test_route_drift_restarts_traefik_only(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert changed_names(run) == {"Write Traefik route archive", "Restart Traefik for archive"}


def test_retired_classifier_units_are_removed(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), RETIRED_PROBE: ["/etc/systemd/system/archive-quote-classifier.timer"]}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {"Remove retired archive quote classifier units"}
    assert any(c.startswith("systemctl disable --now archive-quote-classifier.timer") for c in run.executed_commands)


@pytest.mark.parametrize("verdict", ["bootstrap:bucket", "bootstrap:policy-mismatch", ""])
def test_minio_bootstrap_runs_when_the_probe_disagrees(tmp_path: Path, verdict: str) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), MINIO_PROBE: [verdict] if verdict else []})

    assert changed_names(run) == {"Ensure MinIO media bucket and service account"}
    command, stdin = run.stdin[0]
    assert "minio-bootstrap /usr/local/bin/mc http://127.0.0.1:9001 archive-media archive-media-rw" in command
    assert stdin == (
        f"{S3_SECRETS['minio_root_user']}\n{S3_SECRETS['minio_root_password']}\n"
        f"archive-media\n{S3_SECRETS['media_storage_secret_access_key']}\n"
    )


def test_new_app_credentials_rerun_the_minio_bootstrap(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    rotated = values(cfg, media_storage_secret_access_key="archive-fixture-s3-secret-rotated")
    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert "Ensure MinIO media bucket and service account" in changed_names(run)
    names = [op.name for op in run.ops]
    assert names.index("Deploy archive | Write .env") < names.index(
        "Deploy archive | Ensure MinIO media bucket and service account"
    )


def test_pending_local_media_is_mirrored_into_minio(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), MEDIA_PROBE: ["archive_media_pending"]})

    assert changed_names(run) == {"Migrate local archive-media into MinIO"}
    command, stdin = run.stdin[0]
    assert command.endswith(f"media-migrate /usr/local/bin/mc http://127.0.0.1:9001 archive-media {SITE}/archive-media")
    assert stdin == f"archive-media\n{S3_SECRETS['media_storage_secret_access_key']}\n"


def test_echoport_target_is_upserted_when_pending(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), ECHOPORT_PROBE: ["pending"]})

    assert changed_names(run) == {"Upsert Echoport backup target archive"}
    upsert = run.executed_commands[-1]
    assert upsert.startswith(
        "cd /home/echoport/site && runuser -u echoport -- env HOME=/home/echoport 'ARCHIVE_ECHOPORT="
    )
    for fragment in ('"apply":true', '"schedule":"40 2 * * *"', '"update_schedule":false'):
        assert fragment in upsert


def test_missing_echoport_fails_the_deploy(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    responses: dict[Any, Any] = {**converged(cfg, secrets), "echo installed": [], ECHOPORT_PROBE: []}
    responses[re.compile(r"^test -f /home/echoport/site/manage.py \|\|")] = {"success": False}
    run = run_deploy_fake(deploy_archive, cfg, secrets, rsync=RecordingRsyncRunner(), responses=responses)

    assert not run.succeeded
    failed = [op.name for op in run.ops if not op.succeeded]
    assert failed[0] == "Deploy archive | Require Echoport for the archive backup target"
    assert not any('"apply":true' in command for command in run.executed_commands)


def test_settings_from_the_secrets_file_override_the_config(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg, media_storage_bucket_name="other-bucket", summary_model="gpt-5-mini")
    resolved = resolve(cfg, secrets)
    env = render_env(resolved, secrets, shell=False).reveal().decode()

    assert "ARCHIVE_MEDIA_STORAGE_BUCKET_NAME=other-bucket\n" in env
    assert "ARCHIVE_SUMMARY_MODEL=gpt-5-mini\n" in env
    # Transcription falls back to the summary key and base, as in the playbook.
    assert f"ARCHIVE_TRANSCRIPTION_API_KEY={SECRET_VALUES['summary_api_key']}\n" in env
    assert "ARCHIVE_TRANSCRIPTION_API_BASE=https://api.openai.com/v1\n" in env


def test_secrets_never_recorded(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    secrets = values(cfg)
    responses = {
        **fakehost.LINUX,
        MINIO_PROBE: ["bootstrap:no-app-env"],
        MEDIA_PROBE: ["archive_media_pending"],
        "echo installed": ["installed"],
        ECHOPORT_PROBE: ["pending"],
    }
    run = deploy(cfg, secrets, responses, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}))

    text = run.all_text()
    for key, value in {**SECRET_VALUES, **S3_SECRETS}.items():
        if key != "admin_email":
            assert value not in text, key
    assert not any(value in "\n".join(run.executed_commands) for value in S3_SECRETS.values())


def test_weak_or_placeholder_secrets_are_refused(cfg: ArchiveConfig) -> None:
    for change in ({"api_token": "short"}, {"admin_password": "CHANGEME"}, {"django_secret_key": "x\ny" * 20}):
        with pytest.raises(ValueError, match=r"single lines|too short or placeholders"):
            run_deploy_fake(deploy_archive, cfg, values(cfg, **change), rsync=RecordingRsyncRunner())


def test_s3_needs_its_settings_and_minio_credentials(tmp_path: Path) -> None:
    cfg = s3_cfg(tmp_path)
    with pytest.raises(ValueError, match="media_storage_secret_access_key"):
        resolve(cfg, values(cfg, media_storage_secret_access_key=""))
    assert cfg.secrets is not None
    with pytest.raises(KeyError):
        resolve(cfg, SecretValues(cfg.secrets, {**SECRET_VALUES, "media_storage_secret_access_key": "x" * 30}))
    with pytest.raises(ValueError, match="media_storage_bucket_name"):
        resolve(make_cfg(tmp_path / "b", media_storage_backend="storages.backends.s3.S3Storage"), values(cfg))


def test_config_rejects_bad_values(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError):
        ArchiveConfig(source_path=tmp_path)
    with pytest.raises(ConfigValidationError):
        make_cfg(tmp_path, summary_model="gpt 4")
    with pytest.raises(ConfigValidationError):
        make_cfg(tmp_path / "c", media_storage_backend="other.Storage")


def test_admin_current() -> None:
    line = admin_line("admin", "a@example.invalid", "pw")
    assert admin_current(line, "admin", "a@example.invalid", "pw")
    assert not admin_current(line, "admin", "a@example.invalid", "other")
    assert not admin_current(line, "admin", "b@example.invalid", "pw")
    assert not admin_current(line, "root", "a@example.invalid", "pw")
    assert not admin_current(
        admin_line("admin", "a@example.invalid", "pw", flags="10"), "admin", "a@example.invalid", "pw"
    )
    other_hasher = f"{digest('admin')} {digest('')} 11 argon2$argon2id$v=19 {digest('x')}"
    assert not admin_current(other_hasher, "admin", "", "pw")
    assert not admin_current("", "admin", "", "pw")


def test_media_inside_the_site_survives_delete(tmp_path: Path) -> None:
    cfg = make_cfg(tmp_path, media_storage_location=f"{SITE}/uploads")
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})
    deploy(cfg, values(cfg), rsync=rsync)

    assert all("--exclude=/uploads/" in argv for argv in rsync.calls)


def test_python_version_change_resyncs_dependencies(cfg: ArchiveConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), "sys.version_info": ["3.11"]}
    run = deploy(cfg, secrets, responses)

    assert "uv sync /home/archive/site" in changed_names(run)
    assert "Restart archive.service" in changed_names(run)


def test_mc_never_gets_credentials_as_arguments() -> None:
    from ops_deploy.services.archive.deploy import MEDIA_MIGRATE, MINIO_BOOTSTRAP, MINIO_PROBE

    for script in (MINIO_BOOTSTRAP, MINIO_PROBE, MEDIA_MIGRATE):
        assert "alias set" not in script
        assert '"$app_secret" >' not in script
        # The URL-encoding helper gets the credentials through its environment.
        assert 'MC_USER="$2" MC_SECRET="$3" python3 -c' in script


def test_media_location_must_be_a_literal_path(tmp_path: Path) -> None:
    for location in ("/home/archive/site/uploads[1]", "/home/archive/site/uploads/../uploads", "/srv//media", "/srv/"):
        with pytest.raises(ConfigValidationError):
            make_cfg(tmp_path / str(abs(hash(location))), media_storage_location=location)


def test_venv_version_is_probed_as_the_service_user(cfg: ArchiveConfig) -> None:
    run = deploy(cfg, values(cfg))
    probe = next(c for c in run.fact_commands if "sys.version_info" in c)
    assert f"; then cd {SITE} && runuser -u archive -- " in probe
