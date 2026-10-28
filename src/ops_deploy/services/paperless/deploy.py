"""Paperless 3.2.1 composition, prepared for owned native qualification."""

from __future__ import annotations

import hmac
import re
import shlex
from io import StringIO
from pathlib import PurePosixPath

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import Directory, File
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux
from ops_deploy.base.uv_install import UvInstallConfig, deploy_uv_install
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import http_check, mark_read_only, postgres_database, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.python_security import verify_trust
from ops_deploy.infra.postgres_install import PostgresInstallConfig, deploy_postgres_install
from ops_deploy.infra.redis_install import RedisInstallConfig, deploy_redis_install
from ops_deploy.ops import secret_file

from . import assets, django, layout, operations, python_runtime, scanner
from .config import RELEASE_SHA256, PaperlessConfig, PaperlessCredentials, validate_credentials
from .render import render

PACKAGES = (
    "python3-setuptools",
    "python3-psycopg2",
    "python3-dev",
    "python3-passlib",
    "build-essential",
    "pkg-config",
    "imagemagick",
    "unpaper",
    "ghostscript",
    "icc-profiles-free",
    "qpdf",
    "libleptonica-dev",
    "libmagic-dev",
    "libpoppler-cpp-dev",
    "libxml2-dev",
    "libxslt1-dev",
    "libffi-dev",
    "tesseract-ocr",
    "tesseract-ocr-eng",
    "tesseract-ocr-deu",
    "tesseract-ocr-fra",
    "tesseract-ocr-ita",
    "tesseract-ocr-spa",
    "poppler-utils",
    "antiword",
    "unrtf",
    "libimage-exiftool-perl",
    "p7zip-full",
    "unrar",
    "gnupg",
    "libssl-dev",
    "libcurl4-openssl-dev",
    "libjpeg-dev",
    "libopenjp2-7-dev",
    "libtiff-dev",
    "libtiff6",
    "zlib1g-dev",
    "libfreetype6-dev",
    "liblcms2-dev",
    "libwebp-dev",
    "libharfbuzz-dev",
    "libfribidi-dev",
    "libxcb1-dev",
    "tzdata",
    "fonts-liberation",
    "acl",
)


def version_packages() -> tuple[str, ...]:
    command = shlex.join(["sh", "-c", '. /etc/os-release; printf "%s\\n" "$VERSION_ID"'])
    version = probe(command, name="Paperless distribution package selection")
    if version is None or not re.fullmatch(r"\d+(?:\.\d+)*", version):
        raise DeployError("Paperless distribution version is unknown")
    parts = tuple(int(item) for item in version.split("."))
    return ("libleptonica6",) if parts >= (25, 4) else ()


def dependency_configs(
    cfg: PaperlessConfig,
    credentials: PaperlessCredentials,
    postgres: PostgresInstallConfig | None,
    redis: RedisInstallConfig | None,
    shared_redis_password: SecretStr | None,
) -> tuple[PostgresInstallConfig, RedisInstallConfig]:
    validate_credentials(cfg, credentials)
    pg = postgres or PostgresInstallConfig(version="17", port=cfg.postgres_port)
    rd = redis or RedisInstallConfig(
        bind_addresses=("127.0.0.1",), port=cfg.redis_port, requirepass_enabled=cfg.redis_requirepass_enabled
    )
    if pg.version != "17" or pg.port != cfg.postgres_port:
        raise ValueError("Paperless PostgreSQL dependency must match version17 and application port")
    if rd.port != cfg.redis_port or rd.requirepass_enabled != cfg.redis_requirepass_enabled:
        raise ValueError("Paperless Redis dependency must match application authentication and port")
    if shared_redis_password is not None and not hmac.compare_digest(
        credentials.redis_password.get_secret_value().encode(), shared_redis_password.get_secret_value().encode()
    ):
        raise ValueError("Paperless and the declared shared Redis credentials differ")
    return pg, rd


@deploy("Paperless")
def deploy_paperless(
    cfg: PaperlessConfig,
    credentials: PaperlessCredentials,
    postgres: PostgresInstallConfig | None = None,
    redis: RedisInstallConfig | None = None,
    shared_redis_password: SecretStr | None = None,
) -> None:
    """Original dependency order, conditional app recovery and D2 index admission.

    The private caller supplies the independently declared shared Redis password
    when the instance is shared; inequality refuses before any operation. This
    public argument contains no inventory lookup or credential discovery.
    """
    try:
        pg, rd = dependency_configs(cfg, credentials, postgres, redis, shared_redis_password)
    except ValueError as error:
        raise DeployError(str(error)) from None
    require_linux("paperless")
    layout.require_storage(cfg)
    python = PurePosixPath(cfg.site_root) / ".venv/bin/python"
    home = PurePosixPath(cfg.home_path)
    # pyinfra File returns False for an existing symlink (the normal uv
    # interpreter), None only when absent. Existing links/non-files must not
    # skip the original preflight before dependency writes.
    if cfg.python_security_floor_enabled and host.get_fact(File, path=str(python)) is not None:
        verify_trust(python, user=cfg.username, home=home, name="Paperless environment before dependency changes")
    uv_missing = not host.get_fact(File, path="/usr/local/bin/uv")
    deploy_uv_install(cfg=UvInstallConfig())
    deploy_redis_install(cfg=rd, password=credentials.redis_password)
    deploy_postgres_install(cfg=pg)
    database = postgres_database(
        cfg.postgres_database,
        owner=cfg.postgres_user,
        password=credentials.postgres_password,
        admin_user=pg.admin_user,
        service=pg.service_name,
        port=pg.port,
        enabled=pg.service_enabled,
    )
    apt.packages(name="Install Paperless prerequisite packages", packages=[*PACKAGES, *version_packages()])
    user = layout.account(cfg)
    new_layout = user.will_change or not host.get_fact(Directory, path=cfg.site_root)
    layout.directories(cfg)
    scanner.configure_scanner(cfg, credentials)
    venv = python_runtime.ensure_venv(
        name="Ensure Paperless Python3.14 environment", cfg=cfg, deferred=user.will_change
    )
    assets.python_assets(
        name="Converge Paperless venv ownership", cfg=cfg, action="ownership", deferred=venv.will_change
    )
    if cfg.create_venv_symlink:
        layout.link(cfg, f"{cfg.site_root}/venv", f"{cfg.site_root}/.venv")
    if cfg.python_security_floor_enabled:
        files.put(
            name="Write Paperless Python security constraints",
            src=StringIO(python_runtime.constraints_text()),
            dest=f"{cfg.site_root}/.python-security-constraints.txt",
            user=cfg.username,
            group=cfg.group,
            mode="0644",
        )
    archive = f"paperless-ngx-v{cfg.version}.tar.xz"
    files.download(
        name="Download checksum-bound Paperless release",
        src=f"https://github.com/paperless-ngx/paperless-ngx/releases/download/v{cfg.version}/{archive}",
        dest=f"{cfg.site_root}/{archive}",
        sha256sum=RELEASE_SHA256,
        user=cfg.username,
        group=cfg.group,
        mode="0644",
    )
    release = operations.release(name="Converge Paperless release and current link", cfg=cfg, deferred=new_layout)
    packages = python_runtime.install_packages(
        name="Repair Paperless editable application and dependencies",
        cfg=cfg,
        deferred=uv_missing or venv.will_change or release.will_change,
    )
    python_changes = [venv, release, packages]
    if cfg.patch_ocrmypdf_missing_check:
        patch = assets.python_assets(
            name="Apply original OCR compatibility patch", cfg=cfg, action="ocr", deferred=packages.will_change
        )
    else:
        patch = None
    assets.nltk(cfg)
    assets.install_marker(cfg)
    if cfg.python_security_floor_enabled:
        verify_trust(python, user=cfg.username, home=home, name="Paperless installed environment")
    env = secret_file(
        name="Write Paperless environment",
        path=f"{cfg.site_root}/.env",
        content=SecretContent(render("paperless.env.j2", cfg, credentials)),
        user=cfg.username,
        group=cfg.group,
        mode="0600",
    )
    gunicorn = files.put(
        name="Write Paperless gunicorn configuration",
        src=StringIO(render("gunicorn.conf.py.j2", cfg, credentials)),
        dest=f"{cfg.site_root}/gunicorn.conf.py",
        user=cfg.username,
        group=cfg.group,
        mode="0644",
    )
    deferred = (
        env.will_change
        or database.role.will_change
        or database.database.will_change
        or any(meta.will_change for meta in python_changes)
    )
    migrations = django.migrate(name="Apply pending Paperless migrations", cfg=cfg, deferred=deferred)
    django.ensure_admin(
        name="Converge declared Paperless account flags",
        cfg=cfg,
        payload=django.admin_payload(cfg, credentials),
        deferred=deferred or migrations.will_change,
    )
    django.collect_static(
        name="Converge Paperless static program assets", cfg=cfg, changes=[*python_changes, env], deferred=deferred
    )
    assets.apparmor(cfg)
    units = [
        systemd_unit(unit, render(template, cfg, credentials))
        for unit, template in zip(
            cfg.units,
            (
                "paperless.service.j2",
                "paperless-worker.service.j2",
                "paperless-scheduler.service.j2",
                "paperless-consumer.service.j2",
            ),
            strict=True,
        )
    ]
    # Reindex stops/resumes the declared units; load newly published unit files
    # before that managed step. Do not start inactive units merely to stop them.
    systemd.daemon_reload(name="Load changed Paperless units before reindex", _if=any_changed(*units))
    operations.rebuild_index(
        name="Converge Paperless search index",
        cfg=cfg,
        changes=[("release", release), ("packages", packages), ("migrations", migrations)],
        deferred=deferred or migrations.will_change,
    )
    for index, unit in enumerate(cfg.units):
        # Original migrations/static collection do not notify a restart.
        # Release/package changes already trigger the application rollout.
        triggers = [*python_changes, env, units[index]]
        if index == 0:
            triggers.append(gunicorn)
        if patch is not None and index in {1, 3}:
            triggers.append(patch)
        service_rollout(unit, restart_when=triggers)
        script = (
            f"for i in 1 2 3 4 5; do systemctl is-active --quiet {shlex.quote(unit)} && exit 0; sleep 3; done; exit 1"
        )
        mark_read_only(server.shell(name=f"Verify Paperless unit {unit}", commands=[shlex.join(["sh", "-c", script])]))
    if cfg.traefik_enabled:
        files.directory(
            name="Ensure Traefik dynamic directory", path="/etc/traefik/dynamic", user="root", group="root", mode="0755"
        )
        files.put(
            name="Write Paperless Traefik route",
            src=StringIO(render("paperless.traefik.yml.j2", cfg, credentials)),
            dest="/etc/traefik/dynamic/paperless.yml",
            user="root",
            group="root",
            mode="0644",
        )
    http_check(f"http://127.0.0.1:{cfg.app_port}/api/", status=200, retries=10, delay=6, timeout=10)
