"""Owned release and Python recovery; every fixture mutation is explicit."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from ops_deploy.services.paperless.commands import host_command
from ops_deploy.services.paperless.operations import as_service


def legacy_current(harness: Any) -> None:
    site = Path(harness.CFG.site_root)
    current = site / "paperless-ngx"
    version = site / f"paperless-ngx-v{harness.CFG.version}"
    assert current.is_symlink()
    current.unlink()
    harness.command("cp", "-a", str(version), str(current))
    assert current.is_dir()
    assert not current.is_symlink()
    result = harness.deploy("legacy-current-directory-recovery")
    assert any("release and current link" in name for name in result["managed"])
    assert current.is_symlink()
    assert current.resolve() == version
    harness.deploy("legacy-current-repeat", zero=True)


def extraction(harness: Any) -> None:
    site = Path(harness.CFG.site_root)
    version = site / f"paperless-ngx-v{harness.CFG.version}"
    archive = site / f"paperless-ngx-v{harness.CFG.version}.tar.xz"
    saved_version, saved_archive = site / ".owned-preserved-release", site / ".owned-preserved-archive"
    assert not saved_version.exists()
    assert not saved_archive.exists()
    version.rename(saved_version)
    archive.rename(saved_archive)
    archive.write_bytes(b"owned truncated archive fault")
    user = saved_archive.stat()
    os.chown(archive, user.st_uid, user.st_gid)
    link = site / "paperless-ngx"
    before = link.lstat()
    result = harness.command(
        "sh",
        "-c",
        as_service(harness.CFG, host_command("release")),
        stdin=json.dumps({"site_root": harness.CFG.site_root, "apply": True}),
        check=False,
    )
    assert result.returncode != 0
    assert not version.exists()
    assert link.is_symlink()
    assert link.lstat().st_ino == before.st_ino
    assert link.lstat().st_ctime_ns == before.st_ctime_ns
    harness.write(
        "truncated-archive-refusal.json",
        {
            "exit": result.returncode,
            "current_link_exact": True,
            "release_not_replaced": True,
            "scope": "direct actual release helper, owned archive fault",
        },
    )
    # Restore only the checksum-bound archive after preserving the failed
    # proof. Normal deployment, not fixture copying, reconstructs the release.
    os.replace(saved_archive, archive)
    version.mkdir()
    os.chown(version, user.st_uid, user.st_gid)
    (version / "owned-incomplete").write_text("incomplete extraction")
    result = harness.deploy("incomplete-release-recovery")
    assert any("release and current link" in name for name in result["managed"])
    assert (version / "src/manage.py").is_file()
    shutil.rmtree(saved_version)
    harness.deploy("incomplete-release-repeat", zero=True)


def missing_venv(harness: Any) -> None:
    root = Path(harness.CFG.site_root) / ".venv"
    saved = root.with_name(".owned-preserved-venv")
    assert not saved.exists()
    root.rename(saved)
    result = harness.deploy("missing-venv-recovery")
    assert any("Python3.14 environment" in name for name in result["managed"])
    assert any("editable application" in name for name in result["managed"])
    shutil.rmtree(saved)
    harness.deploy("missing-venv-repeat", zero=True)


def wrong_python(harness: Any) -> None:
    harness.command(
        "sh",
        "-c",
        as_service(harness.CFG, f"/usr/local/bin/uv venv --clear --python 3.13 {harness.CFG.site_root}/.venv"),
        timeout=300,
    )
    result = harness.deploy("wrong-python-recovery")
    assert any("Python3.14 environment" in name for name in result["managed"])
    assert any("editable application" in name for name in result["managed"])
    actual = harness.command(
        harness.CFG.site_root + "/.venv/bin/python", "-c", "import sys;print(sys.version_info[:2])"
    )
    assert actual.stdout.strip() == "(3, 14)"
    harness.deploy("wrong-python-repeat", zero=True)


def broken_interpreter_refusal(harness: Any) -> None:
    python = Path(harness.CFG.site_root) / ".venv/bin/python"
    assert python.is_symlink()
    target = os.readlink(python)
    metadata = python.lstat()
    python.unlink()
    python.write_text("owned invalid interpreter, not executable Python\n")
    python.chmod(0o755)
    os.chown(python, metadata.st_uid, metadata.st_gid)
    try:
        # Original role also refuses at its first dependency security check.
        assert harness.ansible("original-broken-interpreter", allow_failure=True) != 0
        result = harness.deploy("broken-interpreter-trust-refusal", failure=True)
        assert result["managed"] == []
        assert result["uploads"] == 0
        assert result["before"]["sha256"] == result["after"]["sha256"]
        assert result["private_content_equal"]
    finally:
        # Explicit fixture restoration after the original/pyinfra refusal
        # receipts; not automatic deploy recovery or a production repair.
        python.unlink()
        python.symlink_to(target)
        os.chown(python, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
    harness.deploy("broken-interpreter-restored-repeat", zero=True)


def missing_supporting_package(harness: Any) -> None:
    harness.command(
        "sh",
        "-c",
        as_service(harness.CFG, f"/usr/local/bin/uv pip uninstall --python {harness.CFG.site_root}/.venv whitenoise"),
    )
    result = harness.deploy("missing-supporting-package-recovery")
    assert any("editable application" in name for name in result["managed"])
    harness.deploy("supporting-package-repeat", zero=True)


def ocr_pattern(harness: Any) -> None:
    from ops_deploy.services.paperless.files.python_assets import NEW, OLD

    root = Path(harness.CFG.site_root) / "owned-python-assets"
    assert not root.exists()
    venv = root / ".venv"
    target = venv / "lib/python3.14/site-packages/ocrmypdf/helpers.py"
    target.parent.mkdir(parents=True)
    target.write_text(OLD)
    payload = {
        "venv": str(venv),
        "username": harness.CFG.username,
        "group": harness.CFG.group,
        "action": "ownership",
        "apply": True,
    }
    # This deliberately root-owned synthetic tree exercises actual root→service
    # ownership, then service-user OCR patching. It is not installed app code.
    result = harness.command("sh", "-c", host_command("python_assets"), stdin=json.dumps(payload))
    assert result.stdout.strip() == "changed"
    before = target.stat()
    result = harness.command("sh", "-c", host_command("python_assets"), stdin=json.dumps(payload))
    assert result.stdout.strip() == "current"
    assert target.stat().st_ctime_ns == before.st_ctime_ns
    payload.update(action="ocr")
    result = harness.command(
        "sh", "-c", as_service(harness.CFG, host_command("python_assets")), stdin=json.dumps(payload)
    )
    assert result.stdout.strip() == "changed"
    assert target.read_text() == NEW
    before = target.stat()
    result = harness.command(
        "sh", "-c", as_service(harness.CFG, host_command("python_assets")), stdin=json.dumps(payload)
    )
    assert result.stdout.strip() == "current"
    assert (target.stat().st_ino, target.stat().st_mtime_ns, target.stat().st_ctime_ns) == (
        before.st_ino,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    harness.write(
        "actual-owned-python-assets.json",
        {
            "ownership_first": "changed",
            "ownership_repeat": "current",
            "ocr_first": "changed",
            "ocr_repeat": "current",
            "scope": "actual installed helpers, separate synthetic program tree",
        },
    )
    shutil.rmtree(root)


def shared_redis_refusal(harness: Any) -> None:
    result = harness.deploy("shared-redis-mismatch-refusal", shared_redis_password=harness.value(), failure=True)
    assert not result["operations"]
    assert not result["uploads"]
    assert result["before"]["sha256"] == result["after"]["sha256"]
    assert result["private_content_equal"]
    harness.deploy("shared-redis-current-repeat", zero=True)


def database_password(harness: Any) -> None:
    # Synthetic fixed role only. The credential is protected stdin, never a
    # process argument, environment field, evidence value or persisted file.
    wrong = harness.value().get_secret_value()
    statement = f"ALTER ROLE {harness.CFG.postgres_user} PASSWORD '{wrong}';\n"
    harness.command(
        "runuser", "-u", "postgres", "--", "psql", "-Xq", "-v", "ON_ERROR_STOP=1", "-d", "postgres", stdin=statement
    )
    # Django shell itself may not open the database; force a harmless SELECT.
    failed = harness.app(
        "from django.db import connection\nwith connection.cursor() as c: c.execute('SELECT 1')\n", check=False
    )
    assert failed.returncode != 0
    result = harness.deploy("database-declared-password-recovery")
    assert result["managed"]
    actual = harness.app(
        "from django.db import connection\n"
        "with connection.cursor() as c: c.execute('SELECT 1'); print(c.fetchone()[0])\n"
    )
    assert actual.stdout.strip() == "1"
    harness.write(
        "database-password-recovery.json",
        {
            "wrong_password_authentication_failed": True,
            "declared_password_restored": True,
            "scope": "one synthetic declared role; no application row changes",
        },
    )
    harness.deploy("database-password-repeat", zero=True)
