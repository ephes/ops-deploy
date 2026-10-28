"""Synthetic application assertions for the owned Paperless native fixture."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ops_deploy.services.paperless.index_contract import expected_index_sentinels


def query(harness: Any, expression: str) -> Any:
    result = harness.app("import json\nfrom documents.models import Document\nprint(json.dumps(" + expression + "))\n")
    return json.loads(result.stdout)


def wait_count(harness: Any, expected: int) -> None:
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if harness.count() == expected:
            return
        time.sleep(3)
    raise RuntimeError("synthetic ingestion did not reach the declared aggregate")


def sftp_ocr(harness: Any) -> None:
    # Create an image-only PDF. Its pixels/text are synthetic and are never
    # accepted as evidence of physical scanner, personal-data or hardware use.
    pdf = Path("/tmp/paperless-owned-ocr.pdf")
    assert not pdf.exists()
    program = """from PIL import Image,ImageDraw,ImageFont
from pathlib import Path
image=Image.new('RGB',(1800,800),'white')
draw=ImageDraw.Draw(image)
font=ImageFont.truetype(str(next(Path('/usr/share/fonts').rglob('LiberationSans-Regular.ttf'))),70)
draw.text((100,160),'PAPERLESS OWNED QUARTZ FIXTURE',fill='black',font=font)
draw.text((100,300),'Synthetic application qualification only',fill='black',font=font)
image.save('/tmp/paperless-owned-ocr.pdf','PDF',resolution=150)
"""
    harness.command(harness.CFG.site_root + "/.venv/bin/python", "-c", program)
    pdf.chmod(0o644)
    before = harness.count()
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (harness.CREDS.scanner_password.get_secret_value() + "\n").encode())
        os.close(write_fd)
        write_fd = -1
        args = [
            "sshpass",
            "-d",
            str(read_fd),
            "sftp",
            "-o",
            "BatchMode=no",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-b",
            "-",
            harness.CFG.scanner_username + "@127.0.0.1",
        ]
        result = subprocess.run(
            args,
            input=f"put {pdf} /inbox/owned-quartz.pdf\n",
            text=True,
            capture_output=True,
            timeout=60,
            pass_fds=(read_fd,),
            check=False,
        )
        assert result.returncode == 0, "owned SFTP upload failed; output withheld"
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
        pdf.unlink()
    wait_count(harness, before + 1)
    observed = query(
        harness,
        "{'count':Document.objects.count(), 'ocr_match':Document.objects.filter(content__icontains='QUARTZ').exists()}",
    )
    assert observed == {"count": before + 1, "ocr_match": True}
    credentials = urllib.parse.urlencode(
        {"username": harness.CFG.admin_user, "password": harness.CREDS.admin_password.get_secret_value()}
    ).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{harness.CFG.app_port}/api/token/", data=credentials)
    with urllib.request.urlopen(request, timeout=15) as response:
        token = json.loads(response.read(65536))["token"]
    request = urllib.request.Request(
        f"http://127.0.0.1:{harness.CFG.app_port}/api/documents/?query=QUARTZ",
        headers={"Authorization": "Token " + token},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read(1024 * 1024))
    assert result["count"] >= 1
    harness.write(
        "synthetic-sftp-ocr-search.json",
        {
            "sftp_exit": 0,
            "document_count": before + 1,
            "ocr_match": True,
            "authenticated_search_match": True,
            "scope": "synthetic application path; no physical scanner proof",
        },
    )


def schema_and_soft_delete(harness: Any) -> None:
    program = """import json
from django.conf import settings
from documents.models import Document
from documents.search._schema import SCHEMA_VERSION,schema_fingerprint
print(json.dumps({'manager_count':Document.objects.count(),
 'table':Document._meta.db_table,'soft_delete_column':Document._meta.get_field('deleted_at').column,
 'schema_version':SCHEMA_VERSION,'schema_fingerprint':schema_fingerprint(),
 'index_path':str(settings.INDEX_DIR)}))
"""
    result = json.loads(harness.app(program).stdout)
    expected = expected_index_sentinels(harness.CFG.version, harness.CFG.ocr_language)
    assert result["table"] == "documents_document"
    assert result["soft_delete_column"] == "deleted_at"
    assert result["manager_count"] == harness.count()
    assert result["schema_version"] == expected["schema_version"]
    assert result["schema_fingerprint"] == expected["schema_fingerprint"]
    assert result["index_path"] == harness.CFG.external_storage_root + "/data/index"
    harness.write("actual-application-schema.json", result)
    # This is an explicitly managed synthetic test mutation. Never use a real
    # document selector; this fixture has only the one generated owned PDF.
    result = json.loads(
        harness.app("""import json
from documents.models import Document
assert Document.objects.count()==1
document=Document.objects.get()
document.delete()
print(json.dumps({'manager_count':Document.objects.count()}))
""").stdout
    )
    assert result["manager_count"] == 0
    assert harness.count() == 0
    sql = "SELECT count(*) FROM public.documents_document WHERE deleted_at IS NOT NULL;"
    actual = harness.command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-XAtq",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        harness.CFG.postgres_database,
        "-c",
        sql,
    ).stdout.strip()
    assert actual == "1"
    harness.write(
        "actual-soft-delete-count.json",
        {"manager_count": 0, "readonly_sql_live_count": 0, "soft_deleted_synthetic_rows": 1},
    )


def index_faults(harness: Any) -> None:
    root = Path(harness.CFG.external_storage_root) / "data/index"
    settings_path = root / ".index_settings.json"
    original = json.loads(settings_path.read_text())
    cases = {
        "language": {**original, "language": "owned-wrong-language"},
        "schema": {**original, "schema_fingerprint": "owned-wrong-schema"},
    }
    for label, sentinel in cases.items():
        settings_path.write_text(json.dumps(sentinel))
        result = harness.deploy("index-" + label)
        assert any("Converge Paperless search index" in name for name in result["managed"])
        harness.deploy("index-" + label + "-repeat", zero=True)
    settings_path.unlink()
    result = harness.deploy("index-missing-sentinel")
    assert any("Converge Paperless search index" in name for name in result["managed"])
    harness.deploy("index-missing-sentinel-repeat", zero=True)
    settings_path.write_text("[" * 10000)
    result = harness.deploy("index-malformed")
    assert any("Converge Paperless search index" in name for name in result["managed"])
    harness.deploy("index-malformed-repeat", zero=True)
    result = harness.deploy("index-explicit-force", cfg=harness.CFG.model_copy(update={"force_reindex": True}))
    assert any("Converge Paperless search index" in name for name in result["managed"])
    harness.deploy("index-force-repeat", zero=True)


def empty_current_index(harness: Any) -> None:
    assert harness.count() == 1
    # Deliberate owned fault setup uses the upstream writer/opener. This is
    # not the deployment's readonly metadata admission and is labelled managed.
    harness.app("""import json
from django.conf import settings
from documents.search._schema import wipe_index,open_or_rebuild_index
wipe_index(settings.INDEX_DIR)
index=open_or_rebuild_index(settings.INDEX_DIR)
print(json.dumps({'fixture_empty_index':index.searcher().num_docs==0}))
""")
    result = harness.deploy("index-empty-with-current-sentinels")
    assert any("Converge Paperless search index" in name for name in result["managed"])
    harness.deploy("index-empty-repaired-repeat", zero=True)


def reindex_failure_and_retry(harness: Any) -> None:
    manage = Path(harness.CFG.site_root) / f"paperless-ngx-v{harness.CFG.version}/src/manage.py"
    original = manage.read_bytes()
    metadata = manage.stat()
    marker = Path(harness.CFG.site_root) / "owned-reindex-fault-reached"
    assert not marker.exists()
    # The source edit is a named synthetic fixture fault, preserved in raw
    # snapshots. Non-index management calls still execute the original bytes.
    wrapper = (
        "import sys\nfrom pathlib import Path\n"
        "if sys.argv[1:3] == ['document_index','reindex']:\n"
        f"    Path({str(marker)!r}).write_text('owned fault reached')\n"
        "    raise SystemExit(23)\n"
        f"exec(compile({original!r}, __file__, 'exec'))\n"
    )
    manage.write_text(wrapper)
    harness.command("systemctl", "stop", harness.CFG.service_name + "-scheduler")
    before = {
        unit: harness.command("systemctl", "is-active", unit, check=False).stdout.strip() for unit in harness.CFG.units
    }
    assert before[harness.CFG.service_name + "-scheduler"] == "inactive"
    try:
        result = harness.deploy(
            "index-injected-failure", cfg=harness.CFG.model_copy(update={"force_reindex": True}), failure=True
        )
        assert marker.read_text() == "owned fault reached"
        after = {
            unit: harness.command("systemctl", "is-active", unit, check=False).stdout.strip()
            for unit in harness.CFG.units
        }
        assert before == after
        harness.write(
            "index-failure-resumption.json",
            {
                "actual_fault_reached": True,
                "prior_states": before,
                "after_states": after,
                "failed_operations": result["failed_operations"],
                "source_fault_restored_after_this_receipt": True,
            },
        )
    finally:
        # Restoration is explicit fixture teardown after the failure proof,
        # not a hidden service repair or part of the claimed deployment result.
        manage.write_bytes(original)
        manage.chmod(metadata.st_mode & 0o777)
        os.chown(manage, metadata.st_uid, metadata.st_gid)
        marker.unlink(missing_ok=True)
    harness.deploy("index-ordinary-retry", cfg=harness.CFG.model_copy(update={"force_reindex": True}))
    harness.deploy("index-retry-repeat", zero=True)


def static_and_marker_recovery(harness: Any) -> None:
    static = Path(harness.CFG.site_root) / "staticfiles/admin/css/base.css"
    assert static.is_file()
    pids = {
        unit: harness.command("systemctl", "show", unit, "-p", "MainPID", "--value").stdout
        for unit in harness.CFG.units
    }
    static.unlink()
    result = harness.deploy("static-missing-recovery")
    assert any("Converge Paperless static program assets" in name for name in result["managed"])
    assert all(
        harness.command("systemctl", "show", unit, "-p", "MainPID", "--value").stdout == pid
        for unit, pid in pids.items()
    ), "static repair must retain original no-restart semantics"
    harness.deploy("static-repair-repeat", zero=True)
    marker = Path(harness.CFG.site_root) / f".paperless-installed-{harness.CFG.version}"
    marker.unlink()
    result = harness.deploy("marker-missing-recovery")
    assert len(result["managed"]) == 1
    assert "Record installed Paperless release" in result["managed"][0]
    harness.deploy("marker-repair-repeat", zero=True)


def pending_migration(harness: Any) -> None:
    name = "9999_owned_qualification"
    path = Path(harness.CFG.site_root) / f"paperless-ngx-v{harness.CFG.version}/src/documents/migrations/{name}.py"
    assert not path.exists()
    setup = f"""import json
from pathlib import Path
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder
loader=MigrationLoader(connection)
leaves=loader.graph.leaf_nodes('documents')
assert len(leaves)==1
assert ('documents',{name!r}) not in MigrationRecorder(connection).applied_migrations()
source=('from django.db import migrations\\nclass Migration(migrations.Migration):\\n'
        '    dependencies='+repr(leaves)+'\\n'
        '    operations=[migrations.RunSQL(\"SELECT 1;\",reverse_sql=migrations.RunSQL.noop)]\\n')
Path({str(path)!r}).write_text(source)
print(json.dumps({{'owned_pending_migration_created':True}}))
"""
    assert json.loads(harness.app(setup).stdout) == {"owned_pending_migration_created": True}
    result = harness.deploy("pending-owned-migration")
    assert any("Apply pending Paperless migrations" in label for label in result["managed"])
    assert any("Converge Paperless search index" in label for label in result["managed"])
    harness.deploy("pending-migration-repeat", zero=True)
    # Exact owned no-op migration cleanup, not a rollback of any real schema or
    # a production document mutation. Preserve successful proof first.
    cleanup = f"""import json
from pathlib import Path
from django.db import connection
from django.db.migrations.recorder import MigrationRecorder
MigrationRecorder(connection).record_unapplied('documents',{name!r})
Path({str(path)!r}).unlink()
print(json.dumps({{'owned_migration_cleanup':True}}))
"""
    assert json.loads(harness.app(cleanup).stdout) == {"owned_migration_cleanup": True}
    harness.write(
        "owned-migration-cleanup.json",
        {"only_synthetic_noop_migration_removed": True, "actual_application_migrations_untouched": True},
    )
    harness.deploy("pending-migration-cleanup-repeat", zero=True)


def missing_entire_index(harness: Any) -> None:
    """Real owned absent-path fault, exact old-helper failure, normal recovery."""
    from ops_deploy.services.paperless.commands import reindex_payload

    assert harness.OWNED_ADMITTED is True
    index = Path(harness.CFG.external_storage_root) / "data/index"
    assert index.is_dir()
    assert not index.is_symlink()
    assert index.parent.resolve(strict=True) == index.parent
    # Stop the four synthetic units to avoid a background application opener
    # creating the leaf before the deployment can demonstrate recovery.
    harness.write(
        "missing-index-fault-started.json",
        {
            "classification": "declared owned fault setup: stop four units and remove entire synthetic index",
            "before": harness.snapshot_receipt("missing-index-fault", "before", harness.snapshot()),
        },
    )
    for unit in harness.CFG.units:
        harness.command("systemctl", "stop", unit + ".service")
    shutil.rmtree(index)
    assert not index.exists()
    before = harness.snapshot()
    before_receipt = harness.snapshot_receipt("missing-index-old-helper", "before", before)
    harness.write("missing-index-old-helper-started.json", {"before": before_receipt})
    previous = "7522da86d56efe2aeeb9dcf46507fda5954cd767"
    resource = "src/ops_deploy/services/paperless/files/reindex.py"
    source = harness.command("git", "-C", "/opt/controller", "show", previous + ":" + resource).stdout
    expected_sha = "9c022648d43c19fe09ed5f8d786bd43868713ab14e1f66b28e19a999adc3455f"
    assert hashlib.sha256(source.encode()).hexdigest() == expected_sha
    payload = json.loads(reindex_payload(harness.CFG))
    del payload["index_dir"]  # Exact previous helper's public input contract.
    result = harness.command("python3", "-I", "-B", "-c", source, stdin=json.dumps(payload), check=False)
    after = harness.snapshot()
    harness.write(
        "missing-index-old-helper.json",
        {
            "classification": "expected owned old execution-helper failure; not a pyinfra operation/no-op claim",
            "source_commit": previous,
            "source_sha256": expected_sha,
            "exit": result.returncode,
            "stdout": harness.sanitize(result.stdout),
            "stderr": harness.sanitize(result.stderr),
            "before": before_receipt,
            "after": harness.snapshot_receipt("missing-index-old-helper", "after", after),
            "private_content_equal": before.private == after.private,
        },
    )
    assert result.returncode == 1
    assert not index.exists()
    assert result.stderr == "Paperless managed reindex failed; inspect service status locally\n"
    assert before.public == after.public
    assert before.private == after.private
    repaired = harness.deploy("index-missing-entire-directory")
    assert any("Converge Paperless search index" in name for name in repaired["managed"])
    owner = pwd.getpwnam(harness.CFG.username)
    info = index.lstat()
    assert index.is_dir()
    assert not index.is_symlink()
    assert info.st_uid == owner.pw_uid
    harness.write(
        "missing-index-recovered.json",
        {
            "uid": info.st_uid,
            "gid": info.st_gid,
            "directory_created": True,
            "scope": "managed reindex plus normal previously stopped service starts",
        },
    )
    harness.deploy("index-missing-entire-directory-repeat", zero=True)
