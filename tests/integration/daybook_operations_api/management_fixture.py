"""Real management/database contract in a disposable root Linux container."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import shlex
import subprocess
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

import ops_deploy
from ops_deploy.ops.sync_tree import rsync_argv
from ops_deploy.services.daybook_operations_api import OperationsApiConfig, OperationsApiPins, OperationsProfile
from ops_deploy.services.daybook_operations_api.deploy import (
    SOURCE_EXCLUDES,
    management_command,
    management_payload,
    source_ownership_command,
)
from ops_deploy.services.daybook_operations_api.render import render_config, render_unit

DAYBOOK = "45ac5a62fafef66e8c8fb16222362f075b326f7d"
OLD = "ec46a28fbeb33bc4fee924f68e5909832beca28e"
HOME = Path("/home/daybook-operations")
SITE = HOME / "site"
CONF = Path("/etc/daybook-operations")
PG = Path("/tmp/operations-api-postgres")
EVIDENCE = Path("/evidence")
PHASES: list[dict[str, object]] = []


def record(phase: dict[str, object]) -> None:
    PHASES.append(phase)
    (EVIDENCE / "phases.json").write_text(json.dumps(PHASES, indent=2) + "\n")


def package_proof() -> None:
    sha = os.environ["IMPLEMENTATION_SHA"]
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    source = Path(__file__).resolve().parents[3]
    direct = json.loads(importlib.metadata.distribution("ops-deploy").read_text("direct_url.json") or "{}")
    assert direct.get("vcs_info", {}).get("commit_id") == sha
    assert not direct.get("dir_info", {}).get("editable", False)
    installed = Path(ops_deploy.__file__).resolve().parent
    tracked = subprocess.check_output(
        ["git", "-C", str(source), "ls-tree", "-r", "--name-only", sha, "src/ops_deploy/"], text=True
    ).splitlines()
    resources = {}
    for name in tracked:
        member = name.removeprefix("src/ops_deploy/")
        raw = subprocess.check_output(["git", "-C", str(source), "show", sha + ":" + name])
        assert (installed / member).read_bytes() == raw
        assert not (installed / member).is_symlink()
        resources[member] = hashlib.sha256(raw).hexdigest()
    actual = {
        str(path.relative_to(installed))
        for path in installed.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    assert actual == set(resources)
    (EVIDENCE / "installed.json").write_text(
        json.dumps({"implementation": sha, "direct_url": direct, "resources": resources}, indent=2) + "\n"
    )


def command(argv: list[str], *, stdin: bytes | None = None, timeout: int = 600) -> bytes:
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
    if result.returncode:
        # Only owned inputs exist here, but keep the same fixed error boundary.
        raise RuntimeError("owned_fixture_command_failed:" + Path(argv[0]).name)
    return result.stdout


def user(argv: list[str]) -> bytes:
    return command(["/usr/sbin/runuser", "-u", "daybook-operations", "--", *argv])


def application(code: str) -> object:
    shell = (
        "set -a; . /etc/daybook-operations/environment.shell; set +a; "
        "cd /home/daybook-operations/site/services/operations_api; "
        "exec /home/daybook-operations/venv/bin/python -c "
        + shlex.quote(
            "import os;os.environ['DJANGO_SETTINGS_MODULE']='operations_api.settings';"
            "import django;django.setup();" + code
        )
    )
    return json.loads(user(["/bin/sh", "-c", shell]))


def projection() -> object:
    return application(
        "import json;from coordination.models import Principal,Credential,Binding;"
        "print(json.dumps({'principals':list(Principal.objects.order_by('id').values()),"
        "'credentials':list(Credential.objects.order_by('id').values()),"
        "'bindings':list(Binding.objects.order_by('id').values())},default=str,sort_keys=True))"
    )


def managed(cfg: OperationsApiConfig, action: str, *, expected: bool, category: str) -> dict[str, object]:
    result = subprocess.run(
        shlex.split(management_command()),
        input=management_payload(cfg, action).reveal(),
        capture_output=True,
        timeout=620,
    )
    assert not result.stderr
    value: dict[str, object] = json.loads(result.stdout)
    assert value["ok"] is expected
    assert value["category"] == category
    assert result.returncode == (0 if expected else 1)
    assert all(secret.encode() not in result.stdout for secret in ("a" * 40, "b" * 40, "c" * 40, "d" * 40))
    return value


def paired_rsync_repeat() -> None:
    export = Path("/tmp/operations-public-export")
    assert not export.exists()
    export.mkdir()
    archive = command(["git", "-C", str(SITE), "archive", DAYBOOK])
    command(["tar", "-xf", "-", "-C", str(export)], stdin=archive)
    original_site = HOME / "original-site"
    original_site.mkdir()
    original = [
        "rsync",
        "-a",
        "--delete",
        "--no-owner",
        "--no-group",
        *["--exclude=" + pattern for pattern in SOURCE_EXCLUDES],
    ]
    command([*original, str(export) + "/", str(original_site) + "/"])
    command(["chown", "-R", "daybook-operations:daybook-operations", str(original_site)])
    sync = (
        "cd " + str(original_site) + " && "
        "UV_PROJECT_ENVIRONMENT=/home/daybook-operations/original-venv "
        "UV_CACHE_DIR=/home/daybook-operations/.cache "
        "uv sync --frozen --no-dev --group operations-api --python 3.14.7"
    )
    user(["/bin/sh", "-c", sync])
    original_repeat = (
        command(
            [
                *original,
                "--dry-run",
                "--itemize-changes",
                "--out-format=%i %n%L",
                str(export) + "/",
                str(original_site) + "/",
            ]
        )
        .decode()
        .splitlines()
    )

    # Exercise the same SDK argument builder with a local owned destination.
    # Only SSH transport is removed; all file-selection/deletion flags remain.
    def typed(dry: bool) -> list[str]:
        args = rsync_argv(
            export,
            PurePosixPath(SITE),
            "owned",
            user="daybook-operations",
            group="daybook-operations",
            excludes=SOURCE_EXCLUDES,
            rsync_path="/usr/bin/rsync",
            dry_run=dry,
        )
        offset = args.index("-e")
        del args[offset : offset + 2]
        args[-1] = str(SITE) + "/"
        return args

    typed_repeat = command(typed(True)).decode().splitlines()
    command(typed(False))
    user(
        [
            "/bin/sh",
            "-c",
            "cd /home/daybook-operations/site && "
            "UV_PROJECT_ENVIRONMENT=/home/daybook-operations/venv "
            "UV_CACHE_DIR=/home/daybook-operations/.cache "
            "uv sync --frozen --no-dev --group operations-api --python 3.14.7",
        ]
    )
    typed_after_resync = command(typed(True)).decode().splitlines()
    (EVIDENCE / "paired-rsync-repeat.json").write_text(
        json.dumps(
            {
                "original_repeat_itemized": original_repeat,
                "typed_repeat_itemized": typed_repeat,
                "typed_after_real_resync_and_uv_itemized": typed_after_resync,
                "original_genuine_uv_runs": 1,
                "typed_genuine_uv_runs": 2,
                "limit": (
                    "Owned public-source metadata only; any repeat churn requires disposition before live qualification"
                ),
            },
            indent=2,
        )
        + "\n"
    )


def profile_file(body: object) -> None:
    path = CONF / "profiles.json"
    path.write_text(json.dumps(body) + "\n")
    path.chmod(0o600)
    command(["chown", "daybook-operations:daybook-operations", str(path)])


def main() -> None:
    assert os.geteuid() == 0
    assert Path("/.dockerenv").exists()
    assert all(not path.exists() for path in (HOME, CONF, PG))
    assert EVIDENCE.is_dir()
    package_proof()
    started = False
    try:
        command(
            [
                "useradd",
                "--system",
                "--create-home",
                "--home-dir",
                str(HOME),
                "--shell",
                "/usr/sbin/nologin",
                "daybook-operations",
            ]
        )
        PG.mkdir(mode=0o700)
        command(["chown", "postgres:postgres", str(PG)])
        command(["runuser", "-u", "postgres", "--", "initdb", "-D", str(PG), "--auth-local=trust", "--auth-host=trust"])
        command(
            [
                "runuser",
                "-u",
                "postgres",
                "--",
                "pg_ctl",
                "-D",
                str(PG),
                "-l",
                str(PG / "server.log"),
                "-o",
                "-h 127.0.0.1 -p 5432",
                "-w",
                "start",
            ]
        )
        started = True
        command(
            [
                "psql",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "CREATE USER daybook_operations;",
            ]
        )
        command(
            [
                "psql",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "CREATE DATABASE daybook_operations OWNER daybook_operations;",
            ]
        )
        command(["git", "clone", "--quiet", "https://github.com/ephes/daybook.git", str(SITE)])
        command(["git", "-C", str(SITE), "checkout", "--detach", DAYBOOK])
        assert command(["git", "-C", str(SITE), "rev-parse", "HEAD"]).decode().strip() == DAYBOOK
        old = command(["git", "-C", str(SITE), "show", OLD + ":src/daybook/operations_protocol.py"])
        old_namespace: dict[str, Any] = {"__name__": "owned_old_protocol"}
        new_namespace: dict[str, Any] = {"__name__": "owned_new_protocol"}
        exec(compile(old, "<owned-old-protocol>", "exec"), old_namespace)
        exec(
            compile((SITE / "src/daybook/operations_protocol.py").read_bytes(), "<owned-new-protocol>", "exec"),
            new_namespace,
        )
        assert set(new_namespace["ADAPTERS"]) - set(old_namespace["ADAPTERS"]) == {"ops.traefik_patch.v1"}
        command(["chown", "-R", "daybook-operations:daybook-operations", str(HOME)])
        user(
            [
                "/bin/sh",
                "-c",
                "cd /home/daybook-operations/site && "
                "UV_PROJECT_ENVIRONMENT=/home/daybook-operations/venv "
                "UV_CACHE_DIR=/home/daybook-operations/.cache "
                "/usr/local/bin/uv sync --frozen --no-dev --group operations-api --python 3.14.7",
            ]
        )
        paired_rsync_repeat()
        CONF.mkdir(mode=0o750)
        cfg = OperationsApiConfig(source_path=SITE)
        pins = OperationsApiPins(
            secret_key="a" * 40,
            database_password="b" * 40,
            signing_keys={"v1": "c" * 40},
            signing_key_id="v1",
            profiles=(
                OperationsProfile(
                    name="owned-worker",
                    host="owned",
                    profile="operations-worker",
                    enabled=True,
                    tokens=("d" * 40,),
                    monitor_tokens=("e" * 40,),
                ),
            ),
        )
        for name, content in render_config(cfg, pins).items():
            path = CONF / name
            path.write_bytes(content.reveal())
            path.chmod(0o600)
        command(["chown", "-R", "daybook-operations:daybook-operations", str(CONF)])
        migrated = managed(cfg, "migrate", expected=True, category="operations_management_succeeded")
        assert migrated["original_changed"] is True
        managed(cfg, "provision", expected=True, category="operations_management_succeeded")
        migrations = application(
            "import json;from django.db.migrations.recorder import MigrationRecorder;"
            "print(json.dumps(list(MigrationRecorder.Migration.objects.values_list('app','name'))))"
        )
        assert isinstance(migrations, list)
        assert len(migrations) == 8
        assert all(row[0] == "coordination" for row in migrations)
        record({"phase": "fresh", "eight_real_migrations": True, "genuine_commands": 2})
        application(
            "import json;from coordination.models import Principal,Binding;"
            "p=Principal.objects.get(name='owned-worker');p.offers=['owned-offer'];p.save(update_fields=['offers']);"
            "Binding.objects.create(name='owned-source',adapter='ops.traefik_patch.v1',enabled=True,requires=['owned-offer']);print('true')"
        )
        before = projection()
        repeat = managed(cfg, "migrate", expected=True, category="operations_management_succeeded")
        assert repeat["original_changed"] is False
        managed(cfg, "provision", expected=True, category="operations_management_succeeded")
        assert projection() == before
        record({"phase": "repeat", "source_offer_credentials_equal": True, "genuine_commands": 2})
        original = [row.revealed() for row in pins.profiles]
        for name, replacement, category in (
            ("old_schema", {"schema": 3}, "operations_configuration_invalid"),
            ("source_field", {"sources": []}, "operations_configuration_invalid"),
            (
                "purpose_conflict",
                {"tokens": ["e" * 40], "monitor_tokens": ["d" * 40]},
                "management_command_failed",
            ),
            ("identity_conflict", {"host": "foreign"}, "operations_configuration_invalid"),
        ):
            rows = json.loads(json.dumps(original))
            rows[0].update(replacement)
            profile_file(rows)
            managed(cfg, "provision", expected=False, category=category)
            assert projection() == before
            record({"phase": name, "all_fixture_rows_equal": True, "genuine_commands": 1})
        protocol = application(
            "import json;from coordination import service;from coordination.models import Operation;"
            "new=service.ADAPTERS;service.ADAPTERS=frozenset(" + repr(sorted(old_namespace["ADAPTERS"])) + ");"
            "old_refused=service.offered({'adapters':['ops.traefik_patch.v1']},'adapters') is None;"
            "service.ADAPTERS=new;"
            "new_admitted=service.offered({'adapters':['ops.traefik_patch.v1']},'adapters')=={'ops.traefik_patch.v1'};"
            "print(json.dumps({'old_refused':old_refused,'new_admitted':new_admitted,'operation_count':Operation.objects.count()}))"
        )
        assert protocol == {"old_refused": True, "new_admitted": True, "operation_count": 0}
        assert projection() == before
        # Real descendant metadata drift, without changing already-owned files.
        preserved = SITE / "src/daybook/operations_protocol.py"
        preserved_stat = preserved.stat()
        drift_dir = SITE / "owned-descendant-fixture"
        drift_dir.mkdir()
        drift = drift_dir / "root-owned.py"
        drift.write_text("# owned fixture\n")
        assert command(["/bin/sh", "-c", source_ownership_command(cfg, check=True)]).strip() == b"pending"
        command(["/bin/sh", "-c", source_ownership_command(cfg, check=False)])
        assert command(["/bin/sh", "-c", source_ownership_command(cfg, check=True)]).strip() == b"current"
        assert preserved.stat() == preserved_stat
        assert drift.stat().st_uid == HOME.stat().st_uid
        for kind in ("api", "reconcile"):
            unit = Path(
                "/etc/systemd/system/daybook-operations" + ("-reconcile" if kind == "reconcile" else "") + ".service"
            )
            assert not unit.exists()
            unit.write_text(render_unit(cfg, kind))
            unit.chmod(0o644)
        command(
            [
                "systemd-analyze",
                "verify",
                "/etc/systemd/system/daybook-operations.service",
                "/etc/systemd/system/daybook-operations-reconcile.service",
            ]
        )
        profile_file(original)
        command(["runuser", "-u", "postgres", "--", "pg_ctl", "-D", str(PG), "-m", "fast", "-w", "stop"])
        started = False
        managed(cfg, "provision", expected=False, category="operations_storage_unavailable")
        record({"phase": "database_unavailable", "fixed_error_only": True, "genuine_commands": 1})
        record(
            {
                "phase": "protocol_update",
                "only_added_adapter": "ops.traefik_patch.v1",
                "no_dispatch_executed": protocol["operation_count"] == 0,
                "actual_offered_old_refused_new_admitted": True,
                "descendant_ownership_repaired_without_peer_ctime_change": True,
                "systemd_analyze_static_verify": True,
            }
        )
        (EVIDENCE / "management.json").write_text(
            json.dumps(
                {
                    "phases": PHASES,
                    "source": DAYBOOK,
                    "helper_sha256": hashlib.sha256(
                        files("ops_deploy.services.daybook_operations_api")
                        .joinpath("files/management_host.py")
                        .read_bytes()
                    ).hexdigest(),
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        if started:
            command(["runuser", "-u", "postgres", "--", "pg_ctl", "-D", str(PG), "-m", "fast", "-w", "stop"])
        (EVIDENCE / "management-cleanup.json").write_text(
            json.dumps({"postgres_stopped": True, "phases_completed": len(PHASES)}) + "\n"
        )


if __name__ == "__main__":
    main()
