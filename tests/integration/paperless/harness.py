"""Owned native Paperless fixture; synthetic application data only."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.local import LocalConnector

from ops_deploy.services.paperless import PaperlessConfig, PaperlessCredentials, deploy_paperless
from ops_deploy.services.paperless.django import shell_command
from ops_deploy.services.paperless.index_contract import document_count_command, parse_document_count
from ops_deploy.testing.harness import collect_ops

ROOT = Path("/opt/paperless-fixture")
EVIDENCE = Path("/var/tmp/paperless-evidence")
LIBRARY = ROOT / "collections/ansible_collections/local/ops_library"
PHASES: list[dict[str, Any]] = []
VALUES: list[str] = []
MATRIX_COMPLETE = False
OWNED_ADMITTED = False


class BoundedLog(io.TextIOBase):
    """Keep raw CLI bytes private and bounded until redaction is complete."""

    def __init__(self, stream: io.TextIOWrapper, limit: int = 20 * 1024 * 1024) -> None:
        self.stream = stream
        self.limit = limit
        self.size = 0

    def write(self, text: str) -> int:
        size = len(text.encode())
        if self.size + size > self.limit:
            raise RuntimeError("owned CLI log exceeds bound")
        self.size += size
        return self.stream.write(text)

    def flush(self) -> None:
        self.stream.flush()


def value() -> SecretStr:
    text = secrets.token_hex(32)
    VALUES.append(text)
    return SecretStr(text)


CREDS = PaperlessCredentials(
    secret_key=value(), postgres_password=value(), admin_password=value(), scanner_password=value()
)
CFG = PaperlessConfig(traefik_domain="owned.example.test", traefik_enabled=False)


def sanitize(text: str) -> str:
    for secret in VALUES:
        text = text.replace(secret, "<synthetic-redacted>")
    return text


def write(name: str, data: Any) -> None:
    assert "/" not in name
    assert name.endswith(".json")
    encoded = sanitize(json.dumps(data, indent=2, default=str)) + "\n"
    assert len(encoded.encode()) <= 20 * 1024 * 1024
    (EVIDENCE / name).write_text(encoded)


def command(
    *args: str, stdin: str | None = None, check: bool = True, timeout: int = 300, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout, env=env, check=False)
    if check and result.returncode:
        raise RuntimeError(f"owned command failed with exit{result.returncode}; application output withheld")
    return result


def app(program: str, cfg: PaperlessConfig = CFG, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return command("sh", "-c", shell_command(cfg), stdin=program, check=check)


def public_metadata(path: Path) -> dict[str, Any] | None:
    try:
        meta = path.lstat()
    except FileNotFoundError:
        return None
    return {
        "mode": meta.st_mode,
        "uid": meta.st_uid,
        "gid": meta.st_gid,
        "inode": meta.st_ino,
        "size": meta.st_size,
        "mtime_ns": meta.st_mtime_ns,
        "ctime_ns": meta.st_ctime_ns,
        "link": os.readlink(path) if path.is_symlink() else None,
    }


def program_tree(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not root.exists():
        return result
    for parent, dirs, names in os.walk(root, followlinks=False):
        # Python import caches are observed separately from immutable source.
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        for name in ["", *dirs, *names]:
            path = Path(parent) / name
            if path.suffix == ".pyc":
                continue
            result[str(path.relative_to(root))] = public_metadata(path)
            if len(result) > 250_000:
                raise RuntimeError("owned program metadata exceeds fixture bound")
    return result


@dataclass
class Snapshot:
    public: dict[str, Any]
    private: dict[str, bytes]


def snapshot_receipt(label: str, side: str, value: Snapshot) -> dict[str, Any]:
    # Program metadata can be large. Keep each complete raw snapshot separate
    # and compressed; no private body or credential digest is serialized.
    assert side in {"before", "after"}
    body = json.dumps(value.public, sort_keys=True).encode()
    assert len(body) <= 100 * 1024 * 1024
    compressed = gzip.compress(body, mtime=0)
    assert len(compressed) <= 20 * 1024 * 1024
    name = label + "-" + side + ".json.gz"
    (EVIDENCE / name).write_bytes(compressed)
    return {"file": name, "sha256": hashlib.sha256(compressed).hexdigest(), "raw_size": len(body)}


def snapshot(cfg: PaperlessConfig = CFG) -> Snapshot:
    site = Path(cfg.site_root)
    private_paths = [site / ".env", Path("/etc/shadow"), Path("/etc/redis/redis.conf")]
    private = {str(path): path.read_bytes() for path in private_paths if path.is_file()}
    paths = [
        site / "paperless-ngx",
        site / "venv",
        site / f".paperless-installed-{cfg.version}",
        site / "gunicorn.conf.py",
        Path("/etc/fstab"),
        Path("/etc/ssh/sshd_config.d/sftp-scanner.conf"),
        Path("/etc/apparmor.d/local/gs"),
        *private_paths,
    ]
    paths += [Path("/etc/systemd/system") / (unit + ".service") for unit in cfg.units]
    paths += [Path(cfg.external_storage_root) / child for child in ("", "consume", "data", "media")]
    paths.append(Path(cfg.sftp_chroot_dir + "/inbox"))
    files = {str(path): public_metadata(path) for path in paths}
    program_bodies = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
        if path.is_file() and path not in private_paths and not path.is_symlink()
    }
    units = {
        unit: command(
            "systemctl",
            "show",
            unit,
            "-p",
            "MainPID",
            "-p",
            "ActiveState",
            "-p",
            "UnitFileState",
            "-p",
            "ActiveEnterTimestampMonotonic",
            check=False,
        ).stdout
        for unit in (*cfg.units, "redis-server", "postgresql", "postgresql@17-main", "ssh")
    }
    sql = (
        "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; "
        "SELECT 'documents='||count(*) FROM public.documents_document WHERE deleted_at IS NULL; "
        "SELECT 'migrations='||md5(string_agg(app||':'||name,',' ORDER BY app,name)) FROM django_migrations; "
        "SELECT 'admin='||is_active||','||is_staff||','||is_superuser FROM auth_user WHERE username='admin'; "
        "ROLLBACK;"
    )
    if shutil.which("psql"):
        database = command(
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-XAtq",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            cfg.postgres_database,
            "-c",
            sql,
            check=False,
        )
        db_state = {
            "available": database.returncode == 0,
            "operational_aggregates": database.stdout if database.returncode == 0 else None,
        }
    else:
        db_state = {"available": False, "operational_aggregates": None}
    index = Path(cfg.external_storage_root) / "data/index"
    index_state = {}
    for name in ("meta.json", ".index_settings.json"):
        path = index / name
        body = path.read_bytes() if path.is_file() else None
        assert body is None or len(body) <= 1024 * 1024
        index_state[name] = {
            "metadata": public_metadata(path),
            "metadata_sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
        }
    return Snapshot(
        {
            "files": files,
            "public_program_hashes": program_bodies,
            "units": units,
            "database_operational_state": db_state,
            "index_metadata_only": index_state,
            "release": program_tree(site / f"paperless-ngx-v{cfg.version}"),
            "venv": program_tree(site / ".venv"),
            "static": program_tree(site / "staticfiles"),
            "packages": command("dpkg-query", "-W", "-f=${Package}=${Version}\n").stdout,
            "consume_default_acl": command(
                "getfacl", "-cp", cfg.external_storage_root + "/consume", check=False
            ).stdout,
            "mount": command(
                "findmnt",
                "--mountpoint",
                cfg.sftp_chroot_dir + "/inbox",
                "-n",
                "-o",
                "SOURCE,FSTYPE,OPTIONS",
                check=False,
            ).stdout,
        },
        private,
    )


def deploy(
    label: str,
    cfg: PaperlessConfig = CFG,
    creds: PaperlessCredentials = CREDS,
    *,
    zero: bool = False,
    failure: bool = False,
    fish: bool = False,
    shared_redis_password: SecretStr | None = None,
) -> dict[str, Any]:
    before = snapshot(cfg)
    before_receipt = snapshot_receipt(label, "before", before)
    write(label + "-started.json", {"before": before_receipt, "completion_receipt": label + ".json"})
    uploads: list[bool] = []
    state = State(Inventory(([("@local", {})], {})), Config())
    original, original_put = LocalConnector.run_shell_command, LocalConnector.put_file
    error = None
    log = EVIDENCE / (label + ".log")

    def execute(connector: Any, cmd: Any, **kwargs: Any) -> Any:
        raw = cmd if isinstance(cmd, str) else str(cmd.get_raw_value())
        if fish:
            cmd = "fish -c " + shlex.quote(shlex.join(["sh", "-c", raw]))
        return original(connector, cmd, **kwargs)

    def uploaded(*args: Any, **kwargs: Any) -> Any:
        uploads.append(True)
        return original_put(*args, **kwargs)

    with (
        patch.object(LocalConnector, "run_shell_command", execute),
        patch.object(LocalConnector, "put_file", uploaded),
        open(
            ROOT / "private-current-cli.log", "w", opener=lambda path, flags: os.open(path, flags, 0o600)
        ) as raw_stream,
        BoundedLog(raw_stream) as stream,
        contextlib.redirect_stdout(stream),
        contextlib.redirect_stderr(stream),
    ):
        try:
            connect_all(state)
            add_deploy(state, deploy_paperless, cfg=cfg, credentials=creds, shared_redis_password=shared_redis_password)
            run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
    private_log = ROOT / "private-current-cli.log"
    raw = private_log.read_text()
    exposed = any(secret in raw for secret in VALUES)
    log.write_text(sanitize(raw))
    private_log.unlink()
    after = snapshot(cfg)
    managed = [op.name for op in operations if op.changed and not op.read_only]
    failed = [op.name for op in operations if not op.succeeded]
    result = {
        "label": label,
        "managed": managed,
        "uploads": len(uploads),
        "failed_operations": failed,
        "error": sanitize(error) if error else None,
        "operations": [asdict(op) for op in operations],
        "before": before_receipt,
        "after": snapshot_receipt(label, "after", after),
        "private_content_equal": before.private == after.private,
        "plaintext_secret_logged": exposed,
        "fish": fish,
        "classification": "expected-owned-fault" if failure else "healthy",
    }
    write(label + ".json", result)
    PHASES.append(
        {
            key: result[key]
            for key in (
                "label",
                "managed",
                "uploads",
                "failed_operations",
                "error",
                "private_content_equal",
                "plaintext_secret_logged",
                "classification",
            )
        }
    )
    assert not exposed, label
    assert bool(error or failed) == failure, label
    if zero:
        assert not managed, label
        assert not uploads, label
        assert not failed, label
        assert before.public == after.public, label
        assert before.private == after.private, label
    return result


def ansible(label: str, *, version: str = "3.2.1", allow_failure: bool = False) -> int:
    variables = {
        "paperless_traefik_domain": CFG.traefik_domain,
        "paperless_traefik_enabled": False,
        "paperless_version": version,
        "paperless_secret_key": CREDS.secret_key.get_secret_value(),
        "paperless_postgres_password": CREDS.postgres_password.get_secret_value(),
        "paperless_admin_password": CREDS.admin_password.get_secret_value(),
        "paperless_scanner_password": CREDS.scanner_password.get_secret_value(),
    }
    play = [
        {
            "hosts": "localhost",
            "gather_facts": True,
            "connection": "local",
            "vars": variables,
            "roles": ["local.ops_library.paperless_deploy"],
        }
    ]
    path = ROOT / "owned-ansible.yml"
    before = snapshot()
    before_receipt = snapshot_receipt(label, "before", before)
    write(label + "-started.json", {"before": before_receipt, "completion_receipt": label + ".json"})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(yaml.safe_dump(play))
        result = command(
            "/opt/paperless-ansible/bin/ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            str(path),
            timeout=2400,
            check=False,
            env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "collections")},
        )
    finally:
        path.unlink()
    text = sanitize(result.stdout + result.stderr)
    assert len(text.encode()) <= 20 * 1024 * 1024
    (EVIDENCE / (label + ".log")).write_text(text)
    after = snapshot()
    write(
        label + ".json",
        {
            "exit": result.returncode,
            "before": before_receipt,
            "after": snapshot_receipt(label, "after", after),
            "private_content_equal": before.private == after.private,
            "classification": "original-role observation, not a zero-mutation assertion",
        },
    )
    if not allow_failure:
        assert result.returncode == 0, label
    return result.returncode


def count(cfg: PaperlessConfig = CFG) -> int:
    return parse_document_count(
        command("sh", "-c", document_count_command(cfg.postgres_database, cfg.postgres_port)).stdout
    )


def main() -> None:
    global MATRIX_COMPLETE, OWNED_ADMITTED
    # No fixture mutation precedes the owned-guest and actual installed-source
    # receipts. A host invocation or a fabricated GitHub environment alone is
    # insufficient: run-guest creates the marker only after full byte proof.
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getuid() == 0
    assert os.uname().machine == "x86_64"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    owned = json.loads(Path("/var/tmp/paperless-owned-guest.json").read_text())
    artifact = json.loads((EVIDENCE / "installed-artifact.json").read_text())
    assert owned["run"] == os.environ["PAPERLESS_OWNED_ID"] == artifact["run"]
    assert owned["machine"] == Path("/etc/machine-id").read_text().strip() == artifact["machine_id"]
    assert artifact["implementation_sha"] == os.environ["IMPLEMENTATION_SHA"]
    case = os.environ["PAPERLESS_FIXTURE_CASE"]
    assert case in {"current", "upgrade"}
    assert artifact["fixture_case"] == case
    assert not Path(CFG.home_path).exists()
    assert not Path("/mnt/cryptdata").exists()
    OWNED_ADMITTED = True
    Path("/mnt/cryptdata").mkdir()
    # Ansible14.5's genuine mount facts retain only path-shaped source names.
    # tmpfs accepts an arbitrary source label; this remains real tmpfs, not an
    # invented block-device/encryption fact or an injected ansible_mounts value.
    command("mount", "-t", "tmpfs", "-o", "size=1g,mode=0755", "/paperless-owned-data", "/mnt/cryptdata")
    write("storage-scope.json", {"kind": "owned guest tmpfs", "capacity": "1GiB", "encrypted_volume_proof": False})
    harness = sys.modules[__name__]
    # These modules operate only through this guarded, synthetic fixture.
    from tests.integration.paperless import application_matrix, recovery_matrix, scanner_matrix
    from tests.integration.paperless.bootstrap import original_install

    original_install(harness, "3.2.1" if case == "current" else "3.0.4")
    deploy("01-pyinfra-adoption" if case == "current" else "01-pyinfra-upgrade")
    deploy("02-healthy-repeat", zero=True)
    deploy("03-fish-healthy-repeat", zero=True, fish=True)
    ansible("04-original-current-repeat")
    deploy("05-after-original-repeat", zero=True)
    application_matrix.sftp_ocr(harness)
    application_matrix.empty_current_index(harness)
    application_matrix.index_faults(harness)
    application_matrix.reindex_failure_and_retry(harness)
    application_matrix.pending_migration(harness)
    application_matrix.static_and_marker_recovery(harness)
    scanner_matrix.password(harness)
    scanner_matrix.acl(harness)
    scanner_matrix.mount(harness)
    scanner_matrix.invalid_ssh(harness)
    recovery_matrix.legacy_current(harness)
    recovery_matrix.extraction(harness)
    if case == "current":
        recovery_matrix.missing_venv(harness)
        recovery_matrix.broken_interpreter_refusal(harness)
    else:
        recovery_matrix.wrong_python(harness)
        recovery_matrix.missing_supporting_package(harness)
    recovery_matrix.ocr_pattern(harness)
    recovery_matrix.shared_redis_refusal(harness)
    recovery_matrix.database_password(harness)
    application_matrix.schema_and_soft_delete(harness)
    deploy("soft-delete-convergence")
    deploy("99-final-repeat", zero=True)
    resolved = command(
        CFG.site_root + "/.venv/bin/python",
        "-c",
        "import sys,json,importlib.metadata as m;print(json.dumps({'python':sys.version,"
        "'packages':sorted((d.metadata['Name'],d.version) for d in m.distributions())}))",
    )
    write("resolved-application-packages.json", json.loads(resolved.stdout))
    MATRIX_COMPLETE = True


if __name__ == "__main__":
    try:
        main()
    finally:
        if OWNED_ADMITTED:
            write(
                "summary.json",
                {
                    "phases": PHASES,
                    "matrix_complete": MATRIX_COMPLETE,
                    "fixture_case": os.environ["PAPERLESS_FIXTURE_CASE"],
                    "scope": "owned synthetic Ubuntu24 systemd userspace; shared kernel, not hardware",
                },
            )
