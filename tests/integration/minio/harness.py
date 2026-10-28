"""Owned native x86 MinIO/systemd fixture; every identity and object is synthetic."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
import traceback
import urllib.request
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import patch

import yaml
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops
from pyinfra.connectors.local import LocalConnector

from ops_deploy.services.minio import (
    MinioBucket,
    MinioConfig,
    MinioCredentials,
    MinioIdentity,
    MinioPolicy,
    MinioSupersededPolicy,
    MinioUserCredentials,
    deploy_minio,
)
from ops_deploy.testing.harness import collect_ops

ROOT = Path("/opt/minio-fixture")
EVIDENCE = Path(sys.argv[1])
LIBRARY = ROOT / "collections/ansible_collections/local/ops_library"
DATA = Path("/var/lib/minio/data")
VALUES: list[str] = []
PHASES: list[dict[str, Any]] = []
FOREIGN_ALIAS: Mapping[str, str] = MappingProxyType({})


def value() -> SecretStr:
    result = secrets.token_hex(24)
    VALUES.append(result)
    return SecretStr(result)


CREDS = MinioCredentials(
    root_user=SecretStr("fixture-root"), root_password=value(), console_basic_auth_password=value()
)


def sanitize(text: str) -> str:
    for secret in VALUES:
        text = text.replace(secret, "<synthetic-redacted>")
    return text


def write(name: str, data: Any) -> None:
    (EVIDENCE / name).write_text(sanitize(json.dumps(data, indent=2, default=str)) + "\n")


def command(
    *args: str, stdin: str | None = None, check: bool = True, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=300, env=env)
    if check and result.returncode:
        raise RuntimeError(f"owned command failed with exit {result.returncode}; output withheld")
    return result


def mc(
    *args: str, stdin: str | None = None, shared: bool = False, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return command(
        "/opt/minio-artifacts/mc",
        "--json",
        "--config-dir",
        "/root/.mc" if shared else str(ROOT / "admin"),
        *args,
        stdin=stdin,
        check=check,
    )


def fs(path: Path) -> Any:
    if not path.exists() and not path.is_symlink():
        return None
    st = path.lstat()
    return {
        "mode": st.st_mode,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "inode": st.st_ino,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "body": os.readlink(path)
        if path.is_symlink()
        else hashlib.sha256(path.read_bytes()).hexdigest()
        if path.is_file()
        else None,
    }


def tree(root: Path) -> dict[str, Any]:
    return {str(path): fs(path) for path in [root, *sorted(root.rglob("*"))]} if root.exists() else {str(root): None}


def foreign_alias_observation(path: Path, expected: Mapping[str, str]) -> dict[str, Any]:
    """Compare the owned fixture's foreign alias without recording credential values."""
    try:
        config = json.loads(path.read_text())
        if not isinstance(config, dict) or not isinstance(config.get("aliases"), dict):
            raise ValueError("invalid alias config")
        aliases = config["aliases"]
    except (OSError, UnicodeError, ValueError):
        return {"present": False, "equal": False, "different_fields": ["<unreadable-config>"]}
    actual = aliases.get("untouched")
    return {
        "present": "untouched" in aliases,
        "equal": actual == expected,
        "different_fields": (
            sorted(key for key in set(actual) | set(expected) if actual.get(key) != expected.get(key))
            if isinstance(actual, dict)
            else ["<missing-or-invalid-alias>"]
        ),
    }


def snapshot() -> dict[str, Any]:
    paths = [
        "/usr/local/bin/minio",
        "/usr/local/bin/mc",
        "/etc/default/minio",
        "/etc/systemd/system/minio.service",
        "/etc/systemd/system/multi-user.target.wants/minio.service",
        "/etc/traefik/dynamic/minio.yml",
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/root/.mc/config.json",
    ]
    return {
        "files": {path: fs(Path(path)) for path in paths},
        "foreign_alias": foreign_alias_observation(Path("/root/.mc/config.json"), FOREIGN_ALIAS),
        "policies": tree(Path("/etc/minio/policies")),
        "iam": tree(DATA / ".minio.sys/config/iam"),
        "objects": tree(DATA / "fixture-objects"),
        "data_root": fs(DATA),
        "unit": command(
            "systemctl",
            "show",
            "minio.service",
            "-p",
            "MainPID",
            "-p",
            "ActiveState",
            "-p",
            "UnitFileState",
            "-p",
            "ActiveEnterTimestampMonotonic",
            check=False,
        ).stdout,
        "packages": command("dpkg-query", "-W", "-f=${Package}=${Version}\n").stdout,
    }


def deploy(
    label: str,
    cfg: MinioConfig,
    creds: MinioCredentials,
    *,
    zero: bool = False,
    failure: bool = False,
    fish: bool = False,
) -> dict[str, Any]:
    before = snapshot()
    uploads: list[bool] = []
    state = State(Inventory(([("@local", {})], {})), Config())
    original = LocalConnector.run_shell_command
    original_put = LocalConnector.put_file
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
        log.open("w") as stream,
        contextlib.redirect_stdout(stream),
        contextlib.redirect_stderr(stream),
    ):
        try:
            connect_all(state)
            add_deploy(state, deploy_minio, cfg=cfg, credentials=creds)
            run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
    raw_log = log.read_text()
    exposed = any(secret in raw_log for secret in VALUES)
    log.write_text(sanitize(raw_log))
    after = snapshot()
    managed = [op.name for op in operations if op.changed and not op.read_only]
    failed = [op.name for op in operations if not op.succeeded]
    result = {
        "label": label,
        "managed": managed,
        "uploads": len(uploads),
        "failed_operations": failed,
        "error": error,
        "before": before,
        "after": after,
        "operations": [asdict(op) for op in operations],
        "fish": fish,
        "classification": "expected-owned-fault" if failure else "healthy",
        "plaintext_secret_logged": exposed,
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
                "classification",
                "plaintext_secret_logged",
            )
        }
    )
    assert before["foreign_alias"]["equal"], label
    assert after["foreign_alias"]["equal"], label
    assert not exposed, label
    assert bool(error or failed) == failure, label
    if zero:
        assert not managed, label
        assert not uploads, label
        assert not failed, label
        assert before == after, label
    return result


def policy(name: str, resources: list[str], actions: list[str], *, immutable: bool = False) -> MinioPolicy:
    return MinioPolicy(
        name=name,
        document={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}],
        },
        immutable=immutable,
    )


def configured() -> tuple[MinioConfig, MinioCredentials]:
    policies = (
        policy("fixture-prefix", ["arn:aws:s3:::fixture-objects/allowed/*"], ["s3:GetObject", "s3:PutObject"]),
        policy(
            "fixture-object-sync",
            ["arn:aws:s3:::fixture-objects", "arn:aws:s3:::fixture-objects/*"],
            ["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject", "s3:PutObject"],
        ),
        policy(
            "fixture-artifacts",
            ["arn:aws:s3:::fixture-artifacts", "arn:aws:s3:::fixture-artifacts/*"],
            ["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        ),
        policy(
            "fixture-sessions",
            ["arn:aws:s3:::fixture-sessions", "arn:aws:s3:::fixture-sessions/*"],
            ["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject", "s3:PutObject"],
        ),
        policy("fixture-versioned-v2", ["arn:aws:s3:::fixture-objects/notes/*"], ["s3:GetObject"], immutable=True),
    )
    identities = (
        MinioIdentity(
            name="prefix", policies=("fixture-prefix",), exact=True, proof="fixture-objects/allowed/never-created-proof"
        ),
        MinioIdentity(name="sync", policies=("fixture-object-sync",), exact=True, proof="fixture-objects"),
        MinioIdentity(name="artifacts", policies=("fixture-artifacts",), proof="fixture-artifacts"),
        MinioIdentity(name="sessions", policies=("fixture-sessions", "fixture-versioned-v2"), proof="fixture-sessions"),
    )
    credentials = MinioCredentials(
        **{
            **CREDS.model_dump(),
            "identities": {
                identity.name: MinioUserCredentials(access=SecretStr("fixture-user-" + identity.name), secret=value())
                for identity in identities
            },
        }
    )
    cfg = MinioConfig(
        bootstrap_with_mc=True,
        expose_via_traefik=True,
        traefik_host="minio.example.test",
        traefik_api_host="objects.example.test",
        local_minio_binary=Path("/opt/minio-artifacts/minio"),
        local_mc_binary=Path("/opt/minio-artifacts/mc"),
        buckets=(MinioBucket(name="fixture-artifacts"), MinioBucket(name="fixture-sessions")),
        policies=policies,
        identities=identities,
        superseded=(MinioSupersededPolicy(name="fixture-versioned-v1", identity="sessions"),),
    )
    return cfg, credentials


def ansible(
    cfg: MinioConfig, creds: MinioCredentials, *, label: str = "ansible-role", allow_failure: bool = False
) -> int:
    variables = {"minio_" + key: value for key, value in cfg.model_dump(mode="json").items()}
    assert creds.console_basic_auth_password is not None
    root = creds.root_password.get_secret_value()
    auth = creds.console_basic_auth_password.get_secret_value()
    variables.update(
        minio_root_user=creds.root_user.get_secret_value(),
        minio_root_password=root,
        minio_console_basic_auth_password=auth,
        # Exact owned artifacts replace unavailable410 download URLs only.
        minio_download_url="file:///opt/minio-artifacts/minio",
        minio_mc_download_url="file:///opt/minio-artifacts/mc",
    )
    play = [
        {
            "hosts": "localhost",
            "gather_facts": True,
            "connection": "local",
            "vars": variables,
            "roles": ["local.ops_library.minio_deploy"],
        }
    ]
    path = ROOT / "ansible.yml"
    path.write_text(yaml.safe_dump(play))
    path.chmod(0o600)
    before = snapshot()
    result = command(
        "/opt/minio-ansible/bin/ansible-playbook",
        "-i",
        "localhost,",
        "-c",
        "local",
        str(path),
        check=False,
        env={**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(ROOT / "collections")},
    )
    (EVIDENCE / (label + ".log")).write_text(sanitize(result.stdout + result.stderr))
    after = snapshot()
    write(
        label + ".json",
        {
            "exit": result.returncode,
            "before": before,
            "after": after,
            "classification": (
                "original-role observation; alias/bootstrap/recursive chmod may write, NOT zero-mutation proof"
            ),
        },
    )
    path.unlink()
    assert before["foreign_alias"]["equal"], label
    assert after["foreign_alias"]["equal"], label
    if not allow_failure:
        assert result.returncode == 0, "original Ansible role failed"
    return result.returncode


def run_lag_component(creds: MinioCredentials) -> None:
    directory = Path(__file__).parent
    driver = directory / "s4-lag-driver.py.txt"
    probe = directory / "s4-lag-probe.py.txt"
    driver_sha = "8e535d6ff0a0173ce6914137382a58ab99fd07cf8dab5adc7ad3624879024c95"
    probe_sha = "a83cec6f0768601fb10ebad2f72edc18c04004d24d5232da73c7c36ca802ebf2"
    assert hashlib.sha256(driver.read_bytes()).hexdigest() == driver_sha
    assert hashlib.sha256(probe.read_bytes()).hexdigest() == probe_sha
    result = subprocess.run(
        [sys.executable, str(driver), str(probe), probe_sha],
        input=json.dumps(
            {
                "endpoint": "http://127.0.0.1:9001",
                "user": creds.root_user.get_secret_value(),
                "password": creds.root_password.get_secret_value(),
            }
        ),
        text=True,
        capture_output=True,
        timeout=600,
    )
    exposed = any(secret in result.stdout + result.stderr for secret in VALUES)
    write(
        "s4-lag-component.json",
        {
            "exit": result.returncode,
            "driver_sha256": driver_sha,
            "probe_sha256": probe_sha,
            "plaintext_secret_logged": exposed,
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
    )
    assert not exposed, "S4 synthetic component credential output"
    assert result.returncode == 0, "S4 synthetic component failed; separate receipt retained"


def main() -> None:
    global FOREIGN_ALIAS
    cfg, creds = configured()
    access = creds.root_user.get_secret_value()
    root = creds.root_password.get_secret_value()
    alias = {
        "url": "http://127.0.0.1:9001",
        "accessKey": access,
        "secretKey": root,
        "api": "s3v4",
        "path": "auto",
    }
    FOREIGN_ALIAS = MappingProxyType(alias.copy())
    mc("alias", "import", "untouched", stdin=json.dumps(alias), shared=True)
    mc("alias", "import", "local", stdin=json.dumps(alias))
    # Start a new native server and its two owned buckets first. The third
    # synthetic bucket belongs to a fixture consumer, as the real shared bucket
    # pre-exists outside this deployment's bucket-creation ownership.
    base = cfg.model_copy(update={"policies": (), "identities": (), "superseded": ()})
    deploy("01-fresh-server-buckets", base, CREDS)
    mc("mb", "local/fixture-objects")
    deploy("02-declared-iam-first", cfg, creds)
    mc("pipe", "local/fixture-objects/owned-sentinel", stdin="synthetic object sentinel only\n")
    # An unrelated user/policy must remain untouched by every deploy.
    other = policy("fixture-unowned", ["arn:aws:s3:::fixture-objects/unrelated/*"], ["s3:GetObject"])
    mc("admin", "policy", "create", "local", other.name, "/dev/stdin", stdin=json.dumps(other.document))
    unowned = value()
    mc("admin", "user", "add", "local", stdin="fixture-unowned-user\n" + unowned.get_secret_value() + "\n")
    mc("admin", "policy", "attach", "local", other.name, "--user", "fixture-unowned-user")
    deploy("03-healthy-repeat", cfg, creds, zero=True)
    deploy("04-fish-repeat", cfg, creds, zero=True, fish=True)
    ansible(cfg, creds)
    deploy("05-after-ansible-repeat", cfg, creds, zero=True)
    # Original tasks with only exact-artifact file URLs substituted for410.
    # Preserve each real result; delayed restart may make root rotation fail.
    installed_mc = Path("/usr/local/bin/mc")
    held_mc = ROOT / "mc-held"
    installed_mc.rename(held_mc)
    ansible(cfg, creds, label="ansible-missing-client")
    held_mc.unlink()
    command("systemctl", "stop", "minio.service")
    ansible(cfg, creds, label="ansible-stopped-service")
    original_env = Path("/etc/default/minio").read_bytes()
    legacy_rotated = creds.model_copy(update={"root_password": value()})
    legacy_exit = ansible(cfg, legacy_rotated, label="ansible-root-rotation", allow_failure=True)
    if legacy_exit:
        half_applied = deploy("05-original-half-applied-root-admission", cfg, legacy_rotated, failure=True)
        assert half_applied["before"] == half_applied["after"]
        assert not half_applied["managed"]
        assert not half_applied["uploads"]
        write(
            "original-half-applied-adjudication.json",
            {
                "original_exit": legacy_exit,
                "environment_changed": Path("/etc/default/minio").read_bytes() != original_env,
                "pyinfra_result": "safe refusal before writes; current env did not prove active credentials",
                "fixture_reset_follows": True,
            },
        )
    # Explicit owned-fixture reset AFTER saving the real original result.
    Path("/etc/default/minio").write_bytes(original_env)
    command("systemctl", "restart", "minio.service")
    for _attempt in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:9001/minio/health/live", timeout=2) as response:
                if response.status == 200:
                    break
        except OSError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("owned fixture reset did not become healthy")
    mc("alias", "import", "local", stdin=json.dumps(alias), shared=True)
    deploy("05a-after-original-recovery-observations", cfg, creds, zero=True)

    new_root = creds.model_copy(update={"root_password": value()})
    rotation = deploy("05b-root-rotation", cfg, new_root)
    assert len(rotation["managed"]) == 3
    assert rotation["uploads"] == 0  # protected stdin environment transport
    assert rotation["before"]["objects"] == rotation["after"]["objects"]
    assert rotation["before"]["iam"] == rotation["after"]["iam"]
    creds = new_root
    alias["secretKey"] = creds.root_password.get_secret_value()
    mc("alias", "import", "local", stdin=json.dumps(alias))
    deploy("05c-root-rotation-repeat", cfg, creds, zero=True)
    installed_mc.rename(held_mc)
    restored = deploy("05d-missing-client-recovery", cfg, creds)
    assert len(restored["managed"]) == 1
    assert restored["uploads"] == 1
    assert restored["before"]["unit"] == restored["after"]["unit"]
    assert restored["before"]["objects"] == restored["after"]["objects"]
    assert restored["before"]["iam"] == restored["after"]["iam"]
    held_mc.unlink()
    deploy("05e-client-recovery-repeat", cfg, creds, zero=True)
    command("systemctl", "stop", "minio.service")
    restored = deploy("05f-stopped-service-recovery", cfg, creds)
    assert len(restored["managed"]) == 1
    assert restored["uploads"] == 0
    assert restored["before"]["objects"] == restored["after"]["objects"]
    assert restored["before"]["iam"] == restored["after"]["iam"]
    deploy("05g-service-recovery-repeat", cfg, creds, zero=True)
    # A top-level directory mode repair must preserve every descendant.
    os.chmod(DATA, 0o700)
    changed = deploy("06-data-root-mode", cfg, creds)
    assert changed["before"]["objects"] == changed["after"]["objects"]
    assert changed["before"]["iam"] == changed["after"]["iam"]
    deploy("07-data-root-repeat", cfg, creds, zero=True)
    # Disabled users and immutable/exact drift refuse both planning and apply:
    # the public deploy never queues a mutation on those existing-host failures.
    access = creds.identities["prefix"].access.get_secret_value()
    mc("admin", "user", "disable", "local", access)
    fault = deploy("08-disabled-refusal", cfg, creds, failure=True)
    assert fault["before"] == fault["after"]
    assert not fault["managed"]
    assert not fault["uploads"]
    blocked_root = deploy(
        "08a-disabled-root-rotation-refusal", cfg, creds.model_copy(update={"root_password": value()}), failure=True
    )
    assert blocked_root["before"] == blocked_root["after"]
    assert not blocked_root["managed"]
    installed_mc.rename(held_mc)
    partial = deploy("08b-client-recovery-disabled-refusal", cfg, creds, failure=True)
    assert len(partial["managed"]) == 1
    assert partial["uploads"] == 1
    assert partial["before"]["objects"] == partial["after"]["objects"]
    assert partial["before"]["iam"] == partial["after"]["iam"]
    held_mc.unlink()
    command("systemctl", "stop", "minio.service")
    partial = deploy("08c-service-recovery-disabled-refusal", cfg, creds, failure=True)
    assert len(partial["managed"]) == 1
    assert partial["uploads"] == 0
    assert partial["before"]["objects"] == partial["after"]["objects"]
    assert partial["before"]["iam"] == partial["after"]["iam"]
    mc("admin", "user", "enable", "local", access)
    deploy("09-enabled-repeat", cfg, creds, zero=True)
    drift = policy(
        "fixture-versioned-v2", ["arn:aws:s3:::fixture-objects/different/*"], ["s3:GetObject"], immutable=True
    )
    invalid = cfg.model_copy(update={"policies": (*cfg.policies[:-1], drift)})
    fault = deploy("10-immutable-refusal", invalid, creds, failure=True)
    assert fault["before"] == fault["after"]
    assert not fault["managed"]
    mc("admin", "policy", "attach", "local", "fixture-artifacts", "--user", access)
    fault = deploy("11-extra-policy-refusal", cfg, creds, failure=True)
    assert fault["before"] == fault["after"]
    assert not fault["managed"]
    mc("admin", "policy", "detach", "local", "fixture-artifacts", "--user", access)
    deploy("12-attachments-repeat", cfg, creds, zero=True)
    # Only synthetic credentials rotate; no service restart or object write.
    users = dict(creds.identities)
    users["prefix"] = MinioUserCredentials(access=users["prefix"].access, secret=value())
    creds = creds.model_copy(update={"identities": users})
    rotation = deploy("13-secret-rotation", cfg, creds)
    assert len(rotation["managed"]) == 1
    assert rotation["uploads"] == 0
    assert rotation["before"]["unit"] == rotation["after"]["unit"]
    assert rotation["before"]["objects"] == rotation["after"]["objects"]
    deploy("14-rotation-repeat", cfg, creds, zero=True)
    mc("version", "enable", "local/fixture-artifacts")
    deploy("15-false-keeps-versioning", cfg, creds, zero=True)
    assert json.loads(mc("version", "info", "local/fixture-artifacts").stdout)["versioning"]["status"] == "Enabled"
    old = policy("fixture-versioned-v1", ["arn:aws:s3:::fixture-objects/old/*"], ["s3:GetObject"])
    mc("admin", "policy", "create", "local", old.name, "/dev/stdin", stdin=json.dumps(old.document))
    mc("admin", "policy", "attach", "local", old.name, "--user", creds.identities["sessions"].access.get_secret_value())
    deploy("16-superseded-removal", cfg, creds)
    deploy("17-final-repeat", cfg, creds, zero=True)
    with urllib.request.urlopen("http://127.0.0.1:9001/minio/health/live", timeout=10) as response:
        assert response.status == 200
    assert foreign_alias_observation(Path("/root/.mc/config.json"), FOREIGN_ALIAS)["equal"]
    write(
        "summary.json",
        {
            "success": True,
            "phases": PHASES,
            "scope": (
                "native x86 Ubuntu24 systemd userspace/shared owned VM kernel, "
                "synthetic data/credentials only; original Ansible repeat may write; "
                "no inventory or global-I/O claim"
            ),
        },
    )

    run_lag_component(creds)


try:
    main()
except Exception:
    failure_receipt = "post-minio-component-error.json" if (EVIDENCE / "summary.json").exists() else "summary.json"
    write(failure_receipt, {"success": False, "phases": PHASES, "error": traceback.format_exc()})
    raise
