"""Real pyinfra deploys of RustFS in an owned systemd container; synthetic data only.

Usage: harness.py RUSTFS_BINARY EVIDENCE_DIR (through run-container.sh). Every
phase is a real deploy with the local connector; the summary records changed
operations per phase, and repeats must change nothing. S3 checks sign their
own requests with the deploy's standard-library client.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops

from ops_deploy.services.rustfs import (
    RustfsBucket,
    RustfsConfig,
    RustfsCredentials,
    RustfsIdentity,
    RustfsPolicy,
    RustfsUserCredentials,
    deploy_rustfs,
)
from ops_deploy.testing.harness import collect_ops

BINARY = Path(sys.argv[1])
EVIDENCE = Path(sys.argv[2])
HELPER = Path(__file__).resolve().parents[3] / "src/ops_deploy/services/rustfs/files/iam_host.py"
VALUES: list[str] = []
PHASES: list[dict[str, Any]] = []
BUCKET = "fixture-backups"
SOURCE = "fixture-notes"


def secret() -> str:
    value = secrets.token_hex(20)
    VALUES.append(value)
    return value


def creds(access: str, value: str) -> RustfsUserCredentials:
    return RustfsUserCredentials(access=SecretStr(access), secret=SecretStr(value))


def statement(actions: list[str], resources: list[str], **extra: Any) -> dict[str, Any]:
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


POLICIES = (
    RustfsPolicy(
        name="runner-a",
        document={
            "Version": "2012-10-17",
            "Statement": [
                statement(["s3:GetBucketLocation"], [f"arn:aws:s3:::{BUCKET}"]),
                statement(
                    ["s3:ListBucket"], [f"arn:aws:s3:::{BUCKET}"], Condition={"StringLike": {"s3:prefix": ["a/*"]}}
                ),
                statement(["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], [f"arn:aws:s3:::{BUCKET}/a/*"]),
            ],
        },
    ),
    RustfsPolicy(
        name="quotes-get-only",
        document={
            "Version": "2012-10-17",
            "Statement": [statement(["s3:GetObject"], [f"arn:aws:s3:::{SOURCE}/Arbeit/Quotes Benutzt.md"])],
        },
    ),
    RustfsPolicy(
        name="retention",
        document={
            "Version": "2012-10-17",
            "Statement": [
                statement(["s3:ListBucket", "s3:ListBucketVersions"], [f"arn:aws:s3:::{BUCKET}"]),
                statement(["s3:GetObject", "s3:DeleteObject"], [f"arn:aws:s3:::{BUCKET}/*"]),
            ],
        },
    ),
)
IDENTITIES = (
    RustfsIdentity(name="runner", policies=("runner-a",), proof=f"{BUCKET}/a/.credential-proof-absent"),
    RustfsIdentity(name="quotes", policies=("quotes-get-only",), proof=f"{SOURCE}/Arbeit/Quotes Benutzt.md"),
    RustfsIdentity(name="retention", policies=("retention",), proof=BUCKET),
)
ACCESS = {"runner": "fixture-runner", "quotes": "fixture-quotes", "retention": "fixture-retention"}


def config(**changes: Any) -> RustfsConfig:
    base: dict[str, Any] = {
        "buckets": (RustfsBucket(name=BUCKET), RustfsBucket(name=SOURCE)),
        "policies": POLICIES,
        "identities": IDENTITIES,
        "local_binary": BINARY,
    }
    return RustfsConfig(**{**base, **changes})


def credentials(root: str, users: dict[str, str]) -> RustfsCredentials:
    return RustfsCredentials(
        root=creds("fixture-root", root), identities={name: creds(ACCESS[name], users[name]) for name in ACCESS}
    )


def sanitize(text: str) -> str:
    for value in VALUES:
        text = text.replace(value, "<synthetic-redacted>")
    return text


def deploy(label: str, cfg: RustfsConfig, material: RustfsCredentials, *, expect: str) -> dict[str, Any]:
    state = State(Inventory(([("@local", {})], {})), Config())
    log = EVIDENCE / f"{len(PHASES):02d}-{label}.log"
    error = None
    with log.open("w") as stream, contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        try:
            connect_all(state)
            add_deploy(state, deploy_rustfs, cfg=cfg, credentials=material)
            run_ops(state)
        except Exception:
            error = traceback.format_exc()
        finally:
            operations = collect_ops(state, "@local")
            disconnect_all(state)
    raw = log.read_text() + (error or "")
    log.write_text(sanitize(raw))
    changed = [op.name for op in operations if op.changed and not op.read_only]
    failed = error is not None or any(not op.succeeded for op in operations)
    phase = {
        "phase": label,
        "expect": expect,
        "failed": failed,
        "changed": changed,
        "secret_in_log": any(value in raw for value in VALUES),
        "error": sanitize(error.strip().splitlines()[-1]) if error else None,
    }
    PHASES.append(phase)
    assert not phase["secret_in_log"], f"{label}: a synthetic secret reached the log"
    if expect == "zero":
        assert not failed, f"{label}: repeat failed: {phase['error']}"
        assert not changed, f"{label}: repeat changed {changed}"
    elif expect == "change":
        assert not failed, f"{label}: failed: {phase['error']}"
        assert changed, f"{label}: expected changes"
    else:
        assert failed, f"{label}: expected a refusal"
    return phase


class S3:
    def __init__(self) -> None:
        namespace: dict[str, Any] = {"__name__": "rustfs_helper"}
        exec(compile(HELPER.read_text(), str(HELPER), "exec"), namespace)
        self.api = namespace["Api"]("http://127.0.0.1:9020", "us-east-1")
        self.code = namespace["error_code"]

    def __call__(self, access: str, value: str, method: str, path: str, **kwargs: Any) -> tuple[int, str | None]:
        status, data = self.api.request(method, path, access, value, **kwargs)
        return status, self.code(data)


def sh(*args: str, check: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed with {result.returncode}")
    return result.stdout


def expect(label: str, actual: Any, wanted: Any) -> None:
    PHASES.append({"check": label, "actual": actual, "wanted": wanted, "ok": actual == wanted})
    assert actual == wanted, f"{label}: {actual} != {wanted}"


def main() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    root, users = secret(), {name: secret() for name in ACCESS}
    material = credentials(root, users)

    # 1. Absent mount: refused before any change; nothing is created.
    Path("/srv/plain").mkdir(parents=True, exist_ok=True)
    unmounted = config(required_mount="/srv/plain", data_dir="/srv/plain/rustfs/data")
    deploy("absent-mount-refused", unmounted, material, expect="refused")
    expect("no unit after refusal", Path("/etc/systemd/system/rustfs.service").exists(), False)
    expect("no data below unmounted path", Path("/srv/plain/rustfs").exists(), False)

    # 2. First deploy and strict repeat.
    deploy("first", config(), material, expect="change")
    deploy("repeat", config(), material, expect="zero")

    s3 = S3()
    listeners = sh("ss", "-Hltnp").splitlines()
    owned = [line.split()[3] for line in listeners if "rustfs" in line]
    expect("only the loopback API listens", owned, ["127.0.0.1:9020"])
    unit = sh("systemctl", "show", "rustfs.service", "-p", "User", "-p", "ActiveState").split()
    expect("service runs as rustfs", sorted(unit), ["ActiveState=active", "User=rustfs"])
    runner, quotes, retention = ((ACCESS[name], users[name]) for name in ("runner", "quotes", "retention"))
    expect("runner put own prefix", s3(*runner, "PUT", f"/{BUCKET}/a/one.txt", body=b"one")[0], 200)
    expect("runner get own prefix", s3(*runner, "GET", f"/{BUCKET}/a/one.txt")[0], 200)
    expect("runner foreign prefix", s3(*runner, "PUT", f"/{BUCKET}/b/x", body=b"x"), (403, "AccessDenied"))
    expect("runner no delete", s3(*runner, "DELETE", f"/{BUCKET}/a/one.txt"), (403, "AccessDenied"))
    expect("runner admin denied", s3(*runner, "GET", "/rustfs/admin/v3/list-users"), (403, "AccessDenied"))
    expect(
        "root put unicode key",
        s3("fixture-root", root, "PUT", f"/{SOURCE}/Arbeit/Quotes Benutzt.md", body="ä".encode())[0],
        200,
    )
    expect("get-only exact key", s3(*quotes, "GET", f"/{SOURCE}/Arbeit/Quotes Benutzt.md")[0], 200)
    expect("get-only neighbour", s3(*quotes, "GET", f"/{SOURCE}/Arbeit/Quotes Ungenutzt.md"), (403, "AccessDenied"))
    expect("get-only no list", s3(*quotes, "GET", f"/{SOURCE}", query=[("list-type", "2")]), (403, "AccessDenied"))
    expect("retention delete makes marker", s3(*retention, "DELETE", f"/{BUCKET}/a/one.txt")[0], 204)
    expect("current read after marker", s3(*runner, "GET", f"/{BUCKET}/a/one.txt")[0], 404)

    # 3. Identity secret rotation: one IAM change, old secret rejected.
    old_runner = users["runner"]
    users["runner"] = secret()
    rotated = credentials(root, users)
    phase = deploy("identity-rotation", config(), rotated, expect="change")
    expect("rotation changes only IAM", phase["changed"], ["Deploy RustFS | Converge declared RustFS buckets and IAM"])
    expect("old secret rejected", s3(ACCESS["runner"], old_runner, "GET", f"/{BUCKET}/a/x")[1], "SignatureDoesNotMatch")
    deploy("identity-rotation-repeat", config(), rotated, expect="zero")

    # 4. Root rotation: environment write, restart, IAM inspected after restart.
    root = secret()
    rotated = credentials(root, users)
    deploy("root-rotation", config(), rotated, expect="change")
    deploy("root-rotation-repeat", config(), rotated, expect="zero")

    # 5. Out-of-band attachment drift is repaired; a disabled user stops the run.
    admin = "/rustfs/admin/v3/"
    query = [("policyName", "retention"), ("userOrGroup", ACCESS["runner"]), ("isGroup", "false")]
    expect("drift attach", s3("fixture-root", root, "PUT", admin + "set-user-or-group-policy", query=query)[0], 200)
    phase = deploy("attachment-drift", config(), rotated, expect="change")
    expect("drift repaired by IAM only", phase["changed"], ["Deploy RustFS | Converge declared RustFS buckets and IAM"])
    status = [("accessKey", ACCESS["quotes"]), ("status", "disabled")]
    expect("disable user", s3("fixture-root", root, "PUT", admin + "set-user-status", query=status)[0], 200)
    deploy("disabled-user-refused", config(), rotated, expect="refused")
    status = [("accessKey", ACCESS["quotes"]), ("status", "enabled")]
    expect("re-enable user", s3("fixture-root", root, "PUT", admin + "set-user-status", query=status)[0], 200)
    deploy("after-reenable", config(), rotated, expect="zero")

    # 6. A stopped service is started before IAM is inspected.
    sh("systemctl", "stop", "rustfs.service")
    phase = deploy("stopped-service", config(), rotated, expect="change")
    expect("only the start changes", phase["changed"], ["Deploy RustFS | Start rustfs.service"])
    deploy("stopped-service-repeat", config(), rotated, expect="zero")

    # 7. A bind mount below the data root (same device) stops the deploy.
    inner = Path("/mnt/cryptdata/rustfs/data/bound")
    inner.mkdir()
    sh("chown", "rustfs:rustfs", str(inner))
    source = Path("/mnt/cryptdata/bind-source")
    source.mkdir()
    expect("bind source on the same device", source.stat().st_dev, inner.stat().st_dev)
    sh("mount", "--bind", str(source), str(inner))
    deploy("bind-mount-refused", config(), rotated, expect="refused")
    sh("umount", str(inner))
    inner.rmdir()
    source.rmdir()

    # 8. A symlinked ancestor of the data root is refused.
    # The data root itself exists through the alias, so only the symlink check can refuse it.
    Path("/mnt/cryptdata/real/data").mkdir(parents=True)
    sh("chown", "rustfs:rustfs", "/mnt/cryptdata/real/data")
    Path("/mnt/cryptdata/alias").symlink_to("/mnt/cryptdata/real")
    deploy("symlink-ancestor-refused", config(data_dir="/mnt/cryptdata/alias/data"), rotated, expect="refused")
    Path("/mnt/cryptdata/alias").unlink()
    Path("/mnt/cryptdata/real/data").rmdir()
    Path("/mnt/cryptdata/real").rmdir()

    # 9. A foreign-owned file below the data root stops the deploy.
    foreign = Path("/mnt/cryptdata/rustfs/data/foreign-owned")
    foreign.write_text("x")
    deploy("foreign-data-refused", config(), rotated, expect="refused")
    foreign.unlink()
    deploy("final-repeat", config(), rotated, expect="zero")


if __name__ == "__main__":
    outcome = "passed"
    try:
        main()
    except BaseException:
        outcome = "failed"
        (EVIDENCE / "failure.txt").write_text(sanitize(traceback.format_exc()))
        raise
    finally:
        (EVIDENCE / "summary.json").write_text(
            sanitize(json.dumps({"outcome": outcome, "binary": str(BINARY), "steps": PHASES}, indent=2)) + "\n"
        )
