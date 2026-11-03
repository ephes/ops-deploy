"""``RustfsAdminProvisioner`` against a real RustFS 1.0.4 server in an owned Docker container.

Skipped unless ``ECHOPORT_RUSTFS_DOCKER=1`` (``just test-echoport-rustfs``).
Starts the pinned ``rustfs/rustfs`` 1.0.4 image (by digest) on a random
loopback port, writes the environment file the RustFS deploy would write, and
runs every command of the provisioner as the deploy would (the shell commands
the fake-connector tests only compare as strings). It checks what they cannot:
the probe states, the policy round trip, the user upsert and rotation,
attaching, what the account may do afterwards, the refusals and that no
credential reaches any output. The container carries the prefix
``s3-echoport-per-target-store-`` and a random suffix and is removed afterwards.
"""

from __future__ import annotations

import functools
import json
import os
import secrets
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.services.echoport import MinioAccount
from ops_deploy.services.echoport.deploy import RustfsAdminProvisioner, render_policy

pytestmark = pytest.mark.skipif(
    os.environ.get("ECHOPORT_RUSTFS_DOCKER") != "1", reason="set ECHOPORT_RUSTFS_DOCKER=1 to start a RustFS container"
)

IMAGE = "rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2"  # 1.0.4
PREFIX = "s3-echoport-per-target-store"
ROOT_ACCESS = "fixture-root"
BUCKET = "backups"
HELPER = Path(__file__).resolve().parents[1] / "src/ops_deploy/services/rustfs/files/iam_host.py"


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=300)


@functools.cache
def helper() -> dict[str, Any]:
    """One loaded namespace, so ``Refused`` raised by ``Api`` is the class the fixture catches."""
    namespace: dict[str, Any] = {"__name__": "rustfs_iam_host"}
    exec(compile(HELPER.read_text(), "iam_host", "exec"), namespace)
    return namespace


@dataclass
class Lab:
    endpoint: str
    root_secret: str
    env_file: Path
    policy_dir: Path
    outputs: list[str]

    def run(self, command: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        result = subprocess.run(["sh", "-c", command], input=stdin, capture_output=True, text=True, timeout=120)
        self.outputs.extend((result.stdout, result.stderr))
        return result

    def ok(self, command: str, stdin: str = "") -> str:
        result = self.run(command, stdin)
        assert result.returncode == 0, result.stderr
        return result.stdout

    def s3(self, method: str, path: str, access: str, secret: str, **kwargs: Any) -> int:
        api = helper()["Api"](self.endpoint, "us-east-1")
        status, _ = api.request(method, path, access, secret, **kwargs)
        return int(status)

    def root(self, method: str, path: str, query: list[tuple[str, str]] | None = None, body: bytes = b"") -> int:
        return self.s3(method, path, ROOT_ACCESS, self.root_secret, query=query or [], body=body)


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    assert shutil.which("docker"), "ECHOPORT_RUSTFS_DOCKER=1 requires Docker"
    name = f"{PREFIX}-{uuid.uuid4().hex[:8]}"
    root_secret = secrets.token_hex(20)
    tmp = tmp_path_factory.mktemp("rustfs")
    docker(
        "run", "-d", "--name", name, "-p", "127.0.0.1::9000",
        "-e", f"RUSTFS_ACCESS_KEY={ROOT_ACCESS}", "-e", f"RUSTFS_SECRET_KEY={root_secret}",
        "-e", "RUSTFS_CONSOLE_ENABLE=false", "-e", "RUSTFS_CHECK_UPDATE=false", IMAGE,
    )  # fmt: skip
    try:
        port = docker("port", name, "9000/tcp").stdout.splitlines()[0].rpartition(":")[2]
        # What ops-deploy's RustFS deploy writes (rustfs.env.j2), pointing at the container.
        env_file = tmp / "rustfs.env"
        env_file.write_text(
            "# RustFS environment configuration\n\n"
            f'RUSTFS_ACCESS_KEY="{ROOT_ACCESS}"\nRUSTFS_SECRET_KEY="{root_secret}"\n'
            f'RUSTFS_VOLUMES="/data"\nRUSTFS_ADDRESS="127.0.0.1:{port}"\nRUSTFS_REGION="us-east-1"\n'
        )
        current = Lab(f"http://127.0.0.1:{port}", root_secret, env_file, tmp / "policies", [])
        current.policy_dir.mkdir()
        deadline = time.monotonic() + 90
        while True:
            try:
                if current.root("PUT", "/" + BUCKET) == 200:
                    break
            except helper()["Refused"]:
                pass
            assert time.monotonic() < deadline, docker("logs", name, check=False).stderr[-2000:]
            time.sleep(1)
        yield current
    finally:
        docker("rm", "--force", "--volumes", name, check=False)


def install_policy(lab: Lab, account: MinioAccount) -> str:
    document = render_policy(account)
    Path(account.policy_path).write_text(document)
    return document


def state(lab: Lab, store: RustfsAdminProvisioner, account: MinioAccount, document: str) -> str:
    return lab.ok(store.state("probe", account, document)).strip()


def test_provisioner_creates_checks_and_rotates_the_account(lab: Lab) -> None:
    account = MinioAccount(name="echoport-retention", policy_dir=PurePosixPath(lab.policy_dir))
    store = RustfsAdminProvisioner(PurePosixPath(lab.env_file))
    document = install_policy(lab, account)
    secret = secrets.token_hex(18)

    lab.ok(store.require_admin())
    assert state(lab, store, account, document) == "policy=missing user=missing"
    assert lab.run(store.state("verify", account, document)).returncode != 0

    lab.ok(store.create_policy(account))
    assert state(lab, store, account, document) == "policy=ok user=missing"
    # The server stores the policy in its own spelling; the probe still reads it as unchanged.
    lab.ok(store.create_policy(account))
    assert state(lab, store, account, document) == "policy=ok user=missing"

    lab.ok(store.add_user(account), stdin=f"{account.user}\n{secret}\n")
    assert state(lab, store, account, document) == "policy=ok user=unattached"
    lab.ok(store.attach_policy(account))
    assert state(lab, store, account, document) == "policy=ok user=attached"
    lab.ok(store.state("verify", account, document))

    # The account lists, reads and deletes in the bucket; no writes, no admin API.
    lab.root("PUT", f"/{BUCKET}/some-target/archive.tar.gz", body=b"archive")
    assert lab.s3("GET", "/" + BUCKET, account.user, secret, query=[("list-type", "2")]) == 200
    assert lab.s3("GET", f"/{BUCKET}/some-target/archive.tar.gz", account.user, secret) == 200
    assert lab.s3("PUT", f"/{BUCKET}/some-target/new.tar.gz", account.user, secret, body=b"x") == 403
    assert lab.s3("GET", "/rustfs/admin/v3/list-users", account.user, secret) == 403
    assert lab.s3("DELETE", f"/{BUCKET}/some-target/archive.tar.gz", account.user, secret) == 204

    # Upsert: a rotated secret replaces the old one.
    rotated = secrets.token_hex(18)
    lab.ok(store.add_user(account), stdin=f"{account.user}\n{rotated}\n")
    assert lab.s3("GET", "/" + BUCKET, account.user, rotated, query=[("location", "")]) == 200
    assert lab.s3("GET", "/" + BUCKET, account.user, secret, query=[("location", "")]) == 403
    lab.ok(store.state("verify", account, document))

    # A changed document reads as differing until the policy is written again.
    wider = MinioAccount(name="echoport-retention", allow_put=True, policy_dir=PurePosixPath(lab.policy_dir))
    assert state(lab, store, wider, render_policy(wider)) == "policy=differs user=attached"
    assert lab.run(store.state("verify", wider, render_policy(wider))).returncode != 0

    leaked = [value for value in (lab.root_secret, secret, rotated) if any(value in out for out in lab.outputs)]
    assert not leaked, "a credential reached the provisioner's output"


def test_attach_keeps_other_policies_and_verify_refuses_them(lab: Lab) -> None:
    account = MinioAccount(name="extra-policy", policy_dir=PurePosixPath(lab.policy_dir))
    store = RustfsAdminProvisioner(PurePosixPath(lab.env_file))
    document = install_policy(lab, account)
    other = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetBucketLocation"],
             "Resource": [f"arn:aws:s3:::{BUCKET}"]}]}  # fmt: skip
    assert lab.root("PUT", "/rustfs/admin/v3/add-canned-policy", [("name", "other")], json.dumps(other).encode()) == 200
    lab.ok(store.create_policy(account))
    lab.ok(store.add_user(account), stdin=f"{account.user}\n{secrets.token_hex(18)}\n")
    query = [("policyName", "other"), ("userOrGroup", account.user), ("isGroup", "false")]
    assert lab.root("PUT", "/rustfs/admin/v3/set-user-or-group-policy", query) == 200

    lab.ok(store.attach_policy(account))
    assert state(lab, store, account, document) == "policy=ok user=attached"
    verify = lab.run(store.state("verify", account, document))
    assert verify.returncode != 0
    assert "holds policies ['backup-extra-policy', 'other'], not exactly backup-extra-policy" in verify.stderr


def test_disabled_users_wrong_root_and_missing_environment_are_refused(lab: Lab, tmp_path: Path) -> None:
    account = MinioAccount(name="disabled-user", policy_dir=PurePosixPath(lab.policy_dir))
    store = RustfsAdminProvisioner(PurePosixPath(lab.env_file))
    lab.ok(store.add_user(account), stdin=f"{account.user}\n{secrets.token_hex(18)}\n")
    query = [("accessKey", account.user), ("status", "disabled")]
    assert lab.root("PUT", "/rustfs/admin/v3/set-user-status", query) == 200
    refused = lab.run(store.add_user(account), stdin=f"{account.user}\n{secrets.token_hex(18)}\n")
    assert refused.returncode != 0
    assert "refusing to enable or rotate it" in refused.stderr

    wrong = tmp_path / "wrong.env"
    wrong.write_text(lab.env_file.read_text().replace(lab.root_secret, secrets.token_hex(20)))
    result = lab.run(RustfsAdminProvisioner(PurePosixPath(wrong)).require_admin())
    assert result.returncode != 0
    assert result.stderr.strip() == "refused: the server rejects the declared root credentials"

    result = lab.run(RustfsAdminProvisioner(PurePosixPath(tmp_path / "absent.env")).require_admin())
    assert result.returncode != 0
    assert "environment file is not readable" in result.stderr
    assert not any(lab.root_secret in out for out in lab.outputs)
