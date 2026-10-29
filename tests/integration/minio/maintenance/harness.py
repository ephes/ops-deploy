"""Fresh offline KVM exact-binary named-policy maintenance matrix, synthetic only.

No normal deployment, service install, root rotation or S4 matrix is replayed.
The original tagged-block oracle is a source-bound narrow transcription, not an
unmodified Ansible play execution. Native status remains pending until this runs.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict
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

from ops_deploy.services.minio.policy_rollback import (
    MinioPolicyRollbackConfig,
    MinioPolicyRollbackCredentials,
    rollback_minio_policy,
)
from ops_deploy.testing.harness import collect_ops

ROOT = Path("/srv/ops-owned-minio-policy")
ARTIFACTS = Path("/opt/minio-artifacts")
POLICIES = Path("/etc/minio/policies")
ENDPOINT = "http://127.0.0.1:9001"
ALIAS = "local"
ACCESS = "owned-user"
FOREIGN = "owned-foreign"
BUCKET = "owned-policy-objects"
DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{BUCKET}/*"]}],
}
OBJECT = b"owned synthetic maintenance object\n"


def metadata(path: Path) -> dict[str, Any] | None:
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
    }


class Fixture:
    def __init__(self, evidence: Path) -> None:
        self.evidence = evidence
        self.private = [secrets.token_hex(24) for _ in range(4)]
        self.server: subprocess.Popen[bytes] | None = None
        self.phases: list[dict[str, Any]] = []
        self.alias_before = b""
        self.cfg = MinioPolicyRollbackConfig(policy="owned-policy-initial", mc_bin_path=str(ROOT / "fault-mc"))
        self.credentials = MinioPolicyRollbackCredentials(
            root_user=SecretStr("owned-root"), root_password=SecretStr(self.private[0]), access=SecretStr(ACCESS)
        )

    def sanitized(self, text: str) -> str:
        for value in self.private:
            text = text.replace(value, "<owned-redacted>")
        return text

    def write(self, name: str, data: Any) -> None:
        (self.evidence / name).write_text(self.sanitized(json.dumps(data, indent=2, default=str)) + "\n")

    def mc(self, *args: str, body: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [str(ARTIFACTS / "mc"), "--json", "--config-dir", str(ROOT / "admin"), *args],
            input=body,
            capture_output=True,
            timeout=60,
        )
        if check and result.returncode:
            raise RuntimeError(f"owned mc command failed rc={result.returncode}; argv and output withheld")
        return result

    def policy_state(self, policy: str) -> dict[str, Any]:
        info = self.mc("admin", "policy", "info", ALIAS, policy, check=False)
        rows = [json.loads(line) for line in info.stdout.splitlines() if line]
        if info.returncode:
            assert len(rows) == 1
            assert rows[0]["error"]["cause"]["error"]["Code"] == "XMinioAdminNoSuchPolicy", (
                "unknown independent info failure"
            )
            return {"present": False, "users": []}
        entities = self.mc("admin", "policy", "entities", ALIAS, "--policy", policy)
        rows = [json.loads(line) for line in entities.stdout.splitlines() if line]
        users: set[str] = set()
        for row in rows:
            for mapping in row.get("result", {}).get("policyMappings", []):
                if mapping.get("policy") == policy:
                    users.update(mapping.get("users") or [])
        return {"present": True, "users": sorted(users)}

    def account_state(self, user: str) -> dict[str, Any]:
        result = self.mc("admin", "user", "info", ALIAS, user)
        rows = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(rows) == 1
        row = rows[0]
        assert row["status"] == "success"
        assert row["userStatus"] == "enabled"
        # Selected policy attachment is deliberately mutable; credentials and
        # unselected account bodies are never persisted in the evidence.
        return {"identity": user, "enabled": True}

    def snapshot(self) -> dict[str, Any]:
        assert self.server is not None
        assert self.server.poll() is None
        obj = self.mc("cat", f"{ALIAS}/{BUCKET}/known.txt").stdout
        assert obj == OBJECT
        alias_path = Path("/root/.mc/config.json")
        return {
            "server_pid": self.server.pid,
            "server_running": self.server.poll() is None,
            "known_object_sha256": hashlib.sha256(obj).hexdigest(),
            "foreign_alias_equal": alias_path.read_bytes() == self.alias_before,
            "foreign_alias_metadata": metadata(alias_path),
            "binaries": {
                name: {
                    "metadata": metadata(ARTIFACTS / name),
                    "sha256": hashlib.sha256((ARTIFACTS / name).read_bytes()).hexdigest(),
                }
                for name in ("mc", "minio")
            },
            "unrelated_policy": self.policy_state("owned-policy-unrelated"),
            "accounts": {user: self.account_state(user) for user in (ACCESS, FOREIGN)},
            "named_policy": self.policy_state(self.cfg.policy),
            "local_policy_metadata": metadata(Path(self.cfg.policy_file)),
        }

    def setup(self) -> None:
        assert not ROOT.exists()
        assert not POLICIES.exists()
        assert not Path("/root/.mc").exists()
        ROOT.mkdir(mode=0o700)
        POLICIES.mkdir(mode=0o700, parents=True)
        (ROOT / "data").mkdir()
        (ROOT / "admin").mkdir(mode=0o700)
        shutil.copyfile(Path(__file__).with_name("fault-mc.py"), ROOT / "fault-mc")
        (ROOT / "fault-mc").chmod(0o700)
        self.fault("none")
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(ROOT),
            "MINIO_ROOT_USER": "owned-root",
            "MINIO_ROOT_PASSWORD": self.private[0],
        }
        # Output remains in a private fixture file, and is sanitized into the
        # collected receipt in finally. No server command/environment is printed.
        stream = (ROOT / "server.log").open("wb")
        try:
            self.server = subprocess.Popen(
                [
                    str(ARTIFACTS / "minio"),
                    "server",
                    str(ROOT / "data"),
                    "--address",
                    "127.0.0.1:9001",
                    "--console-address",
                    "127.0.0.1:9002",
                ],
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
        finally:
            stream.close()
        for _ in range(100):
            assert self.server.poll() is None, "owned server exited during startup"
            try:
                with urllib.request.urlopen(ENDPOINT + "/minio/health/live", timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("owned loopback MinIO readiness deadline")
        alias = {
            "url": ENDPOINT,
            "accessKey": "owned-root",
            "secretKey": self.private[0],
            "api": "S3v4",
            "path": "auto",
        }
        self.mc("alias", "import", ALIAS, body=json.dumps(alias).encode())
        Path("/root/.mc").mkdir(mode=0o700)
        self.alias_before = json.dumps(
            {"version": "10", "aliases": {"untouched": {**alias, "secretKey": self.private[3]}}}
        ).encode()
        Path("/root/.mc/config.json").write_bytes(self.alias_before)
        Path("/root/.mc/config.json").chmod(0o600)
        for user, password in ((ACCESS, self.private[1]), (FOREIGN, self.private[2])):
            self.mc("admin", "user", "add", ALIAS, user, password)
        self.mc("mb", f"{ALIAS}/{BUCKET}")
        self.mc("pipe", f"{ALIAS}/{BUCKET}/known.txt", body=OBJECT)
        self.create_policy("owned-policy-unrelated", users=(FOREIGN,), local=False)

    def create_policy(
        self, name: str, *, users: tuple[str, ...] = (ACCESS,), local: bool = True, arbitrary: bool = False
    ) -> None:
        document = (
            DOCUMENT
            if not arbitrary
            else {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": [f"arn:aws:s3:::{BUCKET}"]}
                ],
            }
        )
        path = ROOT / "setup-document.json"
        path.write_text(json.dumps(document))
        self.mc("admin", "policy", "create", ALIAS, name, str(path))
        for user in users:
            self.mc("admin", "policy", "attach", ALIAS, name, "--user", user)
        if local:
            (POLICIES / (name + ".json")).write_text(json.dumps(document))
        self.cfg = self.cfg.model_copy(update={"policy": name})
        self.fault("none")

    def fault(self, mode: str) -> None:
        (ROOT / "fault.json").write_text(json.dumps({"mode": mode, "policy": self.cfg.policy}))
        (ROOT / "removed").unlink(missing_ok=True)

    def run(self, label: str, *, failure: bool = False, zero: bool = False) -> dict[str, Any]:
        before = self.snapshot()
        self.write(label + "-before.json", before)
        self.write("inflight.json", {"label": label, "completed_phases": len(self.phases)})
        state = State(Inventory(([("@local", {})], {})), Config())
        uploads: list[bool] = []
        original_put = LocalConnector.put_file
        error = None
        stream = io.StringIO()

        def put(*args: Any, **kwargs: Any) -> Any:
            uploads.append(True)
            return original_put(*args, **kwargs)

        with (
            patch.object(LocalConnector, "put_file", put),
            contextlib.redirect_stdout(stream),
            contextlib.redirect_stderr(stream),
        ):
            try:
                connect_all(state)
                add_deploy(state, rollback_minio_policy, cfg=self.cfg, credentials=self.credentials)
                run_ops(state)
            except Exception as exc:
                error = type(exc).__name__  # Exception text may include command data.
            finally:
                operations = collect_ops(state, "@local")
                disconnect_all(state)
        raw = stream.getvalue()
        exposed = any(value in raw for value in self.private)
        (self.evidence / (label + ".log")).write_text(self.sanitized(raw))
        after = self.snapshot()
        managed = [op.name for op in operations if op.changed and not op.read_only]
        failed = [op.name for op in operations if not op.succeeded]
        row = {
            "label": label,
            "operations": [asdict(op) for op in operations],
            "managed": managed,
            "uploads": len(uploads),
            "error": error,
            "failed": failed,
            "before": before,
            "after": after,
            "expected_fault": failure,
            "secret_logged": exposed,
        }
        self.write(label + ".json", row)
        self.phases.append(
            {
                key: row[key]
                for key in ("label", "managed", "uploads", "error", "failed", "expected_fault", "secret_logged")
            }
        )
        self.write("summary.json", {"component": "policy-rollback", "success": False, "phases": self.phases})
        assert bool(error or failed) == failure, label
        assert not exposed, label
        assert not uploads, label
        for key in (
            "server_pid",
            "server_running",
            "known_object_sha256",
            "foreign_alias_metadata",
            "binaries",
            "unrelated_policy",
            "accounts",
        ):
            assert before[key] == after[key], (label, key)
        assert before["foreign_alias_equal"], label
        assert after["foreign_alias_equal"], label
        if zero:
            assert not managed, label
            assert before == after, label
        return row

    def original_foreign_holder(self) -> dict[str, Any]:
        """Execute the nine original tagged tasks with only the exact-mc path changed."""
        source = Path(__file__).with_name("original-rollback.yml")
        assert (
            hashlib.sha256(source.read_bytes()).hexdigest()
            == "d8090cfa479c44ec4272c64ceb6e5f50b574e1468a347465284273b1c33141e5"
        )
        tasks = yaml.safe_load(source.read_text())
        substitutions = 0
        for task in tasks:
            command = task.get("ansible.builtin.command")
            if command is not None:
                assert command["argv"][0] == "/usr/local/bin/mc"
                command["argv"][0] = str(ARTIFACTS / "mc")
                substitutions += 1
        assert substitutions == 5
        play = [
            {
                "hosts": "all",
                "gather_facts": False,
                "vars": {
                    "daybook_weeknotes_source_policy_name": self.cfg.policy,
                    "daybook_sessions_secrets": {"aws_access_key_id": ACCESS},
                },
                "environment": {"MC_CONFIG_DIR": str(ROOT / "admin")},
                "tasks": tasks,
            }
        ]
        path = ROOT / "original-owned.yml"
        path.write_text(yaml.safe_dump(play, sort_keys=False))
        before = self.snapshot()
        self.write("14-original-foreign-before.json", before)
        result = subprocess.run(
            ["/opt/minio-ansible/bin/ansible-playbook", "-i", "localhost,", "-c", "local", str(path)],
            capture_output=True,
            text=True,
            timeout=300,
            env={"PATH": "/usr/bin:/bin", "HOME": str(ROOT), "ANSIBLE_NOCOLOR": "1"},
        )
        output = result.stdout + result.stderr
        (self.evidence / "14-original-foreign.log").write_text(self.sanitized(output))
        after = self.snapshot()
        row = {
            "exit": result.returncode,
            "before": before,
            "after": after,
            "scope": (
                "nine original tagged tasks; five mc executable paths bound to exact artifact, "
                "synthetic variables/config-dir; not whole deployment"
            ),
        }
        self.write("14-original-foreign.json", row)
        assert not any(value in output for value in self.private)
        assert result.returncode in {0, 2}, "original task invocation/runtime failure"
        if result.returncode == 2:
            # Do not attribute an arbitrary Ansible failure to MinIO's holder
            # behavior. Require the actual failed task and independent partial
            # detach/protected-file observations before making that comparison.
            tasks_seen = re.findall(r"TASK \[([^]]+)\]", result.stdout)
            assert tasks_seen[-1] == "Remove detached dedicated Daybook weeknotes source policy"
            assert after["named_policy"] == {"present": True, "users": [FOREIGN]}
            assert before["local_policy_metadata"] == after["local_policy_metadata"]
        else:
            assert after["named_policy"] == {"present": False, "users": []}
            assert after["local_policy_metadata"] is None
        for key in (
            "server_pid",
            "server_running",
            "known_object_sha256",
            "foreign_alias_metadata",
            "binaries",
            "unrelated_policy",
            "accounts",
        ):
            assert before[key] == after[key], key
        assert before["foreign_alias_equal"]
        assert after["foreign_alias_equal"]
        return row

    def close(self) -> None:
        if self.server is not None:
            if self.server.poll() is None:
                self.server.terminate()
                try:
                    self.server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.server.kill()
                    self.server.wait(timeout=10)
            self.write("owned-server-exit.json", {"pid": self.server.pid, "exit": self.server.returncode})
        path = ROOT / "server.log"
        if path.exists():
            (self.evidence / "owned-server.log").write_text(self.sanitized(path.read_text(errors="replace")))


def admission(evidence: Path) -> None:
    assert os.geteuid() == 0
    assert os.uname().machine == "x86_64"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() == "kvm"
    assert not os.environ.get("GITHUB_ACTIONS")
    assert not os.environ.get("RUNNER_ENVIRONMENT")
    assert evidence == Path("/var/tmp/minio-evidence")
    assert Path("/etc/ops-minio-component").read_text().strip() == "policy-rollback"
    marker = json.loads(Path("/var/tmp/minio-owned-guest.json").read_text())
    assert marker["run"] == Path("/etc/ops-minio-owned-id").read_text().strip()
    assert marker["machine"] == Path("/etc/machine-id").read_text().strip()
    artifact = json.loads((evidence / "installed-artifact.json").read_text())
    assert artifact["kind"] == "kvm-owned"
    assert artifact["run"] == marker["run"]
    assert artifact["machine_id"] == marker["machine"]
    assert artifact["implementation_sha"] == os.environ["IMPLEMENTATION_SHA"]
    assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip", "-j", "address"]))} == {"lo"}
    assert not Path("/etc/default/minio").exists()
    assert not Path("/etc/systemd/system/minio.service").exists()


def matrix(fixture: Fixture) -> None:
    fixture.setup()
    fixture.create_policy("owned-policy-attached")
    fixture.run("01-attached")
    fixture.run("02-attached-repeat", zero=True)
    fixture.create_policy("owned-policy-detached", users=())
    fixture.run("03-detached")
    fixture.run("04-detached-repeat", zero=True)
    fixture.cfg = fixture.cfg.model_copy(update={"policy": "owned-policy-absent"})
    fixture.fault("none")
    Path(fixture.cfg.policy_file).write_text(json.dumps(DOCUMENT))
    fixture.run("05-absent-local-file")
    fixture.run("06-all-absent-repeat", zero=True)
    fixture.create_policy("owned-policy-arbitrary", arbitrary=True)
    fixture.run("07-arbitrary-named-document")
    fixture.run("08-arbitrary-repeat", zero=True)
    for index, mode in enumerate(
        ("detach-before", "detach-after", "remove-before", "info-after-remove", "info-before"), 9
    ):
        fixture.create_policy(f"owned-policy-fault-{index}")
        fixture.fault(mode)
        row = fixture.run(f"{index:02}-fault-{mode}", failure=mode != "detach-after")
        before, after = row["before"], row["after"]
        if mode in {"detach-before", "info-before"}:
            assert before == after  # Actual snapshot equality, not inferred from failed op.
        elif mode == "remove-before":
            assert after["named_policy"] == {"present": True, "users": []}
            assert before["local_policy_metadata"] == after["local_policy_metadata"]
        elif mode == "info-after-remove":
            assert after["named_policy"] == {"present": False, "users": []}
            assert before["local_policy_metadata"] == after["local_policy_metadata"]
        fixture.fault("none")
        fixture.run(f"{index:02}-ordinary-retry", zero=mode == "detach-after")
        fixture.run(f"{index:02}-strict-repeat", zero=True)
    fixture.create_policy("owned-policy-foreign-original", users=(ACCESS, FOREIGN))
    original = fixture.original_foreign_holder()
    fixture.create_policy("owned-policy-foreign-typed", users=(ACCESS, FOREIGN))
    typed = fixture.run("15-foreign-typed", failure=original["exit"] != 0)
    assert typed["after"]["named_policy"] == original["after"]["named_policy"]
    assert (typed["after"]["local_policy_metadata"] is None) == (original["after"]["local_policy_metadata"] is None)
    fixture.write(
        "foreign-holder-comparison.json",
        {
            "original_exit": original["exit"],
            "typed_failed": bool(typed["error"] or typed["failed"]),
            "same_named_outcome": True,
            "same_local_absence": True,
            "actual_server_removal_behavior": "removed" if original["exit"] == 0 else "refused-after-detachment",
        },
    )
    if original["exit"] == 0:
        fixture.run("16-foreign-repeat", zero=True)


def main() -> None:
    evidence = Path(sys.argv[1])
    admission(evidence)
    fixture = Fixture(evidence)
    try:
        matrix(fixture)
        fixture.write("summary.json", {"component": "policy-rollback", "success": True, "phases": fixture.phases})
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
