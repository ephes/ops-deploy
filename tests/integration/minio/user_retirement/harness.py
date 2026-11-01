"""Real pyinfra, real MinIO server and client in a throwaway container; synthetic data only.

Usage: harness.py MINIO_BINARY MC_BINARY EVIDENCE_DIR. Run through run-container.sh.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import SecretStr, ValidationError
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops

from ops_deploy.services.minio.user_retirement import (
    MinioUserRetirementConfig,
    MinioUserRetirementCredentials,
    retire_minio_users,
)
from ops_deploy.testing.harness import collect_ops

ROOT = Path("/tmp/owned-user-retirement")
ENDPOINT = "http://127.0.0.1:9001"
ALIAS = "local"
ROOT_USER = "owned-root"
LEGACY = "legacy_user"
SECOND = "legacy.second"
KEEPER = "keeper_user"
GROUPED = "grouped_user"
SVC_OWNER = "svc_owner_user"
GROUP = "kept-group"
BUCKET = "owned-kept-objects"
OBJECT = b"owned synthetic object\n"
POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{BUCKET}/*"]}],
}


def canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def same(actual: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    """Names only the keys that differ; the snapshot has no credential in it."""
    differing = [key for key in expected if actual.get(key) != expected[key]]
    assert not differing, f"{label}: state changed: {differing}: {actual} != {expected}"


CONDITIONED: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{BUCKET}"],
            "Condition": {"StringLike": {"s3:prefix": [f"owned-{index}/*" for index in range(12)]}},
        }
    ],
}


class Fixture:
    def __init__(self, minio: Path, mc: Path, evidence: Path) -> None:
        self.minio, self.mc_binary, self.evidence = minio, mc, evidence
        self.password = secrets.token_hex(24)
        self.user_secrets = {name: secrets.token_hex(20) for name in (LEGACY, SECOND, KEEPER, GROUPED, SVC_OWNER)}
        self.server: subprocess.Popen[bytes] | None = None
        self.phases: list[dict[str, Any]] = []
        self.shim = ROOT / "mc-shim"
        self.argv_log = ROOT / "argv.log"
        self.fault = ROOT / "fault-condition"
        self.shared_alias = Path("/root/.mc/config.json")

    def private_values(self) -> list[str]:
        return [self.password, *self.user_secrets.values()]

    def mc(self, *args: str, body: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [str(self.mc_binary), "--json", "--config-dir", str(ROOT / "admin"), *args],
            input=body,
            capture_output=True,
            timeout=60,
        )
        if check and result.returncode:
            raise RuntimeError(f"fixture client command failed rc={result.returncode}; output withheld")
        return result

    def rows(self, *args: str) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.mc(*args).stdout.splitlines() if line.strip()]

    def start(self) -> None:
        stream = (ROOT / "server.log").open("ab")
        env = {
            "PATH": os.environ["PATH"],
            "MINIO_ROOT_USER": ROOT_USER,
            "MINIO_ROOT_PASSWORD": self.password,
            "MINIO_BROWSER": "off",
        }
        try:
            self.server = subprocess.Popen(
                [str(self.minio), "server", str(ROOT / "data"), "--address", "127.0.0.1:9001"],
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
        finally:
            stream.close()
        for _ in range(200):
            assert self.server.poll() is None, "server exited during startup"
            try:
                with urllib.request.urlopen(ENDPOINT + "/minio/health/live", timeout=2) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server readiness deadline")

    def stop(self) -> None:
        if self.server is not None:
            self.server.terminate()
            self.server.wait(timeout=30)
            self.server = None

    def seed(self) -> None:
        for path in (ROOT / "admin", ROOT / "data", self.shared_alias.parent):
            path.mkdir(parents=True, mode=0o700, exist_ok=True)
        # With the fault file present, a removal also changes one policy's Condition value:
        # a real change the comparison has to report, with the removal itself already done.
        changed: dict[str, Any] = {**CONDITIONED, "Statement": [dict(CONDITIONED["Statement"][0])]}
        changed["Statement"][0]["Condition"] = {"StringLike": {"s3:prefix": ["owned-changed/*"]}}
        (ROOT / "changed-policy.json").write_text(json.dumps(changed))
        real, fault, changed_path = (
            shlex.quote(str(path)) for path in (self.mc_binary, self.fault, ROOT / "changed-policy.json")
        )
        self.shim.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {shlex.quote(str(self.argv_log))}\n"
            f'{real} "$@"\ncode=$?\n'
            f'case "$*" in *" admin user remove "*)\n'
            f"  if [ -f {fault} ]; then\n"
            f'    {real} --json --config-dir "$3" admin policy create {ALIAS} owned-conditioned '
            f"{changed_path} >/dev/null\n"
            f"  fi;;\nesac\nexit $code\n"
        )
        self.shim.chmod(0o755)
        self.start()
        alias = {"url": ENDPOINT, "accessKey": ROOT_USER, "secretKey": self.password, "api": "S3v4", "path": "auto"}
        self.mc("alias", "import", ALIAS, body=json.dumps(alias).encode())
        self.shared_alias.write_text(json.dumps({"version": "10", "aliases": {"untouched": alias}}))
        self.shared_alias.chmod(0o600)
        for user, value in self.user_secrets.items():
            self.mc("admin", "user", "add", ALIAS, user, value)
        self.mc("mb", f"{ALIAS}/{BUCKET}")
        self.mc("pipe", f"{ALIAS}/{BUCKET}/known.txt", body=OBJECT)
        document = ROOT / "keeper-policy.json"
        document.write_text(json.dumps(POLICY))
        self.mc("admin", "policy", "create", ALIAS, "owned-keeper", str(document))
        document.write_text(json.dumps(CONDITIONED))
        self.mc("admin", "policy", "create", ALIAS, "owned-conditioned", str(document))
        self.mc("admin", "policy", "attach", ALIAS, "readwrite", "--user", LEGACY)
        self.mc("admin", "policy", "attach", ALIAS, "owned-keeper", "--user", SECOND)
        self.mc("admin", "policy", "attach", ALIAS, "owned-keeper", "--user", KEEPER)
        self.mc("admin", "group", "add", ALIAS, GROUP, KEEPER, GROUPED)
        self.mc("admin", "user", "svcacct", "add", ALIAS, SVC_OWNER, "--access-key", "owned-svc-key")

    def state(self) -> dict[str, Any]:
        users = {
            row["accessKey"]: {key: row.get(key) for key in ("policyName", "userStatus", "memberOf")}
            for row in self.rows("admin", "user", "list", ALIAS)
        }
        # The real server returns action lists in a varying order; compare them as sets.
        policies = {
            row["policy"]: canonical(self.rows("admin", "policy", "info", ALIAS, row["policy"])[0]["policyInfo"])
            for row in self.rows("admin", "policy", "list", ALIAS)
        }
        group = self.rows("admin", "group", "info", ALIAS, GROUP)[0]
        group["members"] = sorted(group.get("members") or [])
        buckets = sorted(row["key"] for row in self.rows("ls", ALIAS))
        known = self.mc("cat", f"{ALIAS}/{BUCKET}/known.txt").stdout
        accounts = [row["accessKey"] for row in self.rows("admin", "user", "svcacct", "list", ALIAS, SVC_OWNER)]
        return {
            "users": users,
            "policies": policies,
            "group": {key: group.get(key) for key in ("groupName", "members", "groupStatus")},
            "buckets": buckets,
            "object_sha256": hashlib.sha256(known).hexdigest(),
            "service_accounts": accounts,
            "shared_alias_sha256": hashlib.sha256(self.shared_alias.read_bytes()).hexdigest(),
        }

    def credential_works(self, access: str, secret: str) -> bool:
        probe = ROOT / "probe"
        probe.mkdir(mode=0o700, exist_ok=True)
        base = [str(self.mc_binary), "--json", "--config-dir", str(probe)]
        alias = {"url": ENDPOINT, "accessKey": access, "secretKey": secret, "api": "S3v4", "path": "auto"}
        subprocess.run([*base, "alias", "import", "probe"], input=json.dumps(alias).encode(), capture_output=True)
        result = subprocess.run([*base, "stat", f"probe/{BUCKET}/known.txt"], capture_output=True, timeout=60)
        text = result.stdout.decode()
        if "InvalidAccessKeyId" in text:
            return False
        return result.returncode == 0 or "AccessDenied" in text

    def config(self, users: tuple[str, ...], **fields: Any) -> MinioUserRetirementConfig:
        return MinioUserRetirementConfig(users=users, mc_bin_path=str(self.shim), protected=(KEEPER,), **fields)

    def credentials(self, password: str | None = None, protected: tuple[str, ...] = ()) -> Any:
        return MinioUserRetirementCredentials(
            root_user=SecretStr(ROOT_USER),
            root_password=SecretStr(password or self.password),
            protected_access=tuple(SecretStr(value) for value in protected),
        )

    def deploy(self, label: str, cfg: Any, credentials: Any, *, plan: bool = False) -> dict[str, Any]:
        """One real pyinfra run on the local host; ``plan`` stops where the CLI's --dry stops."""
        state = State(Inventory(([("@local", {})], {})), Config())
        stream = io.StringIO()
        error = None
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            try:
                connect_all(state)
                add_deploy(state, retire_minio_users, cfg=cfg, credentials=credentials)
                # pyinfra decides "would change" while the operation is added, as under --dry.
                planned = [
                    (
                        ", ".join(sorted(state.get_op_meta(op).names)),
                        state.get_op_data_for_host(host, op).operation_meta._maybe_is_change,
                    )
                    for op in state.get_op_order()
                    for host in state.inventory
                ]
                if not plan:
                    run_ops(state)
            except Exception as exc:  # The refusal's text is fixed and is asserted below.
                error = f"{type(exc).__name__}: {exc}"
                planned = []
            finally:
                operations = collect_ops(state, "@local")
                disconnect_all(state)
        raw = stream.getvalue()
        assert not any(value in raw for value in self.private_values()), f"{label}: a secret reached the output"
        (self.evidence / f"{label}.log").write_text(raw)
        return {
            "label": label,
            "error": error,
            "planned": planned,
            "managed": [op.name for op in operations if op.changed and not op.read_only],
            "failed": [op.name for op in operations if not op.succeeded],
        }

    def refused(self, label: str, cfg: Any, credentials: Any, reason: str) -> None:
        before = self.state()
        row = self.deploy(label, cfg, credentials)
        assert row["error"] is not None, label
        assert reason in row["error"], f"{label}: {row['error']}"
        assert row["managed"] == [], label
        same(self.state(), before, label)
        self.phases.append({**row, "state_unchanged": True})

    def invalid_config(self, label: str, **fields: Any) -> None:
        try:
            MinioUserRetirementConfig(**fields)
        except ValidationError as error:
            self.phases.append({"label": label, "error": f"ValidationError x{error.error_count()}"})
            return
        raise AssertionError(f"{label}: config was accepted")

    def run(self) -> None:
        self.seed()
        start = self.state()
        assert start["users"][LEGACY]["policyName"] == "readwrite"
        assert start["service_accounts"] == ["owned-svc-key"]

        # Plan: says one change, runs nothing.
        plan = self.deploy("plan", self.config((LEGACY, SECOND)), self.credentials(), plan=True)
        assert plan["error"] is None, plan
        assert plan["planned"][0][1] is True, plan
        same(self.state(), start, "plan")
        self.phases.append({**plan, "state_unchanged": True})

        # Refusals, all before any change.
        self.invalid_config("refuse-empty-list", users=())
        self.invalid_config("refuse-bad-name", users=("../foreign",))
        self.invalid_config("refuse-flag-name", users=("--help",))
        self.invalid_config("refuse-duplicates", users=(LEGACY, LEGACY))
        self.invalid_config("refuse-protected-config", users=(LEGACY,), protected=(LEGACY,))
        self.refused("refuse-root-user", self.config((ROOT_USER,)), self.credentials(), "a listed user is protected")
        self.refused(
            "refuse-secret-protected",
            self.config((LEGACY,)),
            self.credentials(protected=(LEGACY,)),
            "a listed user is protected",
        )
        self.refused(
            "refuse-group-member-whole-list",
            self.config((LEGACY, GROUPED)),
            self.credentials(),
            "belongs to a group",
        )
        self.refused(
            "refuse-service-account-owner",
            self.config((LEGACY, SVC_OWNER)),
            self.credentials(),
            "owns service accounts",
        )
        self.refused(
            "refuse-wrong-admin-credential",
            self.config((LEGACY,)),
            self.credentials(password=secrets.token_hex(24)),
            "the admin alias is not healthy",
        )
        self.stop()
        row = self.deploy("refuse-server-down", self.config((LEGACY,)), self.credentials())
        assert row["error"], row
        assert "the admin alias is not healthy" in row["error"], row
        assert row["managed"] == []
        self.start()
        same(self.state(), start, "restart")
        self.phases.append({**row, "state_unchanged": True})

        # First removal: exactly the two listed users go.
        assert self.credential_works(LEGACY, self.user_secrets[LEGACY])
        first = self.deploy("first", self.config((LEGACY, SECOND)), self.credentials())
        assert first["error"] is None, first
        assert first["failed"] == [], first
        assert [name.split(" | ")[-1] for name in first["managed"]] == ["Remove listed MinIO users"], first
        after = self.state()
        expected = json.loads(json.dumps(start))
        del expected["users"][LEGACY], expected["users"][SECOND]
        same(after, expected, "first")
        assert not self.credential_works(LEGACY, self.user_secrets[LEGACY])
        assert not self.credential_works(SECOND, self.user_secrets[SECOND])
        assert self.credential_works(KEEPER, self.user_secrets[KEEPER])
        for user in (LEGACY, SECOND):
            reply = self.mc("admin", "user", "info", ALIAS, user, check=False)
            assert reply.returncode
            assert b"XMinioAdminNoSuchUser" in reply.stdout
        self.phases.append({**first, "only_listed_users_changed": True, "retired_keys_rejected": True})

        # Repeat: zero managed operations, whole state equal.
        for label in ("repeat-1", "repeat-2"):
            repeat = self.deploy(label, self.config((LEGACY, SECOND)), self.credentials())
            assert repeat["error"] is None, repeat
            assert repeat["failed"] == [], repeat
            assert repeat["managed"] == [], repeat
            same(self.state(), after, label)
            self.phases.append({**repeat, "state_unchanged": True})

        # A partial list: only the user still there goes.
        self.mc("admin", "user", "add", ALIAS, SECOND, self.user_secrets[SECOND])
        partial = self.deploy("partial-list", self.config((LEGACY, SECOND)), self.credentials())
        assert len(partial["managed"]) == 1, partial
        assert partial["error"] is None, partial
        same(self.state(), after, "partial-list")
        self.phases.append({**partial, "state_unchanged": True})

        # This server's raw Condition order over repeated reads: evidence for the comparison above.
        forms = {
            json.dumps(self.rows("admin", "policy", "info", ALIAS, "owned-conditioned")[0]["policyInfo"]["Policy"])
            for _ in range(40)
        }
        self.phases.append({"label": "condition-order", "raw_forms_in_40_reads": len(forms)})

        # A real Condition change during a removal fails, with the removal done.
        self.mc("admin", "user", "add", ALIAS, SECOND, self.user_secrets[SECOND])
        self.fault.touch()
        drift = self.deploy("real-condition-change", self.config((LEGACY, SECOND)), self.credentials())
        self.fault.unlink()
        assert drift["failed"], drift
        assert drift["managed"] == [], drift
        log = (self.evidence / "real-condition-change.log").read_text()
        assert "state outside the listed users changed" in log, "the failure did not name the comparison"
        reply = self.mc("admin", "user", "info", ALIAS, SECOND, check=False)
        assert b"XMinioAdminNoSuchUser" in reply.stdout, "the removal did not happen"
        self.phases.append({**drift, "failed_after_removal": True})

        # Nothing secret on any client command line, the listed names only in their own removal.
        argv = self.argv_log.read_text()
        assert not any(value in argv for value in self.private_values()), "a secret reached a client command line"
        assert ROOT_USER not in argv, "the root user reached a client command line"
        removals = [line.split()[-1] for line in argv.splitlines() if " admin user remove " in line]
        assert removals == [LEGACY, SECOND, SECOND, SECOND], removals
        for other in (KEEPER, GROUPED):
            assert f" admin user remove {ALIAS} {other}" not in argv
        self.phases.append({"label": "command-lines", "removals": removals, "secrets_on_argv": False})


def main() -> int:
    minio, mc, evidence = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    ROOT.mkdir(mode=0o700, parents=True)
    fixture = Fixture(minio, mc, evidence)
    versions = {
        name: subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=30).stdout.splitlines()[
            0
        ]
        for name, path in (("minio", minio), ("mc", mc))
    }
    summary: dict[str, Any] = {"component": "user-retirement", "versions": versions, "success": False}
    try:
        fixture.run()
        summary["success"] = True
    finally:
        fixture.stop()
        summary["phases"] = fixture.phases
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")
    print(json.dumps({"success": summary["success"], "phases": len(fixture.phases), "versions": versions}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
