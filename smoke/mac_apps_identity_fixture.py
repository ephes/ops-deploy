"""Owned ARM Darwin prerequisite: descriptor-only OpenSSH public-key derivation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from ops_deploy.services.macos_ssh_tunnel.identity import IdentityProbeError, probe_identity


def snapshot(root: Path) -> dict[str, tuple[int, ...]]:
    return {
        str(path.relative_to(root)): (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        for path in (root, *root.rglob("*"))
        if (value := path.lstat())
    }


def main() -> None:
    evidence = Path(os.environ["MAC_APPS_EVIDENCE_DIR"])
    evidence.mkdir(parents=True, exist_ok=True)
    root: Path | None = None
    receipt: dict[str, object] = {
        "implementation": os.environ["IMPLEMENTATION_SHA"],
        "arch": platform.machine(),
        "status": "failed",
        "limitations": [
            "Metadata observer covers the owned fixture tree, not a whole-host syscall trace.",
            "This prerequisite does not qualify identity mutation/recovery or a deployed tunnel.",
        ],
    }
    failure: BaseException | None = None
    try:
        if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
            raise RuntimeError("requires an owned disposable hosted runner")
        if platform.system() != "Darwin" or platform.machine() != "arm64" or os.geteuid() == 0:
            raise RuntimeError("requires the actual non-root ARM Darwin runner identity")
        root = Path(tempfile.mkdtemp(prefix="mac-apps-identity-", dir=Path.home()))
        key = root / "identity"
        comment = "owned-mac-apps-fixture"
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key)],
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        before = snapshot(root)
        public = " ".join(key.with_suffix(".pub").read_text().split()[:2])
        for _ in range(20):
            result = probe_identity(str(Path.home()), str(key), os.getuid(), comment)
            assert result == {"state": "current", "public_key": public}
            assert snapshot(root) == before
        receipt.update(
            current_probes=20,
            fixture_metadata_unchanged=True,
            public_sha256=hashlib.sha256(public.encode()).hexdigest(),
        )
        key.chmod(0o644)
        try:
            probe_identity(str(Path.home()), str(key), os.getuid(), comment)
        except IdentityProbeError:
            pass
        else:
            raise AssertionError("unsafe private mode accepted")
        key.chmod(0o600)
        key.with_suffix(".pub").unlink()
        assert probe_identity(str(Path.home()), str(key), os.getuid(), comment)["state"] == "drift"
        receipt["negative_mode_and_missing_public"] = True
    except BaseException as error:
        failure = error
        receipt["failure_type"] = type(error).__name__
    finally:
        try:
            if root is not None:
                shutil.rmtree(root)
        except OSError as error:
            receipt["cleanup_error_type"] = type(error).__name__
        receipt["cleanup"] = root is None or not root.exists()
        receipt["status"] = "passed" if failure is None and receipt["cleanup"] else "failed"
        (evidence / "identity-proof.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if failure is not None:
        raise failure
    if not receipt["cleanup"]:
        raise RuntimeError("owned identity fixture cleanup failed; see receipt")
    print("owned ARM descriptor identity prerequisite passed; fixture removed")


if __name__ == "__main__":
    main()
