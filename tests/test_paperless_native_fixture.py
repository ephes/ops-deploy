"""Local safety/receipt checks; these do not qualify the native application."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import SecretStr
from pyinfra.connectors.local import LocalConnector

from tests.integration.paperless import application_matrix, evidence, harness


def test_native_guard_refuses_local_execution_before_any_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("host command must not run outside the owned guest")

    monkeypatch.setattr(harness, "command", forbidden)
    with pytest.raises(AssertionError):
        harness.main()
    assert not harness.OWNED_ADMITTED


def test_bash_runner_refuses_local_environment_before_docker() -> None:
    path = Path(__file__).parent / "integration/paperless/run-owned.sh"
    result = subprocess.run(
        ["bash", str(path)], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True, check=False, timeout=10
    )
    assert result.returncode != 0
    assert not result.stdout
    assert not result.stderr


def test_complete_snapshot_keeps_private_bytes_and_digests_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    private = b"owned-secret-must-stay-in-memory"
    snapshot = harness.Snapshot({"file": {"inode": 123, "mtime_ns": 456}}, {"/synthetic/env": private})
    receipt = harness.snapshot_receipt("phase", "before", snapshot)
    raw = gzip.decompress((tmp_path / receipt["file"]).read_bytes())
    assert json.loads(raw) == snapshot.public
    assert private not in raw
    assert hashlib.sha256(private).hexdigest().encode() not in raw
    assert receipt == harness.snapshot_receipt("phase", "before", snapshot)


def test_log_bound_counts_utf8_bytes_and_refuses_before_extra_write(tmp_path: Path) -> None:
    path = tmp_path / "raw-private.log"
    with path.open("w") as stream, harness.BoundedLog(stream, limit=5) as log:
        assert log.write("ä") == 1
        assert log.write("abc") == 3
        with pytest.raises(RuntimeError, match="exceeds bound"):
            log.write("d")
    assert path.read_text() == "äabc"


def test_split_synthetic_log_value_is_redacted_after_complete_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "owned-only-value"
    monkeypatch.setattr(harness, "VALUES", [secret])
    path = tmp_path / "raw-private.log"
    with path.open("w") as stream, harness.BoundedLog(stream) as log:
        log.write(secret[:5])
        log.write(secret[5:])
    assert harness.sanitize(path.read_text()) == "<synthetic-redacted>"


@pytest.mark.parametrize("split", range(1, 16))
def test_streamed_log_withholds_secret_split_across_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: int
) -> None:
    secret = "synthetic-value!"
    monkeypatch.setattr(harness, "VALUES", [secret])
    raw, public = tmp_path / "raw", tmp_path / "public"
    with raw.open("w") as r, public.open("w") as p, harness.BoundedLog(r, sanitized_stream=p) as log:
        log.write("begin " + secret[:split])
        log.flush()
        assert secret[:split] not in public.read_text()
        log.write(secret[split:] + " end " + "x" * 100)
        log.flush()
        assert secret not in public.read_text()
        assert "<synthetic-redacted>" in public.read_text()


def test_actual_timeout_keeps_sanitized_partial_evidence_and_no_fake_completion(tmp_path: Path) -> None:
    root, output = tmp_path / "private", tmp_path / "evidence"
    root.mkdir()
    output.mkdir()
    program = """import sys,time
from pathlib import Path
from tests.integration.paperless import harness as h
h.ROOT=Path(sys.argv[1]);h.EVIDENCE=Path(sys.argv[2])
h.VALUES=['owned-split-secret-value']
h.snapshot=lambda cfg:h.Snapshot({'owned':True},{})
h.connect_all=lambda state:None
h.disconnect_all=lambda state:None
def slow(*args,**kwargs):
 print('progress '+h.VALUES[0][:7],end='',flush=True)
 print(h.VALUES[0][7:]+' safe-prefix '+'x'*100,flush=True)
 (h.EVIDENCE/'timeout-ready.json').write_text('{"ready":true}')
 time.sleep(30)
h.add_deploy=slow
h.deploy('owned-timeout')
"""
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.Popen(
        [sys.executable, "-c", program, str(root), str(output)],
        cwd=repo,
        env=dict(os.environ, PYTHONPATH=str(repo)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while not (output / "timeout-ready.json").exists():
            assert proc.poll() is None, "owned child failed before readiness"
            assert time.monotonic() < deadline, "owned child did not reach readiness"
            time.sleep(0.02)
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=0.1)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)
    assert (output / "owned-timeout-started.json").exists()
    assert not (output / "owned-timeout.json").exists()
    assert not (output / "owned-timeout-after.json.gz").exists()
    log = (output / "owned-timeout.log").read_text()
    assert "<synthetic-redacted>" in log
    assert "safe-prefix" in log
    assert "owned-split-secret-value" not in log
    progress = [json.loads(line) for line in (output / "owned-timeout-progress.log").read_text().splitlines()]
    assert progress[-1]["event"] == "prepare-start"
    assert all(row["utc"] and row["elapsed_seconds"] >= 0 for row in progress)
    manifest = evidence.manifest(output)
    collected = manifest["files"]
    assert isinstance(collected, dict)
    assert "owned-timeout-before.json.gz" in collected
    assert not any("private" in name for name in collected)


@pytest.mark.parametrize(("case", "expected"), [("current", "70m"), ("upgrade", "100m")])
def test_runner_keeps_finite_case_specific_deadline(case: str, expected: str) -> None:
    source = (Path(__file__).parent / "integration/paperless/run-owned.sh").read_text()
    selector = source[source.index("GUEST_DEADLINE=") : source.index('timeout "$GUEST_DEADLINE"')]
    result = subprocess.run(
        ["bash", "-euc", selector + '\nprintf "%s" "$GUEST_DEADLINE"'],
        env={"PAPERLESS_FIXTURE_CASE": case},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout == expected


def test_actual_local_operation_callback_records_names_without_command_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.operation import add_op
    from pyinfra.api.operations import run_ops
    from pyinfra.operations import server

    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    progress = harness.PhaseProgress("owned-callback")
    state = State(Inventory(([("@local", {})], {})), Config())
    state.add_callback_handler(progress.callback())
    connect_all(state)
    try:
        add_op(state, server.shell, name="Owned progress", commands="printf command-body-not-evidence")
        run_ops(state)
    finally:
        disconnect_all(state)
    body = (tmp_path / "owned-callback-progress.log").read_text()
    rows = [json.loads(line) for line in body.splitlines()]
    assert [row["event"] for row in rows] == ["operation-start", "operation-end"]
    assert all(row["names"] == ["Owned progress"] for row in rows)
    assert "command-body-not-evidence" not in body


def test_actual_cleanup_trap_retains_timeout_and_removes_only_owned_resources(tmp_path: Path) -> None:
    source = (Path(__file__).parent / "integration/paperless/run-owned.sh").read_text()
    cleanup = source[source.index("cleanup() {") : source.index("# GitHub documents")]
    output = tmp_path / "evidence"
    output.mkdir()
    for name in ("container", "image", "unrelated"):
        (tmp_path / name).touch()
    docker = tmp_path / "docker"
    docker.write_text("""#!/bin/sh
printf '%s\n' "$*" >> "$OWNED_TEST/calls"
case "$*" in
 'logs owned-test') exit 0;;
 'inspect owned-test') printf '{}';;
 'exec owned-test python3 /opt/paperless-evidence.py') printf '{"files":{},"total_size":0}';;
 "cp owned-test:/var/tmp/paperless-evidence/. $EVIDENCE/") printf 'partial' > "$EVIDENCE/partial.log";;
 'rm -f owned-test') rm "$OWNED_TEST/container";;
 'image rm owned-test:1') rm "$OWNED_TEST/image";;
 'container inspect owned-test') test -e "$OWNED_TEST/container";;
 'image inspect owned-test:1') test -e "$OWNED_TEST/image";;
 *) exit 99;;
esac
""")
    docker.chmod(0o700)
    # This is a cleanup-shell control, not a native Docker/timeout test. The
    # separate child test above exercises a real timeout and retained evidence.
    timeout = tmp_path / "timeout"
    timeout.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    timeout.chmod(0o700)
    result = subprocess.run(
        ["bash", "-euc", cleanup + "\nexit 124"],
        env={
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "NAME": "owned-test",
            "IMAGE": "owned-test:1",
            "EVIDENCE": str(output),
            "OWNED_TEST": str(tmp_path),
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 124
    assert json.loads((output / "runner-exit.json").read_text()) == {
        "run_exit": 124,
        "collection_exit": 0,
        "cleanup_exit": 0,
    }
    assert (output / "partial.log").read_text() == "partial"
    assert not (tmp_path / "container").exists()
    assert not (tmp_path / "image").exists()
    assert (tmp_path / "unrelated").exists()
    calls = (tmp_path / "calls").read_text().splitlines()
    assert next(i for i, value in enumerate(calls) if value.startswith("cp ")) < calls.index("rm -f owned-test")


def test_actual_fixture_refusal_records_bounded_log_without_host_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    monkeypatch.setattr(harness, "PHASES", [])
    monkeypatch.setattr(harness, "snapshot", lambda cfg: harness.Snapshot({"owned": True}, {}))

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("credential mismatch must refuse before any connector command")

    monkeypatch.setattr(LocalConnector, "run_shell_command", forbidden)
    result = harness.deploy("owned-refusal", failure=True, shared_redis_password=SecretStr("wrong-owned-value"))
    assert result["operations"] == []
    assert result["uploads"] == 0
    assert "shared Redis credentials differ" in result["error"]
    assert (tmp_path / "owned-refusal.log").exists()
    assert not (tmp_path / "private-current-cli.log").exists()
    started = json.loads((tmp_path / "owned-refusal-started.json").read_text())
    final = json.loads((tmp_path / started["completion_receipt"]).read_text())
    assert final["before"] == started["before"]
    assert final["after"]["file"] == "owned-refusal-after.json.gz"


def test_evidence_collector_hashes_actual_files_and_refuses_foreign_link(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "phase.json").write_bytes(b"{}")
    assert evidence.manifest(root) == {
        "files": {"phase.json": {"size": 2, "sha256": hashlib.sha256(b"{}").hexdigest()}},
        "total_size": 2,
    }
    foreign = tmp_path / "foreign"
    foreign.write_text("do not copy")
    (root / "linked.log").symlink_to(foreign)
    with pytest.raises(ValueError, match="unexpected path type"):
        evidence.manifest(root)


def test_evidence_collector_refuses_oversized_sparse_file_without_reading_it(tmp_path: Path) -> None:
    with (tmp_path / "large.log").open("wb") as stream:
        stream.truncate(40 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="file exceeds limit"):
        evidence.manifest(tmp_path)


def test_interrupted_phase_preserves_durable_before_without_claiming_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    monkeypatch.setattr(harness, "snapshot", lambda cfg: harness.Snapshot({"owned": True}, {}))

    def interrupt(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(harness, "add_deploy", interrupt)
    with pytest.raises(KeyboardInterrupt):
        harness.deploy("owned-interrupted")
    receipt = json.loads((tmp_path / "owned-interrupted-started.json").read_text())
    assert receipt["completion_receipt"] == "owned-interrupted.json"
    assert not (tmp_path / receipt["completion_receipt"]).exists()
    assert json.loads(gzip.decompress((tmp_path / receipt["before"]["file"]).read_bytes())) == {"owned": True}
    assert not (tmp_path / "owned-interrupted-after.json.gz").exists()
    assert not (tmp_path / "owned-interrupted.json").exists()


@pytest.mark.parametrize("boundary", ["snapshot", "playbook_write"])
def test_ansible_early_failure_never_leaves_secret_playbook(
    boundary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("owned injected failure")

    monkeypatch.setattr(
        harness, "snapshot", fail if boundary == "snapshot" else lambda: harness.Snapshot({"owned": True}, {})
    )
    monkeypatch.setattr(yaml, "safe_dump", fail)
    with pytest.raises(RuntimeError, match="owned injected failure"):
        harness.ansible("owned-failed-ansible")
    assert not (tmp_path / "owned-ansible.yml").exists()
    assert not (tmp_path / "owned-failed-ansible.json").exists()


@pytest.mark.parametrize("owned_image_present", [True, False])
def test_runner_image_receipt_does_not_require_cached_base_tag(tmp_path: Path, owned_image_present: bool) -> None:
    """Execute the real receipt command with a Docker inventory lacking a base tag."""
    source = (Path(__file__).parent / "integration/paperless/run-owned.sh").read_text()
    commands = [line for line in source.splitlines() if line.startswith("docker image inspect ")]
    assert len(commands) == 1
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@" > "$CALLS"\n'
        'test "$OWNED_PRESENT" = true || exit 1\n'
        'test "$#" = 3 && test "$1" = image && test "$2" = inspect && test "$3" = "$IMAGE" || exit 1\n'
        'printf \'[{"Id":"sha256:owned-image"}]\\n\'\n'
    )
    docker.chmod(0o700)
    result = subprocess.run(
        ["bash", "-euc", commands[0]],
        env={
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "IMAGE": "ops-owned-paperless:synthetic",
            "EVIDENCE": str(tmp_path),
            "CALLS": str(tmp_path / "calls"),
            "OWNED_PRESENT": str(owned_image_present).lower(),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert (result.returncode == 0) is owned_image_present
    if owned_image_present:
        assert json.loads((tmp_path / "images.json").read_text()) == [{"Id": "sha256:owned-image"}]
    else:
        assert not (tmp_path / "images.json").read_text()


@pytest.mark.parametrize("fixed_writes", [False, True])
def test_migration_root_control_detects_fixed_command_writes(
    tmp_path: Path,
    fixed_writes: bool,
) -> None:
    cfg = harness.CFG.model_copy(
        update={"external_storage_root": str(tmp_path / "roots"), "sftp_chroot_dir": str(tmp_path / "scanner")}
    )
    paths = [Path(cfg.external_storage_root) / name for name in ("data", "media", "consume")]
    paths.append(Path(cfg.sftp_chroot_dir) / "inbox")
    for path in paths:
        path.mkdir(parents=True)
    receipts: list[Any] = []

    def owned_command(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "--skip-checks" not in args[-1] or fixed_writes:
            for path in paths:
                marker = path / "owned-write-test"
                marker.write_text("")
                marker.unlink()
        return subprocess.CompletedProcess(args, 0, "", "")

    fixture = SimpleNamespace(
        CFG=cfg,
        OWNED_ADMITTED=True,
        command=owned_command,
        public_metadata=harness.public_metadata,
        write=lambda name, data: receipts.append(json.loads(json.dumps(data))),
    )
    if fixed_writes:
        with pytest.raises(AssertionError, match="fixed migration status changed"):
            application_matrix.migration_status_roots(fixture)
    else:
        application_matrix.migration_status_roots(fixture)
    assert len(receipts) == 2
    assert receipts[-1][0]["classification"] == "intentional-old-write-test-control"
    assert receipts[-1][1]["skip_checks"] is True


@pytest.mark.parametrize("kind", ["same", "different", "missing", "symlink", "fifo"])
def test_actual_static_observer_keeps_receipt_for_unsafe_or_missing_output(tmp_path: Path, kind: str) -> None:
    import sys

    source = tmp_path / "paperless-ngx-v3.2.1/static/frontend"
    source.mkdir(parents=True)
    (source / "owned.js").write_bytes(b"same")
    output = tmp_path / "staticfiles/frontend"
    output.mkdir(parents=True)
    destination = output / "owned.js"
    if kind in {"same", "different"}:
        destination.write_bytes(b"same" if kind == "same" else b"different")
    elif kind == "symlink":
        destination.symlink_to(source / "owned.js")
    elif kind == "fifo":
        os.mkfifo(destination)
    # Execute the actual generated standalone observer. Only Django's finder
    # registry is synthetic; frontend source enumeration/digests/refusals are real.
    prefix = """import sys,types
for name in ('django', 'django.apps', 'django.contrib', 'django.contrib.staticfiles',
             'django.contrib.staticfiles.finders'):
    sys.modules[name] = types.ModuleType(name)
sys.modules['django.apps'].apps = None
sys.modules['django.contrib.staticfiles.finders'].get_finders = lambda: []
"""
    written: dict[str, Any] = {}

    def app(program: str, *, check: bool) -> subprocess.CompletedProcess[str]:
        assert not check
        return subprocess.run([sys.executable, "-c", prefix + program], capture_output=True, text=True, timeout=10)

    fixture = SimpleNamespace(
        OWNED_ADMITTED=True,
        CFG=SimpleNamespace(site_root=str(tmp_path), version="3.2.1"),
        app=app,
        write=lambda name, record: written.update({name: record}),
    )
    if kind == "same":
        application_matrix.static_program_observation(fixture, "owned")
    else:
        with pytest.raises(AssertionError):
            application_matrix.static_program_observation(fixture, "owned")
    receipt = written["owned-static-program.json"]
    assert receipt["exit"] == 0
    observed = receipt["observation"]["files"]["frontend/owned.js"]["destination"]
    if kind in {"missing", "symlink", "fifo"}:
        assert observed["sha256"] is None
        assert observed["error"] == {"missing": "FileNotFoundError", "symlink": "OSError", "fifo": "Refusal"}[kind]
    else:
        assert observed["error"] is None
        assert observed["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()


@pytest.mark.parametrize("timed_out", [False, True])
def test_sftp_failure_receipt_precedes_assertion_and_sanitizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timed_out: bool
) -> None:
    pdf = tmp_path / "owned.pdf"
    monkeypatch.setattr(application_matrix, "Path", lambda value: pdf)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    monkeypatch.setattr(harness, "VALUES", ["owned-secret"])
    monkeypatch.setattr(application_matrix, "sftp_diagnostic", lambda fixture: {"metadata": "owned"})
    calls = []

    def command(*args: object) -> None:
        pdf.write_bytes(b"synthetic PDF placeholder; command boundary only")

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs["pass_fds"]
        assert os.read(kwargs["pass_fds"][0], 100) == b"owned-secret\n"
        if timed_out:
            raise subprocess.TimeoutExpired(argv, 60, b"owned output owned-secret", b"Connection closed")
        return subprocess.CompletedProcess(argv, 255, "owned output owned-secret", "Connection closed")

    monkeypatch.setattr(subprocess, "run", run)
    fixture = SimpleNamespace(
        OWNED_ADMITTED=True,
        CFG=SimpleNamespace(site_root="/owned", scanner_username="scanner"),
        CREDS=SimpleNamespace(scanner_password=SecretStr("owned-secret")),
        command=command,
        count=lambda: 0,
        write=harness.write,
    )
    with pytest.raises(subprocess.TimeoutExpired if timed_out else AssertionError):
        application_matrix.sftp_ocr(fixture)
    assert len(calls) == 1
    receipt = json.loads((tmp_path / "synthetic-sftp-attempt.json").read_text())
    assert receipt["exit"] == (None if timed_out else 255)
    if timed_out:
        assert receipt["timed_out"] is True
    assert receipt["stdout"] == "owned output <synthetic-redacted>"
    assert receipt["stderr"] == "Connection closed"
    assert not pdf.exists()


@pytest.mark.parametrize(
    "extra_change",
    [
        None,
        "mode",
        "inode",
        "size",
        "uid",
        "gid",
        "link",
        "new_field",
        "backwards",
        "missing",
        "unit",
        "body",
        "db",
        "index",
        "other_root",
        "root_missing",
        "root_nondict",
    ],
)
def test_old_failed_reindex_allows_only_exact_observed_root_timestamps(extra_change: str | None) -> None:
    cfg = SimpleNamespace(external_storage_root="/owned/paperless", sftp_chroot_dir="/owned/scanner")
    roots = ["/owned/paperless/" + name for name in ("data", "media", "consume")]
    roots.append("/owned/scanner/inbox")
    metadata = {
        "mode": 16877,
        "uid": 1001,
        "gid": 1001,
        "inode": 42,
        "size": 80,
        "mtime_ns": 100,
        "ctime_ns": 101,
        "link": None,
    }
    before: dict[str, Any] = {
        "files": {root: dict(metadata) for root in [*roots, "/owned/paperless"]},
        "units": {"paperless": "inactive"},
        "public_program_hashes": {"program": "same"},
        "database_operational_state": {"documents": 1},
        "index_metadata_only": {"missing": True},
    }
    after = copy.deepcopy(before)
    for root in roots:
        after["files"][root]["mtime_ns"] += 10
        after["files"][root]["ctime_ns"] += 10
    if extra_change in {"mode", "inode", "size", "uid", "gid"}:
        after["files"][roots[0]][extra_change] += 1
    elif extra_change in {"link", "new_field"}:
        after["files"][roots[0]][extra_change] = "unexpected"
    elif extra_change == "backwards":
        after["files"][roots[0]]["mtime_ns"] = 1
    elif extra_change == "missing":
        after["files"][roots[0]]["ctime_ns"] = 101
    elif extra_change == "other_root":
        after["files"]["/owned/paperless"]["mtime_ns"] += 1
    elif extra_change == "root_missing":
        del after["files"][roots[0]]
    elif extra_change == "root_nondict":
        after["files"][roots[0]] = None
    elif extra_change:
        section = {
            "unit": "units",
            "body": "public_program_hashes",
            "db": "database_operational_state",
            "index": "index_metadata_only",
        }[extra_change]
        after[section]["unexpected"] = True
    unchanged_before, unchanged_after = copy.deepcopy(before), copy.deepcopy(after)
    result = application_matrix.old_reindex_fault_observation(before, after, cfg)
    assert result["only_expected_root_metadata_changed"] is (extra_change is None)
    assert before == unchanged_before
    assert after == unchanged_after
    assert "not zero mutation" in result["classification"]
