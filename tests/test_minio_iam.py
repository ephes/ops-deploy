"""Pinned-client synthetic response contracts; not native deployment qualification."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "minio_iam_host", ROOT / "src/ops_deploy/services/minio/files/iam_host.py"
)
assert SPEC
assert SPEC.loader
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
RESPONSES = json.loads((ROOT / "tests/parity/minio/mc-responses.json").read_text())


def reply(name: str) -> Any:
    row = RESPONSES[name]
    return HOST.Reply(row["exit"], row["stdout"], row["stderr"])


@pytest.mark.parametrize(
    ("name", "match"),
    [("correct-prefix-stat", True), ("wrong-prefix-stat", False), ("missing-user-prefix-stat", False)],
)
def test_actual_pinned_client_signed_probe(name: str, match: bool) -> None:
    assert reply(name).credential_matches() is match


def test_actual_transport_failure_never_becomes_rotation() -> None:
    with pytest.raises(HOST.Refused, match="transport or unknown"):
        reply("unreachable-stat").credential_matches()


def test_status_error_with_zero_exit_is_not_success() -> None:
    result = HOST.Reply(0, json.dumps({"status": "error", "error": "unreachable"}), "")
    assert not result.successful
    with pytest.raises(HOST.Refused, match="successful result"):
        result.one()
    with pytest.raises(HOST.Refused, match="contradictory"):
        result.credential_matches()


@pytest.mark.parametrize("body", ["", "not JSON", "[]", "null", '{"status":"maybe"}'])
def test_malformed_reply_stops(body: str) -> None:
    with pytest.raises(HOST.Refused):
        HOST.Reply(1, body, "")


def test_stderr_is_not_discarded_even_on_success() -> None:
    with pytest.raises(HOST.Refused, match="diagnostics"):
        HOST.Reply(0, '{"status":"success"}', "unexpected warning")


@pytest.mark.parametrize(
    ("name", "code"), [("absent-user-info", "XMinioAdminNoSuchUser"), ("absent-policy-info", "XMinioAdminNoSuchPolicy")]
)
def test_only_exact_absence_classification(name: str, code: str) -> None:
    assert reply(name).absent(code)
    assert not reply(name).absent("NoSuchBucket")
    assert not reply("unreachable-stat").absent(code)


def test_conflicting_authentication_errors_stop() -> None:
    valid = json.loads(RESPONSES["correct-prefix-stat"]["stdout"].splitlines()[0])
    invalid = json.loads(RESPONSES["wrong-prefix-stat"]["stdout"].splitlines()[0])
    with pytest.raises(HOST.Refused, match="conflicting"):
        HOST.Reply(1, json.dumps(valid) + "\n" + json.dumps(invalid), "").credential_matches()


def test_unknown_secondary_error_cannot_hide_behind_valid_signature() -> None:
    valid = RESPONSES["correct-prefix-stat"]["stdout"].splitlines()[0]
    bad = {"status": "error", "error": {"type": "fatal", "cause": {"message": "transport broke", "error": {}}}}
    with pytest.raises(HOST.Refused, match="unknown"):
        HOST.Reply(1, valid + "\n" + json.dumps(bad), "").credential_matches()


def test_shared_alias_comparison_preserves_other_aliases(tmp_path: Path) -> None:
    wanted = HOST.alias_document("http://127.0.0.1:9001", "fixture-root", "synthetic-only")
    path = tmp_path / "config.json"
    config = {"version": "10", "aliases": {"local": wanted, "unrelated": {"url": "https://example.invalid"}}}
    path.write_text(json.dumps(config))
    before = path.read_bytes(), path.stat().st_mtime_ns
    assert HOST.alias_current(tmp_path, "local", wanted)
    assert not HOST.alias_current(tmp_path, "missing", wanted)
    assert not HOST.alias_current(tmp_path, "local", {**wanted, "secretKey": "different-synthetic"})
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_normalization_ignores_only_legacy_set_fields_and_statement_order() -> None:
    original = {
        "Version": "2012-10-17",
        "Statement": [{"Action": ["b", "a", "a"], "Resource": "bucket", "Effect": "Allow"}],
    }
    equivalent = {
        "Version": "2012-10-17",
        "Statement": [{"Action": ["a", "b"], "Resource": ["bucket"], "Effect": "Allow"}],
    }
    assert HOST.normalized(original) == HOST.normalized(equivalent)
    assert HOST.normalized(original) != HOST.normalized({**equivalent, "Version": "other"})
    changed = json.loads(json.dumps(equivalent))
    changed["Statement"][0]["Condition"] = {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}
    assert HOST.normalized(original) != HOST.normalized(changed)


def test_data_probe_preserves_owned_tree_and_never_reads_object_bodies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location(
        "minio_data_roots", ROOT / "src/ops_deploy/services/minio/files/data_roots.py"
    )
    assert spec is not None
    assert spec.loader is not None
    data = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(data)
    child = tmp_path / "owned-object"
    child.write_bytes(b"synthetic object sentinel")
    child.chmod(0o640)
    before = child.stat()
    monkeypatch.setattr(data.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(data.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    monkeypatch.setattr(Path, "read_bytes", lambda _: pytest.fail("data probe must not read object bytes"))
    data.inspect([str(tmp_path)], "fixture", "fixture")
    after = child.stat()
    assert (
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (after.st_mode, after.st_uid, after.st_gid, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    monkeypatch.setattr(data.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid() + 1))
    with pytest.raises(ValueError, match="foreign-owned") as error:
        data.inspect([str(tmp_path)], "fixture", "fixture")
    assert "owned-object" not in str(error.value)
    assert child.stat() == after
