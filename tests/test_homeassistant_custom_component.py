"""Owned archive/metadata controls; synthetic HTTP and exact selected GNU tar."""

from __future__ import annotations

import base64
import grp
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pwd
import stat
import subprocess
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from ops_deploy.services.homeassistant.custom_component import CustomComponentConfig, component_payload
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

SPEC = importlib.util.spec_from_file_location(
    "owned_cc_component", str(files("ops_deploy.services.homeassistant").joinpath("files/custom_component.py"))
)
assert SPEC is not None
assert SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def parameters(tmp_path: Path) -> dict[str, Any]:
    parent = tmp_path / "custom_components"
    parent.mkdir()
    component = parent / "custom_conversation"
    return {
        "archive": str(tmp_path / "release.tar.gz"),
        "parent": str(parent),
        "component": str(component),
        "stamp": str(component / ".ansible-cc-version"),
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "version": "1.6.1",
        "sha256": "a" * 64,
        "url": "http://127.0.0.1:1/release",
        "action": "check-install",
    }


@pytest.mark.parametrize(
    "stamp", [None, "wrong", "1.6.1 " + "a" * 64, " \n1.6.1 " + "a" * 64 + "\n", "1.6.1 " + "b" * 64]
)
def test_exact_stamp_trim_and_checksum_trigger(tmp_path: Path, stamp: str | None) -> None:
    data = parameters(tmp_path)
    Path(data["component"]).mkdir()
    Path(data["component"], "unrelated.py").write_text("unchanged code")
    if stamp is not None:
        Path(data["stamp"]).write_text(stamp)
    before = {p.name: p.read_bytes() for p in Path(data["component"]).iterdir()}
    result = helper.run(data)
    assert result["success"] is True
    assert result["changed"] is (stamp is None or stamp.strip() != "1.6.1 " + "a" * 64)
    assert result["effects_started"] is False
    assert {p.name: p.read_bytes() for p in Path(data["component"]).iterdir()} == before


def test_invalid_unicode_or_directory_stamp_means_original_reinstall(tmp_path: Path) -> None:
    data = parameters(tmp_path)
    stamp = Path(data["stamp"])
    stamp.parent.mkdir()
    stamp.write_bytes(b"\xff")
    assert helper.run(data)["changed"] is True
    stamp.unlink()
    stamp.mkdir()
    assert helper.run(data)["changed"] is True


@pytest.mark.parametrize(
    "case",
    ["fresh", "current", "metadata", "mismatch", "bad-sha", "http-error", "gzip", "basic", "netrc", "malformed-netrc"],
)
def test_real_synthetic_download_preserves_original_destination_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    data = parameters(tmp_path)
    body = b"synthetic pinned archive bytes"
    data["sha256"] = hashlib.sha256(body).hexdigest()
    archive = Path(data["archive"])
    if case in {"current", "metadata"}:
        archive.write_bytes(body)
        archive.chmod(0o600 if case == "metadata" else 0o644)
    elif case in {"mismatch", "bad-sha", "http-error", "malformed-netrc"}:
        archive.write_bytes(b"prior destination must survive failure")
        archive.chmod(0o640)
    prior = archive.read_bytes() if archive.exists() else None
    prior_stat = archive.stat() if archive.exists() else None
    calls: list[dict[str, str]] = []
    authfile = tmp_path / "owned.netrc"
    authfile.write_text("machine 127.0.0.1 login synthetic password owned" if case == "netrc" else "")
    if case == "malformed-netrc":
        authfile.write_text("machine 127.0.0.1 strange invalid")
    authfile.chmod(0o600)
    monkeypatch.setenv("NETRC", str(authfile))
    wanted_auth = "Basic " + base64.b64encode(b"synthetic:owned").decode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            calls.append(dict(self.headers))
            if case == "basic" and self.headers.get("Authorization") != wanted_auth:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="owned"')
                self.end_headers()
                return
            self.send_response(503 if case == "http-error" else 200)
            if case == "gzip":
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            content = b"incorrect private response" if case == "bad-sha" else body
            self.wfile.write(gzip.compress(content) if case == "gzip" else content)

        def log_message(self, *_: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        authority = f"127.0.0.1:{server.server_port}"
        data["url"] = "http://" + ("synthetic:owned@" if case == "basic" else "") + authority + "/archive"
        data["action"] = "download"
        result = helper.run(data)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert not thread.is_alive()
    assert list(tmp_path.glob(".ops-ha-cc-*")) == []
    assert "incorrect private response" not in json.dumps(result)
    if case in {"bad-sha", "http-error", "malformed-netrc"}:
        assert result["success"] is False
        assert result["effects_started"] is True  # Temporary staging, then cleanup.
        assert result["archive_replaced"] is False
        assert archive.read_bytes() == prior
        assert prior_stat is not None
        now = archive.stat()
        assert (now.st_ino, now.st_mode, now.st_mtime_ns, now.st_ctime_ns) == (
            prior_stat.st_ino,
            prior_stat.st_mode,
            prior_stat.st_mtime_ns,
            prior_stat.st_ctime_ns,
        )
    else:
        assert result["success"] is True
        assert archive.read_bytes() == body
        assert stat.S_IMODE(archive.stat().st_mode) == 0o644
        assert result["changed"] is (case != "current")
    if case in {"current", "metadata", "malformed-netrc"}:
        assert calls == []
    else:
        assert calls[0]["User-Agent"] == "ansible-httpget"
        if case in {"mismatch", "bad-sha", "http-error"}:
            assert calls[0]["Cache-Control"] == "no-cache"
        if case == "basic":
            assert "Authorization" not in calls[0]  # Original challenge-based URL auth.
            assert calls[1]["Authorization"] == wanted_auth
        if case == "netrc":
            assert calls[0]["Authorization"] == wanted_auth


def make_archive(path: Path) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, mode, body in [
            ("custom-conversation-1.6.1/custom_components/custom_conversation", 0o750, None),
            ("custom-conversation-1.6.1/custom_components/custom_conversation/main.py", 0o640, b"synthetic code"),
            ("custom-conversation-1.6.1/ignored.txt", 0o600, b"not selected"),
        ]:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.mtime = 1700000000
            if body is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))


GNU_TAR = "GNU tar" in subprocess.run(["tar", "--version"], text=True, capture_output=True, check=True).stdout


@pytest.mark.skipif(not GNU_TAR, reason="Exact original GNU tar semantics require owned Linux userspace")
@pytest.mark.parametrize("kind", ["absent", "directory", "file", "link", "dangling"])
def test_actual_gnu_selected_extract_metadata_and_strict_repeat(tmp_path: Path, kind: str) -> None:
    data = parameters(tmp_path)
    root = Path(data["component"])
    target = tmp_path / "outside"
    target.mkdir()
    (target / "keep").write_text("unchanged")
    if kind == "directory":
        root.mkdir()
        (root / "old").write_text("old code")
    elif kind == "file":
        root.write_text("old file")
    elif kind in {"link", "dangling"}:
        root.symlink_to(target if kind == "link" else tmp_path / "missing")
    make_archive(Path(data["archive"]))
    data["action"] = "extract"
    result = helper.run(data)
    assert result["success"] is True, result
    assert result["extracted"] is True
    assert stat.S_IMODE(root.stat().st_mode) == 0o750
    assert stat.S_IMODE((root / "main.py").stat().st_mode) == 0o640
    assert (root / "main.py").stat().st_mtime == 1700000000
    assert list(Path(data["parent"]).iterdir()) == [root]
    assert (target / "keep").read_text() == "unchanged"
    stamp = Path(data["stamp"])
    stamp.write_text(data["version"] + " " + data["sha256"] + "\n")
    before = {
        p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in root.iterdir()
    }
    root_before = root.stat()
    repeat = helper.run(data)
    assert repeat["success"] is True
    assert repeat["changed"] is False
    assert repeat["effects_started"] is False
    assert before == {
        p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in root.iterdir()
    }
    assert root.stat().st_mtime_ns == root_before.st_mtime_ns
    assert root.stat().st_ctime_ns == root_before.st_ctime_ns


def test_failed_extract_retains_actual_partial_removal(tmp_path: Path) -> None:
    data = parameters(tmp_path)
    root = Path(data["component"])
    root.mkdir()
    (root / "prior").write_text("prior code")
    Path(data["archive"]).write_bytes(b"invalid archive")
    data["action"] = "extract"
    result = helper.run(data)
    assert result["success"] is False
    assert result["changed"] is False  # Failed operation, NOT zero target effects.
    assert result["effects_started"] is True
    assert result["component_removed"] is True
    assert result["extracted"] is False
    assert not root.exists()


def test_controller_default_and_custom_source_preserved() -> None:
    default = CustomComponentConfig()
    assert default.version == "1.6.1"
    assert default.sha256 == "6397258af29908ffed7b0eaa79c332ddce7000cb9b9faec5e3bf0e399c020382"
    value = json.loads(component_payload(HomeAssistantRuntimeConfig(), default, "check-install").get_secret_value())
    assert value["stamp"].endswith("/custom_components/custom_conversation/.ansible-cc-version")
    custom = CustomComponentConfig(download_url=SecretStr("https://owned.invalid/custom?token=synthetic"))
    assert custom.url() == "https://owned.invalid/custom?token=synthetic"
    assert "synthetic" not in repr(custom)


@pytest.mark.parametrize("diff", [False, True])
def test_actual_localconnector_archive_plan_and_repeat(tmp_path: Path, diff: bool) -> None:
    import sys

    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.custom_component import _component_action
    from ops_deploy.testing.harness import collect_ops

    site = tmp_path / "site"
    (site / "downloads").mkdir(parents=True)
    source = tmp_path / "source"
    source.write_bytes(b"synthetic archive")
    component = CustomComponentConfig(
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(), download_url=SecretStr(source.as_uri())
    )
    # pytest's temporary path includes underscores; this known-owned fixture
    # substitutes those paths after validating normal production defaults.
    cfg = HomeAssistantRuntimeConfig(user=pwd.getpwuid(os.getuid()).pw_name, group=grp.getgrgid(os.getgid()).gr_name)
    cfg = cfg.model_copy(
        update={"site_path": str(site), "security": cfg.security.model_copy(update={"system_python": sys.executable})}
    )
    destination = site / "downloads/custom-conversation-1.6.1.tar.gz"
    for number in (1, 2):
        state = State(Inventory(([("@local", {})], {})), Config(DIFF=diff))
        try:
            connect_all(state)
            add_deploy(
                state,
                lambda: _component_action(
                    cfg=cfg, component=component, action="download", deferred=False, predecessors=()
                ),
            )
            assert destination.exists() is (number == 2)  # Registration performs no download.
            before = destination.stat() if destination.exists() else None
            run_ops(state)
            ops = collect_ops(state, "@local")
            assert len(ops) == 1
            assert ops[0].succeeded
            assert ops[0].changed is (number == 1)
            assert destination.read_bytes() == source.read_bytes()
            if before is not None:
                after = destination.stat()
                assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
                    after.st_ino,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
        finally:
            disconnect_all(state)


@pytest.mark.skipif(not GNU_TAR, reason="Full selected extraction operation requires original GNU tar")
def test_actual_pyinfra_full_component_first_repeat_and_notifications(tmp_path: Path) -> None:
    import sys

    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.services.homeassistant.custom_component import CustomComponentChanges, install_custom_component
    from ops_deploy.testing.harness import collect_ops

    source = tmp_path / "source.tar.gz"
    make_archive(source)
    cfg = HomeAssistantRuntimeConfig(user=pwd.getpwuid(os.getuid()).pw_name, group=grp.getgrgid(os.getgid()).gr_name)
    cfg = cfg.model_copy(
        update={
            "site_path": str(tmp_path / "site"),
            "config_path": str(tmp_path / "config"),
            "security": cfg.security.model_copy(update={"system_python": sys.executable}),
        }
    )
    component = CustomComponentConfig(
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(), download_url=SecretStr(source.as_uri())
    )
    changes: list[CustomComponentChanges] = []
    root = Path(cfg.config_path) / "custom_components/custom_conversation"
    for number in (1, 2):
        state = State(Inventory(([("@local", {})], {})), Config())
        try:
            connect_all(state)
            add_deploy(state, lambda: changes.append(install_custom_component(cfg, component)))
            assert root.exists() is (number == 2)
            run_ops(state)
            ops = collect_ops(state, "@local")
            assert all(item.succeeded for item in ops)
            assert changes[-1].homeassistant_changed() is (number == 1)
            assert sum(item.changed for item in ops) == (5 if number == 1 else 0)
            assert (root / "main.py").read_bytes() == b"synthetic code"
            assert (root / ".ansible-cc-version").read_text() == component.version + " " + component.sha256 + "\n"
        finally:
            disconnect_all(state)


def test_original_task_source_binding() -> None:
    root = Path(__file__).parent / "parity/homeassistant/custom-component"
    source = json.loads((root / "source.json").read_text())
    assert hashlib.sha256((root / "component.yml").read_bytes()).hexdigest() == source["task_sha256"]


@pytest.mark.skipif(
    not GNU_TAR or os.geteuid() != 0, reason="Owned root/Linux fixture proves archive UID differs from desired user"
)
def test_actual_root_tar_owner_negative_and_original_member_chown(tmp_path: Path) -> None:
    data = parameters(tmp_path)
    data["user"] = "nobody"
    data["group"] = "nogroup"
    wanted_uid = pwd.getpwnam("nobody").pw_uid
    wanted_gid = grp.getgrnam("nogroup").gr_gid
    outside = tmp_path / "outside"
    outside.write_text("unrelated target")
    outside.chmod(0o600)
    outside_before = outside.stat()
    archive = Path(data["archive"])
    make_archive(archive)
    # Add an escaped member name and link to prove the original list decoding
    # and lchown member behavior, not recursive/follow-link ownership repair.
    with tarfile.open(archive, "r:gz") as source:
        entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for member in source:
            content = None
            if member.isfile():
                handle = source.extractfile(member)
                assert handle is not None
                content = handle.read()
            entries.append((member, content))
    with tarfile.open(archive, "w:gz") as target:
        for member, content in entries:
            target.addfile(member, io.BytesIO(content) if content is not None else None)
        link = tarfile.TarInfo("custom-conversation-1.6.1/custom_components/custom_conversation/link")
        link.type = tarfile.SYMTYPE
        link.linkname = str(outside)
        target.addfile(link)
        escaped = tarfile.TarInfo(
            "custom-conversation-1.6.1/custom_components/custom_conversation/space and\nnewline.py"
        )
        escaped.size = 4
        escaped.mode = 0o640
        target.addfile(escaped, io.BytesIO(b"code"))
    argv = [
        "tar",
        "--extract",
        "-C",
        data["parent"],
        "-z",
        "--show-transformed-names",
        "--strip-components=2",
        "custom-conversation-1.6.1/custom_components/custom_conversation",
        "--owner=nobody",
        "--group=nogroup",
        "-f",
        str(archive),
    ]
    old = subprocess.run(argv, capture_output=True, check=False)
    assert old.returncode == 0
    root = Path(data["component"])
    assert (root / "main.py").stat().st_uid == 0  # Exact old helper misses required ownership.
    assert wanted_uid != 0
    data["action"] = "extract"
    fixed = helper.run(data)
    assert fixed["success"] is True, fixed
    for path in [root, *root.iterdir()]:
        info = path.lstat()
        assert (info.st_uid, info.st_gid) == (wanted_uid, wanted_gid)
    assert (root / "space and\nnewline.py").read_bytes() == b"code"
    after = outside.stat()
    assert (after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) == (
        outside_before.st_uid,
        outside_before.st_gid,
        outside_before.st_mode,
        outside_before.st_mtime_ns,
        outside_before.st_ctime_ns,
    )


@pytest.mark.skipif(not GNU_TAR or os.geteuid() != 0, reason="Owned Linux root needed for symlink lchown oracle")
def test_archive_symlink_metadata_preserves_unrelated_target(tmp_path: Path) -> None:
    data = parameters(tmp_path)
    data["user"], data["group"] = "nobody", "nogroup"
    body = b"current synthetic archive"
    target = tmp_path / "outside-archive"
    target.write_bytes(body)
    target.chmod(0o600)
    Path(data["archive"]).symlink_to(target)
    data["sha256"] = hashlib.sha256(body).hexdigest()
    before = target.stat()
    data["action"] = "download"
    result = helper.run(data)
    assert result["success"] is True
    assert result["changed"] is True
    assert result["archive_replaced"] is False
    link = Path(data["archive"]).lstat()
    assert (link.st_uid, link.st_gid) == (pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
    after = target.stat()
    assert (after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_uid,
        before.st_gid,
        before.st_mode,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    repeat = helper.run(data)
    assert repeat["success"] is True
    assert repeat["changed"] is False
    assert repeat["effects_started"] is False
