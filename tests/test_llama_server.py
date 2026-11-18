"""Native detector configuration, secret transport, retention and failure order."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import plistlib
import shlex
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ops_deploy.services.llama_server import LlamaServerConfig, LlamaSourceBuild, deploy_llama_server
from ops_deploy.services.llama_server.deploy import host_command, payload
from ops_deploy.testing import run_deploy_fake

ROOT = Path(__file__).resolve().parents[1]
KEY_VALUE = "x" * 48


def host_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "llama_server_host_test", ROOT / "src/ops_deploy/services/llama_server/files/llama_server_host.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def cfg(tmp_path: Path) -> LlamaServerConfig:
    wrapper = tmp_path / "controller-wrapper.sh"
    pin = LlamaServerConfig(enabled=False).model_sha256
    wrapper.write_text(f'GGUF_SHA256="{pin}"\n# --api-key-file --no-slots --cache-ram 0\n')
    return LlamaServerConfig(user="owner", brew_user="owner", wrapper_source=wrapper)


def test_disabled_api_needs_no_controller_wrapper_or_secret() -> None:
    cfg = LlamaServerConfig(enabled=False)
    assert cfg.required_secret_keys == ()
    assert "contents" not in payload(cfg, {})


@pytest.mark.parametrize("value", ["", "#ignored" * 8, " padded" * 8, "line\n" * 10])
def test_invalid_api_key_rejected_before_host(cfg: LlamaServerConfig, value: str) -> None:
    with pytest.raises(ValueError, match="key"):
        payload(cfg, {"api_key": value})


@pytest.mark.parametrize(
    "changes",
    [
        {"bind_host": "0.0.0.0"},
        {"bind_host": "192.168.1.2"},
        {"bind_host": "::1"},
        {"model_file": "../model.gguf"},
        {"log_dir": "/"},
        {"port": 65536},
        {"model_url": "https://user:password@example.test/file.gguf"},
    ],
)
def test_unsafe_config_rejected(cfg: LlamaServerConfig, changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        LlamaServerConfig.model_validate({**cfg.model_dump(), **changes})


def test_key_only_reaches_secret_stdin(cfg: LlamaServerConfig) -> None:
    data = payload(cfg, {"api_key": KEY_VALUE})
    for action in ["status", "apply", "verify"]:
        command = host_command(data, action)
        public = json.loads(base64.b64decode(shlex.split(command)[-1]))
        assert KEY_VALUE not in command
        assert KEY_VALUE not in json.dumps(public)
        assert "contents" not in public
    assert data["contents"][str(cfg.api_key_path)] == KEY_VALUE + "\n"


def test_plist_preserves_native_owner_domain_and_pin(cfg: LlamaServerConfig) -> None:
    data = payload(cfg, {"api_key": KEY_VALUE})
    parsed = plistlib.loads(data["contents"][str(cfg.launchd_plist_path)].encode())
    assert parsed["UserName"] == "owner"
    assert parsed["GroupName"] == "staff"
    assert parsed["ProgramArguments"] == ["/bin/bash", "/opt/llama-server/detector-server.sh"]
    assert parsed["EnvironmentVariables"]["DELVE_DETECTOR_BUILD"] == cfg.build


def test_current_deployment_has_no_upload_or_mutation(cfg: LlamaServerConfig) -> None:
    run = run_deploy_fake(deploy_llama_server, cfg, {"api_key": KEY_VALUE}, responses={" status ": ["current"]})
    assert run.succeeded
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert len(run.executed_commands) == 1
    assert " verify " in run.executed_commands[0]


def test_failure_stops_before_readiness(cfg: LlamaServerConfig) -> None:
    run = run_deploy_fake(
        deploy_llama_server,
        cfg,
        {"api_key": KEY_VALUE},
        responses={" status ": ["drift"], " apply ": {"success": False, "stderr": "owned fixture fault"}},
    )
    assert not run.succeeded
    assert not any(" verify " in command for command in run.executed_commands)


def test_existing_pinned_model_is_neither_opened_nor_downloaded(tmp_path: Path) -> None:
    module = host_script()
    model = tmp_path / "fixture.gguf"
    model.write_bytes(b"owned synthetic model, not read by status")
    wrapper = tmp_path / "wrapper.sh"
    wrapper.write_text('GGUF_SHA256="declared-pin"')
    with patch.object(module.urllib.request, "urlopen") as download:
        assert (
            module.stage_model({"model_path": str(model), "wrapper_path": str(wrapper), "model_sha256": "declared-pin"})
            is None
        )
    download.assert_not_called()


def test_bad_fresh_download_is_removed_without_replacing_existing_model(tmp_path: Path) -> None:
    module = host_script()
    model = tmp_path / "fixture.gguf"
    model.write_bytes(b"retained prior fixture model")
    before = model.stat()
    cfg = {
        "model_path": str(model),
        "model_dir": str(tmp_path),
        "wrapper_path": str(tmp_path / "missing-wrapper"),
        "model_sha256": "0" * 64,
        "model_url": "https://fixture.example/model.gguf",
        "wheel": os.getgid(),
    }
    with (
        patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(b"bad owned fixture download")),
        patch.object(module.os, "fchown"),
        pytest.raises(RuntimeError, match="checksum"),
    ):
        module.stage_model(cfg)
    assert model.read_bytes() == b"retained prior fixture model"
    assert model.stat().st_ino == before.st_ino
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fixture.gguf"]


def test_unload_waits_for_exact_job_to_leave() -> None:
    module = host_script()
    with (
        patch.object(module, "run") as run,
        patch.object(module, "job", side_effect=[(True, False), (False, False)]),
        patch.object(module.time, "sleep") as sleep,
    ):
        module.unload({"launchd_label": "org.example.owned-detector"})
    run.assert_called_once_with(["/bin/launchctl", "bootout", "system/org.example.owned-detector"], check=False)
    sleep.assert_called_once_with(0.1)


# --- Source mode (docs/services/llama_server.md, "Source build") ------------

PIN_COMMIT = "620d2225cc436ab0b001e3200e590e3b286ef9ab"


@pytest.fixture
def source_cfg(cfg: LlamaServerConfig) -> LlamaServerConfig:
    return LlamaServerConfig.model_validate(
        {
            **cfg.model_dump(exclude={"source_build", "binary"}),
            "source_build": LlamaSourceBuild(tag="b11669", commit=PIN_COMMIT),
        }
    )


def test_source_build_publishes_its_own_binary(source_cfg: LlamaServerConfig) -> None:
    prefix = Path("/opt/llama-server/llama.cpp-b11669-620d2225c")
    assert str(source_cfg.source_prefix) == str(prefix)
    assert str(source_cfg.binary) == str(prefix / "bin/llama-server")
    data = payload(source_cfg, {"api_key": KEY_VALUE})
    parsed = plistlib.loads(data["contents"][str(source_cfg.launchd_plist_path)].encode())
    assert parsed["EnvironmentVariables"]["DELVE_LLAMA_SERVER"] == str(prefix / "bin/llama-server")
    assert data["source_build"] == {
        "repository": "https://github.com/ggml-org/llama.cpp.git",
        "tag": "b11669",
        "commit": PIN_COMMIT,
    }
    # A dumped config validates again (binary already the prefix path).
    assert LlamaServerConfig.model_validate(source_cfg.model_dump()).binary == source_cfg.binary


def test_homebrew_mode_is_unchanged(cfg: LlamaServerConfig) -> None:
    assert cfg.source_prefix is None
    assert str(cfg.binary) == "/opt/homebrew/bin/llama-server"
    assert payload(cfg, {"api_key": KEY_VALUE})["source_build"] is None


@pytest.mark.parametrize(
    "changes",
    [
        {"source_build": {"tag": "b11670", "commit": PIN_COMMIT}},
        {"source_build": {"tag": "b11669", "commit": "f" * 40}},
        {"source_build": {"tag": "b11669", "commit": PIN_COMMIT[:9]}},
        {"source_build": {"tag": "b11669", "commit": PIN_COMMIT, "repository": "https://u:p@github.com/x.git"}},
        {"source_build": {"tag": "b11669", "commit": PIN_COMMIT, "repository": "http://github.com/x.git"}},
        {"install_dir": "/srv/llama"},
        {"log_dir": "/Users/owner/logs"},
        {"stderr_log": "/opt/llama-server/llama.cpp-b11669-620d2225c/bin/llama-server"},
        {"binary": "/usr/local/bin/llama-server"},
        {"binary": "/opt/homebrew/bin/llama-server"},
        {"launchd_plist_path": "/Library/LaunchDaemons/other.plist"},
        {"user": "root"},
    ],
)
def test_source_build_rejects_unsafe_or_moved_layout(source_cfg: LlamaServerConfig, changes: dict[str, Any]) -> None:
    data = {**source_cfg.model_dump(exclude={"source_build", "binary"}), "source_build": source_cfg.source_build}
    with pytest.raises(ValidationError):
        LlamaServerConfig.model_validate({**data, **changes})


def fake_ls(stdout: str, returncode: int = 0) -> Any:
    return type("Result", (), {"stdout": stdout, "returncode": returncode})()


@pytest.mark.parametrize(
    ("stdout", "returncode", "expected"),
    [
        ("drwxr-xr-x  4 root  wheel  128 Oct 19 15:17 /opt/llama-server\n", 0, False),
        ("drwxr-xr-x@ 4 root  wheel  128 Oct 19 15:17 /opt/llama-server\n", 0, False),
        ("drwxr-xr-x+ 4 root  wheel  128 Oct 19 15:17 /opt/llama-server\n 0: user:owner allow add_file\n", 0, True),
        ("drwxr-xr-x@ 4 root  wheel  128 Oct 19 15:17 /x\n 0: group:staff allow write\n", 0, True),
        ("", 1, None),
        ("", 0, None),
    ],
)
def test_acl_check_fails_closed(stdout: str, returncode: int, expected: bool | None) -> None:
    module = host_script()
    with patch.object(module, "run", return_value=fake_ls(stdout, returncode)):
        if expected is None:
            with pytest.raises(RuntimeError, match="ACL"):
                module.has_acl("/x")
        else:
            assert module.has_acl("/x") is expected


def test_chain_refuses_links_other_than_the_system_ones(tmp_path: Path) -> None:
    module = host_script()
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with patch.object(module, "trusted_dir", return_value=True), pytest.raises(RuntimeError, match="link"):
        module.chain(str(tmp_path / "link"))
    with patch.object(module, "trusted_dir", return_value=False), pytest.raises(RuntimeError, match="root-only"):
        module.chain(str(tmp_path / "real"))


def source_host_cfg(**extra: Any) -> dict[str, Any]:
    import pwd

    return {
        "user": pwd.getpwuid(os.getuid()).pw_name,
        "build": "b11669-620d2225c",
        "binary": "/nonexistent/llama-server",
        "install_dir": "/nonexistent",
        "wheel": os.getgid(),
        "source_build": {"repository": "https://example.invalid/llama.cpp.git", "tag": "b11669", "commit": PIN_COMMIT},
        **extra,
    }


def test_wrong_checkout_aborts_before_cmake() -> None:
    module = host_script()
    calls: list[list[str]] = []

    def fake(cfg: dict[str, Any], argv: list[str], **_: Any) -> str:
        calls.append(argv)
        return "f" * 40 if "rev-parse" in argv else ""

    with patch.object(module, "build_run", side_effect=fake), pytest.raises(RuntimeError, match="pinned commit"):
        module.build_source(source_host_cfg(), "/ws")
    assert not any(argv[0] == "cmake" for argv in calls)
    git = [argv for argv in calls if argv[0] == "git"]
    assert git
    assert all(argv[:2] == ["git", "-c"] and "core.hooksPath=/dev/null" in argv for argv in git)


def test_wrong_build_number_aborts_before_cmake() -> None:
    module = host_script()

    def fake(cfg: dict[str, Any], argv: list[str], **_: Any) -> str:
        if "rev-parse" in argv:
            return PIN_COMMIT
        return "11670" if "rev-list" in argv else ""

    with patch.object(module, "build_run", side_effect=fake) as run, pytest.raises(RuntimeError, match="build number"):
        module.build_source(source_host_cfg(), "/ws")
    assert not any(call.args[1][0] == "cmake" for call in run.call_args_list)


def test_build_steps_refuse_a_root_service_user() -> None:
    module = host_script()
    with pytest.raises(RuntimeError, match="non-root"):
        module.build_run(source_host_cfg(user="root"), ["/usr/bin/true"])


def test_build_timeout_kills_the_whole_process_group() -> None:
    module = host_script()
    # Unique sleep durations mark exactly the two processes this test starts.
    tag = str(int.from_bytes(os.urandom(4), "big"))
    child, leader = f"/bin/sleep 30.{tag}", f"/bin/sleep 31.{tag}"
    with patch.object(module, "STEP_TIMEOUT", 1), pytest.raises(module.subprocess.TimeoutExpired):
        module.build_run(source_host_cfg(), ["/bin/sh", "-c", f"{child} & {leader}; wait"])
    left = module.subprocess.run(["/bin/ps", "-axo", "command="], capture_output=True, text=True).stdout
    assert child not in left
    assert leader not in left


def test_existing_mismatched_prefix_is_refused_not_replaced(tmp_path: Path) -> None:
    module = host_script()
    cfg = source_host_cfg(install_dir=str(tmp_path))
    (tmp_path / "llama.cpp-b11669-620d2225c").mkdir()
    with (
        patch.object(module, "source_installed", side_effect=RuntimeError("layout")),
        patch.object(module, "make_workspace") as workspace,
        pytest.raises(RuntimeError),
    ):
        module.publish_binary(cfg)
    workspace.assert_not_called()


def test_failed_build_removes_staging_and_workspace(tmp_path: Path) -> None:
    module = host_script()
    cfg = source_host_cfg(install_dir=str(tmp_path))
    removed: list[list[str]] = []

    def record(cfg: dict[str, Any], argv: list[str], **_: Any) -> str:
        removed.append(argv)
        return ""

    with (
        patch.object(module, "make_workspace", return_value="/ws"),
        patch.object(module, "build_source", side_effect=RuntimeError("fixture build failure")),
        patch.object(module, "build_run", side_effect=record),
        pytest.raises(RuntimeError, match="fixture"),
    ):
        module.publish_binary(cfg)
    assert removed == [["/bin/rm", "-rf", "/ws"]]
    assert list(tmp_path.iterdir()) == []


def test_fresh_put_replaces_a_multiply_linked_file_without_trusting_it(tmp_path: Path) -> None:
    module = host_script()
    target = tmp_path / "detector.plist"
    target.write_bytes(b"same bytes")
    os.link(target, tmp_path / "alias")
    before = target.stat().st_ino
    uid, gid = os.getuid(), os.getgid()
    assert module.put(str(target), b"same bytes", uid, gid, 0o644, fresh=True) is True
    after = target.stat()
    assert after.st_ino != before
    assert after.st_nlink == 1
    assert (tmp_path / "alias").read_bytes() == b"same bytes"
    assert module.put(str(target), b"same bytes", uid, gid, 0o644, fresh=True) is False


def test_build_step_reports_status_and_output() -> None:
    module = host_script()
    assert module.build_run(source_host_cfg(), ["/bin/sh", "-c", "echo out; echo err >&2"]) == "out\nerr\n"
    with pytest.raises(RuntimeError, match="step failed"):
        module.build_run(source_host_cfg(), ["/bin/sh", "-c", "exit 3"])
    # The step cannot forge the leader's status: the status pipe is closed for it.
    with pytest.raises(RuntimeError, match="step failed"):
        module.build_run(
            source_host_cfg(), ["/bin/sh", "-c", "for fd in 3 4 5 6 7 8 9; do echo 0 >&$fd; done 2>/dev/null; exit 1"]
        )


def test_build_step_output_is_size_capped() -> None:
    module = host_script()
    with patch.object(module, "OUTPUT_CAP", 4096), pytest.raises(RuntimeError, match="step failed"):
        module.build_run(source_host_cfg(), ["/bin/sh", "-c", "/usr/bin/yes | /usr/bin/head -c 100000"])


def test_reused_prefix_must_carry_the_full_commit(tmp_path: Path) -> None:
    module = host_script()
    cfg = source_host_cfg(install_dir=str(tmp_path))
    target = tmp_path / "llama.cpp-b11669-620d2225c"
    (target / "bin").mkdir(parents=True)
    (target / "SOURCE_COMMIT").write_text("620d2225c" + "0" * 31 + "\n")
    cfg["binary"] = str(target / "bin/llama-server")
    with (
        patch.object(module, "chain"),
        patch.object(module, "trusted_dir", return_value=True),
        patch.object(module, "exact_file", return_value=True),
        pytest.raises(RuntimeError, match="another commit"),
    ):
        module.source_installed(cfg)
    (target / "SOURCE_COMMIT").write_text(PIN_COMMIT + "\n")
    with (
        patch.object(module, "chain"),
        patch.object(module, "trusted_dir", return_value=True),
        patch.object(module, "exact_file", return_value=True),
    ):
        assert module.source_installed(cfg) is True


def test_status_pipe_works_with_only_standard_descriptors_open() -> None:
    # A fresh interpreter with only 0-2 open: os.pipe() then returns low
    # descriptors (3/4); the leader still uses fd 8 and the step cannot see it.
    import subprocess
    import sys

    script = (
        "import importlib.util, os, pwd, sys\n"
        "spec = importlib.util.spec_from_file_location('h', sys.argv[1])\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "cfg = {'user': pwd.getpwuid(os.getuid()).pw_name}\n"
        "print(m.build_run(cfg, ['/bin/sh', '-c', 'echo ok 2>/dev/null >&8 || echo closed']), end='')\n"
        "print(repr(m.build_run(cfg, ['/usr/bin/true'], quiet=True)))\n"
    )
    path = ROOT / "src/ops_deploy/services/llama_server/files/llama_server_host.py"
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path)], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "closed\n''\n"


def test_chain_rechecks_the_system_link_target_from_root() -> None:
    import stat as stat_module

    module = host_script()
    seen: list[str] = []

    def trusted(path: str, *args: Any) -> bool:
        seen.append(path)
        return True

    def lstat(path: str) -> Any:
        # The Darwin layout on every platform: /etc -> private/etc, root-owned.
        kind = stat_module.S_IFLNK if path == "/etc" else stat_module.S_IFDIR
        return os.stat_result((kind | 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    with (
        patch.object(module, "trusted_dir", side_effect=trusted),
        patch.object(module.os, "lstat", side_effect=lstat),
        patch.object(module.os, "readlink", return_value="private/etc"),
    ):
        assert module.chain("/etc/llama-server") == "/private/etc/llama-server"
    assert seen == ["/", "/", "/private", "/private/etc", "/private/etc/llama-server"]
