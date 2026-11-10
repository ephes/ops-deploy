"""Delegated SSH profile parity and authorization-before-local-mutation contract."""

from __future__ import annotations

import base64
import json
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.macos_ssh_tunnel import MacosSshTunnelConfig
from ops_deploy.services.macos_ssh_tunnel.deploy import host_command

ROOT = Path(__file__).resolve().parents[1]


def recorded(calls: list[Any], value: Any, result: Any) -> Any:
    calls.append(value)
    return result


def helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], dict[str, Any]]:
    cache = tmp_path.parent / ("control-" + tmp_path.name)
    cache.mkdir(mode=0o700, exist_ok=True)
    cfg = MacosSshTunnelConfig(
        owner="operator",
        home=tmp_path,
        host="relay.example.test",
        user="operator",
        target="backend.example.test",
        manage_identity=True,
        relay_home="/Users/operator",
        ssh_connect_timeout=30,
        ssh_control_path=str(cache / "ansible-ssh-%h-%p-%r"),
    )
    command = shlex.split(host_command(cfg, "status"))
    ns: dict[str, Any] = {"__name__": "owned_transport_unit"}
    exec(compile(command[3], "<transport-unit>", "exec"), ns)
    data = json.loads(base64.b64decode(command[-1]))
    for path, text in data["contents"].items():
        resource = Path(path)
        resource.parent.mkdir(parents=True, exist_ok=True)
        resource.write_text(text)
    monkeypatch.setitem(ns, "prepare", lambda value: value)
    monkeypatch.setitem(ns, "identity", lambda _: {"state": "current", "public_key": "ssh-ed25519 synthetic-public"})
    monkeypatch.setitem(ns, "directory_current", lambda *args: True)
    monkeypatch.setitem(ns, "file_metadata", lambda *args: True)
    monkeypatch.setitem(ns, "disabled", lambda _: True)
    monkeypatch.setitem(ns, "loaded", lambda _: False)
    return ns, data


def invoke(ns: dict[str, Any], data: dict[str, Any], action: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["helper", action, base64.b64encode(json.dumps(data).encode()).decode()])
    ns["main"]()


def test_status_actually_checks_relay_but_post_local_verify_does_not_repeat_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ns, data = helper(tmp_path, monkeypatch)
    checks: list[bool] = []

    def authorize(_: Any, public: str, check: bool) -> bool:
        assert public == "ssh-ed25519 synthetic-public"
        checks.append(check)
        return True

    monkeypatch.setitem(ns, "authorize", authorize)
    invoke(ns, data, "status", monkeypatch)
    assert capsys.readouterr().out.strip() == "current"
    assert checks == [True]
    invoke(ns, data, "verify", monkeypatch)
    assert "automatic start remains disabled" in capsys.readouterr().out
    assert checks == [True]


def test_failed_actual_authorization_prevents_stop_and_resource_updates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ns, data = helper(tmp_path, monkeypatch)
    events: list[str] = []

    def authorize(*args: Any) -> bool:
        events.append("authorization")
        raise RuntimeError("owned authorization fault")

    monkeypatch.setitem(ns, "authorize", authorize)
    monkeypatch.setitem(ns, "stop", lambda _: events.append("stop"))
    monkeypatch.setitem(ns, "put", lambda *args: events.append("put"))
    with pytest.raises(RuntimeError, match="owned authorization fault"):
        invoke(ns, data, "apply", monkeypatch)
    assert events == ["authorization"]


def test_successful_authorization_converges_before_local_stop_and_put(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ns, data = helper(tmp_path, monkeypatch)
    events: list[str] = []

    def authorize(_: Any, public: str, check: bool) -> bool:
        assert check is False
        events.append("authorization")
        return True

    monkeypatch.setitem(ns, "authorize", authorize)
    monkeypatch.setitem(ns, "stop", lambda _: events.append("stop"))
    monkeypatch.setitem(ns, "put", lambda *args: events.append("put"))
    invoke(ns, data, "apply", monkeypatch)
    assert events[:2] == ["authorization", "stop"]
    assert events[2:] == ["put"] * 4


def options(argv: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    iterator = iter(argv)
    for arg in iterator:
        if arg == "-o":
            arg = next(iterator)
        elif arg.startswith("-o"):
            arg = arg[2:]
        else:
            continue
        key, _, value = arg.partition("=")
        result.setdefault(key.lower(), shlex.split(value)[0])
    return result


def test_original_ssh_session_options_and_no_extra_whole_ssh_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ns, data = helper(tmp_path, monkeypatch)
    calls: list[Any] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout='{"current":true}')

    monkeypatch.setitem(ns, "run", run)
    assert ns["authorize"](data, "ssh-ed25519 synthetic-public", True)
    argv, kwargs = calls[0]
    opts = options(argv)
    assert opts["controlmaster"] == "auto"
    assert opts["controlpersist"] == "60s"
    assert opts["controlpath"] == data["ssh_control_path"]
    assert opts["connecttimeout"] == "30"
    assert opts["batchmode"] == "yes"
    assert opts["stricthostkeychecking"] == "yes"
    assert opts["updatehostkeys"] == "no"
    assert opts["userknownhostsfile"] == data["known_hosts"]
    assert kwargs["timeout"] is None
    request = json.loads(kwargs["input"])
    assert request["check"] is True
    assert request["comment"] == data["identity_comment"]
    assert 'restrict,port-forwarding,permitopen="backend.example.test:443",command="/usr/bin/false"' in request["line"]


@pytest.mark.parametrize(
    "change",
    [
        {"ssh_connect_timeout": 0},
        {"ssh_control_path": "relative.sock"},
        {"ssh_control_path": "/tmp/../bad.sock"},
        {"ssh_control_path": "/tmp/%x.sock"},
        {"ssh_control_path": "/tmp/sock\nProxyCommand=unsafe"},
    ],
)
def test_invalid_transport_profile_refused(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MacosSshTunnelConfig(
            owner="operator",
            home="/Users/operator",
            host="relay.example.test",
            user="operator",
            target="backend.example.test",
            **change,
        )


def test_local_command_deadline_stays_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ns, _ = helper(tmp_path, monkeypatch)
    calls: list[Any] = []
    monkeypatch.setattr(
        ns["subprocess"], "run", lambda *args, **kwargs: recorded(calls, kwargs, SimpleNamespace(returncode=0))
    )
    ns["run"](["/usr/bin/true"])
    assert calls[0]["timeout"] == 30


def test_generated_ansible_ssh_profile_matches_authorization_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generate the original controller profile with real Ansible, no network."""
    import os
    import shutil
    import subprocess

    binary = shutil.which("ansible")
    if binary is None:
        pytest.skip("actual Ansible SSH oracle is run explicitly on the paired controller")
    calls = tmp_path / "ssh-calls"
    calls.mkdir()
    stub = tmp_path / "ssh-stub"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys,uuid\nfrom pathlib import Path\n"
        "(Path(os.environ['SSH_CALLS'])/str(uuid.uuid4())).write_text(json.dumps(sys.argv[1:]))\n"
        "print('owned no-network SSH oracle')\n"
    )
    stub.chmod(0o755)
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(
        "all:\n  hosts:\n    relay:\n      ansible_host: relay.example.test\n"
        "      ansible_user: operator\n      ansible_port: 22\n"
        "      ansible_ssh_common_args: -o BatchMode=yes -o StrictHostKeyChecking=yes\n"
    )
    ansible_cfg = tmp_path / "ansible.cfg"
    ansible_cfg.write_text(
        "[defaults]\nhost_key_checking=True\ntimeout=30\n"
        "[ssh_connection]\npipelining=True\n"
        "control_path=/tmp/ansible-ssh-%%h-%%p-%%r\n"
    )
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(ansible_cfg),
        "ANSIBLE_SSH_EXECUTABLE": str(stub),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "SSH_CALLS": str(calls),
    }
    completed = subprocess.run(
        [binary, "all", "-i", str(inventory), "-m", "ansible.builtin.raw", "-a", "/usr/bin/true"],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    generated = [json.loads(p.read_text()) for p in calls.iterdir()]
    assert generated
    original_options = options(generated[0])
    ns, data = helper(tmp_path / "owner", monkeypatch)
    observed: list[list[str]] = []
    monkeypatch.setitem(
        ns, "run", lambda argv, **kwargs: recorded(observed, argv, SimpleNamespace(stdout='{"current":true}'))
    )
    assert ns["authorize"](data, "ssh-ed25519 synthetic-public", True)
    actual_options = options(observed[0])
    for name in (
        "controlmaster",
        "controlpersist",
        "connecttimeout",
    ):
        assert actual_options[name] == original_options[name], name
    # Intentional cache-location correction: preserve the original pattern
    # under an existing owner-private parent rather than the shared /tmp.
    assert Path(actual_options["controlpath"]).name == Path(original_options["controlpath"]).name
    assert Path(actual_options["controlpath"]).parent != Path(original_options["controlpath"]).parent
    assert "-C" in generated[0]
    assert "-C" in observed[0]


@pytest.mark.parametrize("cache_state", ["default", "missing", "insecure"])
def test_unselected_or_unavailable_private_cache_uses_isolated_native_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cache_state: str,
) -> None:
    ns, data = helper(tmp_path, monkeypatch)
    if cache_state == "default":
        data["ssh_control_path"] = None
    elif cache_state == "missing":
        data["ssh_control_path"] = str(tmp_path.parent / "never-created" / "ssh-%h-%p-%r")
    else:
        Path(data["ssh_control_path"]).parent.chmod(0o755)
    calls: list[list[str]] = []
    monkeypatch.setitem(
        ns, "run", lambda argv, **kwargs: recorded(calls, argv, SimpleNamespace(stdout='{"current":true}'))
    )
    assert ns["authorize"](data, "ssh-ed25519 synthetic-public", True)
    opts = options(calls[0])
    assert opts["controlmaster"] == "no"
    assert opts["controlpath"] == "none"
    assert "controlpersist" not in opts
    assert opts["stricthostkeychecking"] == "yes"
    assert opts["userknownhostsfile"] == data["known_hosts"]
    assert not (tmp_path.parent / "never-created").exists()


def test_cache_cannot_enter_managed_trees_even_with_tokens() -> None:
    for path in ("/Users/operator/runtime/auth.sock", "/Users/operator/runtime/%h-%p-%r"):
        with pytest.raises(ValidationError, match="outside protected"):
            MacosSshTunnelConfig(
                owner="operator",
                home="/Users/operator",
                host="relay.example.test",
                user="operator",
                target="backend.example.test",
                directory="/Users/operator/runtime",
                ssh_control_path=path,
            )


@pytest.mark.parametrize("kind", ["foreign", "insecure", "regular"])
def test_untrusted_existing_cache_object_is_untouched_and_not_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    import stat

    ns, data = helper(tmp_path, monkeypatch)
    expanded = (
        data["ssh_control_path"]
        .replace("%h", data["host"])
        .replace("%p", str(data["ssh_port"]))
        .replace("%r", data["user"])
    )
    original = ns["os"].lstat
    mode = stat.S_IFREG | 0o600 if kind == "regular" else stat.S_IFSOCK | (0o666 if kind == "insecure" else 0o600)
    uid = ns["os"].geteuid() + 1 if kind == "foreign" else ns["os"].geteuid()

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path) == expanded:
            return SimpleNamespace(st_mode=mode, st_uid=uid)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(ns["os"], "lstat", lstat)
    calls: list[list[str]] = []
    monkeypatch.setitem(
        ns, "run", lambda argv, **kwargs: recorded(calls, argv, SimpleNamespace(stdout='{"current":true}'))
    )
    assert ns["authorize"](data, "ssh-ed25519 synthetic-public", True)
    assert options(calls[0])["controlmaster"] == "no"
    assert options(calls[0])["controlpath"] == "none"


def retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The helper for a state="absent" retirement with the original relay step."""
    ns, data = helper(tmp_path, monkeypatch)
    data.update({"state": "absent", "retire_identity": True, **overrides})
    for path in data["contents"]:
        Path(path).unlink()
    return ns, data


def test_retirement_stops_removes_revokes_then_removes_identity_last(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ns, data = retirement(tmp_path, monkeypatch)
    for path in data["contents"]:
        Path(path).write_text("installed")
    events: list[str] = []
    identity_state = {"state": "current", "public_key": "ssh-ed25519 synthetic-public"}

    def stop(_: Any) -> None:
        assert all(Path(path).exists() for path in data["contents"])
        events.append("stop")

    def revoke(_: Any, check: bool) -> bool:
        assert not any(Path(path).exists() for path in data["contents"])
        events.append(f"revoke check={check}")
        return True

    def manage(args: Any) -> dict[str, Any]:
        assert args.state == "absent"
        assert args.check is False
        assert args.path == data["identity"]
        assert args.comment == data["identity_comment"]
        events.append("identity removed")
        identity_state.clear()
        identity_state["state"] = "missing"
        return {"status": "removed", "changed": True}

    monkeypatch.setitem(ns, "stop", stop)
    monkeypatch.setitem(ns, "revoke", revoke)
    monkeypatch.setitem(ns, "identity", lambda _: dict(identity_state))
    monkeypatch.setitem(ns["ns"], "manage", manage)
    monkeypatch.setitem(ns, "authorize", lambda *args: pytest.fail("a retirement never authorizes"))
    invoke(ns, data, "apply", monkeypatch)
    assert events == ["stop", "revoke check=False", "identity removed"]
    invoke(ns, data, "verify", monkeypatch)
    assert "Tunnel removal is converged." in capsys.readouterr().out
    assert events[-1] == "identity removed"


def test_failed_revocation_keeps_the_identity_for_a_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ns, data = retirement(tmp_path, monkeypatch)
    events: list[str] = []

    def revoke(*args: Any) -> bool:
        events.append("revoke")
        raise RuntimeError("owned relay fault")

    monkeypatch.setitem(ns, "stop", lambda _: events.append("stop"))
    monkeypatch.setitem(ns, "revoke", revoke)
    monkeypatch.setitem(ns["ns"], "manage", lambda args: events.append("identity removed"))
    with pytest.raises(RuntimeError, match="owned relay fault"):
        invoke(ns, data, "apply", monkeypatch)
    assert events == ["stop", "revoke"]


@pytest.mark.parametrize(
    ("identity_state", "relay_current", "expected"),
    [
        ("missing", True, "current"),
        ("missing", False, "drift"),
        ("current", True, "drift"),
        ("drift", True, "drift"),
        ("unsafe", True, "drift"),
    ],
)
def test_retirement_status_requires_missing_identity_and_revoked_relay_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    identity_state: str,
    relay_current: bool,
    expected: str,
) -> None:
    ns, data = retirement(tmp_path, monkeypatch)
    checks: list[bool] = []

    def identity(_: Any) -> dict[str, Any]:
        if identity_state == "unsafe":
            raise ns["probe_ns"]["IdentityProbeError"]("owned unsafe identity")
        return {"state": identity_state}

    def revoke(_: Any, check: bool) -> bool:
        checks.append(check)
        return relay_current

    monkeypatch.setitem(ns, "identity", identity)
    monkeypatch.setitem(ns, "revoke", revoke)
    invoke(ns, data, "status", monkeypatch)
    assert capsys.readouterr().out.strip() == expected
    assert checks == ([True] if identity_state == "missing" else [])


def test_absent_without_retirement_keeps_identity_and_relay_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ns, data = retirement(tmp_path, monkeypatch, retire_identity=False)
    events: list[str] = []
    monkeypatch.setitem(ns, "stop", lambda _: events.append("stop"))
    monkeypatch.setitem(ns, "revoke", lambda *args: events.append("revoke"))
    monkeypatch.setitem(ns["ns"], "manage", lambda args: events.append("identity removed"))
    invoke(ns, data, "apply", monkeypatch)
    assert events == ["stop"]


def test_revocation_uses_the_original_session_and_sends_no_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ns, data = retirement(tmp_path, monkeypatch)
    calls: list[Any] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout='{"current":false,"changed":true}')

    monkeypatch.setitem(ns, "run", run)
    assert ns["revoke"](data, True) is False
    argv, kwargs = calls[0]
    assert options(argv)["controlmaster"] == "auto"
    assert options(argv)["stricthostkeychecking"] == "yes"
    assert kwargs["timeout"] is None
    request = json.loads(kwargs["input"])
    assert request == {
        "home": "/Users/operator",
        "comment": data["identity_comment"],
        "check": True,
        "revoke": True,
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"state": "present"}, "identity retirement requires"),
        ({"manage_identity": False, "relay_home": None}, "identity retirement requires"),
        ({"identity_comment": "restricted-forwarding"}, "unique, non-default identity_comment"),
    ],
)
def test_retirement_requires_absent_state_managed_identity_and_unique_comment(
    change: dict[str, Any], message: str
) -> None:
    values: dict[str, Any] = {
        "owner": "operator",
        "home": "/Users/operator",
        "host": "relay.example.test",
        "user": "operator",
        "target": "backend.example.test",
        "state": "absent",
        "manage_identity": True,
        "relay_home": "/Users/operator",
        "identity_comment": "uat-forwarding-workstation",
        "retire_identity": True,
    }
    MacosSshTunnelConfig(**values)
    with pytest.raises(ValidationError, match=message):
        MacosSshTunnelConfig(**{**values, **change})


def relay_script(tmp_path: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Run the packaged relay program as the remote side does: stdin JSON, own home."""
    import subprocess

    script = ROOT / "src/ops_deploy/services/macos_ssh_tunnel/files/relay_authorization_host.py"
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script.read_text()],
        input=json.dumps({"home": str(tmp_path), **request}) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    result: dict[str, Any] = json.loads(completed.stdout)
    return result


def test_relay_program_revokes_only_lines_with_the_managed_comment(tmp_path: Path) -> None:
    home = tmp_path.resolve()
    home.chmod(0o700)
    ssh = home / ".ssh"
    ssh.mkdir(mode=0o700)
    keys = ssh / "authorized_keys"
    original = (
        b"ssh-ed25519 AAAAother operator@laptop\n"
        b"restrict,port-forwarding ssh-ed25519 AAAAone emerge-uat-forwarding-studio\n"
        b"ssh-ed25519 AAAAkeep emerge-uat-forwarding-studio-old\n"
        b"ssh-ed25519 AAAAtwo emerge-uat-forwarding-studio\r\n"
    )
    keys.write_bytes(original)
    keys.chmod(0o644)
    request = {"comment": "emerge-uat-forwarding-studio", "revoke": True}
    assert relay_script(home, {**request, "check": True}) == {"current": False, "changed": True, "revoked_lines": 2}
    assert keys.read_bytes() == original
    assert relay_script(home, {**request, "check": False})["changed"] is True
    assert keys.read_bytes() == (
        b"ssh-ed25519 AAAAother operator@laptop\nssh-ed25519 AAAAkeep emerge-uat-forwarding-studio-old\n"
    )
    assert keys.stat().st_mode & 0o777 == 0o644
    assert relay_script(home, {**request, "check": True}) == {"current": True, "changed": False, "revoked_lines": 0}
    keys.unlink()
    assert relay_script(home, {**request, "check": False}) == {"current": True, "changed": False, "revoked_lines": 0}
    assert not keys.exists()


def test_relay_program_authorization_is_unchanged_by_revocation_support(tmp_path: Path) -> None:
    home = tmp_path.resolve()
    home.chmod(0o700)
    (home / ".ssh").mkdir(mode=0o700)
    line = "restrict,port-forwarding ssh-ed25519 AAAAone emerge-uat-forwarding-studio"
    request = {"comment": "emerge-uat-forwarding-studio", "line": line}
    assert relay_script(home, {**request, "check": False})["changed"] is True
    keys = home / ".ssh/authorized_keys"
    assert keys.read_text() == line + "\n"
    assert keys.stat().st_mode & 0o777 == 0o600
    assert relay_script(home, {**request, "check": True})["current"] is True


def test_relay_program_revocation_without_ssh_directory_is_current(tmp_path: Path) -> None:
    home = tmp_path.resolve()
    home.chmod(0o700)
    request = {"comment": "emerge-uat-forwarding-studio", "revoke": True}
    for check in (True, False):
        result = relay_script(home, {**request, "check": check})
        assert result == {"current": True, "changed": False, "revoked_lines": 0}
    assert not (home / ".ssh").exists()


@pytest.mark.parametrize(
    ("retire", "apply_name"),
    [
        (False, "Remove stopped tunnel"),
        (True, "Remove stopped tunnel, revoke relay authorization and identity"),
    ],
)
def test_absent_deploy_names_and_status_apply_verify_flow(retire: bool, apply_name: str) -> None:
    from ops_deploy.services.macos_ssh_tunnel import deploy_macos_ssh_tunnel
    from ops_deploy.testing import run_deploy_fake

    cfg = MacosSshTunnelConfig(
        owner="operator",
        home="/Users/operator",
        host="relay.example.test",
        user="operator",
        target="backend.example.test",
        state="absent",
        manage_identity=True,
        relay_home="/Users/operator",
        identity_comment="uat-forwarding-workstation",
        retire_identity=retire,
    )
    drift = run_deploy_fake(deploy_macos_ssh_tunnel, cfg, responses={" status ": ["drift"]})
    assert drift.succeeded
    assert [" apply " in c for c in drift.executed_commands] == [True, False]
    assert " verify " in drift.executed_commands[1]
    prefix = "Deploy owner-session macOS SSH tunnel stopped | "
    assert drift.mutating_changed_ops == [prefix + apply_name]
    assert drift.changed_ops == [prefix + apply_name, prefix + "Verify owner-session tunnel is removed"]
    current = run_deploy_fake(deploy_macos_ssh_tunnel, cfg, responses={" status ": ["current"]})
    assert current.succeeded
    assert len(current.executed_commands) == 1
    assert " verify " in current.executed_commands[0]


@pytest.mark.parametrize("ssh_directory", [False, True])
def test_relay_program_rejects_a_malformed_comment_before_the_filesystem(tmp_path: Path, ssh_directory: bool) -> None:
    import subprocess

    home = tmp_path.resolve()
    home.chmod(0o700)
    if ssh_directory:
        (home / ".ssh").mkdir(mode=0o700)
    with pytest.raises(subprocess.CalledProcessError):
        relay_script(home, {"comment": "bad comment", "revoke": True, "check": True})
