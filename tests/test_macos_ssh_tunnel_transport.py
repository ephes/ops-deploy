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
