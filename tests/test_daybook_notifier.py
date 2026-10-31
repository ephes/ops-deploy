"""Original declaration, private stdin and actual SDK no-send planning controls."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pyinfra.api.facts as sdk_facts
import pytest
from pydantic import ValidationError
from pyinfra.facts.server import Command, Os

from ops_deploy.services.daybook_voice_memo_attention_notifier import (
    DaybookVoiceMemoAttentionNotifierConfig,
    DaybookVoiceMemoAttentionNotifierPins,
    install_daybook_voice_memo_attention_notifier,
)
from ops_deploy.services.daybook_voice_memo_attention_notifier.deploy import component_command, payload
from ops_deploy.testing import run_deploy_fake

KEY = "ssh-ed25519 " + "A" * 68 + " owned"


def pins() -> DaybookVoiceMemoAttentionNotifierPins:
    return DaybookVoiceMemoAttentionNotifierPins(public_key=KEY, native_host="owned-host", recipient="123456789")


@pytest.mark.parametrize(
    "values",
    [
        {"public_key": "ssh-rsa invalid"},
        {"native_host": "CHANGEME"},
        {"native_host": "bad\n"},
        {"recipient": "01234"},
        {"recipient": "1234"},
    ],
)
def test_original_invalid_pins_withheld(values: dict[str, str]) -> None:
    request = {"public_key": KEY, "native_host": "owned-host", "recipient": "123456789", **values}
    with pytest.raises(ValidationError) as caught:
        DaybookVoiceMemoAttentionNotifierPins(**request)
    assert KEY not in str(caught.value)
    assert "123456789" not in str(caught.value)


@pytest.mark.parametrize("path", ["relative.py", "/tmp/noextension", "/tmp/../x.py", "/tmp/x\n.py"])
def test_original_absolute_standalone_source(path: str) -> None:
    with pytest.raises(ValidationError):
        DaybookVoiceMemoAttentionNotifierConfig(script_src=path)


def test_payload_private_pins_and_compile_only_source(tmp_path: Path) -> None:
    source = tmp_path / "work_notify.py"
    source.write_text("raise RuntimeError('not executed')\n")
    cfg = DaybookVoiceMemoAttentionNotifierConfig(script_src=str(source))
    data = json.loads(payload(cfg, pins()))
    assert set(data) == {"public_key", "native_host", "recipient", "container", "script_base64"}
    assert data["public_key"] == KEY
    assert KEY not in repr(pins())
    assert data["recipient"] not in repr(pins())
    assert KEY not in component_command("status") + component_command("install")


def test_real_sdk_status_and_managed_validation_repeat_no_app_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "work_notify.py"
    source.write_text("raise RuntimeError('not executed')\n")
    cfg = DaybookVoiceMemoAttentionNotifierConfig(script_src=str(source))
    calls: list[str] = []

    def fact(
        state: Any,
        host: Any,
        cls: Any,
        args: Any = None,
        kwargs: Any = None,
        ensure_hosts: Any = None,
        apply_failed_hosts: bool = True,
    ) -> Any:
        if cls is Os:
            return "Linux"
        if cls is Command:
            assert kwargs["command"] == component_command("status")
            assert kwargs["_get_pty"] is False
            private = json.loads(kwargs["_stdin"].read())
            assert private["public_key"] == KEY
            calls.append("status")
            return json.dumps(dict.fromkeys(("directories", "script", "config", "authorization"), True))
        raise AssertionError(cls)

    monkeypatch.setattr(sdk_facts, "_get_fact", fact)
    result = run_deploy_fake(install_daybook_voice_memo_attention_notifier, cfg, pins=pins())
    assert result.succeeded
    assert len(result.mutating_changed_ops) == 1
    assert calls == ["status"]
    assert KEY not in repr(result.ops)


def test_original_role_paths_options_and_defaults() -> None:
    import os

    import yaml

    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH unset; paired original-role check is separate")
    root = Path(source) / "roles/daybook_voice_memo_attention_notifier_deploy"
    tasks = yaml.safe_load((root / "tasks/main.yml").read_text())
    inspection = next(task for task in tasks if task["name"] == "Inspect notifier managed paths")
    assert inspection["loop"] == [
        "/usr/local",
        "/usr/local/libexec",
        "/usr/local/libexec/daybook-attention-notify.py",
        "/etc/daybook-attention-notify.json",
        "/root/.ssh",
        "/root/.ssh/authorized_keys",
    ]
    defaults = yaml.safe_load((root / "defaults/main.yml").read_text())
    assert (
        defaults["daybook_voice_memo_attention_notifier_container"]
        == DaybookVoiceMemoAttentionNotifierConfig(script_src="/owned/work_notify.py").container
    )
    authorization = next(
        task for task in tasks if task["name"] == "Define the single restricted notifier authorization"
    )
    assert authorization["ansible.builtin.set_fact"]["daybook_voice_memo_attention_notifier_key_options"] == (
        'restrict,command="/usr/bin/python3 -I /usr/local/libexec/daybook-attention-notify.py '
        '--config /etc/daybook-attention-notify.json"'
    )


@pytest.mark.parametrize("kind", ["fifo", "directory", "symlink", "oversized"])
def test_source_descriptor_refuses_nonregular_or_oversized_without_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    import os

    from ops_deploy.services.daybook_voice_memo_attention_notifier.deploy import read_source

    source = tmp_path / "source.py"
    if kind == "fifo":
        os.mkfifo(source)
    elif kind == "directory":
        source.mkdir()
    elif kind == "symlink":
        target = tmp_path / "target.py"
        target.write_text("pass\n")
        source.symlink_to(target)
    else:
        source.write_bytes(b"x" * 131073)

    def forbidden_read(*args: Any, **kwargs: Any) -> bytes:
        raise AssertionError("unsafe source must not be read")

    monkeypatch.setattr(os, "read", forbidden_read)
    with pytest.raises(ValueError, match="Notifier source"):
        read_source(source)


@pytest.mark.parametrize("kind", ["grow", "replace", "same_size_metadata_change"])
def test_source_descriptor_changes_are_refused_and_reads_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    import os

    from ops_deploy.services.daybook_voice_memo_attention_notifier.deploy import read_source

    source = tmp_path / "source.py"
    source.write_bytes(b"pass\n")
    replacement = tmp_path / "replacement.py"
    replacement.write_bytes(b"None\n")
    original_read = os.read
    counts: list[int] = []
    first = True

    def read(fd: int, count: int) -> bytes:
        nonlocal first
        if first:
            first = False
            if kind == "grow":
                with source.open("ab") as output:
                    output.write(b"x" * 262144)
            elif kind == "replace":
                os.replace(replacement, source)
            else:
                before = source.stat()
                source.write_bytes(b"None\n")
                # Make the observed metadata change deterministic even on a
                # filesystem whose timestamp clock has coarse granularity.
                os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
        value = original_read(fd, count)
        counts.append(len(value))
        assert count <= 65536
        return value

    monkeypatch.setattr(os, "read", read)
    with pytest.raises(ValueError, match="changed during"):
        read_source(source)
    assert sum(counts) <= 131073
