"""Optional paired actual Ansible Templar/authorized_key semantics on owned files."""

from __future__ import annotations

import base64
import importlib.util
import os
import sys
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml


@pytest.mark.parametrize(
    "case", ["fresh", "administrator", "current", "conflicting_options", "foreign_marker", "duplicate"]
)
def test_actual_original_validation_and_authorized_key_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    authorized_module = os.environ.get("ANSIBLE_POSIX_MODULE")
    if not library or not authorized_module:
        pytest.skip("paired original-role oracle requires OPS_LIBRARY_PATH and ANSIBLE_POSIX_MODULE")
    from ansible.template import Templar, trust_as_template  # type: ignore[import-untyped]

    def load(name: str, path: Path) -> Any:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    tasks = yaml.safe_load(
        (Path(library) / "roles/daybook_voice_memo_attention_notifier_deploy/tasks/main.yml").read_text()
    )
    role = {task["name"]: task for task in tasks}
    original = load("owned_original_authorized_key", Path(authorized_module))
    fs = load(
        "owned_notifier_original_fs",
        Path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py"))),
    )
    monkeypatch.setitem(sys.modules, "ops_notifier_filesystem", fs)
    helper = load(
        "owned_notifier_original_compare",
        Path(
            str(files("ops_deploy.services.daybook_voice_memo_attention_notifier").joinpath("files/notifier_host.py"))
        ),
    )
    prefix = "daybook_voice_memo_attention_notifier_"
    key = "ssh-ed25519 " + "A" * 68
    request = {
        "script_src": str(tmp_path / "work_notify.py"),
        "public_key": key + " owned",
        "native_host": "owned-host",
        "recipient": "123456789",
        "container": "openclaw-gateway",
    }
    variables: dict[str, Any] = {prefix + name: value for name, value in request.items()}
    variables["ansible_facts"] = {"system": "Linux"}
    templar = Templar(variables=variables)
    for expression in role["Validate attention notifier deployment inputs"]["ansible.builtin.assert"]["that"]:
        assert templar.evaluate_conditional(trust_as_template(expression))
    for name, value in role["Define the single restricted notifier authorization"]["ansible.builtin.set_fact"].items():
        variables[name] = templar.template(trust_as_template(value))
    options = variables[prefix + "key_options"]
    exact = options + " " + key + " daybook-attention-notifier\n"
    administrator = "# retain administrator\nssh-ed25519 " + "B" * 68 + " administrator\n\n"
    bodies = {
        "fresh": "",
        "administrator": administrator,
        "current": administrator + exact,
        "conflicting_options": key + " administration-key\n",
        "foreign_marker": "ssh-ed25519 " + "C" * 68 + " daybook-attention-notifier\n",
        "duplicate": exact + exact,
    }
    body = bodies[case]
    variables[prefix + "existing_keys"] = {"content": base64.b64encode(body.encode()).decode()}
    templar = Templar(variables=variables)
    original_safe = all(
        templar.evaluate_conditional(trust_as_template(expression))
        for expression in role["Reject reuse of a differently authorized existing key"]["ansible.builtin.assert"][
            "that"
        ]
    )
    if case in {"conflicting_options", "foreign_marker"}:
        assert not original_safe
        with pytest.raises(helper.Refused):
            helper.authorization(body.encode(), key)
        return
    assert original_safe
    if case == "fresh":
        # Compare actual original to_nice_json output with the helper's fresh
        # seed, while routing all filesystem observations to owned synthetic
        # absence. This executes the original Ansible serialization template.
        content = role["Install pinned private notifier configuration"]["ansible.builtin.copy"]["content"]
        original_config = templar.template(trust_as_template(content)).encode()
        monkeypatch.setattr(helper, "inspect_directory", lambda path: (0, 0, 0, 0, 0o40755, 1, 0, 0, 0))
        monkeypatch.setattr(helper, "read", lambda path, limit: (None, None))
        desired = helper.snapshot(
            {name: request[name] for name in ("public_key", "native_host", "recipient", "container")}
            | {"script_base64": base64.b64encode(b"pass\n").decode()}
        )[2]
        assert desired[helper.CONFIG] == original_config
    target = tmp_path / "authorized_keys"
    target.write_text(body)
    writes: list[str] = []

    def write(_module: Any, filename: str, content: str) -> None:
        assert filename == str(target)
        writes.append(content)
        target.write_text(content)

    def fail(**kwargs: Any) -> None:
        raise AssertionError("actual original module unexpectedly refused owned fixture")

    module = SimpleNamespace(_diff=False, check_mode=False, fail_json=fail)
    monkeypatch.setattr(original, "keyfile", lambda *args, **kwargs: str(target))
    monkeypatch.setattr(original, "writefile", write)
    params = {
        "user": "root",
        "key": key,
        "key_options": options,
        "comment": "daybook-attention-notifier",
        "exclusive": False,
        "state": "present",
    }
    result = original.enforce_state(module, params)
    candidate = helper.authorization(body.encode(), key).decode()

    def semantic(text: str) -> dict[str, Any]:
        return {
            identity: value[:4]
            for identity, value in original.parsekeys(module, text).items()
            if value[1] not in (None, "skipped")
        }

    assert semantic(candidate) == semantic(target.read_text())
    assert target.read_text().count(options + " " + key) == (2 if case == "duplicate" else 1)
    assert bool(result.get("changed")) is (case not in {"current", "duplicate"})
    if case in {"administrator", "current"}:
        assert "B" * 68 in target.read_text()
        assert candidate.startswith(administrator)
    if case in {"current", "duplicate"}:
        assert not writes
        assert candidate == body
