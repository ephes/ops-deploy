"""Original role command/order oracle and owned state machine controls only."""

from __future__ import annotations

import os
import runpy
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

M: dict[str, Any] = runpy.run_path(
    str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_controls.py"))
)


class Runner:
    def __init__(self, *, loaded: bool = True, disabled: bool = False, faults: tuple[str, ...] = ()) -> None:
        self.loaded = loaded
        self.disabled = disabled
        self.faults = faults
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> SimpleNamespace:
        self.calls.append(argv)
        command = argv[1]
        rc, out, err = 0, b"", b""
        if command in self.faults:
            return SimpleNamespace(returncode=127, stdout=b"", stderr=b"owned tool error")
        if command == "print" and len(argv[2].split("/")) == 3:
            if self.loaded:
                out = b"pid = 12345\n"
            else:
                rc, err = 113, b'Could not find service "example.owned.photos" in domain for user gui: 501'
        elif command == "print-disabled":
            out = b'"example.owned.photos" => true' if self.disabled else b'"example.owned.photos" => false'
        elif command == "disable":
            self.disabled = True
        elif command == "bootout":
            rc = 0 if self.loaded else 113
            self.loaded = False
        elif command == "enable":
            self.disabled = False
        elif command == "bootstrap":
            self.loaded = True
        return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def controls(runner: Runner) -> Any:
    return M["PhotosControls"]({"uid": 501, "label": "example.owned.photos", "plist": "/owned/photos.plist"}, runner)


def test_original_role_exact_command_order_oracle() -> None:
    root = os.environ.get("OPS_LIBRARY_PATH")
    if not root:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    tasks = yaml.safe_load((Path(root) / "roles/daybook_photos_offload_deploy/tasks/main.yml").read_text())
    names = [row["name"] for row in tasks]
    assert names.index("quiesce | Disable Photos offload before changing deployment state") < names.index(
        "quiesce | Boot out the exact loaded Photos offload service"
    )
    activate = next(
        row for row in tasks if row["name"] == "activate | Enable and verify Photos offload with fail-closed rescue"
    )
    assert [row["ansible.builtin.command"]["argv"][1] for row in activate["rescue"][:2]] == ["disable", "bootout"]
    runner = Runner()
    controls(runner).quiesce()
    assert [argv[1] for argv in runner.calls if argv[1] in {"disable", "bootout"}] == ["disable", "bootout"]
    assert all(argv[-1] == "gui/501/example.owned.photos" for argv in runner.calls if argv[1] in {"disable", "bootout"})


def test_disabled_absent_repeat_and_unknown_errors_are_distinct() -> None:
    runner = Runner(loaded=False, disabled=True)
    assert controls(runner).quiesce() == {"changed": False}
    assert not any(argv[1] == "disable" for argv in runner.calls)
    assert any(argv[1] == "bootout" for argv in runner.calls)
    unknown = Runner(faults=("print",))
    assert controls(unknown).snapshot()["loaded"] is None
    with pytest.raises(M["PhotosControlError"], match="not_disabled_unloaded"):
        controls(unknown).require_quiescent()


@pytest.mark.parametrize("fault", ["disable", "bootout", "print-disabled"])
def test_genuine_cleanup_failures_never_report_quiescence(fault: str) -> None:
    runner = Runner(faults=(fault,))
    with pytest.raises(M["PhotosControlError"]):
        controls(runner).quiesce()
    assert any(argv[1] == "bootout" for argv in runner.calls)


def test_optional_activation_success_and_rescue_without_any_app_call() -> None:
    runner = Runner(loaded=False, disabled=True)
    assert controls(runner).activate() == {"activated": True}
    assert runner.loaded
    assert not runner.disabled
    failed = Runner(loaded=False, disabled=True, faults=("bootstrap",))
    with pytest.raises(M["PhotosControlError"], match="activation_failed_quiesced"):
        controls(failed).activate()
    assert failed.disabled
    assert not failed.loaded
    assert [argv[1] for argv in failed.calls if argv[1] in {"disable", "bootout"}] == ["disable", "bootout"]


def test_failed_rescue_keeps_failure_truth() -> None:
    runner = Runner(loaded=True, disabled=False, faults=("bootstrap", "disable"))
    with pytest.raises(M["PhotosControlError"], match="activation_failed_NOT_quiesced"):
        controls(runner).activate()
    assert any(argv[1] == "bootout" for argv in runner.calls)


@pytest.mark.parametrize("uid", [0, -1, True])
def test_non_gui_identity_refuses_before_commands(uid: Any) -> None:
    runner = Runner()
    with pytest.raises(M["PhotosControlError"]):
        M["PhotosControls"]({"uid": uid, "label": "example.owned.photos"}, runner)
    assert runner.calls == []


def test_original_post_state_order_and_probe_failure_do_not_skip_rescue() -> None:
    runner = Runner()
    controls(runner).quiesce()
    assert [argv[1:] for argv in runner.calls[-3:]] == [
        ["print-disabled", "gui/501"],
        ["print", "gui/501"],
        ["print", "gui/501/example.owned.photos"],
    ]

    class BrokenProbe(Runner):
        def __call__(self, argv: list[str]) -> SimpleNamespace:
            if argv[1] in {"print", "print-disabled"}:
                raise M["PhotosControlError"]("owned probe unavailable")
            return super().__call__(argv)

    broken = BrokenProbe()
    with pytest.raises(M["PhotosControlError"]):
        controls(broken).quiesce(force=True)
    assert [argv[1] for argv in broken.calls] == ["disable", "bootout"]
