"""Original Inbox runtime guard before any source/managed quiescence action."""

from __future__ import annotations

import importlib.util
import os
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE
from ops_deploy.services.daybook_voice_memo_inbox.layout import directories, logs
from tests.test_daybook_inbox_declaration import config


@pytest.fixture
def controls() -> Any:
    spec = importlib.util.spec_from_file_location(
        "owned_inbox_controls", str(files(PACKAGE).joinpath("files/inbox_controls.py"))
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Probes:
    def __init__(self, **overrides: Any) -> None:
        self.overrides = overrides
        self.calls: list[list[str]] = []

    def run(self, argv: list[str]) -> SimpleNamespace:
        self.calls.append(argv)
        kind = (
            "serve"
            if argv[0].endswith("pgrep")
            else (
                "disabled"
                if argv[1] == "print-disabled"
                else "aqua"
                if argv[-1] == "gui/501"
                else "long"
                if argv[-1].endswith("-long")
                else "keeper"
            )
        )
        defaults = {
            "aqua": (0, b""),
            "keeper": (113, b'Could not find service "owned" in domain for user gui:501'),
            "long": (113, b'Could not find service "owned-long" in domain for user gui:501'),
            "serve": (1, b""),
            "disabled": (0, b'"owned" => disabled\n"owned-long" => true\n'),
        }
        rc, body = self.overrides.get(kind, defaults[kind])
        return SimpleNamespace(returncode=rc, stdout=body)


DATA = {"uid": 501, "user": "fixture", "label": "owned", "long_label": "owned-long"}


@pytest.mark.parametrize("argument", [b"serve", b"host-keep"])
def test_loaded_operations_keeper_refuses_without_forwarding_private_environment(
    controls: Any, argument: bytes
) -> None:
    probes = Probes(keeper=(0, b"PRIVATE-OWNED-ENV\n\t" + argument + b"\n"))
    with pytest.raises(controls.InboxError, match="inbox_operations_runtime_still_running") as result:
        controls.require_runtime_stopped(DATA, probes)
    assert "PRIVATE" not in str(result.value)
    assert all(argv[0] in {"/bin/launchctl", "/usr/bin/pgrep"} for argv in probes.calls)


def test_loaded_legacy_ingest_is_allowed_only_before_explicit_quiescence(controls: Any) -> None:
    probes = Probes(keeper=(0, b"\tingest\n"))
    controls.require_runtime_stopped(DATA, probes)
    with pytest.raises(controls.InboxError, match="inbox_label_not_quiescent"):
        controls.require_inbox_quiescent(DATA, probes)


def test_detached_operations_serve_also_refuses_after_keeper_is_unloaded(controls: Any) -> None:
    with pytest.raises(controls.InboxError, match="inbox_operations_runtime_still_running"):
        controls.require_runtime_stopped(DATA, Probes(serve=(0, b"12345\n")))


@pytest.mark.parametrize(
    ("overrides", "category"),
    [
        ({"aqua": (113, b"private")}, "inbox_aqua_unavailable"),
        ({"keeper": (1, b"private")}, "inbox_control_probe_failed"),
        ({"serve": (2, b"private")}, "inbox_control_probe_failed"),
        ({"disabled": (1, b"private")}, "inbox_disabled_labels_unavailable"),
        ({"disabled": (0, b'"owned" => false\n"owned-long" => true')}, "inbox_label_not_disabled"),
        ({"disabled": (0, b'"owned" => true\n"owned" => true\n"owned-long" => true')}, "inbox_label_not_disabled"),
        ({"long": (0, b"private")}, "inbox_label_not_quiescent"),
        ({"long": (1, b"private")}, "inbox_control_probe_failed"),
        ({"long": (113, b"permission denied")}, "inbox_control_probe_failed"),
        ({"keeper": (113, b"permission denied")}, "inbox_control_probe_failed"),
    ],
)
def test_quiescence_requires_genuine_original_observations(
    controls: Any, overrides: dict[str, Any], category: str
) -> None:
    with pytest.raises(controls.InboxError, match=category):
        controls.require_inbox_quiescent(DATA, Probes(**overrides))


def test_original_stopped_disabled_pair_passes_without_application_or_mutation_calls(controls: Any) -> None:
    probes = Probes()
    controls.require_inbox_quiescent(DATA, probes)
    assert all(argv[0] in {"/bin/launchctl", "/usr/bin/pgrep"} for argv in probes.calls)
    assert all(argv[1] in {"print", "print-disabled", "-u"} for argv in probes.calls)
    assert probes.calls[-1] == ["/bin/launchctl", "print", "gui/501/owned-long"]


def test_managed_layout_matches_original_role_exact_paths_owners_modes() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Paired original role oracle is run explicitly for qualification")
    import yaml
    from jinja2 import StrictUndefined
    from jinja2.nativetypes import NativeEnvironment

    cfg = config()
    tasks = yaml.safe_load((Path(source) / "roles/daybook_voice_memo_inbox_deploy/tasks/main.yml").read_text())
    env = NativeEnvironment(undefined=StrictUndefined)
    values = cfg.model_dump(mode="json")
    original_dirs = next(t["loop"] for t in tasks if t["name"] == "Create protected Voice Memo inbox directories")
    expected = [
        {key: (int(value, 8) if key == "mode" else env.from_string(value).render(values)) for key, value in row.items()}
        for row in original_dirs
    ]
    assert [vars(row) for row in directories(cfg)] == expected
    original_logs = next(t["loop"] for t in tasks if t["name"] == "Create owner-only Voice Memo inbox logs")
    assert [row.path for row in logs(cfg)] == [env.from_string(path).render(values) for path in original_logs]
    assert all((row.owner, row.group, row.mode) == ("fixture", "staff", 0o600) for row in logs(cfg))


class ManagedProbes(Probes):
    def __init__(self, *, running: bool = False, fail_bootout: bool = False) -> None:
        super().__init__()
        self.loaded = {"owned", "owned-long"}
        self.disabled: set[str] = set()
        self.running = running
        self.fail_bootout = fail_bootout

    def run(self, argv: list[str]) -> SimpleNamespace:
        self.calls.append(argv)
        action = argv[1]
        if argv[0].endswith("pgrep"):
            return SimpleNamespace(returncode=1, stdout=b"")
        if action == "print" and argv[-1] == "gui/501":
            return SimpleNamespace(returncode=0, stdout=b"")
        if action == "print-disabled":
            return SimpleNamespace(
                returncode=0,
                stdout=b"\n".join(('"' + label + '" => disabled').encode() for label in sorted(self.disabled)),
            )
        label = argv[-1].rsplit("/", 1)[-1]
        if action == "disable":
            self.disabled.add(label)
            return SimpleNamespace(returncode=0, stdout=b"")
        if action == "bootout":
            if self.fail_bootout:
                return SimpleNamespace(returncode=1, stdout=b"private failure")
            self.loaded.discard(label)
            return SimpleNamespace(returncode=0, stdout=b"")
        if label in self.loaded:
            return SimpleNamespace(returncode=0, stdout=b"\thost-keep\n" if self.running else b"\tingest\n")
        return SimpleNamespace(returncode=113, stdout=('Could not find service "' + label + '"').encode())


def test_explicit_quiesce_disables_both_original_lanes_before_bootout_and_repeat_is_zero(controls: Any) -> None:
    probes = ManagedProbes()
    assert controls.quiesce_inbox(DATA, probes) is True
    mutators = [argv for argv in probes.calls if argv[1] in {"disable", "bootout"}]
    assert mutators == [
        ["/bin/launchctl", "disable", "gui/501/owned"],
        ["/bin/launchctl", "disable", "gui/501/owned-long"],
        ["/bin/launchctl", "bootout", "gui/501/owned"],
        ["/bin/launchctl", "bootout", "gui/501/owned-long"],
    ]
    probes.calls.clear()
    assert controls.quiesce_inbox(DATA, probes) is False
    assert all(argv[1] not in {"disable", "bootout"} for argv in probes.calls)


def test_explicit_quiesce_never_touches_the_running_operations_keeper(controls: Any) -> None:
    probes = ManagedProbes(running=True)
    with pytest.raises(controls.InboxError, match="operations_runtime_still_running"):
        controls.quiesce_inbox(DATA, probes)
    assert all(argv[1] not in {"disable", "bootout"} for argv in probes.calls)


def test_failed_bootout_is_genuine_and_does_not_claim_rollback_or_quiescence(controls: Any) -> None:
    probes = ManagedProbes(fail_bootout=True)
    with pytest.raises(controls.InboxError, match="inbox_bootout_failed"):
        controls.quiesce_inbox(DATA, probes)
    assert probes.disabled == {"owned", "owned-long"}
    assert probes.loaded == {"owned", "owned-long"}
    assert sum(argv[1] == "bootout" for argv in probes.calls) == 1


def test_original_launchd_termination_window_is_bounded_and_never_retries_mutations(controls: Any) -> None:
    class Delayed(ManagedProbes):
        def __init__(self) -> None:
            super().__init__()
            self.terminating: dict[str, int] = {}
            self.sleeps: list[int] = []

        def sleep(self, seconds: int) -> None:
            self.sleeps.append(seconds)

        def run(self, argv: list[str]) -> SimpleNamespace:
            label = argv[-1].rsplit("/", 1)[-1]
            if argv[1] == "bootout":
                self.calls.append(argv)
                self.terminating[label] = 2
                return SimpleNamespace(returncode=0, stdout=b"")
            if argv[1] == "print" and label in self.terminating:
                self.terminating[label] -= 1
                if self.terminating[label] == 0:
                    self.loaded.discard(label)
            return super().run(argv)

    probes = Delayed()
    assert controls.quiesce_inbox(DATA, probes) is True
    assert probes.sleeps == [5, 5]
    assert sum(argv[1] == "bootout" for argv in probes.calls) == 2


def test_launchd_termination_exhaustion_stays_a_real_failure(controls: Any) -> None:
    class Stuck(ManagedProbes):
        def __init__(self) -> None:
            super().__init__()
            self.sleeps: list[int] = []

        def sleep(self, seconds: int) -> None:
            self.sleeps.append(seconds)

        def run(self, argv: list[str]) -> SimpleNamespace:
            if argv[1] == "bootout":
                self.calls.append(argv)
                return SimpleNamespace(returncode=0, stdout=b"")
            return super().run(argv)

    probes = Stuck()
    with pytest.raises(controls.InboxError, match="label_not_quiescent"):
        controls.quiesce_inbox(DATA, probes)
    assert probes.sleeps == [5] * 11
    assert sum(argv[1] == "bootout" for argv in probes.calls) == 2
