"""The ported Traefik transaction engine against ops-library's engine (3110a0f1).

Both engines run the same requests on the same fake host (``traefik_tx_fixtures``)
and must return the same results and refusals and leave the same files behind, byte
for byte: the host record, the transaction directory, the binary. Each scenario also
checks what the port did, so agreeing on a wrong outcome would still fail. The parts
outside ``execute`` (policy, evidence, startup arguments, records, the route tree
digest, release archives, the backup set, probes, identity and the command line) are
compared function by function.

Only ``inspect``, ``binary`` and ``resume`` are compared; ``test_traefik_tx_engine``
covers the actions the port refuses.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import types
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, redirect_stdout
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests.traefik_tx_fixtures import (
    ENGINES,
    MACHINE_ID,
    NEW,
    NOW,
    OLD,
    UNIT,
    FakeClock,
    FakeHost,
    FakeUuid,
    Outcome,
    Setup,
    base_setup,
    enrolled_state,
    fake_traefik,
    relaxed_trusted_file,
    release_archive,
    run_scenario,
    sha256,
)

PORT, REFERENCE = ENGINES["ops-deploy"], ENGINES["ops-library"]
ENROLLED = "11111111"  # the revision prefix of the enrolled record (``enrolled_state``)
Scenario = Callable[[Setup], None]
Check = Callable[[Outcome], None]


def outcome_of(call: Callable[[], Any]) -> tuple[str, Any]:
    try:
        return ("ok", call())
    except Exception as exc:
        return (type(exc).__name__, str(exc))


def both(call: Callable[[types.ModuleType], Any]) -> tuple[str, Any]:
    """``call`` with each engine; the outcomes must agree."""

    port = outcome_of(lambda: call(PORT))
    assert port == outcome_of(lambda: call(REFERENCE))
    return port


@pytest.fixture
def relaxed() -> Iterator[None]:
    """``trusted_file`` without root ownership, in both engines."""

    with ExitStack() as stack:
        for engine in ENGINES.values():
            stack.enter_context(patch.object(engine, "trusted_file", relaxed_trusted_file))
        yield


# -- execute(): one request, both engines, same host ----------------------------------------


def unchanged(setup: Setup) -> None:
    pass


def failing(probe: str, times: int = 1) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.host.failing[probe] = times

    return scenario


def host_knob(**knobs: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        for name, value in knobs.items():
            setattr(setup.host, name, value)

    return scenario


def without(*keys: str) -> Scenario:
    def scenario(setup: Setup) -> None:
        for key in keys:
            del setup.request[key]

    return scenario


def with_phase(phase: str) -> Scenario:
    def scenario(setup: Setup) -> None:
        assert setup.state is not None
        setup.state = dict(setup.state, phase=phase)
        setup.request["controller_state"] = setup.state

    return scenario


def release_of(version: str, members: list[tuple[str, bytes | None]] | None = None) -> Scenario:
    """The request names ``version``, in an archive of ``members`` (default: that version's binary)."""

    def scenario(setup: Setup) -> None:
        archive = release_archive(setup.host.root / "other.tar.gz", members or [("traefik", fake_traefik(version))])
        setup.request["release"] = {"version": version, "arch": "amd64", "sha256": sha256(archive.read_bytes())}
        setup.request["archive_path"] = str(archive)
        setup.request["compatibility"]["candidate_binary_sha256"] = sha256(fake_traefik(version))

    return scenario


def release_change(**fields: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.request["release"].update(fields)

    return scenario


def evidence_change(**fields: Any) -> Scenario:
    """Change evidence fields; ``None`` removes one."""

    def scenario(setup: Setup) -> None:
        for key, value in fields.items():
            if value is None:
                del setup.request["evidence"][key]
            else:
                setup.request["evidence"][key] = value

    return scenario


def compatibility_change(**fields: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.request["compatibility"].update(fields)

    return scenario


def record_change(**fields: Any) -> Scenario:
    """The host record and the controller's copy, both changed alike."""

    def scenario(setup: Setup) -> None:
        assert setup.state is not None
        setup.state = dict(setup.state, **fields)
        setup.request["controller_state"] = setup.state

    return scenario


def drifted(setup: Setup) -> None:
    assert setup.state is not None
    record_change(identity=dict(setup.state["identity"], dynamic_sha256="0" * 64))(setup)


def controller_disagrees(setup: Setup) -> None:
    assert setup.state is not None
    setup.request["controller_state"] = dict(setup.state, revision="another-revision")


def not_enrolled(setup: Setup) -> None:
    setup.state = None
    setup.request["controller_state"] = None


def routes_change_after_backup(setup: Setup) -> None:
    def change() -> None:
        (setup.host.dynamic / "app.yml").write_text("http:\n  routers: {changed: {}}\n")

    setup.host.after_backup = change


def shared_state_dir(setup: Setup) -> None:
    setup.state_dir_mode = 0o755


def several(*scenarios: Scenario) -> Scenario:
    def scenario(setup: Setup) -> None:
        for each in scenarios:
            each(setup)

    return scenario


def refused(message: str, kind: str = "Refused") -> Check:
    """The request was refused, nothing restarted and the binary is untouched."""

    def check(outcome: Outcome) -> None:
        assert outcome.result is None
        assert outcome.error == (kind, message)
        assert "restart" not in outcome.calls
        assert outcome.files["bin/traefik"] == (0o755, fake_traefik(OLD))
        record = outcome.record
        assert record is None or record["revision"].startswith(ENROLLED) or record["schema"] == 2

    return check


def transaction_files(outcome: Outcome) -> dict[str, bytes | None]:
    return {
        path.split("/", 2)[2]: content
        for path, (_, content) in outcome.files.items()
        if path.startswith("state/") and path.count("/") == 2
    }


def updated(outcome: Outcome) -> None:
    assert outcome.error is None
    assert outcome.result is not None
    record = outcome.saved
    assert outcome.result == {"changed": True, "state": record}
    assert record["phase"] == "clear"
    assert record["identity"]["version"] == NEW
    assert record["identity"]["binary_sha256"] == sha256(fake_traefik(NEW))
    assert outcome.files["bin/traefik"] == (0o755, fake_traefik(NEW))
    files = transaction_files(outcome)
    assert sorted(files) == ["backup.json", "candidate", "original", "prechange.tar.gz", "request.json"]
    assert files["original"] == fake_traefik(OLD)
    assert files["candidate"] == fake_traefik(NEW)
    [pending] = [json.loads(data) for data in outcome.records_at_restart]
    assert pending["phase"] == "pending"
    assert pending["operation"] == "binary"
    assert pending["previous_revision"].startswith(ENROLLED)
    assert pending["transaction"] == record["transaction"]
    assert pending["intended_identity"] == record["identity"]
    assert pending["identity"]["version"] == OLD
    assert outcome.calls == [
        "probe baseline",
        "version candidate",
        "backup",
        "restart",
        "probe acceptance",
        "probe cleanup",
    ]


def rolled_back(reason: str, *, restarts: int = 2) -> Check:
    def check(outcome: Outcome) -> None:
        assert outcome.error is None
        assert outcome.result is not None
        record = outcome.saved
        assert outcome.result == {"changed": True, "failed": True, "state": record}
        assert record["phase"] == "recovery"
        assert record["reason"] == reason
        assert record["identity"]["version"] == OLD
        assert record["review_due"] == NOW + 3600
        assert "recovery_error" not in record
        assert outcome.files["bin/traefik"] == (0o755, fake_traefik(OLD))
        assert outcome.calls.count("restart") == restarts

    return check


def degraded(reason: str, error: str) -> Check:
    def check(outcome: Outcome) -> None:
        assert outcome.error is None
        assert outcome.result is not None
        record = outcome.saved
        assert outcome.result == {"changed": True, "failed": True, "state": record}
        assert record["phase"] == "degraded"
        assert record["reason"] == reason
        assert record["recovery_error"] == error
        assert outcome.calls.count("restart") == 2

    return check


def no_op(outcome: Outcome) -> None:
    assert outcome.error is None
    assert outcome.result is not None
    assert outcome.result == {"changed": False, "state": outcome.saved}
    assert outcome.saved["revision"].startswith(ENROLLED)
    assert outcome.calls == ["probe baseline", "version candidate", "probe acceptance", "probe cleanup"]


def resumed(outcome: Outcome) -> None:
    assert outcome.error is None
    assert outcome.result is not None
    record = outcome.saved
    assert outcome.result == {"changed": True, "state": record}
    assert record["phase"] == "clear"
    assert record["resumed_from"].startswith(ENROLLED)
    assert record["recovery_review_reference"] == "fixture reviewed recovery"
    assert record["identity"]["version"] == OLD
    assert outcome.calls == ["probe baseline"]


def inspected(*, enrolled: bool) -> Check:
    def check(outcome: Outcome) -> None:
        assert outcome.error is None
        assert outcome.result is not None
        assert outcome.result["identity"]["version"] == OLD
        assert outcome.result["state"] == (outcome.record if enrolled else None)
        assert outcome.calls == []
        assert "lock" not in outcome.files

    return check


@dataclass(frozen=True)
class Case:
    name: str
    action: str
    setup: Scenario
    check: Check


CASES = [
    Case("binary update", "binary", unchanged, updated),
    Case(
        "legacy console_recovery evidence",
        "binary",
        evidence_change(recovery_access=None, console_recovery="console"),
        updated,
    ),
    Case("acceptance fails", "binary", failing("acceptance"), rolled_back("Refused")),
    Case("restart fails", "binary", host_knob(restart_failures=1), rolled_back("Refused")),
    Case("candidate never settles", "binary", host_knob(unsettled_restarts=1), rolled_back("Refused")),
    Case("interrupted", "binary", host_knob(interrupt="acceptance"), rolled_back("KeyboardInterrupt")),
    Case("cleanup fails once", "binary", failing("cleanup"), rolled_back("Refused")),
    Case("cleanup keeps failing", "binary", failing("cleanup", -1), degraded("Refused", "Refused")),
    Case("rollback restart fails", "binary", host_knob(restart_failures=2), degraded("Refused", "Refused")),
    Case("rollback never settles", "binary", host_knob(unsettled_restarts=2), degraded("Refused", "Refused")),
    Case("same release", "binary", release_of(OLD), no_op),
    Case(
        "same release, acceptance fails",
        "binary",
        several(release_of(OLD), failing("acceptance")),
        refused("command failed: acceptance (exit 1)"),
    ),
    Case("baseline probe fails", "binary", failing("baseline"), refused("command failed: baseline (exit 1)")),
    Case("downgrade", "binary", release_of("3.7.12"), refused("ordinary downgrade refused")),
    Case("checksum mismatch", "binary", release_change(sha256="0" * 64), refused("release archive checksum mismatch")),
    Case("checksum not exact", "binary", release_change(sha256="0" * 63), refused("exact SHA256 is required")),
    Case("next major", "binary", release_of("4.0.0"), refused("unsupported release")),
    Case(
        "archive without traefik",
        "binary",
        release_of(NEW, [("LICENSE.md", b"license\n")]),
        refused("archive must contain one bounded regular traefik executable"),
    ),
    Case(
        "two traefik members",
        "binary",
        release_of(NEW, [("traefik", fake_traefik(NEW)), ("traefik", fake_traefik(NEW))]),
        refused("archive must contain one bounded regular traefik executable"),
    ),
    Case(
        "traefik is a directory",
        "binary",
        release_of(NEW, [("traefik", None)]),
        refused("archive must contain one bounded regular traefik executable"),
    ),
    Case(
        "empty traefik",
        "binary",
        release_of(NEW, [("traefik", b"")]),
        refused("archive must contain one bounded regular traefik executable"),
    ),
    Case(
        "candidate reports another version",
        "binary",
        release_of(NEW, [("traefik", fake_traefik("3.7.15"))]),
        refused("candidate version mismatch"),
    ),
    Case(
        "candidate without version",
        "binary",
        release_of(NEW, [("traefik", b"#!/bin/sh\necho no\n")]),
        refused("unparseable Traefik version"),
    ),
    Case(
        "candidate is not what was tested",
        "binary",
        compatibility_change(candidate_binary_sha256="f" * 64),
        refused("candidate differs from isolated test"),
    ),
    Case(
        "static config would change",
        "binary",
        compatibility_change(candidate_config_sha256="f" * 64),
        refused("binary-only operation must preserve static config"),
    ),
    Case(
        "foreign architecture",
        "binary",
        compatibility_change(architecture="riscv64"),
        refused("isolated preflight must match baseline and native architecture"),
    ),
    Case(
        "isolated test of another baseline",
        "binary",
        compatibility_change(baseline={}),
        refused("isolated preflight must match baseline and native architecture"),
    ),
    Case(
        "isolated test failed",
        "binary",
        compatibility_change(passed=False),
        refused("isolated preflight proof required"),
    ),
    Case(
        "baseline pair untested",
        "binary",
        compatibility_change(baseline_pair_passed="yes"),
        refused("isolated preflight proof required"),
    ),
    Case(
        "no proof report",
        "binary",
        compatibility_change(report_reference=""),
        refused("isolated preflight proof required"),
    ),
    Case("host in recovery", "binary", with_phase("recovery"), refused("active recovery or unreviewed baseline drift")),
    Case("host pending", "binary", with_phase("pending"), refused("active recovery or unreviewed baseline drift")),
    Case("host degraded", "binary", with_phase("degraded"), refused("active recovery or unreviewed baseline drift")),
    Case("unreviewed drift", "binary", drifted, refused("active recovery or unreviewed baseline drift")),
    Case(
        "records disagree",
        "binary",
        controller_disagrees,
        refused("controller and host recovery records disagree"),
    ),
    Case("not enrolled", "binary", not_enrolled, refused("missing or wrong host enrollment")),
    Case("record of another host", "binary", record_change(host="other"), refused("missing or wrong host enrollment")),
    Case("record of another schema", "binary", record_change(schema=2), refused("invalid recovery state")),
    Case(
        "routes change during preparation",
        "binary",
        routes_change_after_backup,
        refused("baseline changed during preparation"),
    ),
    Case(
        "stale evidence",
        "binary",
        evidence_change(verified_at=NOW - 3601),
        refused("preflight evidence must be at most one hour old"),
    ),
    Case(
        "evidence from the future",
        "binary",
        evidence_change(verified_at=NOW + 1),
        refused("preflight evidence must be at most one hour old"),
    ),
    Case(
        "placeholder recovery access",
        "binary",
        evidence_change(recovery_access="CHANGEME"),
        refused("missing evidence: recovery_access"),
    ),
    Case(
        "empty recovery access hides no legacy value",
        "binary",
        evidence_change(recovery_access="", console_recovery="console"),
        refused("missing evidence: recovery_access"),
    ),
    Case("blank owner", "binary", evidence_change(owner=" "), refused("missing evidence: owner")),
    Case(
        "observer not watching",
        "binary",
        evidence_change(observer_watch_active="yes"),
        refused("independent observer must be watching"),
    ),
    Case(
        "evidence of another baseline",
        "binary",
        evidence_change(baseline={}),
        refused("reviewed baseline does not match live state"),
    ),
    Case("Traefik stopped", "binary", host_knob(running=None), refused("Traefik is not running")),
    Case("not root", "binary", host_knob(euid=1000), refused("root is required")),
    Case("shared state directory", "binary", shared_state_dir, refused("unsafe state directory")),
    Case("no release", "binary", without("release"), refused("'release'", "KeyError")),
    Case("no evidence", "binary", without("evidence"), refused("'evidence'", "KeyError")),
    Case("resume recovery", "resume", with_phase("recovery"), resumed),
    Case("resume pending", "resume", with_phase("pending"), resumed),
    Case("resume degraded", "resume", with_phase("degraded"), resumed),
    Case("resume clear", "resume", unchanged, resumed),
    Case(
        "resume without review",
        "resume",
        several(with_phase("recovery"), without("recovery_review_reference")),
        refused("reviewed recovery reference required"),
    ),
    Case(
        "resume while the baseline probe fails",
        "resume",
        several(with_phase("recovery"), failing("baseline")),
        refused("command failed: baseline (exit 1)"),
    ),
    Case(
        "resume with disagreeing records",
        "resume",
        several(with_phase("recovery"), controller_disagrees),
        refused("controller and host recovery records disagree"),
    ),
    Case(
        "resume with stale evidence",
        "resume",
        several(with_phase("recovery"), evidence_change(verified_at=NOW - 7200)),
        refused("preflight evidence must be at most one hour old"),
    ),
    Case("resume before enrollment", "resume", not_enrolled, refused("missing or wrong host enrollment")),
    Case("inspect", "inspect", unchanged, inspected(enrolled=True)),
    Case("inspect before enrollment", "inspect", not_enrolled, inspected(enrolled=False)),
    Case("inspect a stopped Traefik", "inspect", host_knob(running=None), refused("Traefik is not running")),
    Case("unknown action", "rollback", unchanged, refused("unknown action")),
]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_engines_agree(case: Case, tmp_path: Path) -> None:
    port = run_scenario(PORT, tmp_path / "host", case.setup, case.action)
    reference = run_scenario(REFERENCE, tmp_path / "host", case.setup, case.action)

    assert port == reference
    case.check(port)


CLI_CASES = {
    "update": ("binary", unchanged, 0, "clear"),
    "rollback": ("binary", failing("acceptance"), 1, "recovery"),
    "degraded": ("binary", failing("cleanup", -1), 1, "degraded"),
    "no-op": ("binary", release_of(OLD), 0, "clear"),
    "refusal": ("binary", with_phase("recovery"), 2, ""),
    "resume": ("resume", with_phase("recovery"), 0, "clear"),
    "inspect": ("inspect", unchanged, 0, "clear"),
}


@pytest.mark.parametrize("case", CLI_CASES.values(), ids=CLI_CASES.keys())
def test_exit_codes_and_output_agree(case: tuple[str, Scenario, int, str], tmp_path: Path) -> None:
    action, scenario, code, phase = case
    port = run_scenario(PORT, tmp_path / "host", scenario, action, cli=True)
    reference = run_scenario(REFERENCE, tmp_path / "host", scenario, action, cli=True)

    assert port == reference
    assert port.error is None
    assert port.result is not None
    assert port.result["exit"] == code
    output = port.result["output"]
    if code == 2:
        assert output == {"failed": True, "error": "active recovery or unreviewed baseline drift"}
    else:
        assert output["state"]["phase"] == phase
        assert output["state"] == port.record


def test_lock_held_by_another_transaction(tmp_path: Path) -> None:
    def held(setup: Setup) -> None:
        setup.hold_lock = True

    port = run_scenario(PORT, tmp_path / "host", held, "binary")
    reference = run_scenario(REFERENCE, tmp_path / "host", held, "binary")

    assert port == reference
    assert port.error is not None
    assert port.error[0] == "BlockingIOError"
    assert port.calls == []
    assert port.record is not None
    assert port.record["revision"].startswith(ENROLLED)


def test_records_cross_between_engines(tmp_path: Path) -> None:
    """A history written alternately by both engines: each loads and continues the other's records."""

    host = FakeHost(REFERENCE, tmp_path)
    host.install()

    def record() -> dict[str, Any] | None:
        path = host.state_root / "state.json"
        return dict(json.loads(path.read_text())) if path.exists() else None

    def step(engine: types.ModuleType, action: str) -> dict[str, Any]:
        host.engine = engine
        with host.patched():
            request = base_setup(host, action).request
            request["controller_state"] = record()
            result: dict[str, Any] = engine.execute(request)
        return result

    enrolled = step(REFERENCE, "enroll")["state"]  # enrollment stays with the reference engine
    host.failing["acceptance"] = 1
    failed = step(PORT, "binary")
    assert failed["failed"] is True
    assert failed["state"]["phase"] == "recovery"
    assert failed["state"]["identity"] == enrolled["identity"]
    assert step(REFERENCE, "inspect")["state"] == failed["state"] == record()
    assert outcome_of(lambda: step(REFERENCE, "binary")) == ("Refused", "active recovery or unreviewed baseline drift")
    resumed_record = step(PORT, "resume")["state"]
    assert resumed_record["resumed_from"] == failed["state"]["revision"]
    done = step(REFERENCE, "binary")
    assert done["changed"] is True
    assert done["state"]["identity"]["version"] == NEW
    assert step(PORT, "inspect")["state"] == done["state"] == record()
    assert step(PORT, "binary") == {"changed": False, "state": done["state"]}


# -- the parts, function by function ----------------------------------------------------------


@pytest.fixture
def clock() -> Iterator[None]:
    with ExitStack() as stack:
        for engine in ENGINES.values():
            stack.enter_context(patch.object(engine, "time", FakeClock()))
            stack.enter_context(patch.object(engine, "uuid", FakeUuid()))
        yield


POLICY = {
    "host": "canary-1",
    "binary_path": "/usr/local/bin/traefik",
    "config_path": "/etc/traefik/traefik.toml",
    "dynamic_path": "/etc/traefik/dynamic",
}


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"binary_path": "/usr/bin/traefik"},
        {"host": "Canary"},
        {"host": "-x"},
        {"host": "a" * 64},
        {"host": 7},
        {"host": None},
        {"binary_path": "/opt/traefik"},
        {"binary_path": "usr/local/bin/traefik"},
        {"binary_path": "/usr/local/bin/../bin/traefik"},
        {"binary_path": "/usr/local/bin//traefik"},
        {"config_path": "/etc/traefik/traefik.yml"},
        {"dynamic_path": "/etc/traefik/dynamic/"},
        {"dynamic_path": "/etc/traefik/routes"},
    ],
    ids=repr,
)
def test_policy(change: dict[str, Any]) -> None:
    policy = {key: value for key, value in {**POLICY, **change}.items() if value is not None}

    both(lambda engine: engine.validate_policy(policy))


@pytest.mark.parametrize(
    "args",
    [
        [b"/usr/local/bin/traefik", b"--configFile=/etc/traefik/traefik.toml"],
        [b"/usr/local/bin/traefik", b"--configfile=/etc/traefik/traefik.toml"],
        [b"/usr/local/bin/traefik", b"--CONFIGFILE=/etc/traefik/traefik.toml"],
        [b"/usr/local/bin/traefik", b"--configFile", b"/etc/traefik/traefik.toml"],
        [b"/usr/local/bin/traefik", b"--configFile=/etc/traefik/other.toml"],
        [b"/usr/local/bin/traefik", b"--configFile=/etc/traefik/traefik.toml", b"--api.insecure=true"],
        [b"/usr/bin/traefik", b"--configFile=/etc/traefik/traefik.toml"],
        [b"/usr/local/bin/traefik"],
    ],
    ids=repr,
)
def test_startup_arguments(args: list[bytes]) -> None:
    binary, config = Path("/usr/local/bin/traefik"), Path("/etc/traefik/traefik.toml")

    both(lambda engine: engine.validate_arguments(args, binary, config))


EVIDENCE = {
    "baseline": {"version": OLD},
    "verified_at": NOW - 10,
    "owner": "operator",
    "review_reference": "review",
    "recovery_access": "ssh",
    "independent_observer": "controller",
    "observer_delivery_test": "http",
    "observer_watch_active": True,
}


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"baseline": {"version": NEW}},
        {"baseline": None},
        {"verified_at": NOW - 3600},
        {"verified_at": NOW - 3601},
        {"verified_at": NOW + 1},
        {"verified_at": "now"},
        {"recovery_access": None, "console_recovery": "console"},
        {"recovery_access": None},
        {"recovery_access": None, "console_recovery": "CHANGEME later"},
        {"recovery_access": 1},
        {"owner": None},
        {"owner": "CHANGEME"},
        {"review_reference": ""},
        {"independent_observer": ["controller"]},
        {"observer_delivery_test": "   "},
        {"observer_watch_active": 1},
        {"observer_watch_active": None},
    ],
    ids=repr,
)
def test_evidence(change: dict[str, Any], clock: None) -> None:
    proof = {key: value for key, value in {**EVIDENCE, **change}.items() if value is not None}

    both(lambda engine: engine.evidence({"evidence": proof}, {"version": OLD}))


def test_records_are_built_alike(clock: None) -> None:
    live = {"version": OLD}

    result = both(lambda engine: engine.state_for({"host": "canary"}, "pending", live, owner="o", operation="binary"))

    assert result == (
        "ok",
        {
            "schema": 1,
            "host": "canary",
            "phase": "pending",
            "identity": live,
            "revision": "00000000-0000-0000-0000-000000000001",
            "updated_at": NOW,
            "owner": "o",
            "operation": "binary",
        },
    )


RECORDS: dict[str, bytes | None] = {
    "missing": None,
    "clear": json.dumps(enrolled_state({"version": OLD})).encode(),
    "degraded": json.dumps(enrolled_state({}, phase="degraded", recovery_error="Refused")).encode(),
    "schema 2": json.dumps(enrolled_state({}, schema=2)).encode(),
    "unknown phase": json.dumps(enrolled_state({}, phase="done")).encode(),
    "no phase": b'{"schema": 1}',
    "invalid JSON": b"{",
    "empty": b"",
}


@pytest.mark.parametrize("content", RECORDS.values(), ids=RECORDS.keys())
def test_host_records_load_alike(content: bytes | None, tmp_path: Path, relaxed: None) -> None:
    path = tmp_path / "state.json"
    if content is not None:
        path.write_bytes(content)
        path.chmod(0o600)

    result = both(lambda engine: engine.load_state(path))

    if content is not None and result[0] == "ok":
        assert result[1] == json.loads(content)


def test_dangling_record_symlink_is_refused_alike(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.symlink_to(tmp_path / "gone.json")

    assert both(lambda engine: engine.load_state(path)) == ("Refused", "dangling state symlink")


def test_a_record_that_is_not_an_object_is_refused(tmp_path: Path, relaxed: None) -> None:
    """The one intended difference in records: the reference engine dies with AttributeError."""

    path = tmp_path / "state.json"
    path.write_text("[]")
    path.chmod(0o600)

    assert outcome_of(lambda: PORT.load_state(path)) == ("Refused", "invalid recovery state")
    assert outcome_of(lambda: REFERENCE.load_state(path))[0] == "AttributeError"


def test_route_tree_digest(tmp_path: Path, relaxed: None) -> None:
    root = tmp_path / "dynamic"
    (root / "nested" / "deeper").mkdir(parents=True)
    (root / "empty").mkdir()
    files = {
        "b.yml": b"b\n",
        "a.yml": b"a\n",
        ".hidden.yml": b"hidden\n",
        "nested/z.toml": b"z\n",
        "nested/deeper/café.yml": b"cafe\n",
    }
    for name, data in files.items():
        (root / name).write_bytes(data)
        (root / name).chmod(0o644)
    ordered = sorted(files.items(), key=lambda item: Path(item[0]).parts)
    items = [[name, hashlib.sha256(data).hexdigest()] for name, data in ordered]
    expected = hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()

    assert both(lambda engine: engine.inventory_tree(root)) == ("ok", expected)
    assert both(lambda engine: engine.inventory_tree(root / "a.yml"))[0] == "Refused"
    (root / "nested" / "link.yml").symlink_to(root / "a.yml")
    assert both(lambda engine: engine.inventory_tree(root))[0] == "Refused"


def test_fixture_archives_do_not_depend_on_the_clock_or_their_name(tmp_path: Path) -> None:
    """The engines run one after the other; their release archives must still be byte-identical."""

    members: list[tuple[str, bytes | None]] = [("traefik", fake_traefik(NEW)), ("traefik-dir", None)]
    with patch("time.time", return_value=1.0):
        first = release_archive(tmp_path / "first.tar.gz", members).read_bytes()
    with patch("time.time", return_value=2_000_000_000.0):
        second = release_archive(tmp_path / "second.tar.gz", members).read_bytes()

    assert first == second


ARCHIVES: dict[str, tuple[list[tuple[str, bytes | None]], str]] = {
    "release": ([("LICENSE.md", b"l\n"), ("traefik", fake_traefik(NEW))], NEW),
    "next major": ([("traefik", fake_traefik("4.0.0"))], "4.0.0"),
    "no traefik": ([("traefik.exe", fake_traefik(NEW))], NEW),
    "traefik below a directory": ([("dist/traefik", fake_traefik(NEW))], NEW),
    "two traefik": ([("traefik", fake_traefik(NEW)), ("traefik", fake_traefik(NEW))], NEW),
    "directory": ([("traefik", None)], NEW),
    "empty": ([("traefik", b"")], NEW),
    "other version": ([("traefik", fake_traefik("3.7.15"))], NEW),
    "no version": ([("traefik", b"#!/bin/sh\necho nothing\n")], NEW),
    "failing binary": ([("traefik", b"#!/bin/sh\nexit 3\n")], NEW),
}


@pytest.mark.parametrize("checksum", ["exact", "upper", "other"])
@pytest.mark.parametrize("archive_case", ARCHIVES.values(), ids=ARCHIVES.keys())
def test_release_archives(
    archive_case: tuple[list[tuple[str, bytes | None]], str], checksum: str, tmp_path: Path
) -> None:
    """Archives are read for real; the candidate's ``version`` runs as a program."""

    members, target = archive_case
    archive = release_archive(tmp_path / "release.tar.gz", members)
    digest = {"exact": sha256(archive.read_bytes()), "upper": sha256(archive.read_bytes()).upper(), "other": "0" * 64}[
        checksum
    ]
    outcomes = {}
    for name, engine in ENGINES.items():
        destination = tmp_path / name
        destination.mkdir()
        outcome = outcome_of(partial(engine.candidate_binary, archive, digest, destination, target))
        candidate = destination / "candidate"
        written = (candidate.stat().st_mode & 0o777, candidate.read_bytes()) if candidate.exists() else None
        outcomes[name] = (outcome[0], outcome[1] if outcome[0] != "ok" else Path(outcome[1]).name, written)

    assert outcomes["ops-deploy"] == outcomes["ops-library"]
    succeeded = archive_case is ARCHIVES["release"] and checksum == "exact"
    assert (outcomes["ops-deploy"] == ("ok", "candidate", (0o755, fake_traefik(NEW)))) is succeeded


BACKUP_POLICY: dict[str, Any] = {
    "binary_path": "/usr/local/bin/traefik",
    "backup_paths": ["/usr/local/bin/traefik", "/etc/traefik", "/etc/systemd/system/traefik.service"],
    "acme_paths": [],
}
PRESENT = {"/usr/local/bin/traefik", "/etc/traefik", "/etc/systemd/system/traefik.service", "/acme.json"}
TARGET = "/etc/traefik/acme/acme.json"
REQUIRED_BACKUP = {"/etc/traefik", "/etc/systemd/system/traefik.service"}
OPTIONAL_BACKUP = {"/etc/letsencrypt", "/etc/systemd/system/traefik.service.d"}


@pytest.mark.parametrize(
    ("change", "present"),
    [
        ({}, set()),
        ({}, {"/etc/letsencrypt"}),
        ({}, {"/etc/systemd/system/traefik.service.d"}),
        ({"backup_paths": [*BACKUP_POLICY["backup_paths"], "/etc/letsencrypt"]}, {"/etc/letsencrypt"}),
        ({"acme_paths": ["/acme.json"]}, set()),
        ({"acme_paths": ["/acme.json"], "backup_paths": [*BACKUP_POLICY["backup_paths"], "/acme.json"]}, set()),
        ({"backup_paths": [*BACKUP_POLICY["backup_paths"], "relative/path"]}, set()),
        ({"backup_paths": [*BACKUP_POLICY["backup_paths"], "/etc/../root"]}, set()),
        ({"backup_paths": [*BACKUP_POLICY["backup_paths"], TARGET]}, set()),
        ({"backup_paths": [*BACKUP_POLICY["backup_paths"], TARGET], "acme_target": TARGET}, set()),
        ({"backup_paths": ["/etc/traefik", "/etc/systemd/system/traefik.service"]}, set()),
        ({"backup_paths": ["/usr/local/bin/traefik", "/etc/systemd/system/traefik.service"]}, set()),
        ({"backup_paths": ["/usr/local/bin/traefik", "/etc/traefik"]}, set()),
        ({"binary_path": "/usr/bin/traefik"}, {"/usr/bin/traefik"}),
    ],
    ids=repr,
)
def test_backup_set(change: dict[str, Any], present: set[str], tmp_path: Path) -> None:
    policy = {**BACKUP_POLICY, **change}
    real_exists = Path.exists
    tar_calls: list[list[str]] = []

    def exists(path: Path, **kwargs: Any) -> bool:
        if str(path).startswith(str(tmp_path)):
            return real_exists(path, **kwargs)
        return str(path) in PRESENT | present

    def tar(argv: list[str], timeout: int = 30, **kwargs: Any) -> str:
        tar_calls.append([*argv[:5], Path(argv[5]).name, *argv[6:], f"timeout={timeout}"])
        Path(argv[5]).write_bytes("\n".join(argv[7:]).encode())
        return ""

    outcomes = {}
    for name, engine in ENGINES.items():
        directory = tmp_path / name
        directory.mkdir()
        with patch.object(engine, "run", tar), patch.object(Path, "exists", exists):
            outcome = outcome_of(partial(engine.backup, policy, directory))
        outcomes[name] = (outcome, sorted((path.name, path.read_bytes()) for path in directory.iterdir()))

    assert outcomes["ops-deploy"] == outcomes["ops-library"]
    complete = REQUIRED_BACKUP | {policy["binary_path"]} | (present & OPTIONAL_BACKUP) | set(policy["acme_paths"])
    valid = all(path.startswith("/") and ".." not in path for path in policy["backup_paths"])
    present_or_target = all(p in PRESENT | present or p == policy.get("acme_target") for p in policy["backup_paths"])
    assert (outcomes["ops-deploy"][0][0] == "ok") is (
        complete <= set(policy["backup_paths"]) and valid and present_or_target
    )
    assert len(tar_calls) in (0, 2)
    assert tar_calls[:1] == tar_calls[1:]


@pytest.mark.parametrize(
    "probe",
    [
        {},
        {"script": "exit 3\n"},
        {"sha256": "0" * 64},
        {"relative": True},
        {"argv": []},
        {"argv": "/bin/true"},
        {"argv": ["/bin/true", 1]},
        {"no_sha": True},
    ],
    ids=repr,
)
def test_probe_programs(probe: dict[str, Any], tmp_path: Path, relaxed: None) -> None:
    program = tmp_path / "probe"
    program.write_text("#!/bin/sh\n" + probe.get("script", "exit 0\n"))
    program.chmod(0o755)
    spec: dict[str, Any] = {"argv": [str(program), "--check"], "sha256": sha256(program.read_bytes())}
    if "argv" in probe:
        spec["argv"] = probe["argv"]
    if "sha256" in probe:
        spec["sha256"] = probe["sha256"]
    if probe.get("relative"):
        spec["argv"] = [os.path.relpath(program), "--check"]
    if probe.get("no_sha"):
        del spec["sha256"]

    result = both(lambda engine: engine.check_probe(spec))

    assert (result == ("ok", None)) is (probe == {})


# -- identity: what systemd and /proc report ------------------------------------------------

PID = 4242


@dataclass
class Proc:
    """What ``identity`` reads from systemd, /proc and /etc/machine-id, for both engines."""

    host: FakeHost
    pids: tuple[int, int] = (PID, PID)
    exe: str = ""
    cmdline: bytes = b""
    environ: bytes = b"LANG=C.UTF-8\0PATH=/usr/bin\0"
    running: bytes = b""

    @contextmanager
    def patched(self) -> Iterator[None]:
        real_readlink, real_read_bytes, real_read_text = os.readlink, Path.read_bytes, Path.read_text
        binary = str(self.host.binary)
        exe = self.exe or binary
        cmdline = self.cmdline or f"{binary}\0--configFile={self.host.config}\0".encode()
        running = self.running or self.host.binary.read_bytes()
        proc = f"/proc/{self.pids[0]}"

        def readlink(path: Any, *args: Any, **kwargs: Any) -> str:
            return exe if os.fspath(path) == f"{proc}/exe" else real_readlink(path, *args, **kwargs)

        def read_bytes(path: Path) -> bytes:
            fake = {f"{proc}/cmdline": cmdline, f"{proc}/environ": self.environ}
            return fake[str(path)] if str(path) in fake else real_read_bytes(path)

        def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
            return MACHINE_ID + "\n" if str(path) == "/etc/machine-id" else real_read_text(path, *args, **kwargs)

        with ExitStack() as stack:
            stack.enter_context(patch("os.readlink", readlink))
            stack.enter_context(patch.object(Path, "read_bytes", read_bytes))
            stack.enter_context(patch.object(Path, "read_text", read_text))
            for engine in ENGINES.values():
                real_digest = engine.digest
                pids = iter(self.pids)

                def digest(path: Path, real_digest: Callable[[Path], str] = real_digest) -> str:
                    return sha256(running) if str(path) == f"{proc}/exe" else real_digest(path)

                def run(argv: list[str], timeout: int = 30, pids: Iterator[int] = pids, **kwargs: Any) -> str:
                    if argv[:2] == ["systemctl", "show"]:
                        return f"{next(pids)}\n"
                    if argv[:2] == ["systemctl", "cat"]:
                        return UNIT
                    assert argv == [binary, "version"], argv
                    return f"Version:      {OLD}\nCodename:     fixture\n"

                stack.enter_context(patch.object(engine, "digest", digest))
                stack.enter_context(patch.object(engine, "run", run))
                stack.enter_context(patch.object(engine, "trusted_file", relaxed_trusted_file))
            yield


PROC_CASES: dict[str, Callable[[FakeHost], Proc]] = {
    "running": lambda host: Proc(host),
    "lowercase flag": lambda host: Proc(host, cmdline=f"{host.binary}\0--configfile={host.config}\0".encode()),
    "replaced on disk": lambda host: Proc(host, exe=f"{host.binary} (deleted)"),
    "other executable": lambda host: Proc(host, exe="/opt/traefik"),
    "extra argument": lambda host: Proc(host, cmdline=f"{host.binary}\0--configFile={host.config}\0-x\0".encode()),
    "environment override": lambda host: Proc(host, environ=b"TRAEFIK_LOG_LEVEL=DEBUG\0"),
    "stopped": lambda host: Proc(host, pids=(0, 0)),
    "restarted while observed": lambda host: Proc(host, pids=(PID, PID + 1)),
    "running image differs": lambda host: Proc(host, running=b"older image"),
}


@pytest.mark.parametrize("case", PROC_CASES.values(), ids=PROC_CASES.keys())
def test_identity(case: Callable[[FakeHost], Proc], tmp_path: Path) -> None:
    host = FakeHost(PORT, tmp_path)
    host.install()
    policy = host.policy()

    with case(host).patched():
        result = both(lambda engine: engine.identity(policy))

    if case in (PROC_CASES["running"], PROC_CASES["lowercase flag"]):
        assert result[0] == "ok"
        assert result[1] == {
            "machine_id": MACHINE_ID,
            "binary_path": str(host.binary),
            "binary_sha256": sha256(host.binary.read_bytes()),
            "version": OLD,
            "config_path": str(host.config),
            "config_sha256": sha256(host.config.read_bytes()),
            "dynamic_sha256": result[1]["dynamic_sha256"],
            "unit_sha256": sha256(UNIT.encode()),
        }
    else:
        assert result[0] == "Refused"


@pytest.mark.parametrize(
    "config",
    [
        '[providers.file]\ndirectory = "{dynamic}"\n',
        '[providers.file]\ndirectory = "/elsewhere"\n',
        '[providers.file]\ndirectory = "{dynamic}"\nfilename = "/etc/traefik/routes.yml"\n',
        '[providers.file]\ndirectory = "{dynamic}"\n[providers.docker]\n',
        '[entryPoints.web]\naddress = ":80"\n',
        "not toml = = =\n",
    ],
    ids=repr,
)
def test_identity_static_config(config: str, tmp_path: Path) -> None:
    host = FakeHost(PORT, tmp_path)
    host.install()
    host.config.write_text(config.format(dynamic=host.dynamic))

    with Proc(host).patched():
        result = both(lambda engine: engine.identity(host.policy()))

    assert (result[0] == "ok") is (config == '[providers.file]\ndirectory = "{dynamic}"\n')


# -- the command line -----------------------------------------------------------------------


@pytest.fixture
def umask() -> Iterator[None]:
    """``main`` sets umask 077 for the process, as on the host; give the test run its own back."""

    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.mark.parametrize(
    "request_text",
    [
        None,
        "{",
        "[]",
        "{}",
        json.dumps({"action": "binary"}),
        json.dumps({"action": "inspect", "policy": {**POLICY, "host": "Bad"}}),
        json.dumps({"action": "rollback", "policy": POLICY}),
    ],
    ids=repr,
)
def test_command_line(request_text: str | None, tmp_path: Path, umask: None) -> None:
    path = tmp_path / "request.json"
    if request_text is not None:
        path.write_text(request_text)
    results = {}
    for name, engine in ENGINES.items():
        output = io.StringIO()
        with patch("sys.argv", ["engine.py", "--request", str(path)]), redirect_stdout(output):
            code = engine.main()
        results[name] = (code, output.getvalue())

    assert results["ops-deploy"] == results["ops-library"]
    assert results["ops-deploy"][0] == 2
    assert json.loads(results["ops-deploy"][1])["failed"] is True
