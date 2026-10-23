"""The engine's ``rebaseline`` action: route-only drift becomes a new ``clear`` record, nothing else does.

Only ops-deploy's engine has the action (ops-library's refuses it as unknown), so these
tests run the port alone on the fake host of ``traefik_tx_fixtures`` and then hand its
records to both engines. Every refusal must leave the host record, the route inventory and
Traefik as they were.
"""

from __future__ import annotations

import copy
import gzip
import json
import shutil
import tarfile
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
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
    FakeHost,
    Outcome,
    Setup,
    base_setup,
    fake_traefik,
    relaxed_trusted_file,
    run_scenario,
    sha256,
)

PORT, REFERENCE = ENGINES["ops-deploy"], ENGINES["ops-library"]
ENROLLED = "11111111"  # the revision prefix of the enrolled record (``enrolled_state``)
INVENTORY = "state/" + PORT.ROUTE_INVENTORY
Change = Callable[[FakeHost], None]


def add_route(name: str = "new.yml", text: str = "http:\n  routers: {new: {}}\n") -> Change:
    def change(host: FakeHost) -> None:
        path = host.dynamic / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o644)

    return change


def edit_route(name: str = "app.yml") -> Change:
    def change(host: FakeHost) -> None:
        path = host.dynamic / name
        path.write_text(path.read_text() + "# redeployed\n")

    return change


def remove_route(name: str = "app.yml") -> Change:
    def change(host: FakeHost) -> None:
        (host.dynamic / name).unlink()

    return change


def new_binary(host: FakeHost) -> None:
    """Another Traefik on disk and running: binary hash and version differ."""

    host.binary.write_bytes(fake_traefik(NEW))
    host.running = host.binary.read_bytes()


def edit_config(host: FakeHost) -> None:
    host.config.write_text(host.config.read_text() + "# edited\n")


def drifted(
    *changes: Change, record: dict[str, Any] | None = None, phase: str | None = None
) -> Callable[[Setup], None]:
    """Change the host after enrollment; the request's evidence then binds the new live identity.

    ``record`` overrides identity fields of the enrolled record (unit and machine drift,
    which the fake host cannot change itself); ``phase`` replaces the record's phase.
    """

    def scenario(setup: Setup) -> None:
        assert setup.state is not None
        host = setup.host
        for change in changes:
            change(host)
        state = copy.deepcopy(setup.state)
        state["identity"].update(record or {})
        if phase is not None:
            state["phase"] = phase
        setup.state = state
        setup.request["controller_state"] = state
        setup.request["evidence"]["baseline"] = host.identity(host.policy())

    return scenario


def run(tmp_path: Path, scenario: Callable[[Setup], None], *, cli: bool = False) -> Outcome:
    return run_scenario(PORT, tmp_path / "host", scenario, "rebaseline", cli=cli)


def run_from(tmp_path: Path, scenario: Callable[[Setup], None]) -> tuple[Outcome, dict[str, Any]]:
    """``run``, and the record the scenario put on the host before the engine ran."""

    before: dict[str, Any] = {}

    def capture(setup: Setup) -> None:
        scenario(setup)
        assert setup.state is not None
        before.update(copy.deepcopy(setup.state))

    return run(tmp_path, capture), before


def assert_untouched(outcome: Outcome, before: dict[str, Any]) -> None:
    assert outcome.record == before
    assert INVENTORY not in outcome.files
    assert "restart" not in outcome.calls
    assert [name for name in outcome.files if name.startswith("state/") and name != "state/state.json"] == []


# -- the reconciliation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [(add_route(),), (edit_route(),), (remove_route(), add_route("other.yml")), (add_route("nested/deep.yml"),)],
    ids=["added", "modified", "replaced", "nested"],
)
def test_route_only_drift_becomes_a_new_clear_record(changes: tuple[Change, ...], tmp_path: Path) -> None:
    outcome, before = run_from(tmp_path, drifted(*changes))

    assert outcome.error is None
    record = outcome.saved
    assert outcome.result == {"changed": True, "state": record}
    assert record["phase"] == "clear"
    assert record["schema"] == 1
    assert record["host"] == "fixture"
    assert record["rebaselined_from"] == before["revision"]
    assert record["revision"] != before["revision"]
    assert record["updated_at"] == NOW
    assert record["owner"] == "operator"
    live = record["identity"]
    assert live != before["identity"]
    assert {key for key in live if live[key] != before["identity"][key]} == {"dynamic_sha256"}
    assert record["rebaseline"] == {
        "previous_dynamic_sha256": before["identity"]["dynamic_sha256"],
        "dynamic_sha256": live["dynamic_sha256"],
        # The enrolled record names no transaction and there is no inventory yet.
        "changed_files": None,
        "changed_files_basis": "unavailable",
        "review_reference": "fixture review",
    }
    # Only the baseline probe ran; Traefik was not restarted and the binary is untouched.
    assert outcome.calls == ["probe baseline"]
    assert outcome.files["bin/traefik"][1] == fake_traefik(OLD)
    inventory = json.loads(outcome.files[INVENTORY][1] or b"")
    assert outcome.files[INVENTORY][0] == 0o600
    assert inventory["dynamic_sha256"] == live["dynamic_sha256"]
    assert PORT.canonical(inventory["files"]) == live["dynamic_sha256"]
    assert [name for name, _ in inventory["files"]] == sorted(
        str(path.relative_to(tmp_path / "host" / "etc" / "dynamic"))
        for path in (tmp_path / "host" / "etc" / "dynamic").rglob("*")
        if path.is_file()
    )


def test_exit_code_and_output_as_a_program(tmp_path: Path) -> None:
    done = run(tmp_path, drifted(add_route()), cli=True)
    assert done.result is not None
    assert done.result["exit"] == 0
    assert done.result["output"] == {"changed": True, "state": done.record}

    refused = run(tmp_path, drifted(add_route(), new_binary), cli=True)
    assert refused.result is not None
    assert refused.result["exit"] == 2
    assert refused.result["output"] == {
        "failed": True,
        "error": "rebaseline reconciles route drift only; also differs: binary_sha256, version",
    }


# -- every other drift, phase and failure is refused -------------------------------------------

UNIT_DRIFT = {"unit_sha256": sha256(b"another unit")}
MACHINE_DRIFT = {"machine_id": "f" * 32}
REFUSALS = {
    "binary drift": (
        drifted(add_route(), new_binary),
        "rebaseline reconciles route drift only; also differs: binary_sha256, version",
    ),
    "binary drift without route drift": (
        drifted(new_binary),
        "rebaseline reconciles route drift only; also differs: binary_sha256, version",
    ),
    "config drift": (
        drifted(add_route(), edit_config),
        "rebaseline reconciles route drift only; also differs: config_sha256",
    ),
    "unit drift": (
        drifted(add_route(), record=UNIT_DRIFT),
        "rebaseline reconciles route drift only; also differs: unit_sha256",
    ),
    "machine drift": (
        drifted(add_route(), record=MACHINE_DRIFT),
        "rebaseline reconciles route drift only; also differs: machine_id",
    ),
    "binary path drift": (
        drifted(add_route(), record={"binary_path": "/usr/bin/traefik"}),
        "rebaseline reconciles route drift only; also differs: binary_path",
    ),
    "a field the record lacks": (
        drifted(add_route(), record={"extra": "x"}),
        "rebaseline reconciles route drift only; also differs: extra",
    ),
    "several drifts at once": (
        drifted(add_route(), new_binary, edit_config, record=UNIT_DRIFT),
        "rebaseline reconciles route drift only; also differs: binary_sha256, config_sha256, unit_sha256, version",
    ),
    "no drift at all": (drifted(), "no route drift to rebaseline"),
    "pending": (
        drifted(add_route(), phase="pending"),
        "rebaseline requires a clear record; anything else needs a reviewed resume",
    ),
    "recovery": (
        drifted(add_route(), phase="recovery"),
        "rebaseline requires a clear record; anything else needs a reviewed resume",
    ),
    "degraded": (
        drifted(add_route(), phase="degraded"),
        "rebaseline requires a clear record; anything else needs a reviewed resume",
    ),
    "recovery without route drift": (
        drifted(phase="recovery"),
        "rebaseline requires a clear record; anything else needs a reviewed resume",
    ),
}


@pytest.mark.parametrize("case", REFUSALS.values(), ids=REFUSALS.keys())
def test_everything_but_route_drift_on_a_clear_record_is_refused(
    case: tuple[Callable[[Setup], None], str], tmp_path: Path
) -> None:
    scenario, message = case
    outcome, before = run_from(tmp_path, scenario)

    assert outcome.error == ("Refused", message)
    assert_untouched(outcome, before)
    assert outcome.calls == []  # refused before the probe


def test_a_failing_baseline_probe_is_refused(tmp_path: Path) -> None:
    def scenario(setup: Setup) -> None:
        drifted(add_route())(setup)
        setup.host.failing["baseline"] = 1

    outcome, before = run_from(tmp_path, scenario)

    assert outcome.error == ("Refused", "command failed: baseline (exit 1)")
    assert_untouched(outcome, before)
    assert outcome.calls == ["probe baseline"]


def test_an_interrupted_baseline_probe_writes_nothing(tmp_path: Path) -> None:
    def scenario(setup: Setup) -> None:
        drifted(add_route())(setup)
        setup.host.interrupt = "baseline"

    before: dict[str, Any] = {}

    def capture(setup: Setup) -> None:
        scenario(setup)
        before.update(copy.deepcopy(setup.state or {}))

    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, capture)
    assert json.loads((tmp_path / "host" / "state" / "state.json").read_text()) == before
    assert not (tmp_path / "host" / INVENTORY).exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (add_route("late.yml"), "route tree changed during rebaseline"),
        (new_binary, "identity changed during rebaseline probe"),
    ],
    ids=["routes", "binary"],
)
def test_a_change_during_the_probe_is_refused(change: Change, message: str, tmp_path: Path) -> None:
    host = FakeHost(PORT, tmp_path)
    host.install()
    with host.patched():
        setup = base_setup(host, "rebaseline")
        drifted(add_route())(setup)
        host.state_root.mkdir(mode=0o700)
        PORT.save(host.state_root / "state.json", setup.state)
        probe = host.check_probe

        def probe_and_change(spec: dict[str, Any]) -> None:
            probe(spec)
            change(host)

        with patch.object(PORT, "check_probe", probe_and_change), pytest.raises(PORT.Refused, match=f"^{message}$"):
            PORT.execute(setup.request)
    assert json.loads((host.state_root / "state.json").read_text()) == setup.state
    assert not (host.state_root / PORT.ROUTE_INVENTORY).exists()


GENERIC = {
    "stale evidence": (
        lambda setup: setup.request["evidence"].update(verified_at=NOW - 7200),
        "preflight evidence must be at most one hour old",
    ),
    "evidence for another identity": (
        lambda setup: setup.request["evidence"].update(baseline={"machine_id": MACHINE_ID}),
        "reviewed baseline does not match live state",
    ),
    "disagreeing records": (
        lambda setup: setup.request.update(controller_state=None),
        "controller and host recovery records disagree",
    ),
    "missing owner": (lambda setup: setup.request["evidence"].pop("owner"), "missing evidence: owner"),
}


@pytest.mark.parametrize("case", GENERIC.values(), ids=GENERIC.keys())
def test_the_common_preconditions_hold(case: tuple[Callable[[Setup], None], str], tmp_path: Path) -> None:
    change, message = case

    def scenario(setup: Setup) -> None:
        drifted(add_route())(setup)
        change(setup)

    outcome, before = run_from(tmp_path, scenario)

    assert outcome.error == ("Refused", message)
    assert_untouched(outcome, before)


def test_before_enrollment_it_is_refused(tmp_path: Path) -> None:
    def scenario(setup: Setup) -> None:
        setup.state = None
        setup.request["controller_state"] = None

    outcome = run(tmp_path, scenario)
    assert outcome.error == ("Refused", "missing or wrong host enrollment")
    assert "state/state.json" not in outcome.files


def test_a_record_without_a_route_digest_is_refused(tmp_path: Path) -> None:
    def scenario(setup: Setup) -> None:
        drifted(add_route())(setup)
        assert setup.state is not None
        del setup.state["identity"]["dynamic_sha256"]

    outcome = run(tmp_path, scenario)
    assert outcome.error == ("Refused", "invalid recovery state")


# -- the changed file names --------------------------------------------------------------------


class ArchivingHost(FakeHost):
    """The fake host, but ``backup`` writes a real ``prechange.tar.gz`` of the route tree as ``tar`` would.

    Its ``trusted_file`` refuses with the engine's ``Refused``, as the real one does.
    """

    @contextmanager
    def patched(self) -> Iterator[None]:
        engine = self.engine

        def trusted_file(path: Path) -> None:
            try:
                relaxed_trusted_file(path)
            except RuntimeError as exc:
                raise engine.Refused(str(exc)) from exc

        with super().patched(), patch.object(engine, "trusted_file", trusted_file):
            yield

    def backup(self, policy: dict[str, Any], directory: Path) -> None:
        self.calls.append("backup")
        with tarfile.open(directory / "prechange.tar.gz", "w:gz") as bundle:
            bundle.add(self.binary, arcname=str(self.binary).lstrip("/"))
            bundle.add(self.dynamic.parent, arcname=str(self.dynamic.parent).lstrip("/"))
        (directory / "prechange.tar.gz").chmod(0o600)
        self.engine.save(directory / "backup.json", {"paths": policy["backup_paths"], "sha256": "fixture"})


def history(host: FakeHost) -> Callable[[types.ModuleType, str], dict[str, Any]]:
    """Run actions one after another on ``host``, each with the record the last one left."""

    def step(engine: types.ModuleType, action: str) -> dict[str, Any]:
        host.engine = engine
        with host.patched():
            request = base_setup(host, action).request
            path = host.state_root / "state.json"
            request["controller_state"] = json.loads(path.read_text()) if path.exists() else None
            result: dict[str, Any] = engine.execute(request)
        return result

    return step


def test_after_a_binary_transaction_the_archive_names_the_changed_files(tmp_path: Path) -> None:
    host = ArchivingHost(REFERENCE, tmp_path)
    host.install()
    add_route("keep.yml")(host)
    add_route("gone.yml")(host)
    step = history(host)
    step(REFERENCE, "enroll")
    updated = step(PORT, "binary")["state"]
    assert updated["transaction"].startswith(str(host.state_root))

    add_route("added.yml")(host)
    edit_route("app.yml")(host)
    remove_route("gone.yml")(host)
    record = step(PORT, "rebaseline")["state"]

    assert record["rebaseline"]["changed_files_basis"] == "prechange_archive"
    assert record["rebaseline"]["changed_files"] == {
        "added": ["added.yml"],
        "modified": ["app.yml"],
        "removed": ["gone.yml"],
    }
    assert record["rebaselined_from"] == updated["revision"]
    assert record["identity"]["version"] == NEW
    assert "transaction" not in record

    # The next rebaseline diffs against the inventory this one left.
    add_route("later.yml")(host)
    again = step(PORT, "rebaseline")["state"]
    assert again["rebaseline"]["changed_files_basis"] == "route_inventory"
    assert again["rebaseline"]["changed_files"] == {"added": ["later.yml"], "modified": [], "removed": []}

    # And so does one after a later record that left the routes as they were.
    step(PORT, "resume")
    remove_route("later.yml")(host)
    last = step(PORT, "rebaseline")["state"]
    assert last["rebaseline"]["changed_files_basis"] == "route_inventory"
    assert last["rebaseline"]["changed_files"] == {"added": [], "modified": [], "removed": ["later.yml"]}


def test_archived_names_are_ordered_like_the_route_tree(tmp_path: Path) -> None:
    """Paths sort by component ("app/route.yml" before "app.yml"), not as strings."""

    host = ArchivingHost(REFERENCE, tmp_path)
    host.install()
    add_route("app/route.yml")(host)
    add_route("app-b.yml")(host)
    host.engine = PORT
    with host.patched():
        assert [name for name, _ in PORT.route_files(host.dynamic)] == ["app/route.yml", "app-b.yml", "app.yml"]
    step = history(host)
    step(REFERENCE, "enroll")
    step(PORT, "binary")
    add_route("app/other.yml")(host)
    record = step(PORT, "rebaseline")["state"]

    assert record["rebaseline"]["changed_files_basis"] == "prechange_archive"
    assert record["rebaseline"]["changed_files"] == {"added": ["app/other.yml"], "modified": [], "removed": []}


def archive_case(tmp_path: Path, spoil: Callable[[FakeHost, Path], None]) -> dict[str, Any]:
    """Enroll, update (with a real archive), let ``spoil`` damage the archive basis, add a route, rebaseline."""

    host = ArchivingHost(REFERENCE, tmp_path)
    host.install()
    step = history(host)
    step(REFERENCE, "enroll")
    transaction = Path(step(PORT, "binary")["state"]["transaction"])
    spoil(host, transaction)
    add_route()(host)
    record: dict[str, Any] = step(PORT, "rebaseline")["state"]
    return record


def write_record(host: FakeHost, **fields: Any) -> None:
    path = host.state_root / "state.json"
    PORT.save(path, {**json.loads(path.read_text()), **fields})


def spoiled_archive(data: bytes) -> Callable[[FakeHost, Path], None]:
    def spoil(host: FakeHost, transaction: Path) -> None:
        (transaction / "prechange.tar.gz").write_bytes(data)

    return spoil


def other_archive(host: FakeHost, transaction: Path) -> None:
    """A valid archive of a different route tree than the record's."""

    edit_route()(host)
    host.backup(host.policy(), transaction)
    (host.dynamic / "app.yml").write_text("http:\n  routers: {}\n")


def moved_transaction(host: FakeHost, transaction: Path) -> None:
    elsewhere = host.root / "elsewhere" / transaction.name
    shutil.copytree(transaction, elsewhere)
    write_record(host, transaction=str(elsewhere))


def symlinked_archive(host: FakeHost, transaction: Path) -> None:
    archive = transaction / "prechange.tar.gz"
    archive.rename(transaction / "real.tar.gz")
    archive.symlink_to(transaction / "real.tar.gz")


def stale_inventory(host: FakeHost, transaction: Path) -> None:
    """An inventory of another tree and no usable archive: neither basis applies."""

    PORT.save(host.state_root / PORT.ROUTE_INVENTORY, {"dynamic_sha256": "x", "files": [["app.yml", "0" * 64]]})
    (transaction / "prechange.tar.gz").unlink()


@pytest.mark.parametrize(
    "spoil",
    [
        spoiled_archive(b"not an archive"),
        spoiled_archive(gzip.compress(b"not a tar")),
        spoiled_archive(b""),
        other_archive,
        moved_transaction,
        symlinked_archive,
        stale_inventory,
        lambda host, transaction: write_record(host, transaction=7),
        lambda host, transaction: write_record(host, transaction=str(transaction.parent / "not-a-uuid")),
        lambda host, transaction: (transaction / "prechange.tar.gz").unlink(),
    ],
    ids=[
        "garbage",
        "gzip without tar",
        "empty",
        "another tree",
        "outside the state directory",
        "symlink",
        "stale inventory",
        "transaction not a string",
        "not a transaction directory",
        "archive gone",
    ],
)
def test_without_a_verified_basis_the_file_names_are_unavailable(
    spoil: Callable[[FakeHost, Path], None], tmp_path: Path
) -> None:
    record = archive_case(tmp_path, spoil)

    assert record["phase"] == "clear"
    assert record["rebaseline"]["changed_files_basis"] == "unavailable"
    assert record["rebaseline"]["changed_files"] is None


@pytest.mark.parametrize(
    "inventory",
    [
        "not json",
        json.dumps([]),
        json.dumps({"files": "app.yml"}),
        json.dumps({"files": [["app.yml"]]}),
        json.dumps({"files": [["app.yml", 7]]}),
    ],
)
def test_a_malformed_inventory_is_ignored(inventory: str, tmp_path: Path) -> None:
    def spoil(host: FakeHost, transaction: Path) -> None:
        path = host.state_root / PORT.ROUTE_INVENTORY
        path.write_text(inventory)
        path.chmod(0o600)

    record = archive_case(tmp_path, spoil)
    # The archive still names the change.
    assert record["rebaseline"]["changed_files_basis"] == "prechange_archive"
    assert record["rebaseline"]["changed_files"] == {"added": ["new.yml"], "modified": [], "removed": []}


# -- the records cross between engines ---------------------------------------------------------


def test_both_engines_continue_from_a_rebaselined_record(tmp_path: Path) -> None:
    """The reference engine refuses route drift; after a rebaseline either engine updates."""

    for name, engine in ENGINES.items():
        host = FakeHost(REFERENCE, tmp_path / name)
        host.install()
        step = history(host)
        step(REFERENCE, "enroll")
        add_route()(host)
        with host.patched(), pytest.raises(REFERENCE.Refused, match=r"^unknown action$"):
            REFERENCE.execute(base_setup(host, "rebaseline").request)
        refused = pytest.raises(engine.Refused, match=r"^active recovery or unreviewed baseline drift$")
        with refused:
            step(engine, "binary")
        rebaselined = step(PORT, "rebaseline")["state"]
        assert step(REFERENCE, "inspect")["state"] == rebaselined
        done = step(engine, "binary")
        assert done["changed"] is True
        assert done["state"]["phase"] == "clear"
        assert done["state"]["identity"]["version"] == NEW
        assert done["state"]["identity"]["dynamic_sha256"] == rebaselined["identity"]["dynamic_sha256"]
