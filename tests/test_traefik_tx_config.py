"""``enroll`` and the static configuration actions of the Traefik transaction engine.

As in ``test_traefik_tx_scenarios``: each scenario runs a request on the fake host
(``traefik_tx_fixtures``) and checks the result or refusal and the files left behind.
The validators (``validate_alias``, ``validate_metrics_bind``, ``validate_acme_storage``),
the ACME store reading (``certificate_set``, ``acme_preflight``) and the TLS probe of
local Traefik (``tls_fingerprints``, ``verify_tls_fingerprints``), which the fake host
replaces or relaxes in ``execute``, are tested function by function, their outcomes
pinned in ``tests/golden/traefik_tx/test_traefik_tx_config.json`` (``OutcomePins``).
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import types
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests import stubs
from tests.traefik_tx_fixtures import (
    ACME_NAMES,
    ACME_SOURCE,
    ACME_TARGET,
    NOW,
    OLD,
    PORT,
    FakeHost,
    Outcome,
    OutcomePins,
    Setup,
    acme_store,
    enrolled_state,
    fake_traefik,
    relaxed_trusted_file,
    run_scenario,
    sha256,
    static_configs,
)

PINS = OutcomePins("test_traefik_tx_config")
ENROLLED = "11111111"
DYNAMIC = Path("/etc/traefik/dynamic")
Scenario = Callable[[Setup], None]
Check = Callable[[Outcome], None]


def outcome_of(call: Callable[[], Any]) -> tuple[str, Any]:
    try:
        return ("ok", call())
    except Exception as exc:
        return (type(exc).__name__, str(exc))


@pytest.fixture(autouse=True)
def _pins(request: pytest.FixtureRequest, tmp_path: Path) -> None:
    PINS.start(request.node.name, tmp_path)


def pinned(call: Callable[[types.ModuleType], Any]) -> tuple[str, Any]:
    """``call`` with the engine; the outcome must be the pinned one."""

    outcome: tuple[str, Any] = PINS.check(outcome_of(lambda: call(PORT)))
    return outcome


def configs(action: str) -> tuple[bytes, bytes, dict[str, str]]:
    before, after, approved = static_configs(DYNAMIC)[action]
    return before.encode(), after.encode(), approved


# -- scenarios ------------------------------------------------------------------------------


def unchanged(setup: Setup) -> None:
    pass


def several(*scenarios: Scenario) -> Scenario:
    def scenario(setup: Setup) -> None:
        for each in scenarios:
            each(setup)

    return scenario


def failing(probe: str, times: int = 1) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.host.failing[probe] = times

    return scenario


def host_knob(**knobs: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        for name, value in knobs.items():
            setattr(setup.host, name, value)

    return scenario


def request_change(**fields: Any) -> Scenario:
    """Change request fields; ``None`` removes one."""

    def scenario(setup: Setup) -> None:
        for key, value in fields.items():
            if value is None:
                del setup.request[key]
            else:
                setup.request[key] = value

    return scenario


def policy_change(**fields: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.request["policy"].update(fields)

    return scenario


def compatibility_change(**fields: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.request["compatibility"].update(fields)

    return scenario


def candidate(text: bytes) -> Scenario:
    """Another reviewed candidate, tested as such (so only the engine's delta check can refuse it)."""

    def scenario(setup: Setup) -> None:
        setup.request["candidate_config_base64"] = base64.b64encode(text).decode()
        setup.request["compatibility"]["candidate_config_sha256"] = sha256(text)

    return scenario


def relive(change: Callable[[FakeHost], object]) -> Scenario:
    """Change the host, then make record, evidence and proof name its new live identity."""

    def scenario(setup: Setup) -> None:
        change(setup.host)
        setup.host.running = setup.host.binary.read_bytes()
        live = setup.host.identity(setup.request["policy"])
        if setup.state is not None:
            setup.state = dict(setup.state, identity=live)
        setup.request["controller_state"] = setup.state
        setup.request["evidence"]["baseline"] = live
        setup.request["compatibility"].update(baseline=live, candidate_binary_sha256=live["binary_sha256"])
        setup.request["approved_binary_sha256"] = live["binary_sha256"]

    return scenario


def static_config(action: str, index: int) -> Scenario:
    """The host's static config is the fixture's live config (0) or candidate (1) of ``action``."""

    def change(host: FakeHost) -> None:
        live, reviewed, _ = static_configs(host.dynamic)[action]
        host.config.write_text((live, reviewed)[index])

    return relive(change)


def installed(version: str) -> Scenario:
    return relive(lambda host: stubs.install(host.binary, fake_traefik(version)))


def with_phase(phase: str) -> Scenario:
    def scenario(setup: Setup) -> None:
        assert setup.state is not None
        setup.state = dict(setup.state, phase=phase)
        setup.request["controller_state"] = setup.state

    return scenario


def enrolled(setup: Setup) -> None:
    setup.state = enrolled_state(setup.request["evidence"]["baseline"])
    setup.request["controller_state"] = setup.state


def controller_claims_a_record(setup: Setup) -> None:
    setup.request["controller_state"] = enrolled_state(setup.request["evidence"]["baseline"])


def evidence_change(**fields: Any) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.request["evidence"].update(fields)

    return scenario


def acme_target(content: bytes) -> Scenario:
    def scenario(setup: Setup) -> None:
        setup.host.acme_target.write_bytes(content)
        setup.host.acme_target.chmod(0o600)

    return scenario


def acme_source(content: bytes | None = None, mode: int = 0o600) -> Scenario:
    def scenario(setup: Setup) -> None:
        if content is not None:
            setup.host.acme_source.write_bytes(content)
        setup.host.acme_source.chmod(mode)

    return scenario


def source_changes_after_backup(setup: Setup) -> None:
    def change() -> None:
        setup.host.acme_source.write_bytes(acme_store(("app.example.invalid",)))

    setup.host.after_backup = change


# -- checks ---------------------------------------------------------------------------------


def refused(message: str, kind: str = "Refused", *, version: str = OLD) -> Check:
    """Refused with ``message``; nothing restarted, the binary (``version``) untouched, no ACME copy."""

    def check(outcome: Outcome) -> None:
        assert outcome.result is None
        assert outcome.error == (kind, message)
        assert "restart" not in outcome.calls
        assert outcome.files["bin/traefik"] == (0o755, fake_traefik(version))
        record = outcome.record
        assert record is None or record["revision"].startswith(ENROLLED)
        assert "etc/acme/acme.json" not in outcome.files or outcome.files["etc/acme/acme.json"][1] != acme_store()

    return check


def refused_as(kind: str) -> Check:
    def check(outcome: Outcome) -> None:
        assert outcome.result is None
        assert outcome.error is not None
        assert outcome.error[0] == kind
        assert "restart" not in outcome.calls

    return check


def transaction_files(outcome: Outcome) -> dict[str, bytes | None]:
    return {
        path.split("/", 2)[2]: content
        for path, (_, content) in outcome.files.items()
        if path.startswith("state/") and path.count("/") == 2
    }


ACME_CALLS = ["openssl", "openssl"]


def config_updated(action: str, *, retried: bytes | None = None) -> Check:
    """The candidate is live, the binary unchanged, the record ``clear`` for the new identity."""

    def check(outcome: Outcome) -> None:
        old, new = (text.encode() for text in static_configs_of(outcome)[action][:2])
        assert outcome.error is None
        assert outcome.result is not None
        record = outcome.saved
        assert outcome.result == {"changed": True, "state": record}
        assert record["phase"] == "clear"
        assert record["identity"]["config_sha256"] == sha256(new)
        assert outcome.files["etc/traefik.toml"] == (0o644, new)
        assert outcome.files["bin/traefik"] == (0o755, fake_traefik(OLD))
        files = transaction_files(outcome)
        expected = ["backup.json", "candidate.toml", "original", "prechange.tar.gz", "request.json"]
        if action == "acme_storage":
            expected.append("acme-baseline.json")
            if retried is not None:
                expected.append("acme-target.orig")
        assert sorted(files) == sorted(expected)
        assert files["original"] == old
        assert files["candidate.toml"] == new
        [pending] = [json.loads(data) for data in outcome.records_at_restart]
        assert (pending["phase"], pending["operation"]) == ("pending", action)
        assert pending["previous_revision"].startswith(ENROLLED)
        assert pending["intended_identity"] == record["identity"]
        calls = ["probe baseline", "backup", "restart", "probe acceptance", "probe cleanup"]
        if action == "acme_storage":
            assert outcome.files["etc/acme/acme.json"] == (0o600, acme_store())
            assert outcome.files["etc/acme"] == (0o700, None)
            assert outcome.files["acme.json"] == (0o600, acme_store())
            baseline = json.loads(files["acme-baseline.json"] or b"")
            assert baseline["source_sha256"] == sha256(acme_store())
            assert sorted(baseline["tls_fingerprints"]) == sorted(ACME_NAMES)
            assert [names for names, _ in baseline["certificates"]] == [
                ["app.example.invalid", "www.example.invalid"],
                ["mail.example.invalid"],
            ]
            if retried is not None:
                assert files["acme-target.orig"] == retried
            calls = [
                "probe baseline",
                *ACME_CALLS,
                "tls",
                "backup",
                *ACME_CALLS,
                "restart",
                "probe acceptance",
                "probe cleanup",
                *ACME_CALLS,
                "tls",
            ]
        assert outcome.calls == calls

    return check


def static_configs_of(outcome: Outcome) -> dict[str, tuple[str, str, dict[str, str]]]:
    """The fixture configs for the scenario host (its dynamic directory is in the provider)."""

    config = outcome.files["etc/traefik.toml"][1] or b""
    directory = config.decode().split('directory = "', 1)[1].split('"', 1)[0]
    return static_configs(Path(directory))


def config_rolled_back(action: str, reason: str = "Refused", *, restarts: int = 2) -> Check:
    def check(outcome: Outcome) -> None:
        assert outcome.error is None
        assert outcome.result is not None
        record = outcome.saved
        assert outcome.result == {"changed": restarts > 0, "failed": True, "state": record}
        assert record["phase"] == "recovery"
        assert record["reason"] == reason
        assert record["review_due"] == NOW + 3600
        assert "recovery_error" not in record
        before = static_configs_of(outcome)[action][0].encode()
        assert outcome.files["etc/traefik.toml"] == (0o644, before)
        assert record["identity"]["config_sha256"] == sha256(before)
        assert outcome.calls.count("restart") == restarts

    return check


def config_degraded(error: str = "Refused") -> Check:
    def check(outcome: Outcome) -> None:
        assert outcome.error is None
        assert outcome.result is not None
        record = outcome.saved
        assert outcome.result == {"changed": True, "failed": True, "state": record}
        assert record["phase"] == "degraded"
        assert record["recovery_error"] == error
        assert outcome.calls.count("restart") == 2

    return check


def config_no_op(outcome: Outcome) -> None:
    assert outcome.error is None
    assert outcome.result == {"changed": False, "state": outcome.saved}
    assert outcome.saved["revision"].startswith(ENROLLED)
    assert outcome.calls == ["probe baseline", "probe acceptance", "probe cleanup"]
    assert sorted(transaction_files(outcome)) == ["candidate.toml", "request.json"]


def enrolled_check(outcome: Outcome) -> None:
    assert outcome.error is None
    assert outcome.result is not None
    record = outcome.saved
    assert outcome.result == {"changed": True, "state": record}
    assert set(record) == {"schema", "host", "phase", "identity", "revision", "updated_at", "owner"}
    assert (record["phase"], record["owner"], record["updated_at"]) == ("clear", "operator", NOW)
    assert record["identity"]["version"] == OLD
    assert outcome.calls == []
    assert transaction_files(outcome) == {}


@dataclass(frozen=True)
class Case:
    name: str
    action: str
    setup: Scenario
    check: Check


def alias_cases() -> list[Case]:
    before, after, _ = configs("alias")
    return [
        Case("alias", "alias", unchanged, config_updated("alias")),
        Case("alias acceptance fails", "alias", failing("acceptance"), config_rolled_back("alias")),
        Case(
            "alias interrupted",
            "alias",
            host_knob(interrupt="acceptance"),
            config_rolled_back("alias", "KeyboardInterrupt"),
        ),
        Case("alias restart fails", "alias", host_knob(restart_failures=1), config_rolled_back("alias")),
        Case("alias rollback restart fails", "alias", host_knob(restart_failures=2), config_degraded()),
        Case("alias cleanup keeps failing", "alias", failing("cleanup", -1), config_degraded()),
        Case(
            "alias already live",
            "alias",
            static_config("alias", 1),
            config_no_op,
        ),
        Case(
            "alias with an unrelated change",
            "alias",
            candidate(after + b"[api]\ninsecure = true\n"),
            refused("alias candidate changes unrelated configuration"),
        ),
        Case(
            "alias map misses an entrypoint",
            "alias",
            policy_change(alias_policy={"web": "delete"}),
            refused("alias map must cover every entrypoint"),
        ),
        Case(
            "alias strategy other than delete",
            "alias",
            policy_change(alias_policy={"web": "delete", "web-secure": "keep"}),
            refused("only the approved delete strategy is supported"),
        ),
        Case(
            "alias candidate not tested",
            "alias",
            compatibility_change(candidate_config_sha256="f" * 64),
            refused("alias candidate differs from isolated test"),
        ),
        Case(
            "alias with another binary tested",
            "alias",
            compatibility_change(candidate_binary_sha256="f" * 64),
            refused("alias candidate differs from isolated test"),
        ),
        Case(
            "alias executable not approved",
            "alias",
            request_change(approved_binary_sha256="0" * 64),
            refused("alias operation requires approved executable hash"),
        ),
        Case(
            "alias on an old Traefik",
            "alias",
            installed("3.7.11"),
            refused("alias policy requires a compatible running and installed binary", version="3.7.11"),
        ),
        Case("alias candidate not base64", "alias", request_change(candidate_config_base64="!"), refused_as("Error")),
        Case("alias without approval", "alias", request_change(approved_binary_sha256=None), refused_as("KeyError")),
        Case("alias without candidate", "alias", request_change(candidate_config_base64=None), refused_as("KeyError")),
        Case(
            "alias without isolated proof",
            "alias",
            compatibility_change(passed=False),
            refused("isolated preflight proof required"),
        ),
        Case(
            "alias while in recovery",
            "alias",
            with_phase("recovery"),
            refused("active recovery or unreviewed baseline drift"),
        ),
        Case(
            "alias baseline probe fails",
            "alias",
            failing("baseline"),
            refused("command failed: baseline (exit 1)"),
        ),
        Case(
            "alias of the unchanged config",
            "alias",
            candidate(before),
            refused("alias candidate changes unrelated configuration"),
        ),
    ]


def metrics_cases() -> list[Case]:
    _, after, _ = configs("metrics_bind")
    return [
        Case("metrics bind", "metrics_bind", unchanged, config_updated("metrics_bind")),
        Case(
            "metrics bind acceptance fails",
            "metrics_bind",
            failing("acceptance"),
            config_rolled_back("metrics_bind"),
        ),
        Case(
            "metrics bind already live",
            "metrics_bind",
            static_config("metrics_bind", 1),
            refused("metrics entrypoint already exists"),
        ),
        Case(
            "metrics bind before the alias policy",
            "metrics_bind",
            static_config("alias", 0),
            refused("existing entrypoint alias policy is incomplete"),
        ),
        Case(
            "metrics bind policy misses the new entrypoint",
            "metrics_bind",
            policy_change(alias_policy={"web": "delete", "web-secure": "delete"}),
            refused("metrics binding policy must cover every resulting entrypoint"),
        ),
        Case(
            "metrics bind on another address",
            "metrics_bind",
            candidate(after.replace(b"127.0.0.1:8080", b"0.0.0.0:8080")),
            refused("metrics binding candidate changes unrelated static configuration"),
        ),
    ]


def acme_cases() -> list[Case]:
    _, after, _ = configs("acme_storage")
    return [
        Case("acme storage", "acme_storage", unchanged, config_updated("acme_storage")),
        Case(
            "acme storage retried onto an exact copy",
            "acme_storage",
            acme_target(acme_store()),
            config_updated("acme_storage", retried=acme_store()),
        ),
        Case(
            "acme storage onto an empty target",
            "acme_storage",
            acme_target(b""),
            config_updated("acme_storage", retried=b""),
        ),
        Case(
            "acme storage onto a foreign target",
            "acme_storage",
            acme_target(acme_store(("other.example.invalid",))),
            refused("ACME target must be absent, empty or an exact copy of the source"),
        ),
        Case(
            "acme source readable by the group",
            "acme_storage",
            acme_source(mode=0o640),
            refused("ACME source must be 0600"),
        ),
        Case(
            "acme source outside the backup set",
            "acme_storage",
            lambda setup: setup.request["policy"]["backup_paths"].pop(),
            refused("source backup is required"),
        ),
        Case(
            "acme source not an approved store",
            "acme_storage",
            policy_change(acme_paths=[]),
            refused("source backup is required"),
        ),
        Case(
            "acme store without certificates",
            "acme_storage",
            acme_source(json.dumps({"letsencrypt": {"Certificates": []}}).encode()),
            refused("empty certificate store"),
        ),
        Case(
            "acme store with two resolvers",
            "acme_storage",
            acme_source(json.dumps({"letsencrypt": {}, "other": {}}).encode()),
            refused("expected one letsencrypt resolver"),
        ),
        Case(
            "acme served certificate changes",
            "acme_storage",
            host_knob(tls_wrong_restarts=1),
            config_rolled_back("acme_storage"),
        ),
        Case(
            "acme served certificate stays changed",
            "acme_storage",
            host_knob(tls_wrong_restarts=2),
            config_degraded(),
        ),
        Case(
            "acme source changes before the copy",
            "acme_storage",
            source_changes_after_backup,
            config_rolled_back("acme_storage", restarts=0),
        ),
        Case(
            "acme candidate with another email",
            "acme_storage",
            candidate(after.replace(b"operator@", b"changed@")),
            refused("ACME candidate changes unrelated configuration"),
        ),
        Case(
            "acme candidate on another store path",
            "acme_storage",
            candidate(after.replace(ACME_TARGET.encode(), b"/etc/traefik/acme.json")),
            refused("ACME candidate changes unrelated configuration"),
        ),
        Case(
            "acme on another source",
            "acme_storage",
            policy_change(acme_source="/root/acme.json"),
            refused("unsupported ACME source"),
        ),
    ]


def enroll_cases() -> list[Case]:
    return [
        Case("enroll", "enroll", unchanged, enrolled_check),
        Case(
            "enroll over a record",
            "enroll",
            enrolled,
            refused("enrollment cannot overwrite any existing recovery record"),
        ),
        Case(
            "enroll while the controller has a record",
            "enroll",
            controller_claims_a_record,
            refused("controller and host recovery records disagree"),
        ),
        Case(
            "enroll on stale evidence",
            "enroll",
            evidence_change(verified_at=NOW - 3601),
            refused("preflight evidence must be at most one hour old"),
        ),
        Case(
            "enroll without an observer",
            "enroll",
            evidence_change(observer_watch_active=False),
            refused("independent observer must be watching"),
        ),
        Case("enroll as another user", "enroll", host_knob(euid=1000), refused("root is required")),
        Case("enroll a stopped Traefik", "enroll", host_knob(running=None), refused("Traefik is not running")),
    ]


CASES = alias_cases() + metrics_cases() + acme_cases() + enroll_cases()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_scenario(case: Case, tmp_path: Path) -> None:
    case.check(run_scenario(PORT, tmp_path / "host", case.setup, case.action))


CLI_CASES = {
    "enroll": ("enroll", unchanged, 0, "clear"),
    "alias": ("alias", unchanged, 0, "clear"),
    "alias rollback": ("alias", failing("acceptance"), 1, "recovery"),
    "metrics bind refusal": ("metrics_bind", with_phase("pending"), 2, ""),
    "acme degraded": ("acme_storage", host_knob(tls_wrong_restarts=2), 1, "degraded"),
}


@pytest.mark.parametrize("case", CLI_CASES.values(), ids=CLI_CASES.keys())
def test_exit_codes_and_output(case: tuple[str, Scenario, int, str], tmp_path: Path) -> None:
    action, scenario, code, phase = case
    port = run_scenario(PORT, tmp_path / "host", scenario, action, cli=True)

    assert port.error is None
    assert port.result is not None
    assert port.result["exit"] == code
    assert port.result["output"].get("state", {}).get("phase", "") == phase


# -- the replaced functions, on their own ---------------------------------------------


def alias_pairs() -> list[tuple[bytes, bytes, dict[str, str]]]:
    before, after, approved = configs("alias")
    udp = before + b'[entryPoints.dns]\naddress = ":53/udp"\n'
    underscore = before.replace(
        b'address = ":80"\n', b'address = ":80"\n[entryPoints.web.http]\nunderscoreHeadersStrategy = "x"\n'
    )
    return [
        (before, after, approved),
        (after, after, approved),
        (before, before, approved),
        (before, after, {"web": "delete"}),
        (before, after, {**approved, "extra": "delete"}),
        (before, after, {"web": "delete", "web-secure": "allow"}),
        (udp, after, {**approved, "dns": "delete"}),
        (underscore, after, approved),
        (b"[api]\n", b"[api]\n", {}),
        (before, b"not = [toml", approved),
    ]


@pytest.mark.parametrize("pair", alias_pairs())
def test_validate_alias(pair: tuple[bytes, bytes, dict[str, str]]) -> None:
    pinned(lambda engine: engine.validate_alias(*pair))


def metrics_pairs() -> list[tuple[bytes, bytes, dict[str, str]]]:
    before, after, approved = configs("metrics_bind")
    plain = configs("alias")[0]
    return [
        (before, after, approved),
        (after, after, approved),
        (before, after, {"web": "delete", "web-secure": "delete"}),
        (before, after, {**approved, "traefik": "allow"}),
        (plain, after, approved),
        (before.replace(b"[metrics.prometheus]\naddEntryPointsLabels = true\n", b""), after, approved),
        (before.replace(b"addEntryPointsLabels = true", b'entryPoint = "web"'), after, approved),
        (before, after.replace(b"127.0.0.1", b"0.0.0.0"), approved),
        (b"[metrics]\nprometheus = 1\n", after, approved),
        (b"entryPoints = 1\n", after, approved),
        (b"[api]\n", after, approved),
    ]


@pytest.mark.parametrize("pair", metrics_pairs())
def test_validate_metrics_bind(pair: tuple[bytes, bytes, dict[str, str]]) -> None:
    pinned(lambda engine: engine.validate_metrics_bind(*pair))


ACME_POLICY = {"acme_source": ACME_SOURCE, "acme_target": ACME_TARGET}


def acme_pairs() -> list[tuple[bytes, bytes, dict[str, Any]]]:
    before, after, _ = configs("acme_storage")
    return [
        (before, after, ACME_POLICY),
        (before, after, {**ACME_POLICY, "acme_source": "/root/acme.json"}),
        (before, after, {**ACME_POLICY, "acme_target": "/acme.json"}),
        (before, after, {}),
        (after, after, ACME_POLICY),
        (before.replace(b"[letsencrypt]\n\n", b""), after, ACME_POLICY),
        (before.replace(b"[letsencrypt]\n\n", b"[letsencrypt]\nx = 1\n\n"), after, ACME_POLICY),
        (before.replace(b'email = "operator@example.invalid"', b"email = 1"), after, ACME_POLICY),
        (before.replace(b'storage = "acme.json"\n', b'storage = "acme.json"\ncaServer = "x"\n'), after, ACME_POLICY),
        (before.replace(b'keyType = "RSA4096"', b'storage = "/old.json"'), after, ACME_POLICY),
        (before, after.replace(b"RSA4096", b"EC256"), ACME_POLICY),
        (
            before.replace(b"[certificatesResolvers.letsencrypt.acme]", b"[certificatesResolvers.other.acme]"),
            after,
            ACME_POLICY,
        ),
    ]


@pytest.mark.parametrize("pair", acme_pairs())
def test_validate_acme_storage(pair: tuple[bytes, bytes, dict[str, Any]]) -> None:
    pinned(lambda engine: engine.validate_acme_storage(*pair))


def fake_openssl(argv: list[str], timeout: int = 30, **kwargs: Any) -> str:
    assert argv == ["openssl", "x509", "-noout", "-enddate"]
    pem = kwargs["input"]
    return f"notAfter={sha256(pem.encode())[:8]}\n" if "BEGIN" in pem else "no\n"


STORES = {
    "populated": acme_store(),
    "one certificate": acme_store(("app.example.invalid",)),
    "two resolvers": json.dumps({"letsencrypt": {}, "other": {}}).encode(),
    "no certificates": json.dumps({"letsencrypt": {"Certificates": []}}).encode(),
    "certificates not a list": json.dumps({"letsencrypt": {"Certificates": {}}}).encode(),
    "empty domain": json.dumps(
        {"letsencrypt": {"Certificates": [{"domain": {"main": ""}, "certificate": "QkVHSU4="}]}}
    ).encode(),
    "certificate not base64": json.dumps(
        {"letsencrypt": {"Certificates": [{"domain": {"main": "a"}, "certificate": "!"}]}}
    ).encode(),
    "no expiry": json.dumps(
        {"letsencrypt": {"Certificates": [{"domain": {"main": "a"}, "certificate": "eA=="}]}}
    ).encode(),
    "not JSON": b"{",
}


@pytest.mark.parametrize("store", STORES.values(), ids=STORES.keys())
def test_certificate_set(store: bytes) -> None:
    def call(engine: types.ModuleType) -> Any:
        with patch.object(engine, "run", fake_openssl):
            return engine.certificate_set(store)

    pinned(call)


@pytest.fixture
def acme_host(tmp_path: Path) -> Iterator[FakeHost]:
    host = FakeHost(PORT, tmp_path / "host")
    host.install()
    host.acme_source.write_bytes(acme_store())
    host.acme_source.chmod(0o600)
    host.acme_target.parent.mkdir()
    with ExitStack() as stack:
        stack.enter_context(patch.object(Path, "lstat", host.lstat_as_root(Path.lstat)))
        stack.enter_context(patch.object(PORT, "trusted_file", relaxed_trusted_file))
        stack.enter_context(patch.object(PORT, "run", fake_openssl))
        yield host


def target_directory_symlink(host: FakeHost) -> None:
    host.acme_target.parent.rmdir()
    host.acme_target.parent.symlink_to(host.root)


PREFLIGHTS: dict[str, Callable[[FakeHost], object]] = {
    "absent target": lambda host: None,
    "empty target": lambda host: host.acme_target.write_bytes(b""),
    "exact copy": lambda host: host.acme_target.write_bytes(acme_store()),
    "foreign target": lambda host: host.acme_target.write_bytes(b"{}"),
    "source 0640": lambda host: host.acme_source.chmod(0o640),
    "group-writable target directory": lambda host: host.acme_target.parent.chmod(0o775),
    "no target directory": lambda host: host.acme_target.parent.rmdir(),
    "target directory is a symlink": target_directory_symlink,
    "no source": lambda host: host.acme_source.unlink(),
}


@pytest.mark.parametrize("change", PREFLIGHTS.values(), ids=PREFLIGHTS.keys())
def test_acme_preflight(change: Callable[[FakeHost], object], acme_host: FakeHost) -> None:
    change(acme_host)
    policy = {"acme_source": str(acme_host.acme_source), "acme_target": str(acme_host.acme_target)}

    pinned(lambda engine: engine.acme_preflight(policy))


class FakeTls:
    """A connection to local Traefik that serves one leaf per SNI name (``None``: none)."""

    def __init__(self, served: dict[str, bytes | None], connected: list[tuple[str, int]]) -> None:
        self.served = served
        self.connected = connected
        self.name = ""

    def connect(self, address: tuple[str, int], timeout: float) -> FakeTls:
        assert timeout == 10
        self.connected.append(address)
        if address != ("127.0.0.1", 443) or not self.served:
            raise ConnectionRefusedError
        return self

    def wrap(self, context: ssl.SSLContext, sock: Any, server_hostname: str) -> FakeTls:
        assert context.verify_mode == ssl.CERT_NONE
        assert not context.check_hostname
        self.name = server_hostname
        return self

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        assert binary_form
        return self.served.get(self.name)

    def __enter__(self) -> FakeTls:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


SERVED: dict[str, dict[str, bytes | None]] = {
    "every name": {name: name.encode() for name in ACME_NAMES},
    "one name without a certificate": {**{name: name.encode() for name in ACME_NAMES}, ACME_NAMES[1]: None},
    "nothing listens": {},
}


@pytest.mark.parametrize("served", SERVED.values(), ids=SERVED.keys())
def test_tls_fingerprints(served: dict[str, bytes | None]) -> None:
    def call(engine: types.ModuleType) -> Any:
        connected: list[tuple[str, int]] = []
        fake = FakeTls(served, connected)
        with (
            patch.object(socket, "create_connection", fake.connect),
            patch.object(
                ssl.SSLContext,
                "wrap_socket",
                lambda context, sock, server_hostname: fake.wrap(context, sock, server_hostname),
            ),
        ):
            return engine.tls_fingerprints(list(ACME_NAMES)), connected

    pinned(call)


@pytest.mark.parametrize("failures", [0, 1, 4, 5])
@pytest.mark.parametrize("kind", ["refused", "oserror"])
def test_verify_tls_fingerprints_settles_but_never_accepts_another_leaf(failures: int, kind: str) -> None:
    baseline = {"a": "1"}

    def call(engine: types.ModuleType) -> Any:
        left, sleeps = [failures], list[float]()

        def probe(names: list[str]) -> dict[str, str]:
            if left[0]:
                left[0] -= 1
                if kind == "oserror":
                    raise ConnectionResetError
                return {"a": "2"}
            return dict(baseline)

        with (
            patch.object(engine, "tls_fingerprints", probe),
            patch.object(engine.time, "sleep", sleeps.append),
        ):
            try:
                engine.verify_tls_fingerprints(["a"], baseline)
            except engine.Refused as exc:
                return ("refused", str(exc), type(exc.__cause__).__name__, sleeps)
            return ("ok", sleeps)

    assert pinned(call)[1][0] == ("refused" if failures == 5 else "ok")


def test_the_actions() -> None:
    assert (
        PORT.PORTED
        == PORT.ACTIONS
        == ("inspect", "enroll", "binary", "alias", "metrics_bind", "acme_storage", "resume")
    )
    assert set(PORT.CONFIG_ACTIONS) == {"alias", "metrics_bind", "acme_storage"}
