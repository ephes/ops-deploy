"""A fake host for the Traefik transaction engine, and pinned outcomes of its functions.

:class:`FakeHost` replaces what a test cannot have
or must pin: systemd and the running process (``identity``, ``systemctl restart``,
``traefik version``), the probe programs, the ``tar`` backup, root (``geteuid``,
the root-owned state directory, ``trusted_file`` without the ownership check),
``validate_policy`` (it allows only the real host paths), and ``time`` and
``uuid4`` (fixed, so records compare byte for byte). For the static configuration
actions it also replaces ``openssl`` (a certificate's expiry is derived from its PEM),
the TLS probe of local Traefik (``tls_fingerprints``), the root ownership of the ACME
target's parent directories, and maps the fake host's ACME paths to the real ones for
``validate_acme_storage``, which accepts only those. The replaced functions are tested
on their own, their outcomes pinned by :class:`OutcomePins`. Everything else runs for
real on files below a temporary root: state records, the lock, the transaction
directory, the release archive, the candidate, the binary replacement and its rollback.
``run_scenario`` drives the engine through one request and returns everything it left
behind.
"""

from __future__ import annotations

import base64
import copy
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import types
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path, PosixPath
from typing import Any
from unittest.mock import patch

from ops_deploy.infra.traefik_tx import engine as port
from tests import stubs

PORT = port
GOLDEN = Path(__file__).parent / "golden" / "traefik_tx"


def plain(value: Any, roots: tuple[str, ...] = ()) -> Any:
    """``value`` as JSON data, with the test's temporary directory spelled ``<tmp>``."""

    if isinstance(value, bytes):
        try:
            return {"bytes": plain(value.decode(), roots)}
        except UnicodeDecodeError:
            return {"bytes_sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, PosixPath):
        value = str(value)
    if isinstance(value, str):
        for root in roots:
            value = value.replace(root, "<tmp>")
        return value
    if isinstance(value, dict):
        return {str(plain(key, roots)): plain(item, roots) for key, item in value.items()}
    if isinstance(value, set | frozenset):
        return sorted((plain(item, roots) for item in value), key=repr)
    if isinstance(value, list | tuple):
        return [plain(item, roots) for item in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return repr(value)


class OutcomePins:
    """Outcomes of the engine's functions, pinned in ``tests/golden/traefik_tx/<name>.json``.

    The records and refusals the engine returns are what the hosts' state and the
    operator rely on; a changed outcome fails until it is re-recorded on purpose with
    ``OPS_DEPLOY_UPDATE_GOLDEN=1`` (run serially: ``-p no:xdist``) and reviewed.
    """

    def __init__(self, name: str) -> None:
        self.path = GOLDEN / f"{name}.json"
        self.test = ""
        self.count = 0
        self.roots: tuple[str, ...] = ()
        self._data: dict[str, Any] | None = None

    def start(self, test: str, tmp_path: Path) -> None:
        self.test, self.count = test, 0
        self.roots = tuple(sorted({str(tmp_path), os.path.realpath(tmp_path)}, key=len, reverse=True))

    def check(self, outcome: Any) -> Any:
        key = self.test if self.count == 0 else f"{self.test}#{self.count}"
        self.count += 1
        value = plain(outcome, self.roots)
        if os.environ.get("OPS_DEPLOY_UPDATE_GOLDEN") == "1":
            data = json.loads(self.path.read_text()) if self.path.exists() else {}
            data[key] = value
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
            return outcome
        if self._data is None:
            self._data = json.loads(self.path.read_text())
        assert key in self._data, f"no pinned outcome {key} in {self.path.name} (OPS_DEPLOY_UPDATE_GOLDEN=1 records it)"
        assert value == self._data[key], key
        return outcome


NOW = 1_800_000_000
OLD, NEW = "3.7.14", "3.7.16"
MACHINE_ID = "0123456789abcdef0123456789abcdef"
UNIT = (
    "# /etc/systemd/system/traefik.service\n[Service]\n"
    "ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.toml\n"
)
PROBES = ("baseline", "acceptance", "cleanup")
CONFIG_ACTIONS = ("alias", "metrics_bind", "acme_storage")
ACME_SOURCE, ACME_TARGET = "/acme.json", "/etc/traefik/acme/acme.json"
ACME_NAMES = ("app.example.invalid", "www.example.invalid", "mail.example.invalid")


def static_configs(dynamic: Path) -> dict[str, tuple[str, str, dict[str, str]]]:
    """Per configuration action: the live static config, the reviewed candidate, the policy's ``alias_policy``."""

    provider = f'[providers.file]\ndirectory = "{dynamic}"\nwatch = true\n'
    entrypoints = '[entryPoints.web]\naddress = ":80"\n\n[entryPoints.web-secure]\naddress = ":443"\n'
    metrics = "[metrics.prometheus]\naddEntryPointsLabels = true\n"
    aliased = (
        '[entryPoints.web]\naddress = ":80"\n[entryPoints.web.http]\naliasHeadersStrategy = "delete"\n\n'
        '[entryPoints.web-secure]\naddress = ":443"\n[entryPoints.web-secure.http]\naliasHeadersStrategy = "delete"\n'
    )
    loopback = '[entryPoints.traefik]\naddress = "127.0.0.1:8080"\n'
    loopback += '[entryPoints.traefik.http]\naliasHeadersStrategy = "delete"\n'
    resolver = '[certificatesResolvers.letsencrypt.acme]\nkeyType = "RSA4096"\n'
    challenge = '[certificatesResolvers.letsencrypt.acme.httpChallenge]\nentryPoint = "web"\n'
    misplaced = '[letsencrypt]\n\n[acme]\nemail = "operator@example.invalid"\nstorage = "acme.json"\n'
    moved = f'email = "operator@example.invalid"\nstorage = "{ACME_TARGET}"\n'
    both = {"web": "delete", "web-secure": "delete"}
    return {
        "alias": (provider + entrypoints + metrics, provider + aliased + metrics, both),
        "metrics_bind": (
            provider + aliased + metrics,
            provider + aliased + loopback + metrics + 'entryPoint = "traefik"\n',
            {**both, "traefik": "delete"},
        ),
        "acme_storage": (
            provider + aliased + resolver + challenge + misplaced,
            provider + aliased + resolver + moved + challenge,
            both,
        ),
    }


def acme_store(names: tuple[str, ...] = ACME_NAMES) -> bytes:
    """A populated ACME store as Traefik writes it; the "PEM" is a fixture string."""

    certificates = [
        {
            "domain": {"main": names[0], "sans": list(names[1:2])},
            "certificate": base64.b64encode(f"-----BEGIN CERTIFICATE-----\n{names[0]}\n".encode()).decode(),
            "key": "fixture-private-key",
        }
    ]
    if len(names) > 2:
        certificates.append(
            {
                "domain": {"main": names[2]},
                "certificate": base64.b64encode(f"-----BEGIN CERTIFICATE-----\n{names[2]}\n".encode()).decode(),
                "key": "fixture-private-key",
            }
        )
    store = {"letsencrypt": {"Account": {"Email": "operator@example.invalid"}, "Certificates": certificates}}
    return json.dumps(store, indent=1).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fake_traefik(version: str) -> bytes:
    """A stand-in executable: a shell script that answers ``version`` like Traefik."""

    return f"#!/bin/sh\necho 'Version:      {version}'\necho 'Codename:     fixture'\n".encode()


def version_of(executable: bytes) -> str | None:
    match = re.search(rb"Version: +(\S+)'", executable)
    return None if match is None else match.group(1).decode()


def release_archive(path: Path, members: list[tuple[str, bytes | None]]) -> Path:
    """A ``tar.gz`` like Traefik's releases; a ``None`` member is a directory.

    The gzip header carries no time and no name, so the same members always give the
    same bytes: two engine runs that straddle a second still get the same checksum.
    """

    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as bundle,
    ):
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                bundle.addfile(info)
            else:
                info.size, info.mode = len(data), 0o755
                bundle.addfile(info, io.BytesIO(data))
    return path


class RootOwnedPath(PosixPath):
    """A path whose ``stat`` reports root ownership: the engines require a root-owned state root."""

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        info = super().stat(follow_symlinks=follow_symlinks)
        fields = (info.st_mode, info.st_ino, info.st_dev, info.st_nlink, 0, 0, info.st_size)
        return os.stat_result((*fields, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)))


def relaxed_trusted_file(path: Path) -> None:
    """``trusted_file`` without the root ownership, which a test cannot provide."""

    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise RuntimeError(f"fixture file not regular or writable by others: {path}")


class FakeClock:
    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def time(self) -> float:
        return float(NOW)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


class FakeUuid:
    def __init__(self) -> None:
        self.count = 0

    def uuid4(self) -> uuid.UUID:
        self.count += 1
        return uuid.UUID(int=self.count)


@dataclass
class FakeHost:
    """Traefik on a temporary root, as both engines see it through the patched functions."""

    engine: types.ModuleType
    root: Path
    running: bytes | None = None
    calls: list[str] = field(default_factory=list)
    # The host record as it was on disk at each restart (the pending record, while it is live).
    records_at_restart: list[bytes] = field(default_factory=list)
    # probe name -> failures left (-1: always); a probe named in ``interrupt`` raises KeyboardInterrupt once.
    failing: dict[str, int] = field(default_factory=dict)
    interrupt: str = ""
    restart_failures: int = 0
    # Restarts that come up with a different identity than the binary on disk (a unit that does not settle).
    unsettled_restarts: int = 0
    unsettled: bool = False
    after_backup: Callable[[], None] | None = None
    # Restarts after which local Traefik serves another certificate (until the next restart).
    tls_wrong_restarts: int = 0
    tls_wrong: bool = False
    euid: int = 0
    clock: FakeClock = field(default_factory=FakeClock)
    uuids: FakeUuid = field(default_factory=FakeUuid)
    real_validate_acme_storage: Callable[[bytes, bytes, dict[str, Any]], None] = field(init=False, repr=False)

    @property
    def binary(self) -> Path:
        return self.root / "bin" / "traefik"

    @property
    def config(self) -> Path:
        return self.root / "etc" / "traefik.toml"

    @property
    def dynamic(self) -> Path:
        return self.root / "etc" / "dynamic"

    @property
    def state_root(self) -> Path:
        return self.root / "state"

    @property
    def acme_source(self) -> Path:
        return self.root / "acme.json"

    @property
    def acme_target(self) -> Path:
        return self.root / "etc" / "acme" / "acme.json"

    def probe(self, name: str) -> dict[str, Any]:
        path = self.root / "probes" / name
        return {"argv": [str(path), "--fixture"], "sha256": sha256(path.read_bytes())}

    def install(self, version: str = OLD) -> None:
        for directory in (self.binary.parent, self.dynamic, self.root / "probes"):
            directory.mkdir(parents=True, exist_ok=True)
        # The engine replaces it atomically (a new inode), never in place: a shared copy is safe.
        stubs.install(self.binary, fake_traefik(version))
        self.config.write_text(f'[providers.file]\ndirectory = "{self.dynamic}"\nwatch = true\n')
        (self.dynamic / "app.yml").write_text("http:\n  routers: {}\n")
        for path in (self.config, self.dynamic / "app.yml"):
            path.chmod(0o644)
        for name in PROBES:
            stubs.install(self.root / "probes" / name, f"#!/bin/sh\n# {name} probe fixture\n")
        self.running = self.binary.read_bytes()

    def policy(self) -> dict[str, Any]:
        return {
            "host": "fixture",
            "binary_path": str(self.binary),
            "config_path": str(self.config),
            "dynamic_path": str(self.dynamic),
            "backup_paths": [str(self.binary), str(self.config)],
            "acme_paths": [],
            "alias_policy": {},
        }

    # -- what the engines call ------------------------------------------------------------

    def identity(self, policy: dict[str, Any]) -> dict[str, Any]:
        if self.running is None:
            raise self.engine.Refused("Traefik is not running")
        disk = Path(policy["binary_path"]).read_bytes()
        if self.running != disk:
            raise self.engine.Refused("running/installed executable hash drift")
        return {
            "machine_id": MACHINE_ID,
            "binary_path": policy["binary_path"],
            "binary_sha256": sha256(disk),
            "version": "0.0.0" if self.unsettled else str(version_of(disk)),
            "config_path": policy["config_path"],
            "config_sha256": sha256(Path(policy["config_path"]).read_bytes()),
            "dynamic_sha256": self.engine.inventory_tree(Path(policy["dynamic_path"])),
            "unit_sha256": sha256(UNIT.encode()),
        }

    def run(self, argv: list[str], timeout: int = 30, **kwargs: Any) -> str:
        if argv == ["systemctl", "restart", "traefik.service"]:
            self.calls.append("restart")
            self.records_at_restart.append((self.state_root / "state.json").read_bytes())
            if self.restart_failures:
                self.restart_failures -= 1
                raise self.engine.Refused("command failed: systemctl (exit 1)")
            self.running = self.binary.read_bytes()
            self.tls_wrong = self.tls_wrong_restarts > 0
            self.tls_wrong_restarts = max(0, self.tls_wrong_restarts - 1)
            self.unsettled = self.unsettled_restarts > 0
            self.unsettled_restarts = max(0, self.unsettled_restarts - 1)
            return ""
        if len(argv) == 2 and argv[1] == "version":
            self.calls.append(f"version {Path(argv[0]).name}")
            found = version_of(Path(argv[0]).read_bytes())
            return "no version here\n" if found is None else f"Version:      {found}\nCodename:     fixture\n"
        if argv == ["openssl", "x509", "-noout", "-enddate"]:
            pem = kwargs["input"]
            self.calls.append("openssl")
            return f"notAfter={sha256(pem.encode())[:12]} GMT\n" if "BEGIN" in pem else "unable to load\n"
        raise AssertionError(f"unexpected command: {argv}")

    def tls_fingerprints(self, names: list[str]) -> dict[str, str]:
        self.calls.append("tls")
        return {name: sha256(f"{name} {'other' if self.tls_wrong else 'served'}".encode()) for name in names}

    def validate_acme_storage(self, before: bytes, after: bytes, policy: dict[str, Any]) -> None:
        """The engine's own check, with this host's ACME paths named as the real ones."""

        paths = {str(self.acme_source): ACME_SOURCE, str(self.acme_target): ACME_TARGET}
        named = {key: paths.get(str(policy.get(key)), policy.get(key)) for key in ("acme_source", "acme_target")}
        self.real_validate_acme_storage(before, after, {**policy, **named})

    def lstat_as_root(self, real: Callable[..., os.stat_result]) -> Callable[..., os.stat_result]:
        """``Path.lstat`` reporting root for the ACME target's parent directories."""

        parents = {self.acme_target.parent, self.acme_target.parent.parent}

        def lstat(path: Path) -> os.stat_result:
            info = real(path)
            if Path(path) not in parents:
                return info
            fields = (info.st_mode, info.st_ino, info.st_dev, info.st_nlink, 0, 0, info.st_size)
            return os.stat_result((*fields, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)))

        return lstat

    def check_probe(self, spec: dict[str, Any]) -> None:
        name = Path(spec["argv"][0]).name
        self.calls.append(f"probe {name}")
        if name == self.interrupt:
            self.interrupt = ""
            raise KeyboardInterrupt
        left = self.failing.get(name, 0)
        if left:
            self.failing[name] = left - 1 if left > 0 else left
            raise self.engine.Refused(f"command failed: {name} (exit 1)")

    def backup(self, policy: dict[str, Any], directory: Path) -> None:
        self.calls.append("backup")
        self.engine.atomic(directory / "prechange.tar.gz", b"fixture archive")
        self.engine.save(directory / "backup.json", {"paths": policy["backup_paths"], "sha256": "fixture"})
        if self.after_backup is not None:
            self.after_backup()

    @contextmanager
    def patched(self) -> Iterator[None]:
        engine = self.engine
        with ExitStack() as stack:
            for name, value in {
                "STATE_ROOT": RootOwnedPath(self.state_root),
                "LOCK": self.root / "lock",
                "validate_policy": lambda policy: None,
                "trusted_file": relaxed_trusted_file,
                "identity": self.identity,
                "run": self.run,
                "check_probe": self.check_probe,
                "backup": self.backup,
                "time": self.clock,
                "uuid": self.uuids,
                "tls_fingerprints": self.tls_fingerprints,
                "validate_acme_storage": self.validate_acme_storage,
            }.items():
                if name == "validate_acme_storage":
                    self.real_validate_acme_storage = engine.validate_acme_storage
                stack.enter_context(patch.object(engine, name, value))
            stack.enter_context(patch.object(Path, "lstat", self.lstat_as_root(Path.lstat)))
            stack.enter_context(patch("os.geteuid", new=lambda: self.euid))
            yield


@dataclass
class Setup:
    """What a scenario may change before the engine runs: the host, the request, the record."""

    host: FakeHost
    request: dict[str, Any]
    state: dict[str, Any] | None
    state_dir_mode: int = 0o700
    hold_lock: bool = False


def enrolled_state(identity: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """A clear record as an enrollment leaves it (fixed revision and time)."""

    record = {
        "schema": 1,
        "host": "fixture",
        "phase": "clear",
        "identity": identity,
        "revision": "11111111-2222-4333-8444-555555555555",
        "updated_at": NOW - 86400,
        "owner": "operator",
    }
    record.update(fields)
    return record


def base_setup(host: FakeHost, action: str) -> Setup:
    """A complete, valid request for ``action`` against a clear record (no record for ``enroll``).

    For a static configuration action the host's static config is first rewritten to that
    action's live config (:func:`static_configs`); ``acme_storage`` also gets a populated
    ACME source and an empty target directory.
    """

    policy = host.policy()
    after: bytes | None = None
    if action in CONFIG_ACTIONS:
        before, candidate_config, alias_policy = static_configs(host.dynamic)[action]
        host.config.write_text(before)
        after = candidate_config.encode()
        policy["alias_policy"] = alias_policy
        if action == "acme_storage":
            host.acme_source.write_bytes(acme_store())
            host.acme_source.chmod(0o600)
            host.acme_target.parent.mkdir(mode=0o755, exist_ok=True)
            policy.update(acme_source=str(host.acme_source), acme_target=str(host.acme_target))
            policy["acme_paths"] = [str(host.acme_source)]
            policy["backup_paths"] = [*policy["backup_paths"], str(host.acme_source)]
    live = host.identity(policy)
    candidate = fake_traefik(NEW)
    archive = release_archive(
        host.root / "release.tar.gz", [("LICENSE.md", b"license\n"), ("traefik", candidate), ("CHANGELOG.md", b"log\n")]
    )
    state: dict[str, Any] | None = enrolled_state(live)
    request: dict[str, Any] = {
        "action": action,
        "policy": policy,
        "controller_state": state,
        "evidence": {
            "baseline": live,
            "verified_at": NOW - 60,
            "owner": "operator",
            "review_reference": "fixture review",
            "recovery_access": "fresh key-authenticated root SSH; binary-only",
            "independent_observer": "fixture controller",
            "observer_delivery_test": "fixture HTTP baseline",
            "observer_watch_active": True,
        },
        "baseline_probe": host.probe("baseline"),
        "acceptance_probe": host.probe("acceptance"),
        "cleanup_probe": host.probe("cleanup"),
        "compatibility": {
            "baseline": live,
            "architecture": os.uname().machine,
            "candidate_binary_sha256": sha256(candidate),
            "candidate_config_sha256": live["config_sha256"],
            "passed": True,
            "baseline_pair_passed": True,
            "report_reference": "fixture proof",
        },
        "release": {"version": NEW, "arch": "amd64", "sha256": sha256(archive.read_bytes())},
        "archive_path": str(archive),
    }
    if action == "resume":
        request["recovery_review_reference"] = "fixture reviewed recovery"
    if after is not None:
        request["candidate_config_base64"] = base64.b64encode(after).decode()
        request["approved_binary_sha256"] = live["binary_sha256"]
        request["compatibility"].update(
            candidate_binary_sha256=live["binary_sha256"], candidate_config_sha256=sha256(after)
        )
    if action == "enroll":
        state = None
        request["controller_state"] = None
    return Setup(host=host, request=request, state=state)


def run_main(engine: types.ModuleType, root: Path, request: dict[str, Any]) -> dict[str, Any]:
    """``engine.main`` on ``request`` written to a file; ``main`` sets umask 077 and is given back the old one."""

    path = root / "request.json"
    path.write_text(json.dumps(request))
    output = io.StringIO()
    previous = os.umask(0o022)
    try:
        with patch("sys.argv", ["engine.py", "--request", str(path)]), redirect_stdout(output):
            code = engine.main()
    finally:
        os.umask(previous)
    return {"exit": code, "output": json.loads(output.getvalue())}


@dataclass
class Outcome:
    """Everything one engine run returned or left behind."""

    result: dict[str, Any] | None
    error: tuple[str, str] | None
    files: dict[str, tuple[int, bytes | None]]
    calls: list[str]
    sleeps: list[float]
    records_at_restart: list[bytes]

    @property
    def record(self) -> dict[str, Any] | None:
        """The host record left behind, if any."""

        data = self.files.get("state/state.json")
        return None if data is None or data[1] is None else dict(json.loads(data[1]))

    @property
    def saved(self) -> dict[str, Any]:
        """The host record left behind; there must be one."""

        record = self.record
        assert record is not None
        return record


def snapshot(root: Path) -> dict[str, tuple[int, bytes | None]]:
    """Mode and content of every entry below ``root`` (``None`` for directories)."""

    entries: dict[str, tuple[int, bytes | None]] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        entries[str(path.relative_to(root))] = (stat.S_IMODE(info.st_mode), content)
    return entries


def run_scenario(
    engine: types.ModuleType, root: Path, scenario: Callable[[Setup], None], action: str, *, cli: bool = False
) -> Outcome:
    """Run ``engine`` on a fresh host at ``root`` (always the same path, so runs compare byte for byte).

    With ``cli`` the request goes through ``main`` as a file; the result is then the exit
    code and the printed JSON.
    """

    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    host = FakeHost(engine, root)
    host.install()
    result: dict[str, Any] | None = None
    error: tuple[str, str] | None = None
    with host.patched(), ExitStack() as stack:
        setup = base_setup(host, action)
        scenario(setup)
        if setup.state is not None:
            host.state_root.mkdir(mode=0o700)
            engine.save(host.state_root / "state.json", setup.state)
            host.state_root.chmod(setup.state_dir_mode)
        if setup.hold_lock:
            holder = stack.enter_context((root / "lock").open("a"))
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            result = run_main(engine, root, setup.request) if cli else engine.execute(copy.deepcopy(setup.request))
        except Exception as exc:
            error = (type(exc).__name__, str(exc))
    return Outcome(
        result=result,
        error=error,
        files=snapshot(root),
        calls=host.calls,
        sleeps=host.clock.sleeps,
        records_at_restart=host.records_at_restart,
    )
