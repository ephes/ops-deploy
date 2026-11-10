"""services.software_estate_publisher: the two ops-library publisher roles.

Fake-host runs cover the Linux operations (fresh host, converged host,
removal); the macOS host program runs for real against a temporary home with
a recording ``launchctl`` stand-in (owner mode, as on Atlas).
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shlex
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.software_estate_publisher import (
    SoftwareEstatePublisherConfig,
    deploy_software_estate_publisher,
    release_id,
)
from ops_deploy.services.software_estate_publisher import deploy as darwin
from ops_deploy.services.software_estate_publisher.render import PROGRAMS, config_json, program, render
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

ENDPOINT = "https://graphyard.example.invalid/v1/inventory"
POLICY = {"host": "fractal", "applications": [{"id": "traefik", "unit": "traefik.service"}], "application_roots": []}
WRITER = "synthetic-writer-value"
RELEASE = "/usr/local/lib/software-estate-publisher/" + release_id()
PATH_CHECK = re.compile(r"^python3 -I -c .\"\"\"The Linux role")


def secrets(values: dict[str, str]) -> SecretValues:
    return SecretValues(SecretRef("secrets/prod/software_estate_test.yml"), values)


def linux(**overrides: Any) -> SoftwareEstatePublisherConfig:
    values: dict[str, Any] = {
        "platform": "linux",
        "hostnames": ("fractal",),
        "endpoint": ENDPOINT,
        "policy": POLICY,
        "minute": 7,
        "python": "/usr/bin/python3",
    }
    return SoftwareEstatePublisherConfig.model_validate({**values, **overrides})


def test_release_is_the_roles_content_hash() -> None:
    joined = "".join(program(name).rstrip() for name in PROGRAMS)
    assert release_id() == hashlib.sha256(joined.encode()).hexdigest()
    # The release macmini and staging run since 2026-09-21 (ops-library 61c239d3).
    assert release_id() == "180b3a94c83641b4c03d545c2d9a882b056dd232d769bc158fd2eee58401d823"


def test_linux_rendering_is_the_roles() -> None:
    cfg = linux()
    timer = render(cfg, "publisher.timer.j2")
    assert "OnCalendar=*-*-* *:07:00\n" in timer
    assert timer.endswith("WantedBy=timers.target\n")
    service = render(cfg, "publisher.service.j2")
    assert f"ExecStart=/usr/bin/python3 {RELEASE}/publish.py --config /etc/software-estate-publisher/config.json\n" in (
        service
    )
    assert render(cfg, "run.j2").splitlines()[-1] == (
        "exec /usr/sbin/runuser -u software-estate-publisher -- /usr/bin/python3 "
        f'{RELEASE}/publish.py --config /etc/software-estate-publisher/config.json "$@"'
    )
    data = json.loads(config_json(cfg))
    assert data == {
        "credential_file": "/etc/software-estate-publisher/writer",
        "directory": "/var/lib/software-estate-publisher",
        "endpoint": ENDPOINT,
        "hostnames": ["fractal"],
        "policy": POLICY,
    }
    assert config_json(cfg) == json.dumps(data, indent=4, sort_keys=True) + "\n"


@pytest.mark.parametrize(
    "overrides",
    [
        {"owner": "jochen"},
        {"endpoint": "http://graphyard.example.invalid/v1/inventory"},
        {"policy": {**POLICY, "host": "macmini"}},
        {"policy": None},
        {"minute": 60},
        {"python": "/usr/bin/../bin/python3"},
    ],
)
def test_linux_config_refuses(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        linux(**overrides)


def test_removal_needs_no_policy_or_endpoint() -> None:
    cfg = linux(state="absent", policy=None, endpoint="")
    assert cfg.state == "absent"


def _fresh_linux() -> dict[Any, Any]:
    return {
        **fakehost.LINUX,
        "id -u": ["0"],
        "test -d /run/systemd/system": ["systemd"],
        "uname -n": ["fractal"],
        PATH_CHECK: ["ok"],
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/etc/systemd/system"),
    }


def test_fresh_linux_host_gets_the_roles_files_in_order() -> None:
    result = run_deploy_fake(
        deploy_software_estate_publisher, linux(), secrets({"writer": f"  {WRITER}\n"}), responses=_fresh_linux()
    )
    assert result.succeeded, result.error
    assert [path for path in result.written_paths] == [
        *(f"{RELEASE}/{name}" for name in PROGRAMS),
        "/etc/software-estate-publisher/config.json",
        "/usr/local/bin/software-estate-publisher",
        "/etc/systemd/system/software-estate-publisher.service",
        "/etc/systemd/system/software-estate-publisher.timer",
        "/etc/software-estate-publisher/writer",
    ]
    assert result.written("/etc/software-estate-publisher/writer") == (WRITER + "\n").encode()
    for name in PROGRAMS:
        assert result.written(f"{RELEASE}/{name}") == program(name).encode()
    commands = "\n".join(result.executed_commands)
    assert "useradd -d /nonexistent -s /usr/sbin/nologin -g software-estate-publisher -r -M" in commands
    assert f"{RELEASE}/publish.py --config /etc/software-estate-publisher/config.json --check" in commands
    assert "systemctl daemon-reload" in commands
    assert "systemctl start --no-block software-estate-publisher.service" in commands
    assert WRITER not in result.all_text()
    validate = next(op for op in result.ops if op.name.endswith("Validate the configuration as the publisher account"))
    assert validate.read_only


def _converged_linux(cfg: SoftwareEstatePublisherConfig) -> dict[Any, Any]:
    account = "software-estate-publisher"
    responses = _fresh_linux()
    responses.update(fakehost.accounts({account: "/nonexistent"}))
    for path in ("/etc/software-estate-publisher", "/var/lib/software-estate-publisher/outbox"):
        responses.update(fakehost.directory(path, user=account, mode="drwx------"))
    responses.update(fakehost.directory("/var/lib/software-estate-publisher", user=account, mode="drwx------"))
    responses.update(fakehost.directory("/usr/local/lib/software-estate-publisher"))
    responses.update(fakehost.directory(RELEASE))
    for name in PROGRAMS:
        responses.update(fakehost.file(f"{RELEASE}/{name}", program(name)))
    responses.update(
        fakehost.file("/etc/software-estate-publisher/writer", WRITER + "\n", user=account, mode="-rw-------")
    )
    responses.update(
        fakehost.file("/etc/software-estate-publisher/config.json", config_json(cfg), user=account, mode="-rw-------")
    )
    responses.update(
        fakehost.file("/usr/local/bin/software-estate-publisher", render(cfg, "run.j2"), mode="-rwxr-xr-x")
    )
    for unit, template in (("service", "publisher.service.j2"), ("timer", "publisher.timer.j2")):
        responses.update(fakehost.file(f"/etc/systemd/system/software-estate-publisher.{unit}", render(cfg, template)))
    responses.update(fakehost.service("software-estate-publisher.timer"))
    return responses


def test_converged_linux_host_changes_nothing() -> None:
    cfg = linux()
    result = run_deploy_fake(
        deploy_software_estate_publisher, cfg, secrets({"writer": WRITER}), responses=_converged_linux(cfg)
    )
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert result.written_paths == []


TIMER_UNIT, SERVICE_UNIT = "software-estate-publisher.timer", "software-estate-publisher.service"
WANTS_LINK = f"/etc/systemd/system/timers.target.wants/{TIMER_UNIT}"


def unit_state(unit: str, load: str, active: str) -> dict[str, Any]:
    """The removal's ``systemctl show -p LoadState -p ActiveState UNIT`` fact."""

    return {f"systemctl show -p LoadState -p ActiveState {unit}": [f"LoadState={load}", f"ActiveState={active}"]}


def _remove(responses: dict[Any, Any]) -> Any:
    return run_deploy_fake(
        deploy_software_estate_publisher, linux(state="absent", policy=None), None, responses=responses
    )


def _verification(result: Any) -> Any:
    return next(op for op in result.ops if op.name.endswith("Verify the publisher units are unloaded"))


def test_linux_removal_keeps_programs_configuration_and_state() -> None:
    responses = _fresh_linux()
    for unit in ("service", "timer"):
        responses.update(fakehost.file(f"/etc/systemd/system/software-estate-publisher.{unit}", "unit\n"))
    responses.update(fakehost.service(TIMER_UNIT))
    responses.update(fakehost.service(SERVICE_UNIT, running=False))
    responses.update(unit_state(TIMER_UNIT, "loaded", "active"))
    responses.update(unit_state(SERVICE_UNIT, "loaded", "inactive"))
    result = _remove(responses)
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert "systemctl stop software-estate-publisher.timer" in commands
    assert "systemctl stop software-estate-publisher.service" not in commands
    assert any("systemctl disable software-estate-publisher.timer" in command for command in commands)
    removed = [command for command in commands if command.startswith("rm ")]
    assert removed == [
        "rm -f /etc/systemd/system/software-estate-publisher.timer",
        "rm -f /etc/systemd/system/software-estate-publisher.service",
    ]
    assert "systemctl daemon-reload" in commands
    assert _verification(result).read_only
    text = "\n".join(commands)
    for kept in ("/etc/software-estate-publisher", "/var/lib/software-estate-publisher", RELEASE):
        assert kept not in text
    assert result.written_paths == []


def test_linux_removal_stops_units_whose_files_are_already_gone() -> None:
    # The unit files were deleted by hand; systemd still has both units loaded
    # and the timer scheduled.
    responses = _fresh_linux()
    responses.update(fakehost.symlink(WANTS_LINK, f"/etc/systemd/system/{TIMER_UNIT}"))
    responses.update(unit_state(TIMER_UNIT, "loaded", "active"))
    responses.update(unit_state(SERVICE_UNIT, "loaded", "activating"))
    result = _remove(responses)
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert commands.index("systemctl stop software-estate-publisher.timer") < commands.index(
        "systemctl stop software-estate-publisher.service"
    )
    # `systemctl disable` needs the unit file; the enablement link goes directly.
    assert not any("systemctl disable" in command for command in commands)
    assert [command for command in commands if command.startswith("rm ")] == [f"rm -f {WANTS_LINK}"]
    assert commands.index("systemctl daemon-reload") > commands.index(f"rm -f {WANTS_LINK}")
    assert _verification(result).read_only


def test_linux_removal_reloads_systemd_for_a_loaded_unit_without_a_file() -> None:
    responses = _fresh_linux()
    responses.update(unit_state(TIMER_UNIT, "loaded", "inactive"))
    responses.update(unit_state(SERVICE_UNIT, "not-found", "inactive"))
    result = _remove(responses)
    assert result.succeeded, result.error
    assert "systemctl daemon-reload" in result.executed_commands
    assert not any("systemctl stop" in command for command in result.executed_commands)


def test_removed_linux_publisher_changes_nothing() -> None:
    responses = _fresh_linux()
    responses.update(unit_state(TIMER_UNIT, "not-found", "inactive"))
    responses.update(unit_state(SERVICE_UNIT, "not-found", "failed"))
    result = _remove(responses)
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert "systemctl daemon-reload" not in result.executed_commands
    verification = _verification(result)
    assert verification.read_only
    [script] = [command for command in result.executed_commands if "is still loaded or active" in command]
    for unit in (TIMER_UNIT, SERVICE_UNIT):
        assert f"s=$(systemctl show -p LoadState -p ActiveState {unit}) || exit 1" in script


@pytest.mark.parametrize(
    ("load", "active", "passes"),
    [
        ("not-found", "inactive", True),
        ("not-found", "failed", True),
        ("loaded", "inactive", False),
        ("not-found", "active", False),
        ("not-found", "activating", False),
        ("not-found", "deactivating", False),
    ],
)
def test_linux_removal_verification_reads_systemd(tmp_path: Path, load: str, active: str, passes: bool) -> None:
    responses = _fresh_linux()
    responses.update(unit_state(TIMER_UNIT, "not-found", "inactive"))
    [script] = [command for command in _remove(responses).executed_commands if "is still loaded" in command]
    # A systemctl stand-in: the service answers with this state, the timer is gone.
    stub = tmp_path / "systemctl"
    stub.write_text(
        '#!/bin/sh\ncase "$6" in *.service) printf "LoadState=%s\\nActiveState=%s\\n" '
        f"{load} {active};; *) printf 'LoadState=not-found\\nActiveState=inactive\\n';; esac\n"
    )
    stub.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}
    result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, env=env, check=False)
    assert (result.returncode == 0) is passes, result.stderr
    if not passes:
        assert f"{SERVICE_UNIT} is still loaded or active" in result.stderr


def test_linux_removal_fails_while_a_unit_stays_loaded() -> None:
    responses: dict[Any, Any] = {"is still loaded or active": {"success": False, "stderr": "still loaded"}}
    responses.update(_fresh_linux())
    responses.update(unit_state(TIMER_UNIT, "loaded", "active"))
    result = _remove(responses)
    assert not result.succeeded
    assert not _verification(result).succeeded


def test_unsafe_linux_paths_stop_before_any_change() -> None:
    responses: dict[Any, Any] = {
        **_fresh_linux(),
        PATH_CHECK: {"success": False, "stderr": "Unsafe publisher path: /etc"},
    }
    result = run_deploy_fake(
        deploy_software_estate_publisher, linux(), secrets({"writer": WRITER}), responses=responses
    )
    assert not result.succeeded
    assert result.executed_commands == []


def test_wrong_linux_host_is_refused() -> None:
    responses = {**_fresh_linux(), "uname -n": ["macmini"]}
    result = run_deploy_fake(
        deploy_software_estate_publisher, linux(), secrets({"writer": WRITER}), responses=responses
    )
    assert not result.succeeded
    assert result.executed_commands == []


# ------------------------------------------------------------------------------- macOS


def darwin_config(home: Path, **overrides: Any) -> SoftwareEstatePublisherConfig:
    name = socket.gethostname().split(".")[0].lower()
    values: dict[str, Any] = {
        "platform": "darwin",
        "hostnames": (name,),
        "endpoint": ENDPOINT,
        "policy": {"host": name, "applications": [], "application_roots": ["/Applications"]},
        "minute": 37,
        "python": sys.executable,
        "owner": os.environ.get("USER", "jochen"),
        "home": str(home),
        "directory": str(home / ".local/state/software-estate/test"),
        "credential_file": str(home / ".config/software-estate/graphyard-test.writer"),
    }
    return SoftwareEstatePublisherConfig.model_validate({**values, **overrides})


def test_darwin_rendering_is_the_roles(tmp_path: Path) -> None:
    cfg = darwin_config(tmp_path / "home")
    plist = plistlib.loads(render(cfg, "publisher.plist.j2").encode())
    assert plist["Label"] == "local.ops.software-estate"
    assert plist["StartCalendarInterval"] == {"Minute": 37}
    assert plist["ProgramArguments"][1] == f"{cfg.program}/{release_id()}/publish.py"
    assert plist["Umask"] == 63
    assert render(cfg, "run.j2") == (
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {cfg.program}/{release_id()}/publish.py "
        f'--config {cfg.program}/config.json "$@"\n'
    )
    assert sorted(json.loads(config_json(cfg))) == ["credential_file", "directory", "endpoint", "hostnames", "policy"]


def test_darwin_paths_stay_below_home(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        darwin_config(tmp_path / "home", credential_file="/etc/writer")
    with pytest.raises(ValidationError):
        linux(platform="darwin")


@pytest.fixture
def mac(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A temporary owner home and a recording launchctl/plutil on a fake root."""

    if sys.platform != "darwin":
        pytest.skip("the macOS host program runs on Darwin")
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    log = tmp_path / "launchctl.log"
    state = tmp_path / "loaded"
    return {"home": home, "log": log, "state": state}


def _host_program(
    action: str, request: str, fixture: dict[str, Any], *, owner_home: Path
) -> subprocess.CompletedProcess[str]:
    """Run darwin_host.py with launchctl, plutil, pwd and the hostname replaced."""

    source = program("darwin_host.py")
    shim = f"""
import os, pwd, subprocess, sys, types
real_run = subprocess.run
LOG, STATE = {str(fixture["log"])!r}, {str(fixture["state"])!r}
DISABLED = STATE + ".disabled"
def fake_run(argv, **kwargs):
    if argv[0] == "/usr/bin/plutil":
        return subprocess.CompletedProcess(argv, 0, "", "")
    if argv[0] != "/bin/launchctl":
        return real_run(argv, **kwargs)
    open(LOG, "a").write(" ".join(argv[1:]) + "\\n")
    verb, out, code = argv[1], "", 0
    if verb == "print":
        code = 0 if argv[2].count("/") == 1 or os.path.exists(STATE) else 113
    elif verb == "print-disabled":
        out = open(DISABLED).read() if os.path.exists(DISABLED) else ""
    elif verb == "bootout" and os.path.exists(STATE):
        os.unlink(STATE)
    elif verb == "bootstrap":
        open(STATE, "w").close()
    elif verb in ("disable", "enable"):
        open(DISABLED, "w").write('"' + argv[2].split("/")[-1] + '" => ' + verb + 'd\\n')
    return subprocess.CompletedProcess(argv, code, out, "")
subprocess.run = fake_run
def owner(name):
    return types.SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid(), pw_dir={str(owner_home)!r}, pw_name=name)
pwd.getpwnam = owner
sys.argv = ["darwin_host", {action!r}]
SOURCE = {source!r}
exec(compile(SOURCE, "<software-estate-publisher>", "exec"), {{"__name__": "__main__", "SOURCE": SOURCE}})
"""
    return subprocess.run(
        [sys.executable, "-I", "-c", shim], input=request, capture_output=True, text=True, timeout=120
    )


def _fake_python(tmp_path: Path) -> str:
    # Stands in for publish.py --check: the real publisher would contact nothing
    # in --check, but needs a writer and a policy file layout this test skips.
    script = tmp_path / "python"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    return str(script)


def test_darwin_install_status_and_removal(mac: dict[str, Any], tmp_path: Path) -> None:
    home = mac["home"]
    cfg = darwin_config(home, python=_fake_python(tmp_path))
    status = _host_program("status", darwin.darwin_request(cfg, writer=WRITER), mac, owner_home=home)
    assert (status.returncode, status.stdout.strip()) == (0, "pending"), status.stderr
    applied = _host_program("apply", darwin.darwin_request(cfg, writer=WRITER, apply=True), mac, owner_home=home)
    assert (applied.returncode, applied.stdout.strip()) == (0, "changed"), applied.stderr
    writer = Path(str(cfg.credential_file))
    assert writer.read_text() == WRITER + "\n"
    assert stat.S_IMODE(writer.stat().st_mode) == 0o600
    for path, (content, mode) in darwin.darwin_contents(cfg).items():
        assert Path(path).read_text() == content
        assert stat.S_IMODE(Path(path).stat().st_mode) == mode
    assert stat.S_IMODE(Path(cfg.plist).parent.stat().st_mode) == 0o755
    log = mac["log"].read_text().splitlines()
    assert [line.split()[0] for line in log if line.split()[0] in {"disable", "enable", "bootstrap"}] == [
        "disable",
        "enable",
        "bootstrap",
        "enable",
    ]
    again = _host_program("status", darwin.darwin_request(cfg, writer=WRITER), mac, owner_home=home)
    assert again.stdout.strip() == "current", again.stderr
    # An existing writer is never replaced.
    writer.write_text("kept\n")
    rerun = _host_program("apply", darwin.darwin_request(cfg, writer=WRITER, apply=True), mac, owner_home=home)
    assert rerun.stdout.strip() == "unchanged", rerun.stderr
    assert writer.read_text() == "kept\n"

    absent = cfg.model_copy(update={"state": "absent"})
    removed = _host_program("apply", darwin.darwin_request(absent, apply=True), mac, owner_home=home)
    assert removed.stdout.strip() == "changed", removed.stderr
    assert not Path(cfg.plist).exists()
    for kept in (cfg.config_path, cfg.program / "run", writer, Path(str(cfg.directory)) / "outbox"):
        assert Path(kept).exists()
    final = _host_program("verify", darwin.darwin_request(absent), mac, owner_home=home)
    assert (final.returncode, final.stdout.strip()) == (0, "current"), final.stderr


def test_darwin_credential_is_required_without_a_writer(mac: dict[str, Any], tmp_path: Path) -> None:
    # Studio: the deploy supplies no writer; the credential must already exist.
    home = mac["home"]
    cfg = darwin_config(home, python=_fake_python(tmp_path))
    status = _host_program("status", darwin.darwin_request(cfg), mac, owner_home=home)
    assert (status.returncode, status.stdout.strip()) == (0, "pending"), status.stderr
    applied = _host_program("apply", darwin.darwin_request(cfg, apply=True), mac, owner_home=home)
    assert applied.returncode != 0
    assert "is missing or not a private regular file" in applied.stderr
    assert not Path(cfg.plist).exists()
    verify = _host_program("verify", darwin.darwin_request(cfg), mac, owner_home=home)
    assert verify.returncode != 0
    assert "credential" in verify.stderr

    writer = Path(str(cfg.credential_file))
    writer.parent.mkdir(mode=0o700, parents=True)
    writer.parent.chmod(0o700)
    writer.write_text(WRITER + "\n")
    writer.chmod(0o600)
    applied = _host_program("apply", darwin.darwin_request(cfg, apply=True), mac, owner_home=home)
    assert (applied.returncode, applied.stdout.strip()) == (0, "changed"), applied.stderr
    verify = _host_program("verify", darwin.darwin_request(cfg), mac, owner_home=home)
    assert (verify.returncode, verify.stdout.strip()) == (0, "current"), verify.stderr

    # A deleted credential is no longer reported as current.
    writer.unlink()
    status = _host_program("status", darwin.darwin_request(cfg), mac, owner_home=home)
    assert (status.returncode, status.stdout.strip()) == (0, "pending"), status.stderr
    verify = _host_program("verify", darwin.darwin_request(cfg), mac, owner_home=home)
    assert verify.returncode != 0
    assert "credential" in verify.stderr


@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        (lambda writer: writer.chmod(0o644), "not private"),
        (lambda writer: writer.parent.chmod(0o755), "not private"),
        (lambda writer: os.link(writer, writer.with_name("copy")), "hard links"),
    ],
)
def test_darwin_verify_refuses_an_unsafe_credential(
    mac: dict[str, Any], tmp_path: Path, damage: Any, reason: str
) -> None:
    home = mac["home"]
    cfg = darwin_config(home, python=_fake_python(tmp_path))
    applied = _host_program("apply", darwin.darwin_request(cfg, writer=WRITER, apply=True), mac, owner_home=home)
    assert applied.returncode == 0, applied.stderr
    damage(Path(str(cfg.credential_file)))
    verify = _host_program("verify", darwin.darwin_request(cfg), mac, owner_home=home)
    assert verify.returncode != 0
    assert reason in verify.stderr


def test_darwin_verify_refuses_an_oversized_credential(mac: dict[str, Any], tmp_path: Path) -> None:
    home = mac["home"]
    cfg = darwin_config(home, python=_fake_python(tmp_path))
    applied = _host_program("apply", darwin.darwin_request(cfg, writer=WRITER, apply=True), mac, owner_home=home)
    assert applied.returncode == 0, applied.stderr
    Path(str(cfg.credential_file)).write_text("x" * 4097)
    verify = _host_program("verify", darwin.darwin_request(cfg), mac, owner_home=home)
    assert verify.returncode != 0
    assert "at most 4096 bytes" in verify.stderr


def test_darwin_unsafe_path_is_refused(mac: dict[str, Any], tmp_path: Path) -> None:
    home = mac["home"]
    cfg = darwin_config(home, python=_fake_python(tmp_path))
    (home / ".local").mkdir()
    (home / ".local/share").symlink_to(tmp_path)
    result = _host_program("status", darwin.darwin_request(cfg), mac, owner_home=home)
    assert result.returncode != 0
    assert "symlink" in result.stderr


def test_darwin_status_reaches_the_host_on_stdin_only() -> None:
    cfg = darwin_config(Path("/Users/owner"))
    result = run_deploy_fake(
        deploy_software_estate_publisher,
        cfg,
        secrets({"writer": WRITER}),
        responses={"darwin_host": ["pending"], "/usr/bin/python3 -I -B -c": ["pending"]},
    )
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == ["Software estate publisher | Install and load the publisher job"]
    assert WRITER not in result.all_text()
    assert any(WRITER in payload for _command, payload in result.stdin)
