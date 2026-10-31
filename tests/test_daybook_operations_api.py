"""Original defaults/rendering and protected management behavior, without target IO."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ops_deploy.services.daybook_operations_api import OperationsApiConfig, OperationsApiPins, OperationsProfile
from ops_deploy.services.daybook_operations_api.deploy import dependency_command, management_payload
from ops_deploy.services.daybook_operations_api.render import render_config, render_route, render_unit


def pins() -> OperationsApiPins:
    return OperationsApiPins(
        secret_key="a" * 40,
        database_password="b" * 40,
        signing_keys={"v1": "c" * 40},
        signing_key_id="v1",
        profiles=(
            OperationsProfile(
                name="studio-importer", host="studio", profile="voice-memo-importer", enabled=True, tokens=("d" * 40,)
            ),
        ),
    )


def config(**extra: object) -> OperationsApiConfig:
    return OperationsApiConfig(source_path=Path("/owned/export"), **extra)


def test_fresh_disabled_explicit_git_and_rsync() -> None:
    assert not config().enabled
    assert config(enabled=True).enabled
    assert OperationsApiConfig(deploy_method="git", git_revision="a" * 40).deploy_method == "git"
    with pytest.raises(ValidationError):
        OperationsApiConfig(deploy_method="git", git_revision="main")
    with pytest.raises(ValidationError):
        OperationsApiConfig()


def test_original_private_public_units_and_router_hashes() -> None:
    cfg = config(
        domain="operations.home.xn--wersdrfer-47a.de",
        allowed_networks=("100.64.0.0/10", "fd7a:115c:a1e0::/48", "192.168.178.94/32"),
    )
    assert (
        hashlib.sha256(render_unit(cfg, "api").encode()).hexdigest()
        == "00ac35bb1dfb3d36d14c19ef4d9809990277fbac3bb4ab11c2589f7e50a2c8c0"
    )
    assert (
        hashlib.sha256(render_unit(cfg, "reconcile").encode()).hexdigest()
        == "d12625b995cd1b72bbbabd4151fb1bc262a1b87f94febe5deb7eec0e127f8fa0"
    )
    assert (
        hashlib.sha256(render_route(cfg).encode()).hexdigest()
        == "14e1e706af883667ee267ba3bf7916c350def2352eb9a118441ccf9914d84d76"
    )


def test_original_four_configs_and_distinct_shell_environment() -> None:
    result = render_config(config(), pins())
    assert set(result) == {"environment", "environment.shell", "profiles.json", "lifecycle.json"}
    assert b"OPERATIONS_RECORD_LIMIT=100000\n" in result["environment"].reveal()
    assert b'OPERATIONS_CAPACITY_WARN_DAYS="30"\n' in result["environment.shell"].reveal()
    profile = json.loads(result["profiles.json"].reveal())[0]
    assert set(profile) == {"schema", "name", "host", "profile", "enabled", "tokens", "monitor_tokens"}
    assert profile["schema"] == 4
    assert "sources" not in profile
    assert json.loads(result["lifecycle.json"].reveal())["backup_root"] == "/opt/backups/daybook_operations"


@pytest.mark.parametrize(
    "change",
    [
        {"storage_sample_max_age": 2},
        {"capacity_warn_utilization": 0.9},
        {"capacity_critical_days": 31},
        {"port": 1024},
        {"allowed_networks": ()},
    ],
)
def test_original_invalid_thresholds(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        config(**change)


def test_profile_schema_purpose_and_secret_validation() -> None:
    original = dict(
        name="studio-importer", host="studio", profile="voice-memo-importer", enabled=True, tokens=("d" * 40,)
    )
    invalid: tuple[dict[str, object], ...] = (
        {"schema": True},
        {"schema": 3},
        {"sources": []},
        {"monitor_tokens": ("d" * 40,)},
        {"enabled": "true"},
    )
    for extra in invalid:
        with pytest.raises(ValidationError):
            OperationsProfile.model_validate(original | extra)
    assert "d" * 40 not in repr(OperationsProfile.model_validate(original))
    valid = pins().model_dump(by_alias=True)
    assert OperationsApiPins.model_validate(valid).signing_key_id == "v1"
    with pytest.raises(ValidationError, match="Selected signing key must exist"):
        OperationsApiPins.model_validate(valid | {"signing_key_id": "missing"})


def test_original_dependency_group_and_separate_venv() -> None:
    cfg = config()
    actual = dependency_command(cfg, check=False)
    assert "--frozen --no-dev --group operations-api --python 3.14" in actual
    assert "/home/daybook-operations/venv" in actual
    assert "--check --offline --no-cache --no-python-downloads" in dependency_command(cfg, check=True)


def helper() -> ModuleType:
    file = Path(__file__).parents[1] / "src/ops_deploy/services/daybook_operations_api/files/management_host.py"
    spec = importlib.util.spec_from_file_location("operations_management_owned", file)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(("action", "changed"), [("migrate", True), ("provision", False)])
def test_genuine_management_command_and_private_shell_source(action: str, changed: bool) -> None:
    module = helper()
    stdout = b"Applying coordination.0001_initial... OK\n" if changed else b"Profiles reconciled\n"
    with patch.object(
        module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")
    ) as run:
        result = module.run(json.loads(management_payload(config(), action).reveal()))
    assert result["ok"]
    assert result["original_changed"] is changed
    argv = run.call_args.args[0]
    assert argv[:5] == ["/usr/sbin/runuser", "-u", "daybook-operations", "--", "/bin/sh"]
    assert ". /etc/daybook-operations/environment.shell" in argv[-1]
    assert (
        "migrate --noinput" in argv[-1]
        if action == "migrate"
        else "provision_operations /etc/daybook-operations/profiles.json" in argv[-1]
    )
    assert "env" not in run.call_args.kwargs


def test_management_failure_never_exports_private_output() -> None:
    module = helper()
    for raw, category in [
        (b"PRIVATE_DATABASE_URL secret traceback", "management_command_failed"),
        (b"PRIVATE operations_storage_unavailable", "operations_storage_unavailable"),
    ]:
        with patch.object(
            module.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"PRIVATE", stderr=raw)
        ):
            result = module.run(json.loads(management_payload(config(), "provision").reveal()))
        assert not result["ok"]
        assert result["category"] == category
        assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("drift", ["none", "source", "dependencies", "ownership", "configuration"])
def test_actual_sdk_existing_repeat_keeps_explicit_state_and_genuine_management(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool, drift: str
) -> None:
    import importlib

    from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake
    from tests import fakehost

    backend = importlib.import_module("ops_deploy.services.daybook_operations_api.deploy")
    cfg = OperationsApiConfig(source_path=tmp_path, enabled=enabled)
    private = pins()
    dependency_calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        backend, "deploy_postgres_install", lambda **kwargs: dependency_calls.append(("postgres", kwargs))
    )
    monkeypatch.setattr(backend, "deploy_uv_install", lambda **kwargs: dependency_calls.append(("uv", kwargs)))
    responses = {**fakehost.LINUX, **fakehost.system_account(cfg.user, cfg.home, shell="/usr/sbin/nologin")}
    for path, mode in (
        (cfg.home, "drwxr-x---"),
        (str(cfg.site_path), "drwxr-x---"),
        (cfg.config_dir, "drwxr-x---"),
        (cfg.backup_root, "drwx------"),
    ):
        responses.update(fakehost.directory(path, user=cfg.user, mode=mode))
    for parent in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(parent))
    for name, content in render_config(cfg, private).items():
        responses.update(
            fakehost.file(cfg.config_dir + "/" + name, content.reveal().decode(), user=cfg.user, mode="-rw-------")
        )
    for kind in ("api", "reconcile"):
        name = "daybook-operations" + ("-reconcile" if kind == "reconcile" else "")
        responses.update(fakehost.file("/etc/systemd/system/" + name + ".service", render_unit(cfg, kind)))
        responses.update(fakehost.service(name + ".service", running=enabled, enabled=enabled))
    responses.update(fakehost.file(cfg.traefik_path, render_route(cfg)))
    responses["if " + dependency_command(cfg, check=True)] = ["current"]
    responses[backend.source_ownership_command(cfg, check=True)] = ["current"]
    rsync = RecordingRsyncRunner()
    if drift == "source":
        rsync = RecordingRsyncRunner({"--dry-run": [">fcs....... src/daybook/operations_protocol.py"]})
    elif drift == "dependencies":
        responses["if " + dependency_command(cfg, check=True)] = ["pending"]
    elif drift == "ownership":
        responses[backend.source_ownership_command(cfg, check=True)] = ["pending"]
    elif drift == "configuration":
        responses.update(fakehost.file(cfg.config_dir + "/environment", "OLD", user=cfg.user, mode="-rw-------"))
    run = run_deploy_fake(backend.deploy_daybook_operations_api, cfg, pins=private, rsync=rsync, responses=responses)
    assert run.succeeded, run.error
    assert [name for name, _ in dependency_calls] == ["postgres", "uv"]
    assert dependency_calls[0][1]["cfg"] == cfg.postgres
    management = [(command, json.loads(stdin)) for command, stdin in run.stdin if "<operations-management>" in command]
    assert [value["action"] for _, value in management] == ["migrate", "provision"]
    restarts = [command for command in run.executed_commands if "systemctl restart" in command]
    assert len(restarts) == (2 if enabled and drift in {"source", "dependencies", "configuration"} else 0)
    assert not any("systemctl stop" in command for command in run.executed_commands)
    assert not any("systemctl start" in command for command in run.executed_commands)
    if drift != "configuration":
        assert not run.uploads
    for secret in ("a" * 40, "b" * 40, "c" * 40, "d" * 40):
        assert secret not in repr(run.ops)
    changed = [name.rsplit(" | ", 1)[-1] for name in run.mutating_changed_ops]
    assert changed.count("Operations API migrate") == changed.count("Operations API provision") == 1
    if drift == "none":
        assert changed == ["Operations API migrate", "Operations API provision"], changed
    if drift == "source":
        assert len(rsync.calls) == 2
        assert "--dry-run" not in rsync.calls[-1]
        assert "Sync Operations API frozen dependencies" in changed
    if drift == "ownership":
        assert "Set original source ownership" in changed
        assert not any(row == "Sync Operations API frozen dependencies" for row in changed)


def test_source_ownership_checks_descendants_without_exporting_paths(tmp_path: Path) -> None:
    import grp
    import os
    import pwd
    import subprocess

    from ops_deploy.services.daybook_operations_api.deploy import source_ownership_command

    user = pwd.getpwuid(os.getuid()).pw_name
    try:
        grp.getgrnam(user)
    except KeyError:
        user = "daemon"  # macOS owner has no same-named primary group
    owned = tmp_path / "site"
    owned.mkdir()
    private = owned / "private-name-must-not-export"
    private.write_text("unread private body")
    cfg = config(user=user, site=str(owned))
    result = subprocess.run(
        ["/bin/sh", "-c", source_ownership_command(cfg, check=True)], capture_output=True, check=True
    )
    expected = (
        b"current\n"
        if private.stat().st_uid == pwd.getpwnam(user).pw_uid and grp.getgrgid(private.stat().st_gid).gr_name == user
        else b"pending\n"
    )
    assert result.stdout == expected
    assert not result.stderr
    assert private.read_text() == "unread private body"
    assert str(private).encode() not in result.stdout


def test_real_shell_companion_preserves_json_and_private_values(tmp_path: Path) -> None:
    import shlex
    import subprocess
    import sys

    private = pins()
    target = tmp_path / "environment.shell"
    target.write_bytes(render_config(config(), private)["environment.shell"].reveal())
    target.chmod(0o600)
    code = (
        "import json,os;print(json.dumps({"
        "'secret':os.environ['OPERATIONS_SECRET_KEY'],"
        "'keys':json.loads(os.environ['OPERATIONS_SIGNING_KEYS'])}))"
    )
    result = subprocess.run(
        [
            "/bin/sh",
            "-c",
            "set -a; . "
            + shlex.quote(str(target))
            + "; set +a; exec "
            + shlex.join([sys.executable, "-I", "-c", code]),
        ],
        capture_output=True,
        check=True,
    )
    assert json.loads(result.stdout) == {"secret": "a" * 40, "keys": {"v1": "c" * 40}}
    assert not result.stderr
