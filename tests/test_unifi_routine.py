"""Routine selection, safe Mongo configuration and initialized-install updates."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.unifi import UnifiConfig, UnifiRoutine
from ops_deploy.services.unifi.deploy import payload
from ops_deploy.services.unifi.routine import HA, MONGO
from tests.test_unifi import CFG, SECRETS, host_module, mongodb_state

SELECTION = {
    "package_version": "9.5.21-31260-1",
    "package_url": "https://dl.ui.com/unifi/9.5.21/unifi_sysvinit_all.deb",
    "package_sha256": "7da1cc9ab1ae0c8f302c242d622ee52f867457a69116b2aa4c13812e756986af",
}
CONFIG = """storage:
  dbPath: /var/lib/mongodb
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  quiet: true
  verbosity: 0
net:
  port: 27017
  bindIp: 127.0.0.1
security:
  authorization: enabled
setParameter:
  suppressNoTLSPeerCertificateWarning: true
  diagnosticDataCollectionEnabled: false
"""


def mongo_module() -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/unifi/files/mongo_config.py"
    spec = importlib.util.spec_from_file_location("mongo_config", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_selected_artifact_payload_keeps_initialized_auth_admission() -> None:
    cfg = UnifiConfig(**{**CFG.model_dump(), "routine": UnifiRoutine(**SELECTION)})
    data = json.loads(payload(cfg, SECRETS))
    assert data["routine"] is True
    state = mongodb_state()
    state["opts"]["systemLog"]["quiet"] = False
    host_module().check_mongodb_state(state, data)
    state["opts"]["security"]["authorization"] = "disabled"
    with pytest.raises(ValueError, match="mongodb_auth"):
        host_module().check_mongodb_state(state, data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("package_url", "http://dl.ui.com/unifi/9.5.21/unifi_sysvinit_all.deb"),
        ("package_url", "https://example.com/package.deb"),
        ("package_version", "latest"),
        ("package_sha256", "unverified"),
    ],
)
def test_selection_requires_explicit_vendor_artifact(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        UnifiRoutine(**{**SELECTION, field: value})


def test_package_url_release_must_match_full_version() -> None:
    with pytest.raises(ValidationError):
        UnifiConfig(**{**CFG.model_dump(), "routine": {**SELECTION, "package_version": "9.4.19-31042-1"}})


def test_mongo_config_retains_storage_auth_and_unknown_settings() -> None:
    module = mongo_module()
    source = CONFIG.replace("quiet: true", "quiet: false").replace("verbosity: 0", "verbosity: 2")
    source += "replication:\n  replSetName: retain-me\n"
    expected = CONFIG + "replication:\n  replSetName: retain-me\n"
    assert module.desired(source) == expected
    assert module.desired(expected) == expected


@pytest.mark.parametrize(
    "source",
    [
        CONFIG.replace("authorization: enabled", "authorization: disabled"),
        CONFIG.replace("bindIp: 127.0.0.1", "bindIp: 0.0.0.0"),
        CONFIG + "security:\n  authorization: enabled\n",
        CONFIG.replace("quiet: true", "quiet: true\n  quiet: false"),
    ],
)
def test_unsafe_ambiguous_config_refuses(source: str) -> None:
    with pytest.raises(ValueError, match="MongoDB"):
        mongo_module().desired(source)


def test_mongo_missing_owned_fields_insert_in_correct_section() -> None:
    result = mongo_module().desired(CONFIG.replace("  quiet: true\n", "").replace("  verbosity: 0\n", ""))
    import yaml

    data = yaml.safe_load(result)
    assert data["systemLog"]["quiet"] is True
    assert data["systemLog"]["verbosity"] == 0
    assert data["security"] == {"authorization": "enabled"}


def test_ha_repair_preserves_id_and_supports_both_foreign_key_types() -> None:
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(HA.split("\ntry:\n    ha_main")[0], namespace)
    data = json.loads(payload(CFG, SECRETS))
    data.update(create_homeassistant_user=True, homeassistant_password="fixture")
    script = namespace["ha_javascript"](data, "$6$fixture")
    assert "user._id.toString()" in script
    assert "site._id.toString()" in script
    assert "updateMany(query" in script
    assert "drop" not in script
    state = mongodb_state()
    assert namespace["ha_pending"](state, data) is True
    state["ha"] = {"x_shadow": "irrelevant"}
    namespace["matches_password"] = lambda *_: True
    state["privileges"] = [{"role": "readonly", "permissions": []}]
    assert namespace["ha_pending"](state, data) is False
    state["privileges"].append({"role": "admin", "permissions": []})
    assert namespace["ha_pending"](state, data) is True
    assert "authorization: disabled" not in MONGO + HA


def test_mongo_eof_and_whitespace_headers_do_not_duplicate_or_skip_fields() -> None:
    module = mongo_module()
    import yaml

    source = CONFIG.rstrip("\n").replace(
        "diagnosticDataCollectionEnabled: false", "diagnosticDataCollectionEnabled: true"
    )
    result = module.desired(source)
    assert result.count("diagnosticDataCollectionEnabled:") == 1
    assert yaml.safe_load(result)["setParameter"]["diagnosticDataCollectionEnabled"] is False
    assert module.desired(result) == result
    source = CONFIG.replace("systemLog:\n", "systemLog:   \n").replace("  quiet: true\n", "")
    assert yaml.safe_load(module.desired(source))["systemLog"]["quiet"] is True


def test_fixture_existing_account_guard_stops_before_provisioning(tmp_path: Path) -> None:
    import os
    import subprocess

    for name, body in {
        "id": 'if [ "$1" = -u ]; then echo 0; fi; exit 0',
        "ps": "echo systemd",
        "uname": "echo x86_64",
    }.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
    script = Path(__file__).parent / "integration/unifi_routine/run.sh"
    result = subprocess.run(
        ["/bin/bash", str(script)],
        text=True,
        capture_output=True,
        env={
            "PATH": f"{tmp_path}:/bin",
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "IMPLEMENTATION_SHA": "a" * 40,
            "HARNESS_SHA": "b" * 40,
            "GITHUB_RUN_ID": "123",
            "HOME": os.environ["HOME"],
        },
    )
    assert result.returncode == 1
    assert "Refusing existing UniFi account" in result.stderr


def installer_module() -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/unifi/files/install_package.py"
    spec = importlib.util.spec_from_file_location("install_package", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("failure", ["digest", "metadata", "downgrade"])
def test_installer_refuses_before_stop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    import hashlib
    from types import SimpleNamespace

    module = installer_module()
    package = tmp_path / "fixture.deb"
    package.write_bytes(b"fixture artifact")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    calls = []

    def run(args: list[str], **kwargs: Any) -> Any:
        calls.append(args)
        if args[0] == "dpkg-query":
            return SimpleNamespace(returncode=0, stdout="9.5.21-31260-1")
        if args[0] == "dpkg":
            return SimpleNamespace(returncode=0)
        raise AssertionError("must refuse before service/package mutation")

    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(
        module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: (
            "Package: "
            + ("wrong" if failure == "metadata" else "unifi")
            + "\nVersion: 9.4.19-31042-1\nArchitecture: all\n"
        ),
    )
    with pytest.raises(
        ValueError, match={"digest": "digest", "metadata": "metadata", "downgrade": "downgrade"}[failure]
    ):
        module.main(str(package), "9.4.19-31042-1", "0" * 64 if failure == "digest" else digest)
    assert all(call[0] not in {"systemctl", "apt-get"} for call in calls)


def test_routine_downgrade_refuses_in_read_only_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    module = host_module()
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path: "systemd" if str(path) == "/proc/1/comm" else "ID=ubuntu\nVERSION_CODENAME=noble",
    )
    calls = []

    def run(args: list[str], **kwargs: Any) -> str:
        calls.append(args)
        if args[0] == "uname":
            return "x86_64"
        if args[0] == "ip":
            return "src 10.2.3.4"
        assert args[0] == "dpkg-query"
        return "ii |9.5.21-31260-1"

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    data = json.loads(payload(CFG, SECRETS))
    data.update(routine=True, selected_package_version="9.4.19-31042-1")
    with pytest.raises(ValueError, match="controller_downgrade"):
        module.check(data)
    assert calls[-1][0] == "dpkg-query"


@pytest.mark.parametrize("case", ["missing-runtime", "leftover", "wrong-os", "failed-query"])
def test_initialized_database_runtime_admission_branches(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    import subprocess

    module = host_module()
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path: (
            "systemd"
            if str(path) == "/proc/1/comm"
            else "ID=ubuntu\nVERSION_CODENAME=" + ("jammy" if case == "wrong-os" else "noble")
        ),
    )
    monkeypatch.setattr(Path, "is_file", lambda _: False)
    monkeypatch.setattr(Path, "is_symlink", lambda _: False)
    monkeypatch.setattr(Path, "exists", lambda path: case == "leftover" and str(path) == "/var/lib/unifi")

    def missing_user(name: str) -> Any:
        raise KeyError(name)

    def run(args: list[str], **kwargs: Any) -> str:
        if args[0] == "uname":
            return "x86_64"
        if args[0] == "ip":
            return "src 10.2.3.4"
        if args[0] == "dpkg-query":
            raise subprocess.CalledProcessError(2 if case == "failed-query" else 1, args, output="")
        if args[:2] == ["systemctl", "is-active"]:
            return "active"
        if args[:2] == ["systemctl", "is-enabled"]:
            return "enabled"
        if args[:2] == ["systemctl", "show"]:
            return "Mon 2026-10-26 12:00:00.000000 UTC"
        raise AssertionError(args)

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module.pwd, "getpwnam", missing_user)
    monkeypatch.setattr(module, "mongodb_state", lambda _: mongodb_state())
    data = json.loads(payload(CFG, SECRETS))
    data.update(routine=True, manage_firewall=False)
    if case == "missing-runtime":
        module.check(data)
    else:
        reason = {
            "leftover": "unpackaged_controller_data",
            "wrong-os": "routine_requires",
            "failed-query": "package_query_failed",
        }[case]
        with pytest.raises(ValueError, match=reason):
            module.check(data)


def test_mongo_comments_nested_options_and_duplicate_headers() -> None:
    import yaml

    source = CONFIG.replace("  quiet: true", "  # Keep existing comments\n  quiet: false")
    source = source.replace("net:\n", "  component:\n    accessControl:\n      verbosity: 1\nnet:\n")
    result = mongo_module().desired(source)
    assert "  # Keep existing comments" in result
    assert yaml.safe_load(result)["systemLog"]["component"] == {"accessControl": {"verbosity": 1}}
    assert yaml.safe_load(result)["systemLog"]["quiet"] is True
    with pytest.raises(ValueError, match="duplicate MongoDB section"):
        mongo_module().desired(CONFIG + "setParameter:\n  diagnosticDataCollectionEnabled: true\n")


@pytest.mark.parametrize("failure", ["missing", "digest", "metadata"])
def test_verified_installer_failure_retry_leaves_data_absent_until_package_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    import hashlib
    import os
    from types import SimpleNamespace

    module = installer_module()
    data = tmp_path / "data"
    monkeypatch.setattr(module, "DATA", data)
    monkeypatch.setattr(module.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    package = tmp_path / "fixture.deb"
    version = "9.5.21-31260-1"
    package.write_bytes(b"verified fixture")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    metadata_valid = failure != "metadata"
    events: list[str] = []

    def output(args: list[str], **kwargs: Any) -> str:
        if args[0] == "dpkg-deb":
            return f"Package: {'unifi' if metadata_valid else 'other'}\nVersion: {version}\nArchitecture: all\n"
        assert args[0] == "dpkg-query"
        return "ii |" + version

    def run(args: list[str], **kwargs: Any) -> Any:
        if args[0] == "dpkg-query":
            return SimpleNamespace(returncode=1, stdout="")
        if args[0] == "systemctl":
            assert not data.exists()
            events.append("stop")
        elif args[0] == "apt-get":
            config = data / "system.properties"
            text = config.read_text()
            assert config.stat().st_mode & 0o7777 == 0o600
            assert "db.mongo.local=false\n" in text
            assert "db.mongo.uri=mongodb://unifi:fixture@127.0.0.1:27017/unifi?authSource=admin\n" in text
            assert "statdb.mongo.uri=mongodb://unifi:fixture@127.0.0.1:27017/unifi_stat?authSource=admin\n" in text
            events.append("install")
        else:
            raise AssertionError(args)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "check_output", output)
    monkeypatch.setattr(module.subprocess, "run", run)
    initial = {"initialize": True, "mongodb_password": "fixture"}
    if failure == "missing":
        package.unlink()
    with pytest.raises(ValueError, match=r"package (file|digest|metadata)"):
        module.main(str(package), version, "0" * 64 if failure == "digest" else digest, initial)
    assert not data.exists()
    assert events == []
    # Retry through the production installer entry, not just its initializer.
    metadata_valid = True
    package.write_bytes(b"verified fixture")
    module.main(str(package), version, digest, initial)
    assert events == ["stop", "install"]


def test_installer_existing_controller_never_rewrites_database_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib
    from types import SimpleNamespace

    module = installer_module()
    data = tmp_path / "data"
    data.mkdir()
    config = data / "system.properties"
    config.write_text("existing private database selection\n")
    before = config.read_bytes()
    monkeypatch.setattr(module, "DATA", data)
    package = tmp_path / "fixture.deb"
    package.write_bytes(b"fixture")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    version = "9.5.21-31260-1"
    monkeypatch.setattr(
        module.subprocess,
        "check_output",
        lambda args, **_: (
            f"Package: unifi\nVersion: {version}\nArchitecture: all\n" if args[0] == "dpkg-deb" else "ii |" + version
        ),
    )
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda args, **_: SimpleNamespace(
            returncode=1 if args[0] == "dpkg" else 0,
            stdout="9.4.19-31042-1" if args[0] == "dpkg-query" else "",
        ),
    )
    module.main(str(package), version, digest, {"initialize": False})
    assert config.read_bytes() == before
    with pytest.raises(ValueError, match="appeared after admission"):
        module.main(str(package), version, digest, {"initialize": True, "mongodb_password": "fixture"})
    assert config.read_bytes() == before


@pytest.mark.parametrize("missing_controller", [False, True])
def test_normal_deploy_transports_initialization_only_for_absent_controller(
    monkeypatch: pytest.MonkeyPatch,
    missing_controller: bool,
) -> None:
    from ops_deploy.services.unifi import deploy_unifi, routine
    from ops_deploy.testing import run_deploy_fake
    from tests.test_unifi import SENTINEL, converged

    # Keep deploy_unifi -> install_selected -> secret_stdin intact. Only isolate
    # package presence and HA preparation, unrelated to installer transport.
    monkeypatch.setattr(routine, "prepare_routine", lambda *_: (True, missing_controller))
    monkeypatch.setattr(routine, "reconcile_ha", lambda **_: None)
    cfg = UnifiConfig(**{**CFG.model_dump(), "routine": SELECTION})
    run = run_deploy_fake(deploy_unifi, cfg, SECRETS, responses=converged())
    assert run.succeeded, run.error
    [(_, stdin)] = [(command, value) for command, value in run.stdin if "Verified local package install" in command]
    assert json.loads(stdin) == {
        "initialize": missing_controller,
        "mongodb_password": SENTINEL if missing_controller else "",
    }
    assert not any(SENTINEL in command for command in run.executed_commands + run.fact_commands)
