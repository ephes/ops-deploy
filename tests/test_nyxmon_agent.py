"""The monitoring agent switch (the role's agent_rust.yml and agent_verify.yml) against the fake connector."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.nyxmon import NyxmonConfig, deploy_nyxmon
from ops_deploy.services.nyxmon.agent import _agent
from ops_deploy.services.nyxmon.deploy import TEMPLATE_PACKAGE
from ops_deploy.testing import FakeRun, fish_unsafe, run_deploy_fake
from tests import fakehost
from tests.nyxmon_fixtures import make_source
from tests.test_nyxmon import SECRET_VALUES, converged, deploy

SHA = "b5ea97633a77d3297ef93991d6db38475f37995fae654cea995e7050ae998305"
OTHER_SHA = "0" * 64
ROOT = "/opt/nyxmon-agent"
DROPIN = "/etc/systemd/system/nyxmon-monitor.service.d/agent-impl.conf"
URL = "https://github.com/ephes/nyxmon/releases/download/agent-rs-v0.1.0/nyxmon-agent-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
PRUNE_PROBE = f"nyxmon-agent prune {ROOT} 0.1.0 nyxmon-monitor 3 --dry-run"
PYTHON_CHECK = "Deploy nyxmon | Check nyxmon-monitor runs the Python agent"
RUST_CHECK = "Deploy nyxmon | Check nyxmon-monitor runs the Rust agent"
VALIDATE = "Deploy nyxmon | Validate nyxmon-agent 0.1.0"
SELECT_RUST = "Deploy nyxmon | Select the Rust agent for nyxmon-monitor"
SELECT_PYTHON = "Deploy nyxmon | Select the Python agent for nyxmon-monitor"
RELOAD = "Deploy nyxmon | Reload systemd for nyxmon-monitor.service"
RESTART = "Deploy nyxmon | Restart nyxmon-monitor.service"
PRUNE = "Deploy nyxmon | Prune old Rust agent versions"
REMEMBER = "Deploy nyxmon | Remember the previously selected Rust agent"


def make(tmp_path: Path, **agent: Any) -> tuple[NyxmonConfig, SecretValues]:
    ref = SecretRef("secrets/prod/nyxmon.yml")
    cfg = NyxmonConfig(
        source_path=make_source(tmp_path), secrets=ref, opsgate_submit_base_url="http://studio.example:8711", **agent
    )
    return cfg, SecretValues(ref, SECRET_VALUES)


def rust(tmp_path: Path, version: str = "0.1.0", **agent: Any) -> tuple[NyxmonConfig, SecretValues]:
    return make(tmp_path, agent_impl="rust", agent_rust_version=version, agent_rust_sha256=SHA, **agent)


def dropin(cfg: NyxmonConfig) -> str:
    return render(TEMPLATE_PACKAGE, "agent-impl.conf.j2", cfg=cfg)


def installed(*versions: str, sha256: str = SHA) -> dict[str, Any]:
    """Facts of a host with these Rust agent versions below the install root."""

    responses: dict[str, Any] = {**fakehost.directory(ROOT)}
    for version in versions:
        responses.update(fakehost.directory(f"{ROOT}/{version}"))
        responses.update(fakehost.file(f"{ROOT}/{version}/.archive-sha256", f"{sha256}\n"))
    return responses


def host(cfg: NyxmonConfig, secrets: SecretValues, *versions: str, selected: str | None = None) -> dict[str, Any]:
    """A deployed host: ``versions`` installed, the drop-in selecting ``selected`` (``None``: no drop-in)."""

    responses = {**converged(cfg, secrets), **installed(*versions)}
    if selected is None:
        return responses
    # First: the fake connector answers with the first key contained in a
    # command, and ``cat <unit>`` is contained in ``cat <unit>.d/agent-impl.conf``.
    return {**selected_dropin(cfg, selected), **responses}


def selected_dropin(cfg: NyxmonConfig, version: str) -> dict[str, Any]:
    return fakehost.file(DROPIN, dropin(cfg.model_copy(update={"agent_rust_version": version})))


def read_only(run: FakeRun) -> list[str]:
    return [op.name for op in run.ops if op.read_only]


# -- configuration (the role's "Validate monitoring agent implementation settings") --


def test_defaults_follow_the_role(tmp_path: Path) -> None:
    cfg, _ = make(tmp_path)

    assert (cfg.agent_impl, cfg.agent_rust_version, cfg.agent_rust_sha256) == ("python", "", "")
    assert (cfg.agent_rust_install_root, cfg.agent_rust_keep_versions) == (ROOT, 3)
    assert cfg.agent_rust_local_archive is None
    assert cfg.model_copy(update={"agent_rust_version": "0.1.0"}).agent_rust_url == URL


@pytest.mark.parametrize("entry", ["model_validate_json", "model_validate_strings"])
def test_agent_settings_validate_from_text(tmp_path: Path, entry: str) -> None:
    data = {
        "source_path": str(make_source(tmp_path)),
        "secrets": {"path": "secrets/prod/nyxmon.yml"},
        "agent_impl": "rust",
        "agent_rust_version": "0.1.0",
        "agent_rust_sha256": SHA,
        "agent_rust_keep_versions": "2",
    }
    text = json.dumps(data) if entry == "model_validate_json" else data

    cfg = getattr(NyxmonConfig, entry)(text)

    assert (cfg.agent_impl, cfg.agent_rust_binary, cfg.agent_rust_keep_versions) == (
        "rust",
        f"{ROOT}/0.1.0/nyxmon-agent",
        2,
    )


@pytest.mark.parametrize(
    ("agent", "message"),
    [
        ({"agent_impl": "rust"}, "agent_impl rust needs agent_rust_version"),
        ({"agent_impl": "Rust"}, "agent_impl"),
        ({"agent_impl": ""}, "agent_impl"),
        ({"agent_rust_version": "0.1.0"}, "needs agent_rust_sha256"),
        ({"agent_rust_sha256": SHA}, "need agent_rust_version"),
        ({"agent_rust_version": "0.1", "agent_rust_sha256": SHA}, "agent_rust_version"),
        ({"agent_rust_version": "v0.1.0", "agent_rust_sha256": SHA}, "agent_rust_version"),
        ({"agent_rust_version": "0.1.0", "agent_rust_sha256": SHA.upper()}, "agent_rust_sha256"),
        ({"agent_rust_version": "0.1.0", "agent_rust_sha256": SHA[:-1]}, "agent_rust_sha256"),
        ({"agent_rust_install_root": "/"}, "agent_rust_install_root"),
        ({"agent_rust_install_root": "/opt/nyxmon-agent/"}, "agent_rust_install_root"),
        ({"agent_rust_install_root": "opt/nyxmon-agent"}, "agent_rust_install_root"),
        ({"agent_rust_keep_versions": 0}, "agent_rust_keep_versions"),
        ({"agent_rust_keep_versions": True}, "whole number"),
        ({"agent_rust_keep_versions": 1.0}, "whole number"),
        ({"agent_rust_keep_versions": "1.5"}, "whole number"),
        ({"agent_rust_keep_versions": -1}, "whole number"),
        ({"agent_rust_release_url": "https://x/{commit}.tar.gz"}, "no placeholder but"),
        ({"agent_rust_release_url": "ftp://x/{version}.tar.gz"}, "http"),
        ({"agent_rust_release_url": "https://x/$(id)/{version}"}, "http"),
    ],
)
def test_invalid_agent_settings_are_refused(tmp_path: Path, agent: dict[str, Any], message: str) -> None:
    with pytest.raises((ConfigValidationError, ValueError), match=message):
        make(tmp_path, **agent)


def test_local_archive_needs_a_version_and_a_file(tmp_path: Path) -> None:
    archive = tmp_path / "agent.tar.gz"
    archive.write_bytes(b"archive")
    with pytest.raises((ConfigValidationError, ValueError), match="need agent_rust_version"):
        make(tmp_path, agent_rust_local_archive=archive)
    with pytest.raises((ConfigValidationError, ValueError), match="is not a file"):
        make(tmp_path, agent_rust_version="0.1.0", agent_rust_local_archive=tmp_path / "missing.tar.gz")


# -- deploys -------------------------------------------------------------------


def test_python_without_a_pin_installs_nothing(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path)

    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert not any(ROOT in command for command in run.executed_commands if "Prune" in command or "install" in command)
    assert PRUNE not in [op.name for op in run.ops]
    assert PYTHON_CHECK in read_only(run)


def test_pinned_version_is_installed_without_switching(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path, agent_rust_version="0.1.0", agent_rust_sha256=SHA)

    run = deploy(cfg, secrets, converged(cfg, secrets))

    # Installed ahead of the switch (impl python): no drop-in, no restart.
    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Create the Rust agent install root",
        "Deploy nyxmon | Install nyxmon-agent 0.1.0",
        PRUNE,
    ]
    install = next(c for c in run.executed_commands if "nyxmon-agent install" in c)
    assert f"nyxmon-agent install {ROOT} 0.1.0 {SHA} {URL} nyxmon /home/nyxmon/site/db.sqlite3 ''" in install
    assert not any(DROPIN in path for path in run.uploaded_paths)
    assert PYTHON_CHECK in read_only(run)


def test_first_rust_deploy_installs_after_the_migrations_and_starts_the_rust_agent(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)

    run = deploy(cfg, secrets)

    commands = run.executed_commands
    migrate = next(c for c in commands if "manage.py migrate" in c)
    install = next(c for c in commands if "nyxmon-agent install" in c)
    assert commands.index(migrate) < commands.index(install) < commands.index("systemctl start nyxmon-monitor.service")
    assert f"{ROOT}/0.1.0/nyxmon-agent --db" in run.upload(DROPIN).decode()
    # Started with the drop-in in place: no restart right after the start.
    assert "systemctl restart nyxmon-monitor.service" not in commands
    assert RUST_CHECK in read_only(run)
    assert PRUNE in run.mutating_changed_ops


def test_converged_python_with_a_pin_changes_nothing(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path, agent_rust_version="0.1.0", agent_rust_sha256=SHA)

    run = deploy(cfg, secrets, host(cfg, secrets, "0.1.0"))

    assert run.mutating_changed_ops == []
    assert VALIDATE in read_only(run)
    assert PYTHON_CHECK in read_only(run)
    assert run.uploads == []
    assert run.stdin == []


def test_converged_rust_changes_nothing(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)

    run = deploy(cfg, secrets, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    assert run.mutating_changed_ops == []
    assert read_only(run) == [
        VALIDATE,
        "Deploy nyxmon | Wait for port 127.0.0.1:10017",
        "Deploy nyxmon | Check http://127.0.0.1:10017/",
        RUST_CHECK,
        "Deploy nyxmon | Check nyxmon-monitor OpsGate settings",
    ]
    assert not any(c.startswith("systemctl") for c in run.executed_commands)
    validate = next(c for c in run.executed_commands if "nyxmon-agent validate" in c)
    assert f"nyxmon-agent validate {ROOT} 0.1.0 nyxmon /home/nyxmon/site/db.sqlite3" in validate


def test_switch_python_to_rust_writes_the_dropin_and_restarts_the_monitor(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)

    run = deploy(cfg, secrets, host(cfg, secrets, "0.1.0"))

    assert run.mutating_changed_ops == [SELECT_RUST, RELOAD, RESTART, PRUNE]
    assert run.upload(DROPIN).decode() == (
        "# Managed by Ansible (nyxmon_deploy): nyxmon_agent_impl=rust.\n"
        "# Removed when nyxmon_agent_impl=python; the base unit then runs the venv\n"
        "# start-agent again.\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={ROOT}/0.1.0/nyxmon-agent --db /home/nyxmon/site/db.sqlite3 --enable-telegram\n"
    )
    assert "systemctl restart nyxmon.service" not in run.executed_commands
    check = next(c for c in run.executed_commands if "is-active" in c and "readlink" in c)
    assert f"= {ROOT}/0.1.0/nyxmon-agent ]" in check
    commands = run.executed_commands
    assert commands.index("systemctl restart nyxmon-monitor.service") < commands.index(check)
    prune = next(c for c in commands if "nyxmon-agent prune" in c)
    assert commands.index(check) < commands.index(prune)


def test_switch_rust_to_python_removes_the_dropin_and_keeps_the_version(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path, agent_rust_version="0.1.0", agent_rust_sha256=SHA)

    run = deploy(cfg, secrets, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    # The documented rollback: the drop-in goes, the binary stays as the rollback target.
    assert run.mutating_changed_ops == [SELECT_PYTHON, REMEMBER, RELOAD, RESTART, PRUNE]
    assert f"rm -f {DROPIN}" in run.executed_commands
    assert run.upload(f"{ROOT}/.previous-version") == b"0.1.0\n"
    assert PYTHON_CHECK in read_only(run)


def test_rollback_to_python_without_a_pin(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path)

    run = deploy(cfg, secrets, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    assert run.mutating_changed_ops == [SELECT_PYTHON, REMEMBER, RELOAD, RESTART]
    assert PRUNE not in [op.name for op in run.ops]


def test_version_change_installs_switches_and_remembers_the_old_one(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path, "0.2.0")

    responses = host(cfg, secrets, "0.1.0", selected="0.1.0")
    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy nyxmon | Install nyxmon-agent 0.2.0",
        SELECT_RUST,
        REMEMBER,
        RELOAD,
        RESTART,
        PRUNE,
    ]
    assert f"{ROOT}/0.2.0/nyxmon-agent --db" in run.upload(DROPIN).decode()
    assert run.upload(f"{ROOT}/.previous-version") == b"0.1.0\n"


def test_previous_version_is_not_remembered_when_its_directory_is_gone(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path, "0.2.0")
    responses = {**selected_dropin(cfg, "0.1.0"), **host(cfg, secrets, "0.2.0")}

    run = deploy(cfg, secrets, responses)

    assert REMEMBER not in run.mutating_changed_ops
    assert SELECT_RUST in run.mutating_changed_ops


def test_installed_version_from_another_archive_is_refused_before_any_change(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**converged(cfg, secrets), **installed("0.1.0", sha256=OTHER_SHA)}

    with pytest.raises(ValueError, match="never replaced in place") as caught:
        run_deploy_fake(deploy_nyxmon, cfg, secrets, responses=responses)
    assert OTHER_SHA in str(caught.value)
    assert SHA in str(caught.value)


def test_installed_version_without_a_recorded_checksum_is_refused(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**converged(cfg, secrets), **fakehost.directory(f"{ROOT}/0.1.0")}

    with pytest.raises(ValueError, match="sha256 unknown"):
        run_deploy_fake(deploy_nyxmon, cfg, secrets, responses=responses)


def test_local_archive_is_uploaded_and_pinned_by_its_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "nyxmon-agent.tar.gz"
    archive.write_bytes(b"local archive")
    digest = hashlib.sha256(b"local archive").hexdigest()
    cfg, secrets = make(tmp_path, agent_impl="rust", agent_rust_version="0.1.0", agent_rust_local_archive=archive)

    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.upload(f"{ROOT}/.upload.tar.gz") == b"local archive"
    install = next(c for c in run.executed_commands if "nyxmon-agent install" in c)
    assert f"{ROOT} 0.1.0 {digest} " in install
    assert install.endswith(f" {ROOT}/.upload.tar.gz")


def test_local_archive_must_match_a_pinned_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "nyxmon-agent.tar.gz"
    archive.write_bytes(b"local archive")
    cfg, secrets = rust(tmp_path, agent_rust_local_archive=archive)

    with pytest.raises(ValueError, match="not agent_rust_sha256"):
        run_deploy_fake(deploy_nyxmon, cfg, secrets, responses=converged(cfg, secrets))


def test_pending_prune_runs_after_the_check(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**host(cfg, secrets, "0.1.0", selected="0.1.0"), PRUNE_PROBE: [f"{ROOT}/0.0.1"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PRUNE]
    prune = next(c for c in run.executed_commands if "nyxmon-agent prune" in c)
    assert prune.endswith(f"nyxmon-agent prune {ROOT} 0.1.0 nyxmon-monitor 3")


def test_failed_prune_probe_prunes_and_probes_again(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**host(cfg, secrets, "0.1.0", selected="0.1.0"), PRUNE_PROBE: ["oops", "ops-deploy-probe-failed"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PRUNE]
    assert "Deploy nyxmon | Probe again: Rust agent versions to prune" in read_only(run)


# -- the host script through real shells (the parts that need neither root nor GNU tools) --

LOGIN_SHELLS = ["bash", pytest.param("fish", marks=pytest.mark.skipif(not shutil.which("fish"), reason="no fish"))]


@pytest.fixture
def fake_agent(tmp_path: Path) -> tuple[Path, str]:
    """An install root with a fake ``0.1.0/nyxmon-agent`` and a PATH whose ``runuser`` just runs its argv."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    runuser = bin_dir / "runuser"
    runuser.write_text('#!/bin/sh\n[ "$1" = -u ] && [ "$3" = -- ] || exit 97\nshift 3\nexec "$@"\n')
    runuser.chmod(0o755)
    root = tmp_path / "it's root"
    (root / "0.1.0").mkdir(parents=True)
    agent = root / "0.1.0" / "nyxmon-agent"
    agent.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  --version) printf "%s\\n" "${FAKE_VERSION-nyxmon-agent 0.1.0 (abc123)}" ;;\n'
        '  --check-schema) [ "$3" = "$FAKE_DB" ] || exit 9\n'
        '    echo "${FAKE_SCHEMA_OUT-ok}"; exit "${FAKE_SCHEMA_RC-0}" ;;\n'
        "esac\n"
    )
    agent.chmod(0o755)
    return root, f"{bin_dir}:{os.environ['PATH']}"


def run_validate(root: Path, path: str, login_shell: str, **env: str) -> subprocess.CompletedProcess[str]:
    command = _agent("validate", root, "0.1.0", "nyxmon", "/db's.sqlite3")
    line = make_unix_command(StringCommand(command)).get_raw_value()
    assert not fish_unsafe(line)
    environment = {**os.environ, "PATH": path, "FAKE_DB": "/db's.sqlite3", **env}
    return subprocess.run([login_shell, "-c", line], capture_output=True, text=True, env=environment, check=False)


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("env", "error"),
    [
        ({}, None),
        ({"FAKE_VERSION": "nyxmon-agent\n0.1.0"}, None),  # split like the role's .split()
        ({"FAKE_VERSION": "nyxmon-agent 0.1.1 (abc123)"}, "--version exited 0"),
        ({"FAKE_VERSION": "nyxmon 0.1.0"}, "expected 'nyxmon-agent 0.1.0 (<commit>)'"),
        ({"FAKE_VERSION": ""}, "--version"),
        ({"FAKE_SCHEMA_RC": "3", "FAKE_SCHEMA_OUT": "missing table"}, "--check-schema exited 3: missing table"),
    ],
)
def test_validate_checks_version_and_schema(
    fake_agent: tuple[Path, str], login_shell: str, env: dict[str, str], error: str | None
) -> None:
    root, path = fake_agent

    result = run_validate(root, path, login_shell, **env)

    assert (result.returncode == 0) is (error is None), result.stderr
    if error is not None:
        assert error in result.stderr


def test_keep_versions_has_no_upper_bound(tmp_path: Path) -> None:
    cfg, _ = make(tmp_path, agent_rust_keep_versions=250)

    assert cfg.agent_rust_keep_versions == 250
