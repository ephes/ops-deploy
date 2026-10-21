"""The graphyard agent switch (graphyard_deploy's agent_rust.yml and agent_verify.yml) against the fake connector."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.graphyard import GraphyardConfig, deploy_graphyard_core
from ops_deploy.services.graphyard._common import render_role
from ops_deploy.services.graphyard.agent import _agent, render_dropin
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, fish_unsafe, run_deploy_fake
from tests import fakehost
from tests.graphyard_fixtures import REF, core_config, macmini_core_config, make_source, secrets_values
from tests.test_graphyard import PREFIX, converged, deploy

SHA = "b5ea97633a77d3297ef93991d6db38475f37995fae654cea995e7050ae998305"
OTHER_SHA = "0" * 64
ROOT = "/opt/graphyard-agent"
DB = "/opt/apps/graphyard/site/src/django/db.sqlite3"
DROPIN_DIR = "/etc/systemd/system/graphyard-agent.service.d"
DROPIN = f"{DROPIN_DIR}/agent-impl.conf"
URL = (
    "https://github.com/ephes/graphyard/releases/download/agent-rs-v0.1.0/"
    "graphyard-agent-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
)
PRUNE_PROBE = f"graphyard-agent prune {ROOT} 0.1.0 graphyard-agent 3 --dry-run"
PYTHON_CHECK = PREFIX + "Check graphyard-agent runs the Python agent"
RUST_CHECK = PREFIX + "Check graphyard-agent runs the Rust agent"
VALIDATE = PREFIX + "Validate graphyard-agent 0.1.0"
INSTALL_ROOT = PREFIX + "Create the Rust agent install root"
SELECT_RUST = PREFIX + "Select the Rust agent for graphyard-agent"
SELECT_PYTHON = PREFIX + "Select the Python agent for graphyard-agent"
CREATE_DROPIN_DIR = PREFIX + f"Create {DROPIN_DIR}"
RELOAD = PREFIX + "Reload systemd for graphyard-agent.service"
RESTART = PREFIX + "Restart graphyard-agent.service"
PRUNE = PREFIX + "Prune old Rust agent versions"
REMEMBER = PREFIX + "Remember the previously selected Rust agent"


def make(tmp_path: Path, **agent: Any) -> tuple[GraphyardConfig, SecretValues]:
    return macmini_core_config(make_source(tmp_path), **agent), secrets_values()


def rust(tmp_path: Path, version: str = "0.1.0", **agent: Any) -> tuple[GraphyardConfig, SecretValues]:
    return make(tmp_path, agent_impl="rust", agent_rust_version=version, agent_rust_sha256=SHA, **agent)


def installed(*versions: str, sha256: str = SHA) -> dict[str, Any]:
    """Facts of a host with these Rust agent versions below the install root."""

    responses: dict[str, Any] = {**fakehost.directory(ROOT)}
    for version in versions:
        responses.update(fakehost.directory(f"{ROOT}/{version}"))
        responses.update(fakehost.file(f"{ROOT}/{version}/.archive-sha256", f"{sha256}\n"))
    return responses


def selected_dropin(cfg: GraphyardConfig, version: str) -> dict[str, Any]:
    return {
        **fakehost.file(DROPIN, render_dropin(cfg.model_copy(update={"agent_rust_version": version}))),
        **fakehost.directory(DROPIN_DIR),
    }


def host(cfg: GraphyardConfig, secrets: SecretValues, *versions: str, selected: str | None = None) -> dict[str, Any]:
    """A deployed host: ``versions`` installed, the drop-in selecting ``selected`` (``None``: no drop-in)."""

    responses = {**converged(cfg, secrets), **installed(*versions)}
    if selected is None:
        return responses
    # First: the fake connector answers with the first key contained in a
    # command, and ``cat <unit>`` is contained in ``cat <unit>.d/agent-impl.conf``.
    return {**selected_dropin(cfg, selected), **responses}


def read_only(run: FakeRun) -> list[str]:
    return [op.name for op in run.ops if op.read_only]


# -- configuration (the role's "Validate agent implementation settings") -----------


def test_defaults_follow_the_role(tmp_path: Path) -> None:
    cfg, _ = make(tmp_path)

    assert (cfg.agent_impl, cfg.agent_rust_version, cfg.agent_rust_sha256) == ("python", "", "")
    assert (cfg.agent_rust_install_root, cfg.agent_rust_keep_versions) == (ROOT, 3)
    assert cfg.agent_rust_local_archive is None
    assert cfg.model_copy(update={"agent_rust_version": "0.1.0"}).agent_rust_url == URL
    assert "agent-rs/target/" in cfg.source_excludes


def test_agent_settings_validate_from_inventory_values(tmp_path: Path) -> None:
    data = {
        "source_path": str(make_source(tmp_path)),
        "secrets": {"path": "secrets/prod/graphyard.yml"},
        "agent_impl": "rust",
        "agent_rust_version": "0.1.0",
        "agent_rust_sha256": SHA,
        "agent_rust_keep_versions": "2",
    }
    cfg = GraphyardConfig.model_validate(data)

    assert (cfg.agent_impl, cfg.agent_rust_binary, cfg.agent_rust_keep_versions) == (
        "rust",
        f"{ROOT}/0.1.0/graphyard-agent",
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
        ({"agent_rust_install_root": "/opt/graphyard-agent/"}, "agent_rust_install_root"),
        ({"agent_rust_install_root": "opt/graphyard-agent"}, "agent_rust_install_root"),
        ({"agent_rust_install_root": "/opt/graphyard agent"}, "agent_rust_install_root"),
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


def test_keep_versions_has_no_upper_bound(tmp_path: Path) -> None:
    cfg, _ = make(tmp_path, agent_rust_keep_versions=250)

    assert cfg.agent_rust_keep_versions == 250


# -- deploys -------------------------------------------------------------------


def test_python_without_a_pin_installs_nothing(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path)

    run = deploy(cfg, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert not any(ROOT in command for command in run.executed_commands if "graphyard-agent install" in command)
    assert PRUNE not in [op.name for op in run.ops]
    assert INSTALL_ROOT not in [op.name for op in run.ops]
    assert PYTHON_CHECK in read_only(run)
    check = next(c for c in run.executed_commands if "/proc/$pid/cmdline" in c)
    for arg in ("/opt/apps/graphyard/site/.venv/bin/python", "manage.py", "start_agent"):
        assert f"grep -qxF -- {arg} " in check
    assert f"in {ROOT}/*) exit 1;;" in check


def test_pinned_version_is_installed_without_switching(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path, agent_rust_version="0.1.0", agent_rust_sha256=SHA)

    run = deploy(cfg, converged(cfg, secrets))

    # Installed ahead of the switch (impl python): no drop-in, no restart.
    assert run.mutating_changed_ops == [INSTALL_ROOT, PREFIX + "Install graphyard-agent 0.1.0", PRUNE]
    install = next(c for c in run.executed_commands if "graphyard-agent install" in c)
    assert f"graphyard-agent install {ROOT} 0.1.0 {SHA} {URL} graphyard {DB} ''" in install
    assert not any(DROPIN in path for path in run.uploaded_paths)
    assert PYTHON_CHECK in read_only(run)


def test_first_rust_deploy_installs_after_the_migrations_and_starts_the_rust_agent(tmp_path: Path) -> None:
    cfg, _ = rust(tmp_path)
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f+++++++++ pyproject.toml"]})

    run = deploy(cfg, rsync=rsync)

    commands = run.executed_commands
    migrate = next(c for c in commands if "manage.py migrate --noinput" in c)
    install = next(c for c in commands if "graphyard-agent install" in c)
    start = "systemctl start graphyard-agent.service"
    check = next(c for c in commands if "is-active" in c and "readlink" in c)
    prune = next(c for c in commands if "graphyard-agent prune" in c)
    health = next(c for c in commands if "/v1/health" in c)
    assert commands.index(migrate) < commands.index(install) < commands.index(start)
    assert commands.index(start) < commands.index(check) < commands.index(prune) < commands.index(health)
    assert run.upload(DROPIN).decode() == render_dropin(cfg)
    assert f"{ROOT}/0.1.0/graphyard-agent --db {DB}\n" in run.upload(DROPIN).decode()
    assert CREATE_DROPIN_DIR in run.mutating_changed_ops
    # Started with the drop-in in place: no restart right after the start.
    assert "systemctl restart graphyard-agent.service" not in commands
    assert RUST_CHECK in read_only(run)
    assert PRUNE in run.mutating_changed_ops
    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--exclude=agent-rs/target/" in real


def test_converged_python_with_a_pin_changes_nothing(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path, agent_rust_version="0.1.0", agent_rust_sha256=SHA)

    run = deploy(cfg, host(cfg, secrets, "0.1.0"))

    assert run.mutating_changed_ops == []
    assert VALIDATE in read_only(run)
    assert PYTHON_CHECK in read_only(run)
    assert run.uploads == []
    validate = next(c for c in run.executed_commands if "graphyard-agent validate" in c)
    assert f"graphyard-agent validate {ROOT} 0.1.0 graphyard {DB}" in validate


def test_converged_rust_changes_nothing(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)

    run = deploy(cfg, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    assert run.mutating_changed_ops == []
    assert VALIDATE in read_only(run)
    assert RUST_CHECK in read_only(run)
    assert not any(
        c.startswith(("systemctl start", "systemctl restart", "systemctl daemon-reload")) for c in run.executed_commands
    )
    assert run.uploads == []


def test_switch_python_to_rust_writes_the_dropin_and_restarts_the_agent_only(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)

    run = deploy(cfg, host(cfg, secrets, "0.1.0"))

    assert run.mutating_changed_ops == [CREATE_DROPIN_DIR, SELECT_RUST, RELOAD, RESTART, PRUNE]
    assert run.upload(DROPIN).decode() == (
        "# Managed by Ansible (graphyard_deploy): graphyard_agent_impl=rust.\n"
        "# Removed when graphyard_agent_impl=python; the base unit then runs the venv\n"
        "# manage.py start_agent again.\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={ROOT}/0.1.0/graphyard-agent --db {DB}\n"
    )
    commands = run.executed_commands
    assert "systemctl restart graphyard-web.service" not in commands
    check = next(c for c in commands if "is-active" in c and "readlink" in c)
    assert f"= {ROOT}/0.1.0/graphyard-agent ]" in check
    assert commands.index("systemctl restart graphyard-agent.service") < commands.index(check)
    prune = next(c for c in commands if "graphyard-agent prune" in c)
    assert commands.index(check) < commands.index(prune)


def test_switch_rust_to_python_removes_the_dropin_and_keeps_the_version(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path, agent_rust_version="0.1.0", agent_rust_sha256=SHA)

    run = deploy(cfg, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    # The documented rollback: the drop-in goes, the binary stays as the rollback target.
    assert run.mutating_changed_ops == [SELECT_PYTHON, REMEMBER, RELOAD, RESTART, PRUNE]
    assert f"rm -f {DROPIN}" in run.executed_commands
    assert run.upload(f"{ROOT}/.previous-version") == b"0.1.0\n"
    assert PYTHON_CHECK in read_only(run)


def test_rollback_to_python_without_a_pin(tmp_path: Path) -> None:
    cfg, secrets = make(tmp_path)

    run = deploy(cfg, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    assert run.mutating_changed_ops == [SELECT_PYTHON, REMEMBER, RELOAD, RESTART]
    assert PRUNE not in [op.name for op in run.ops]


def test_version_change_installs_switches_and_remembers_the_old_one(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path, "0.2.0")

    run = deploy(cfg, host(cfg, secrets, "0.1.0", selected="0.1.0"))

    assert run.mutating_changed_ops == [
        PREFIX + "Install graphyard-agent 0.2.0",
        SELECT_RUST,
        REMEMBER,
        RELOAD,
        RESTART,
        PRUNE,
    ]
    assert f"{ROOT}/0.2.0/graphyard-agent --db" in run.upload(DROPIN).decode()
    assert run.upload(f"{ROOT}/.previous-version") == b"0.1.0\n"


def test_previous_version_is_not_remembered_when_its_directory_is_gone(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path, "0.2.0")
    responses = {**selected_dropin(cfg, "0.1.0"), **host(cfg, secrets, "0.2.0")}

    run = deploy(cfg, responses)

    assert REMEMBER not in run.mutating_changed_ops
    assert SELECT_RUST in run.mutating_changed_ops


def test_code_change_restarts_the_rust_agent_too(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... src/graphyard/views.py"]})

    run = deploy(cfg, host(cfg, secrets, "0.1.0", selected="0.1.0"), rsync=rsync)

    # Like the role: code, dependencies or the env file restart both units, whichever agent runs.
    assert RESTART in run.mutating_changed_ops
    assert SELECT_RUST not in run.mutating_changed_ops


def test_installed_version_from_another_archive_is_refused_before_any_change(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**converged(cfg, secrets), **installed("0.1.0", sha256=OTHER_SHA)}

    with pytest.raises(ValueError, match="never replaced in place") as caught:
        run_deploy_fake(deploy_graphyard_core, cfg, secrets, RecordingRsyncRunner(), responses=responses)
    assert OTHER_SHA in str(caught.value)
    assert SHA in str(caught.value)


def test_installed_version_without_a_recorded_checksum_is_refused(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**converged(cfg, secrets), **fakehost.directory(f"{ROOT}/0.1.0")}

    with pytest.raises(ValueError, match="sha256 unknown"):
        run_deploy_fake(deploy_graphyard_core, cfg, secrets, RecordingRsyncRunner(), responses=responses)


def test_local_archive_is_uploaded_and_pinned_by_its_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "graphyard-agent.tar.gz"
    archive.write_bytes(b"local archive")
    digest = hashlib.sha256(b"local archive").hexdigest()
    cfg, secrets = make(tmp_path, agent_impl="rust", agent_rust_version="0.1.0", agent_rust_local_archive=archive)

    run = deploy(cfg, converged(cfg, secrets))

    assert run.upload(f"{ROOT}/.upload.tar.gz") == b"local archive"
    install = next(c for c in run.executed_commands if "graphyard-agent install" in c)
    assert f"{ROOT} 0.1.0 {digest} " in install
    assert install.endswith(f" {ROOT}/.upload.tar.gz")


def test_local_archive_must_match_a_pinned_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "graphyard-agent.tar.gz"
    archive.write_bytes(b"local archive")
    cfg, secrets = rust(tmp_path, agent_rust_local_archive=archive)

    with pytest.raises(ValueError, match="not agent_rust_sha256"):
        run_deploy_fake(deploy_graphyard_core, cfg, secrets, RecordingRsyncRunner(), responses=converged(cfg, secrets))


def test_pending_prune_runs_after_the_check(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**host(cfg, secrets, "0.1.0", selected="0.1.0"), PRUNE_PROBE: [f"{ROOT}/0.0.1"]}

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [PRUNE]
    prune = next(c for c in run.executed_commands if "graphyard-agent prune" in c)
    assert prune.endswith(f"graphyard-agent prune {ROOT} 0.1.0 graphyard-agent 3")


def test_failed_prune_probe_prunes_and_probes_again(tmp_path: Path) -> None:
    cfg, secrets = rust(tmp_path)
    responses = {**host(cfg, secrets, "0.1.0", selected="0.1.0"), PRUNE_PROBE: ["oops", "ops-deploy-probe-failed"]}

    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == [PRUNE]
    assert PREFIX + "Probe again: Rust agent versions to prune" in read_only(run)


def test_custom_unit_and_paths_follow_the_config(tmp_path: Path) -> None:
    cfg = core_config(
        make_source(tmp_path),
        runtime=None,
        agent_service_name="gy-agent",
        site_path="/srv/gy/site",
        agent_impl="rust",
        agent_rust_version="1.2.3-rc.1",
        agent_rust_sha256=SHA,
        agent_rust_install_root="/srv/agents",
        agent_rust_keep_versions=5,
    )
    secrets = SecretValues(REF, {k: v for k, v in secrets_values().items() if not k.startswith("grafana")})

    run = deploy(cfg, secrets=secrets)

    dropin = run.upload("/etc/systemd/system/gy-agent.service.d/agent-impl.conf").decode()
    assert "ExecStart=/srv/agents/1.2.3-rc.1/graphyard-agent --db /srv/gy/site/src/django/db.sqlite3\n" in dropin
    prune = next(c for c in run.executed_commands if "graphyard-agent prune" in c)
    assert prune.endswith("graphyard-agent prune /srv/agents 1.2.3-rc.1 gy-agent 5")
    check = next(c for c in run.executed_commands if "is-active" in c and "readlink" in c)
    assert "systemctl is-active gy-agent)" in check


def test_rendered_dropin_is_the_roles_template(tmp_path: Path) -> None:
    cfg, _ = rust(tmp_path)

    assert render_dropin(cfg) == render_role(
        "agent-impl.conf.j2",
        {"graphyard_agent_rust_binary": f"{ROOT}/0.1.0/graphyard-agent", "graphyard_django_path": str(cfg.django_path)},
    )


# -- the host script through real shells (the parts that need neither root nor GNU tools) --

LOGIN_SHELLS = ["bash", pytest.param("fish", marks=pytest.mark.skipif(not shutil.which("fish"), reason="no fish"))]


@pytest.fixture
def fake_agent(tmp_path: Path) -> tuple[Path, str]:
    """An install root with a fake ``0.1.0/graphyard-agent`` and a PATH whose ``runuser`` just runs its argv."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    runuser = bin_dir / "runuser"
    runuser.write_text('#!/bin/sh\n[ "$1" = -u ] && [ "$3" = -- ] || exit 97\nshift 3\nexec "$@"\n')
    runuser.chmod(0o755)
    root = tmp_path / "it's root"
    (root / "0.1.0").mkdir(parents=True)
    agent = root / "0.1.0" / "graphyard-agent"
    agent.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  --version) printf "%s\\n" "${FAKE_VERSION-graphyard-agent 0.1.0 (abc123)}" ;;\n'
        '  --check-schema) [ "$3" = "$FAKE_DB" ] || exit 9\n'
        '    echo "${FAKE_SCHEMA_OUT-ok}"; exit "${FAKE_SCHEMA_RC-0}" ;;\n'
        "esac\n"
    )
    agent.chmod(0o755)
    return root, f"{bin_dir}:{os.environ['PATH']}"


def run_validate(root: Path, path: str, login_shell: str, **env: str) -> subprocess.CompletedProcess[str]:
    command = _agent("validate", root, "0.1.0", "graphyard", "/db's.sqlite3")
    line = make_unix_command(StringCommand(command)).get_raw_value()
    assert not fish_unsafe(line)
    environment = {**os.environ, "PATH": path, "FAKE_DB": "/db's.sqlite3", **env}
    return subprocess.run([login_shell, "-c", line], capture_output=True, text=True, env=environment, check=False)


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("env", "error"),
    [
        ({}, None),
        ({"FAKE_VERSION": "graphyard-agent\n0.1.0"}, None),  # split like the role's .split()
        ({"FAKE_VERSION": "graphyard-agent 0.1.1 (abc123)"}, "--version exited 0"),
        ({"FAKE_VERSION": "graphyard 0.1.0"}, "expected 'graphyard-agent 0.1.0 (<commit>)'"),
        ({"FAKE_VERSION": ""}, "--version"),
        ({"FAKE_SCHEMA_RC": "3", "FAKE_SCHEMA_OUT": "missing column"}, "--check-schema exited 3: missing column"),
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


@pytest.mark.parametrize("impl", ["python", "rust"])
def test_agent_check_survives_fish(tmp_path: Path, impl: str) -> None:
    """The check's wire form means the same to fish (root's login shell on macmini) as to sh."""

    agent: dict[str, Any] = {"agent_impl": impl, "agent_rust_version": "0.1.0", "agent_rust_sha256": SHA}
    cfg, secrets = make(tmp_path, **agent)
    responses = host(cfg, secrets, "0.1.0", selected="0.1.0" if impl == "rust" else None)

    run = deploy(cfg, responses)

    assert run.fish_unsafe_commands == []
