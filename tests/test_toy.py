import hashlib
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.rsync import RsyncError, RsyncResult
from ops_deploy.core.templates import render
from ops_deploy.services.toy import ToyConfig, deploy_toy
from ops_deploy.services.toy.deploy import TEMPLATE_PACKAGE
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake

GOLDEN = Path(__file__).parent / "golden"
HOST_DATA = {"ssh_hostname": "toy.example.invalid", "ssh_user": "deploy"}
ITEMIZED_CHANGE = [">f.st...... app.py"]


@pytest.fixture
def source(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("print('hi')\n")
    return tmp_path


@pytest.fixture
def cfg(source: Path) -> ToyConfig:
    return ToyConfig(source_path=source)


def _stat(path: str, *, user: str, mode: str) -> tuple[str, str]:
    line = f"user={user} group={user} mode={mode} atime=0 mtime=0 ctime=0 size=10 '{path}'"
    return f"test -e {path} ||", line


def converged_host(cfg: ToyConfig, **overrides: str) -> dict[str, Any]:
    """Fake responses describing a host where the toy service is fully deployed.

    ``overrides`` replaces the remote content of ``config``/``unit`` to model drift.
    """

    rendered = {
        "config": overrides.get("config", render(TEMPLATE_PACKAGE, "toy.conf.j2", cfg=cfg)),
        "unit": overrides.get("unit", render(TEMPLATE_PACKAGE, "toy.service.j2", cfg=cfg)),
    }
    responses: dict[str, Any] = {}
    for key, path, owner in (("config", cfg.config_path, cfg.user), ("unit", cfg.unit_path, "root")):
        digest = hashlib.sha1(rendered[key].encode()).hexdigest()
        responses[f"sha1sum {path} "] = f"{digest}  {path}"
        responses.update([_stat(str(path), user=owner, mode="-rw-r--r--")])
    responses.update(
        [
            _stat(str(cfg.site_path), user=cfg.user, mode="drwxr-xr-x"),
            _stat("/etc/systemd/system", user="root", mode="drwxr-xr-x"),
        ]
    )
    service = f"{cfg.service_name}.service"
    responses[f"--property SubState {service}"] = [f"Id={service}", "SubState=running"]
    responses[f"--property UnitFileState {service}"] = [f"Id={service}", "UnitFileState=enabled"]
    return responses


def test_first_run_creates_everything_and_starts_service(cfg: ToyConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = run_deploy_fake(deploy_toy, cfg, rsync=rsync, host_data=HOST_DATA)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "mkdir -p /home/toy/site" in commands
    assert "chown toy:toy /home/toy/site" in commands
    assert "systemctl daemon-reload" in commands
    assert "systemctl enable toy.service" in commands
    assert run.uploaded_paths == ["/home/toy/site/toy.conf", "/etc/systemd/system/toy.service"]
    assert run.upload("/home/toy/site/toy.conf") == render(TEMPLATE_PACKAGE, "toy.conf.j2", cfg=cfg).encode()
    assert run.function_calls == ["_run_rsync"]
    real_syncs = [argv for argv in rsync.calls if "--dry-run" not in argv]
    assert real_syncs == [
        [
            "rsync", "-rlt", "--delete", "--no-owner", "--no-group", "--chown=toy:toy",
            "--exclude=.git", "--exclude=.venv", "--exclude=__pycache__", "--exclude=.env",
            "-e", "ssh", f"{cfg.source_path}/", "deploy@toy.example.invalid:/home/toy/site/app/",
        ]
    ]  # fmt: skip


def test_noop_run_changes_nothing(cfg: ToyConfig) -> None:
    rsync = RecordingRsyncRunner()

    run = run_deploy_fake(deploy_toy, cfg, rsync=rsync, responses=converged_host(cfg), host_data=HOST_DATA)

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []
    assert run.uploads == []
    assert run.function_calls == []
    assert all("--dry-run" in argv for argv in rsync.calls)


def test_code_change_syncs_and_restarts_without_daemon_reload(cfg: ToyConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})

    run = run_deploy_fake(deploy_toy, cfg, rsync=rsync, responses=converged_host(cfg), host_data=HOST_DATA)

    assert run.succeeded, run.error
    assert run.changed_ops == ["Deploy toy service | Sync source", "Deploy toy service | Restart service"]
    assert run.function_calls == ["_run_rsync"]
    assert run.executed_commands == ["systemctl restart toy.service"]


def test_config_drift_rewrites_config_and_restarts(cfg: ToyConfig) -> None:
    responses = converged_host(cfg, config="GREETING=stale\n")

    run = run_deploy_fake(deploy_toy, cfg, rsync=RecordingRsyncRunner(), responses=responses, host_data=HOST_DATA)

    assert run.changed_ops == ["Deploy toy service | Write config", "Deploy toy service | Restart service"]
    assert run.uploaded_paths == ["/home/toy/site/toy.conf"]
    assert run.upload("/home/toy/site/toy.conf") == render(TEMPLATE_PACKAGE, "toy.conf.j2", cfg=cfg).encode()
    assert "systemctl daemon-reload" not in run.executed_commands
    assert run.executed_commands[-1] == "systemctl restart toy.service"


def test_unit_drift_reloads_systemd_before_restart(cfg: ToyConfig) -> None:
    responses = converged_host(cfg, unit="[Unit]\nDescription=old\n")

    run = run_deploy_fake(deploy_toy, cfg, rsync=RecordingRsyncRunner(), responses=responses, host_data=HOST_DATA)

    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index("systemctl restart toy.service")


def test_without_source_path_rsync_is_never_called() -> None:
    rsync = RecordingRsyncRunner()

    run = run_deploy_fake(deploy_toy, ToyConfig(), rsync=rsync, host_data=HOST_DATA)

    assert run.succeeded
    assert rsync.calls == []
    assert "Deploy toy service | Sync source" not in [op.name for op in run.ops]


def test_failed_rsync_dry_run_aborts_before_any_change(cfg: ToyConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": RsyncResult(255, stderr="ssh: connect refused")})

    with pytest.raises(RsyncError, match="connect refused"):
        run_deploy_fake(deploy_toy, cfg, rsync=rsync, host_data=HOST_DATA)


@pytest.mark.parametrize("template", ["toy.conf.j2", "toy.service.j2"])
def test_templates_match_golden_files(template: str) -> None:
    cfg = ToyConfig(greeting="moin", app_port=10123)
    expected = (GOLDEN / template.removesuffix(".j2")).read_text()

    assert render(TEMPLATE_PACKAGE, template, cfg=cfg) == expected


def test_source_path_must_exist_and_is_not_echoed(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="source_path is not a directory") as excinfo:
        ToyConfig(source_path=tmp_path / "hunter2-missing")
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in repr(excinfo.value)


def test_toy_config_rejects_placeholder_greeting() -> None:
    with pytest.raises(ValidationError, match="greeting still contains the placeholder"):
        ToyConfig(greeting="CHANGEME")
