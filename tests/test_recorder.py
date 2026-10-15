"""Deploy-level scenarios for recorder against the fake connector."""

import hashlib
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.core.templates import render
from ops_deploy.services.recorder import RecorderConfig, deploy_recorder
from ops_deploy.services.recorder.deploy import TEMPLATE_PACKAGE, render_env, render_route, traefik_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.recorder_fixtures import BINARY, FakeToolchain, make_source

HOST = "recorder.example.com"
UNIT = "/etc/systemd/system/recorder.service"
ROUTE = "/etc/traefik/dynamic/recorder.yml"
ENV = "/etc/recorder/recorder.env"
BIN = "/opt/recorder/recorderd"
SECRET_VALUES = {
    "session_secret": "recorder-fixture-session-secret",
    "admin_emails": "admin@example.com",
    "mail_token": "recorder-fixture-mail-token",
    "s3_access_key": "recorder-fixture-access",
    "s3_secret_key": "recorder-fixture-s3-secret",
}
READ_ONLY = ["Deploy recorder | Check recorder /health"]


@pytest.fixture
def cfg(tmp_path: Path) -> RecorderConfig:
    return RecorderConfig(
        source_path=make_source(tmp_path),
        artifact_path=tmp_path / "recorderd",
        secrets=SecretRef("secrets/prod/recorder.yml"),
        public_url=f"https://{HOST}",
        traefik_host=HOST,
        s3_endpoint="127.0.0.1:9001",
    )


def values(cfg: RecorderConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


@pytest.fixture
def secrets(cfg: RecorderConfig) -> SecretValues:
    return values(cfg)


def converged(
    cfg: RecorderConfig, secrets: SecretValues, *, binary: bytes = BINARY, drift: dict[str, str] | None = None
) -> dict[str, Any]:
    content = {
        ENV: render_env(cfg, secrets).reveal().decode(),
        UNIT: render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=cfg),
        ROUTE: render_route(cfg, traefik_config(cfg)),
        **(drift or {}),
    }
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account("recorder", "/var/lib/recorder", shell="/usr/sbin/nologin"),
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("ca-certificates"),
        **fakehost.directory("/var/lib/recorder", user="recorder", mode="drwxr-x---"),
        **fakehost.directory("/opt/recorder"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.service("recorder.service"),
    }
    # /etc/recorder is root:recorder 0750.
    responses["test -e /etc/recorder ||"] = [
        "user=root group=recorder mode=drwxr-x--- atime=0 mtime=0 ctime=0 size=10 '/etc/recorder'"
    ]
    for path, text in content.items():
        responses.update(fakehost.file(path, text))
    responses[f"test -e {ENV} ||"] = [
        f"user=root group=recorder mode=-rw-r----- atime=0 mtime=0 ctime=0 size=10 '{ENV}'"
    ]
    responses[f"sha1sum {BIN} "] = [f"{hashlib.sha1(binary).hexdigest()}  {BIN}"]
    responses[f"sha256sum {BIN} "] = [f"{hashlib.sha256(binary).hexdigest()}  {BIN}"]
    responses[f"test -e {BIN} ||"] = [f"user=root group=root mode=-rwxr-xr-x atime=0 mtime=0 ctime=0 size=10 '{BIN}'"]
    return responses


def deploy(
    cfg: RecorderConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    runner: FakeToolchain | None = None,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_recorder, cfg, secrets, runner=runner or FakeToolchain(), responses=responses or dict(fakehost.LINUX)
    )
    assert run.succeeded, run.error
    return run


def test_first_run_builds_and_installs_everything(cfg: RecorderConfig, secrets: SecretValues) -> None:
    toolchain = FakeToolchain()
    run = deploy(cfg, secrets, runner=toolchain)

    assert [argv[:3] for argv, _, _ in toolchain.calls] == [
        ["npm", "ci", "--no-audit"],
        ["npm", "run", "build"],
        ["go", "build", "-trimpath"],
    ]
    go_argv, go_cwd, go_env = toolchain.calls[2]
    assert go_cwd == cfg.source_path
    assert go_env == {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    assert go_argv[-3:] == ["-o", str(cfg.artifact_path), "./cmd/recorderd"]
    assert toolchain.calls[0][1] == cfg.source_path / "web"

    commands = run.executed_commands
    assert "useradd -d /var/lib/recorder -s /usr/sbin/nologin -g recorder -r -M recorder" in commands
    assert run.upload(f"{BIN}.ops-deploy-new") == BINARY
    assert run.upload(UNIT).decode() == render(TEMPLATE_PACKAGE, "recorder.service.j2", cfg=cfg)
    assert run.upload(ROUTE).decode() == render_route(cfg, traefik_config(cfg))
    assert "chmod 750 /var/lib/recorder" in commands
    assert "chown root:recorder /etc/recorder" in commands
    assert any("systemctl daemon-reload" in c for c in commands)
    assert any("systemctl start recorder.service" in c for c in commands)
    # Started by this run: no restart on top.
    assert not any("systemctl restart recorder.service" in c for c in commands)
    # Traefik picks the route up through its file watch; it is never restarted.
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    assert "apt-get" in " ".join(commands)


def test_second_run_changes_nothing(cfg: RecorderConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert [op for op in run.changed_ops if op not in READ_ONLY] == []
    assert run.uploaded_paths == []


def test_new_binary_restarts(cfg: RecorderConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, binary=b"older build"))

    assert run.uploaded_paths == [f"{BIN}.ops-deploy-new"]
    assert (
        f"chown root:root {BIN}.ops-deploy-new && chmod 0755 {BIN}.ops-deploy-new && mv -f {BIN}.ops-deploy-new {BIN}"
    ) in run.executed_commands
    assert "Deploy recorder | Restart recorder.service" in run.mutating_changed_ops
    assert not any("daemon-reload" in c for c in run.executed_commands)


def test_env_change_restarts_without_leaking(cfg: RecorderConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, session_secret="rotated-fixture-session")
    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert sorted(run.mutating_changed_ops) == [
        "Deploy recorder | Restart recorder.service",
        "Deploy recorder | Write recorder.env",
    ]
    text = run.all_text() + repr(run.ops)
    for value in rotated.values():
        assert value not in text


def test_unit_change_reloads_and_restarts(cfg: RecorderConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, drift={UNIT: "[Service]\nExecStart=/old\n"}))

    assert sorted(run.mutating_changed_ops) == [
        "Deploy recorder | Install systemd unit recorder.service",
        "Deploy recorder | Reload systemd for recorder.service",
        "Deploy recorder | Restart recorder.service",
    ]


def test_route_change_neither_restarts_recorder_nor_traefik(cfg: RecorderConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, drift={ROUTE: "http: {}\n"}))

    assert run.mutating_changed_ops == ["Deploy recorder | Write Traefik route recorder"]


def test_build_failure_stops_before_any_operation(cfg: RecorderConfig, secrets: SecretValues) -> None:
    with pytest.raises(RuntimeError, match=r"go build -trimpath failed \(1\): go build broke"):
        run_deploy_fake(
            deploy_recorder, cfg, secrets, runner=FakeToolchain(fail="go build"), responses=dict(fakehost.LINUX)
        )


def test_smoke_runs_after_the_deploy(cfg: RecorderConfig, secrets: SecretValues) -> None:
    smoked = cfg.model_copy(update={"smoke_url": f"https://{HOST}"})
    toolchain = FakeToolchain()
    run = deploy(smoked, secrets, converged(cfg, secrets), runner=toolchain)

    assert toolchain.calls[-1][0] == [str(cfg.source_path / "scripts/smoke.sh"), f"https://{HOST}", "--expect-accounts"]
    assert run.function_calls == ["_smoke"]
    assert run.mutating_changed_ops == []


def test_failing_smoke_fails_the_deploy(cfg: RecorderConfig, secrets: SecretValues) -> None:
    smoked = cfg.model_copy(update={"smoke_url": f"https://{HOST}"})
    run = run_deploy_fake(
        deploy_recorder, smoked, secrets, runner=FakeToolchain(smoke_rc=1), responses=converged(cfg, secrets)
    )

    assert not run.succeeded


def test_missing_secrets_fail_before_building(cfg: RecorderConfig) -> None:
    toolchain = FakeToolchain()
    assert cfg.secrets is not None
    with pytest.raises(MissingSecretKeysError, match="session_secret"):
        run_deploy_fake(
            deploy_recorder, cfg, SecretValues(cfg.secrets, {"admin_emails": "a@example.com"}), runner=toolchain
        )
    assert toolchain.calls == []


@pytest.mark.parametrize("bad", ['quo"te', "back\\slash", "two\nlines"])
def test_unquotable_secret_values_are_refused(cfg: RecorderConfig, bad: str) -> None:
    with pytest.raises(ValueError, match="secret mail_token must be a single line") as caught:
        render_env(cfg, values(cfg, mail_token=bad))
    assert bad not in str(caught.value)


def test_config_rejects_bad_inputs(tmp_path: Path) -> None:
    base: dict[str, Any] = {
        "source_path": make_source(tmp_path),
        "secrets": SecretRef("secrets/prod/recorder.yml"),
        "public_url": f"https://{HOST}",
        "traefik_host": HOST,
    }
    RecorderConfig(**base)
    for bad in (
        {"source_path": tmp_path},
        {"max_chunk_bytes": 0},
        {"public_url": 'https://x/"q'},
        {"s3_bucket": 'a"b'},
        {"goarch": "386"},
    ):
        with pytest.raises(ConfigValidationError):
            RecorderConfig(**{**base, **bad})
    with pytest.raises(ConfigValidationError):
        RecorderConfig(**{k: v for k, v in base.items() if k != "secrets"})


def test_relative_controller_paths_are_made_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_source(tmp_path)
    monkeypatch.chdir(tmp_path)
    cfg = RecorderConfig(
        source_path=Path("recorder"),
        artifact_path=Path("out/recorderd"),
        public_url=f"https://{HOST}",
        traefik_host=HOST,
        secrets=SecretRef("secrets/prod/recorder.yml"),
    )
    assert cfg.source_path == tmp_path / "recorder"
    assert cfg.artifact_path == tmp_path / "out/recorderd"
