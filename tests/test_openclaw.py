"""OpenClaw deploy, removal and Nyxmon checks on the fake host; the host script's steps.

The inputs are the ``production`` parity case (the playbook's values with
synthetic secrets); ``test_openclaw_parity.py`` checks the bytes.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.helpers.traefik import hash_password, route_guard_command
from ops_deploy.services.openclaw import (
    OpenClawConfig,
    OpenClawNyxmonChecks,
    OpenClawRemoveConfig,
    OpenClawSecrets,
    deploy_openclaw,
    deploy_openclaw_nyxmon_checks,
    deploy_openclaw_remove,
    layout,
)
from ops_deploy.services.openclaw.deploy import source_command, source_state, stat_answer
from ops_deploy.services.openclaw.validate import ValidationError
from ops_deploy.services.openclaw.variables import resolve, version_at_least
from ops_deploy.testing.harness import FakeRun, run_deploy_fake
from tests import fakehost
from tests.test_infra_docker_vector import DOCKER_PACKAGES, docker_converged
from tests.test_openclaw_parity import host_script, inputs

P = "Deploy OpenClaw | "
CFG, SECRETS = inputs("production")
V = CFG.role_variables(SECRETS)
DATA = "/mnt/cryptdata/openclaw/data"
HOST_STEPS = ("config", "doctor", "plugins", "migrations", "audio", "cron")


def with_variables(**changes: Any) -> OpenClawConfig:
    return OpenClawConfig(variables={**CFG.variables, **changes}, httpd=CFG.httpd)


def owned(spec: layout.FileSpec) -> dict[str, Any]:
    quoted = shlex.quote(spec.path)
    return {f"if test -f {quoted} && ! test -L {quoted}; then stat": stat_answer(spec).splitlines()}


def root_file(spec: layout.FileSpec) -> dict[str, Any]:
    mode = {"0644": "-rw-r--r--", "0600": "-rw-------", "0755": "-rwxr-xr-x"}[spec.mode]
    return fakehost.file(spec.path, spec.content.decode(), mode=mode)


def written(spec: layout.FileSpec) -> dict[str, Any]:
    return owned(spec) if spec.owner.isdigit() else root_file(spec)


def numeric_directory(path: str, mode: str) -> dict[str, Any]:
    return {f"if test -d {shlex.quote(path)}; then stat": [f"1000 1000 {int(mode, 8):o}"]}


def converged(v: dict[str, Any] = V) -> dict[str, Any]:
    """A host the role (or a previous run) has fully deployed with ``v``."""

    responses: dict[str, Any] = {**docker_converged()}
    responses.update(fakehost.accounts({"openclaw": "/home/openclaw", "metrics": "/home/metrics"}, ("docker",)))
    for folder in layout.directories(v) + layout.workspace_directories(v):
        if folder.owner.isdigit():
            responses.update(numeric_directory(folder.path, folder.mode))
        else:
            responses.update(fakehost.directory(folder.path, user=folder.owner))
    responses.update(fakehost.directory("/etc/traefik/dynamic"))
    for path in ("/var/lib/openclaw-metrics", "/etc/openclaw-metrics-endpoint"):
        responses.update(fakehost.stat(path, group="metrics", mode="drwxr-x---"))
    specs = [
        layout.env_file(v),
        *layout.workspace_prompts(v),
        layout.audio_plan(v),
        layout.compose_file(v),
        layout.unit_file(v),
        layout.route_file(v),
        layout.logrotate_file(v),
        *layout.weeknotes_files(v),
        *layout.feature_files(v),
        *layout.workspace_skill_files(v),
        *layout.metrics_files(v).values(),
        layout.manifest_file(v),
    ]
    for spec in specs:
        responses.update(written(spec))
        if spec.create_only:
            responses[f"if test -e {shlex.quote(spec.path)}; then echo present"] = ["present"]
    responses[f"if test -e {shlex.quote(DATA + '/openclaw.json')}; then echo present"] = ["present"]
    responses["rev-parse HEAD"] = ["current"]
    responses[f"docker image inspect openclaw:{v['openclaw_version']} >/dev/null 2>&1; then echo present"] = ["present"]
    for step in HOST_STEPS:
        responses[f" {step} check )"] = ["current"]
    responses.update(fakehost.deb_installed(*DOCKER_PACKAGES, "python3", "apache2-utils"))
    responses.update(fakehost.directory("/home/openclaw", user="openclaw"))
    for path in ("/etc/systemd/system", "/usr/local/bin", "/etc/logrotate.d"):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.file("/etc/openclaw-metrics-endpoint/htpasswd", f"nyxmon:{HASH}\n"))
    for unit in ("openclaw.service", "openclaw-metrics-collector.timer", "openclaw-metrics-endpoint.service"):
        responses.update(fakehost.service(unit))
    return responses


HASH = hash_password("fixture-metrics-password")


def run(responses: dict[str, Any], cfg: OpenClawConfig = CFG, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_openclaw, cfg, SECRETS, responses=responses)
    assert result.succeeded is ok, result.error
    return result


def test_converged_host_changes_nothing() -> None:
    result = run(converged())

    assert result.mutating_changed_ops == []
    assert [op.name for op in result.ops if op.changed] == [
        f"{P}validate | Weeknotes S3 client binary is executable",
        f"{P}validate | Require prepared replacement CA bundle before activation",
        f"{P}Check Docker and Compose",
        f"{P}Verify Docker Compose v2 is available",
        f"{P}Run OpenClaw health check",
        f"{P}Wait for gateway to accept commands",
        f"{P}Run collector once for initial metrics file",
        f"{P}Check openclaw-metrics-endpoint runs the Python HTTP server and answers",
    ]
    assert not any("systemctl restart" in command for command in result.executed_commands)
    assert result.uploads == []


def test_fresh_host_deploys_in_the_role_order() -> None:
    result = run({**fakehost.UBUNTU})
    names = result.mutating_changed_ops
    order = [
        f"{P}Ensure OpenClaw user exists",
        f"{P}Clone OpenClaw repository",
        f"{P}Build OpenClaw Docker image",
        f"{P}Write /home/openclaw/site/.env",
        f"{P}Write {DATA}/openclaw.json",
        f"{P}Normalize the seeded OpenClaw gateway config",
        f"{P}Activate the new image through Doctor",
        f"{P}Install the official Codex runtime plugin",
        f"{P}Run guarded upstream upgrade migrations",
        f"{P}Apply the dedicated audio auth profile",
        f"{P}Write /home/openclaw/site/docker-compose.yml",
        f"{P}Install systemd unit openclaw.service",
        f"{P}Restart openclaw (deploy)",
        f"{P}Restart openclaw (weeknotes)",
        f"{P}Register the weeknotes reminder cron job",
        f"{P}Restart openclaw (skills)",
        f"{P}Write {DATA}/managed-skills-manifest.json",
        f"{P}Reset session bindings when managed skills changed",
    ]
    assert [name for name in names if name in order] == order
    # A seeded config is neither migrated nor patched by the host step, only normalized.
    assert f"{P}Reconcile the existing OpenClaw gateway config" not in names


@pytest.mark.parametrize("answer", ["current", "pending"])
def test_forced_config_normalizes_an_unchanged_seed_when_needed(answer: str) -> None:
    cfg = with_variables(openclaw_force_config=True)
    v = cfg.role_variables(SECRETS)
    responses = {**converged(v), **written(layout.seed_file(v)), " config check )": [answer]}
    names = run(responses, cfg).mutating_changed_ops

    assert f"{P}Write {DATA}/openclaw.json" not in names
    assert (f"{P}Normalize the seeded OpenClaw gateway config" in names) is (answer == "pending")


def test_route_is_written_under_the_traefik_guard() -> None:
    assert route_guard_command() not in run(converged()).executed_commands
    assert route_guard_command() in run({**fakehost.UBUNTU}).executed_commands


def test_metrics_without_credentials_are_refused() -> None:
    secrets = OpenClawSecrets(
        variables={k: v for k, v in SECRETS.variables.items() if k != "openclaw_metrics_endpoint_auth_password"}
    )
    with pytest.raises(ValidationError, match="metrics \\| Validate required variables"):
        CFG.role_variables(secrets)
    with pytest.raises(ValidationError, match="metrics \\| Validate synthetic canary settings"):
        with_variables(openclaw_metrics_endpoint_synthetic_canary_interval=60).role_variables(SECRETS)
    disabled = {"openclaw_metrics_endpoint_enabled": False, "openclaw_metrics_endpoint_synthetic_canary_interval": 60}
    with_variables(**disabled).role_variables(secrets)


def test_secrets_never_reach_a_command_line_or_upload() -> None:
    result = run({**fakehost.UBUNTU})
    text = result.all_text()

    for secret in ("sk-ant-fixture-anthropic", "fixture-gateway-token-0123456789", "spw-j", "fixture-paperless-token"):
        assert secret not in text
    assert "sk-ant-fixture-anthropic" in result.written("/home/openclaw/site/.env").decode()
    assert json.loads(result.written(f"{DATA}/credentials/paperless.json"))["token"] == "fixture-paperless-token"


def test_changed_skill_restarts_once_and_resets_sessions() -> None:
    responses = converged()
    handler = next(spec for spec in layout.feature_files(V) if spec.path.endswith("mail-imap/handler.py"))
    responses[f"if test -f {shlex.quote(handler.path)} && ! test -L {shlex.quote(handler.path)}; then stat"] = [
        "absent"
    ]
    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Write {handler.path}", f"{P}Restart openclaw (skills)"]


def test_changed_workspace_skill_resets_session_bindings() -> None:
    responses = converged()
    skill = layout.workspace_skill_files(V)[0]
    responses[f"if test -f {shlex.quote(skill.path)} && ! test -L {shlex.quote(skill.path)}; then stat"] = ["absent"]
    result = run(responses)

    assert result.mutating_changed_ops == [
        f"{P}Write {skill.path}",
        f"{P}Restart openclaw (skills)",
        f"{P}Reset session bindings when managed skills changed",
    ]


def test_pending_host_steps_restart_the_gateway_before_the_health_check() -> None:
    responses = converged()
    responses[" config check )"] = ["pending"]
    responses[" plugins check )"] = ["pending"]
    result = run(responses)

    assert result.mutating_changed_ops == [
        f"{P}Reconcile the existing OpenClaw gateway config",
        f"{P}Install the official Codex runtime plugin",
        f"{P}Restart openclaw (deploy)",
    ]
    names = [op.name for op in result.ops]
    assert names.index(f"{P}Restart openclaw (deploy)") < names.index(f"{P}Run OpenClaw health check")


def test_new_release_activates_and_rebuilds() -> None:
    responses = converged()
    responses["rev-parse HEAD"] = ["pending"]
    responses[" doctor check )"] = ["pending"]
    result = run(responses)

    assert result.mutating_changed_ops == [
        f"{P}Clone OpenClaw repository",
        f"{P}Build OpenClaw Docker image",
        f"{P}Activate the new image through Doctor",
        f"{P}Restart openclaw (deploy)",
    ]


def test_a_failed_probe_runs_the_step() -> None:
    responses = converged()
    responses[" cron check )"] = ["", "ops-deploy-probe-failed"]
    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Register the weeknotes reminder cron job"]


def test_unported_features_are_refused() -> None:
    with pytest.raises(ValueError, match="heartbeat_recovery_managed"):
        with_variables(openclaw_heartbeat_recovery_managed=True)
    with pytest.raises(ValueError, match="registration_backport_managed"):
        with_variables(openclaw_codex_v2026_9_1_registration_backport_managed=True)


def test_inputs_are_split_by_secrecy() -> None:
    with pytest.raises(ValueError, match="belong to the secret inputs"):
        with_variables(openclaw_gateway_token="token")
    with pytest.raises(ValueError, match="belong to the public inputs"):
        OpenClawSecrets(variables={"openclaw_version": "v1.0.0"})
    with pytest.raises(ValueError, match="not variables of the openclaw_deploy role"):
        with_variables(openclaw_unknown=1)


@pytest.mark.parametrize(
    ("changes", "task"),
    [
        ({"openclaw_telegram_streaming_mode": "fast"}, "Telegram streaming settings"),
        ({"openclaw_homeassistant_allow_domains": ["Light"]}, "Home Assistant allowed domains format"),
        ({"openclaw_agent_model_fallbacks": ["openai/gpt-6.1-sol"]}, "Optional model fallback policy semantics"),
        ({"openclaw_network_mode": "host", "openclaw_bind_host": "0.0.0.0"}, "Gateway network mode"),
        ({"openclaw_paperless_max_limit": 11}, "Paperless base settings"),
    ],
)
def test_the_roles_asserts_refuse(changes: dict[str, Any], task: str) -> None:
    with pytest.raises(ValidationError, match=task):
        with_variables(**changes).role_variables(SECRETS)


def test_short_audio_key_is_refused_without_showing_it() -> None:
    secrets = OpenClawSecrets(variables={**SECRETS.variables, "openclaw_audio_transcription_api_key": "short-key"})
    with pytest.raises(ValidationError, match="Enabled audio transcription settings") as raised:
        CFG.role_variables(secrets)

    assert "short-key" not in str(raised.value)


def test_data_dir_moves_every_path_below_it() -> None:
    resolved = resolve({"openclaw_version": "v2026.10.2", "openclaw_data_dir": "/srv/oc"})

    assert resolved["openclaw_imap_credentials_path"] == "/srv/oc/credentials/imap_accounts.json"
    assert resolved["openclaw_session_state_path"] == "/srv/oc/agents/main/sessions/sessions.json"
    assert resolved["openclaw_site_dir"] == "/home/openclaw/site"
    assert resolved["openclaw_codex_plugin_version"] == "2026.10.2"


def test_semver_comparisons() -> None:
    assert version_at_least("v2026.10.2", "2026.9.7")
    assert not version_at_least("v2026.9.6", "2026.9.7")
    assert version_at_least("v2026.9.1", "2026.9.1")


# -- the build checkout probe ----------------------------------------------------------------


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.mark.parametrize("annotated", [True, False])
def test_source_probe_reads_the_tag_commit(tmp_path: Path, annotated: bool) -> None:
    remote = tmp_path / "remote"
    remote.mkdir()
    git("init", "-q", cwd=remote)
    (remote / "file").write_text("one\n")
    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qam", "one", "--allow-empty", cwd=remote)
    git("add", "file", cwd=remote)
    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "two", cwd=remote)
    tag = ["-a", "-m", "release"] if annotated else []
    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "tag", *tag, "v1.0.0", cwd=remote)
    build = tmp_path / "build"
    variables = {
        "openclaw_build_dir": str(build),
        "openclaw_version": "v1.0.0",
        "openclaw_repo_url": f"file://{remote}",
        "openclaw_git_depth": 1,
        "openclaw_git_single_branch": True,
    }

    def state() -> str:
        return subprocess.run(["sh", "-c", source_state(variables)], capture_output=True, text=True).stdout.strip()

    assert state() == "absent"
    git("clone", "-q", "--depth", "1", "--branch", "v1.0.0", f"file://{remote}", str(build), cwd=tmp_path)
    assert state() == "current"
    (build / "file").write_text("changed\n")
    assert state() == "dirty"
    git("checkout", "-q", "--", "file", cwd=build)
    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "tag", "-f", *tag, "v1.0.0", "HEAD~1", cwd=remote)
    assert state() == "pending"


def test_source_follows_a_changed_repository_url(tmp_path: Path) -> None:
    remotes = []
    for name in ("old", "new"):
        remote = tmp_path / name
        remote.mkdir()
        git("init", "-q", cwd=remote)
        (remote / "file").write_text(f"{name}\n")
        git("add", "file", cwd=remote)
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", name, cwd=remote)
        git("tag", "v1.0.0", cwd=remote)
        remotes.append(remote)
    build = tmp_path / "build"
    git("clone", "-q", "--depth", "1", "--branch", "v1.0.0", f"file://{remotes[0]}", str(build), cwd=tmp_path)
    variables = {
        "openclaw_build_dir": str(build),
        "openclaw_version": "v1.0.0",
        "openclaw_repo_url": f"file://{remotes[1]}",
        "openclaw_git_depth": 1,
        "openclaw_git_single_branch": True,
    }

    def sh(command: str) -> str:
        return subprocess.run(["sh", "-c", command], capture_output=True, text=True, check=True).stdout.strip()

    assert sh(source_state(variables)) == "pending"
    sh(source_command(variables))
    assert sh(source_state(variables)) == "current"
    assert (build / "file").read_text() == "new\n"


# -- the host script -------------------------------------------------------------------------


class Commands:
    """A fake ``subprocess.run`` for the host script: answers by argv prefix, records calls."""

    def __init__(self, answers: dict[tuple[str, ...], tuple[int, str]]) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        for prefix, (code, out) in self.answers.items():
            if tuple(argv[: len(prefix)]) == prefix:
                return subprocess.CompletedProcess(argv, code, out, "")
        return subprocess.CompletedProcess(argv, 0, "", "")


REQUEST = {
    "container": "openclaw-gateway",
    "image": "openclaw:v2026.10.2",
    "site_dir": "/home/openclaw/site",
    "data_dir": DATA,
    "service": "openclaw",
    "workspace_dir": f"{DATA}/workspace",
}
STATE = ("docker", "inspect", "--format", "{{.State.Running}} {{.Config.Image}}")
IMAGE = ("docker", "inspect", "--format", "{{.Config.Image}}")


def test_doctor_runs_only_for_a_new_image(monkeypatch: pytest.MonkeyPatch) -> None:
    script = host_script()
    commands = Commands({IMAGE: (0, "openclaw:v2026.10.2\n")})
    monkeypatch.setattr(script, "run", commands)
    assert script.doctor(REQUEST, True) is False

    commands = Commands({IMAGE: (0, "openclaw:v2026.9.4\n"), ("systemctl", "show"): (0, "loaded\n")})
    monkeypatch.setattr(script, "run", commands)
    assert script.doctor(REQUEST, True) is True
    assert ["systemctl", "stop", "openclaw.service"] in commands.calls
    assert commands.calls[-1][-5:] == ["openclaw:v2026.10.2", "openclaw.mjs", "doctor", "--fix", "--non-interactive"]


def test_cli_shares_the_running_gateways_pid_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    script = host_script()
    monkeypatch.setattr(script, "run", Commands({STATE: (0, "true openclaw:v2026.10.2\n")}))
    argv = script.cli_argv(REQUEST)

    assert argv[:7] == ["docker", "run", "--rm", "--network", "host", "--pid", "container:openclaw-gateway"]
    assert argv[-3:] == ["node", "openclaw:v2026.10.2", "dist/index.js"]
    monkeypatch.setattr(script, "run", Commands({STATE: (0, "true openclaw:v2026.9.4\n")}))
    with pytest.raises(script.StepError, match="different image"):
        script.cli_argv(REQUEST)


def test_plugin_is_reinstalled_only_for_another_version(monkeypatch: pytest.MonkeyPatch) -> None:
    script = host_script()
    request = {**REQUEST, "plugin_id": "codex", "plugin_package": "@openclaw/codex", "plugin_version": "2026.10.2"}
    inspect = {"plugin": {"id": "codex"}, "install": {"resolvedName": "@openclaw/codex", "version": "2026.10.2"}}
    commands = Commands({STATE: (1, ""), ("docker", "run"): (0, json.dumps(inspect))})
    monkeypatch.setattr(script, "run", commands)

    assert script.plugins(request, True) is False
    assert not any("install" in call for call in commands.calls)


def test_plugin_check_verifies_the_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    script = host_script()
    request = {**REQUEST, "plugin_id": "codex", "plugin_package": "@openclaw/codex", "plugin_version": "2026.10.2"}
    other = {"plugin": {"id": "other"}, "install": {"resolvedName": "@other/codex", "version": "2026.10.2"}}
    monkeypatch.setattr(script, "cli_ready", lambda _request: True)
    monkeypatch.setattr(script, "run", Commands({STATE: (1, ""), ("docker", "run"): (0, json.dumps(other))}))

    assert script.plugins(request, False) is True
    with pytest.raises(script.StepError, match="identity or version"):
        script.plugins(request, True)


def cron_list(*jobs: dict[str, Any]) -> tuple[int, str]:
    return 0, json.dumps({"jobs": list(jobs)})


JOB = {
    "id": "j1",
    "name": "weeknotes-reminder",
    "schedule": {"kind": "cron", "expr": "0 9 * * 1-5"},
    "sessionTarget": "main",
    "payload": {"kind": "systemEvent", "text": "/todo reminder"},
}
CRON = {"site_dir": "/home/openclaw/site", "cron": "0 9 * * 1-5", "command": "/todo reminder"}
LIST = (
    "docker",
    "compose",
    "-f",
    "/home/openclaw/site/docker-compose.yml",
    "run",
    "--rm",
    "openclaw-cli",
    "cron",
    "list",
)


@pytest.mark.parametrize(
    ("jobs", "pending"),
    [((JOB,), False), ((), True), ((JOB, {**JOB, "id": "j2"}), True), (({**JOB, "sessionTarget": "isolated"},), True)],
)
def test_cron_drift(monkeypatch: pytest.MonkeyPatch, jobs: tuple[dict[str, Any], ...], pending: bool) -> None:
    script = host_script()
    monkeypatch.setattr(script, "run", Commands({LIST: cron_list(*jobs)}))

    assert script.cron(CRON, False) is pending


def test_drifted_cron_is_removed_then_added(monkeypatch: pytest.MonkeyPatch) -> None:
    script = host_script()
    commands = Commands({LIST: cron_list(JOB, {**JOB, "id": "j2"})})
    monkeypatch.setattr(script, "run", commands)
    monkeypatch.setattr(script.time, "sleep", lambda _: None)

    assert script.cron(CRON, True) is True
    verbs = [call[7:9] for call in commands.calls]
    assert verbs == [["cron", "list"], ["cron", "rm"], ["cron", "rm"], ["cron", "add"]]


def test_legacy_workspace_state_triggers_the_migration(tmp_path: Path) -> None:
    script = host_script()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    request = {**REQUEST, "data_dir": str(tmp_path), "workspace_dir": str(workspace)}
    assert script.legacy_state(request) == []

    (tmp_path / "workspace-attestations").mkdir()
    (tmp_path / "workspace-attestations" / "a.attested").write_text("")
    (tmp_path / "workspace.attested").write_text("")
    assert sorted(Path(path).name for path in script.legacy_state(request)) == ["a.attested", "workspace.attested"]


def test_session_reset_clears_cached_skill_snapshots(tmp_path: Path) -> None:
    script = host_script()
    path = tmp_path / "sessions.json"
    path.write_text(json.dumps({"a": {"skillsSnapshot": {}, "sessionId": "x", "keep": 1}, "b": {"keep": 2}, "c": 3}))

    assert script.session({"path": str(path)}, True) is True
    data = json.loads(path.read_text())
    assert data["a"] == {"keep": 1, "systemSent": False, "abortedLastRun": False, "updatedAt": 0}
    assert data["b"] == {"keep": 2}
    assert script.session({"path": str(path)}, True) is False


# -- removal ---------------------------------------------------------------------------------


R = "Remove OpenClaw | "


def units(active: str = "inactive", enabled: str = "disabled") -> dict[str, list[str]]:
    lines = ["Id=openclaw.service", "LoadState=loaded", f"ActiveState={active}", f"UnitFileState={enabled}", "---"]
    return {"systemctl show --property Id": lines}


def test_removal_requires_confirmation() -> None:
    result = run_deploy_fake(deploy_openclaw_remove, OpenClawRemoveConfig(), responses=fakehost.UBUNTU)

    assert not result.succeeded
    assert "openclaw_remove_confirm" in str(result.error)


def test_removal_of_an_absent_install_changes_nothing() -> None:
    cfg = OpenClawRemoveConfig(confirm=True, variables={"openclaw_data_dir": DATA})
    result = run_deploy_fake(deploy_openclaw_remove, cfg, responses={**fakehost.UBUNTU, **units()})

    assert result.succeeded, result.error
    assert result.changed_ops == []


def test_removal_keeps_data_image_and_account_by_default() -> None:
    present = {
        f"test -e {path} && echo yes": ["yes"]
        for path in (
            "/etc/systemd/system/openclaw.service",
            "/etc/logrotate.d/openclaw",
            "/home/openclaw/site/docker-compose.yml",
            "/home/openclaw/site",
            "/home/openclaw/build/openclaw",
            "/home/openclaw/logs",
            "/etc/traefik/dynamic/openclaw.yml",
            DATA,
        )
    }
    responses = {
        **fakehost.UBUNTU,
        **units("active", "enabled"),
        **present,
        "docker container inspect openclaw-gateway": ["present"],
        "getent passwd openclaw": ["openclaw:x:999:999::/home/openclaw:/usr/sbin/nologin"],
    }
    cfg = OpenClawRemoveConfig(confirm=True, variables={"openclaw_data_dir": DATA})
    result = run_deploy_fake(deploy_openclaw_remove, cfg, responses=responses)

    assert result.succeeded, result.error
    assert result.changed_ops == [
        f"{R}Stop openclaw.service",
        f"{R}Disable openclaw.service",
        f"{R}Remove /etc/systemd/system/openclaw.service",
        f"{R}Reload systemd after removing the OpenClaw unit",
        f"{R}Remove /etc/logrotate.d/openclaw",
        f"{R}Remove OpenClaw compose stack (best effort)",
        f"{R}Remove container openclaw-gateway (best effort)",
        f"{R}Remove /home/openclaw/site/docker-compose.yml",
        f"{R}Remove /home/openclaw/site",
        f"{R}Remove /home/openclaw/build/openclaw",
        f"{R}Remove /home/openclaw/logs",
        f"{R}Remove /etc/traefik/dynamic/openclaw.yml",
    ]
    commands = "\n".join(result.executed_commands)
    assert f"rm -rf {DATA}" not in commands
    assert "userdel" not in commands


def test_removal_toggles_are_not_variables() -> None:
    with pytest.raises(ValueError, match="openclaw_remove_data"):
        OpenClawRemoveConfig(variables={"openclaw_remove_data": True})


# -- Nyxmon ----------------------------------------------------------------------------------


ROWS = (
    {
        "name": "OpenClaw Gateway Health (JSON Metrics)",
        "check_type": "json-metrics",
        "url": "http://127.0.0.1:9104/.well-known/openclaw-health",
        "check_interval": 120,
        "data": {"url": "http://127.0.0.1:9104/.well-known/openclaw-health", "auth": {"password": "pw"}},
    },
)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_converged_nyxmon_checks_are_left_alone() -> None:
    row = ROWS[0]
    state = json.dumps([row["check_type"], row["url"], row["check_interval"], json.dumps(row["data"], sort_keys=True)])
    responses = {
        "if test -f /home/nyxmon/site/db.sqlite3; then echo present": ["present"],
        "NYXMON_SERVICE_NAME=openclaw python3 -I -c": [
            "service present",
            f"check {digest(str(row['name']))} {digest(state)}",
        ],
    }
    result = run_deploy_fake(deploy_openclaw_nyxmon_checks, OpenClawNyxmonChecks(checks=ROWS), responses=responses)

    assert result.succeeded, result.error
    assert result.changed_ops == []


def test_nyxmon_checks_upsert_carries_the_login_on_stdin_only() -> None:
    responses = {
        "if test -f /home/nyxmon/site/db.sqlite3; then echo present": ["present"],
        "NYXMON_SERVICE_NAME=openclaw python3 -I -c": ["service absent"],
    }
    result = run_deploy_fake(deploy_openclaw_nyxmon_checks, OpenClawNyxmonChecks(checks=ROWS), responses=responses)

    assert result.changed_ops == ["OpenClaw Nyxmon checks | Upsert Nyxmon OpenClaw json-metrics checks"]
    assert '"password": "pw"' not in result.all_text()


def test_missing_nyxmon_database_skips_the_checks() -> None:
    result = run_deploy_fake(deploy_openclaw_nyxmon_checks, OpenClawNyxmonChecks(checks=ROWS), responses={})

    assert result.succeeded
    assert result.changed_ops == []
