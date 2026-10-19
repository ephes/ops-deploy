"""Deploy-level scenarios for delve against the fake connector."""

import base64
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.services.delve import DelveConfig, build_delved, deploy_delve
from ops_deploy.services.delve.deploy import (
    DETECTOR_API_KEY_PATTERN,
    STOREKIT_ROOT_CERTS,
    TEMPLATE_PACKAGE,
    analysis_secret_files,
    render_env,
    render_route,
    traefik_config,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

REF = SecretRef("secrets/prod/delve.yml")
SECRET_VALUES = {"session_secret": "delve-fixture-session-secret", "dogfood_token": "delve-fixture-dogfood"}
BINARY = "\x7fELF fixture delved v1\n"
PEM = "/etc/delve/apple-storekit-root-certs.pem"
STAGED = "/opt/delve/.delved.ops-deploy"
ENV = "/etc/delve/delve.env"
UNIT = "/etc/systemd/system/delve.service"
COLLECTOR = "/etc/systemd/system/delve-discovery-collect"
ROUTE = "/etc/traefik/dynamic/delve.yml"
APT = {**fakehost.LINUX, "command -v apt-get": ["/usr/bin/apt-get"]}
READ_ONLY = ["Deploy delve | Wait for port 127.0.0.1:10026", "Deploy delve | Check delve /health"]


@pytest.fixture
def cfg(tmp_path: Path) -> DelveConfig:
    binary = tmp_path / "delved"
    binary.write_text(BINARY)
    return DelveConfig(
        binary_path=binary,
        secrets=REF,
        storekit_root_certs_path=PEM,
        storekit_bundle_id="org.example.player",
        storekit_product_ids="org.example.player.pro",
        apple_client_id="org.example.player",
        profile_legacy_reregister=True,
    )


def values(**changes: str) -> SecretValues:
    return SecretValues(REF, {**SECRET_VALUES, **changes})


def converged(cfg: DelveConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where delve is fully deployed; ``drift`` overrides file content by path."""

    content = {
        "/opt/delve/delved": BINARY,
        PEM: STOREKIT_ROOT_CERTS.read_text(),
        ENV: render_env(cfg, secrets).reveal().decode(),
        UNIT: render(TEMPLATE_PACKAGE, "delve.service.j2", cfg=cfg),
        f"{COLLECTOR}.service": render(TEMPLATE_PACKAGE, "delve-discovery-collect.service.j2", cfg=cfg),
        f"{COLLECTOR}.timer": render(TEMPLATE_PACKAGE, "delve-discovery-collect.timer.j2", cfg=cfg),
        ROUTE: render_route(cfg, traefik_config(cfg), None),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **APT,
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("ca-certificates", "curl"),
        **fakehost.system_account("delve", "/var/lib/delve", shell="/usr/sbin/nologin"),
        **fakehost.stat("/var/lib/delve", user="delve", mode="drwxr-x---"),
        **fakehost.directory("/opt/delve"),
        **fakehost.stat("/etc/delve", group="delve", mode="drwxr-x---"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/traefik/dynamic"),
    }
    for path, text in content.items():
        mode = {"/opt/delve/delved": "-rwxr-xr-x", ENV: "-rw-r-----"}.get(path, "-rw-r--r--")
        responses.update(fakehost.file(path, text, mode=mode))
        if path in (ENV, PEM):
            responses.update(fakehost.stat(path, group="delve", mode=mode))
    responses.update(fakehost.service("delve.service"))
    responses.update(fakehost.service("delve-discovery-collect.timer", running=False, enabled=False))
    return responses


def deploy(cfg: DelveConfig, secrets: SecretValues, responses: dict[str, Any] | None = None) -> FakeRun:
    run = run_deploy_fake(deploy_delve, cfg, secrets, responses=APT if responses is None else responses)
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: DelveConfig) -> None:
    run = deploy(cfg, values())

    commands = run.executed_commands
    assert "useradd -d /var/lib/delve -s /usr/sbin/nologin -g delve -r -M delve" in commands
    assert run.upload(STAGED) == BINARY.encode()
    assert "mv -f /opt/delve/.delved.ops-deploy /opt/delve/delved" in commands
    assert run.upload(PEM) == STOREKIT_ROOT_CERTS.read_bytes()
    assert run.upload(UNIT).decode().startswith("# Managed by Ansible (delve_deploy)")
    assert "systemctl start delve.service" in commands
    assert "systemctl restart delve.service" not in commands
    # The collector timer stays disabled and stopped by default.
    assert not any("start delve-discovery-collect" in c or "enable delve-discovery-collect" in c for c in commands)
    # The env file goes over stdin via secret_file, never as an upload.
    assert len(run.stdin) == 1
    assert ENV not in run.uploaded_paths
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY


def test_second_run_changes_nothing_mutating(cfg: DelveConfig) -> None:
    run = deploy(cfg, values(), converged(cfg, values()))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []


@pytest.mark.parametrize(
    ("path", "op"),
    [
        ("/opt/delve/delved", "Install delved"),
        (PEM, "Install StoreKit root certificates"),
    ],
)
def test_new_binary_or_certificates_restart_only_delve(cfg: DelveConfig, path: str, op: str) -> None:
    run = deploy(cfg, values(), converged(cfg, values(), **{path: "old\n"}))

    assert run.mutating_changed_ops == [f"Deploy delve | {op}", "Deploy delve | Restart delve.service"]


def test_new_binary_is_staged_and_renamed_over_the_running_one(cfg: DelveConfig) -> None:
    # Writing into a running executable fails with ETXTBSY; a rename does not.
    run = deploy(cfg, values(), converged(cfg, values(), **{"/opt/delve/delved": "old\n"}))

    assert run.uploaded_paths == [STAGED]
    assert "mv -f /opt/delve/.delved.ops-deploy /opt/delve/delved" in run.executed_commands


def test_binary_mode_drift_is_fixed_in_place(cfg: DelveConfig) -> None:
    responses = converged(cfg, values())
    responses.update(fakehost.stat("/opt/delve/delved", mode="-rwxrwxrwx"))

    run = deploy(cfg, values(), responses)

    assert run.uploads == []
    assert "chmod 755 /opt/delve/delved" in run.executed_commands
    assert run.mutating_changed_ops == ["Deploy delve | Install delved", "Deploy delve | Restart delve.service"]


def test_secret_rotation_rewrites_env_and_restarts(cfg: DelveConfig) -> None:
    rotated = values(session_secret="rotated-fixture-session-secret")

    run = deploy(cfg, rotated, converged(cfg, values()))

    assert run.mutating_changed_ops == ["Deploy delve | Write delve.env", "Deploy delve | Restart delve.service"]
    assert "rotated-fixture-session-secret" not in run.all_text()


def test_unit_change_reloads_and_restarts(cfg: DelveConfig) -> None:
    run = deploy(cfg, values(), converged(cfg, values(), **{UNIT: "[Unit]\n"}))

    assert run.mutating_changed_ops == [
        "Deploy delve | Install systemd unit delve.service",
        "Deploy delve | Reload systemd for delve.service",
        "Deploy delve | Restart delve.service",
    ]


def test_collector_unit_change_reloads_without_restarting_delve(cfg: DelveConfig) -> None:
    run = deploy(cfg, values(), converged(cfg, values(), **{f"{COLLECTOR}.timer": "[Timer]\n"}))

    assert run.mutating_changed_ops == [
        "Deploy delve | Install systemd unit delve-discovery-collect.timer",
        "Deploy delve | Reload systemd for delve-discovery-collect",
    ]


def test_enabled_timer_is_enabled_and_started(cfg: DelveConfig) -> None:
    on = cfg.model_copy(update={"discovery_collector_timer_enabled": True})

    run = deploy(on, values(), converged(on, values()))

    assert run.mutating_changed_ops == ["Deploy delve | Set delve-discovery-collect.timer state"]
    assert "systemctl start delve-discovery-collect.timer" in run.executed_commands
    assert "systemctl enable delve-discovery-collect.timer" in run.executed_commands


def test_route_change_writes_the_file_without_restarting_traefik(cfg: DelveConfig) -> None:
    run = deploy(cfg, values(), converged(cfg, values(), **{ROUTE: "http: {}\n"}))

    assert run.mutating_changed_ops == ["Deploy delve | Write Traefik route delve"]


def test_traefik_disabled_writes_no_route(cfg: DelveConfig) -> None:
    run = deploy(cfg.model_copy(update={"traefik_enabled": False}), values())

    assert ROUTE not in run.uploaded_paths


def test_public_health_check_goes_through_traefik_on_loopback(cfg: DelveConfig) -> None:
    run = deploy(cfg.model_copy(update={"public_health_check": True}), values(), converged(cfg, values()))

    assert run.changed_ops == [*READ_ONLY, "Deploy delve | Check delve /health through Traefik"]
    check = run.executed_commands[-1]
    assert "--resolve delve.example.com:443:127.0.0.1 https://delve.example.com/health" in check


def test_health_check_failure_fails_the_deploy(cfg: DelveConfig) -> None:
    responses = {**converged(cfg, values()), "sh -c 'for i in $(seq 1 10)": {"success": False}}

    run = run_deploy_fake(deploy_delve, cfg, values(), responses=responses)

    assert not run.succeeded


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: DelveConfig, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, values())
    used = values(dogfood_token="rotated-fixture-dogfood") if scenario == "rotated" else values()

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-dogfood"):
        assert value not in text


def test_env_file_rides_on_stdin_only(cfg: DelveConfig) -> None:
    run = deploy(cfg, values())

    ((command, payload),) = run.stdin
    assert SECRET_VALUES["session_secret"] not in command
    assert SECRET_VALUES["session_secret"].encode() in base64.b64decode("".join(payload.split()))


def test_dogfood_token_is_optional(cfg: DelveConfig) -> None:
    env = render_env(cfg, SecretValues(REF, {"session_secret": "s" * 16})).reveal().decode()

    assert "DELVE_DOGFOOD_TOKEN" not in env
    assert 'DELVE_PROFILE_LEGACY_REREGISTER="true"' in env
    assert "DELVE_APPLE_SERVER_NOTIFICATIONS" not in env


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"session_secret": "short-secret"}, "at least 16"),
        ({"dogfood_token": 'a"b'}, "dogfood_token must be a single line"),
        ({"session_secret": "line-one-0123456\nX=1"}, "session_secret must be a single line"),
    ],
)
def test_bad_secrets_fail_before_any_operation(cfg: DelveConfig, changes: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message) as excinfo:
        run_deploy_fake(deploy_delve, cfg, values(**changes), responses=APT)
    for value in changes.values():
        assert value not in str(excinfo.value)


def test_missing_secret_key_fails(cfg: DelveConfig) -> None:
    with pytest.raises(KeyError, match="session_secret"):
        run_deploy_fake(deploy_delve, cfg, SecretValues(REF, {"dogfood_token": "x"}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"storekit_root_certs_path": PEM},
        {"apple_server_notifications": True},
        {"discovery_collector_concurrency": 1},
        {"discovery_collector_concurrency": 9},
        {"discovery_poll_interval_seconds": 21599},
        {"discovery_poll_interval_seconds": 86401},
        {"discovery_poll_jitter_seconds": -1},
        {"discovery_episode_ttl_seconds": 0},
        {"discovery_max_items_per_feed": 501},
        {"discovery_max_sources_per_run": 101},
        {"public_url": 'https://x"y'},
        {"admin_emails": "a@b c"},
        {"data_dir": "relative"},
        {"traefik_entrypoints": ()},
    ],
)
def test_role_validations(tmp_path: Path, overrides: dict[str, Any]) -> None:
    binary = tmp_path / "delved"
    binary.write_text(BINARY)
    with pytest.raises(ConfigValidationError):
        DelveConfig(binary_path=binary, secrets=REF, **overrides)


def test_binary_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="binary_path"):
        DelveConfig(binary_path=tmp_path / "missing", secrets=REF)


def test_build_cross_compiles_like_the_playbook(tmp_path: Path) -> None:
    (tmp_path / "src" / "cmd" / "delved").mkdir(parents=True)
    calls: list[tuple[Sequence[str], Path, dict[str, str]]] = []

    def runner(argv: Sequence[str], cwd: Path, env: dict[str, str]) -> None:
        calls.append((argv, cwd, env))
        Path(argv[argv.index("-o") + 1]).write_text(BINARY)

    out = build_delved(tmp_path / "src", tmp_path / "delved", runner=runner)

    assert out.read_text() == BINARY
    ((argv, cwd, env),) = calls
    assert list(argv) == [
        "go",
        "build",
        "-trimpath",
        "-ldflags=-s",
        "-ldflags=-w",
        "-o",
        str(tmp_path / "delved"),
        "./cmd/delved",
    ]
    assert cwd == tmp_path / "src"
    assert env == {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}


def test_build_resolves_a_relative_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "src" / "cmd" / "delved").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)

    def runner(argv: Sequence[str], cwd: Path, env: dict[str, str]) -> None:
        Path(argv[argv.index("-o") + 1]).write_text(BINARY)

    assert build_delved(Path("src"), Path("delved"), runner=runner) == tmp_path / "delved"


def test_curl_is_installed_for_the_checks(cfg: DelveConfig) -> None:
    run = deploy(cfg, values())

    assert any(c.endswith("install ca-certificates curl") for c in run.executed_commands)


def test_build_refuses_a_non_checkout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a delve backend checkout"):
        build_delved(tmp_path, tmp_path / "delved", runner=lambda *_: None)


# --- Server ad analysis -------------------------------------------------------

MEDIA = "/var/lib/delve-smart-skip-media"
PROFILE = "/etc/delve/smart-skip-analysis-profile.json"
TOKEN_FILE = "/etc/delve/voxhelm-token"
KEY_FILE = "/etc/delve/detector-api-key"
PROFILE_JSON = '{"taxonomy": "server-taxonomy-v1"}\n'
ANALYSIS_SECRETS = {"voxhelm_token": "v" * 64, "detector_api_key": "d" * 64}


@pytest.fixture
def analysis(cfg: DelveConfig, tmp_path: Path) -> DelveConfig:
    profile = tmp_path / "profile.json"
    profile.write_text(PROFILE_JSON)
    return cfg.model_copy(
        update={
            "smart_skip_analysis": True,
            "smart_skip_analysis_profile_src": profile,
            "analysis_media_dir": PurePosixPath(MEDIA),
            "analysis_media_disk_cap_bytes": 20000000000,
            "ffprobe_path": PurePosixPath("/usr/bin/ffprobe"),
            "ffmpeg_path": PurePosixPath("/usr/bin/ffmpeg"),
            "voxhelm_url": "http://studio.example.ts.net:8787",
            "detector_url": "http://studio.example.ts.net:8177",
        }
    )


def analysis_values(**changes: str) -> SecretValues:
    return values(**{**ANALYSIS_SECRETS, **changes})


def converged_analysis(cfg: DelveConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    responses = converged(cfg, secrets)
    responses.update(fakehost.deb_installed("ca-certificates", "curl", "ffmpeg"))
    responses.update(fakehost.stat(MEDIA, user="delve", mode="drwx------"))
    content = {
        PROFILE: PROFILE_JSON,
        TOKEN_FILE: f"{secrets['voxhelm_token']}\n",
        KEY_FILE: f"{secrets['detector_api_key']}\n",
        **drift,
    }
    for path, text in content.items():
        responses.update(fakehost.file(path, text, mode="-rw-r-----"))
        responses.update(fakehost.stat(path, group="delve", mode="-rw-r-----"))
    return responses


def test_analysis_first_run_installs_its_pieces(analysis: DelveConfig) -> None:
    run = deploy(analysis, analysis_values())

    commands = run.executed_commands
    assert any(c.endswith("install ca-certificates curl ffmpeg") for c in commands)
    assert f"mkdir -p {MEDIA}" in commands
    assert f"chmod 700 {MEDIA}" in commands
    assert f"chown delve:delve {MEDIA}" in commands
    assert run.upload(PROFILE) == PROFILE_JSON.encode()
    assert TOKEN_FILE not in run.uploaded_paths
    assert KEY_FILE not in run.uploaded_paths
    # delve.env, the token file and the key file, each over stdin.
    assert len(run.stdin) == 3
    decoded = [base64.b64decode("".join(payload.split())) for _command, payload in run.stdin]
    assert decoded[1:] == [f"{'v' * 64}\n".encode(), f"{'d' * 64}\n".encode()]
    unit = run.upload(UNIT).decode()
    assert "ReadWritePaths=/var/lib/delve\n" in unit
    assert f"ReadWritePaths={MEDIA}\n" in unit


def test_analysis_env_names_files_never_secrets(analysis: DelveConfig) -> None:
    env = render_env(analysis, analysis_values()).reveal().decode()

    assert 'DELVE_SMART_SKIP_ANALYSIS="true"\n' in env
    assert f'DELVE_SMART_SKIP_ANALYSIS_PROFILE="{PROFILE}"\n' in env
    assert f'DELVE_ANALYSIS_MEDIA_DIR="{MEDIA}"\n' in env
    assert 'DELVE_ANALYSIS_MEDIA_DISK_CAP_BYTES="20000000000"\n' in env
    assert f'DELVE_VOXHELM_TOKEN_FILE="{TOKEN_FILE}"\n' in env
    assert f'DELVE_DETECTOR_API_KEY_FILE="{KEY_FILE}"\n' in env
    assert "v" * 64 not in env
    assert "d" * 64 not in env
    assert "DELVE_VOXHELM_POLL_SECONDS" not in env


def test_analysis_second_run_changes_nothing_mutating(analysis: DelveConfig) -> None:
    run = deploy(analysis, analysis_values(), converged_analysis(analysis, analysis_values()))

    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert run.stdin == []


@pytest.mark.parametrize(
    ("path", "op"),
    [
        (PROFILE, "Install the server ad analysis profile"),
        (TOKEN_FILE, "Write the voxhelm producer token file"),
        (KEY_FILE, "Write the detector API key file"),
    ],
)
def test_analysis_file_change_restarts_delve(analysis: DelveConfig, path: str, op: str) -> None:
    run = deploy(analysis, analysis_values(), converged_analysis(analysis, analysis_values(), **{path: "old\n"}))

    assert run.mutating_changed_ops == [f"Deploy delve | {op}", "Deploy delve | Restart delve.service"]


def test_rotated_analysis_secret_is_never_recorded(analysis: DelveConfig) -> None:
    rotated = analysis_values(detector_api_key="r" * 48)

    run = deploy(analysis, rotated, converged_analysis(analysis, analysis_values()))

    assert run.mutating_changed_ops == [
        "Deploy delve | Write the detector API key file",
        "Deploy delve | Restart delve.service",
    ]
    text = run.all_text() + repr(run.ops)
    for value in ("r" * 48, "v" * 64, "d" * 64):
        assert value not in text


def test_switching_the_analysis_off_removes_the_secret_files(analysis: DelveConfig, cfg: DelveConfig) -> None:
    host = converged_analysis(analysis, analysis_values())
    host.update(converged(cfg, values()))  # env and unit of the switched-off config

    run = deploy(cfg, values(), host)

    assert run.mutating_changed_ops == [
        "Deploy delve | Remove the voxhelm producer token file",
        "Deploy delve | Remove the detector API key file",
    ]
    assert f"rm -f {TOKEN_FILE}" in run.executed_commands
    assert f"rm -f {KEY_FILE}" in run.executed_commands
    # The media directory and the profile stay.
    assert not any(MEDIA in c or PROFILE in c for c in run.executed_commands)


def test_media_dir_inside_the_data_dir_needs_no_extra_write_path(analysis: DelveConfig) -> None:
    inside = analysis.model_copy(update={"analysis_media_dir": PurePosixPath("/var/lib/delve/smart-skip-media")})

    unit = render(TEMPLATE_PACKAGE, "delve.service.j2", cfg=inside)

    assert [line for line in unit.splitlines() if line.startswith("ReadWritePaths=")] == [
        "ReadWritePaths=/var/lib/delve"
    ]


def test_without_urls_no_secret_is_needed(analysis: DelveConfig) -> None:
    bare = analysis.model_copy(update={"voxhelm_url": "", "detector_url": ""})

    run = deploy(bare, values())

    assert len(run.stdin) == 1
    env = render_env(bare, values()).reveal().decode()
    assert "DELVE_VOXHELM" not in env
    assert "DELVE_DETECTOR" not in env


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"voxhelm_token": "CHANGEME"}, "voxhelm_token must be a single line of at least 32"),
        ({"detector_api_key": "short-key"}, "detector_api_key must be a single line of at least 32"),
        ({"detector_api_key": "x" * 40 + "\ny"}, "detector_api_key must be a single line"),
        # llama-server reads a key-file line starting with "#" as a comment.
        ({"detector_api_key": "#" + "k" * 39}, "detector_api_key must be at least 32 of"),
        ({"detector_api_key": "k" * 20 + " " + "k" * 20}, "detector_api_key must be at least 32 of"),
        ({"detector_api_key": "k" * 39 + ","}, "detector_api_key must be at least 32 of"),
    ],
)
def test_bad_analysis_secrets_fail_before_any_operation(
    analysis: DelveConfig, changes: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message) as excinfo:
        run_deploy_fake(deploy_delve, analysis, analysis_values(**changes), responses=APT)
    for value in changes.values():
        if value != "CHANGEME":  # the placeholder is named, a value never is
            assert value not in str(excinfo.value)


def test_missing_analysis_secret_fails(analysis: DelveConfig) -> None:
    with pytest.raises(KeyError, match="detector_api_key"):
        run_deploy_fake(deploy_delve, analysis, values(voxhelm_token="v" * 64), responses=APT)


@pytest.mark.parametrize(
    "overrides",
    [
        {"smart_skip_analysis": True},  # no profile
        {"smart_skip_analysis": True, "smart_skip_analysis_profile_src": "missing.json"},
        {"voxhelm_url": "http://studio.example.ts.net:8787/v1"},
        {"detector_url": "http://user:pw@studio:8177"},
        {"detector_url": "studio:8177"},
        {"analysis_media_dir": "smart-skip-media"},
        {"analysis_media_dir": "/var/lib/delve media"},
        {"analysis_media_disk_cap_bytes": 0},
        {"detector_timeout_seconds": 0},
        {"ffprobe_path": "ffprobe"},
    ],
)
def test_analysis_validations(tmp_path: Path, overrides: dict[str, Any]) -> None:
    binary = tmp_path / "delved"
    binary.write_text(BINARY)
    with pytest.raises(ConfigValidationError):
        DelveConfig(binary_path=binary, secrets=REF, **overrides)


@pytest.mark.parametrize("text", ["not json\n", "[1, 2]\n"])
def test_profile_must_be_a_json_object(tmp_path: Path, text: str) -> None:
    binary = tmp_path / "delved"
    binary.write_text(BINARY)
    profile = tmp_path / "profile.json"
    profile.write_text(text)
    with pytest.raises(ConfigValidationError, match="JSON object"):
        DelveConfig(binary_path=binary, secrets=REF, smart_skip_analysis=True, smart_skip_analysis_profile_src=profile)


def test_media_dir_must_not_be_the_data_dir(tmp_path: Path) -> None:
    binary = tmp_path / "delved"
    binary.write_text(BINARY)
    profile = tmp_path / "profile.json"
    profile.write_text(PROFILE_JSON)
    with pytest.raises(ConfigValidationError, match="data directory"):
        DelveConfig(
            binary_path=binary,
            secrets=REF,
            smart_skip_analysis=True,
            smart_skip_analysis_profile_src=profile,
            analysis_media_dir="/var/lib/delve/",
        )


@pytest.mark.parametrize("key", ["0123456789abcdef" * 4, "A" * 32, "abc-._~+/=" * 4, " " + "k" * 40 + " "])
def test_detector_keys_llama_server_reads_whole_are_accepted(analysis: DelveConfig, key: str) -> None:
    contents = analysis_secret_files(analysis, analysis_values(detector_api_key=key))

    assert contents["detector_api_key"].reveal() == f"{key.strip()}\n".encode()


def test_detector_key_pattern_is_the_roles() -> None:
    # ops-library's llama_server_deploy / delve_deploy use the same string.
    assert DETECTOR_API_KEY_PATTERN == r"^[A-Za-z0-9._~+/=-]{32,}\Z"
