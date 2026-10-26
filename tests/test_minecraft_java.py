"""Minecraft controller validation, host guard, secret flow and rollout."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.services.minecraft_java import MinecraftJavaConfig, deploy_minecraft_java
from ops_deploy.services.minecraft_java.deploy import guard_command, rendered, validate_secrets
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

RCON_FIXTURE = "fixture-rcon-password"


def config(**changes: Any) -> MinecraftJavaConfig:
    return MinecraftJavaConfig.model_validate(
        {
            "secrets": SecretRef("secrets/minecraft.yml"),
            "eula_agreed": True,
            "server_jar_url": "https://example.org/server.jar",
            "server_jar_sha256": "a" * 64,
            "firewall_allowed_networks": ["192.0.2.0/24"],
            **changes,
        }
    )


def values(cfg: MinecraftJavaConfig) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {"rcon_password": RCON_FIXTURE})


@pytest.mark.parametrize(
    "change",
    [
        {"eula_agreed": False},
        {"server_jar_sha256": "bad"},
        {"server_jar_url": None},
        {"loader_mode": "forge"},
        {"mods_enabled": True},
        {"port": 25575},
        {"world_name": "../world"},
        {"home": "/opt/../etc"},
        {"extra_args": "$(touch /tmp/pwn)"},
        {"firewall_allowed_networks": []},
        {"firewall_allowed_networks": ["bad network"]},
        {"motd": "server\nrcon.password=bad"},
        {"motd": " leading space"},
        {"seed": " leading space"},
        {"motd": "café"},
        {"site_path": "/tmp/server name"},
    ],
)
def test_invalid_config_is_refused(change: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        config(**change)


@pytest.mark.parametrize(
    "password", ["short", "CHANGEME", "secret\nline", 'secret"quote', "secret\\slash", "secret with space"]
)
def test_ambiguous_password_is_refused_without_echo(password: str) -> None:
    cfg = config()
    assert cfg.secrets is not None
    with pytest.raises(ValueError, match="safe ASCII") as exc:
        validate_secrets(SecretValues(cfg.secrets, {"rcon_password": password}))
    assert password not in str(exc.value)


@pytest.mark.parametrize(
    ("previous", "world", "override", "ok"),
    [
        (None, "world", False, False),
        ("vanilla", "world", False, False),
        ("forge", "world", False, True),
        ("vanilla", "new-world", False, True),
        ("vanilla", "world", True, True),
    ],
)
def test_production_guard_checks_existing_world_without_leaking_properties(
    tmp_path: Path,
    previous: str | None,
    world: str,
    override: bool,
    ok: bool,
) -> None:
    if previous is not None:
        (tmp_path / ".loader_mode").write_text(previous + "\n")
    (tmp_path / "server.properties").write_text("level-name=world\nrcon.password=private-fixture\n")
    cfg = config(
        site_path=tmp_path,
        home=str(tmp_path.parent),
        loader_mode="forge",
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://example.org/forge.jar",
        forge_installer_sha256="b" * 64,
        world_name=world,
        allow_mode_switch_same_world=override,
    )
    result = subprocess.run(shlex.split(guard_command(cfg)), capture_output=True, text=True, check=False)
    assert (result.returncode == 0) is ok
    assert "private-fixture" not in result.stdout + result.stderr


def converged(cfg: MinecraftJavaConfig) -> dict[str, Any]:
    secrets = values(cfg)
    responses = {
        **fakehost.LINUX,
        **fakehost.system_account(cfg.user, cfg.home),
        **fakehost.apt_cache_fresh(),
        **fakehost.deb_installed("openjdk-21-jre-headless", "build-essential", "git", "ufw", "curl", "ca-certificates"),
        **fakehost.service("minecraft-java.service"),
        **fakehost.directory("/etc/systemd/system"),
        guard_command(cfg): [
            "safe " + json.dumps({"loader_mode": cfg.loader_mode, "world_name": cfg.world_name}, sort_keys=True)
        ],
        "minecraft-config-state": ["current"],
        "/usr/local/bin/mcrcon -v": ["mcrcon 0.7.2"],
        "LC_ALL=C ufw status": ["Status: active", "fixture rules"],
        "LC_ALL=C ufw show added": ["ufw deny 25575/tcp", "ufw allow from 192.0.2.0/24 to any port 25565 proto tcp"],
        "sha256sum /opt/minecraft/server/server.jar": ["a" * 64 + "  /opt/minecraft/server/server.jar"],
        **fakehost.file("/usr/local/bin/mcrcon", "binary", mode="-rwxr-xr-x"),
    }
    for path in (cfg.home, str(cfg.site_path), str(cfg.site_path / "logs")):
        responses.update(fakehost.directory(path, user=cfg.user))
    for name, template, mode in (("server.properties", "server.properties.j2", "-rw-r-----"),):
        responses.update(
            fakehost.file(str(cfg.site_path / name), rendered(cfg, template, secrets), user=cfg.user, mode=mode)
        )
    responses.update(
        fakehost.file(
            cfg.home + "/.env", rendered(cfg, "minecraft-java.env.j2", secrets), user=cfg.user, mode="-rw-------"
        )
    )
    responses.update(fakehost.file(str(cfg.site_path / ".loader_mode"), "vanilla\n", user=cfg.user))
    responses.update(
        fakehost.file(
            str(cfg.site_path / ".loader_state.json"),
            json.dumps({"loader_mode": cfg.loader_mode, "world_name": cfg.world_name}, sort_keys=True) + "\n",
            user=cfg.user,
        )
    )
    responses.update(
        fakehost.file(
            str(cfg.site_path / "eula.txt"),
            "# By setting eula=true you are accepting the Minecraft EULA\n# https://aka.ms/MinecraftEULA\neula=true\n",
            user=cfg.user,
        )
    )
    responses.update(
        fakehost.file("/etc/systemd/system/minecraft-java.service", rendered(cfg, "minecraft-java.service.j2", secrets))
    )
    responses.update(fakehost.stat(str(cfg.site_path / "server.jar"), user=cfg.user))
    return responses


def test_converged_has_no_mutations_and_never_touches_backups() -> None:
    cfg = config()
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=converged(cfg))
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops, run.mutating_changed_ops
    assert "backup" not in "\n".join(run.executed_commands)
    assert "fixture-rcon-password" not in "\n".join(run.executed_commands)


def test_changed_properties_restart_and_secret_stays_on_stdin() -> None:
    cfg = config()
    responses = {"/server.properties properties 0640": ["pending"], **converged(cfg)}
    responses["sha256sum /opt/minecraft/server/server.properties "] = [
        hashlib.sha256(b"old").hexdigest() + "  /opt/minecraft/server/server.properties"
    ]
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    assert any("restart" in command for command in run.executed_commands)
    assert "fixture-rcon-password" not in "\n".join(run.executed_commands)


def test_mode_guard_failure_precedes_all_operations() -> None:
    cfg = config()
    with pytest.raises(ValueError, match="guard did not pass"):
        run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses={guard_command(cfg): ["unsafe"]})


def test_converged_forge_and_mods_have_no_mutations() -> None:
    cfg = config(
        loader_mode="forge",
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://example.org/forge.jar",
        forge_installer_sha256="b" * 64,
        mods_enabled=True,
        mods=[{"name": "example", "url": "https://example.org/example.jar", "sha256": "c" * 64}],
    )
    responses = converged(cfg)
    secrets = values(cfg)
    responses["python3 -c 'import pathlib,sys; p="] = ["yes"]
    for target, template, mode in (
        ("user_jvm_args.txt", "user_jvm_args.txt.j2", "-rw-r--r--"),
        ("start-forge.sh", "start-forge.sh.j2", "-rwxr-xr-x"),
    ):
        responses.update(
            fakehost.file(str(cfg.site_path / target), rendered(cfg, template, secrets), user=cfg.user, mode=mode)
        )
    responses.update(fakehost.file(str(cfg.site_path / ".loader_mode"), "forge\n", user=cfg.user))
    responses.update(fakehost.file(str(cfg.site_path / ".forge_version"), "1.20.1-47.4.0\n", user=cfg.user))
    responses.update(
        fakehost.file(str(cfg.site_path / ".forge_installer_checksum"), "sha256:" + "b" * 64 + "\n", user=cfg.user)
    )
    responses.update(fakehost.stat(str(cfg.site_path / "run.sh"), user=cfg.user, mode="-rwxr-xr-x"))
    responses.update(fakehost.directory(str(cfg.site_path / "mods"), user=cfg.user))
    responses.update(fakehost.stat(str(cfg.site_path / "mods/example.jar"), user=cfg.user))
    responses["sha256sum /opt/minecraft/server/mods/example.jar"] = [
        "c" * 64 + "  /opt/minecraft/server/mods/example.jar"
    ]
    run = run_deploy_fake(deploy_minecraft_java, cfg, secrets, responses=responses)
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops, run.mutating_changed_ops


@pytest.mark.parametrize(
    "template",
    [
        "server.properties.j2",
        "ops.json.j2",
        "whitelist.json.j2",
        "minecraft-java.service.j2",
        "minecraft-java.env.j2",
        "start-forge.sh.j2",
        "user_jvm_args.txt.j2",
    ],
)
@pytest.mark.parametrize("mode", ["vanilla", "forge"])
def test_templates_against_current_role_snapshot(template: str, mode: str) -> None:
    import jinja2

    cfg = config(
        loader_mode=mode,
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://example.org/forge.jar",
        forge_installer_sha256="b" * 64,
        whitelist_players=["Player_1"],
        ops=["Player_2"],
    )
    secrets = values(cfg)
    source = Path(__file__).parent / "parity/minecraft_java_3110a0f1" / template
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    original = env.from_string(source.read_text()).render(**cfg.context(secrets))
    if template == "minecraft-java.service.j2":
        original = original.replace('-p "${RCON_PASSWORD}" "stop"', '"stop"')
        original = original.replace(
            "# Auto-restart on failure\n",
            "# Forge exits 143 after a clean RCON stop.\nSuccessExitStatus=143\n\n# Auto-restart on failure\n",
        )
    if template == "minecraft-java.env.j2":
        original = original.replace(
            "RCON_PASSWORD=" + secrets["rcon_password"],
            "RCON_PASSWORD=" + secrets["rcon_password"] + "\nMCRCON_PASS=" + secrets["rcon_password"],
        )
    assert rendered(cfg, template, secrets) == original


@pytest.mark.parametrize("valid", [True, False])
def test_download_verifies_before_replacing_and_cleans_stage(tmp_path: Path, valid: bool) -> None:
    import os
    import shutil
    import sys

    from ops_deploy.services.minecraft_java.deploy import _download

    target = tmp_path / "server.jar"
    target.write_text("previous verified jar")
    tools = tmp_path / "tools"
    tools.mkdir()
    curl = tools / "curl"
    curl.write_text(
        '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n'
        'if [ "$1" = --output ]; then shift; printf fixture > "$1"; exit; fi\n'
        "shift\ndone\nexit 1\n"
    )
    curl.chmod(0o755)
    runuser = tools / "runuser"
    runuser.write_text('#!/bin/sh\nwhile [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n')
    runuser.chmod(0o755)
    if sys.platform != "darwin" and (sha_tool := shutil.which("sha256sum")):
        (tools / "sha256sum").symlink_to(sha_tool)
    else:
        checker = tools / "sha256sum"
        checker.write_text(
            f"#!{sys.executable}\nimport hashlib,pathlib,sys\n"
            "expected,path=sys.stdin.read().strip().split(' ',1)\n"
            "sys.exit(hashlib.sha256(pathlib.Path(path.strip()).read_bytes()).hexdigest()!=expected)\n"
        )
        checker.chmod(0o755)
    checksum = hashlib.sha256(b"fixture" if valid else b"different").hexdigest()
    run = run_deploy_fake(
        _download,
        src="https://example.org/server.jar",
        dest=str(target),
        user="fixture",
        group="fixture",
        mode="0644",
        sha256sum=checksum,
    )
    assert run.succeeded, run.error
    assert len(run.executed_commands) == 1
    result = subprocess.run(
        shlex.split(run.executed_commands[0]),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PATH": f"{tools}:/usr/bin:/bin"},
    )
    assert (result.returncode == 0) is valid, result.stderr
    assert target.read_text() == ("fixture" if valid else "previous verified jar")
    assert not list(tmp_path.glob(".minecraft-download.*"))


def test_existing_ufw_comments_and_protocol_order_do_not_schedule_changes() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["LC_ALL=C ufw show added"] = [
        "ufw deny 25575/tcp comment 'Minecraft RCON - blocked externally, localhost only'",
        "ufw allow proto tcp from 192.0.2.0/24 to any port 25565 comment 'Minecraft Java game port'",
    ]
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops, run.mutating_changed_ops


def test_inactive_firewall_aborts_before_service_start() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["LC_ALL=C ufw status"] = ["Status: inactive"]
    with pytest.raises(ValueError, match="active UFW"):
        run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)


def test_review_download_caller_drops_root_for_all_staging_steps() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["sha256sum /opt/minecraft/server/server.jar"] = ["0" * 64 + "  /opt/minecraft/server/server.jar"]
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    download = next(command for command in run.executed_commands if ".minecraft-download." in command)
    assert download.startswith("runuser -u minecraft -g minecraft -- bash -c ")


def test_review_java_rewrite_does_not_restart_the_real_deploy_caller() -> None:
    cfg = config()
    secrets = values(cfg)
    lines = [
        line
        for line in rendered(cfg, "server.properties.j2", secrets).splitlines()
        if line and not line.startswith("#")
    ]
    rewritten = "# Minecraft server\n# startup timestamp\n" + "\n".join(reversed(lines)) + "\n"
    responses = converged(cfg)
    responses.update(
        fakehost.file(str(cfg.site_path / "server.properties"), rewritten, user=cfg.user, mode="-rw-r-----")
    )
    responses["minecraft-config-state"] = ["current"]
    run = run_deploy_fake(deploy_minecraft_java, cfg, secrets, responses=responses)
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops, run.mutating_changed_ops


def test_review_retry_after_partial_new_world_deploy(tmp_path: Path) -> None:
    import json

    root = tmp_path / "server"
    root.mkdir()
    (root / ".loader_mode").write_text("vanilla\n")
    (root / "server.properties").write_text("level-name=old-world\n")
    cfg = config(
        home=str(tmp_path),
        site_path=root,
        loader_mode="forge",
        world_name="new-world",
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://example.org/forge.jar",
        forge_installer_sha256="b" * 64,
    )
    before = subprocess.run(shlex.split(guard_command(cfg)), capture_output=True, text=True, check=False)
    assert before.returncode == 0
    responses = converged(cfg)
    responses[guard_command(cfg)] = before.stdout.splitlines()
    responses["bash -ec "] = {"success": False}
    responses["minecraft-config-state"] = ["pending"]
    responses.update(
        fakehost.file(str(root / "server.properties"), "level-name=old-world\n", user=cfg.user, mode="-rw-r-----")
    )
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert not run.succeeded
    # Replay precisely the files the production caller wrote before its failure.
    state_path = str(root / ".loader_state.json")
    (root / ".loader_state.json").write_bytes(run.written(state_path))
    (root / "server.properties").write_bytes(run.written(str(root / "server.properties")))
    assert json.loads((root / ".loader_state.json").read_text())["world_name"] == "old-world"
    retry = subprocess.run(shlex.split(guard_command(cfg)), capture_output=True, text=True, check=False)
    assert retry.returncode == 0, retry.stderr


@pytest.mark.parametrize("case", ["java-save", "unicode-space", "changed", "continuation", "separator", "escape"])
def test_production_semantic_properties_probe(tmp_path: Path, case: str) -> None:
    import sys

    from ops_deploy.services.minecraft_java.deploy import CONFIG_STATE_SOURCE

    cfg = config()
    desired = rendered(cfg, "server.properties.j2", values(cfg))
    entries = [line for line in desired.splitlines() if line and not line.startswith("#")]
    saved = []
    for line in reversed(entries):
        key, value = line.split("=", 1)
        for character in (":", "=", "#", "!"):
            value = value.replace(character, chr(92) + character)
        saved.append(key + "=" + value)
    observed = "#Minecraft server\n#startup timestamp\n" + "\n".join(saved) + "\nunknown-property=retained\n"
    expected = "current"
    if case == "unicode-space":
        observed = observed.replace("motd=A Minecraft Server", "motd=A" + chr(92) + "u0020Minecraft Server")
    elif case == "changed":
        observed = observed.replace("max-players=20", "max-players=21")
        expected = "pending"
    elif case == "continuation":
        observed += "motd=continued" + chr(92) + "\nnextline\n"
        expected = "unsupported"
    elif case == "separator":
        observed = observed.replace("motd=A Minecraft Server", "motd:A Minecraft Server")
        expected = "unsupported"
    elif case == "escape":
        observed = observed.replace("motd=A Minecraft Server", "motd=A" + chr(92) + "qServer")
        expected = "unsupported"
    target = tmp_path / "server.properties"
    target.write_text(observed)
    target.chmod(0o640)
    os.chown(target, -1, os.getgid())
    result = subprocess.run(
        [sys.executable, "-I", "-c", CONFIG_STATE_SOURCE, str(target), "properties", "0640"],
        input=json.dumps({"content": desired}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == expected
    assert RCON_FIXTURE not in result.stdout + result.stderr


def test_server_added_player_uuids_are_semantically_current(tmp_path: Path) -> None:
    import sys

    from ops_deploy.services.minecraft_java.deploy import CONFIG_STATE_SOURCE

    desired = '[{"name":"Player_1","level":4,"bypassesPlayerLimit":true}]'
    target = tmp_path / "ops.json"
    target.write_text(
        '[{"uuid":"00000000-0000-0000-0000-000000000001","bypassesPlayerLimit":true,"level":4,"name":"Player_1"}]'
    )
    target.chmod(0o644)
    os.chown(target, -1, os.getgid())
    result = subprocess.run(
        [sys.executable, "-I", "-c", CONFIG_STATE_SOURCE, str(target), "players", "0644"],
        input=json.dumps({"content": desired}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.stdout.strip() == "current"


def test_completed_sidecar_does_not_hide_a_later_ansible_world_change(tmp_path: Path) -> None:
    (tmp_path / ".loader_mode").write_text("vanilla\n")
    (tmp_path / "server.properties").write_text("level-name=later-world\n")
    (tmp_path / ".loader_state.json").write_text(json.dumps({"loader_mode": "vanilla", "world_name": "old-world"}))
    cfg = config(
        home=str(tmp_path.parent),
        site_path=tmp_path,
        loader_mode="forge",
        world_name="later-world",
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://example.org/forge.jar",
        forge_installer_sha256="b" * 64,
    )
    result = subprocess.run(shlex.split(guard_command(cfg)), capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "Unsafe loader switch" in result.stderr


@pytest.mark.parametrize("different_candidate", [True, False])
def test_pending_transition_refuses_unrelated_candidate_or_external_drift(
    tmp_path: Path, different_candidate: bool
) -> None:
    (tmp_path / ".loader_mode").write_text("vanilla\n")
    (tmp_path / "server.properties").write_text(
        "level-name=" + ("old-world" if different_candidate else "external-world") + "\n"
    )
    (tmp_path / ".loader_state.json").write_text(
        json.dumps(
            {
                "loader_mode": "vanilla",
                "world_name": "old-world",
                "pending_loader_mode": "forge",
                "pending_world_name": "new-world",
            }
        )
    )
    cfg = config(
        home=str(tmp_path.parent),
        site_path=tmp_path,
        loader_mode="forge",
        world_name="different-world" if different_candidate else "new-world",
        forge_version="1.20.1-47.4.0",
        forge_installer_url="https://example.org/forge.jar",
        forge_installer_sha256="b" * 64,
    )
    result = subprocess.run(shlex.split(guard_command(cfg)), capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert ("Resume the pending" if different_candidate else "Unexpected Minecraft state drift") in result.stderr


@pytest.mark.parametrize("artifact", ["server.jar", "forge-installer.jar", "mods/example.jar"])
def test_missing_artifact_bootstraps_through_deploy(artifact: str) -> None:
    cfg = (
        config()
        if artifact == "server.jar"
        else config(
            loader_mode="forge",
            forge_version="1.20.1-47.4.0",
            forge_installer_url="https://example.org/forge.jar",
            forge_installer_sha256="b" * 64,
            mods_enabled=True,
            mods=[{"name": "example", "url": "https://example.org/example.jar", "sha256": "c" * 64}],
        )
    )
    target = str(cfg.site_path / artifact)
    responses = {**fakehost.stat(target), **converged(cfg)}
    responses["sha256sum " + target] = {"success": False}
    # Override the stat response to model a genuinely absent destination.
    responses[next(iter(fakehost.stat(target)))] = []
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    assert not any("sha256sum " + target in command for command in run.fact_commands)
    assert any(".minecraft-download." in command and target in command for command in run.executed_commands)


@pytest.mark.parametrize("post_check_fails", [False, True])
def test_failed_mcrcon_probe_installs_and_verifies_through_deploy(post_check_fails: bool) -> None:
    from ops_deploy.helpers.probes import FAILED

    responses: dict[Any, Any] = {
        # A raw failing fact aborts pyinfra before its install can run. The
        # existing probe wrapper reports the same failure as successful stdout.
        re.compile(r"^\( .*mcrcon -v", re.S): [FAILED],
        "probe still fails: Minecraft mcrcon": {"success": not post_check_fails},
        **converged(config()),
    }
    responses["/usr/local/bin/mcrcon -v"] = {"success": False}
    cfg = config()
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert any("mcrcon -v" in command for command in run.fact_commands)
    assert run.succeeded is not post_check_fails, run.error
    assert run.op("Deploy Minecraft Java | Install mcrcon if missing").changed
    assert any("probe still fails: Minecraft mcrcon" in command for command in run.executed_commands)
    if post_check_fails:
        assert not any(".minecraft-download." in command for command in run.executed_commands)


@pytest.mark.parametrize("version", ["missing", "unsupported", "old", "0.7.2", "0.7.20", "failed-current"])
def test_production_mcrcon_probe_and_verification_shell(tmp_path: Path, version: str) -> None:
    from ops_deploy.helpers.probes import FAILED

    cfg = config()
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=converged(cfg))
    assert run.succeeded, run.error
    fact = next(command for command in run.fact_commands if "mcrcon -v" in command)
    verify = next(command for command in run.executed_commands if "probe still fails: Minecraft mcrcon" in command)
    executable = tmp_path / "mcrcon"
    if version != "missing":
        banner = "mcrcon " + ("0.7.1" if version == "old" else "0.7.2" if version == "failed-current" else version)
        executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' "
            + shlex.quote(banner)
            + "\nexit "
            + ("1" if version in ("unsupported", "failed-current") else "0")
            + "\n"
        )
        executable.chmod(0o755)
    # Execute the exact production shell from the real deploy caller, replacing
    # only its executable path. No installed binary or network is touched.
    probe_result = subprocess.run(
        ["sh", "-c", fact.replace("/usr/local/bin/mcrcon", shlex.quote(str(executable)))],
        capture_output=True,
        text=True,
        check=False,
    )
    verify_result = subprocess.run(
        ["sh", "-c", verify.replace("/usr/local/bin/mcrcon", shlex.quote(str(executable)))],
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe_result.returncode == 0
    assert (probe_result.stdout.splitlines()[-1:] == [FAILED]) is (version != "0.7.2")
    assert (verify_result.returncode == 0) is (version == "0.7.2")


def test_started_with_inactive_ufw_refuses_before_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(
        "ops_deploy.services.minecraft_java.deploy.apt.packages", lambda **kwargs: called.append("packages")
    )
    cfg = config()
    responses = {**converged(cfg), "LC_ALL=C ufw status": ["Status: inactive"]}
    with pytest.raises(ValueError, match="active UFW"):
        run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert not called


def test_stopped_with_inactive_ufw_has_no_start_restart_or_running_health() -> None:
    cfg = config(service_state="stopped")
    responses = {
        **converged(cfg),
        **fakehost.service("minecraft-java.service", running=False),
        "LC_ALL=C ufw status": ["Status: inactive"],
    }
    # Runtime changes must also keep the service stopped.
    responses.update(fakehost.file("/etc/systemd/system/minecraft-java.service", "old unit"))
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    assert "daemon-reload" in commands
    assert not re.search(r"systemctl (start|restart) ", commands)
    assert "mcrcon -H" not in commands
    assert "ufw enable" not in commands


def test_stopped_converged_has_no_mutations() -> None:
    cfg = config(service_state="stopped")
    responses = {**converged(cfg), **fakehost.service("minecraft-java.service", running=False)}
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    assert not run.mutating_changed_ops, run.mutating_changed_ops


def test_missing_mcrcon_and_properties_are_expected_bootstrap_states() -> None:
    cfg = config()
    responses = converged(cfg)
    responses[next(iter(fakehost.stat("/usr/local/bin/mcrcon")))] = []
    responses[next(iter(fakehost.stat(str(cfg.site_path / "server.properties"))))] = []
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    assert not any("mcrcon -v" in command for command in run.fact_commands)
    assert not any("server.properties properties" in command for command in run.fact_commands)
    assert run.op("Deploy Minecraft Java | Install mcrcon if missing").changed
    assert run.op("Deploy Minecraft Java | Write Minecraft server.properties").changed


@pytest.mark.parametrize(
    ("state", "result", "code", "listener", "ok"),
    [
        ("inactive", "success", "0", "", True),
        ("failed", "exit-code", "143", "", True),
        ("failed", "exit-code", "1", "", False),
        ("failed", "signal", "143", "", False),
        ("active", "success", "0", "", False),
        ("inactive", "success", "0", "LISTEN", False),
    ],
)
def test_stopped_check_admits_only_inactive_or_legacy_clean_shutdown(
    tmp_path: Path,
    state: str,
    result: str,
    code: str,
    listener: str,
    ok: bool,
) -> None:
    from ops_deploy.services.minecraft_java.deploy import stopped_check

    systemctl = tmp_path / "systemctl"
    systemctl.write_text(
        '#!/bin/sh\ncase "$3" in\n'
        + "ActiveState) echo "
        + shlex.quote(state)
        + ";;\n"
        + "Result) echo "
        + shlex.quote(result)
        + ";;\n"
        + "ExecMainStatus) echo "
        + shlex.quote(code)
        + ";;\nesac\n"
    )
    systemctl.chmod(0o755)
    ss = tmp_path / "ss"
    ss.write_text("#!/bin/sh\nprintf %s " + shlex.quote(listener) + "\n")
    ss.chmod(0o755)
    run = subprocess.run(
        ["/bin/sh", "-c", stopped_check(config())], env={**os.environ, "PATH": str(tmp_path)}, check=False
    )
    assert (run.returncode == 0) is ok


def test_stopped_running_service_stops_before_any_runtime_write() -> None:
    cfg = config(service_state="stopped")
    responses = converged(cfg)
    responses.update(fakehost.file("/etc/systemd/system/minecraft-java.service", "old unit"))
    responses["/server.properties properties 0640"] = ["pending"]
    run = run_deploy_fake(deploy_minecraft_java, cfg, values(cfg), responses=responses)
    assert run.succeeded, run.error
    commands = run.executed_commands
    stop = next(i for i, c in enumerate(commands) if "systemctl stop" in c)
    writes = [
        i
        for i, c in enumerate(commands)
        if " server.properties " in c or "/etc/systemd/system/minecraft-java.service" in c
    ]
    assert writes
    assert stop < min(writes)
    assert not any(re.search(r"systemctl (start|restart) ", c) for c in commands)
