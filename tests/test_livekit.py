"""livekit on compose_app against the fake connector (tests/livekit_fixtures.py).

The restart and recreate rules are what matters here: a converged host gets
no mutating operation and no container command at all; a changed config file
restarts only its reader; an image bump recreates through ``up``; the switch
from the role's files applies once.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretValues
from ops_deploy.services.compose_app.render import render_compose
from ops_deploy.services.livekit import LivekitConfig, deploy_livekit
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.livekit_fixtures import (
    EGRESS_IMAGE,
    EGRESS_YAML,
    IMAGE_IDS,
    ROUTE,
    SECRET_VALUES,
    SERVER_IMAGE,
    SERVER_YAML,
    STATE,
    ansible_deployed,
    converged,
    livekit_config,
    values,
)

PREFIX = "Deploy livekit | "
PENDING = f"{PREFIX}Mark livekit pending"
RELOAD = f"{PREFIX}Reload livekit.service"
STAMP = f"{PREFIX}Record the applied livekit state"
WRITE_SERVER = f"{PREFIX}Write {SERVER_YAML}"
WRITE_EGRESS = f"{PREFIX}Write {EGRESS_YAML}"
RESTART_SERVER = f"{PREFIX}Restart livekit-server for their config files"
RESTART_EGRESS = f"{PREFIX}Restart livekit-egress for their config files"
RESTART_BOTH = f"{PREFIX}Restart livekit-egress, livekit-server for their config files"
ROUTE_WRITE = "Deploy livekit route | Write Traefik route livekit"
NEW_SERVER = "example.org/livekit/livekit-server:v1.12.1@sha256:" + "c" * 64


@pytest.fixture
def cfg() -> LivekitConfig:
    return livekit_config()


@pytest.fixture
def secrets(cfg: LivekitConfig) -> SecretValues:
    return values(cfg)


def deploy(cfg: LivekitConfig, secrets: SecretValues, responses: dict[str, Any], *, succeed: bool = True) -> FakeRun:
    run = run_deploy_fake(deploy_livekit, cfg, secrets, responses=responses)
    if succeed:
        assert run.succeeded, run.error
    return run


def container_commands(run: FakeRun) -> list[str]:
    """Everything that could stop, recreate or restart a container or Traefik."""

    words = ("compose -p", "systemctl reload", "systemctl restart", "systemctl start", "systemctl stop", "docker pull")
    return [c for c in run.executed_commands if any(w in c for w in words)]


# -- the model ---------------------------------------------------------------------


def test_the_compose_app_keeps_the_roles_names_privileges_and_mounts(cfg: LivekitConfig) -> None:
    app = cfg.compose_app()
    server, egress = app.services

    assert (app.service_name, app.unit_name, app.project) == ("livekit", "livekit", "livekit")
    assert str(app.compose_path) == "/opt/livekit/docker-compose.yml"
    assert (app.user, app.users, app.groups) == ("root", (), ())
    assert (server.name, server.container_name, egress.name, egress.container_name) == (
        "livekit-server",
        "livekit-server",
        "livekit-egress",
        "livekit-egress",
    )
    assert server.network_mode == egress.network_mode == "host"
    assert server.host_network_reason
    assert egress.host_network_reason
    assert server.ports == egress.ports == ()
    assert server.command == ("--config", "/etc/livekit/livekit.yaml")
    assert (server.cap_add, egress.cap_add) == ((), ("SYS_ADMIN",))
    assert (server.shm_size, egress.shm_size) == (None, "1g")
    assert [(str(b.source), str(b.container_path), b.read_only) for b in server.binds] == [
        (SERVER_YAML, "/etc/livekit/livekit.yaml", True)
    ]
    assert [(str(b.source), str(b.container_path), b.read_only) for b in egress.binds] == [
        (EGRESS_YAML, "/etc/egress.yaml", True)
    ]
    assert [(e.key, e.value) for e in egress.environment] == [("EGRESS_CONFIG_FILE", "/etc/egress.yaml")]
    assert server.restart == egress.restart == "unless-stopped"
    assert [(str(c.path), c.mode, c.owner, c.group, c.restarts) for c in app.config_files] == [
        (SERVER_YAML, "0600", "root", "root", ("livekit-server",)),
        (EGRESS_YAML, "0640", "root", "root", ("livekit-egress",)),
    ]
    assert app.stop == "down"
    assert app.route is None  # the role's own route, written by deploy_livekit
    assert set(app.required_secret_keys) == set(LivekitConfig.required_secret_keys)
    assert [(c.url, c.retries) for c in app.checks.http] == [("http://127.0.0.1:7880/", 60)]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"server_image": "livekit/livekit-server:v1.12.0"}, "server_image"),
        ({"egress_image": "livekit/egress:latest"}, "egress_image"),
        ({"node_ip": "fd00::1"}, "node_ip must be an IPv4 address"),
        ({"node_ip": "192.0.2.300"}, "node_ip must be an IPv4 address"),
        ({"webhook_url": 'https://x.example.invalid/"hook'}, "webhook_url"),
        ({"webhook_url": "ftp://x.example.invalid/hook"}, "webhook_url"),
        ({"s3_endpoint": "http://127.0.0.1:9001/$x"}, "s3_endpoint"),
        ({"s3_bucket": "Recorder"}, "s3_bucket"),
        ({"redis_address": "127.0.0.1"}, "redis_address"),
        ({"rtc_port_range_start": 50200}, "rtc_port_range_start must not be above"),
        ({"user": "livekit"}, "user must be root"),
        ({"config_dir": "/opt/livekit"}, "must differ"),
        ({"traefik_host": "bad host"}, "traefik_host"),
        ({"secrets": None}, "requires a secrets file"),
    ],
)
def test_unsafe_or_incomplete_inputs_are_refused(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        livekit_config(**change)


def test_json_and_string_inputs_validate_with_the_defaults(cfg: LivekitConfig) -> None:
    data = {
        "secrets": "secrets/prod/livekit.yml",
        "server_image": SERVER_IMAGE,
        "egress_image": EGRESS_IMAGE,
        "node_ip": "192.0.2.10",
        "webhook_url": "https://recorder.example.invalid/api/livekit/webhook",
        "traefik_host": "livekit.example.invalid",
    }

    assert LivekitConfig.model_validate_json(json.dumps(data)) == cfg
    assert LivekitConfig.model_validate_strings(data) == cfg
    assert LivekitConfig.model_validate(data) == cfg
    explicit = {**data, "site_path": "/opt/livekit", "config_dir": "/etc/livekit"}
    assert LivekitConfig.model_validate_json(json.dumps(explicit)) == cfg
    with pytest.raises(ConfigValidationError, match="config_dir"):
        LivekitConfig.model_validate_json(json.dumps({**data, "config_dir": "/etc/live kit"}))


@pytest.mark.parametrize("key", sorted(SECRET_VALUES))
def test_an_empty_or_missing_secret_stops_the_run_before_any_operation(cfg: LivekitConfig, key: str) -> None:
    assert cfg.secrets is not None
    missing = SecretValues(cfg.secrets, {k: v for k, v in SECRET_VALUES.items() if k != key})
    for secrets in (values(cfg, **{key: ""}), values(cfg, **{key: "   "}), missing):
        # Raised while the deploy is added, before pyinfra plans any operation.
        with pytest.raises((KeyError, ValueError), match=key) as raised:
            run_deploy_fake(deploy_livekit, cfg, secrets, responses=converged(cfg, values(cfg)))
        assert SECRET_VALUES[key] not in str(raised.value)


def test_a_placeholder_secret_is_refused_by_key(cfg: LivekitConfig) -> None:
    with pytest.raises(ValueError, match="secret api_secret must be set and not a placeholder"):
        run_deploy_fake(deploy_livekit, cfg, values(cfg, api_secret="CHANGEME"), responses=converged(cfg, values(cfg)))


# -- converged: nothing is recreated or restarted ---------------------------------------


def test_a_converged_host_gets_no_mutating_operation_and_no_container_command(
    cfg: LivekitConfig, secrets: SecretValues
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert container_commands(run) == []
    read_only = [op.name for op in run.ops if op.changed]
    assert f"{PREFIX}Check the livekit services run" in read_only
    assert f"{PREFIX}Check http://127.0.0.1:7880/" in read_only


def test_the_run_after_the_switch_is_a_no_op(cfg: LivekitConfig, secrets: SecretValues) -> None:
    first = deploy(cfg, secrets, ansible_deployed(cfg, secrets))
    assert RELOAD in first.mutating_changed_ops

    # The host as the first run left it: its uploads, its stamp.
    second = deploy(cfg, secrets, converged(cfg, secrets))

    assert second.mutating_changed_ops == []
    assert container_commands(second) == []


# -- the switch from the role's files ------------------------------------------------


def test_the_switch_from_the_role_applies_once_without_a_pull_or_a_traefik_restart(
    cfg: LivekitConfig, secrets: SecretValues
) -> None:
    run = deploy(cfg, secrets, ansible_deployed(cfg, secrets))

    assert run.mutating_changed_ops == [
        PENDING,
        f"{PREFIX}Write docker-compose.yml",
        WRITE_SERVER,
        WRITE_EGRESS,
        f"{PREFIX}Install systemd unit livekit.service",
        f"{PREFIX}Reload systemd for livekit.service",
        RELOAD,
        RESTART_BOTH,
        STAMP,
    ]
    commands = container_commands(run)
    assert commands == [
        "systemctl reload livekit.service",
        "docker compose -p livekit -f /opt/livekit/docker-compose.yml restart livekit-egress livekit-server",
    ]
    # The role's route is kept byte for byte: no write, and Traefik is never restarted.
    assert ROUTE_WRITE not in run.mutating_changed_ops
    assert not any("traefik" in c and "systemctl" in c for c in run.executed_commands)
    assert not any("docker pull" in c for c in run.executed_commands)
    # egress.yaml goes from the old 0644 to the role's 0640.
    egress_install = next(c for c in run.executed_commands if "/etc/livekit egress.yaml " in c)
    assert egress_install.endswith(" 0640 root root")


def test_secrets_never_reach_commands_or_op_arguments(cfg: LivekitConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, ansible_deployed(cfg, secrets))
    text = run.all_text()

    for key, value in SECRET_VALUES.items():
        assert value not in text, key
    stamp = [stdin for command, stdin in run.stdin if command.endswith("' stamp")]
    assert len(stamp) == 1


# -- what a change restarts ------------------------------------------------------------


def test_a_server_only_change_restarts_only_the_server(cfg: LivekitConfig, secrets: SecretValues) -> None:
    changed = livekit_config(webhook_url="https://recorder.example.invalid/api/livekit/other")

    run = deploy(changed, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == [PENDING, WRITE_SERVER, RELOAD, RESTART_SERVER, STAMP]
    restart = "docker compose -p livekit -f /opt/livekit/docker-compose.yml restart livekit-server"
    assert restart in run.executed_commands


def test_an_egress_only_change_restarts_only_egress(cfg: LivekitConfig, secrets: SecretValues) -> None:
    changed = livekit_config(s3_bucket="recordings")

    run = deploy(changed, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == [PENDING, WRITE_EGRESS, RELOAD, RESTART_EGRESS, STAMP]


def test_a_rotated_api_secret_restarts_both(cfg: LivekitConfig, secrets: SecretValues) -> None:
    rotated = values(cfg, api_secret="fixture-rotated-secret-0123456789")

    run = deploy(cfg, rotated, converged(cfg, secrets))

    assert run.mutating_changed_ops == [PENDING, WRITE_SERVER, WRITE_EGRESS, RELOAD, RESTART_BOTH, STAMP]


def test_an_image_bump_recreates_through_up_and_restarts_nothing(cfg: LivekitConfig, secrets: SecretValues) -> None:
    bumped = livekit_config(server_image=NEW_SERVER)

    run = deploy(bumped, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        PENDING,
        f"{PREFIX}Write docker-compose.yml",
        f"{PREFIX}Pull {NEW_SERVER}",
        RELOAD,
        STAMP,
    ]
    assert not any(" restart " in c for c in run.executed_commands)


def test_a_hand_edited_config_file_is_rewritten_and_its_reader_restarted(
    cfg: LivekitConfig, secrets: SecretValues
) -> None:
    responses = converged(cfg, secrets)
    responses.update(fakehost.file(EGRESS_YAML, "# edited\n", mode="-rw-r-----"))

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, WRITE_EGRESS, RELOAD, RESTART_EGRESS, STAMP]


def test_a_stopped_container_is_started_by_up_without_a_restart(cfg: LivekitConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    responses["docker inspect --format"] = [
        f"livekit-server running {IMAGE_IDS[SERVER_IMAGE]} False",
        f"livekit-egress exited {IMAGE_IDS[EGRESS_IMAGE]} False",
    ]

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, RELOAD, STAMP]


def test_a_pending_run_is_finished_and_restarts_both_readers(cfg: LivekitConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets, **{f"test -e {STATE}/pending": ["pending"]})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, RELOAD, RESTART_BOTH, STAMP]


# -- the route --------------------------------------------------------------------------


def test_route_drift_rewrites_only_the_route_and_never_restarts_traefik(
    cfg: LivekitConfig, secrets: SecretValues
) -> None:
    responses = converged(cfg, secrets)
    responses.update(fakehost.file(ROUTE, "http: {}\n"))

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [ROUTE_WRITE]
    assert container_commands(run) == []
    assert run.upload(ROUTE).decode().startswith("# Managed by Ansible (livekit_deploy).")


def test_without_a_traefik_host_no_route_is_written(secrets: SecretValues) -> None:
    cfg = livekit_config(traefik_host=None)

    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert not any(op.name.startswith("Deploy livekit route") for op in run.ops)


def test_the_stamp_records_the_pins_and_both_config_files(cfg: LivekitConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, ansible_deployed(cfg, secrets))
    stdin = next(text for command, text in run.stdin if command.endswith("' stamp"))

    stamp = json.loads(base64.b64decode(stdin))["stamp"]
    assert stamp["images"] == [SERVER_IMAGE, EGRESS_IMAGE]
    assert set(stamp["files"]) == {"/opt/livekit/docker-compose.yml", SERVER_YAML, EGRESS_YAML}
    assert set(stamp["services"]) == {"livekit-server", "livekit-egress"}
    assert render_compose(cfg.compose_app()).count("@sha256:") == 2
