"""compose_app against the fake connector, in the torrent stack's shape (tests/compose_app_fixtures.py)."""

from __future__ import annotations

import ast
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.core import ConfigValidationError, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.compose_app import (
    ComposeAppConfig,
    ComposeAppRemoveConfig,
    ComposeService,
    ConfigFile,
    Directory,
    EnvEntry,
    EnvFile,
    PublishedPort,
    Route,
    Secret,
    deploy_compose_app,
    remove_compose_app,
)
from ops_deploy.services.compose_app.render import MANAGED, render_compose, render_env, render_unit
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.compose_app_fixtures import (
    APIKEY,
    APPS_ENV,
    CLIENT_IMAGE,
    COMPOSE,
    COPY_PROBE,
    DATA,
    GID,
    IMAGE_IDS,
    QBT_PROBE,
    RENDER_PROBE,
    ROUTE,
    SECRET_VALUES,
    SITE,
    STATE,
    UID,
    UNIT,
    VPN_ENV,
    VPN_IMAGE,
    converged,
    running,
    stack_config,
    stamp_document,
    values,
)

PREFIX = "Deploy vpnstack | "
STOP_DEPENDENTS = f"{PREFIX}Stop client, indexer before their network namespace is replaced"
RELOAD = f"{PREFIX}Reload vpnstack.service"
START = f"{PREFIX}Start vpnstack.service"
PENDING = f"{PREFIX}Mark vpnstack pending"
STAMP = f"{PREFIX}Record the applied vpnstack state"
HOST_ENV = f"{PREFIX}Write the env files with host values"
QBT = f"{PREFIX}Reconcile qBittorrent credentials and preferences"
COPY = f"{PREFIX}Copy the indexer API key into the client search plugin"


@pytest.fixture
def cfg() -> ComposeAppConfig:
    return stack_config()


@pytest.fixture
def secrets(cfg: ComposeAppConfig) -> SecretValues:
    return values(cfg)


def deploy(cfg: ComposeAppConfig, secrets: SecretValues, responses: dict[str, Any], *, succeed: bool = True) -> FakeRun:
    run = run_deploy_fake(deploy_compose_app, cfg, secrets, responses=responses)
    if succeed:
        assert run.succeeded, run.error
    return run


def ops_before(run: FakeRun, first: str, second: str) -> bool:
    names = [op.name for op in run.ops]
    return names.index(first) < names.index(second)


# -- the canonical files --------------------------------------------------------


def test_compose_file_is_a_deterministic_render_with_long_binds(cfg: ComposeAppConfig) -> None:
    text = render_compose(cfg)
    doc = yaml.safe_load(text)

    assert text.startswith(f"# {MANAGED}\nname: vpnstack\nservices:\n  vpn:\n")
    assert render_compose(cfg) == text
    vpn, client = doc["services"]["vpn"], doc["services"]["client"]
    assert vpn["ports"] == ["127.0.0.1:18080:8080", "127.0.0.1:19117:9117"]
    assert vpn["env_file"] == [VPN_ENV]
    assert vpn["sysctls"] == {"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}
    assert client["network_mode"] == "service:vpn"
    assert client["depends_on"] == {"vpn": {"condition": "service_healthy", "restart": True}}
    assert client["env_file"] == [APPS_ENV]
    downloads = "/srv/crypt/media/downloads/torrents"
    assert client["volumes"][1] == {
        "type": "bind",
        "source": downloads,
        "target": downloads,
        "bind": {"create_host_path": False},
    }
    assert "ports" not in client
    assert "networks" not in doc


def test_compose_values_are_literal(cfg: ComposeAppConfig) -> None:
    vpn = cfg.services[0].model_copy(
        update={"environment": (EnvEntry(key="PATTERN", value="a$b${c}"),), "command": ("sh", "-c", "echo $HOME")}
    )
    text = render_compose(cfg.model_copy(update={"services": (vpn, *cfg.services[1:])}))

    service = yaml.safe_load(text)["services"]["vpn"]
    assert service["environment"] == {"PATTERN": "a$$b$${c}"}
    assert service["command"] == ["sh", "-c", "echo $$HOME"]


def test_env_files_are_single_quoted_with_host_values_left_to_the_host(
    cfg: ComposeAppConfig, secrets: SecretValues
) -> None:
    vpn = render_env(cfg, cfg.env_files[0], secrets)
    apps = render_env(cfg, cfg.env_files[1], secrets)

    assert vpn.host_rendered
    assert apps.host_rendered
    text = "".join(segment[1] if segment[0] == "text" else "<host>" for segment in vpn.segments)
    assert text.splitlines() == [
        f"# {MANAGED}",
        "TZ='Europe/Berlin'",
        "VPN_SERVICE_PROVIDER='examplevpn'",
        "VPN_TYPE='wireguard'",
        f"WIREGUARD_PRIVATE_KEY='{SECRET_VALUES['vpn_private_key']}'",
        f"WIREGUARD_PRESHARED_KEY='{SECRET_VALUES['vpn_preshared_key']}'",
        "WIREGUARD_ADDRESSES='10.66.0.2/32'",
        "SERVER_COUNTRIES='Netherlands,Sweden'",
        "FIREWALL_VPN_INPUT_PORTS='40000'",
        'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE=\'{"auth":"apikey","apikey":"<host>"}\'',
    ]
    assert ["host_secret", APIKEY, 24] in vpn.segments
    assert ["user", "vpnstack"] in apps.segments
    assert ["group", "media"] in apps.segments


def test_env_file_without_host_values_is_rendered_on_the_controller(
    cfg: ComposeAppConfig, secrets: SecretValues
) -> None:
    env = EnvFile(name="plain.env", entries=(EnvEntry(key="TZ", value=Secret(secret="tz")),))

    rendered = render_env(cfg, env, secrets)

    assert rendered.content is not None
    assert rendered.content.reveal().decode() == f"# {MANAGED}\nTZ='Europe/Berlin'\n"
    assert rendered.mode == "0600"


@pytest.mark.parametrize("value", ["it's", "back\\slash", " padded", "two\nlines"])
def test_env_values_that_compose_would_misread_are_refused_by_key(
    cfg: ComposeAppConfig, secrets: SecretValues, value: str
) -> None:
    bad = values(cfg, tz=value)
    with pytest.raises(ValueError, match=r"secret tz for TZ in vpn\.env") as raised:
        render_env(cfg, cfg.env_files[0], bad)
    assert value not in str(raised.value)


def test_secret_forms(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    with pytest.raises(ValueError, match="secret vpn_forwarded_port must be a number"):
        render_env(cfg, cfg.env_files[1], values(cfg, vpn_forwarded_port="40000a"))
    with pytest.raises(ValueError, match="secret vpn_addresses has no IPv4 address"):
        render_env(cfg, cfg.env_files[0], values(cfg, vpn_addresses="fd00::2/128"))


def test_unit_reloads_with_up_and_requires_the_mount(cfg: ComposeAppConfig) -> None:
    unit = render_unit(cfg)
    compose = f"/usr/bin/docker compose -p vpnstack -f {COMPOSE}"

    for line in (
        "Description=VPN stack (vpn + client + indexer) (Docker Compose project vpnstack)",
        "RequiresMountsFor=/srv/crypt",
        "Type=oneshot",
        "RemainAfterExit=yes",
        f"ExecStart={compose} up -d --remove-orphans",
        f"ExecReload={compose} up -d --remove-orphans",
        f"ExecStop={compose} down",
        "TimeoutStartSec=300",
    ):
        assert line in unit.splitlines()


def test_required_secret_keys_follow_the_references(cfg: ComposeAppConfig) -> None:
    assert set(cfg.required_secret_keys) == set(SECRET_VALUES)


# -- validation ---------------------------------------------------------------


def _with(cfg: ComposeAppConfig, index: int, **update: Any) -> dict[str, Any]:
    """``cfg`` dumped, with service ``index`` updated (dumped values)."""

    data = cfg.model_dump()
    data["services"][index].update(update)
    return data


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"image": "example.org/vpn/gate:v3"}, "image"),
        ({"image": "example.org/vpn/gate:latest"}, "image"),
        ({"ports": [{"published": 18080, "target": 8080, "host_ip": "0.0.0.0"}]}, "exposure_reason"),
        ({"network_mode": "host", "ports": []}, "host_network_reason"),
        ({"binds": [{"source": "/srv/elsewhere"}]}, "not declared"),
        ({"cap_add": ["SYS_PTRACE"]}, "cap_add"),
        ({"devices": ["/dev/sda"]}, "devices"),
    ],
)
def test_service_rules(cfg: ComposeAppConfig, change: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        ComposeAppConfig.model_validate(_with(cfg, 0, **change))


def test_unknown_keys_are_refused(cfg: ComposeAppConfig) -> None:
    data = cfg.model_dump()
    data["services"][0]["privileged"] = True
    with pytest.raises(ConfigValidationError, match="extra_forbidden"):
        ComposeAppConfig.model_validate(data)


def test_a_namespace_provider_needs_a_healthcheck(cfg: ComposeAppConfig) -> None:
    with pytest.raises(ConfigValidationError, match="provides a network namespace and needs a healthcheck"):
        ComposeAppConfig.model_validate(_with(cfg, 0, healthcheck=None))


def test_dependents_publish_no_ports(cfg: ComposeAppConfig) -> None:
    with pytest.raises((ConfigValidationError, ValueError), match="publishes no ports"):
        ComposeService(
            name="client",
            image=CLIENT_IMAGE,
            network_mode="service:vpn",
            ports=(PublishedPort(published=1, target=1),),
        )


def test_route_port_must_be_published(cfg: ComposeAppConfig) -> None:
    data = cfg.model_dump()
    data["route"] = {"host": "x.example.org", "port": 1234, "access": "internal"}
    with pytest.raises(ConfigValidationError, match="route port 1234"):
        ComposeAppConfig.model_validate(data)


def test_route_access_modes() -> None:
    with pytest.raises(ValueError, match="needs basic_auth_user"):
        Route(host="x.example.org", port=1, access="internal_or_basic_auth")
    with pytest.raises(ValueError, match="public_reason"):
        Route(host="x.example.org", port=1, access="public")
    with pytest.raises(ValueError, match="takes no basic auth"):
        Route(host="x.example.org", port=1, access="internal", basic_auth_password=Secret(secret="pw"))


# -- deploy: converged and first runs ------------------------------------------


def test_converged_host_gets_no_mutating_operation(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    read_only = [op.name for op in run.ops if op.changed]
    assert f"{PREFIX}Port preflight" in read_only
    assert f"{PREFIX}Check the vpnstack services run" in read_only
    assert f"{PREFIX}Check client runs in the network namespace of vpn" in read_only
    assert f"{PREFIX}Check port 18080 listens on 127.0.0.1 only" in read_only


def test_first_deploy_applies_in_order_and_records_the_stamp(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**fakehost.UBUNTU})
    changed = run.mutating_changed_ops

    for name in (PENDING, HOST_ENV, f"{PREFIX}Pull {VPN_IMAGE}", STOP_DEPENDENTS, START, QBT, COPY, STAMP):
        assert name in changed
    assert RELOAD not in changed
    assert ops_before(run, PENDING, f"{PREFIX}Write compose.yml")
    assert ops_before(run, HOST_ENV, START)
    assert ops_before(run, f"{PREFIX}Pull {VPN_IMAGE}", START)
    assert ops_before(run, STOP_DEPENDENTS, START)
    assert ops_before(run, f"{PREFIX}Write Traefik route vpnstack", STAMP)
    assert "systemctl restart traefik.service" not in run.executed_commands
    # The stamp step gets the fingerprint on stdin, the host resolves the ids.
    stamp_stdin = [text for command, text in run.stdin if command.endswith("' stamp")]
    assert len(stamp_stdin) == 1


def test_secrets_never_reach_commands_uploads_or_op_arguments(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**fakehost.UBUNTU})
    text = run.all_text()

    for key, value in SECRET_VALUES.items():
        # Not secret in effect: the time zone, the port, the address (filtered), the route's user.
        if key in ("tz", "vpn_forwarded_port", "vpn_addresses", "basic_auth_user"):
            continue
        assert value not in text, key
    route = run.upload(ROUTE).decode()
    assert SECRET_VALUES["basic_auth_password"] not in route


def test_second_run_after_a_stamp_is_a_no_op_also_for_the_route(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    first = deploy(cfg, secrets, {**fakehost.UBUNTU})
    route = first.upload(ROUTE).decode()

    responses = converged(cfg, secrets)
    responses.update(fakehost.file(ROUTE, route))
    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == []


# -- what an apply restarts ----------------------------------------------------


def _changed_apps_env(cfg: ComposeAppConfig) -> ComposeAppConfig:
    apps = cfg.env_files[1]
    entries = (*apps.entries, EnvEntry(key="EXTRA", value="1"))
    return cfg.model_copy(update={"env_files": (cfg.env_files[0], apps.model_copy(update={"entries": entries}))})


def test_an_app_env_change_reloads_without_stopping_anything(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    changed_cfg = _changed_apps_env(cfg)
    responses = converged(cfg, secrets)
    responses[RENDER_PROBE] = [
        f"id group:media {GID}",
        f"id user:vpnstack {UID}",
        f"file {VPN_ENV} same",
        f"file {APPS_ENV} differs",
    ]

    run = deploy(changed_cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, HOST_ENV, RELOAD, QBT, STAMP]
    assert "systemctl reload vpnstack.service" in run.executed_commands


def test_a_vpn_env_change_stops_the_dependents_before_the_reload(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    changed = values(cfg, vpn_preshared_key="fixture-other-preshared-key0123456789=")
    responses = converged(cfg, secrets)
    responses[RENDER_PROBE] = [
        f"id group:media {GID}",
        f"id user:vpnstack {UID}",
        f"file {VPN_ENV} differs",
        f"file {APPS_ENV} same",
    ]

    run = deploy(cfg, changed, responses)

    assert run.mutating_changed_ops == [PENDING, HOST_ENV, STOP_DEPENDENTS, RELOAD, QBT, STAMP]
    assert "docker compose -p vpnstack -f /home/vpnstack/site/compose.yml stop client indexer" in run.executed_commands


def test_a_unit_only_change_reloads_systemd_and_touches_no_container(
    cfg: ComposeAppConfig, secrets: SecretValues
) -> None:
    responses = converged(cfg, secrets)
    responses.update(fakehost.file(UNIT, render_unit(cfg).replace("TimeoutStartSec=300", "TimeoutStartSec=0")))

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        f"{PREFIX}Install systemd unit vpnstack.service",
        f"{PREFIX}Reload systemd for vpnstack.service",
    ]


def test_a_unit_systemd_did_not_reload_is_reloaded(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    responses = converged(
        cfg, secrets, **{"systemctl show -p ActiveState": ["ActiveState=active", "NeedDaemonReload=yes"]}
    )

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [f"{PREFIX}Reload systemd for vpnstack.service"]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"client": "exited"}, [PENDING, RELOAD, QBT, STAMP]),
        ({"indexer": ""}, [PENDING, RELOAD, QBT, STAMP]),
        ({"vpn": "exited"}, [PENDING, STOP_DEPENDENTS, RELOAD, QBT, STAMP]),
    ],
)
def test_a_stopped_or_removed_container_is_restored(
    cfg: ComposeAppConfig, secrets: SecretValues, status: dict[str, str], expected: list[str]
) -> None:
    responses = converged(cfg, secrets, **{"docker inspect --format": running(cfg, **status)})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == expected


def test_a_container_on_another_image_is_recreated(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    lines = [line.replace(IMAGE_IDS[CLIENT_IMAGE], "sha256:" + "8" * 64) for line in running(cfg)]
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"docker inspect --format": lines}))

    assert run.mutating_changed_ops == [PENDING, RELOAD, QBT, STAMP]


def test_a_missing_image_is_pulled_before_the_apply(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    images = [f"{ref} {image}" for ref, image in IMAGE_IDS.items() if ref != CLIENT_IMAGE]
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"docker image inspect": images}))

    assert run.mutating_changed_ops == [PENDING, f"{PREFIX}Pull {CLIENT_IMAGE}", RELOAD, QBT, STAMP]
    assert f"docker pull --quiet {CLIENT_IMAGE}" in run.executed_commands


def test_an_inactive_unit_is_started_with_the_dependents_stopped_first(
    cfg: ComposeAppConfig, secrets: SecretValues
) -> None:
    responses = converged(cfg, secrets, **{"systemctl show -p ActiveState": ["ActiveState=inactive"]})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, STOP_DEPENDENTS, START, QBT, STAMP]


# -- the gating state machine --------------------------------------------------


def test_a_run_that_stopped_after_its_writes_is_finished_by_the_next(
    cfg: ComposeAppConfig, secrets: SecretValues
) -> None:
    """Files and stamp as desired, but ``pending`` left: apply again, every provider handled."""

    responses = converged(cfg, secrets, **{f"test -e {STATE}/pending": ["pending"]})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, STOP_DEPENDENTS, RELOAD, QBT, STAMP]


def test_a_failed_apply_reverted_to_the_stamp_is_applied_again(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    """A change failed (stamp still old, pending set); its revert matches the stamp, the host still has the change."""

    responses = converged(cfg, secrets, **{f"test -e {STATE}/pending": ["pending"]})
    responses[RENDER_PROBE] = [
        f"id group:media {GID}",
        f"id user:vpnstack {UID}",
        f"file {VPN_ENV} differs",
        f"file {APPS_ENV} same",
    ]

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, HOST_ENV, STOP_DEPENDENTS, RELOAD, QBT, STAMP]


def test_a_hand_edited_compose_file_is_rewritten_and_applied(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    responses.update(fakehost.file(COMPOSE, render_compose(cfg) + "# edited\n"))

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, f"{PREFIX}Write compose.yml", STOP_DEPENDENTS, RELOAD, QBT, STAMP]


def test_a_missing_stamp_applies_once(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets, **{f"cat {STATE}/applied.json": []})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, STOP_DEPENDENTS, RELOAD, QBT, STAMP]


def test_changed_host_ids_apply(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets)
    responses[RENDER_PROBE] = [
        f"id group:media {GID + 1}",
        f"id user:vpnstack {UID}",
        f"file {VPN_ENV} same",
        f"file {APPS_ENV} differs",
    ]

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [PENDING, HOST_ENV, RELOAD, QBT, STAMP]


def test_a_failing_env_probe_writes_and_applies(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{RENDER_PROBE: ["boom", FAILED]}))

    assert run.mutating_changed_ops == [PENDING, HOST_ENV, STOP_DEPENDENTS, RELOAD, QBT, STAMP]


def test_an_unhealthy_vpn_fails_the_apply_with_the_dependents_stopped(
    cfg: ComposeAppConfig, secrets: SecretValues
) -> None:
    changed = values(cfg, vpn_preshared_key="fixture-other-preshared-key0123456789=")
    responses = converged(cfg, secrets)
    responses[RENDER_PROBE] = [
        f"id group:media {GID}",
        f"id user:vpnstack {UID}",
        f"file {VPN_ENV} differs",
        f"file {APPS_ENV} same",
    ]
    responses["systemctl reload vpnstack.service"] = {"success": False}

    run = deploy(cfg, changed, responses, succeed=False)

    assert not run.succeeded
    assert run.op(STOP_DEPENDENTS).changed
    assert not run.op(RELOAD).succeeded
    # Nothing after the failed apply: no API step, no stamp, so the next run applies again.
    assert not any(command.endswith("' stamp") for command in run.executed_commands)
    assert not run.op(STAMP).succeeded


def test_config_file_readers_restart_when_it_changes(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    config = ConfigFile(
        path=f"{DATA}/client/config/extra.yml", format="yaml", data={"key": "new"}, restarts=("client",)
    )
    with_config = cfg.model_copy(update={"config_files": (config,)})
    responses = converged(cfg, secrets)
    stamp = json.loads(stamp_document(cfg, secrets))
    stamp["files"][str(config.path)] = "0" * 64
    responses[f"cat {STATE}/applied.json"] = [json.dumps(stamp)]

    run = deploy(with_config, secrets, responses)

    assert run.mutating_changed_ops == [
        PENDING,
        f"{PREFIX}Write {config.path}",
        RELOAD,
        f"{PREFIX}Restart client for their config files",
        QBT,
        STAMP,
    ]
    assert "docker compose -p vpnstack -f /home/vpnstack/site/compose.yml restart client" in run.executed_commands


# -- steps, legacy paths, preflight ---------------------------------------------


def test_preference_drift_runs_the_apply_step_only(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    responses = converged(cfg, secrets, **{QBT_PROBE: ["drift listen_port"]})

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [QBT]
    stdin = [text for command, text in run.stdin if command.endswith("' apply")]
    assert len(stdin) == 1


def test_a_differing_key_copy_is_written(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{COPY_PROBE: ["differs"]}))

    assert run.mutating_changed_ops == [COPY]


def test_legacy_paths(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    responses = converged(
        cfg,
        secrets,
        **{
            f"test -d {DATA}/incomplete": ["yes"],
            f"test -d {DATA}/watch": ["yes"],
            f"find {DATA}/watch ! -type d": [f"{DATA}/watch/file"],
            f"test -e {SITE}/.env && echo yes": ["yes"],
            **fakehost.stat(f"{SITE}/.env"),
        },
    )

    run = deploy(cfg, secrets, responses)

    assert f"{PREFIX}Remove the empty legacy directory {DATA}/incomplete" in run.mutating_changed_ops
    assert f"{PREFIX}Remove the empty legacy directory {DATA}/watch" not in run.mutating_changed_ops
    assert f"{PREFIX}Remove the former {SITE}/.env" in run.mutating_changed_ops
    assert PENDING in run.mutating_changed_ops


def test_port_preflight_runs_before_any_change(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**fakehost.UBUNTU, "ss -Hltnp": {"success": False}}, succeed=False)

    assert not run.succeeded
    assert run.mutating_changed_ops == []


# -- remove --------------------------------------------------------------------


def test_remove_needs_confirmation(cfg: ComposeAppConfig) -> None:
    run = run_deploy_fake(remove_compose_app, ComposeAppRemoveConfig(app=cfg), responses={**fakehost.LINUX})
    assert not run.succeeded


def test_remove_keeps_data_and_host_secrets(cfg: ComposeAppConfig) -> None:
    responses = {
        **fakehost.LINUX,
        "docker ps -aq": ["abc"],
        "systemctl show": ["Id=vpnstack.service", "ActiveState=active", "UnitFileState=enabled", "---"],
        **{f"test -e {path} && echo yes": ["yes"] for path in (UNIT, ROUTE, VPN_ENV, APPS_ENV, COMPOSE, STATE)},
    }

    run = run_deploy_fake(remove_compose_app, ComposeAppRemoveConfig(app=cfg, confirm=True), responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "docker compose -p vpnstack -f /home/vpnstack/site/compose.yml down --remove-orphans" in commands
    for path in (UNIT, ROUTE, VPN_ENV, APPS_ENV, COMPOSE, STATE):
        assert f"rm -rf {path}" in commands
    assert not any(DATA in command or APIKEY in command for command in commands)


def test_the_documented_arr_example_validates() -> None:
    text = (Path(__file__).parents[1] / "docs/services/compose_app.md").read_text()
    code = text.split("```python\nRADARR = ", 1)[1].split("\n```", 1)[0]
    spec = ast.literal_eval(code.replace("<version>", "6.0.4").replace("<digest>", "0" * 64))

    cfg = ComposeAppConfig.model_validate({**spec, "service_name": "radarr", "secrets": "secrets/prod/radarr.yml"})

    assert cfg.route is not None
    assert cfg.route.access == "internal"
    doc = yaml.safe_load(render_compose(cfg))
    assert doc["networks"] == {"media": {"name": "media", "external": True}}
    assert doc["services"]["radarr"]["networks"] == ["default", "media"]


def test_an_internal_route_has_no_external_router(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    from ops_deploy.helpers.traefik import render_route
    from ops_deploy.services.compose_app.deploy import route_config

    route = cfg.route
    assert route is not None
    internal = cfg.model_copy(update={"route": Route(host=route.host, port=route.port, access="internal")})
    rendered = route_config(internal, secrets)
    assert rendered is not None

    doc = yaml.safe_load(render_route(rendered, None))
    routers = doc["http"]["routers"]
    assert set(routers) == {"vpnstack-int", "vpnstack-http"}
    assert "ClientIP(`192.168.0.0/16`)" in routers["vpnstack-int"]["rule"]
    assert routers["vpnstack-http"]["rule"] == routers["vpnstack-int"]["rule"]
    assert "middlewares" not in doc["http"] or "vpnstack-auth" not in doc["http"]["middlewares"]


def test_config_files_may_not_restart_a_namespace_provider(cfg: ComposeAppConfig) -> None:
    data = cfg.model_dump()
    data["config_files"] = [{"path": f"{SITE}/vpn/extra.yml", "format": "yaml", "data": {}, "restarts": ["vpn"]}]
    with pytest.raises(ConfigValidationError, match="restarts namespace provider vpn"):
        ComposeAppConfig.model_validate(data)


def test_directory_owner_and_group_are_both_names_or_both_ids() -> None:
    with pytest.raises(ValueError, match="both names or both numeric ids"):
        Directory(path="/srv/x", owner="990", group="media")


def _run_check(command: str, tmp_path: Path, ss: str, ports: str) -> subprocess.CompletedProcess[str]:
    """Run a generated check locally with stand-ins for ``ss`` and ``docker``."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "ss").write_text(f"#!/bin/sh\ncat <<'X'\n{ss}\nX\n")
    (bin_dir / "docker").write_text(f"#!/bin/sh\ncat <<'X'\n{ports}\nX\n")
    for tool in ("ss", "docker"):
        (bin_dir / tool).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    return subprocess.run(["sh", "-c", command], capture_output=True, text=True, env=env, check=False)


@pytest.mark.parametrize("host_ip", ["127.0.0.1", "::1"])
def test_port_checks_match_addresses_literally(cfg: ComposeAppConfig, tmp_path: Path, host_ip: str) -> None:
    from ops_deploy.services.compose_app import checks

    vpn = cfg.services[0].model_copy(update={"ports": (PublishedPort(published=18080, target=8080, host_ip=host_ip),)})
    app = cfg.model_copy(update={"services": (vpn, *cfg.services[1:]), "route": None, "steps": ()})
    address = f"[{host_ip}]" if ":" in host_ip else host_ip
    listener = f'LISTEN 0 4096 {address}:18080 0.0.0.0:* users:(("docker-proxy",pid=1,fd=4))'
    ours = f"{address}:18080->8080/tcp"

    def command(build: Any) -> str:
        run = run_deploy_fake(lambda: build(app), responses={**fakehost.LINUX})
        return next(c for c in run.executed_commands if c.startswith("sh -c "))

    from pyinfra.api import deploy as pyinfra_deploy

    preflight = command(pyinfra_deploy("p")(checks.port_preflight))
    listen = command(pyinfra_deploy("l")(lambda a: checks.listen(a)))

    assert _run_check(preflight, tmp_path, listener, ours).returncode == 0
    taken = _run_check(preflight, tmp_path, listener, "")
    assert taken.returncode == 1
    assert "port tcp/18080 is in use" in taken.stderr
    assert _run_check(preflight, tmp_path, "", "").returncode == 0
    assert _run_check(listen, tmp_path, listener.replace("users:", "x"), ours).returncode == 0
    wide = f"{listener}\nLISTEN 0 4096 0.0.0.0:18080 0.0.0.0:*"
    assert _run_check(listen, tmp_path, wide, ours).returncode == 1
