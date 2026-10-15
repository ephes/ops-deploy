"""Deploy-level scenarios for logyard ingress, the Vector producer and the whole stack."""

import base64
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.infra.vector_apt_install import repository_line
from ops_deploy.services.logyard import (
    AllowedPath,
    LogyardIngressConfig,
    LogyardVectorConfig,
    Match,
    deploy_logyard,
    deploy_logyard_ingress,
    deploy_logyard_vector,
)
from ops_deploy.services.logyard import ingress as ingress_module
from ops_deploy.services.logyard import vector as vector_module
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.logyard_fixtures import ingress_config, make_source, secrets_values, stack_config, vector_config
from tests.test_infra_docker_vector import vector_converged
from tests.test_logyard import converged as core_converged

ROUTE = "/etc/traefik/dynamic/logyard.yml"
INGRESS = "Deploy logyard ingress | "
VECTOR = "Deploy logyard vector | "
FRAGMENT = "/etc/vector/config.d/30-logyard-journald.yaml"
GLOBAL = "/etc/vector/config.d/00-global.yaml"
DEFAULTS = "/etc/default/vector"
VERSION = "vector 0.58.1 (x86_64-unknown-linux-gnu 1a2b3c4 2026-05-01 12:00:00.123456789)"


# -- ingress ------------------------------------------------------------------------


def ingress_converged(cfg: LogyardIngressConfig) -> dict[str, Any]:
    return {
        **fakehost.LINUX,
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(ROUTE, ingress_module.render_route(cfg)),
    }


def run_ingress(cfg: LogyardIngressConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_logyard_ingress, cfg, responses=responses or dict(fakehost.LINUX))
    assert result.succeeded, result.error
    return result


def test_ingress_first_run_writes_the_route() -> None:
    cfg = ingress_config()

    run = run_ingress(cfg)

    assert run.upload(ROUTE).decode() == ingress_module.render_route(cfg)
    assert "mkdir -p /etc/traefik/dynamic" in run.executed_commands
    # Like the role: Traefik's file provider picks the route up, nothing restarts it.
    assert not any("traefik" in c and "systemctl" in c for c in run.executed_commands)


def test_ingress_second_run_changes_nothing() -> None:
    cfg = ingress_config()

    run = run_ingress(cfg, ingress_converged(cfg))

    assert run.mutating_changed_ops == []
    assert run.uploaded_paths == []


def test_ingress_change_rewrites_only_the_route() -> None:
    old, new = ingress_config(), ingress_config(middlewares=("auth@file",))

    run = run_ingress(new, ingress_converged(old))

    assert run.mutating_changed_ops == [INGRESS + "Write Traefik route logyard"]
    assert "- auth@file" in run.upload(ROUTE).decode()


def test_ingress_routes_only_the_producer_paths() -> None:
    routers = yaml.safe_load(ingress_module.render_route(ingress_config()))["http"]["routers"]

    rule = routers["logyard-int"]["rule"]
    assert "Path(`/loki/api/v1/push`)" in rule
    assert "Path(`/ready`)" in rule
    assert "Method(`POST`)" in rule
    assert "/query" not in rule
    assert routers["logyard-root"]["middlewares"] == ["logyard-root-redirect"]


def test_ingress_without_resolver_or_redirect() -> None:
    text = ingress_module.render_route(ingress_config(traefik_cert_resolver="", root_redirect_enabled=False))

    parsed = yaml.safe_load(text)["http"]
    assert "logyard-root" not in parsed["routers"]
    assert parsed["routers"]["logyard-int"]["tls"] == {}
    assert "logyard-root-redirect" not in parsed["middlewares"]


@pytest.mark.parametrize(
    "bad",
    [
        {"host": "logyard.example.com"},
        {"host": "bad host"},
        {"backend_url": "ftp://127.0.0.1:3101"},
        {"backend_url": "http://127.0.0.1"},
        {"internal_ip_ranges": ()},
        {"internal_ip_ranges": ("not-a-network",)},
        {"allowed_paths": ()},
        {"allowed_paths": ({"path": "no-slash", "methods": ("GET",)},)},
        {"allowed_paths": ({"path": "/ok", "methods": ()},)},
        {"allowed_paths": ({"path": "/ok", "methods": ("get",)},)},
        {"root_redirect_url": ""},
        {"middlewares": ("bad middleware",)},
        {"unknown": 1},
    ],
)
def test_ingress_config_rejects_bad_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ingress_config(**bad)


def test_ingress_allowed_path_model() -> None:
    entry = AllowedPath(path="/ready", methods=("GET",))
    assert ingress_config(allowed_paths=(entry,)).allowed_paths == (entry,)


# -- vector ---------------------------------------------------------------------------


def file_as(path: str, text: str, *, group: str, mode: str) -> dict[str, Any]:
    return {**fakehost.file(path, text), **fakehost.stat(path, group=group, mode=mode)}


def vector_host(cfg: LogyardVectorConfig, **drift: str) -> dict[str, Any]:
    """A host where Vector and the Logyard fragment are deployed; ``drift`` overrides file content."""

    content = {
        FRAGMENT: vector_module.render_fragment(cfg, True),
        GLOBAL: vector_module.render_global(cfg),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **vector_converged(cfg.apt),
        "vector --version": [VERSION],
        **fakehost.stat("/var/lib/vector", user="vector", mode="drwxr-x---"),
        **fakehost.stat("/etc/vector/config.d", group="vector", mode="drwxr-x---"),
        **fakehost.directory("/etc/default"),
        **file_as(DEFAULTS, "# vector\nVECTOR_CONFIG_DIR=/etc/vector/config.d\n", group="root", mode="-rw-r--r--"),
        **fakehost.service("vector.service"),
    }
    for path, text in content.items():
        responses.update(file_as(path, text, group="vector", mode="-rw-r-----"))
    return responses


def run_vector(cfg: LogyardVectorConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_logyard_vector, cfg, responses=responses or dict(fakehost.UBUNTU))
    assert result.succeeded, (result.error, [op.name for op in result.ops if not op.succeeded])
    return result


def test_vector_first_run_installs_configures_and_starts() -> None:
    cfg = vector_config()

    run = run_vector(cfg)
    commands = run.executed_commands

    assert run.upload(FRAGMENT).decode() == vector_module.render_fragment(cfg, True)
    assert run.upload(GLOBAL).decode() == 'data_dir: "/var/lib/vector"\n'
    assert run.upload(DEFAULTS).decode() == "VECTOR_CONFIG_DIR=/etc/vector/config.d\n"
    assert "chown vector:vector /var/lib/vector" in commands
    assert "chown root:vector /etc/vector/config.d" in commands
    # The package may have started Vector with its stock config: restart once configured.
    assert "systemctl restart vector.service" in commands
    assert "systemctl enable vector.service" in commands
    assert "systemctl start vector.service" in commands
    # Validation happens before the live files are replaced.
    validate = next(i for i, c in enumerate(commands) if "vector validate" in c)
    assert validate < commands.index("systemctl restart vector.service")
    assert not any(c.startswith("mv ") and "30-logyard" in c for c in commands)


def test_vector_second_run_changes_nothing_but_the_validation() -> None:
    cfg = vector_config()

    run = run_vector(cfg, vector_host(cfg))

    assert run.mutating_changed_ops == []
    assert run.uploaded_paths == []
    assert run.changed_ops == [VECTOR + "Validate the staged Vector configuration"]


def test_vector_fragment_change_restarts_vector_once() -> None:
    cfg = vector_config()

    run = run_vector(cfg, vector_host(cfg, **{FRAGMENT: "sources: {}\n"}))

    assert run.mutating_changed_ops == [
        VECTOR + "Deploy the Logyard Vector config fragment",
        VECTOR + "Restart vector.service",
    ]
    assert run.executed_commands.count("systemctl restart vector.service") == 1


def test_vector_env_line_is_set_when_missing_or_different() -> None:
    cfg = vector_config()
    responses = vector_host(cfg)
    responses.update(
        file_as(DEFAULTS, "# vector\nVECTOR_CONFIG_DIR=/etc/vector\nOTHER=1\n", group="root", mode="-rw-r--r--")
    )

    run = run_vector(cfg, responses)

    assert run.mutating_changed_ops == [
        VECTOR + "Point Vector at its config directory",
        VECTOR + "Restart vector.service",
    ]
    assert run.upload(DEFAULTS).decode() == "# vector\nVECTOR_CONFIG_DIR=/etc/vector/config.d\nOTHER=1\n"


def test_lineinfile_matches_the_modules_behaviour() -> None:
    line = "VECTOR_CONFIG_DIR=/x"
    pattern = "^VECTOR_CONFIG_DIR="
    lineinfile = vector_module.lineinfile

    assert lineinfile("p", pattern, line, current=None) == "VECTOR_CONFIG_DIR=/x\n"
    assert lineinfile("p", pattern, line, current=["A=1"]) == "A=1\nVECTOR_CONFIG_DIR=/x\n"
    # The last match is replaced, earlier ones stay.
    assert lineinfile("p", pattern, line, current=["VECTOR_CONFIG_DIR=a", "B=2", "VECTOR_CONFIG_DIR=b"]) == (
        "VECTOR_CONFIG_DIR=a\nB=2\nVECTOR_CONFIG_DIR=/x\n"
    )
    # A commented-out assignment is not a match.
    assert (
        lineinfile("p", pattern, line, current=["#VECTOR_CONFIG_DIR=a"])
        == "#VECTOR_CONFIG_DIR=a\nVECTOR_CONFIG_DIR=/x\n"
    )


def test_other_global_data_dir_stops_the_deploy_before_any_change() -> None:
    cfg = vector_config()
    responses = vector_host(cfg, **{GLOBAL: 'data_dir: "/srv/vector"\n'})

    run = run_deploy_fake(deploy_logyard_vector, cfg, responses=responses)

    assert not run.succeeded
    assert "uses data_dir=/srv/vector" in str(run.error)
    assert run.executed_commands == []


def test_global_data_dir_helper() -> None:
    from pathlib import PurePosixPath

    default = PurePosixPath("/var/lib/vector")
    assert vector_module.global_data_dir(None, default) == "/var/lib/vector"
    assert vector_module.global_data_dir(["sources: {}"], default) == "/var/lib/vector"
    assert vector_module.global_data_dir(['data_dir: "/x"'], default) == "/x"
    assert vector_module.global_data_dir(["data_dir: /y", "api:", "  enabled: true"], default) == "/y"


@pytest.mark.parametrize(
    ("output", "default", "expected"),
    [
        (VERSION, False, True),
        ("vector 0.54.0 (x86_64)", True, False),
        ("vector 0.57.0 (x86_64)", False, True),
        ("vector 0.56.9 (x86_64)", True, False),
        ("vector 1.0.0", False, True),
        ("", True, True),
        ("", False, False),
        ("command not found", False, False),
    ],
)
def test_template_confinement_follows_the_installed_version(output: str, default: bool, expected: bool) -> None:
    assert vector_module.supports_confinement(output, default) is expected


def test_old_vector_gets_a_fragment_without_the_opt_out() -> None:
    cfg = vector_config()
    responses = vector_host(cfg)
    responses["vector --version"] = ["vector 0.45.0 (x86_64-unknown-linux-gnu)"]

    run = run_vector(cfg, responses)

    # The fragment on the host has the opt-out; Vector 0.45 predates it.
    assert run.mutating_changed_ops == [
        VECTOR + "Deploy the Logyard Vector config fragment",
        VECTOR + "Restart vector.service",
    ]
    assert "dangerously_allow_unconfined_template_resolution" not in run.upload(FRAGMENT).decode()


def test_validation_stages_the_directory_and_validates_it() -> None:
    cfg = vector_config()

    run = run_vector(cfg, vector_host(cfg))

    command = next(c for c in run.executed_commands if "vector validate" in c)
    assert "mktemp -d /tmp/logyard-vector-validate-" in command
    assert 'rm -rf "$dir"' in command
    assert "! -name 30-logyard-journald.yaml ! -name 00-global.yaml" in command
    assert "vector validate --skip-healthchecks --config-dir" in command
    # A missing config directory (first install) is no reason to fail before validating.
    assert "if [ -d /etc/vector/config.d ]; then find /etc/vector/config.d" in command
    decoded = [base64.b64decode(part).decode() for part in re.findall(r"printf %s (\S+) \| base64 -d", command)]
    assert 'data_dir: "/var/lib/vector"\n' in decoded
    assert vector_module.render_fragment(cfg, True) in decoded


def test_vector_options_reach_the_fragment() -> None:
    cfg = vector_config(
        include_units=("ssh.service",),
        include_matches=(Match(key="_COMM", value="sshd"),),
        current_boot_only=True,
        ingest_endpoint="https://logyard.example.invalid",
        host_id="fractal",
        environment="staging",
    )

    fragment = yaml.safe_load(vector_module.render_fragment(cfg, True))

    assert fragment["sources"]["journald_logs"] == {
        "type": "journald",
        "current_boot_only": True,
        "include_units": ["ssh.service"],
        "include_matches": {"_COMM": "sshd"},
    }
    sink = fragment["sinks"]["logyard_loki"]
    assert sink["endpoint"] == "https://logyard.example.invalid"
    assert sink["labels"]["host"] == "fractal"
    assert sink["labels"]["environment"] == "staging"
    assert sink["dangerously_allow_unconfined_template_resolution"] is True


@pytest.mark.parametrize(
    "bad",
    [
        {"host_id": "has space"},
        {"host_id": ""},
        {"source_type": "file"},
        {"ingest_endpoint": "ftp://x"},
        {"data_dir": "var/lib/vector"},
        {"config_name": "30-logyard.txt"},
        {"buffer_max_size": 0},
        {"unknown": 1},
    ],
)
def test_vector_config_rejects_bad_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        vector_config(**bad)


def test_vector_installs_from_the_configured_repository() -> None:
    cfg = vector_config()

    run = run_vector(cfg)

    assert run.upload(cfg.apt.repo_list_file).decode() == repository_line(cfg.apt)


# -- the stack ----------------------------------------------------------------------------


def test_stack_runs_core_ingress_and_vector_in_the_playbooks_order(tmp_path: Path) -> None:
    cfg = stack_config(make_source(tmp_path))

    run = run_deploy_fake(
        deploy_logyard,
        cfg,
        secrets_values(),
        RecordingRsyncRunner(),
        responses={**fakehost.UBUNTU},
    )

    assert run.succeeded, run.error
    uploads = run.uploaded_paths
    order = [
        uploads.index("/etc/logyard/loki-config.yml"),
        uploads.index("/etc/traefik/dynamic/logyard.yml"),
        uploads.index("/etc/vector/config.d/30-logyard-journald.yaml"),
    ]
    assert order == sorted(order)


def test_converged_stack_changes_nothing(tmp_path: Path) -> None:
    cfg = stack_config(make_source(tmp_path))
    core, vector = core_converged(cfg.core), vector_host(cfg.vector)
    responses = {**core, **ingress_converged(cfg.ingress), **vector}
    # Facts that list several hosts' worth of state are the union of both.
    for key in ("dpkg -l", "cat /etc/group", "cat /etc/passwd | cut"):
        responses[key] = list(dict.fromkeys([*core[key], *vector.get(key, [])]))

    run = run_deploy_fake(deploy_logyard, cfg, secrets_values(), RecordingRsyncRunner(), responses=responses)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploaded_paths == []
