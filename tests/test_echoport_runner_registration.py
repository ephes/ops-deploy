"""``_echoport_runner.registration``: a same-host root runner's register playbook as one deploy, on the fake host."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner import RunnerConfig, runner_script, service_config, sudoers_rule
from ops_deploy.services._echoport_runner.access import MinioAccess, alias_digest, render_account_policy
from ops_deploy.services._echoport_runner.registration import (
    DEFAULT_IPV4_FALLBACK,
    RunnerRegistration,
    install_registration,
    register_runner,
    template_variables,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/echoport_runner"
INPUTS = json.loads((PARITY / "inputs.json").read_text())["runners"]
EXPECTED = json.loads((PARITY / "expected.json").read_text())["runners"]
SECRET = "fixture-account-secret-0123456789abcdef"  # pragma: allowlist secret
ANCESTORS = {"LC_ALL=C LANG=C stat -c '%u %g %a %F'": ["0 0 755 directory"] * 3}
MC_PRESENT = {"test -x /usr/local/bin/mc": ["present"]}
ACCOUNT_PROBE = "def statements(doc)"
ROUTE = "ip -4 route get 8.8.8.8"
STORED = "select data::text from service where name"
# The address inputs.json gives homeassistant's ansible_default_ipv4.
HOMEASSISTANT_ADDRESS = "192.0.2.10"


def registration(name: str = "snappymail-backup", **changes: Any) -> RunnerRegistration:
    """A runner of inputs.json, registered for its target as the playbook does."""

    runner = INPUTS[name]
    variables = dict(runner["inputs"])
    ipv4: tuple[str, ...] = ()
    if "ansible_default_ipv4" in variables:
        del variables["ansible_default_ipv4"]
        ipv4 = ("homeassistant_backup_health_forwarded_for",)
        del variables[ipv4[0]]
    alias = variables["echoport_backup_minio_alias"]
    values: dict[str, Any] = {
        "runner": RunnerConfig(
            service=name,
            description=f"{name} runner",
            steps=("init", "upload", "result"),
            template=runner["template"],
            run_as="root",
        ),
        "access": MinioAccess(
            target=alias.removeprefix("backup-"),
            os_user="root",
            alias=alias,
            url="http://127.0.0.1:9001",
            scoped=True,
            retired_aliases=("minio",),
        ),
        "packages": ("rsync",),
        "variables": variables,
        "default_ipv4_variables": ipv4,
        **changes,
    }
    return RunnerRegistration(**values)


def _file(path: str, content: str, *, group: str, mode: str) -> dict[str, Any]:
    return {
        f"sha1sum {path} ": [f"{hashlib.sha1(content.encode()).hexdigest()}  {path}"],
        f"sha256sum {path} ": [f"{hashlib.sha256(content.encode()).hexdigest()}  {path}"],
        **fakehost.stat(path, user="root", group=group, mode=mode),
    }


def converged(cfg: RunnerRegistration, *, address: str = HOMEASSISTANT_ADDRESS) -> dict[Any, Any]:
    """A host the playbook left: packages, account, alias and runner as it writes them."""

    access, runner = cfg.access, cfg.runner
    route = f"8.8.8.8 via 192.0.2.1 dev eth0 src {address} uid 0"
    script = runner_script(runner, {**template_variables_for(cfg, address)})
    responses: dict[Any, Any] = {
        **ANCESTORS,
        **MC_PRESENT,
        ROUTE: [route],
        **fakehost.deb_installed(*cfg.packages),
        re.compile(rf"mc ls {access.alias}/backups/{access.target}/ >/dev/null && echo ok"): ["ok"],
        ACCOUNT_PROBE: ["policy=ok user=attached"],
        re.compile(rf"alias list {access.alias} \)"): [alias_digest(access.url, access.account.user, SECRET)],
        re.compile(r"alias list minio \)"): ["none"],
        **fakehost.directory("/etc/minio/policies", mode="drwxr-x---"),
        **fakehost.file(
            f"/etc/minio/policies/backup-{access.target}.json",
            render_account_policy(access.account),
            mode="-rw-r-----",
        ),
    }
    for path in ("/usr/local/libexec", runner.libexec_root, runner.runner_dir, runner.services, runner.service_dir):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.directory("/etc/sudoers.d"))
    responses.update(_file(runner.script, script, group=runner.group, mode="-rwxr-x---"))
    config = service_config(runner)
    responses.update(_file(f"{runner.service_dir}/config.json", config, group="root", mode="-rw-r--r--"))
    responses.update(_file(runner.sudoers, sudoers_rule(runner), group="root", mode="-r--r-----"))
    responses[STORED] = [json.dumps(json.loads(config))]
    return responses


def template_variables_for(cfg: RunnerRegistration, address: str | None) -> dict[str, Any]:
    variables = dict(cfg.variables)
    if cfg.default_ipv4_variables:
        variables["ansible_default_ipv4"] = {} if address is None else {"address": address}
        for name in cfg.default_ipv4_variables:
            variables[name] = address or DEFAULT_IPV4_FALLBACK
    return variables


def deploy(cfg: RunnerRegistration) -> Any:
    def run() -> None:
        install_registration(cfg, secret_key=SECRET)

    return run


def refused(run: Any) -> str:
    assert isinstance(run.error, DeployError), run.error
    assert run.executed_commands == []
    return str(run.error)


A1 = (
    "snappymail-backup",
    "delve-backup",
    "echoport-self-backup",
    "fastdeploy-backup",
    "homeassistant-backup",
    "weeknotes-home-backup",
    "paperless-backup",
)


@pytest.mark.parametrize("name", A1)
def test_the_runner_renders_as_ansible_rendered_it(name: str) -> None:
    # expected.json: ansible-playbook's rendering of the same values (homeassistant
    # with ansible_default_ipv4.address 192.0.2.10, read here from the host's route).
    cfg = registration(name)
    variables = template_variables_for(cfg, HOMEASSISTANT_ADDRESS)

    assert hashlib.sha256(runner_script(cfg.runner, variables).encode()).hexdigest() == EXPECTED[name]


@pytest.mark.parametrize("name", A1)
def test_a_converged_host_gets_no_mutating_operation(name: str) -> None:
    cfg = registration(name)
    run = run_deploy_fake(deploy(cfg), responses=converged(cfg))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert SECRET not in run.all_text()


def test_a_first_run_installs_packages_access_and_runner_in_the_playbooks_order() -> None:
    cfg = registration()
    responses = {**ANCESTORS, **MC_PRESENT, ACCOUNT_PROBE: ["policy=missing user=missing"]}
    run = run_deploy_fake(register_runner, cfg, secret_key=SECRET, responses=responses)

    assert run.succeeded, run.error
    names = [name.removeprefix("Echoport backup runner registration | ") for name in run.changed_ops]
    order = [
        "Install the packages of snappymail-backup",
        "Create or update MinIO user of snappymail",
        "Configure mc alias backup-snappymail of root",
        "Install the snappymail-backup runner script",
        "Write config.json of snappymail-backup",
        "Sync FastDeploy services for snappymail-backup",
    ]
    assert [n for n in names if n in order] == order
    assert SECRET not in run.all_text()


def test_a_missing_mc_refuses_before_any_write() -> None:
    cfg = registration()
    message = refused(run_deploy_fake(deploy(cfg), responses={**ANCESTORS, "test -x /usr/local/bin/mc": ["missing"]}))

    assert "mc (MinIO client) not found at /usr/local/bin/mc" in message


def test_an_unsafe_directory_above_the_libexec_root_refuses_before_any_write() -> None:
    cfg = registration()
    unsafe = ["0 0 755 directory", "1000 0 755 directory", "0 0 755 directory"]
    responses = {**converged(cfg), "LC_ALL=C LANG=C stat -c '%u %g %a %F'": unsafe}

    assert "must be a root-owned directory" in refused(run_deploy_fake(deploy(cfg), responses=responses))


def test_homeassistant_without_a_default_route_uses_ansibles_fallback() -> None:
    cfg = registration("homeassistant-backup")
    run = run_deploy_fake(deploy(cfg), responses={**converged(cfg), ROUTE: [""]})

    assert run.succeeded, run.error
    # The runner the deploy uploads, not a copy of its logic.
    script = run.upload(cfg.runner.script).decode()
    assert f'HEALTH_CHECK_FORWARDED_FOR = "{DEFAULT_IPV4_FALLBACK}"' in script
    assert script == runner_script(cfg.runner, template_variables_for(cfg, None))


def test_homeassistant_renders_the_hosts_address() -> None:
    cfg = registration("homeassistant-backup")
    responses = {**converged(cfg), ROUTE: ["8.8.8.8 via 192.0.2.1 dev eth0 src 198.51.100.7 uid 0"]}
    run = run_deploy_fake(deploy(cfg), responses=responses)

    assert run.succeeded, run.error
    script = run.upload(cfg.runner.script).decode()
    assert 'HEALTH_CHECK_FORWARDED_FOR = "198.51.100.7"' in script


def test_a_malformed_route_source_refuses() -> None:
    cfg = registration("homeassistant-backup")
    run = run_deploy_fake(deploy(cfg), responses={**converged(cfg), ROUTE: ["8.8.8.8 dev eth0 src 'x'"]})

    assert "unexpected source address" in refused(run)


def test_other_runners_do_not_read_the_route() -> None:
    def plan() -> None:
        template_variables(registration())

    run = run_deploy_fake(plan, responses={})

    assert run.succeeded, run.error
    assert ROUTE not in run.all_text()


@pytest.mark.parametrize(
    "changes",
    [
        {"variables": {"echoport_backup_minio_alias": "backup-other"}},
        {"variables": {"echoport_backup_mc_install_path": "/opt/mc"}},
        {"variables": {"echoport_backup_default_bucket": "other-bucket"}},
        {"default_ipv4_variables": ("echoport_backup_default_bucket",)},
    ],
)
def test_values_that_contradict_the_access_are_refused(changes: dict[str, Any]) -> None:
    base = registration()
    if "variables" in changes:
        changes = {"variables": {**base.variables, **changes["variables"]}}
    with pytest.raises(ValueError, match="runner registration"):
        registration(**changes)


def test_a_runner_as_deploy_or_from_content_or_unscoped_is_refused() -> None:
    base = registration()
    with pytest.raises(ValueError, match="runs as root"):
        registration(runner=base.runner.model_copy(update={"run_as": ""}))
    with pytest.raises(ValueError, match="vendored runner template"):
        registration(
            runner=RunnerConfig(service="snappymail-backup", steps=("init",), content="#!/bin/sh\n", run_as="root")
        )
    with pytest.raises(ValueError, match="scoped account"):
        registration(access=base.access.model_copy(update={"scoped": False}))


def test_a_template_that_is_not_a_vendored_runner_is_refused() -> None:
    base = registration()
    for template in ("heis_production_backup.py.j2", "_work_dir.py.j2"):
        with pytest.raises(ValueError, match="vendored runner template"):
            registration(runner=base.runner.model_copy(update={"template": template}))


def test_a_template_without_the_work_dir_include_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # The playbooks' "Require a runner that works on the external disk only";
    # every vendored runner includes _work_dir.py.j2 today.
    from ops_deploy.services._echoport_runner import registration as module

    monkeypatch.setattr(module, "_template_source", lambda _template: "WORK_DIR = '/tmp'\n")
    with pytest.raises(ValueError, match=r"does not include _work_dir\.py\.j2"):
        registration()
