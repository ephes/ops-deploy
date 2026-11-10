"""``_echoport_runner``: heis-production-backup and villakunterbunt-staging-backup, on the fake host.

Their templates predate the work dir on the external disk: the registration
makes the playbooks' temp dir instead (:class:`TempDir`), and heis's also
installs the playbook's monthly token rotation timer (:mod:`.rotation`).
Their playbooks wrote the runner into FastDeploy's services root; the port
installs it in the libexec layout and removes that copy.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner import RunnerConfig, runner_script
from ops_deploy.services._echoport_runner.access import KnownHost, MinioAccess, WorkDir
from ops_deploy.services._echoport_runner.registration import (
    DeployRunnerRegistration,
    TempDir,
    install_deploy_registration,
)
from ops_deploy.services._echoport_runner.rotation import (
    TokenRotation,
    install_token_rotation,
    rotation_names,
    rotation_texts,
)
from ops_deploy.services._echoport_runner.target import RunnerTarget, ServiceToken, target_code, target_script
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests import test_echoport_runner_deploy_registration as deploy_tests

INPUTS = deploy_tests.INPUTS
EXPECTED = deploy_tests.EXPECTED
USER = "fixture-fastdeploy-user"
HEIS = "heis-production-backup"
VILLA = "villakunterbunt-staging-backup"
HEIS_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdddddddddddddddddddddddddddddddddddddddddd"
HELPER = "/usr/local/sbin/rotate-heis-production-backup-token"
UNIT = "heis-production-backup-token-rotate"
ROTATION_VARIABLES = {
    "heis_production_backup_fastdeploy_root": "/home/fastdeploy/site",
    "heis_production_backup_fastdeploy_user": "fastdeploy",
    "heis_production_backup_service_name_fd": HEIS,
    "heis_production_backup_service_token_expiration_days": 90,
    "heis_production_backup_target_name": "heis-production",
}
BINDINGS = {
    "target": "heis_production_backup_target_name",
    "service": "heis_production_backup_service_name_fd",
    "fastdeploy_root": "heis_production_backup_fastdeploy_root",
    "fastdeploy_user": "heis_production_backup_fastdeploy_user",
    "days": "heis_production_backup_service_token_expiration_days",
}
# Each playbook's order of its parts (the first task of each).
TASKS: dict[str, tuple[Any, ...]] = {
    HEIS: ("packages", "mc", "access", "runner", "temp_dir", "known_hosts", "target", "token_rotation"),
    VILLA: ("packages", "mc", "access", "runner", "temp_dir", "known_hosts", "target"),
}


def rotation(**changes: Any) -> TokenRotation:
    values: dict[str, Any] = {
        "name": "heis_production_backup",
        "helper": HELPER,
        "unit": UNIT,
        "variables": ROTATION_VARIABLES,
        "user_variable": "heis_production_backup_service_token_user",
        "bindings": BINDINGS,
        **changes,
    }
    return TokenRotation(**values)


def target(name: str) -> RunnerTarget:
    short = name.removesuffix("-backup")
    return RunnerTarget(
        name=short,
        script=target_script("remote_sqlite_site"),
        values={
            "target_name": short,
            "target_description": f"{short} backup",
            "service_name_fd": name,
            "target_schedule": "35 3 * * *",
            "target_retention_days": 30,
            "target_timeout_seconds": 1800,
            "default_bucket": "backups",
        },
        token=ServiceToken(targets=(short,), service=name),
    )


def registration(name: str = HEIS, **changes: Any) -> DeployRunnerRegistration:
    variables = dict(INPUTS[name]["inputs"])
    short = name.removesuffix("-backup")
    host = str(variables[name.replace("-", "_").removesuffix("_backup") + "_backup_default_host"])
    known = KnownHost(name=host, pin=HEIS_KEY, pin_address=host) if name == HEIS else KnownHost(name=host)
    values: dict[str, Any] = {
        "runner": RunnerConfig(
            service=name,
            description=f"{name} runner",
            steps=("init", "upload", "result"),
            template=INPUTS[name]["template"],
            sudoers_file=f"/etc/sudoers.d/{name.replace('-', '_')}",
        ),
        "access": MinioAccess(
            target=short,
            os_user="deploy",
            alias=f"backup-{short}",
            url="http://127.0.0.1:9001",
            scoped=True,
            retired_aliases=("minio",),
        ),
        "packages": ("sqlite3",),
        "variables": variables,
        "temp_dir": TempDir(path=str(variables["echoport_backup_temp_dir"]), owner="deploy"),
        "tasks": TASKS[name],
        "known_hosts": (known,),
        "target": target(name),
        "token_rotation": rotation() if name == HEIS else None,
        **changes,
    }
    return DeployRunnerRegistration(**values)


def check_key(cfg: RunnerTarget) -> str:
    return target_code(cfg, "check").splitlines()[1]


def run(cfg: DeployRunnerRegistration, responses: dict[Any, Any]) -> Any:
    def deploy() -> None:
        install_deploy_registration(cfg, secret_key=deploy_tests.SECRET, keyscan=deploy_tests.scan, token_user=USER)

    return run_deploy_fake(deploy, responses=responses)


def converged(cfg: DeployRunnerRegistration) -> dict[Any, Any]:
    """A host the port left: the runner in the libexec layout, the temp dir, the target and the timer."""

    responses = deploy_tests.converged(cfg)
    assert cfg.temp_dir is not None
    assert cfg.target is not None
    responses.update(fakehost.stat(cfg.temp_dir.path, user="deploy", mode="drwxr-xr-x"))
    responses[check_key(cfg.target)] = ["unchanged"]
    if cfg.token_rotation is not None:
        texts = cfg.token_rotation.rendered(USER)
        responses.update(deploy_tests._file(HELPER, texts["helper"], group="root", mode="-rwx------"))
        responses.update(
            {
                "find /usr/local/sbin": [],
                **fakehost.directory("/etc/systemd/system"),
                **fakehost.file(f"/etc/systemd/system/{UNIT}.service", texts["service"]),
                **fakehost.file(f"/etc/systemd/system/{UNIT}.timer", texts["timer"]),
                f"--property SubState {UNIT}.timer": [f"Id={UNIT}.timer", "SubState=waiting"],
                f"--property UnitFileState {UNIT}.timer": [f"Id={UNIT}.timer", "UnitFileState=enabled"],
            }
        )
    return responses


# -- parity --------------------------------------------------------------------------


@pytest.mark.parametrize("name", [HEIS, VILLA])
def test_the_runner_renders_as_ansible_rendered_it(name: str) -> None:
    cfg = registration(name)

    assert hashlib.sha256(runner_script(cfg.runner, dict(cfg.variables)).encode()).hexdigest() == EXPECTED[name]


def test_the_kept_rotation_texts() -> None:
    assert rotation_names() == ("heis_production_backup",)
    texts = rotation_texts("heis_production_backup")
    assert f"ExecStart={HELPER}\n" in texts["service"]
    assert "OnCalendar=monthly\n" in texts["timer"]
    with pytest.raises(ValueError, match="not a kept token rotation"):
        rotation_texts("../targets")


def test_the_helper_renders_as_ansibles_copy_with_quote_and_to_json() -> None:
    helper = rotation().rendered("o'brien")["helper"]

    assert "  cd /home/fastdeploy/site &&\n  sudo -u fastdeploy \\\n" in helper
    assert "    /home/fastdeploy/site/.venv/bin/python \\\n" in helper
    assert "    --user 'o'\"'\"'brien' \\\n    --days 90 \\\n" in helper
    assert '    name="heis-production"\n' in helper
    assert "{{" not in helper
    assert helper.endswith("unset HEIS_BACKUP_SERVICE_TOKEN token\n")


# -- plans ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [HEIS, VILLA])
def test_a_converged_host_gets_no_mutating_operation(name: str) -> None:
    cfg = registration(name)
    fake = run(cfg, converged(cfg))

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    assert USER not in fake.all_text()
    assert deploy_tests.SECRET not in fake.all_text()


def test_the_old_layout_moves_and_the_parts_follow_the_playbooks_order() -> None:
    cfg = registration(HEIS)
    responses = converged(cfg)
    old = f"{cfg.runner.service_dir}/backup.py"
    responses.update(fakehost.file(old, "old runner\n", user="root", mode="-rwxr-xr-x"))
    responses.update(fakehost.stat("/tmp/heis-production-backup", user="deploy", mode="drwxrwxr-x"))
    assert cfg.target is not None
    responses[check_key(cfg.target)] = ["pending"]
    for path in (HELPER, f"/etc/systemd/system/{UNIT}.service", f"/etc/systemd/system/{UNIT}.timer"):
        responses = {key: value for key, value in responses.items() if path not in str(key)}
    responses[f"--property SubState {UNIT}.timer"] = [f"Id={UNIT}.timer", "SubState=dead"]
    responses[f"--property UnitFileState {UNIT}.timer"] = [f"Id={UNIT}.timer", "UnitFileState=disabled"]
    fake = run(cfg, responses)

    assert fake.succeeded, fake.error
    names = deploy_tests.ops(fake)
    order = [
        f"Remove the old FastDeploy-writable copy {old}",
        "Ensure the temp dir /tmp/heis-production-backup",
        "Issue or reuse the FastDeploy token and upsert the Echoport backup target heis-production",
        f"Install the token rotation helper {HELPER}",
        f"Install systemd unit {UNIT}.service",
        f"Install systemd unit {UNIT}.timer",
        f"Reload systemd for {UNIT}.timer",
        f"Enable and start {UNIT}.timer",
    ]
    assert [name for name in names if name in order] == order
    assert f"chmod 755 {cfg.temp_dir.path if cfg.temp_dir else ''}" in fake.executed_commands
    # The token user reaches the host on stdin only (token include and helper).
    assert USER not in fake.all_text()
    assert [stdin for command, stdin in fake.stdin if "issueservicetoken" in command] == [f"{USER}\n"]


def test_the_rotation_alone_reloads_only_when_a_unit_changed() -> None:
    cfg = rotation()
    texts = cfg.rendered(USER)
    responses: dict[Any, Any] = {
        **deploy_tests._file(HELPER, texts["helper"], group="root", mode="-rwx------"),
        "find /usr/local/sbin": [],
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.file(f"/etc/systemd/system/{UNIT}.service", texts["service"]),
        **fakehost.file(f"/etc/systemd/system/{UNIT}.timer", texts["timer"]),
        f"--property SubState {UNIT}.timer": [f"Id={UNIT}.timer", "SubState=waiting"],
        f"--property UnitFileState {UNIT}.timer": [f"Id={UNIT}.timer", "UnitFileState=enabled"],
    }
    fake = run_deploy_fake(lambda: install_token_rotation(cfg, USER), responses=responses)

    assert fake.succeeded, fake.error
    assert fake.mutating_changed_ops == []
    assert not any("daemon-reload" in command for command in fake.executed_commands)


def test_a_missing_token_user_refuses() -> None:
    fake = run_deploy_fake(lambda: install_token_rotation(rotation(), " "), responses={})

    assert isinstance(fake.error, DeployError)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"variables": {k: v for k, v in ROTATION_VARIABLES.items() if "days" not in k}}, "the texts read"),
        ({"user_variable": "heis_production_backup_fastdeploy_user"}, "a variable name of its own"),
        ({"helper": "/usr/local/sbin/other"}, "does not run /usr/local/sbin/other"),
        ({"unit": "other-rotate"}, "does not start other-rotate.service"),
    ],
)
def test_a_rotation_other_than_the_playbooks_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        rotation(**changes)


def _variables(name: str, **update: Any) -> dict[str, Any]:
    return {**INPUTS[name]["inputs"], **update}


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"temp_dir": None}, "exactly one of the work dir and the temp dir"),
        (
            {"work_dir": WorkDir(path="/mnt/cryptdata/backups/tmp/heis-production-backup", owner="deploy")},
            "exactly one of the work dir and the temp dir",
        ),
        ({"variables": _variables(HEIS, echoport_backup_temp_dir="/tmp/other")}, "must be the temp dir"),
        ({"temp_dir": TempDir(path="/tmp/heis-production-backup", owner="nobody")}, "runner's user deploy"),
        ({"token_rotation": None}, "tasks must name each part exactly once"),
        (
            {"tasks": ("packages", "mc", "access", "runner", "temp_dir", "known_hosts", "token_rotation", "target")},
            "the token_rotation task comes after the target task",
        ),
    ],
)
def test_what_the_playbook_never_does_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        registration(HEIS, **changes)


def test_a_work_dir_template_gets_no_temp_dir() -> None:
    base = deploy_tests.registration("marina-staging-backup")
    variables = {**base.variables, "echoport_backup_temp_dir": "/tmp/marina-staging-backup"}
    with pytest.raises(ValueError, match="works on the external disk: give it the work dir"):
        DeployRunnerRegistration(
            **{
                **dict(base),
                "variables": variables,
                "work_dir": None,
                "temp_dir": TempDir(path="/tmp/marina-staging-backup", owner="deploy"),
                "tasks": ("packages", "mc", "access", "temp_dir", "runner", "known_hosts"),
            }
        )


@pytest.mark.parametrize(
    ("binding", "value"),
    [
        ("target", "other"),
        ("service", "other-backup"),
        ("fastdeploy_root", "/srv/fastdeploy"),
        ("fastdeploy_user", "fd"),
        ("days", 30),
    ],
)
def test_a_rotation_of_another_target_or_token_is_refused(binding: str, value: Any) -> None:
    variables = {**ROTATION_VARIABLES, BINDINGS[binding]: value}
    with pytest.raises(ValueError, match=f"the token rotation's {binding} must be"):
        registration(HEIS, token_rotation=rotation(variables=variables))


def test_a_rotation_whose_token_is_scoped_to_another_target_is_refused() -> None:
    base = target(HEIS)
    other = base.model_copy(update={"token": ServiceToken(targets=("other",), service=HEIS)})
    with pytest.raises(ValueError, match="not scoped to the target"):
        registration(HEIS, target=other)


def test_rotation_bindings_name_every_value() -> None:
    with pytest.raises(ValueError, match="bindings name a variable for each"):
        rotation(bindings={k: v for k, v in BINDINGS.items() if k != "days"})


def test_a_rotation_needs_the_target_with_a_token() -> None:
    cfg = registration(HEIS)
    assert cfg.target is not None
    with pytest.raises(ValueError, match="rotates the token of the target"):
        registration(HEIS, target=cfg.target.model_copy(update={"token": None}))
