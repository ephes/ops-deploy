"""``_echoport_runner.generic``: the generic runner ``echoport-backup`` and its per-target accesses, on the fake host.

The runner renders to what ``ansible-playbook`` rendered for macmini's
sixteen targets (``echoport-backup-macmini`` in the parity record), which is
byte for byte the script read on macmini on 2026-11-10 (sha256 below);
``config.json`` and the sudoers rule are what the role wrote there.
"""

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
from ops_deploy.services._echoport_runner.generic import (
    GenericRunnerRegistration,
    install_generic_registration,
    register_generic_runner,
)
from ops_deploy.services.minio.config import MC_SHA256
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/echoport_runner"
INPUTS = json.loads((PARITY / "inputs.json").read_text())["runners"]
EXPECTED = json.loads((PARITY / "expected.json").read_text())["runners"]
CASE = "echoport-backup-macmini"
# /usr/local/libexec/fastdeploy/echoport-backup/backup.py on macmini, 2026-11-10.
LIVE_RUNNER_SHA256 = "d92c2fc302a8a293137ab279c17d8293deed704469d8e99f213a986860ac745a"
LIVE_CONFIG = (
    '{\n    "deploy_script": "/usr/local/libexec/fastdeploy/echoport-backup/backup.py",\n'
    '    "description": "Echoport backup service - backs up SQLite databases and files to MinIO",\n'
    '    "name": "echoport-backup",\n    "steps": [\n'
    + ",\n".join(
        f'        {{\n            "name": "{step}"\n        }}'
        for step in ("init", "backup", "download", "upload", "verify", "extract", "stop", "restore", "start", "result")
    )
    + "\n    ]\n}\n"
)
LIVE_SUDOERS = (
    "# FastDeploy runner echoport-backup (ops-library fastdeploy_runner).\n"
    "# The script and every directory above it are root-owned; NOSETENV because\n"
    "# FastDeploy passes the context in the --config file, not the environment.\n"
    "fastdeploy ALL=(deploy) NOPASSWD:NOSETENV: /usr/local/libexec/fastdeploy/echoport-backup/backup.py *\n"
    "deploy ALL=(root) NOPASSWD:NOSETENV: /usr/local/libexec/fastdeploy/echoport-backup/backup.py *\n"
)
STEPS = ("init", "backup", "download", "upload", "verify", "extract", "stop", "restore", "start", "result")
ANCESTORS = {"LC_ALL=C LANG=C stat -c '%u %g %a %F'": ["0 0 755 directory"] * 3}
MC_PRESENT = {"test -x /usr/local/bin/mc": ["present"]}
ACCOUNT_PROBE = "def statements(doc)"
STORED = "select data::text from service where name"


def secret(target: str) -> str:
    return f"fixture-secret-{target}-0123456789abcdef"[:40]  # pragma: allowlist secret


def runner() -> RunnerConfig:
    return RunnerConfig(
        service="echoport-backup",
        description="Echoport backup service - backs up SQLite databases and files to MinIO",
        steps=STEPS,
        template="backup.py.j2",
        run_as="root",
        sudoers_file="/etc/sudoers.d/echoport_backup",
    )


def access(target: str, alias: str, *, retired: tuple[str, ...] = ("minio",)) -> MinioAccess:
    url = "http://127.0.0.1:9020" if alias.startswith("rustfs-") else "http://127.0.0.1:9001"
    return MinioAccess(
        target=target,
        os_user="root",
        alias=alias,
        url=url,
        scoped=True,
        retired_aliases=retired,
        **({"store": "rustfs", "rustfs_account": True} if alias.startswith("rustfs-") else {}),
    )


def registration(aliases: dict[str, str] | None = None, **changes: Any) -> GenericRunnerRegistration:
    variables = dict(INPUTS[CASE]["inputs"])
    if aliases is not None:
        variables["echoport_backup_minio_prefix_aliases"] = aliases
    accesses = tuple(
        access(target, alias) for target, alias in variables["echoport_backup_minio_prefix_aliases"].items()
    )
    values: dict[str, Any] = {"runner": runner(), "accesses": accesses, "variables": variables, **changes}
    return GenericRunnerRegistration(**values)


def secrets(cfg: GenericRunnerRegistration) -> dict[str, str]:
    return {a.target: secret(a.target) for a in cfg.accesses}


def _file(path: str, content: str, *, group: str, mode: str) -> dict[str, Any]:
    return {
        f"sha1sum {path} ": [f"{hashlib.sha1(content.encode()).hexdigest()}  {path}"],
        f"sha256sum {path} ": [f"{hashlib.sha256(content.encode()).hexdigest()}  {path}"],
        **fakehost.stat(path, user="root", group=group, mode=mode),
    }


def converged(cfg: GenericRunnerRegistration) -> dict[Any, Any]:
    """macmini as the playbook left it: sqlite3, pinned mc, runner, accounts and aliases."""

    run = cfg.runner
    responses: dict[Any, Any] = {
        **ANCESTORS,
        **MC_PRESENT,
        **fakehost.deb_installed(*cfg.packages),
        "sha256sum /usr/local/bin/mc ": [f"{MC_SHA256}  /usr/local/bin/mc"],
        **fakehost.stat("/usr/local/bin/mc", user="root", mode="-rwxr-xr-x"),
        ACCOUNT_PROBE: ["policy=ok user=attached"],
        re.compile(r"alias list minio \)"): ["none"],
        **fakehost.directory("/etc/minio/policies", mode="drwxr-x---"),
    }
    for a in cfg.accesses:
        responses[re.compile(rf"mc ls {a.alias}/backups/{a.target}/ >/dev/null && echo ok")] = ["ok"]
        responses[re.compile(rf"alias list {a.alias} \)")] = [alias_digest(a.url, a.account.user, secret(a.target))]
        responses.update(
            fakehost.file(
                f"/etc/minio/policies/backup-{a.target}.json", render_account_policy(a.account), mode="-rw-r-----"
            )
        )
    for path in ("/usr/local/libexec", run.libexec_root, run.runner_dir, run.services, run.service_dir):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.directory("/etc/sudoers.d"))
    responses.update(_file(run.script, runner_script(run, cfg.variables), group="deploy", mode="-rwxr-x---"))
    config = service_config(run)
    responses.update(_file(f"{run.service_dir}/config.json", config, group="root", mode="-rw-r--r--"))
    responses.update(_file(run.sudoers, sudoers_rule(run), group="root", mode="-r--r-----"))
    responses[STORED] = [json.dumps(json.loads(config))]
    return responses


def deploy(cfg: GenericRunnerRegistration, given: dict[str, str] | None = None) -> Any:
    def run() -> None:
        install_generic_registration(cfg, secrets=secrets(cfg) if given is None else given)

    return run


def refused(run: Any) -> str:
    assert isinstance(run.error, DeployError), run.error
    assert run.executed_commands == []
    return str(run.error)


def test_the_runner_config_and_sudoers_are_what_macmini_has() -> None:
    cfg = registration()
    script = runner_script(cfg.runner, cfg.variables)

    assert hashlib.sha256(script.encode()).hexdigest() == LIVE_RUNNER_SHA256 == EXPECTED[CASE]
    assert service_config(cfg.runner) == LIVE_CONFIG
    assert sudoers_rule(cfg.runner) == LIVE_SUDOERS
    assert cfg.runner.script == "/usr/local/libexec/fastdeploy/echoport-backup/backup.py"
    assert cfg.runner.service_dir == "/home/fastdeploy/site/services/echoport-backup"


def test_the_macmini_case_lists_the_sixteen_targets_in_the_playbooks_order() -> None:
    aliases = INPUTS[CASE]["inputs"]["echoport_backup_minio_prefix_aliases"]

    assert len(aliases) == 16
    assert list(aliases)[-1] == "echoport"
    assert all(alias == f"backup-{target}" for target, alias in aliases.items())


def test_a_converged_host_gets_no_mutating_operation() -> None:
    cfg = registration()
    run = run_deploy_fake(deploy(cfg), responses=converged(cfg))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert not any(s in run.all_text() for s in secrets(cfg).values())


def test_a_first_run_follows_the_playbooks_order() -> None:
    # Two targets, one of them moved to RustFS.
    cfg = registration({"archive": "backup-archive", "nyxmon": "rustfs-backup-nyxmon"})
    responses: dict[Any, Any] = {
        **ANCESTORS,
        **MC_PRESENT,
        ACCOUNT_PROBE: ["policy=missing user=missing"],
        re.compile(r"alias list minio \)"): ["present-digest"],
    }
    run = run_deploy_fake(register_generic_runner, cfg, secrets=secrets(cfg), responses=responses)

    assert run.succeeded, run.error
    names = [n.removeprefix("Echoport generic runner registration | ") for n in run.changed_ops]
    order = [
        "Install the packages of echoport-backup",
        "Download pinned MinIO client",
        "Install the echoport-backup runner script",
        "Write config.json of echoport-backup",
        "Sync FastDeploy services for echoport-backup",
        "Create or update MinIO user of archive",
        "Configure mc alias backup-archive of root",
        "Remove retired mc alias minio of root",
        "Configure mc alias rustfs-backup-nyxmon of root",
    ]
    assert [n for n in names if n in order] == order
    # RustFS creates its own accounts; the retired alias goes once.
    assert "Create or update MinIO user of nyxmon" not in names
    assert names.count("Remove retired mc alias minio of root") == 1
    assert not any(s in run.all_text() for s in secrets(cfg).values())


def test_a_missing_mc_refuses_before_any_write() -> None:
    cfg = registration()
    responses = {**converged(cfg), "test -x /usr/local/bin/mc": ["missing"]}

    assert "`just deploy-one minio` installs the pinned client" in refused(
        run_deploy_fake(deploy(cfg), responses=responses)
    )


def test_the_secrets_must_be_exactly_the_targets() -> None:
    cfg = registration()
    given = secrets(cfg)
    del given["archive"]

    assert "exactly the secrets of its targets" in refused(
        run_deploy_fake(deploy(cfg, given), responses=converged(cfg))
    )


def test_a_bad_secret_refuses_before_any_write() -> None:
    cfg = registration()
    given = {**secrets(cfg), "nyxmon": "CHANGEME"}

    assert "32 to 40 characters" in refused(run_deploy_fake(deploy(cfg, given), responses=converged(cfg)))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda v, a: (
                {
                    **v,
                    "echoport_backup_minio_prefix_aliases": dict(
                        reversed(v["echoport_backup_minio_prefix_aliases"].items())
                    ),
                },
                a,
            ),
            "in order",
        ),
        (lambda v, a: (v, a[:-1]), "in order"),
        (lambda v, a: ({**v, "echoport_backup_default_bucket": "other"}, a), "every access's bucket"),
        (lambda v, a: ({**v, "echoport_backup_minio_require_prefix_alias": "yes"}, a), "must be a bool"),
        (lambda v, a: (v, (*a[:-1], a[-1].model_copy(update={"scoped": False}))), "scoped account"),
        (lambda v, a: (v, (*a[:-1], a[-1].model_copy(update={"retired_aliases": ()}))), "same aliases"),
    ],
)
def test_the_playbooks_values_are_enforced(change: Any, message: str) -> None:
    cfg = registration()
    variables, accesses = change(dict(cfg.variables), cfg.accesses)

    with pytest.raises(ValueError, match=message):
        GenericRunnerRegistration(runner=cfg.runner, accesses=accesses, variables=variables)


def test_another_template_is_refused() -> None:
    cfg = registration()

    with pytest.raises(ValueError, match=r"renders backup\.py\.j2"):
        GenericRunnerRegistration(
            runner=cfg.runner.model_copy(update={"template": "delve_backup.py.j2"}),
            accesses=cfg.accesses,
            variables=cfg.variables,
        )
