"""``_echoport_runner.registration``: the deploy-user runners' register playbooks (A2 and A3), on the fake host."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner import RunnerConfig, runner_script, service_config, sudoers_rule
from ops_deploy.services._echoport_runner import access as access_module
from ops_deploy.services._echoport_runner.access import (
    KnownHost,
    MinioAccess,
    WorkDir,
    alias_digest,
    controller_keyscan,
    render_account_policy,
)
from ops_deploy.services._echoport_runner.registration import (
    CredentialsFile,
    DeployKey,
    DeployRunnerRegistration,
    MediaSource,
    install_deploy_registration,
    media_credentials,
    register_deploy_runner,
)
from ops_deploy.services.vibe_coding.render import known_hosts as apply_known_host
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/echoport_runner"
INPUTS = json.loads((PARITY / "inputs.json").read_text())["runners"]
EXPECTED = json.loads((PARITY / "expected.json").read_text())["runners"]
SECRET = "fixture-account-secret-0123456789abcdef"  # pragma: allowlist secret
PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-private-key\n-----END OPENSSH PRIVATE KEY-----\n"
PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixturePublicKeyFixturePublicKeyFixtureP deploy@macmini\n"
SOURCE_KEY = "fixture-source-access-key"  # pragma: allowlist secret
SOURCE_SECRET = "fixture-source-secret-key-value"  # pragma: allowlist secret
ANCESTORS = {"LC_ALL=C LANG=C stat -c '%u %g %a %F'": ["0 0 755 directory"] * 3}
MC_PRESENT = {"test -x /usr/local/bin/mc": ["present"]}
ACCOUNT_PROBE = "def statements(doc)"
STORED = "select data::text from service where name"
KNOWN = "/home/deploy/.ssh/known_hosts"
KINDS = "if [ -L"
KEYS = {
    "staging.example.invalid": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "production.example.invalid": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
}
OTHER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICcccccccccccccccccccccccccccccccccccccccccc"

STAGING = ("homepage-staging-backup", "python-podcast-staging-backup", "marina-staging-backup")
PRODUCTION_DB = ("homepage-production-db-backup", "python-podcast-production-db-backup")
MEDIA = ("homepage-media-backup", "python-podcast-media-backup")
RUNNERS = (*STAGING, *PRODUCTION_DB, *MEDIA)
# Each playbook's order of its parts.
TASKS: dict[str, tuple[str, ...]] = {
    "homepage-staging-backup": ("mc", "packages", "access", "work_dir", "runner", "known_hosts"),
    "python-podcast-staging-backup": ("mc", "packages", "access", "work_dir", "runner", "known_hosts"),
    "marina-staging-backup": ("packages", "mc", "access", "work_dir", "runner", "known_hosts"),
    **dict.fromkeys(PRODUCTION_DB, ("ssh_key", "known_hosts", "mc", "packages", "access", "work_dir", "runner")),
    **dict.fromkeys(MEDIA, ("access", "packages", "work_dir", "credentials", "runner")),
}
PACKAGES = {
    "marina-staging-backup": ("sqlite3",),
    **dict.fromkeys(
        ("homepage-staging-backup", "python-podcast-staging-backup", *PRODUCTION_DB), ("postgresql-client",)
    ),
    **dict.fromkeys(MEDIA, ("rclone",)),
}


def _target(name: str) -> str:
    return name.removesuffix("-backup")


def _host_names(name: str, variables: dict[str, Any]) -> tuple[str, ...]:
    if name in PRODUCTION_DB:
        prefix = name.removesuffix("-production-db-backup").replace("python-podcast", "pp").replace("-", "_")
        return (variables[f"{prefix}_prod_db_backup_source_host"], variables[f"{prefix}_prod_db_backup_restore_host"])
    if name in STAGING:
        return ("staging.example.invalid",)
    return ()


def registration(name: str = "homepage-staging-backup", **changes: Any) -> DeployRunnerRegistration:
    """A runner of inputs.json, registered as its playbook does."""

    runner = INPUTS[name]
    variables = dict(runner["inputs"])
    media = name in MEDIA
    prefix = name.replace("-", "_") + "_"
    bucket_variable = prefix + "source_bucket" if media else None
    if bucket_variable:
        del variables[bucket_variable]
    work = next(v for k, v in variables.items() if k.endswith("_work_dir"))
    values: dict[str, Any] = {
        "runner": RunnerConfig(
            service=name,
            description=f"{name} runner",
            steps=("init", "upload", "result"),
            template=runner["template"],
        ),
        "access": MinioAccess(
            target=_target(name),
            os_user="none" if media else "deploy",
            alias=f"backup-{_target(name)}",
            url="http://127.0.0.1:9001",
            scoped=True,
            retired_aliases=() if media else ("minio",),
        ),
        "packages": PACKAGES[name],
        "variables": variables,
        "work_dir": WorkDir(path=work, owner="deploy"),
        "tasks": TASKS[name],
        "known_hosts": tuple(KnownHost(name=host) for host in _host_names(name, variables)),
        "ssh_key": name in PRODUCTION_DB,
        "credentials": CredentialsFile(path=variables[prefix + "credentials_file"]) if media else None,
        "source_bucket_variable": bucket_variable,
        **changes,
    }
    return DeployRunnerRegistration(**values)


def source(name: str) -> MediaSource | None:
    if name not in MEDIA:
        return None
    bucket = INPUTS[name]["inputs"][name.replace("-", "_") + "_source_bucket"]
    return MediaSource(bucket=bucket, access_key=SOURCE_KEY, secret_key=SOURCE_SECRET)


def scan(name: str) -> str:
    return f"# {name}:22 SSH-2.0-OpenSSH_9.8\n{name} {KEYS[name]}\n"


def deploy(cfg: DeployRunnerRegistration, **kwargs: Any) -> Any:
    name = cfg.runner.service
    values: dict[str, Any] = {
        "secret_key": SECRET,
        "ssh_key": DeployKey(private=PRIVATE, public=PUBLIC) if cfg.ssh_key else None,
        "source": source(name),
        "keyscan": scan,
        **kwargs,
    }

    def run() -> None:
        install_deploy_registration(cfg, **values)

    return run


def _file(path: str, content: str, *, user: str = "root", group: str, mode: str) -> dict[str, Any]:
    return {
        f"sha1sum {path} ": [f"{hashlib.sha1(content.encode()).hexdigest()}  {path}"],
        f"sha256sum {path} ": [f"{hashlib.sha256(content.encode()).hexdigest()}  {path}"],
        **fakehost.stat(path, user=user, group=group, mode=mode),
    }


def _variables(cfg: DeployRunnerRegistration) -> dict[str, Any]:
    variables = dict(cfg.variables)
    found = source(cfg.runner.service)
    if found is not None:
        assert cfg.source_bucket_variable is not None
        variables[cfg.source_bucket_variable] = found.bucket
    return variables


def converged(cfg: DeployRunnerRegistration) -> dict[Any, Any]:
    """A host the playbook left: key, known hosts, account, alias, work dir, credentials and runner."""

    access, runner = cfg.access, cfg.runner
    responses: dict[Any, Any] = {**ANCESTORS, **MC_PRESENT, **fakehost.deb_installed(*cfg.packages)}
    if cfg.known_hosts:
        lines = [f"{known.name} {KEYS[known.name]}\n" for known in cfg.known_hosts]
        for number, known in enumerate(cfg.known_hosts, start=1):
            responses[f"ssh-keygen -F {known.name} "] = [
                f"# Host {known.name} found: line {number} ",
                lines[number - 1],
            ]
        responses["base64 -w0"] = ["present", base64.b64encode("".join(lines).encode()).decode()]
        responses.update(fakehost.stat(KNOWN, user="deploy", mode="-rw-r--r--"))
    if cfg.ssh_key:
        responses.update(fakehost.stat("/home/deploy/.ssh", user="deploy", mode="drwx------"))
        responses.update(
            _file("/home/deploy/.ssh/id_ed25519", PRIVATE, user="deploy", group="deploy", mode="-rw-------")
        )
        responses.update(
            _file("/home/deploy/.ssh/id_ed25519.pub", PUBLIC, user="deploy", group="deploy", mode="-rw-r--r--")
        )
    responses.update(
        {
            ACCOUNT_PROBE: ["policy=ok user=attached"],
            **fakehost.directory("/etc/minio/policies", mode="drwxr-x---"),
            **fakehost.file(
                f"/etc/minio/policies/backup-{access.target}.json",
                render_account_policy(access.account),
                mode="-rw-r-----",
            ),
        }
    )
    if access.os_user != "none":
        responses[re.compile(rf"mc ls {access.alias}/backups/{access.target}/ >/dev/null && echo ok")] = ["ok"]
        responses[re.compile(rf"alias list {access.alias} \)")] = [
            alias_digest(access.url, access.account.user, SECRET)
        ]
        responses[re.compile(r"alias list minio \)")] = ["none"]
    responses.update(
        {
            "mountpoint -q": ["mounted"],
            KINDS: ["dir"] * (len(cfg.work_dir.parents) + 1),
            "getfacl": ["ok"],
            **fakehost.stat(cfg.work_dir.path, user="deploy", mode="drwx------"),
        }
    )
    if cfg.credentials is not None:
        found = source(runner.service)
        assert found is not None
        text = media_credentials(found, access_key=access.account.user, secret_key=SECRET)
        responses.update(fakehost.stat(cfg.credentials.directory, user="root", group="deploy", mode="drwxr-x---"))
        responses.update(_file(cfg.credentials.path, text, group="deploy", mode="-rw-r-----"))
    script = runner_script(runner, _variables(cfg))
    for path in ("/usr/local/libexec", runner.libexec_root, runner.runner_dir, runner.services, runner.service_dir):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.directory("/etc/sudoers.d"))
    responses.update(_file(runner.script, script, group=runner.group, mode="-rwxr-x---"))
    config = service_config(runner)
    responses.update(_file(f"{runner.service_dir}/config.json", config, group="root", mode="-rw-r--r--"))
    responses.update(_file(runner.sudoers, sudoers_rule(runner), group="root", mode="-r--r-----"))
    responses[STORED] = [json.dumps(json.loads(config))]
    return responses


def refused(run: Any) -> str:
    assert isinstance(run.error, DeployError), run.error
    assert run.executed_commands == []
    return str(run.error)


def ops(run: Any) -> list[str]:
    return [name.removeprefix("Echoport backup runner registration | ") for name in run.changed_ops]


# -- parity -------------------------------------------------------------------------


@pytest.mark.parametrize("name", RUNNERS)
def test_the_runner_renders_as_ansible_rendered_it(name: str) -> None:
    cfg = registration(name)

    assert hashlib.sha256(runner_script(cfg.runner, _variables(cfg)).encode()).hexdigest() == EXPECTED[name]


def test_the_deploy_user_rule_is_fastdeploy_to_deploy_only() -> None:
    rule = sudoers_rule(registration().runner)

    assert rule.splitlines()[-1] == (
        "fastdeploy ALL=(deploy) NOPASSWD:NOSETENV: /usr/local/libexec/fastdeploy/homepage-staging-backup/backup.py *"
    )
    assert "ALL=(root)" not in rule


def test_the_credentials_file_is_the_playbooks_copy_content() -> None:
    # The playbooks' `copy: content: |` with `to_json`, as ansible-core 2.21 writes it
    # (ensure_ascii escapes, the block's final newline).
    found = MediaSource(bucket="media-bucket", access_key='a"b', secret_key="sé/\\")

    assert media_credentials(found, access_key="bk-user", secret_key="dest") == (
        "{\n"
        '  "source_access_key": "a\\"b",\n'
        '  "source_secret_key": "s\\u00e9/\\\\",\n'
        '  "dest_access_key": "bk-user",\n'
        '  "dest_secret_key": "dest"\n'
        "}\n"
    )


# -- plans --------------------------------------------------------------------------


@pytest.mark.parametrize("name", [*STAGING, *PRODUCTION_DB])
def test_a_converged_host_gets_no_mutating_operation(name: str) -> None:
    cfg = registration(name)
    run = run_deploy_fake(deploy(cfg), responses=converged(cfg))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    for value in (SECRET, PRIVATE.splitlines()[1]):
        assert value not in run.all_text()


@pytest.mark.parametrize("name", MEDIA)
def test_a_converged_media_host_upserts_only_the_minio_user(name: str) -> None:
    # No alias proves the stored secret current, so the user is upserted on every
    # run, as minio_deploy's backup_account does in the playbook.
    cfg = registration(name)
    run = run_deploy_fake(deploy(cfg), responses=converged(cfg))

    assert run.succeeded, run.error
    assert [name.removeprefix("Echoport backup runner registration | ") for name in run.mutating_changed_ops] == [
        f"Create or update MinIO user of {_target(name)}"
    ]
    for value in (SECRET, SOURCE_KEY, SOURCE_SECRET):
        assert value not in run.all_text()
    assert not any(re.search(r"alias (list|import|remove)", c) for c in run.executed_commands)


def test_a_staging_runner_is_installed_in_its_playbooks_order() -> None:
    cfg = registration("homepage-staging-backup")
    responses = {
        **ANCESTORS,
        **MC_PRESENT,
        ACCOUNT_PROBE: ["policy=missing user=missing"],
        "mountpoint -q": ["mounted"],
    }
    responses[KINDS] = ["dir", "dir", "missing"]
    responses["base64 -w0"] = ["absent"]
    run = run_deploy_fake(register_deploy_runner, cfg, secret_key=SECRET, keyscan=scan, responses=responses)

    assert run.succeeded, run.error
    order = [
        "Install the packages of homepage-staging-backup",
        "Create or update MinIO user of homepage-staging",
        "Configure mc alias backup-homepage-staging of deploy",
        "Ensure the work dir /mnt/cryptdata/backups/tmp/homepage-staging-backup",
        "Install the homepage-staging-backup runner script",
        "Sync FastDeploy services for homepage-staging-backup",
        f"Add the ed25519 host key of staging.example.invalid to {KNOWN}",
        f"Ensure the ownership of {KNOWN}",
    ]
    assert [name for name in ops(run) if name in order] == order
    assert run.upload(KNOWN) == f"staging.example.invalid {KEYS['staging.example.invalid']}\n".encode()
    assert f"chown deploy:deploy {KNOWN}" in run.executed_commands
    assert "sudo" not in " ".join(c for c in run.executed_commands if "mc" in c)
    assert SECRET not in run.all_text()


def test_a_production_db_runner_installs_the_deploy_key_first() -> None:
    cfg = registration("homepage-production-db-backup")
    responses = {**ANCESTORS, **MC_PRESENT, ACCOUNT_PROBE: ["policy=ok user=attached"], "mountpoint -q": ["mounted"]}
    responses[KINDS] = ["dir", "dir", "dir"]
    responses["base64 -w0"] = ["absent"]
    run = run_deploy_fake(deploy(cfg), responses=responses)

    assert run.succeeded, run.error
    names = ops(run)
    assert names[:5] == [
        "Ensure the SSH directory of deploy",
        "Install the SSH key id_ed25519 of deploy",
        "Install the SSH key id_ed25519.pub of deploy",
        f"Add the ed25519 host keys of production.example.invalid, staging.example.invalid to {KNOWN}",
        f"Ensure the ownership of {KNOWN}",
    ]
    assert names.index("Install the packages of homepage-production-db-backup") > 4
    # Both names in one upload, in the playbook's order.
    assert run.upload(KNOWN).decode() == "".join(
        f"{name} {KEYS[name]}\n" for name in _host_names(cfg.runner.service, dict(cfg.variables))
    )
    text = run.all_text()
    for value in (SECRET, PRIVATE.splitlines()[1], "FixturePublicKey"):
        assert value not in text
    installs = [c for c in run.executed_commands if c.startswith("python3 -I -c") and "/home/deploy/.ssh" in c]
    assert len(installs) == 2
    assert all("0600" in c or "0644" in c for c in installs)


def test_a_media_runner_writes_its_credentials_file_and_no_alias() -> None:
    cfg = registration("homepage-media-backup")
    responses = {
        **ANCESTORS,
        **MC_PRESENT,
        ACCOUNT_PROBE: ["policy=missing user=missing"],
        "mountpoint -q": ["mounted"],
    }
    responses[KINDS] = ["dir", "dir", "dir"]
    run = run_deploy_fake(deploy(cfg), responses=responses)

    assert run.succeeded, run.error
    names = ops(run)
    assert names.index("Create or update MinIO user of homepage-media") < names.index(
        "Install the packages of homepage-media-backup"
    )
    assert (
        names.index("Ensure the credentials directory /etc/echoport-media")
        < names.index("Install the credentials file /etc/echoport-media/homepage-media-backup.json")
        < names.index("Install the homepage-media-backup runner script")
    )
    assert not any(re.search(r"alias (list|import|remove)", c) for c in run.executed_commands)
    assert "chown root:deploy /etc/echoport-media" in run.executed_commands
    assert "chmod 750 /etc/echoport-media" in run.executed_commands
    (install,) = [
        c for c in run.executed_commands if c.startswith("python3 -I -c") and "homepage-media-backup.json" in c
    ]
    assert " 0640 root deploy" in install
    script = run.upload(cfg.runner.script).decode()
    assert 'SOURCE_BUCKET = "homepage-media-fixture"' in script
    for value in (SECRET, SOURCE_KEY, SOURCE_SECRET):
        assert value not in run.all_text()


# -- known hosts --------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
@pytest.mark.parametrize(
    "lines",
    [
        # production's key changed (replaced in place), staging's missing
        ["other.example.invalid {other}", "production.example.invalid {other}", "x.example.invalid {other}"],
        # both changed; staging's entry lies behind production's
        ["production.example.invalid {other}", "a.example.invalid {other}", "staging.example.invalid {other}"],
        # a line naming both hosts
        ["production.example.invalid,staging.example.invalid {other}", "b.example.invalid {other}"],
        # both current
        ["production.example.invalid {production}", "staging.example.invalid {staging}"],
        # staging's key changed, production's current
        ["staging.example.invalid {other}", "production.example.invalid {production}"],
    ],
)
def test_two_known_hosts_end_as_two_ansible_tasks_leave_the_file(tmp_path: Path, lines: list[str]) -> None:
    # Ansible's known_hosts runs `ssh-keygen -F` against the file the previous
    # task left; the port asks the host once and moves its answers past a
    # replaced line. Here the reference applies the tasks one after the other
    # with the real ssh-keygen.
    values = {
        "other": OTHER,
        "production": KEYS["production.example.invalid"],
        "staging": KEYS["staging.example.invalid"],
    }
    current = "".join(line.format(**values) + "\n" for line in lines)
    names = ("production.example.invalid", "staging.example.invalid")
    path = tmp_path / "known_hosts"

    def lookup(name: str) -> str:
        found = subprocess.run(["ssh-keygen", "-F", name, "-f", str(path)], capture_output=True, text=True, check=False)
        return found.stdout

    path.write_text(current)
    first = {name: lookup(name) for name in names}
    expected: str | None = current
    for name in names:
        path.write_text(expected or "")
        expected = apply_known_host(expected, lookup(name), f"{name} {KEYS[name]}") or expected

    cfgs = [KnownHost(name=name) for name in names]
    responses: dict[Any, Any] = {"base64 -w0": ["present", base64.b64encode(current.encode()).decode()]}
    for name in names:
        responses[f"ssh-keygen -F {name} "] = first[name].splitlines()
    responses.update(fakehost.stat(KNOWN, user="deploy", mode="-rw-r--r--"))

    def plan() -> None:
        access_module.known_hosts_entries(cfgs, scan)

    run = run_deploy_fake(plan, responses=responses)

    assert run.succeeded, run.error
    if expected == current:
        assert run.changed_ops == []
    else:
        assert run.upload(KNOWN).decode() == expected


def test_a_keyscan_that_times_out_refuses_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", hang)
    with pytest.raises(DeployError, match="gave no answer within 60 s; nothing was written"):
        controller_keyscan("staging.example.invalid")

    cfg = registration()
    run = run_deploy_fake(deploy(cfg, keyscan=None), responses=converged(cfg))
    assert "gave no answer" in refused(run)


def test_a_missing_keyscan_refuses_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(DeployError, match="could not run on the controller"):
        controller_keyscan("staging.example.invalid")


@pytest.mark.parametrize(
    "answer", ["", f"staging.example.invalid {KEYS['staging.example.invalid']}\nstaging.example.invalid {OTHER}\n"]
)
def test_anything_but_one_scanned_key_refuses_before_any_write(answer: str) -> None:
    cfg = registration("homepage-production-db-backup")

    def keyscan(name: str) -> str:
        return scan(name) if name.startswith("production") else answer

    # The production key resolves; staging's refuses, before the SSH key or the production line is written.
    message = refused(run_deploy_fake(deploy(cfg, keyscan=keyscan), responses=converged(cfg)))
    assert "staging.example.invalid from ssh-keyscan" in message


# -- refusals -----------------------------------------------------------------------


def test_a_missing_mc_refuses_before_any_write() -> None:
    cfg = registration("marina-staging-backup")
    responses = {**converged(cfg), "test -x /usr/local/bin/mc": ["missing"]}

    assert "mc (MinIO client) not found" in refused(run_deploy_fake(deploy(cfg), responses=responses))


def test_an_unmounted_work_disk_refuses_before_any_write() -> None:
    cfg = registration("homepage-production-db-backup")
    responses = {**converged(cfg), "mountpoint -q": ["missing"]}

    assert "/mnt/cryptdata is not mounted" in refused(run_deploy_fake(deploy(cfg), responses=responses))


def test_missing_or_extra_secrets_refuse() -> None:
    cfg = registration("homepage-production-db-backup")
    with pytest.raises(DeployError, match="deploy SSH key"):
        install_deploy_registration(cfg, secret_key=SECRET)
    staging = registration()
    with pytest.raises(DeployError, match="deploy SSH key"):
        install_deploy_registration(staging, secret_key=SECRET, ssh_key=DeployKey(private=PRIVATE, public=PUBLIC))
    with pytest.raises(DeployError, match="media source"):
        install_deploy_registration(registration("homepage-media-backup"), secret_key=SECRET)
    with pytest.raises(DeployError, match="media source"):
        install_deploy_registration(staging, secret_key=SECRET, source=source("homepage-media-backup"))


@pytest.mark.parametrize("bucket", ["", "UPPER", 'x"; import os', "a" * 70])
def test_a_source_bucket_that_is_no_bucket_name_is_refused_without_showing_it(bucket: str) -> None:
    with pytest.raises(ValueError, match="value withheld") as raised:
        MediaSource(bucket=bucket, access_key=SOURCE_KEY, secret_key=SOURCE_SECRET)
    assert SOURCE_SECRET not in str(raised.value)


def _changed_variables(name: str, **update: Any) -> dict[str, Any]:
    return {"variables": {**registration(name).variables, **update}}


@pytest.mark.parametrize(
    ("name", "changes", "message"),
    [
        ("homepage-staging-backup", {"runner": "run_as"}, "no run_as rule"),
        ("homepage-staging-backup", {"access": {"os_user": "root"}}, "deploy's mc alias"),
        ("homepage-staging-backup", {"access": {"scoped": False}}, "scoped account"),
        (
            "homepage-staging-backup",
            {"work_dir": WorkDir(path="/mnt/cryptdata/backups/tmp/x", owner="backup")},
            "work dir belongs",
        ),
        (
            "homepage-staging-backup",
            _changed_variables("homepage-staging-backup", homepage_staging_backup_work_dir="/mnt/cryptdata/other"),
            "homepage_staging_backup_work_dir must be what the registration provisions (work_dir)",
        ),
        (
            "homepage-staging-backup",
            _changed_variables("homepage-staging-backup", echoport_backup_minio_alias="backup-other"),
            "echoport_backup_minio_alias must be the access's alias",
        ),
        ("homepage-staging-backup", {"tasks": ("mc", "packages", "access", "work_dir", "runner")}, "exactly once"),
        ("homepage-staging-backup", {"tasks": TASKS["homepage-staging-backup"] + ("mc",)}, "exactly once"),
        ("homepage-staging-backup", {"tasks": TASKS["homepage-staging-backup"] + ("ssh_key",)}, "exactly once"),
        (
            "homepage-staging-backup",
            {"known_hosts": (KnownHost(name="staging.example.invalid", path="/root/.ssh/known_hosts"),)},
            "known hosts go to",
        ),
        (
            "homepage-staging-backup",
            {"source_bucket_variable": "homepage_staging_backup_source_bucket"},
            "only a media runner",
        ),
        ("homepage-media-backup", {"access": {"os_user": "deploy"}}, "os_user none"),
        ("homepage-media-backup", {"source_bucket_variable": None}, "_source_bucket variable"),
        (
            "homepage-media-backup",
            _changed_variables("homepage-media-backup", homepage_media_backup_minio_url="http://127.0.0.1:9020"),
            "homepage_media_backup_minio_url must be what the registration provisions (minio_url)",
        ),
        (
            "homepage-media-backup",
            {"credentials": CredentialsFile(path="/etc/echoport-media/other.json")},
            "homepage_media_backup_credentials_file must be",
        ),
        ("homepage-media-backup", {"tasks": ("access", "packages", "work_dir", "runner")}, "exactly once"),
    ],
)
def test_what_the_playbook_never_does_is_refused(name: str, changes: dict[str, Any], message: str) -> None:
    base = registration(name)
    if changes.get("runner") == "run_as":
        changes = {"runner": base.runner.model_copy(update={"run_as": "root"})}
    elif isinstance(changes.get("access"), dict):
        changes = {"access": base.access.model_copy(update=changes["access"])}
    with pytest.raises(ValueError, match=re.escape(message)):
        registration(name, **changes)


def test_a_media_template_without_no_check_dest_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # The media playbooks' "Require a media runner that works with a scoped MinIO account".
    from ops_deploy.services._echoport_runner import registration as module

    monkeypatch.setattr(module, "_template_source", lambda _template: "{% include '_work_dir.py.j2' %}\n")
    with pytest.raises(ValueError, match="without --no-check-dest"):
        registration("homepage-media-backup")


def test_a_credentials_file_needs_a_directory_of_its_own() -> None:
    for path in ("/x.json", "/etc/x.json", "//x.json", "//etc/x.json", "/etc/echoport-media/../x.json"):
        with pytest.raises(ValueError, match="directory of its own"):
            CredentialsFile(path=path)


def test_two_known_hosts_refuse_a_file_without_a_final_newline() -> None:
    # known_hosts would append to its last line; the answers read once no longer describe the file.
    current = f"staging.example.invalid {OTHER}"
    cfgs = [KnownHost(name="production.example.invalid"), KnownHost(name="staging.example.invalid")]
    responses: dict[Any, Any] = {
        "base64 -w0": ["present", base64.b64encode(current.encode()).decode()],
        "ssh-keygen -F staging.example.invalid ": [
            "# Host staging.example.invalid found: line 1 ",
            f"staging.example.invalid {OTHER}",
        ],
    }

    def plan() -> None:
        access_module.known_hosts_entries(cfgs, scan)

    assert "does not end with a newline" in refused(run_deploy_fake(plan, responses=responses))
