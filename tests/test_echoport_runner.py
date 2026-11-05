"""``_echoport_runner``: the fastdeploy_runner port and the runner's host access parts, on the fake host."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.services._echoport_runner import (
    RunnerConfig,
    deploy_runner,
    install_runner,
    libexec_ancestors,
    service_config,
    sudoers_rule,
)
from ops_deploy.services._echoport_runner.access import (
    KnownHost,
    MinioAccess,
    WorkDir,
    alias_digest,
    host_keys,
    known_host,
    minio_access,
    render_account_policy,
    work_dir,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

SCRIPT = "#!/usr/bin/env python3\nprint('runner')\n"
ANCESTORS = {"stat -c '%u %g %a %F'": ["0 0 755 directory"] * 3}
STORED = "select data::text from service where name"


def runner(**changes: Any) -> RunnerConfig:
    values: dict[str, Any] = {
        "service": "paperless-backup",
        "description": "Paperless backup",
        "steps": ("init", "upload", "result"),
        "content": SCRIPT,
        "run_as": "root",
        **changes,
    }
    return RunnerConfig(**values)


def _file(path: str, content: str, *, group: str, mode: str) -> dict[str, Any]:
    return {
        f"sha1sum {path} ": [f"{hashlib.sha1(content.encode()).hexdigest()}  {path}"],
        f"sha256sum {path} ": [f"{hashlib.sha256(content.encode()).hexdigest()}  {path}"],
        **fakehost.stat(path, user="root", group=group, mode=mode),
    }


def refused(run: Any) -> str:
    """The deploy stopped while planning, before any command ran; the refusal's text."""

    assert isinstance(run.error, DeployError), run.error
    assert run.executed_commands == []
    return str(run.error)


def converged(cfg: RunnerConfig, **changes: Any) -> dict[str, Any]:
    """A host the role (or a first run) left: every path as the role writes it, FastDeploy in step."""

    responses: dict[str, Any] = {**ANCESTORS}
    for path in ("/usr/local/libexec", cfg.libexec_root, cfg.runner_dir, cfg.services, cfg.service_dir):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.directory("/etc/sudoers.d"))
    responses.update(_file(cfg.script, SCRIPT, group=cfg.group, mode="-rwxr-x---"))
    responses.update(_file(f"{cfg.service_dir}/config.json", service_config(cfg), group="root", mode="-rw-r--r--"))
    responses.update(_file(cfg.sudoers, sudoers_rule(cfg), group="root", mode="-r--r-----"))
    responses[STORED] = [json.dumps(json.loads(service_config(cfg)))]
    responses.update(changes)
    return responses


# -- settings: the role's assert ----------------------------------------------------


def test_defaults_follow_the_role() -> None:
    cfg = runner(description=None, run_as="")

    assert cfg.runner_description == "paperless-backup"
    assert cfg.script == "/usr/local/libexec/fastdeploy/paperless-backup/backup.py"
    assert cfg.group == "deploy"
    assert cfg.service_dir == "/home/fastdeploy/site/services/paperless-backup"
    assert cfg.sudoers == "/etc/sudoers.d/paperless_backup"
    assert cfg.legacy == ("/home/fastdeploy/site/services/paperless-backup/backup.py",)
    assert cfg.python == "/home/fastdeploy/site/.venv/bin/python"


@pytest.mark.parametrize(
    "changes",
    [
        {"service": "Paperless"},
        {"service": "-backup"},
        {"script_name": ".hidden"},
        {"steps": ()},
        {"template": "paperless_backup.py.j2"},
        {"content": None},
        {"content": ""},
        {"libexec_root": "relative/root"},
        {"libexec_root": "/usr/local/../libexec"},
        {"dir": "/usr/local/libexec/fastdeploy/a/b"},
        {"dir": "/elsewhere/paperless-backup"},
        {"libexec_root": "/home/fastdeploy/site/libexec"},
        {"fastdeploy_user": "Fast"},
        {"deploy_user": "1deploy"},
        {"script_group": "Deploy"},
        {"run_as": "Root"},
        {"sudoers_file": "/etc/sudoers.d/paperless.backup"},
        {"sudoers_file": "/etc/sudoers.d/sub/paperless"},
        {"script_mode": "0777"},
    ],
)
def test_settings_the_role_refuses_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="validation error"):
        runner(**changes)


def test_ancestors_are_the_roles() -> None:
    assert libexec_ancestors("/usr/local/libexec/fastdeploy") == ["/", "/usr", "/usr/local", "/usr/local/libexec"]
    assert libexec_ancestors("/opt") == ["/"]


# -- the role's steps ----------------------------------------------------------------


def test_first_run_writes_every_path_in_the_roles_order() -> None:
    cfg = runner()
    run = run_deploy_fake(deploy_runner, cfg, responses={**ANCESTORS})

    assert run.succeeded, run.error
    names = [name.removeprefix("Echoport backup runner | ") for name in run.changed_ops]
    assert names == [
        "Ensure directory /usr/local/libexec",
        "Ensure directory /usr/local/libexec/fastdeploy",
        "Ensure directory /usr/local/libexec/fastdeploy/paperless-backup",
        "Install the paperless-backup runner script",
        "Ensure directory /home/fastdeploy/site/services",
        "Ensure directory /home/fastdeploy/site/services/paperless-backup",
        "Write config.json of paperless-backup",
        "Install sudoers rule paperless_backup",
        "Sync FastDeploy services for paperless-backup",
    ]
    commands = run.executed_commands
    for path in ("/usr/local/libexec", cfg.libexec_root, cfg.runner_dir, cfg.services, cfg.service_dir):
        assert f"chmod 755 {path}" in commands
        assert f"chown root:root {path}" in commands
    assert f"chown root:deploy {cfg.script}" in commands
    assert f"chmod 750 {cfg.script}" in commands
    assert f"chmod 644 {cfg.service_dir}/config.json" in commands
    # No directory is handed to another owner by the uploads.
    assert not any(c.startswith("chown root:deploy") and not c.endswith("backup.py") for c in commands)
    assert run.upload(cfg.script) == SCRIPT.encode()
    assert run.upload(f"{cfg.service_dir}/config.json") == service_config(cfg).encode()
    assert run.upload("/etc/sudoers.d/.ops-deploy-paperless_backup") == sudoers_rule(cfg).encode()
    sync = commands.index(
        "cd /home/fastdeploy/site && runuser -u fastdeploy -- env HOME=/home/fastdeploy "
        "/home/fastdeploy/site/.venv/bin/python commands.py syncservices"
    )
    assert sync > next(i for i, c in enumerate(commands) if c.startswith("visudo -cqf"))


def test_a_converged_host_gets_no_mutating_operation() -> None:
    cfg = runner()
    run = run_deploy_fake(deploy_runner, cfg, responses=converged(cfg))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert not any("syncservices" in c for c in run.executed_commands)


def test_a_changed_config_json_is_synced() -> None:
    old = runner(steps=("init", "result"))
    cfg = runner()
    responses = converged(cfg)
    responses.update(_file(f"{cfg.service_dir}/config.json", service_config(old), group="root", mode="-rw-r--r--"))
    run = run_deploy_fake(deploy_runner, cfg, responses=responses)

    assert [n.removeprefix("Echoport backup runner | ") for n in run.mutating_changed_ops] == [
        "Write config.json of paperless-backup",
        "Sync FastDeploy services for paperless-backup",
    ]


@pytest.mark.parametrize("stored", [[], ['{"name": "paperless-backup"}'], ["not json"]])
def test_a_stale_fastdeploy_service_is_synced(stored: list[str]) -> None:
    cfg = runner()
    run = run_deploy_fake(deploy_runner, cfg, responses=converged(cfg, **{STORED: stored}))

    assert [n.removeprefix("Echoport backup runner | ") for n in run.mutating_changed_ops] == [
        "Sync FastDeploy services for paperless-backup",
    ]


def test_a_failed_service_probe_syncs_and_probes_again() -> None:
    cfg = runner()
    run = run_deploy_fake(deploy_runner, cfg, responses=converged(cfg, **{STORED: ["ops-deploy-probe-failed"]}))

    assert run.succeeded, run.error
    assert "Echoport backup runner | Sync FastDeploy services for paperless-backup" in run.changed_ops
    assert "Echoport backup runner | Probe again: FastDeploy service paperless-backup" in [op.name for op in run.ops]


def test_sync_false_leaves_fastdeploy_alone() -> None:
    cfg = runner(sync=False)
    run = run_deploy_fake(deploy_runner, cfg, responses={**ANCESTORS})

    assert not any("syncservices" in c or "psql" in c for c in run.executed_commands + run.fact_commands)


def test_legacy_copies_are_removed_after_the_sync() -> None:
    cfg = runner(legacy_files=("/home/fastdeploy/site/services/paperless-backup/backup.py", "/tmp/old.py"))
    responses = converged(cfg, **{STORED: []})
    for path in cfg.legacy:
        responses.update(fakehost.file(path, "old\n"))
    run = run_deploy_fake(deploy_runner, cfg, responses=responses)

    commands = run.executed_commands
    sync = next(i for i, c in enumerate(commands) if "syncservices" in c)
    removals = [i for i, c in enumerate(commands) if c.startswith("rm -f")]
    assert [commands[i] for i in removals] == [f"rm -f {path}" for path in cfg.legacy]
    assert min(removals) > sync


def test_the_installed_script_is_never_removed_as_legacy() -> None:
    cfg = runner(legacy_files=("/usr/local/libexec/fastdeploy/paperless-backup/backup.py",))
    responses = converged(cfg)
    run = run_deploy_fake(deploy_runner, cfg, responses=responses)

    assert not any(c.startswith("rm ") for c in run.executed_commands)


@pytest.mark.parametrize(
    "lines",
    [
        ["0 0 755 directory", "1000 0 755 directory", "0 0 755 directory"],
        ["0 0 755 directory", "0 50 775 directory", "0 0 755 directory"],
        ["0 0 755 directory", "0 0 757 directory", "0 0 755 directory"],
        ["0 0 755 directory", "0 0 777 symbolic link", "0 0 755 directory"],
        ["0 0 755 directory", "missing", "0 0 755 directory"],
        ["0 0 755 directory"],
        ["ops-deploy-probe-failed"],
    ],
)
def test_an_unsafe_directory_above_the_libexec_root_refuses_before_any_write(lines: list[str]) -> None:
    refused(run_deploy_fake(deploy_runner, runner(), responses={"stat -c '%u %g %a %F'": lines}))


def test_group_writable_by_root_group_is_accepted() -> None:
    cfg = runner()
    lines = ["0 0 755 directory", "0 0 775 directory", "0 0 755 directory"]
    run = run_deploy_fake(deploy_runner, cfg, responses=converged(cfg, **{"stat -c '%u %g %a %F'": lines}))

    assert run.succeeded, run.error


def test_a_template_is_rendered_with_the_plays_variables() -> None:
    from tests.test_echoport_runner_parity import EXPECTED, INPUTS

    spec = INPUTS["snappymail-backup"]
    cfg = runner(service="snappymail-backup", content=None, template=spec["template"])

    def deploy() -> None:
        install_runner(cfg, spec["inputs"])

    run = run_deploy_fake(deploy, responses={**ANCESTORS})

    assert hashlib.sha256(run.upload(cfg.script)).hexdigest() == EXPECTED["runners"]["snappymail-backup"]


# -- MinIO account and mc alias ---------------------------------------------------------

# A line of the echoport deploy's files/minio_account.py, which the probe command carries.
ACCOUNT_PROBE = "def statements(doc)"
ROOT_ALIAS_KEY = "fixture-root-user"
ROOT_SECRET = "fixture-root-password-value"  # pragma: allowlist secret
ACCOUNT_SECRET = "fixture-account-secret-0123456789abcdef"  # pragma: allowlist secret


def access(**changes: Any) -> MinioAccess:
    values: dict[str, Any] = {
        "target": "paperless",
        "os_user": "root",
        "alias": "backup-paperless",
        "url": "http://127.0.0.1:9001",
        "scoped": True,
        "retired_aliases": ("minio",),
        **changes,
    }
    return MinioAccess(**values)


def alias_probe(alias: str) -> re.Pattern[str]:
    return re.compile(rf"alias list {alias} \)")


def access_converged(cfg: MinioAccess, access_key: str, secret: str) -> dict[Any, Any]:
    return {
        ACCOUNT_PROBE: ["policy=ok user=attached"] if cfg.scoped else [],
        alias_probe(cfg.alias): [alias_digest(cfg.url, access_key, secret)],
        **{alias_probe(retired): ["none"] for retired in cfg.retired_aliases},
        **fakehost.directory("/etc/minio/policies", mode="drwxr-x---"),
        **fakehost.file(
            f"/etc/minio/policies/backup-{cfg.target}.json", render_account_policy(cfg.account), mode="-rw-r-----"
        ),
    }


def test_scoped_account_converged_is_a_noop() -> None:
    cfg = access()
    user = cfg.account.user

    def deploy() -> None:
        minio_access(cfg, access_key=user, secret_key=ACCOUNT_SECRET)

    run = run_deploy_fake(deploy, responses=access_converged(cfg, user, ACCOUNT_SECRET))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert ACCOUNT_SECRET not in run.all_text()


def test_scoped_account_is_created_and_the_alias_imported_from_stdin() -> None:
    cfg = access()
    user = cfg.account.user

    def deploy() -> None:
        minio_access(cfg, access_key=user, secret_key=ACCOUNT_SECRET)

    responses = {
        ACCOUNT_PROBE: ["policy=missing user=missing"],
        alias_probe(cfg.alias): ["none"],
        alias_probe("minio"): ["0" * 64],
    }
    run = run_deploy_fake(deploy, responses=responses)

    assert run.succeeded, run.error
    assert user == "bk-" + hashlib.sha256(b"paperless").hexdigest()[:17]
    assert [name for name in run.changed_ops if "Verify" not in name and "Require" not in name] == [
        "Create MinIO policy directory",
        "Install MinIO policy backup-paperless",
        "Create or update MinIO policy backup-paperless",
        "Create or update MinIO user of paperless",
        "Attach MinIO policy backup-paperless",
        "Configure mc alias backup-paperless of root",
        "Remove retired mc alias minio of root",
    ]
    stdin = dict(run.stdin)
    add = next(command for command in stdin if "admin user add" in command)
    assert stdin[add] == f"{user}\n{ACCOUNT_SECRET}\n"
    imported = next(command for command in stdin if "alias import" in command)
    assert json.loads(stdin[imported]) == {
        "url": cfg.url,
        "accessKey": user,
        "secretKey": ACCOUNT_SECRET,
        "api": "s3v4",
        "path": "auto",
    }
    assert "runuser -u root -- env HOME=/root /usr/local/bin/mc alias import backup-paperless" in imported
    assert ACCOUNT_SECRET not in "\n".join(run.executed_commands + run.fact_commands)
    policy = json.loads(run.upload("/etc/minio/policies/backup-paperless.json"))
    actions = [statement["Action"] for statement in policy["Statement"]]
    assert actions[-1] == ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
    assert policy["Statement"][-1]["Resource"] == ["arn:aws:s3:::backups/paperless/*"]


def test_unscoped_target_keeps_the_shared_alias_with_the_root_credentials() -> None:
    cfg = access(scoped=False, alias="minio", retired_aliases=())

    def deploy() -> None:
        minio_access(cfg, access_key=ROOT_ALIAS_KEY, secret_key=ROOT_SECRET)

    run = run_deploy_fake(deploy, responses={alias_probe("minio"): ["none"]})

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == ["Configure mc alias minio of root"]
    assert not any("admin" in c for c in run.executed_commands)
    assert ROOT_SECRET not in run.all_text()
    assert ROOT_ALIAS_KEY not in run.all_text()


def test_rustfs_store_proves_the_account_and_creates_nothing_on_minio() -> None:
    cfg = access(store="rustfs", rustfs_account=True, alias="rustfs-backup-paperless", url="http://127.0.0.1:9020")
    user = cfg.account.user

    def deploy() -> None:
        minio_access(cfg, access_key=user, secret_key=ACCOUNT_SECRET)

    run = run_deploy_fake(deploy, responses=access_converged(cfg, user, ACCOUNT_SECRET))

    assert run.succeeded, run.error
    assert not any("admin" in c for c in run.executed_commands)
    assert run.executed_commands[-1] == (
        "runuser -u root -- env HOME=/root /usr/local/bin/mc ls rustfs-backup-paperless/backups/paperless/ >/dev/null"
    )


def test_rclone_runner_gets_no_alias() -> None:
    cfg = access(os_user="none", retired_aliases=())
    user = cfg.account.user

    def deploy() -> None:
        minio_access(cfg, access_key=user, secret_key=ACCOUNT_SECRET)

    run = run_deploy_fake(deploy, responses=access_converged(cfg, user, ACCOUNT_SECRET))

    assert run.succeeded, run.error
    assert not any("alias import" in c or "alias remove" in c for c in run.executed_commands)
    assert not any("alias list" in c for c in run.fact_commands)
    # Without an alias nothing proves the stored secret current: the upsert runs, as in the role.
    assert run.mutating_changed_ops == ["Create or update MinIO user of paperless"]


@pytest.mark.parametrize(
    "changes",
    [
        {"store": "rustfs"},
        {"store": "rustfs", "rustfs_account": True, "scoped": False},
        {"alias": "minio"},
        {"alias": "1bad"},
        {"url": "ftp://x"},
        {"os_user": "Root"},
    ],
)
def test_access_the_include_refuses_is_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="validation error"):
        access(**changes)


@pytest.mark.parametrize(
    ("key", "secret"),
    [("", ACCOUNT_SECRET), ("bk-other", ACCOUNT_SECRET), (None, "short"), (None, "")],
)
def test_bad_credentials_refuse_without_showing_them(key: str | None, secret: str) -> None:
    cfg = access()

    def deploy() -> None:
        minio_access(cfg, access_key=cfg.account.user if key is None else key, secret_key=secret)

    message = refused(run_deploy_fake(deploy, responses={ACCOUNT_PROBE: ["policy=ok user=attached"]}))
    if secret:
        assert secret not in message


# -- work dir -------------------------------------------------------------------------

WORK = "/mnt/cryptdata/backups/tmp/homepage-staging-backup"
KINDS = "if [ -L"


def test_work_dir_parents_are_the_includes() -> None:
    cfg = WorkDir(path=WORK, owner="deploy")

    assert cfg.parents == ["/mnt/cryptdata/backups", "/mnt/cryptdata/backups/tmp"]


@pytest.mark.parametrize(
    "changes",
    [
        {"path": "relative/dir"},
        {"path": "/mnt/cryptdata/backups/../etc"},
        {"path": "/mnt/cryptdata/backups//tmp"},
        {"path": "/mnt/cryptdata/backups/tmp/"},
        {"path": "/mnt/cryptdata"},
        {"path": "/srv/elsewhere"},
        {"mount": "/"},
        {"owner": "root"},
    ],
)
def test_work_dir_the_include_refuses_is_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="validation error"):
        WorkDir(**{"path": WORK, "owner": "deploy", **changes})


def test_work_dir_on_a_fresh_disk() -> None:
    cfg = WorkDir(path=WORK, owner="deploy")
    responses = {"mountpoint -q": ["mounted"], KINDS: ["dir", "missing", "missing"], "getfacl": ["missing"]}
    run = run_deploy_fake(work_dir, cfg, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    # The existing parent keeps owner and mode; the new one is root-only.
    assert "chmod 700 /mnt/cryptdata/backups" not in commands
    assert "chmod 700 /mnt/cryptdata/backups/tmp" in commands
    assert "setfacl -P -m user:deploy:--x /mnt/cryptdata/backups" in commands
    assert "setfacl -P -m user:deploy:--x /mnt/cryptdata/backups/tmp" in commands
    assert f"chown deploy:deploy {WORK}" in commands
    assert f"chmod 700 {WORK}" in commands
    assert commands.index("chmod 700 /mnt/cryptdata/backups/tmp") < commands.index(
        "setfacl -P -m user:deploy:--x /mnt/cryptdata/backups/tmp"
    )


def test_work_dir_converged_is_a_noop() -> None:
    cfg = WorkDir(path=WORK, owner="deploy")
    responses = {
        "mountpoint -q": ["mounted"],
        KINDS: ["dir", "dir", "dir"],
        "getfacl": ["ok"],
        **fakehost.stat(WORK, user="deploy", mode="drwx------"),
    }
    run = run_deploy_fake(work_dir, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []


@pytest.mark.parametrize(
    "responses",
    [
        {"mountpoint -q": ["missing"]},
        {"mountpoint -q": ["mounted"], KINDS: ["link", "dir", "dir"]},
        {"mountpoint -q": ["mounted"], KINDS: ["dir", "dir", "other"]},
        {"mountpoint -q": ["mounted"], KINDS: ["dir"]},
    ],
)
def test_work_dir_refuses_before_any_write(responses: dict[str, Any]) -> None:
    refused(run_deploy_fake(work_dir, WorkDir(path=WORK, owner="deploy"), responses=responses))


# -- known host -------------------------------------------------------------------------

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
OTHER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
KNOWN = "/home/deploy/.ssh/known_hosts"


def _no_scan(name: str) -> str:
    raise AssertionError("a pinned key is never scanned")


def test_a_pin_is_used_without_scanning() -> None:
    cfg = KnownHost(name="staging.example.invalid", pin=KEY, pin_address="staging.example.invalid")

    assert host_keys(cfg, _no_scan) == [KEY]


def test_scanned_keys_are_filtered_to_the_names_ed25519_lines() -> None:
    cfg = KnownHost(name="staging.example.invalid")
    output = "\n".join(
        [
            "# staging.example.invalid:22 SSH-2.0-OpenSSH_9.8",
            f"staging.example.invalid {KEY}",
            f"staging.example.invalid {KEY}",
            f"other.example.invalid {OTHER}",
            "staging.example.invalid ssh-rsa AAAAB3Nza",
        ]
    )

    assert host_keys(cfg, lambda name: output) == [KEY]


@pytest.mark.parametrize(
    ("cfg", "scan"),
    [
        (KnownHost(name="staging.example.invalid"), ""),
        (KnownHost(name="staging.example.invalid"), f"staging.example.invalid {KEY}\nstaging.example.invalid {OTHER}"),
        (KnownHost(name="staging.example.invalid", pin="", pin_address="staging.example.invalid"), ""),
        (KnownHost(name="staging.example.invalid", pin="ssh-ed25519 AAAA", pin_address="staging.example.invalid"), ""),
        (KnownHost(name="staging.example.invalid", pin=KEY, pin_address="10.0.0.1"), ""),
    ],
)
def test_anything_but_one_good_key_refuses_before_writing(cfg: KnownHost, scan: str) -> None:
    def deploy() -> None:
        known_host(cfg, lambda name: scan)

    assert "Nothing was written" in refused(run_deploy_fake(deploy))


def test_a_missing_entry_is_appended_keeping_the_file() -> None:
    cfg = KnownHost(name="staging.example.invalid", pin=KEY, pin_address="staging.example.invalid")
    current = f"other.example.invalid {OTHER}\n"
    encoded = __import__("base64").b64encode(current.encode()).decode()

    def deploy() -> None:
        known_host(cfg, _no_scan)

    responses = {
        "base64 -w0": ["present", encoded],
        **fakehost.stat(KNOWN, user="deploy", mode="-rw-r--r--"),
    }
    run = run_deploy_fake(deploy, responses=responses)

    assert run.succeeded, run.error
    assert run.upload(KNOWN) == (current + f"staging.example.invalid {KEY}\n").encode()
    assert f"chown deploy:deploy {KNOWN}" in run.executed_commands


def test_a_present_key_changes_nothing() -> None:
    cfg = KnownHost(name="staging.example.invalid", pin=KEY, pin_address="staging.example.invalid")
    current = f"staging.example.invalid {KEY}\n"
    encoded = __import__("base64").b64encode(current.encode()).decode()

    def deploy() -> None:
        known_host(cfg, _no_scan)

    responses = {
        "base64 -w0": ["present", encoded],
        "ssh-keygen -F": ["# Host staging.example.invalid found: line 1", f"staging.example.invalid {KEY}"],
    }
    run = run_deploy_fake(deploy, responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []
