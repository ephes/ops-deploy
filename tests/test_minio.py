"""Deploy-level scenarios for minio and its backup accounts against the fake connector."""

import hashlib
import json
from typing import Any

import bcrypt
import pytest
from pydantic import SecretStr

from ops_deploy.core import ConfigValidationError, SecretRef, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.minio import (
    BackupAccount,
    Bucket,
    MinioConfig,
    RunnerAlias,
    deploy_backup_account,
    deploy_minio,
)
from ops_deploy.services.minio.deploy import (
    check_secrets,
    render_env,
    render_policy,
    render_route,
    render_unit,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

ENV = "/etc/default/minio"
UNIT = "/etc/systemd/system/minio.service"
ROUTE = "/etc/traefik/dynamic/minio.yml"
DATA = "/mnt/cryptdata/minio/data"
MINIO = "/usr/local/bin/minio"
MC = "/usr/local/bin/mc"
MINIO_SHA = "2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4"
MC_SHA = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
CONSOLE = "minio.example.invalid"
SECRET_VALUES = {
    "root_user": "minio-fixture-root",
    "root_password": "minio-fixture-root-password-0123",
    "console_basic_auth_password": "minio-fixture-console-pw",
}
ALIAS_PROBE = "--json alias list local"
BUCKET_PROBE = "what the MinIO bootstrap still has to do"
OWNER_PROBE = f"then find {DATA} -ignore_readdir_race ! -user minio"
PREFIX = "Deploy minio | "
READ_ONLY = [
    "Require /mnt/cryptdata to be mounted",
    "Port preflight tcp/9001 tcp/9002",
    "Wait for the MinIO API port",
    "Wait for the MinIO console port",
    "Check MinIO health endpoint",
    "Verify mc alias local",
    "Verify MinIO bucket voxhelm",
    "Verify MinIO bucket agent-sessions",
]


def digest(*parts: str) -> str:
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def make_cfg(**overrides: Any) -> MinioConfig:
    # ops-control's minio_config(): deploy-minio.yml's role vars.
    fields: dict[str, Any] = {
        "secrets": SecretRef("secrets/prod/minio.yml"),
        "data_dirs": (DATA,),
        "required_mounts": ("/mnt/cryptdata",),
        "port_preflight": True,
        "expose_via_traefik": True,
        "traefik_host": CONSOLE,
        "traefik_api_host": "s3.example.invalid",
        "bootstrap_with_mc": True,
        "buckets": (Bucket(name="voxhelm", policy="private"), Bucket(name="agent-sessions", policy="private")),
        **overrides,
    }
    return MinioConfig(**fields)


@pytest.fixture
def cfg() -> MinioConfig:
    return make_cfg()


def values(cfg: MinioConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


def binary(path: str, sha256: str) -> dict[str, Any]:
    return {f"sha256sum {path} ": [f"{sha256}  {path}"], **fakehost.stat(path, mode="-rwxr-xr-x")}


def converged(cfg: MinioConfig, secrets: SecretValues, **drift: str) -> dict[str, Any]:
    """Facts of a host where MinIO is fully deployed; ``drift`` overrides file content by path."""

    content = {
        UNIT: render_unit(cfg, secrets),
        ROUTE: render_route(cfg, secrets, hash_password(secrets["console_basic_auth_password"])),
        ENV: render_env(cfg, secrets).reveal().decode(),
    }
    content.update(drift)
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.accounts({"minio": "/home/minio"}),
        **binary(MINIO, MINIO_SHA),
        **binary(MC, MC_SHA),
    }
    responses.update(fakehost.directory("/home/minio", user="minio", mode="drwxr-x---"))
    responses.update(fakehost.directory(DATA, user="minio", mode="drwxr-x---"))
    for path in ("/etc/minio", "/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        responses.update(fakehost.file(path, text, mode="-rw-------" if path == ENV else "-rw-r--r--"))
    responses.update(fakehost.service("minio.service"))
    responses[ALIAS_PROBE] = [digest("http://127.0.0.1:9001", secrets["root_user"], secrets["root_password"])]
    responses[BUCKET_PROBE] = ["{}"]
    return responses


def deploy(cfg: MinioConfig, secrets: SecretValues, responses: dict[str, Any] | None = None) -> FakeRun:
    run = run_deploy_fake(deploy_minio, cfg, secrets, responses=responses or fakehost.LINUX)
    assert run.succeeded, run.error
    return run


def changed_names(run: FakeRun, prefix: str = PREFIX) -> set[str]:
    return {name.removeprefix(prefix) for name in run.mutating_changed_ops}


def test_first_run_installs_everything(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    # Before mc is installed the probes report the states of a first deploy.
    run = deploy(cfg, secrets, {**fakehost.LINUX, BUCKET_PROBE: ["absent"], ALIAS_PROBE: ["none"]})

    commands = run.executed_commands
    assert "useradd -d /home/minio -s /usr/sbin/nologin -g minio -r -M minio" in commands
    install = next(c for c in commands if "minio.RELEASE.2025-10-15T17-29-55Z.hotfix.c392ab039" in c)
    # The role's minio_download_url for a hotfix build, checked before it replaces the binary.
    assert (
        "https://dl.min.io/server/minio/hotfixes/linux-amd64/archive/archive/"
        "minio.RELEASE.2025-10-15T17-29-55Z.hotfix.c392ab039"
    ) in install
    assert install.index("sha256sum -c") < install.index("mv -f")
    assert f"echo {MINIO_SHA}" in install
    mc_install = next(c for c in commands if "mc.RELEASE.2025-08-13T08-35-41Z" in c)
    assert "https://dl.min.io/client/mc/release/linux-amd64/archive/mc.RELEASE.2025-08-13T08-35-41Z" in mc_install
    assert run.upload(UNIT).decode() == render_unit(cfg, secrets)
    start = commands.index("systemctl start minio.service")
    assert "systemctl restart minio.service" not in commands
    # The bootstrap after MinIO runs: the alias, then every bucket step.
    alias = next(c for c in commands if "alias import local" in c)
    buckets = [c for c in commands if c.startswith(f"{MC} mb local/")]
    assert buckets == [f"{MC} mb local/voxhelm --ignore-existing", f"{MC} mb local/agent-sessions --ignore-existing"]
    assert f"{MC} anonymous set private local/voxhelm" in commands
    assert start < commands.index(alias) < commands.index(buckets[0])
    # The env file and the admin alias travel on stdin only.
    stdin = dict(run.stdin)
    assert json.loads(stdin[alias]) == {
        "url": "http://127.0.0.1:9001",
        "accessKey": SECRET_VALUES["root_user"],
        "secretKey": SECRET_VALUES["root_password"],
        "api": "s3v4",
        "path": "auto",
    }
    assert ENV not in run.uploaded_paths
    route = run.upload(ROUTE).decode()
    line = next(line for line in route.splitlines() if line.strip().startswith('- "admin:'))
    auth_hash = line.strip()[len('- "admin:') : -1]
    assert bcrypt.checkpw(SECRET_VALUES["console_basic_auth_password"].encode(), auth_hash.encode())
    assert route == render_route(cfg, secrets, auth_hash)
    # The role does not restart Traefik: it watches its dynamic directory.
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    assert [op.name.removeprefix(PREFIX) for op in run.ops if op.read_only] == READ_ONLY


def test_second_run_changes_nothing_mutating(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert [name.removeprefix(PREFIX) for name in run.changed_ops] == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any("chown" in c or "curl -fsSL" in c or " mb " in c for c in run.executed_commands)


def test_checks_run_before_any_change(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    for failing in ("mountpoint -q /mnt/cryptdata", "sport = :$port"):
        run = run_deploy_fake(deploy_minio, cfg, secrets, responses={**fakehost.LINUX, failing: {"success": False}})

        assert not run.succeeded
        assert run.mutating_changed_ops == []
        assert run.stdin == []
        assert not any("useradd" in c or "curl" in c for c in run.executed_commands)


def test_env_change_restarts_minio(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    rotated = values(cfg, root_password="minio-fixture-rotated-password-01")
    run = deploy(cfg, rotated, converged(cfg, secrets))

    # The env file and root's alias follow the new password; MinIO restarts once.
    assert changed_names(run) == {f"Write {ENV}", "Restart minio.service", "Configure root's mc alias local"}
    commands = run.executed_commands
    assert commands.index("systemctl restart minio.service") < next(
        i for i, c in enumerate(commands) if "alias import local" in c
    )


def test_unit_change_reloads_and_restarts(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{UNIT: "[Unit]\n"}))

    assert changed_names(run) == {
        "Install systemd unit minio.service",
        "Reload systemd for minio.service",
        "Restart minio.service",
    }


def test_new_binary_is_installed_and_restarts(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), **binary(MINIO, "0" * 64)}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {"Install MinIO /usr/local/bin/minio", "Restart minio.service"}


def test_mc_upgrade_does_not_restart(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), **binary(MC, "0" * 64)}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {"Install mc /usr/local/bin/mc"}


def test_binary_mode_drift_is_fixed_without_download(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), **fakehost.stat(MINIO, mode="-rwxrwxrwx")}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {f"Set owner and mode of {MINIO}"}
    assert not any("curl -fsSL" in c for c in run.executed_commands)


def test_route_drift_rewrites_only_the_route(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert changed_names(run) == {"Write Traefik route minio"}


def test_bucket_steps_run_only_for_what_differs(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), BUCKET_PROBE: [json.dumps({"agent-sessions": ["anonymous"]})]}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {"Set anonymous access private on MinIO bucket agent-sessions"}


def test_versioning_is_enabled_when_asked(cfg: MinioConfig) -> None:
    cfg = make_cfg(buckets=(Bucket(name="backups", versioning=True),))
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), BUCKET_PROBE: [json.dumps({"backups": ["version"]})]}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {"Enable versioning on MinIO bucket backups"}
    assert f"{MC} version enable local/backups" in run.executed_commands


@pytest.mark.parametrize("answer", [[FAILED], ["not json"], ['["a list"]']], ids=["failed", "garbage", "list"])
def test_a_failing_bucket_probe_runs_every_step_and_probes_again(cfg: MinioConfig, answer: list[str]) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), BUCKET_PROBE: answer})

    assert changed_names(run) == {
        "Create MinIO bucket voxhelm",
        "Create MinIO bucket agent-sessions",
        "Set anonymous access private on MinIO bucket voxhelm",
        "Set anonymous access private on MinIO bucket agent-sessions",
    }
    assert run.op(PREFIX + "Probe again: MinIO buckets").changed


def test_foreign_owned_data_is_chowned(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets, {**converged(cfg, secrets), OWNER_PROBE: ["x"]})

    assert changed_names(run) == {f"Set ownership below {DATA}"}
    assert f"chown -R minio:minio {DATA}" in run.executed_commands
    # Never a recursive chmod of the store.
    assert not any("chmod -R" in c for c in run.executed_commands)


def test_kept_data_without_the_user_is_chowned(cfg: MinioConfig) -> None:
    # A first deploy over kept data: the probe cannot name a missing user.
    secrets = values(cfg)
    responses = {**converged(cfg, secrets), f"id -u minio >/dev/null 2>&1; then find {DATA}": ["x"]}
    run = deploy(cfg, secrets, responses)

    assert changed_names(run) == {f"Set ownership below {DATA}"}
    assert not any("Probe again" in op.name for op in run.ops)


def test_without_traefik_and_bootstrap_only_the_server(cfg: MinioConfig) -> None:
    cfg = make_cfg(expose_via_traefik=False, bootstrap_with_mc=False, buckets=(), port_preflight=False)
    secrets = SecretValues(
        SecretRef("secrets/prod/minio.yml"), {k: SECRET_VALUES[k] for k in ("root_user", "root_password")}
    )
    run = deploy(cfg, secrets)

    assert ROUTE not in run.uploaded_paths
    assert not any(MC in c for c in run.executed_commands)
    # Only the env file travels on stdin; there is no admin alias to import.
    assert len(run.stdin) == 1


def test_secrets_never_recorded(cfg: MinioConfig) -> None:
    secrets = values(cfg)
    run = deploy(cfg, secrets)

    text = run.all_text()
    for key, value in SECRET_VALUES.items():
        assert value not in text, key


def test_missing_placeholder_and_unsafe_secrets_are_refused(cfg: MinioConfig) -> None:
    check_secrets(cfg, values(cfg))
    ref = SecretRef("secrets/prod/minio.yml")
    with pytest.raises(MissingSecretKeysError):
        check_secrets(cfg, SecretValues(ref, {"root_user": "x"}))
    with pytest.raises(MissingSecretKeysError):
        check_secrets(cfg, SecretValues(ref, {k: SECRET_VALUES[k] for k in ("root_user", "root_password")}))
    for key in ("root_password", "console_basic_auth_password"):
        with pytest.raises(ValueError, match=key):
            check_secrets(cfg, values(cfg, **{key: "CHANGEME"}))
    # An empty value counts as missing.
    with pytest.raises(MissingSecretKeysError, match="root_user"):
        check_secrets(cfg, values(cfg, root_user=""))
    for bad in ('pw"x', "pw\\x", "pw\nx", "pw\rx"):
        with pytest.raises(ValueError, match="double quotes") as caught:
            check_secrets(cfg, values(cfg, root_password=bad))
        assert bad not in str(caught.value)


def test_config_rejects_bad_values() -> None:
    for overrides, message in (
        ({"data_dirs": ()}, "data_dirs"),
        ({"data_dirs": ("relative",)}, "paths must be absolute"),
        ({"data_dirs": ("/srv/../etc",)}, "paths must be absolute"),
        ({"data_dirs": ("/srv/min io",)}, "paths must be absolute"),
        ({"expose_via_traefik": True, "traefik_host": "minio.home.example.com"}, "traefik_host"),
        ({"console_port": 9001}, "must differ"),
        ({"buckets": (Bucket(name="voxhelm"), Bucket(name="voxhelm"))}, "unique"),
        ({"bootstrap_with_mc": False}, "bootstrap_with_mc"),
        ({"checksum": "sha256:abc"}, "checksum"),
        ({"version": "latest"}, "version"),
        ({"site_path": "/srv/minio"}, "site_path"),
        ({"tls_enable": True}, "tls_enable"),
        ({"service_accounts": []}, "service_accounts"),
    ):
        with pytest.raises(ConfigValidationError, match=message):
            make_cfg(**overrides)
    for policy in ("readonly", "writeonly", "custom"):
        with pytest.raises(ValueError, match="policy"):
            Bucket(name="voxhelm", policy=policy)


def test_download_urls_follow_the_role() -> None:
    release = make_cfg(version="RELEASE.2024-10-02T17-50-41Z")
    assert release.binary_url == (
        "https://dl.min.io/server/minio/release/linux-amd64/archive/minio.RELEASE.2024-10-02T17-50-41Z"
    )
    custom = make_cfg(download_url="http://127.0.0.1:8000/minio", mc_download_url="http://127.0.0.1:8000/mc")
    assert (custom.binary_url, custom.mc_url) == ("http://127.0.0.1:8000/minio", "http://127.0.0.1:8000/mc")


# -- tasks_from: backup_account ---------------------------------------------------

ACCOUNT_PREFIX = "Deploy MinIO backup account | "
SECRET = SecretStr("account-fixture-secret-0123456789")
ACCOUNT = BackupAccount(name="delve", alias=RunnerAlias(name="backup-delve"))
ACCOUNT_USER = "bk-" + hashlib.sha256(b"delve").hexdigest()[:17]
POLICY_FILE = "/etc/minio/policies/backup-delve.json"
ACCOUNT_PROBE = " probe /usr/local/bin/mc local backup-delve "
RUNNER_ALIAS_PROBE = "--json alias list backup-delve"
RUNNER_LOGIN = "ls backup-delve/backups/delve/ >/dev/null && echo ok"
ACCOUNT_STEPS = {
    "policy": "Create or update MinIO policy backup-delve",
    "user": "Create or update MinIO user of delve",
    "attach": "Attach MinIO policy backup-delve",
    "alias": "Configure mc alias backup-delve of root",
}
ACCOUNT_READ_ONLY = [
    "Require the MinIO admin alias local of root",
    "Verify mc alias backup-delve reaches backups/delve/",
    "Verify MinIO account delve",
]


def account_converged(account: BackupAccount = ACCOUNT, secret: SecretStr = SECRET) -> dict[str, Any]:
    responses: dict[str, Any] = {**fakehost.LINUX}
    responses.update(fakehost.directory("/etc/minio/policies", mode="drwxr-x---"))
    responses.update(fakehost.directory("/root", mode="drwx------"))
    responses.update(fakehost.file(account.policy_path.as_posix(), render_policy(account), mode="-rw-r-----"))
    responses[ACCOUNT_PROBE] = ["policy=ok user=attached"]
    responses[RUNNER_ALIAS_PROBE] = [digest("http://127.0.0.1:9001", account.user, secret.get_secret_value())]
    responses[RUNNER_LOGIN] = ["ok"]
    return responses


def deploy_account(responses: dict[str, Any], account: BackupAccount = ACCOUNT, secret: SecretStr = SECRET) -> FakeRun:
    run = run_deploy_fake(deploy_backup_account, account, secret, responses=responses)
    assert run.succeeded, run.error
    return run


def test_account_first_run_creates_everything_through_the_admin_alias() -> None:
    run = deploy_account({**fakehost.LINUX, **fakehost.directory("/root", mode="drwx------")})

    commands = run.executed_commands
    steps = [
        f"{MC} admin info local",
        f"{MC} admin policy create local backup-delve {POLICY_FILE}",
        f"{MC} admin user add local",
        f"{MC} admin policy attach local backup-delve --user {ACCOUNT_USER}",
    ]
    positions = [next(i for i, c in enumerate(commands) if c.startswith(step)) for step in steps]
    assert positions == sorted(positions)
    assert run.upload(POLICY_FILE).decode() == render_policy(ACCOUNT)
    stdin = dict(run.stdin)
    user_add = commands[positions[2]]
    assert stdin[user_add] == f"{ACCOUNT_USER}\n{SECRET.get_secret_value()}\n"
    alias = next(c for c in commands if "alias import backup-delve" in c)
    assert commands.index(alias) > positions[3]
    assert json.loads(stdin[alias]) == {
        "url": "http://127.0.0.1:9001",
        "accessKey": ACCOUNT_USER,
        "secretKey": SECRET.get_secret_value(),
        "api": "s3v4",
        "path": "auto",
    }
    assert SECRET.get_secret_value() not in run.all_text()
    assert [op.name.removeprefix(ACCOUNT_PREFIX) for op in run.ops if op.read_only] == ACCOUNT_READ_ONLY


def test_account_second_run_changes_nothing() -> None:
    run = deploy_account(account_converged())

    assert run.mutating_changed_ops == []
    assert run.stdin == []


@pytest.mark.parametrize(
    ("state", "steps"),
    [
        ("policy=differs user=attached", {"policy"}),
        ("policy=missing user=attached", {"policy"}),
        ("policy=ok user=unattached", {"attach"}),
        ("policy=ok user=missing", {"user", "attach"}),
        ("policy=missing user=missing", {"policy", "user", "attach"}),
    ],
)
def test_account_steps_run_only_for_what_differs(state: str, steps: set[str]) -> None:
    run = deploy_account({**account_converged(), ACCOUNT_PROBE: [state]})

    assert changed_names(run, ACCOUNT_PREFIX) == {ACCOUNT_STEPS[step] for step in steps}


def test_a_secret_the_alias_cannot_log_in_with_is_upserted() -> None:
    run = deploy_account({**account_converged(), RUNNER_LOGIN: []})

    assert changed_names(run, ACCOUNT_PREFIX) == {ACCOUNT_STEPS["user"]}


def test_account_secret_rotation_upserts_the_user_then_the_alias() -> None:
    rotated = SecretStr("account-fixture-rotated-0123456789")
    run = deploy_account(account_converged(), secret=rotated)

    assert changed_names(run, ACCOUNT_PREFIX) == {ACCOUNT_STEPS["user"], ACCOUNT_STEPS["alias"]}


def test_without_a_runner_alias_the_user_is_upserted_every_run() -> None:
    # As the role: ``mc admin user add`` runs on every pass, nothing proves the secret.
    account = BackupAccount(name="delve")
    run = deploy_account(account_converged(account), account=account)

    assert changed_names(run, ACCOUNT_PREFIX) == {ACCOUNT_STEPS["user"]}


def test_without_root_admin_alias_nothing_changes_on_minio() -> None:
    responses = {
        **account_converged(),
        f"{MC} admin info local": {"success": False},
        ACCOUNT_PROBE: ["policy=missing user=missing"],
    }
    run = run_deploy_fake(deploy_backup_account, ACCOUNT, SECRET, responses=responses)

    assert not run.succeeded
    assert not any("mc admin policy" in c or "mc admin user" in c for c in run.executed_commands)
    assert run.stdin == []


def test_an_account_that_fails_verification_fails_the_deploy() -> None:
    responses = {**account_converged(), " verify /usr/local/bin/mc local backup-delve ": {"success": False}}
    run = run_deploy_fake(deploy_backup_account, ACCOUNT, SECRET, responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == ACCOUNT_PREFIX + "Verify MinIO account delve"


def test_runner_alias_of_another_user_goes_through_runuser() -> None:
    account = BackupAccount(
        name="marina-staging", alias=RunnerAlias(name="backup-marina-staging", os_user="deploy", home="/home/deploy")
    )
    run = deploy_account({**fakehost.LINUX, **fakehost.directory("/home/deploy", user="deploy")}, account=account)

    alias = next(c for c in run.executed_commands if "alias import backup-marina-staging" in c)
    assert "runuser -u deploy -- env HOME=/home/deploy /usr/local/bin/mc alias import backup-marina-staging" in alias
    assert 'chown deploy "$d/alias.json"' in alias


def test_account_secret_follows_the_roles_input_check() -> None:
    for bad in ("x" * 31, "x" * 41, "CHANGEME", "x" * 20 + "\n" + "x" * 20):
        with pytest.raises(ValueError, match="secret key") as caught:
            run_deploy_fake(deploy_backup_account, ACCOUNT, SecretStr(bad), responses=account_converged())
        assert bad == "CHANGEME" or bad not in str(caught.value)
    for name in ("", "-lead", "has space", "a/b"):
        with pytest.raises(ValueError, match="name"):
            BackupAccount(name=name)
    with pytest.raises(ValueError, match="prefixes"):
        BackupAccount(name="delve", prefixes=("delve/*",))


def test_account_names_and_listing() -> None:
    assert ACCOUNT.user == ACCOUNT_USER
    assert len(ACCOUNT.user) == 20
    assert ACCOUNT.listing == "backups/delve/"
    assert BackupAccount(name="echoport-retention", whole_bucket=True).listing == "backups"
    weeknotes = BackupAccount(name="weeknotes_home", prefixes=("weeknotes_home", "weeknotes-home"))
    assert weeknotes.listing == "backups/weeknotes_home/"


def test_verbose_output_shows_no_digest_or_hash(cfg: MinioConfig) -> None:
    # ``pyinfra -vvv`` prints fact output; digests of credentials and the
    # route's bcrypt hash must not be part of it.
    secrets = values(cfg)
    responses = converged(cfg, secrets)
    route = responses[f"cat {ROUTE}"]
    auth_hash = next(line for line in route if '- "admin:' in line).strip()[len('- "admin:') : -1]
    alias_digest = responses[ALIAS_PROBE][0]
    env_sha = hashlib.sha256(render_env(cfg, secrets).reveal()).hexdigest()
    run = run_deploy_fake(deploy_minio, cfg, secrets, responses=responses, verbose=True)

    assert run.succeeded, run.error
    output = "\n".join(run.printed)
    # Verbose output is on: a public fact (the binary's sha256) is printed.
    assert MINIO_SHA in output
    for secret in (auth_hash, alias_digest, env_sha, *SECRET_VALUES.values()):
        assert secret not in output


def test_verbose_account_output_shows_no_digest() -> None:
    responses = account_converged()
    alias_digest = responses[RUNNER_ALIAS_PROBE][0]
    run = run_deploy_fake(deploy_backup_account, ACCOUNT, SECRET, responses=responses, verbose=True)

    assert run.succeeded, run.error
    output = "\n".join(run.printed)
    # Verbose output is on: a public fact (the policy file's mode) is printed.
    assert "mode=-rw-r-----" in output
    assert alias_digest not in output
    assert SECRET.get_secret_value() not in output


def test_runner_alias_cannot_replace_roots_admin_alias() -> None:
    with pytest.raises(ValueError, match="admin alias"):
        BackupAccount(name="delve", alias=RunnerAlias(name="local"))
    with pytest.raises(ValueError, match="admin alias"):
        BackupAccount(name="delve", admin_alias="admin", alias=RunnerAlias(name="admin"))
    # Another user's alias of that name is that user's own configuration.
    BackupAccount(name="delve", alias=RunnerAlias(name="local", os_user="deploy", home="/home/deploy"))
