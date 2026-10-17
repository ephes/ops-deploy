"""Deploy MinIO and a scoped backup account to the smoke target.

Needs the pinned linux-amd64 ``minio`` and ``mc`` in ``MINIO_BIN_DIR``
(dl.min.io no longer serves the pinned community builds; copy them from a host
that has them). The VM serves them over loopback HTTP as the download URL, so
the fresh deploy goes through the download and checksum path; amd64 binaries
run through qemu-user on an arm64 VM. The data directory lives on a tmpfs
mounted for the test, the mount the deploy requires.

Steps: a port preflight that refuses a foreign listener before any change, a
deploy that refuses an unmounted data volume, a fresh deploy, a converged
rerun, a unit change (one restart), a scoped backup account (create, rerun,
upload and download with its alias, a foreign prefix refused), a secret
rotation, and a rerun after it.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shlex
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import SecretStr

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.minio import (
    BackupAccount,
    Bucket,
    MinioConfig,
    RunnerAlias,
    deploy_backup_account,
    deploy_minio,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

CONSOLE = "minio.example.invalid"
MOUNT = "/mnt/minio-smoke"
DATA = f"{MOUNT}/minio/data"
DOWNLOADS = "/root/minio-smoke-downloads"
SERVE_PORT = 8097
PREFIX = "Deploy minio | "
ACCOUNT_PREFIX = "Deploy MinIO backup account | "


def bin_dir() -> Path | None:
    configured = os.environ.get("MINIO_BIN_DIR")
    return Path(configured) if configured else None


def reset(smoke_host: SmokeHost) -> None:
    """Remove every trace of an earlier run (MinIO, its data, root's mc configuration)."""

    smoke_host.run(
        "systemctl disable --now minio 2>/dev/null; "
        "systemctl stop minio-smoke-downloads minio-smoke-squatter 2>/dev/null; "
        "rm -f /etc/systemd/system/minio.service /etc/default/minio /usr/local/bin/minio /usr/local/bin/mc "
        "/etc/traefik/dynamic/minio.yml; systemctl daemon-reload; "
        f"umount {MOUNT} 2>/dev/null; rm -rf {MOUNT} /etc/minio /root/.mc /var/lib/minio; "
        "userdel -r minio 2>/dev/null; groupdel minio 2>/dev/null; true",
        check=False,
    )


@dataclass(frozen=True)
class Deployed:
    cfg: MinioConfig
    values: SecretValues
    squatted: SshRun
    unmounted: SshRun
    first: SshRun
    second: SshRun
    unit_change: SshRun
    unit_rerun: SshRun
    pids: tuple[str, str, str]


def deploy(smoke_host: SmokeHost, label: str, cfg: MinioConfig, values: SecretValues) -> SshRun:
    run = run_deploy_ssh(deploy_minio, cfg, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
    TIMINGS[f"minio {label}"] = run.seconds
    return run


def pid(smoke_host: SmokeHost) -> str:
    return smoke_host.out("systemctl show -p MainPID --value minio")


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost) -> Deployed:
    binaries = bin_dir()
    if binaries is None or not (binaries / "minio").is_file() or not (binaries / "mc").is_file():
        pytest.skip("no pinned minio and mc binaries (set MINIO_BIN_DIR)")
    reset(smoke_host)
    if smoke_host.out("uname -m") != "x86_64":
        smoke_host.run(
            "test -e /proc/sys/fs/binfmt_misc/qemu-x86_64 || DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y -qq qemu-user-static binfmt-support >/dev/null"
        )
    smoke_host.run(f"install -d -m 0700 {DOWNLOADS}")
    for name in ("minio", "mc"):
        upload(smoke_host, (binaries / name).read_bytes(), f"{DOWNLOADS}/{name}")
    smoke_host.run(
        "systemd-run --unit=minio-smoke-downloads --property=Type=simple "
        f"python3 -m http.server {SERVE_PORT} --bind 127.0.0.1 --directory {DOWNLOADS} >/dev/null"
    )

    ref = SecretRef("secrets/smoke/minio.yml")
    values = SecretValues(
        ref,
        {
            "root_user": f"smoke-root-{secrets.token_hex(4)}",
            "root_password": f"smoke-pw-{secrets.token_hex(16)}$`'x",
            "console_basic_auth_password": f"smoke-basic-{secrets.token_hex(12)}",
        },
    )
    # ops-control's minio_config() with the smoke host's names and paths.
    cfg = MinioConfig(
        secrets=ref,
        download_url=f"http://127.0.0.1:{SERVE_PORT}/minio",
        mc_download_url=f"http://127.0.0.1:{SERVE_PORT}/mc",
        data_dirs=(DATA,),
        required_mounts=(MOUNT,),
        port_preflight=True,
        expose_via_traefik=True,
        traefik_host=CONSOLE,
        traefik_api_host="s3.example.invalid",
        bootstrap_with_mc=True,
        buckets=(Bucket(name="voxhelm", policy="private"), Bucket(name="backups", versioning=True)),
    )

    # A foreign listener on the API port: the preflight refuses before any change.
    smoke_host.run(
        "systemd-run --unit=minio-smoke-squatter --property=Type=simple "
        "python3 -m http.server 9001 --bind 127.0.0.1 >/dev/null; "
        "for i in $(seq 1 20); do ss -Hltn 'sport = :9001' | grep -q . && break; sleep 0.5; done"
    )
    smoke_host.run(f"install -d {MOUNT} && mount -t tmpfs -o size=512m tmpfs {MOUNT}")
    squatted = deploy(smoke_host, "squatted port", cfg, values)
    smoke_host.run("systemctl stop minio-smoke-squatter")
    # The data volume is not mounted: refused before any change.
    smoke_host.run(f"umount {MOUNT}")
    unmounted = deploy(smoke_host, "unmounted volume", cfg, values)
    smoke_host.run(f"mount -t tmpfs -o size=512m tmpfs {MOUNT}")

    first = deploy(smoke_host, "first run", cfg, values)
    assert first.succeeded, (first.error, [op.name for op in first.ops if not op.succeeded])
    started = pid(smoke_host)
    second = deploy(smoke_host, "second run", cfg, values)
    assert second.succeeded, second.error
    changed = cfg.model_copy(update={"systemd_memory_max": "1G"})
    unit_change = deploy(smoke_host, "unit change", changed, values)
    assert unit_change.succeeded, unit_change.error
    restarted = pid(smoke_host)
    unit_rerun = deploy(smoke_host, "unit change rerun", changed, values)
    assert unit_rerun.succeeded, unit_rerun.error
    return Deployed(
        changed, values, squatted, unmounted, first, second, unit_change, unit_rerun,
        (started, restarted, pid(smoke_host)),
    )  # fmt: skip


def upload(smoke_host: SmokeHost, data: bytes, path: str) -> None:
    """Copy ``data`` to ``path`` on the host (base64 over stdin)."""

    quoted = shlex.quote(path)
    smoke_host.run(f"base64 -d > {quoted} && chmod 0644 {quoted}", input=base64.b64encode(data).decode())


def test_preflight_and_mount_check_refuse_before_any_change(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for run, failing in (
        (deployed.squatted, "Port preflight tcp/9001 tcp/9002"),
        (deployed.unmounted, f"Require {MOUNT} to be mounted"),
    ):
        assert not run.succeeded
        assert next(op.name for op in run.ops if not op.succeeded) == PREFIX + failing
        assert run.mutating_changed_ops == []


def test_first_run_installs_and_second_changes_nothing(smoke_host: SmokeHost, deployed: Deployed) -> None:
    names = {name.removeprefix(PREFIX) for name in deployed.first.mutating_changed_ops}
    assert {
        "Install MinIO /usr/local/bin/minio",
        "Install mc /usr/local/bin/mc",
        "Configure root's mc alias local",
        "Create MinIO bucket voxhelm",
        "Create MinIO bucket backups",
        "Enable versioning on MinIO bucket backups",
        # mc was not installed while planning, so every bucket step ran.
        "Set anonymous access private on MinIO bucket voxhelm",
    } <= names
    for run in (deployed.first, deployed.second, deployed.unit_change, deployed.unit_rerun):
        assert not any("| Probe again: " in op.name for op in run.ops)
    assert "Restart minio.service" not in names
    assert deployed.second.mutating_changed_ops == []


def test_unit_change_restarts_once(smoke_host: SmokeHost, deployed: Deployed) -> None:
    names = {name.removeprefix(PREFIX) for name in deployed.unit_change.mutating_changed_ops}
    assert names == {"Install systemd unit minio.service", "Reload systemd for minio.service", "Restart minio.service"}
    started, restarted, after = deployed.pids
    assert restarted != started
    assert after == restarted
    assert deployed.unit_rerun.mutating_changed_ops == []
    assert smoke_host.out("systemctl show -p MemoryMax --value minio") == str(1024**3)


def test_minio_runs_with_the_roles_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active minio") == "active"
    assert smoke_host.out("systemctl is-enabled minio") == "enabled"
    assert smoke_host.out("stat -c '%a %U %G' /etc/default/minio") == "600 root root"
    assert (
        smoke_host.out("stat -c '%a %U %G' /usr/local/bin/minio /usr/local/bin/mc").splitlines()
        == ["755 root root"] * 2
    )
    assert smoke_host.out(f"stat -c '%a %U %G' {DATA}") == "750 minio minio"
    assert smoke_host.out("stat -c '%a %U %G' /home/minio") == "750 minio minio"
    assert smoke_host.out("getent passwd minio | cut -d: -f6,7") == "/home/minio:/usr/sbin/nologin"
    sockets = smoke_host.out("ss -H -ltn '( sport = :9001 or sport = :9002 )'")
    # MinIO answers on both loopback addresses for 127.0.0.1.
    assert all("127.0.0.1:" in line or "[::1]:" in line for line in sockets.splitlines()), sockets
    assert smoke_host.out("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9001/minio/health/live") == "200"
    buckets = smoke_host.out("mc ls local/ | awk '{print $NF}'").split()
    assert buckets == ["backups/", "voxhelm/"]
    assert '"Enabled"' in smoke_host.out("mc --json version info local/backups")


def test_admin_alias_holds_the_root_credentials_without_a_command_line(
    smoke_host: SmokeHost, deployed: Deployed
) -> None:
    alias = smoke_host.out(
        "python3 -c \"import json; a = json.load(open('/root/.mc/config.json'))['aliases']['local']; "
        "print(a['url'], a['api'], a['path'])\""
    )
    assert alias == "http://127.0.0.1:9001 s3v4 auto"
    smoke_host.run("mc admin info local >/dev/null")


def test_traefik_route_is_the_dual_router(smoke_host: SmokeHost, deployed: Deployed) -> None:
    route = smoke_host.out("cat /etc/traefik/dynamic/minio.yml")
    assert "minio-console-int" in route
    assert "minio-console-ext" in route
    assert "Host(`s3.example.invalid`)" in route
    base = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {CONSOLE}:443:127.0.0.1"
    # Loopback is outside the internal ranges: the public router asks for basic auth.
    assert smoke_host.out(f"{base} https://{CONSOLE}/") == "401"
    password = deployed.values["console_basic_auth_password"]
    assert smoke_host.run(f"{base} -u admin:{shlex.quote(password)} https://{CONSOLE}/").stdout.strip() == "200"


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.values.items():
        found = smoke_host.run(
            "grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root /home/minio /etc/minio /etc/traefik "
            f"--exclude=config.json --exclude-dir={DOWNLOADS.rsplit('/', 1)[1]} || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key


# -- tasks_from: backup_account --------------------------------------------------


@dataclass(frozen=True)
class Account:
    account: BackupAccount
    first: SshRun
    second: SshRun
    rotated: SshRun
    rotated_rerun: SshRun
    secret: SecretStr


@pytest.fixture(scope="module")
def account(smoke_host: SmokeHost, deployed: Deployed) -> Account:
    spec = BackupAccount(name="smoke-target", alias=RunnerAlias(name="backup-smoke-target"))

    def run(label: str, secret: SecretStr) -> SshRun:
        result = run_deploy_ssh(
            deploy_backup_account, spec, secret, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        TIMINGS[f"backup account {label}"] = result.seconds
        assert result.succeeded, (label, result.error, [op.name for op in result.ops if not op.succeeded])
        return result

    secret = SecretStr(f"smoke-account-{secrets.token_hex(12)}")
    first = run("first run", secret)
    second = run("second run", secret)
    rotated_secret = SecretStr(f"smoke-rotated-{secrets.token_hex(12)}")
    rotated = run("rotation", rotated_secret)
    rotated_rerun = run("rotation rerun", rotated_secret)
    return Account(spec, first, second, rotated, rotated_rerun, rotated_secret)


def test_account_is_created_then_converged(account: Account) -> None:
    names = {name.removeprefix(ACCOUNT_PREFIX) for name in account.first.mutating_changed_ops}
    assert names == {
        "Create MinIO policy directory",
        "Install MinIO policy backup-smoke-target",
        "Create or update MinIO policy backup-smoke-target",
        "Create or update MinIO user of smoke-target",
        "Attach MinIO policy backup-smoke-target",
        "Configure mc alias backup-smoke-target of root",
    }
    assert account.second.mutating_changed_ops == []


def test_secret_rotation_upserts_the_user_and_the_alias(account: Account) -> None:
    names = {name.removeprefix(ACCOUNT_PREFIX) for name in account.rotated.mutating_changed_ops}
    assert names == {"Create or update MinIO user of smoke-target", "Configure mc alias backup-smoke-target of root"}
    assert account.rotated_rerun.mutating_changed_ops == []


def test_account_holds_exactly_its_policy(smoke_host: SmokeHost, account: Account) -> None:
    user = json.loads(smoke_host.out(f"mc admin user info --json local {account.account.user}"))
    assert user["policyName"] == "backup-smoke-target"
    assert user["userStatus"] == "enabled"
    assert not user.get("memberOf")
    assert smoke_host.out("stat -c '%a %U' /etc/minio/policies /etc/minio/policies/backup-smoke-target.json").split(
        "\n"
    ) == ["750 root", "640 root"]


def test_scoped_upload_and_download(smoke_host: SmokeHost, account: Account) -> None:
    alias = "backup-smoke-target"
    payload = secrets.token_hex(32)
    smoke_host.run(f"printf %s {payload} > /root/smoke-object")
    smoke_host.run(f"mc cp /root/smoke-object {alias}/backups/smoke-target/archive.txt >/dev/null")
    assert smoke_host.out(f"mc cat {alias}/backups/smoke-target/archive.txt") == payload
    smoke_host.run(f"mc cp {alias}/backups/smoke-target/archive.txt /root/smoke-download >/dev/null")
    assert smoke_host.out("cat /root/smoke-download") == payload
    # Another prefix, the bucket root, another bucket, deleting and the admin API are refused.
    for refused in (
        f"mc cp /root/smoke-object {alias}/backups/other-target/x.txt",
        f"mc ls {alias}/backups/",
        f"mc ls {alias}/voxhelm/",
        f"mc rm {alias}/backups/smoke-target/archive.txt",
        f"mc admin info {alias}",
    ):
        assert smoke_host.run(f"{refused} >/dev/null 2>&1", check=False).returncode != 0, refused
    smoke_host.run("rm -f /root/smoke-object /root/smoke-download")
