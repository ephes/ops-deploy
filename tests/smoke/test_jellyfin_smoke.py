"""Deploy jellyfin to the smoke target: fresh install, converged rerun, password rotation, keyring repair.

Installs Jellyfin from the real upstream repository (network access needed).
Media directories, their group and the route host are throwaway names; the
reset purges the Jellyfin packages so the first run starts from scratch.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import pytest
from pydantic import SecretStr

from ops_deploy.helpers import BasicAuth
from ops_deploy.services.jellyfin import JellyfinConfig, deploy_jellyfin
from ops_deploy.services.jellyfin.deploy import repository_line
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "jellyfin-smoke.example.invalid"
GROUP = "jfsmoke-media"
MEDIA_ROOT = "/srv/jellyfin-smoke"
MEDIA = (f"{MEDIA_ROOT}/video/movies", f"{MEDIA_ROOT}/video/tv")
FOREIGN = f"{MEDIA_ROOT}/video/youtube"
KEYRING = "/usr/share/keyrings/jellyfin-archive-keyring.gpg"
LIST = "/etc/apt/sources.list.d/jellyfin.list"
ROUTE = "/etc/traefik/dynamic/jellyfin.yml"
P = "Deploy Jellyfin | "
READ_ONLY = [
    f"{P}Require the mount /boot",
    f"{P}Wait for Jellyfin port to be open",
    f"{P}Perform Jellyfin HTTP health check",
]


@dataclass(frozen=True)
class Deployed:
    cfg: JellyfinConfig
    password: str
    runs: dict[str, SshRun]
    route_stat: tuple[str, str]
    pids: tuple[str, str]


def reset(smoke_host: SmokeHost) -> None:
    smoke_host.run(
        "systemctl disable --now jellyfin 2>/dev/null; "
        "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q 'jellyfin*' >/dev/null 2>&1; "
        f"rm -rf {KEYRING} {LIST} {ROUTE} {MEDIA_ROOT} /var/lib/jellyfin /etc/jellyfin /var/log/jellyfin; "
        f"groupadd -f {GROUP}; install -d -m 0700 {FOREIGN}; apt-get update -q >/dev/null; true"
    )


def deploy(smoke_host: SmokeHost, cfg: JellyfinConfig, password: str, label: str) -> SshRun:
    auth = BasicAuth(user="admin", password=SecretStr(password))
    run = run_deploy_ssh(deploy_jellyfin, cfg, auth, host_name=smoke_host.name, host_data=smoke_host.host_data)
    TIMINGS[f"jellyfin {label} run"] = run.seconds
    assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
    return run


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost) -> Deployed:
    arch = smoke_host.out("dpkg --print-architecture")
    cfg = JellyfinConfig(
        repo_distro="ubuntu",
        repo_release=smoke_host.out(". /etc/os-release && echo $VERSION_CODENAME"),
        repo_arch=arch,
        traefik_host=HOST,
        media_directories=MEDIA,
        media_dir_group=GROUP,
        media_dir_mode="02775",
        mounts_required=("/boot",),
    )
    reset(smoke_host)
    password = secrets.token_urlsafe(24)
    runs = {"first": deploy(smoke_host, cfg, password, "first")}
    route_before = smoke_host.out(f"stat -c '%Y %i' {ROUTE}")
    pid_before = smoke_host.out("systemctl show -p MainPID --value jellyfin")
    runs["second"] = deploy(smoke_host, cfg, password, "second")
    route_after = smoke_host.out(f"stat -c '%Y %i' {ROUTE}")
    pid_after = smoke_host.out("systemctl show -p MainPID --value jellyfin")
    rotated = secrets.token_urlsafe(24)
    runs["rotated"] = deploy(smoke_host, cfg, rotated, "rotated")
    # An armored keyring (what a hand-made `curl > keyring` leaves) is repaired.
    smoke_host.run(f"gpg --enarmor < {KEYRING} > {KEYRING}.asc && mv {KEYRING}.asc {KEYRING}")
    runs["keyring"] = deploy(smoke_host, cfg, rotated, "keyring")
    runs["converged"] = deploy(smoke_host, cfg, rotated, "converged")
    return Deployed(cfg, rotated, runs, (route_before, route_after), (pid_before, pid_after))


def test_first_run_installs_and_second_run_changes_nothing(deployed: Deployed) -> None:
    first = deployed.runs["first"].mutating_changed_ops
    assert f"{P}Install Jellyfin repository key" in first
    assert f"{P}Install Jellyfin packages" in first
    assert f"{P}Install the first available Jellyfin ffmpeg package" in first
    assert deployed.runs["second"].mutating_changed_ops == []
    assert deployed.runs["second"].changed_ops == READ_ONLY
    assert deployed.route_stat[0] == deployed.route_stat[1]
    assert deployed.pids[0] == deployed.pids[1]


def test_rotation_rewrites_only_the_route(deployed: Deployed) -> None:
    assert deployed.runs["rotated"].mutating_changed_ops == [f"{P}Write Traefik route jellyfin"]


def test_armored_keyring_is_repaired_then_converged(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert deployed.runs["keyring"].mutating_changed_ops == [
        f"{P}Install Jellyfin repository key",
        f"{P}Update apt cache",
        f"{P}Install the first available Jellyfin ffmpeg package",
    ]
    assert deployed.runs["converged"].mutating_changed_ops == []
    assert smoke_host.out(f"head -c 5 {KEYRING} | grep -c -- ----- || true") == "0"
    assert smoke_host.out(f"stat -c '%U:%G %a' {KEYRING}") == "root:root 644"


def test_repository_packages_and_service(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.run(f"cat {LIST}").stdout == repository_line(deployed.cfg)
    assert smoke_host.out(f"stat -c '%U:%G %a' {LIST}") == "root:root 644"
    status = smoke_host.out("dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'jellyfin*' apache2-utils")
    installed = {line.split()[0] for line in status.splitlines() if line.split()[1:2] == ["ii"]}
    assert {"jellyfin", "apache2-utils"} <= installed
    assert any(name.startswith("jellyfin-ffmpeg") for name in installed)
    assert smoke_host.out("systemctl is-active jellyfin") == "active"
    assert smoke_host.out("systemctl is-enabled jellyfin") == "enabled"
    for path in ("/var/lib/jellyfin", "/etc/jellyfin", "/var/log/jellyfin"):
        assert smoke_host.out(f"stat -c '%U:%G %a' {path}") == "jellyfin:jellyfin 750"


def test_media_dirs_are_setgid_and_the_foreign_dir_is_untouched(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for path in MEDIA:
        assert smoke_host.out(f"stat -c '%U:%G %a' {path}") == f"root:{GROUP} 2775"
    assert smoke_host.out(f"stat -c '%U:%G %a' {FOREIGN}") == "root:root 700"


def test_traefik_asks_outside_clients_for_basic_auth(smoke_host: SmokeHost, deployed: Deployed) -> None:
    base = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/"
    code = ""
    for _ in range(15):
        code = smoke_host.run(base, check=False).stdout.strip()
        if code == "401":
            break
        smoke_host.run("sleep 1")
    assert code == "401"  # 127.0.0.1 is outside the role's internal ranges
    authed = smoke_host.run(f"{base} -K -", input=f'user = "admin:{deployed.password}"\n').stdout.strip()
    assert authed in ("200", "301", "302", "307", "308")
