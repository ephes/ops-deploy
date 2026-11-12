"""NFS client mount on macmini: validation, rendered units, the sealed mount point, flag on and off."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import NfsClientConfig, NfsClientMount, NfsHostsEntry, deploy_nfs_client_mount
from ops_deploy.base.nfs_client_mount import guard_command, render_docker_dropin, render_unit
from ops_deploy.base.tlshd import (
    CA_PATH,
    CONFIG_PATH,
    DROPIN_DIR,
    DROPIN_PATH,
    pem,
    render_config,
    render_dropin,
    trust_check_command,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.nfs_fixtures import CA, CLIENT_CERT, KEY, KEY_MARKER, tls

UNIT = "mnt-cryptdata-media.mount"
UNIT_PATH = f"/etc/systemd/system/{UNIT}"
DOCKER_DROPIN = "/etc/systemd/system/docker.service.d/mnt-cryptdata-media.conf"
MEDIA = NfsClientMount(
    where=PurePosixPath("/mnt/cryptdata/media"),
    what="192.168.178.116:/fast/media",
    options=("vers=4.2", "hard", "noatime", "nconnect=4", "xprtsec=mtls"),
    requires_mounts_for=(PurePosixPath("/mnt/cryptdata"),),
    order_docker_after=True,
)
HOSTS_ENTRY = NfsHostsEntry(address="192.168.178.116", name="fractal-nfs")
# The design's client (docs/MACMINI_MEDIA_ON_FRACTAL.md in ops-control).
ON = NfsClientConfig(enabled=True, mounts=(MEDIA,), hosts_entries=(HOSTS_ENTRY,), tls=tls("client"))
OFF = ON.model_copy(update={"enabled": False})
HOSTS = "127.0.0.1 localhost\n127.0.1.1 macmini\n::1 ip6-localhost ip6-loopback\n"
PROBE = "findmnt -rn -o FSTYPE,SOURCE --mountpoint"
UNIT_STATE = f"for unit in {UNIT}"
DOCKER_TOUCH = re.compile(
    r"systemctl\s+(?:\S+\s+)*(restart|reload|try-restart|reload-or-restart|stop|start|kill)\b.*docker"
)
WITH_LINE = HOSTS + "192.168.178.116 fractal-nfs\n"
MOUNT_POINT_CHANGE = re.compile(r"\b(chmod|chattr|chown|mkdir|rm|rmdir)\b")


def unit_state(active: str = "inactive", file_state: str = "", load: str = "not-found") -> dict[str, Any]:
    return {UNIT_STATE: [f"LoadState={load}", f"ActiveState={active}", f"UnitFileState={file_state}", "---"]}


def tlshd_converged() -> dict[str, Any]:
    cfg = tls("client")
    return {
        **fakehost.directory("/etc/tlshd"),
        **fakehost.directory(DROPIN_DIR),
        **fakehost.file(CA_PATH, pem(CA)),
        **fakehost.file("/etc/tlshd/client.pem", pem(CLIENT_CERT), mode="-rw-------"),
        **fakehost.file("/etc/tlshd/client.key", pem(KEY), mode="-rw-------"),
        **fakehost.file(CONFIG_PATH, render_config(cfg)),
        **fakehost.file(DROPIN_PATH, render_dropin()),
        **fakehost.service("tlshd.service"),
    }


def macmini(*, hosts: str = HOSTS, verdict: str = "sealed", installed: bool = True) -> dict[str, Any]:
    """Today's macmini: packages, hosts line and tlshd as given, no mount unit yet."""

    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.directory("/etc"),
        **fakehost.file("/etc/hosts", hosts),
        PROBE: [verdict],
        **unit_state(),
        "for unit in zfs-share.service remote-fs-pre.target": [
            *("LoadState=not-found", "ActiveState=inactive", "UnitFileState=", "---"),
            *("LoadState=loaded", "ActiveState=inactive", "UnitFileState=static", "---"),
        ],
    }
    if installed:
        responses.update(fakehost.deb_installed("nfs-common", "ktls-utils"))
        responses.update(tlshd_converged())
    return responses


def mounted(cfg: NfsClientConfig = ON) -> dict[str, Any]:
    """The switched host: unit, drop-in, hosts line and the mount in place."""

    responses = macmini(hosts=WITH_LINE, verdict="mounted-ok")
    responses.update(unit_state("active", "enabled", "loaded"))
    responses.update(fakehost.directory("/etc/systemd/system"))
    responses.update(fakehost.directory("/etc/systemd/system/docker.service.d", mode="drwx------"))
    responses.update(fakehost.file(UNIT_PATH, render_unit(MEDIA, tls=cfg.tls is not None)))
    responses.update(fakehost.file(DOCKER_DROPIN, render_docker_dropin(MEDIA)))
    return responses


def assert_docker_untouched(commands: list[str]) -> None:
    assert not [command for command in commands if DOCKER_TOUCH.search(command)]


def test_unit_is_the_designs_mount() -> None:
    assert render_unit(MEDIA, tls=True) == (
        "# Managed by ops-deploy base.nfs_client_mount; local changes are overwritten.\n"
        "[Unit]\n"
        "Description=NFS 192.168.178.116:/fast/media at /mnt/cryptdata/media\n"
        "Wants=network-online.target tlshd.service\n"
        "After=network-online.target tlshd.service\n"
        "RequiresMountsFor=/mnt/cryptdata\n"
        "\n[Mount]\n"
        "What=192.168.178.116:/fast/media\n"
        "Where=/mnt/cryptdata/media\n"
        "Type=nfs4\n"
        "Options=vers=4.2,hard,noatime,nconnect=4,xprtsec=mtls,_netdev\n"
        "TimeoutSec=90\n"
        "\n[Install]\n"
        "WantedBy=remote-fs.target\n"
    )
    assert MEDIA.unit == UNIT
    assert MEDIA.docker_dropin == DOCKER_DROPIN


def test_plain_unit_has_no_tlshd_and_no_requires_line() -> None:
    plain = NfsClientMount(where=PurePosixPath("/srv/nfs"), what="10.0.0.1:/x", options=("vers=4.2",), timeout_sec=30)
    text = render_unit(plain, tls=False)
    assert "Wants=network-online.target\nAfter=network-online.target\n\n[Mount]" in text
    assert "tlshd" not in text
    assert "RequiresMountsFor" not in text
    assert "Options=vers=4.2,_netdev\nTimeoutSec=30\n" in text


def test_docker_dropin_is_ordering_only() -> None:
    assert render_docker_dropin(MEDIA).endswith("[Unit]\nAfter=mnt-cryptdata-media.mount\n")
    assert "Requires" not in render_docker_dropin(MEDIA)


@pytest.mark.parametrize(
    "mount",
    [
        {"where": "mnt/media"},
        {"where": "/"},
        {"where": "/mnt/crypt-data/media"},
        {"where": "/.hidden/media"},
        {"where": "/mnt/../etc"},
        {"what": "fractal:/fast/media"},
        {"what": "192.168.178.116"},
        {"what": "192.168.178.116:fast/media"},
        {"what": "192.168.178.300:/fast/media"},
        {"options": ("vers=4.2", "_netdev")},
        {"options": ("vers=4.2,hard",)},
        {"options": ("hard", "hard")},
        {"requires_mounts_for": ("relative",)},
        {"timeout_sec": 0},
    ],
)
def test_invalid_mounts_are_refused(mount: dict[str, Any]) -> None:
    data = {**MEDIA.model_dump(), **mount}
    with pytest.raises(ValidationError):
        NfsClientMount.model_validate(data)


@pytest.mark.parametrize(
    "changes",
    [
        {"tls": None},
        {"tls": tls("server")},
        {"mounts": (MEDIA, MEDIA)},
        {"hosts_entries": (HOSTS_ENTRY, NfsHostsEntry(address="192.168.178.116", name="other"))},
        {"hosts_entries": (HOSTS_ENTRY, NfsHostsEntry(address="192.168.178.117", name="fractal-nfs"))},
    ],
)
def test_inconsistent_configs_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        NfsClientConfig.model_validate({**dict(ON), **changes})


@pytest.mark.parametrize(("address", "name"), [("fractal", "x"), ("192.168.178.116", "bad name"), ("10.0.0.01", "x")])
def test_invalid_hosts_entries_are_refused(address: str, name: str) -> None:
    with pytest.raises(ValidationError):
        NfsHostsEntry(address=address, name=name)


def test_enabled_is_required() -> None:
    with pytest.raises(ValidationError):
        NfsClientConfig.model_validate({"mounts": ()})


def test_flag_on_fresh_host_installs_then_checks_the_seal_before_starting() -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, ON, responses=macmini(installed=False))

    assert run.succeeded, run.error
    commands = run.executed_commands
    install = commands.index(
        "env NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive "
        "apt-get install -y -q --no-install-recommends nfs-common"
    )
    # remote-fs-pre.target is static on macmini and zfs-share does not exist: nothing to re-enable.
    assert not any(command.startswith("systemctl enable -- zfs-share") for command in commands)
    hosts = next(n for n, c in enumerate(commands) if "fractal-nfs" in c and ">> /etc/hosts" in c)
    tlshd = commands.index("systemctl restart tlshd.service")
    reload = commands.index("systemctl daemon-reload", tlshd)
    enable = commands.index(f"systemctl enable -- {UNIT}")
    guard = commands.index(guard_command(MEDIA))
    start = commands.index(f"systemctl start -- {UNIT}")
    assert install < hosts < tlshd < reload < enable < guard < start
    assert run.written(UNIT_PATH) == render_unit(MEDIA, tls=True).encode()
    assert run.written(DOCKER_DROPIN) == render_docker_dropin(MEDIA).encode()
    assert_docker_untouched(commands)
    assert KEY_MARKER not in run.all_text()
    # The mount point itself is never touched.
    assert not [c for c in commands if "/mnt/cryptdata/media" in c and MOUNT_POINT_CHANGE.search(c)]


def test_flag_on_converged_and_mounted_changes_nothing() -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, ON, responses=mounted())

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert f"systemctl start -- {UNIT}" not in run.executed_commands
    assert guard_command(MEDIA) not in run.executed_commands


def test_changed_unit_reloads_but_never_remounts_or_touches_docker() -> None:
    responses = mounted()
    responses.update(fakehost.file(UNIT_PATH, "[Mount]\n"))
    responses.update(fakehost.file(DOCKER_DROPIN, "[Unit]\n"))
    run = run_deploy_fake(deploy_nfs_client_mount, ON, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "systemctl daemon-reload" in commands
    assert not any(UNIT in command and ("start" in command or "restart" in command) for command in commands)
    assert_docker_untouched(commands)


def test_without_docker_ordering_the_dropin_is_removed() -> None:
    mount = MEDIA.model_copy(update={"order_docker_after": False})
    cfg = ON.model_copy(update={"mounts": (mount,)})
    responses = mounted(cfg)
    run = run_deploy_fake(deploy_nfs_client_mount, cfg, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert f"rm -f {DOCKER_DROPIN}" in commands
    assert "systemctl daemon-reload" in commands
    assert_docker_untouched(commands)


@pytest.mark.parametrize(
    "verdict",
    [
        "refuse not empty",
        "refuse mode 755",
        "refuse mode 2000",
        "refuse not immutable",
        "refuse owner root:media",
        "refuse symlink",
        "refuse not a directory",
        "refuse mount point",
        "refuse mounted: ext4 /dev/mapper/cryptdata",
        "refuse mounted: nfs4 192.168.178.116:/fast/other",
        "",
    ],
)
def test_unsealed_mount_point_refuses_the_whole_deploy(verdict: str) -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, ON, responses=macmini(verdict=verdict))

    assert not run.succeeded
    assert "not a sealed mount point" in str(run.error)
    assert verdict in str(run.error)
    assert run.executed_commands == []


def test_flag_off_on_a_host_that_never_had_the_mount_changes_nothing() -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, OFF, responses=macmini(hosts=WITH_LINE))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.executed_commands == [trust_check_command()]


def test_flag_off_does_not_need_a_sealed_mount_point() -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, OFF, responses=macmini(verdict="refuse owner root:media"))

    assert run.succeeded, run.error
    assert not any("findmnt" in command for command in run.fact_commands)


def test_flag_off_still_deploys_packages_hosts_and_tlshd() -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, OFF, responses=macmini(installed=False))

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert any(command.endswith("--no-install-recommends nfs-common") for command in commands)
    assert any("'192.168.178.116 fractal-nfs' >> /etc/hosts" in command for command in commands)
    assert "systemctl restart tlshd.service" in commands
    assert UNIT_PATH not in run.written_paths


def test_flag_off_stops_disables_and_removes() -> None:
    responses = mounted()
    run = run_deploy_fake(deploy_nfs_client_mount, OFF, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    stop = commands.index(f"systemctl stop -- {UNIT}")
    disable = commands.index(f"systemctl disable -- {UNIT}")
    remove_unit = commands.index(f"rm -f {UNIT_PATH}")
    remove_dropin = commands.index(f"rm -f {DOCKER_DROPIN}")
    reload = commands.index("systemctl daemon-reload")
    assert stop < disable < remove_unit < remove_dropin < reload
    assert_docker_untouched(commands)
    assert not [c for c in commands if re.search(r"\b(chmod|chattr|rmdir)\b.*/mnt/cryptdata/media", c)]


def test_existing_hosts_line_is_kept() -> None:
    commented = fakehost.file("/etc/hosts", HOSTS + "192.168.178.116  fractal-nfs  # nfs\n")
    run = run_deploy_fake(deploy_nfs_client_mount, ON, responses=mounted() | commented)

    assert run.succeeded, run.error
    assert not any("/etc/hosts" in command for command in run.executed_commands)


@pytest.mark.parametrize(
    "line",
    ["192.168.178.116 fractal", "192.168.178.116 fractal-nfs fractal", "10.0.0.5 fractal-nfs"],
)
def test_a_foreign_hosts_line_is_never_rewritten(line: str) -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, ON, responses=macmini(hosts=HOSTS + line + "\n"))

    assert not run.succeeded
    assert "/etc/hosts already" in str(run.error)
    assert run.executed_commands == []


def test_hosts_append_keeps_a_missing_final_newline_apart() -> None:
    run = run_deploy_fake(deploy_nfs_client_mount, OFF, responses=macmini())

    append = next(command for command in run.executed_commands if ">> /etc/hosts" in command)
    assert append == (
        "grep -qxF -- '192.168.178.116 fractal-nfs' /etc/hosts || "
        '{ [ -z "$(tail -c 1 /etc/hosts)" ] || echo >> /etc/hosts; '
        "echo '192.168.178.116 fractal-nfs' >> /etc/hosts; }"
    )


def test_flag_off_never_stops_a_mount_it_did_not_render() -> None:
    """A hand-made mount at ``where`` shows as an active unit without our unit file."""

    responses = macmini(hosts=WITH_LINE, verdict="mounted-ok")
    responses.update(unit_state("active", "", "loaded"))
    run = run_deploy_fake(deploy_nfs_client_mount, OFF, responses=responses)

    assert run.succeeded, run.error
    assert not [c for c in run.executed_commands if f"systemctl stop -- {UNIT}" in c]
    assert not [c for c in run.executed_commands if f"systemctl disable -- {UNIT}" in c]


def test_probe_requires_the_configured_transport_security() -> None:
    from ops_deploy.base.nfs_client_mount import seal_probe

    probe = seal_probe(MEDIA)
    assert "*,xprtsec=mtls,*" in probe
    assert "refuse mounted" in probe
