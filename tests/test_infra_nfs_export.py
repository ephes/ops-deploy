"""NFS exports on Fractal: config validation, rendered files, fake-host rollout and its restarts."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base.tlshd import CA_PATH, CONFIG_PATH, DROPIN_DIR, DROPIN_PATH, pem, render_config, render_dropin
from ops_deploy.infra import NfsExport, NfsExportClient, NfsExportConfig, deploy_nfs_export
from ops_deploy.infra.nfs_export import (
    NFS_CONF_PATH,
    exports_check_command,
    exports_path,
    render_exports,
    render_nfs_conf,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.nfs_fixtures import CA, KEY, KEY_MARKER, SERVER_CERT, tls

OPTIONS = ("rw", "sync", "no_subtree_check", "no_root_squash", "sec=sys", "xprtsec=mtls")
MEDIA = NfsExport(
    name="media",
    path=PurePosixPath("/fast/media"),
    fsid=1,
    clients=(NfsExportClient(host="192.168.178.94", options=OPTIONS),),
)
# The design's export (docs/MACMINI_MEDIA_ON_FRACTAL.md in ops-control).
CFG = NfsExportConfig(exports=(MEDIA,), tls=tls("server"))
UNITS_BEFORE = "for unit in zfs-share.service remote-fs-pre.target"
NFS_INSTALL = (
    "env NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive "
    "apt-get install -y -q --no-install-recommends nfs-kernel-server"
)
RESTART = "systemctl restart nfs-mountd.service nfs-server.service"


def keep_units() -> dict[str, Any]:
    lines = ["LoadState=loaded", "ActiveState=active", "UnitFileState=enabled", "---"]
    lines += ["LoadState=loaded", "ActiveState=active", "UnitFileState=static", "---"]
    return {UNITS_BEFORE: lines}


def converged(cfg: NfsExportConfig = CFG) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.deb_installed("nfs-kernel-server", "ktls-utils"),
        **fakehost.directory("/etc"),
        **fakehost.directory("/etc/nfs.conf.d"),
        **fakehost.directory("/etc/exports.d"),
        **fakehost.file(NFS_CONF_PATH, render_nfs_conf()),
        **fakehost.service("nfs-server.service"),
    }
    for export in cfg.exports:
        responses.update(fakehost.file(exports_path(export), render_exports(export)))
    if cfg.tls is not None:
        responses.update(
            {
                **fakehost.directory("/etc/tlshd"),
                **fakehost.directory(DROPIN_DIR),
                **fakehost.file(CA_PATH, pem(CA)),
                **fakehost.file("/etc/tlshd/server.pem", pem(SERVER_CERT), mode="-rw-------"),
                **fakehost.file("/etc/tlshd/server.key", pem(KEY), mode="-rw-------"),
                **fakehost.file(CONFIG_PATH, render_config(cfg.tls)),
                **fakehost.file(DROPIN_PATH, render_dropin()),
                **fakehost.service("tlshd.service"),
            }
        )
    return responses


def export_data(options: tuple[str, ...] = ("rw",), **fields: Any) -> dict[str, Any]:
    data = {"name": "media", "path": "/fast/media", "fsid": 1}
    return {**data, "clients": [{"host": "192.168.178.94", "options": list(options)}], **fields}


def config(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "exports": [
            {
                "name": "media",
                "path": "/fast/media",
                "fsid": 1,
                "clients": [{"host": "192.168.178.94", "options": list(OPTIONS)}],
            }
        ],
        "tls": tls("server"),
    }
    data.update(changes)
    return data


def test_exports_line_is_the_designs() -> None:
    assert render_exports(MEDIA) == (
        "# Managed by ops-deploy infra.nfs_export; local changes are overwritten.\n"
        "/fast/media 192.168.178.94(rw,sync,no_subtree_check,no_root_squash,sec=sys,xprtsec=mtls,fsid=1)\n"
    )
    assert exports_path(MEDIA) == "/etc/exports.d/media.exports"


def test_several_clients_share_the_fsid() -> None:
    export = MEDIA.model_copy(
        update={
            "fsid": 7,
            "clients": (
                NfsExportClient(host="192.168.178.94", options=("rw", "sec=sys")),
                NfsExportClient(host="10.0.0.0/24", options=("ro",)),
            ),
        }
    )
    assert render_exports(export).splitlines()[1] == (
        "/fast/media 192.168.178.94(rw,sec=sys,fsid=7) 10.0.0.0/24(ro,fsid=7)"
    )


def test_nfs_conf_turns_manage_gids_off() -> None:
    assert render_nfs_conf().endswith("[mountd]\nmanage-gids=n\n")


@pytest.mark.parametrize(
    "changes",
    [
        {"tls": None},
        {"exports": []},
        {"tls": tls("client")},
    ],
)
def test_invalid_top_level_configs_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        NfsExportConfig.model_validate(config(**changes))


def test_plain_nfs_needs_no_tls() -> None:
    cfg = NfsExportConfig.model_validate(
        config(
            tls=None,
            exports=[export_data(("rw", "xprtsec=none"))],
        )
    )
    assert cfg.tls is None


@pytest.mark.parametrize(
    "export",
    [
        {"name": "Media"},
        {"name": "a/b"},
        {"name": "-media"},
        {"path": "fast/media"},
        {"path": "/"},
        {"path": "/fast/../etc"},
        {"path": "//fast/media"},
        {"path": "/fast/my media"},
        {"fsid": 0},
        {"fsid": "1"},
        {"clients": []},
        {"clients": [{"host": "macmini", "options": ["rw"]}]},
        {"clients": [{"host": "192.168.178.0/16", "options": ["rw"]}]},
        {"clients": [{"host": "2001:db8::1", "options": ["rw"]}]},
        {"clients": [{"host": "192.168.178.94", "options": ["rw", "fsid=3"]}]},
        {"clients": [{"host": "192.168.178.94", "options": ["rw,sync"]}]},
        {"clients": [{"host": "192.168.178.94", "options": ["rw", "rw"]}]},
        {"clients": [{"host": "192.168.178.94", "options": ["rw"]}, {"host": "192.168.178.94", "options": ["ro"]}]},
    ],
)
def test_invalid_exports_are_refused(export: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        NfsExportConfig.model_validate(config(exports=[export_data(**export)]))


@pytest.mark.parametrize("xprtsec", ["xprtsec=tls", "xprtsec=mtls", "xprtsec=none:mtls"])
def test_tls_options_need_tls(xprtsec: str) -> None:
    with pytest.raises(ValidationError, match="needs tls"):
        NfsExportConfig.model_validate(config(tls=None, exports=[export_data(("rw", xprtsec))]))


@pytest.mark.parametrize("field", ["name", "path", "fsid"])
def test_exports_must_differ(field: str) -> None:
    first = export_data(name="a", path="/fast/a", fsid=1)
    second = export_data(name="b", path="/fast/b", fsid=2)
    second[field] = first[field]
    with pytest.raises(ValidationError, match="unique"):
        NfsExportConfig.model_validate(config(tls=None, exports=[first, second]))


def test_fresh_host_plan() -> None:
    run = run_deploy_fake(deploy_nfs_export, CFG, responses={**fakehost.UBUNTU, **keep_units()})

    assert run.succeeded, run.error
    commands = run.executed_commands
    install = commands.index(NFS_INSTALL)
    # zfs-share was enabled before the install; remote-fs-pre.target is static.
    assert commands[install + 1] == "systemctl enable -- zfs-share.service"
    assert run.written(NFS_CONF_PATH) == render_nfs_conf().encode()
    assert run.written("/etc/exports.d/media.exports") == render_exports(MEDIA).encode()
    assert "chmod 644 /etc/exports.d/media.exports" in commands
    tlshd_restart = commands.index("systemctl restart tlshd.service")
    restart = commands.index(RESTART)
    exportfs = commands.index("exportfs -ra")
    assert install < tlshd_restart < restart < exportfs
    assert commands[-1] == exports_check_command(CFG)
    assert dict(run.secret_files)["/etc/tlshd/server.key"] == pem(KEY).encode()
    assert KEY_MARKER not in run.all_text()
    assert not any("sharenfs" in command or command.startswith("zfs ") for command in commands)


def test_converged_host_changes_nothing() -> None:
    run = run_deploy_fake(deploy_nfs_export, CFG, responses=converged())

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    commands = run.executed_commands
    assert RESTART not in commands
    assert "exportfs -ra" not in commands
    assert exports_check_command(CFG) in commands


def test_changed_exports_reexport_without_restart() -> None:
    responses = converged()
    responses.update(fakehost.file("/etc/exports.d/media.exports", "/fast/media 192.168.178.94(rw)\n"))
    run = run_deploy_fake(deploy_nfs_export, CFG, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "exportfs -ra" in commands
    assert RESTART not in commands
    assert run.written_paths == ["/etc/exports.d/media.exports"]


def test_changed_nfs_conf_restarts_mountd_and_server_only() -> None:
    responses = converged()
    responses.update(fakehost.file(NFS_CONF_PATH, "[mountd]\nmanage-gids=y\n"))
    run = run_deploy_fake(deploy_nfs_export, CFG, responses=responses)

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert commands.count(RESTART) == 1
    assert "exportfs -ra" not in commands
    assert "systemctl restart tlshd.service" not in commands


def test_without_tls_no_tlshd() -> None:
    cfg = NfsExportConfig.model_validate(
        config(
            tls=None,
            exports=[export_data(("rw", "sec=sys"))],
        )
    )
    run = run_deploy_fake(deploy_nfs_export, cfg, responses={**fakehost.UBUNTU, **keep_units()})

    assert run.succeeded, run.error
    assert not any("tlshd" in command or "ktls" in command for command in run.executed_commands)


def test_exportfs_check_matches_every_path() -> None:
    cfg = NfsExportConfig.model_validate(
        config(
            tls=None,
            exports=[
                export_data(name="a", path="/fast/a", fsid=1),
                export_data(name="b", path="/fast/b", fsid=2),
            ],
        )
    )
    check = exports_check_command(cfg)
    assert "grep -qxF -- /fast/a" in check
    assert "grep -qxF -- /fast/b" in check
    assert check.startswith("listed=$(exportfs -v | awk '{print $1}') && ")
