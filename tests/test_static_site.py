"""Deploy-level scenarios for static_site against the fake connector."""

import os
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.services.static_site import StaticSiteConfig, StaticSiteSourceError, deploy_static_site, validate_source
from ops_deploy.services.static_site.deploy import render_route, render_server, render_unit
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.metrics_httpd_fixtures import verify_op
from tests.static_site_fixtures import make_source

HOST = "static.test.example"
HOST_DATA = {"ssh_hostname": "site.example.invalid", "ssh_user": "root"}
UNIT = "/etc/systemd/system/static-site.service"
ROUTE = "/etc/traefik/dynamic/static-site.yml"
SERVER = "/usr/local/libexec/static-site-httpd.py"
ROOT = "/srv/static-sites/static-site"
ITEMIZED = [">f+++++++++ index.html"]
READ_ONLY = [
    "Deploy static site | Check loopback static service",
    verify_op("Deploy static site | ", "static-site"),
]


@pytest.fixture
def cfg(tmp_path: Path) -> StaticSiteConfig:
    return StaticSiteConfig(source_path=make_source(tmp_path), traefik_host=HOST)


def converged(
    cfg: StaticSiteConfig, *, drift: dict[str, str] | None = None, user_shell: str = "/usr/sbin/nologin"
) -> dict[str, Any]:
    content = {
        UNIT: render_unit(cfg),
        ROUTE: render_route(cfg),
        SERVER: render_server(cfg),
        **(drift or {}),
    }
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account(cfg.user, f"/home/{cfg.user}", shell=user_shell),
        **fakehost.directory(str(cfg.site_path.parent)),
        **fakehost.directory("/usr/local/libexec"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.stat(str(cfg.site_path), group=cfg.group_name, mode="drwxr-xr-x"),
        **fakehost.service(f"{cfg.service_name}.service"),
    }
    for path, text in content.items():
        responses.update(fakehost.file(path, text, mode="-rwxr-xr-x" if path == SERVER else "-rw-r--r--"))
    return responses


def deploy(
    cfg: StaticSiteConfig, responses: dict[str, Any] | None = None, rsync: RecordingRsyncRunner | None = None
) -> FakeRun:
    run = run_deploy_fake(
        deploy_static_site,
        cfg,
        rsync=rsync or RecordingRsyncRunner(),
        responses=responses or dict(fakehost.LINUX),
        host_data=HOST_DATA,
    )
    assert run.succeeded, run.error
    return run


def test_first_run_installs_everything(cfg: StaticSiteConfig) -> None:
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED})
    run = deploy(cfg, rsync=rsync)

    commands = run.executed_commands
    assert "useradd -d /home/static-site -s /usr/sbin/nologin -g static-site -r -M static-site" in commands
    assert run.upload(UNIT).decode() == render_unit(cfg)
    assert run.upload(ROUTE).decode() == render_route(cfg)
    assert run.upload(SERVER).decode() == render_server(cfg)
    assert any("systemctl daemon-reload" in c for c in commands)
    assert any("systemctl start static-site.service" in c for c in commands)
    # Started by this run: no restart on top. Traefik picks the route up itself.
    assert not any("systemctl restart static-site.service" in c for c in commands)
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    assert "Deploy static site | Publish site content" in run.changed_ops
    (real,) = [argv for argv in rsync.calls if "--dry-run" not in argv]
    assert "--chown=root:static-site" in real
    assert "--chmod=D0755,F0644" in real
    assert "--delete" in real
    assert real[-1] == "root@site.example.invalid:/srv/static-sites/static-site/"


def test_second_run_changes_nothing(cfg: StaticSiteConfig) -> None:
    run = deploy(cfg, converged(cfg))

    assert run.mutating_changed_ops == []
    assert [op for op in run.changed_ops if op not in READ_ONLY] == []
    assert run.uploaded_paths == []


def test_content_change_publishes_without_restarting(cfg: StaticSiteConfig) -> None:
    run = deploy(cfg, converged(cfg), rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED}))

    assert run.mutating_changed_ops == ["Deploy static site | Publish site content"]


def test_server_script_change_restarts(cfg: StaticSiteConfig) -> None:
    run = deploy(cfg, converged(cfg, drift={SERVER: "#!/usr/bin/env python3\n"}))

    assert sorted(run.mutating_changed_ops) == [
        "Deploy static site | Install static HTTP server",
        "Deploy static site | Restart static-site.service",
    ]


def test_unit_change_reloads_and_restarts(cfg: StaticSiteConfig) -> None:
    run = deploy(cfg, converged(cfg, drift={UNIT: "[Service]\nExecStart=/old\n"}))

    assert sorted(run.mutating_changed_ops) == [
        "Deploy static site | Install systemd unit static-site.service",
        "Deploy static site | Reload systemd for static-site.service",
        "Deploy static site | Restart static-site.service",
    ]


def test_route_change_restarts_nothing(cfg: StaticSiteConfig) -> None:
    run = deploy(cfg, converged(cfg, drift={ROUTE: "http: {}\n"}))

    assert run.mutating_changed_ops == ["Deploy static site | Write Traefik route static-site"]


def test_private_publication_demands_private_modes_and_checks_them(tmp_path: Path) -> None:
    cfg = StaticSiteConfig(source_path=make_source(tmp_path), traefik_host=HOST, private=True)
    rsync = RecordingRsyncRunner(responses={"--dry-run": ITEMIZED})
    run = deploy(cfg, rsync=rsync)

    assert any("chmod 750 /srv/static-sites/static-site" in c for c in run.executed_commands)
    assert all("--chmod=D0750,F0640" in argv for argv in rsync.calls)
    assert "Deploy static site | Check private publication modes" in run.changed_ops
    assert any("perm /o=rwx" in c for c in run.executed_commands)


def test_public_probe_only_when_requested(cfg: StaticSiteConfig) -> None:
    quiet = deploy(cfg, converged(cfg))
    verified = deploy(
        cfg.model_copy(update={"verify_public": True, "healthcheck_contains": "benchpack registry snapshot"}),
        converged(cfg),
    )

    assert not any(f"https://{HOST}/" in c for c in quiet.executed_commands)
    public = [c for c in verified.executed_commands if f"https://{HOST}/" in c]
    assert len(public) == 1
    assert "seq 1 20" in public[0]
    assert "benchpack registry snapshot" in public[0]
    assert verified.mutating_changed_ops == []


def test_traefik_disabled_writes_no_route(tmp_path: Path) -> None:
    cfg = StaticSiteConfig(source_path=make_source(tmp_path), traefik_enabled=False)
    run = deploy(cfg, rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED}))

    assert ROUTE not in run.written_paths
    assert not any("traefik" in c for c in run.executed_commands)


def test_existing_user_is_left_alone(cfg: StaticSiteConfig) -> None:
    run = deploy(cfg, converged(cfg, user_shell="/bin/bash"))

    assert run.mutating_changed_ops == []
    assert not any("usermod" in c or "useradd" in c for c in run.executed_commands)


def test_invalid_source_fails_before_any_operation(tmp_path: Path) -> None:
    cfg = StaticSiteConfig(source_path=tmp_path / "missing", traefik_host=HOST)
    with pytest.raises(StaticSiteSourceError, match="missing, not a directory"):
        run_deploy_fake(deploy_static_site, cfg, rsync=RecordingRsyncRunner(), responses=dict(fakehost.LINUX))


def test_source_checks(tmp_path: Path) -> None:
    def cfg_for(source: Path, **kw: Any) -> StaticSiteConfig:
        return StaticSiteConfig(source_path=source, traefik_host=HOST, **kw)

    good = make_source(tmp_path)
    validate_source(cfg_for(good))

    # A missing or non-regular required file.
    (good / "report.md").unlink()
    with pytest.raises(StaticSiteSourceError, match=r"report\.md"):
        validate_source(cfg_for(good))
    (good / "report.md").mkdir()
    with pytest.raises(StaticSiteSourceError, match=r"report\.md"):
        validate_source(cfg_for(good))
    (good / "report.md").rmdir()
    (good / "report.md").write_text("x\n")

    # Symlinks, also hidden and nested ones.
    (good / "sub").mkdir()
    (good / "sub" / ".hidden").symlink_to("/etc/passwd")
    with pytest.raises(StaticSiteSourceError, match="symbolic links"):
        validate_source(cfg_for(good))
    (good / "sub" / ".hidden").unlink()
    validate_source(cfg_for(good))

    # Strict mode: nested directories and extra files are refused.
    with pytest.raises(StaticSiteSourceError, match="Strict"):
        validate_source(cfg_for(good, restrict_to_required_files=True))
    (good / "sub").rmdir()
    (good / "extra.txt").write_text("x\n")
    with pytest.raises(StaticSiteSourceError, match="Strict"):
        validate_source(cfg_for(good, restrict_to_required_files=True))
    validate_source(cfg_for(good))
    (good / "extra.txt").unlink()
    validate_source(cfg_for(good, restrict_to_required_files=True))

    # A symlinked source root and a FIFO.
    link = tmp_path / "link"
    link.symlink_to(good)
    with pytest.raises(StaticSiteSourceError, match="symlink"):
        validate_source(cfg_for(link))
    os.mkfifo(good / "pipe")
    with pytest.raises(StaticSiteSourceError, match="socket, FIFO"):
        validate_source(cfg_for(good))


def test_config_defaults_follow_the_service_name(tmp_path: Path) -> None:
    cfg = StaticSiteConfig(service_name="benchmarks-static", source_path=make_source(tmp_path), traefik_host=HOST)

    assert cfg.user == "benchmarks-static"
    assert cfg.group_name == "benchmarks-static"
    assert str(cfg.site_path) == "/srv/static-sites/benchmarks-static"
    assert str(cfg.server_path) == "/usr/local/libexec/benchmarks-static-httpd.py"


def test_config_rejects_bad_inputs(tmp_path: Path) -> None:
    base: dict[str, Any] = {"source_path": make_source(tmp_path), "traefik_host": HOST}
    StaticSiteConfig(**base)
    for bad in (
        {"service_name": "Bad_Name"},
        {"source_path": Path("relative/site")},
        {"source_path": Path("/")},
        {"source_path": Path("/tmp/with space")},
        {"site_path": Path("/srv/../etc")},
        {"bind_host": "0.0.0.0"},
        {"port": 80},
        {"required_files": ()},
        {"required_files": ("../etc/passwd",)},
        {"traefik_host": None},
        {"traefik_host": "static.example.com"},
        {"traefik_entrypoints": ()},
        {"traefik_http_entrypoint": "web-secure"},
        {"traefik_allowed_networks": ("10.0.0.1/8",)},
        {"traefik_allowed_networks": ("10.0.0.0",)},
        {"traefik_allowed_networks": ("10.0.0.0/255.0.0.0",)},
        {"traefik_cert_resolver": "a b"},
        {"public_healthcheck_retries": 0},
    ):
        with pytest.raises(ConfigValidationError):
            StaticSiteConfig(**{**base, **bad})
    # Without ingress no hostname is needed.
    StaticSiteConfig(source_path=base["source_path"], traefik_enabled=False)
