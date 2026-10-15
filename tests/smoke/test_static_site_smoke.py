"""Deploy static_site to the smoke target: first run, converged rerun, a content update and a private variant.

The content comes from a throwaway directory; nothing outside the VM's static
site paths is touched.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.services.static_site import StaticSiteConfig, StaticSiteSourceError, deploy_static_site
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "static-smoke.example.invalid"
NAME = "static-smoke"
ROOT = f"/srv/static-sites/{NAME}"
PORT = 10062
MARKER = "static smoke marker"
ALLOWED = ("10.0.0.0/8", "192.168.0.0/16")


@dataclass(frozen=True)
class Deployed:
    cfg: StaticSiteConfig
    first: SshRun
    second: SshRun
    update: SshRun
    pids: tuple[str, str]


def reset(smoke_host: SmokeHost) -> None:
    smoke_host.run(
        f"systemctl disable --now {NAME} 2>/dev/null; rm -rf /etc/systemd/system/{NAME}.service "
        f"/usr/local/libexec/{NAME}-httpd.py {ROOT} /etc/traefik/dynamic/{NAME}.yml; "
        f"userdel {NAME} 2>/dev/null; groupdel {NAME} 2>/dev/null; systemctl daemon-reload; true"
    )


def publish(source: Path, **extra: str) -> None:
    source.mkdir(exist_ok=True)
    for name, text in {
        "index.html": f"<p>{MARKER}</p>\n",
        "report.md": "# r\n",
        "snapshot.json": "{}\n",
        **extra,
    }.items():
        (source / name).write_text(text)


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    source = tmp_path_factory.mktemp("static-site") / "site"
    publish(source)
    cfg = StaticSiteConfig(
        service_name=NAME,
        source_path=source,
        port=PORT,
        traefik_host=HOST,
        traefik_allowed_networks=ALLOWED,
        restrict_to_required_files=True,
        healthcheck_contains=MARKER,
    )
    reset(smoke_host)
    runs = []
    pids: list[str] = []
    for label in ("first", "second", "update"):
        if label == "update":
            publish(source, **{"index.html": f"<p>{MARKER} v2</p>\n"})
            pids.append(smoke_host.out(f"systemctl show -p MainPID --value {NAME}"))
        run = run_deploy_ssh(deploy_static_site, cfg, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"static_site {label} run"] = run.seconds
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    pids.append(smoke_host.out(f"systemctl show -p MainPID --value {NAME}"))
    first, second, update = runs
    return Deployed(cfg, first, second, update, pids=(pids[0], pids[1]))


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert "Deploy static site | Publish site content" in deployed.first.changed_ops
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_content_update_publishes_without_a_restart(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert deployed.update.mutating_changed_ops == ["Deploy static site | Publish site content"]
    before, after = deployed.pids
    assert before == after
    assert "v2" in smoke_host.out(f"curl -fsS http://127.0.0.1:{PORT}/")


def test_service_is_hardened_and_serves_headers_but_no_listing(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"systemctl is-active {NAME}") == "active"
    assert smoke_host.out(f"systemctl is-enabled {NAME}") == "enabled"
    headers = smoke_host.out(f"curl -sI http://127.0.0.1:{PORT}/report.md")
    assert "X-Content-Type-Options: nosniff" in headers
    assert "Cache-Control: no-cache" in headers
    assert smoke_host.out(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{PORT}/missing/") == "404"
    assert smoke_host.out(f"ss -ltn 'sport = :{PORT}' | awk 'NR>1 {{print $4}}'") == f"127.0.0.1:{PORT}"


def test_traefik_serves_and_guards_the_site(smoke_host: SmokeHost, deployed: Deployed) -> None:
    # The smoke client is on 127.0.0.1, outside the allowlist: 403 from the router, no redirect.
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/"
    code = ""
    for _ in range(15):
        code = smoke_host.run(curl, check=False).stdout.strip()
        if code == "403":
            break
        smoke_host.run("sleep 1")
    assert code == "403"


def test_files_have_the_roles_owners_and_modes(smoke_host: SmokeHost, deployed: Deployed) -> None:
    listing = smoke_host.out(
        f"stat -c '%a %U %G %n' {ROOT} {ROOT}/index.html /usr/local/libexec/{NAME}-httpd.py "
        f"/etc/traefik/dynamic/{NAME}.yml"
    ).splitlines()
    assert listing == [
        f"755 root {NAME} {ROOT}",
        f"644 root {NAME} {ROOT}/index.html",
        f"755 root root /usr/local/libexec/{NAME}-httpd.py",
        f"644 root root /etc/traefik/dynamic/{NAME}.yml",
    ]
    assert smoke_host.out(f"getent passwd {NAME} | cut -d: -f6,7") == f"/home/{NAME}:/usr/sbin/nologin"
    assert smoke_host.run(f"test -e /home/{NAME}", check=False).returncode != 0


def test_private_publication_and_strict_source(smoke_host: SmokeHost, deployed: Deployed, tmp_path: Path) -> None:
    source = tmp_path / "site"
    publish(source)
    private = deployed.cfg.model_copy(update={"private": True, "verify_public": False})
    ok = run_deploy_ssh(
        deploy_static_site, private.model_copy(update={"source_path": source}),
        host_name=smoke_host.name, host_data=smoke_host.host_data,
    )  # fmt: skip
    assert ok.succeeded, (ok.error, [op for op in ok.ops if not op.succeeded])
    assert smoke_host.out(f"stat -c '%a' {ROOT} {ROOT}/index.html").splitlines() == ["750", "640"]
    assert smoke_host.out(f"find {ROOT} -perm /o=rwx | wc -l") == "0"
    again = run_deploy_ssh(
        deploy_static_site, private.model_copy(update={"source_path": source}),
        host_name=smoke_host.name, host_data=smoke_host.host_data,
    )  # fmt: skip
    assert again.mutating_changed_ops == []
    # The loopback server (a different user, via the group) still reads it.
    assert MARKER in smoke_host.out(f"curl -fsS http://127.0.0.1:{PORT}/")
    # A source with an extra file is refused before anything changes.
    (source / "extra.txt").write_text("x\n")
    with pytest.raises(StaticSiteSourceError, match="Strict"):
        run_deploy_ssh(
            deploy_static_site, private.model_copy(update={"source_path": source}),
            host_name=smoke_host.name, host_data=smoke_host.host_data,
        )  # fmt: skip
