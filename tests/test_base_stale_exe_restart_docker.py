"""``stale_exe_restart`` against real systemd, nginx, dpkg and apt in an owned Docker container.

Skipped unless ``STALE_EXE_DOCKER_CONTAINER`` holds the full ID of a running
container named ``ops-deploy-stale-exe-*``, labelled
``ops-deploy.fixture=stale-exe-restart``, with no network, not privileged, no
mounts and systemd as PID 1, built from ``debian:trixie`` with ``systemd
systemd-sysv dbus nginx python3``, ``nginx.service`` masked and the installed
nginx ``.deb`` under ``/opt/stale-exe-fixture/debs`` (``docs/base.md``). The
test creates its own units and files in the container and never touches
anything outside it; the Docker CLI is wrapped so that pyinfra can only
inspect, exec and copy into that container.

Like a service's own nginx unit, the fixture ``webapp-nginx.service`` runs
the packaged ``/usr/sbin/nginx`` under its own name and a service account. A
package update is simulated by renaming a copy over the binary (same bytes,
new inode: ``dpkg --verify`` stays clean), and finally by a real ``apt-get
install --reinstall`` of the cached package, which goes through the apt hook.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.base import StaleExeRestartConfig, deploy_stale_exe_restart
from ops_deploy.base.stale_exe_restart import APT_HOOK, CONFIG_PATH, SCRIPT_PATH, STATE_PATH
from ops_deploy.testing.harness import DeployRun, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("STALE_EXE_DOCKER_CONTAINER"), reason="no owned stale_exe_restart Docker container"
)

P = "Stale binary restart | "
FRESH = [
    P + "Ensure /usr/local/libexec/ops-deploy",
    P + f"Install {SCRIPT_PATH}",
    P + "Ensure /etc/ops-deploy",
    P + f"Write {CONFIG_PATH}",
    P + "Install systemd unit stale-exe-restart.service",
    P + "Install systemd unit stale-exe-restart.timer",
    P + "Reload systemd for the stale-exe-restart units",
    P + "Enable and start stale-exe-restart.timer",
    P + f"Write {APT_HOOK}",
]
NGINX = "webapp-nginx.service"
ARGV = ["/usr/sbin/nginx", "-c", "/etc/webapp/nginx.conf", "-g", "daemon off;"]
CFG = StaleExeRestartConfig.model_validate(
    {
        "units": [
            {
                "unit": NGINX,
                "binary": "/usr/sbin/nginx",
                "package": "nginx",
                "test": "nginx",
                "expected_argv": ARGV,
                "http_probe": {"url": "http://127.0.0.1:18080/health", "headers": {"Host": "webapp"}, "status": 204},
            }
        ]
    }
)
NGINX_CONF = """\
worker_processes 2;
pid /run/webapp-nginx/nginx.pid;
error_log /var/log/webapp-nginx/error.log;
events { worker_connections 64; }
http {
    access_log /var/log/webapp-nginx/access.log;
    client_body_temp_path /var/lib/webapp-nginx/body;
    proxy_temp_path /var/lib/webapp-nginx/proxy;
    fastcgi_temp_path /var/lib/webapp-nginx/fastcgi;
    uwsgi_temp_path /var/lib/webapp-nginx/uwsgi;
    scgi_temp_path /var/lib/webapp-nginx/scgi;
    server {
        listen 127.0.0.1:18080;
        location /health { return 204; }
        location / { return 200 "ok"; }
    }
}
"""
# A service's own nginx unit, as a deploy role writes it.
NGINX_UNIT = """\
[Unit]
Description=Fixture nginx run by a service account
After=network.target

[Service]
Type=simple
User=webapp
Group=webapp
PIDFile=/run/webapp-nginx/nginx.pid
RuntimeDirectory=webapp-nginx
RuntimeDirectoryMode=0755
ExecStartPre=/usr/sbin/nginx -t -c /etc/webapp/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/webapp/nginx.conf -g 'daemon off;'
ExecReload=/usr/sbin/nginx -c /etc/webapp/nginx.conf -s reload
ExecStop=/usr/sbin/nginx -c /etc/webapp/nginx.conf -s quit
Restart=on-failure
LimitNOFILE=65536
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
FIXTURE_DIR = "/opt/stale-exe-fixture"
OTHERS = {
    # Maps a copy of a library through LD_PRELOAD; the copy is replaced later.
    "fixture-libholder.service": (
        f"Environment=LD_PRELOAD={FIXTURE_DIR}/lib/libfixture.so.1\nExecStart=/usr/bin/sleep infinity\n"
    ),
    # Runs a copy of sleep; the copy is replaced later.
    "fixture-exeholder.service": f"ExecStart={FIXTURE_DIR}/bin/fixture-sleep infinity\n",
    # Its own mount namespace: skipped by the report.
    "fixture-sandboxed.service": "PrivateTmp=yes\nExecStart=/usr/bin/sleep infinity\n",
}
SETUP = f"""\
set -e
systemctl disable --now stale-exe-restart.timer 2>/dev/null || true
rm -f /etc/systemd/system/stale-exe-restart.service /etc/systemd/system/stale-exe-restart.timer {APT_HOOK}
rm -rf /usr/local/libexec/ops-deploy /etc/ops-deploy /var/lib/ops-deploy
id webapp >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin webapp
install -d -o webapp -g webapp -m 0750 /var/log/webapp-nginx /var/lib/webapp-nginx
install -d -m 0755 /etc/webapp {FIXTURE_DIR}/lib {FIXTURE_DIR}/bin
lib=$(ldconfig -p | awk '/libz\\.so\\.1 /{{print $NF; exit}}')
cp "$lib" {FIXTURE_DIR}/lib/libfixture.so.1
cp /usr/bin/sleep {FIXTURE_DIR}/bin/fixture-sleep
"""


class Container:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["STALE_EXE_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        assert info["Name"].startswith("/ops-deploy-stale-exe-")
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "stale-exe-restart"
        assert info["HostConfig"]["NetworkMode"] == "none"
        assert info["HostConfig"]["Privileged"] is False
        assert not info["Mounts"]
        assert self.out("cat /proc/1/comm") == "systemd"

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([self.binary, *args], capture_output=True, text=True, check=True, timeout=120)

    def sh(self, command: str, *, check: bool = True, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, "exec", self.identifier, "bash", "-c", command],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    def detach(self, argv: list[str]) -> None:
        subprocess.run([self.binary, "exec", "-d", self.identifier, *argv], check=True, timeout=60)

    def out(self, command: str) -> str:
        return self.sh(command).stdout.strip()

    def write(self, path: str, content: str, mode: str = "0644") -> None:
        subprocess.run(
            [
                self.binary,
                "exec",
                "-i",
                self.identifier,
                "sh",
                "-c",
                f"cat > {shlex.quote(path)} && chmod {mode} {path}",
            ],
            input=content,
            text=True,
            check=True,
            timeout=60,
        )

    def guard_connector(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        wrapper = tmp / "docker-guard"
        wrapper.write_text(
            '#!/bin/sh\ncase "$1:$2" in container:inspect|exec:*|cp:*) ;; *) exit 97 ;; esac\nexec '
            + shlex.quote(self.binary)
            + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        monkeypatch.setattr(DockerConnector, "docker_cmd", shlex.quote(str(wrapper)))

    def deploy(self, cfg: StaleExeRestartConfig) -> DeployRun:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        run = DeployRun()
        try:
            connect_all(state)
            assert state.activated_hosts
            add_deploy(state, deploy_stale_exe_restart, cfg)
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, name)
            disconnect_all(state)
        return run

    # -- fixture state ----------------------------------------------------------------
    def setup(self) -> None:
        self.sh(SETUP)
        self.write("/etc/webapp/nginx.conf", NGINX_CONF)
        self.write(f"/etc/systemd/system/{NGINX}", NGINX_UNIT)
        for unit, body in OTHERS.items():
            self.write(f"/etc/systemd/system/{unit}", f"[Service]\nType=simple\n{body}")
        self.sh(f"systemctl daemon-reload && systemctl restart {NGINX} {' '.join(OTHERS)}")
        assert self.out(f"systemctl is-active {NGINX}") == "active"

    def pid(self, unit: str) -> str:
        return self.out(f"systemctl show -p MainPID --value {unit}")

    def exe(self, unit: str) -> str:
        return self.out(f"readlink /proc/$(systemctl show -p MainPID --value {unit})/exe")

    def nginx_current(self) -> bool:
        main = self.pid(NGINX)
        running = self.out(f"stat -L -c %d:%i /proc/{main}/exe")
        return self.exe(NGINX) == "/usr/sbin/nginx" and running == self.out("stat -c %d:%i /usr/sbin/nginx")

    def replace(self, path: str) -> None:
        """A package-style update: a copy renamed over ``path`` (same bytes, new inode)."""

        quoted = shlex.quote(path)
        self.sh(f"cp -p {quoted} {quoted}.new && mv -f {quoted}.new {quoted}")

    def report(self) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(self.out(f"/usr/bin/python3 -I {SCRIPT_PATH} report"))
        return result

    def oneshot(self) -> tuple[int, dict[str, Any]]:
        done = self.sh("systemctl start stale-exe-restart.service", check=False, timeout=600)
        state: dict[str, Any] = json.loads(self.out(f"cat {STATE_PATH}"))
        return done.returncode, state

    def unit_row(self, state: dict[str, Any]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = [row for row in state["units"] if row["unit"] == NGINX]
        assert len(rows) == 1
        return rows[0]


def test_stale_exe_restart_in_a_real_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Container()
    box.guard_connector(tmp_path, monkeypatch)
    box.setup()
    others = {unit: box.pid(unit) for unit in OTHERS}
    nginx = box.pid(NGINX)

    # Run 1 installs everything and restarts nothing; the oneshot never ran.
    first = box.deploy(CFG)
    assert first.succeeded, first.error
    assert first.mutating_changed_ops == FRESH
    assert box.pid(NGINX) == nginx
    assert box.out("systemctl show -p InvocationID --value stale-exe-restart.service") == ""
    assert box.out("systemctl is-active stale-exe-restart.timer") == "active"
    assert box.out("systemctl is-enabled stale-exe-restart.timer") == "enabled"
    assert box.out(f"stat -c '%U:%G %a' {SCRIPT_PATH} {CONFIG_PATH} {APT_HOOK}").split("\n") == [
        "root:root 755",
        "root:root 644",
        "root:root 644",
    ]

    # Run 2 changes nothing.
    second = box.deploy(CFG)
    assert second.succeeded, second.error
    assert second.mutating_changed_ops == []
    assert box.pid(NGINX) == nginx

    # Nothing is stale yet; the sandboxed unit's process is only checked for (deleted) marks.
    report = box.report()
    assert [(row["unit"], row["status"]) for row in report["units"]] == [(NGINX, "current")]
    assert report["report_only"] == []
    assert report["foreign_namespace_pids"] >= 1

    # A package-style update of nginx, the library copy and the sleep copy.
    box.replace("/usr/sbin/nginx")
    box.replace(f"{FIXTURE_DIR}/lib/libfixture.so.1")
    box.replace(f"{FIXTURE_DIR}/bin/fixture-sleep")
    assert box.out("dpkg --verify nginx") == ""
    assert box.exe(NGINX) == "/usr/sbin/nginx (deleted)"
    report = box.report()
    assert report["units"][0]["status"] == "stale"
    assert report["units"][0]["action"] == "test_and_restart"
    assert {row["unit"]: (row["stale_exe"], row["deleted_libs"]) for row in report["report_only"]} == {
        "fixture-exeholder.service": ([f"{FIXTURE_DIR}/bin/fixture-sleep"], []),
        "fixture-libholder.service": ([], ["libfixture.so.1"]),
    }
    assert box.pid(NGINX) == nginx  # report is read-only

    # The oneshot restarts exactly the allowlisted unit, once.
    code, state = box.oneshot()
    assert code == 0, state
    assert box.unit_row(state)["status"] == "restarted"
    assert box.pid(NGINX) != nginx
    assert box.nginx_current()
    assert {unit: box.pid(unit) for unit in OTHERS} == others
    assert state["attempts"][NGINX]["result"] == "restarted"
    assert box.out(f"stat -c %a {STATE_PATH}") == "644"
    assert "webapp-nginx.service: restarting" in box.out("journalctl -u stale-exe-restart.service -o cat --no-pager")

    # Again: current, no restart.
    nginx = box.pid(NGINX)
    code, state = box.oneshot()
    assert code == 0
    assert box.unit_row(state)["status"] == "current"
    assert box.pid(NGINX) == nginx

    # A broken configuration: the test fails, nothing is restarted, the run fails.
    box.replace("/usr/sbin/nginx")
    box.sh("sed -i 's/^http {/http {\\n    bogus_directive on;/' /etc/webapp/nginx.conf")
    code, state = box.oneshot()
    assert code != 0
    assert box.unit_row(state)["status"] == "test_failed"
    assert box.pid(NGINX) == nginx
    assert box.out("systemctl is-failed stale-exe-restart.service") == "failed"

    # Fixed again: the next run restarts it.
    box.write("/etc/webapp/nginx.conf", NGINX_CONF)
    code, state = box.oneshot()
    assert code == 0, state
    assert box.unit_row(state)["status"] == "restarted"
    assert box.nginx_current()

    # A unit file changed on disk but not loaded: refused, not restarted.
    nginx = box.pid(NGINX)
    box.replace("/usr/sbin/nginx")
    box.sh(f"echo '# edited' >> /etc/systemd/system/{NGINX}")
    code, state = box.oneshot()
    assert code != 0
    row = box.unit_row(state)
    assert (row["status"], "NeedDaemonReload" in row["reason"]) == ("refused", True)
    assert box.pid(NGINX) == nginx
    box.write(f"/etc/systemd/system/{NGINX}", NGINX_UNIT)
    box.sh("systemctl daemon-reload")
    code, state = box.oneshot()
    assert code == 0, state
    assert box.unit_row(state)["status"] == "restarted"

    # dpkg busy (its frontend lock held): the run waits until it is free, then acts.
    nginx = box.pid(NGINX)
    box.replace("/usr/sbin/nginx")
    hold = (
        "import fcntl, time; f = open('/var/lib/dpkg/lock-frontend', 'w'); "
        "fcntl.lockf(f, fcntl.LOCK_EX); time.sleep(15)"
    )
    box.detach(["python3", "-c", hold])
    time.sleep(1)
    code, state = box.oneshot()
    assert code == 0, state
    assert state["dpkg_waited_s"] >= 10
    assert box.unit_row(state)["status"] == "restarted"
    assert box.pid(NGINX) != nginx

    # A real package reinstall: the apt hook queues the oneshot, which waits
    # until apt is done and then restarts the unit onto the new inode.
    nginx = box.pid(NGINX)
    checked = state["checked_at"]
    box.sh("apt-get install -y --reinstall -o Dpkg::Options::=--force-confold /opt/stale-exe-fixture/debs/nginx_*.deb")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        latest = json.loads(box.out(f"cat {STATE_PATH}"))
        active = box.out("systemctl show -p ActiveState --value stale-exe-restart.service")
        if latest.get("checked_at") != checked and active in ("inactive", "failed"):
            break
        time.sleep(2)
    else:
        raise AssertionError("the apt hook did not run stale-exe-restart.service")
    assert box.unit_row(latest)["status"] == "restarted", latest
    assert box.pid(NGINX) != nginx
    assert box.nginx_current()
    assert box.out("dpkg --verify nginx") == ""
    assert {unit: box.pid(unit) for unit in OTHERS} == others

    # The deploy still changes nothing.
    final = box.deploy(CFG)
    assert final.succeeded, final.error
    assert final.mutating_changed_ops == []
