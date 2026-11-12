"""nfs_tls_status: config, the exporter on fixtures, the json-metrics rules and the deploys' plans."""

from __future__ import annotations

import json
import operator
import os
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services.nfs_tls_status import (
    PASSWORD_KEY,
    NfsTlsStatusCheckConfig,
    NfsTlsStatusConfig,
    deploy_nfs_tls_status,
    deploy_nfs_tls_status_check,
    status_id,
)
from ops_deploy.services.nfs_tls_status import deploy as nts
from ops_deploy.services.os_lifecycle.deploy import HTTPD_SCRIPT
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.metrics_httpd_fixtures import verify_op, without_switch

PASSWORD = "fixture-endpoint-password"
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: PASSWORD})
TAILSCALE_IP = "100.64.0.7"
SOURCE = "192.0.2.10:/fast/media"
MOUNT: dict[str, Any] = {
    "where": "/mnt/cryptdata/media",
    "source": SOURCE,
    "required_options": ["xprtsec=mtls"],
    "unit": "mnt-cryptdata-media.mount",
}
CLIENT_CERTS = ["/etc/tlshd/client.pem", "/etc/tlshd/nfs-ca.pem"]


CHECK_FIELDS: dict[str, Any] = {
    "service_name": "x",
    "name": "y",
    "check_interval": 60,
    "data": {"url": "http://192.0.2.1:9109/.well-known/nfs-tls", "checks": [{}]},
}


def server_cfg(**changes: Any) -> NfsTlsStatusConfig:
    fields: dict[str, Any] = {
        "secrets": "secrets/fixture.yml",
        "port": 9109,
        "units": ["nfs-server.service", "tlshd.service"],
        "certificates": ["/etc/tlshd/server.pem", "/etc/tlshd/nfs-ca.pem"],
    }
    return NfsTlsStatusConfig.model_validate({**fields, **changes})


def client_cfg(**changes: Any) -> NfsTlsStatusConfig:
    fields: dict[str, Any] = {
        "secrets": "secrets/fixture.yml",
        "port": 9109,
        "units": ["tlshd.service"],
        "mounts": [MOUNT],
        "certificates": CLIENT_CERTS,
    }
    return NfsTlsStatusConfig.model_validate({**fields, **changes})


# -- config --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("nfs-server.service", "nfs_server_service"),
        ("mnt-cryptdata-media.mount", "mnt_cryptdata_media_mount"),
        ("/mnt/cryptdata/media", "mnt_cryptdata_media"),
        ("/etc/tlshd/nfs-ca.pem", "etc_tlshd_nfs_ca_pem"),
        ("Odd--Name.Service", "odd_name_service"),
    ],
)
def test_report_keys_are_plain_jsonpath_names(text: str, key: str) -> None:
    assert status_id(text) == key


def test_defaults() -> None:
    cfg = client_cfg()

    assert (cfg.service_name, cfg.user, cfg.auth_user, cfg.path) == (
        "nfs-tls-status-endpoint",
        "metrics",
        "nyxmon",
        "/.well-known/nfs-tls",
    )
    assert str(cfg.json_path) == "/var/lib/nfs-tls-status/status.json"
    assert cfg.bind == "tailscale"
    assert (cfg.timer_interval, cfg.warn_days, cfg.max_age_seconds) == (300, 60, 900)
    assert cfg.mounts[0].fstype == "nfs4"
    assert cfg.httpd_impl == "python"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"port": None}, "port"),
        ({"secrets": None}, "secrets file"),
        ({"units": ["tlshd"]}, "units"),
        ({"units": ["tlshd.service;reboot"]}, "units"),
        ({"units": ["tlshd.service", "TLSHD.service"]}, "distinct report keys"),
        ({"units": ["1tlshd.service"]}, "starting with a letter"),
        ({"certificates": ["/etc/tlshd/a-b.pem", "/etc/tlshd/a_b.pem"]}, "distinct report keys"),
        ({"certificates": ["relative.pem"]}, "certificates"),
        ({"mounts": [MOUNT, MOUNT]}, "distinct report keys"),
        ({"mounts": [{**MOUNT, "required_options": ["a,b"]}]}, "required_options"),
        ({"mounts": [{**MOUNT, "source": "host:/x y"}]}, "source"),
        ({"mounts": [{**MOUNT, "extra": 1}]}, "extra"),
        ({"warn_days": 0}, "warn_days"),
        ({"timer_interval": 10}, "timer_interval"),
        ({"bind": "tailscale-interface"}, "bind"),
        ({"auth_user": "CHANGE_ME"}, "placeholder"),
        ({"nyxmon_check": {**CHECK_FIELDS, "auth_username": "other"}}, "auth_user"),
    ],
)
def test_bad_configs_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        client_cfg(**changes)


def test_the_rules_follow_the_report() -> None:
    assert client_cfg().check_conditions() == [
        {"path": "$.meta.age_seconds", "op": "<", "value": 900, "severity": "warning"},
        {"path": "$.units.tlshd_service.ok", "op": "==", "value": True, "severity": "critical"},
        {"path": "$.mounts.mnt_cryptdata_media.ok", "op": "==", "value": True, "severity": "critical"},
        {"path": "$.certificates.etc_tlshd_client_pem.ok", "op": "==", "value": True, "severity": "warning"},
        {"path": "$.certificates.etc_tlshd_client_pem.days_left", "op": ">", "value": 0, "severity": "critical"},
        {"path": "$.certificates.etc_tlshd_nfs_ca_pem.ok", "op": "==", "value": True, "severity": "warning"},
        {"path": "$.certificates.etc_tlshd_nfs_ca_pem.days_left", "op": ">", "value": 0, "severity": "critical"},
    ]
    # Before the switch the client has no mount: no mount rule.
    assert not any(".mounts." in rule["path"] for rule in client_cfg(mounts=[]).check_conditions())
    assert server_cfg(timer_interval=600).check_conditions()[0]["value"] == 1800


def test_the_exporter_config_carries_every_key() -> None:
    config = json.loads(nts.render_config(client_cfg()))

    assert config == {
        "state_group": "metrics",
        "warn_days": 60,
        "units": [{"id": "tlshd_service", "unit": "tlshd.service"}],
        "mounts": [
            {
                "id": "mnt_cryptdata_media",
                "where": "/mnt/cryptdata/media",
                "source": SOURCE,
                "fstype": "nfs4",
                "required_options": ["xprtsec=mtls"],
                "unit": "mnt-cryptdata-media.mount",
            }
        ],
        "certificates": [
            {"id": "etc_tlshd_client_pem", "path": "/etc/tlshd/client.pem"},
            {"id": "etc_tlshd_nfs_ca_pem", "path": "/etc/tlshd/nfs-ca.pem"},
        ],
    }


def test_the_endpoint_is_a_valid_metrics_httpd_json_file_endpoint() -> None:
    cfg = client_cfg()

    assert metrics_httpd.problems(nts.httpd_endpoint(cfg, TAILSCALE_IP)) == []
    unit = nts.render_endpoint_unit(cfg, TAILSCALE_IP)
    assert (
        "ExecStart=/usr/bin/python3 -I /usr/local/lib/nfs-tls-status/nfs_tls_status_httpd.py --bind 100.64.0.7 "
        "--port 9109 --path /.well-known/nfs-tls --json-path /var/lib/nfs-tls-status/status.json "
        "--htpasswd-file /etc/nfs-tls-status/htpasswd --realm nfs-tls-status --server-name nfs-tls-status-httpd/1\n"
    ) in unit
    assert "User=metrics\nGroup=metrics\n" in unit
    assert "IPAddressDeny=any\nIPAddressAllow=localhost\nIPAddressAllow=100.64.0.0/10\n" in unit
    assert "ReadOnlyPaths=/var/lib/nfs-tls-status\n" in unit


def test_the_collector_runs_as_root_and_writes_only_its_directory() -> None:
    unit = nts.render_collector_service(client_cfg())

    assert "User=root\n" in unit
    assert "ProtectSystem=strict\nReadWritePaths=/var/lib/nfs-tls-status\n" in unit
    assert (
        "ExecStart=/usr/bin/python3 -I /usr/local/lib/nfs-tls-status/nfs_tls_status.py "
        "--config /etc/nfs-tls-status/config.json --out /var/lib/nfs-tls-status/status.json\n"
    ) in unit
    timer = nts.render_timer(client_cfg(timer_interval=120))
    assert "OnActiveSec=30s\nOnUnitActiveSec=120s\n" in timer


# -- the exporter on fixtures ---------------------------------------------------------------------

FAKE_SYSTEMCTL = """
import json, os, sys
unit = sys.argv[-1]
states = json.loads(os.environ["FAKE_UNITS"])
if states.get(unit) == "fail":
    print("Failed to connect to bus", file=sys.stderr)
    sys.exit(1)
active = states.get(unit)
print("LoadState=" + ("loaded" if active else "not-found"))
print("ActiveState=" + (active or "inactive"))
print("SubState=" + ("running" if active == "active" else "dead"))
"""
# Prints the file's notAfter line as openssl does; anything else is not a certificate.
FAKE_OPENSSL = """
import sys
path = sys.argv[sys.argv.index("-in") + 1]
lines = [line for line in open(path).read().splitlines() if line.startswith("notAfter=")]
if not lines:
    print("Could not find certificate from " + path, file=sys.stderr)
    sys.exit(1)
print(lines[0])
"""
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def not_after(days: float) -> str:
    """openssl's ``-enddate`` line for a certificate ending ``days`` from now (day padded like openssl)."""

    end = time.gmtime(time.time() + days * 86400)
    clock = time.strftime("%H:%M:%S", end)
    return f"notAfter={MONTHS[end.tm_mon - 1]} {end.tm_mday:>2} {clock} {end.tm_year} GMT"


def mountinfo_line(where: str, fstype: str, source: str, options: str) -> str:
    return f"512 31 0:77 / {where} rw,relatime shared:300 - {fstype} {source} {options}"


MOUNTED = mountinfo_line(
    "/mnt/cryptdata/media",
    "nfs4",
    SOURCE,
    "rw,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,xprtsec=mtls",
)
BASE_MOUNTS = "\n".join(
    [
        "29 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw",
        "31 29 0:26 / /mnt/cryptdata rw,relatime shared:2 - ext4 /dev/mapper/cryptdata rw",
    ]
)


def run_exporter(
    tmp_path: Path,
    cfg: NfsTlsStatusConfig,
    *,
    units: dict[str, str],
    certificates: Mapping[str, str | None],
    mountinfo: str | None = BASE_MOUNTS,
) -> dict[str, Any]:
    """The exporter against fake ``systemctl``/``openssl``, certificate files and a mount table."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("systemctl", FAKE_SYSTEMCTL), ("openssl", FAKE_OPENSSL)):
        tool = bin_dir / name
        tool.write_text(f"#!{sys.executable}\n{body}")
        tool.chmod(0o755)
    config = json.loads(nts.render_config(cfg))
    config["state_group"] = None
    for entry in config["certificates"]:
        local = tmp_path / "certs" / entry["id"]
        local.parent.mkdir(exist_ok=True)
        content = certificates.get(entry["path"])
        if content is not None:
            local.write_text(content)
        entry["path"] = str(local)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    table = tmp_path / "mountinfo"
    if mountinfo is not None:
        table.write_text(mountinfo + "\n")
    out = tmp_path / "status.json"
    script = Path(nts.__file__).parent / "files" / "nfs_tls_status.py"
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_UNITS": json.dumps(units)}
    done = subprocess.run(
        [sys.executable, "-I", str(script), "--config", str(config_path), "--out", str(out), "--mountinfo", str(table)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    assert [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")] == []
    report: dict[str, Any] = json.loads(out.read_text())
    return report


OPS = {"<": operator.lt, ">": operator.gt, "==": operator.eq}


def failed_rules(cfg: NfsTlsStatusConfig, report: dict[str, Any]) -> list[tuple[str, str]]:
    """Nyxmon's reading of the rules: a missing path or a null fails, else Python's operator decides."""

    served = {**report, "meta": {"age_seconds": 5}}
    failed = []
    for rule in cfg.check_conditions():
        value: Any = served
        for part in rule["path"].removeprefix("$.").split("."):
            value = value.get(part) if isinstance(value, dict) else None
        try:
            ok = value is not None and OPS[rule["op"]](value, rule["value"])
        except TypeError:
            ok = False
        if not ok:
            failed.append((rule["path"], rule["severity"]))
    return failed


VALID = {path: not_after(400) for path in CLIENT_CERTS}
ACTIVE = {"tlshd.service": "active", "mnt-cryptdata-media.mount": "active"}


def test_a_healthy_client_passes_every_rule(tmp_path: Path) -> None:
    cfg = client_cfg()

    report = run_exporter(tmp_path, cfg, units=ACTIVE, certificates=VALID, mountinfo=f"{BASE_MOUNTS}\n{MOUNTED}")

    assert report["ok"] is True
    assert report["schema"] == 1
    assert report["units"] == {
        "tlshd_service": {
            "unit": "tlshd.service",
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "ok": True,
            "problems": [],
        }
    }
    mount = report["mounts"]["mnt_cryptdata_media"]
    assert mount["where"] == "/mnt/cryptdata/media"
    assert (mount["present"], mount["fstype"], mount["source"], mount["missing_options"]) == (True, "nfs4", SOURCE, [])
    assert (mount["unit"], mount["unit_active_state"], mount["ok"]) == ("mnt-cryptdata-media.mount", "active", True)
    assert "xprtsec=mtls" in mount["options"]
    certificate = report["certificates"]["etc_tlshd_client_pem"]
    assert certificate["days_left"] in (399, 400)
    assert certificate["ok"] is True
    assert certificate["not_after"].endswith("+00:00")
    assert failed_rules(cfg, report) == []


@pytest.mark.parametrize(
    ("units", "failed"),
    [
        ({"tlshd.service": "inactive"}, "(load state loaded)"),
        ({"tlshd.service": "failed"}, "failed"),
        ({}, "inactive (load state not-found)"),
        ({"tlshd.service": "fail"}, "systemctl show failed: Failed to connect to bus"),
    ],
    ids=["inactive", "failed", "missing", "systemctl fails"],
)
def test_a_unit_that_is_not_active_is_critical(tmp_path: Path, units: dict[str, str], failed: str) -> None:
    cfg = client_cfg(mounts=[])

    report = run_exporter(tmp_path, cfg, units=units, certificates=VALID)

    entry = report["units"]["tlshd_service"]
    assert entry["ok"] is False
    assert failed in entry["problems"][0]
    assert entry["unit"] == "tlshd.service"
    assert report["ok"] is False
    assert failed_rules(cfg, report) == [("$.units.tlshd_service.ok", "critical")]


@pytest.mark.parametrize(
    ("mountinfo", "units", "problem"),
    [
        (BASE_MOUNTS, ACTIVE, "not mounted"),
        (f"{BASE_MOUNTS}\n{MOUNTED.replace(',xprtsec=mtls', '')}", ACTIVE, "missing options: xprtsec=mtls"),
        (f"{BASE_MOUNTS}\n{MOUNTED.replace(SOURCE, '192.0.2.99:/fast/media')}", ACTIVE, "source 192.0.2.99"),
        (f"{BASE_MOUNTS}\n{MOUNTED.replace(' nfs4 ', ' nfs ')}", ACTIVE, "file system type nfs, expected nfs4"),
        (f"{BASE_MOUNTS}\n{MOUNTED}", {"tlshd.service": "active"}, "mnt-cryptdata-media.mount: inactive"),
        (None, ACTIVE, "cannot read the mount table"),
    ],
    ids=["absent", "without mtls", "other source", "other type", "unit inactive", "no table"],
)
def test_a_wrong_or_missing_mount_is_critical(
    tmp_path: Path, mountinfo: str | None, units: dict[str, str], problem: str
) -> None:
    cfg = client_cfg()

    report = run_exporter(tmp_path, cfg, units=units, certificates=VALID, mountinfo=mountinfo)

    entry = report["mounts"]["mnt_cryptdata_media"]
    assert entry["ok"] is False
    assert any(problem in text for text in entry["problems"]), entry["problems"]
    assert entry["where"] == "/mnt/cryptdata/media"
    assert failed_rules(cfg, report) == [("$.mounts.mnt_cryptdata_media.ok", "critical")]


def test_the_topmost_mount_counts_and_escapes_are_decoded(tmp_path: Path) -> None:
    autofs = "500 31 0:70 / /mnt/cryptdata/media rw,relatime shared:299 - autofs systemd-1 rw,fd=50"
    spaced = mountinfo_line("/srv/with\\040space", "nfs4", SOURCE, "rw,xprtsec=mtls")
    spaced_mount = {"where": "/srv/with_space", "source": SOURCE, "required_options": ["xprtsec=mtls"]}
    cfg = client_cfg(mounts=[MOUNT, spaced_mount])

    report = run_exporter(
        tmp_path, cfg, units=ACTIVE, certificates=VALID, mountinfo=f"{BASE_MOUNTS}\n{autofs}\n{MOUNTED}\n{spaced}"
    )

    assert report["mounts"]["mnt_cryptdata_media"]["ok"] is True
    # "/srv/with space" is not "/srv/with_space": the decoded path is compared.
    assert report["mounts"]["srv_with_space"]["problems"] == ["not mounted"]


def test_an_autofs_trigger_without_the_nfs_mount_is_not_enough(tmp_path: Path) -> None:
    autofs = "500 31 0:70 / /mnt/cryptdata/media rw,relatime shared:299 - autofs systemd-1 rw,fd=50"
    cfg = client_cfg()

    report = run_exporter(tmp_path, cfg, units=ACTIVE, certificates=VALID, mountinfo=f"{BASE_MOUNTS}\n{autofs}")

    assert "file system type autofs, expected nfs4" in report["mounts"]["mnt_cryptdata_media"]["problems"]


@pytest.mark.parametrize(
    ("content", "days_left", "failed"),
    [
        (not_after(30.5), 30, [("ok", "warning")]),
        (not_after(-2.5), -3, [("ok", "warning"), ("days_left", "critical")]),
        (not_after(0.5), 0, [("ok", "warning"), ("days_left", "critical")]),
        (None, None, [("ok", "warning"), ("days_left", "critical")]),
        ("-----BEGIN PRIVATE KEY-----\n", None, [("ok", "warning"), ("days_left", "critical")]),
    ],
    ids=["expiring", "expired", "last day", "missing", "not a certificate"],
)
def test_certificate_expiry(
    tmp_path: Path, content: str | None, days_left: int | None, failed: list[tuple[str, str]]
) -> None:
    cfg = client_cfg(mounts=[])

    certificates = {**VALID, "/etc/tlshd/client.pem": content}
    report = run_exporter(tmp_path, cfg, units=ACTIVE, certificates=certificates)

    entry = report["certificates"]["etc_tlshd_client_pem"]
    assert entry["days_left"] == days_left
    assert entry["ok"] is False
    assert entry["problems"]
    assert entry["path"].endswith("etc_tlshd_client_pem")
    assert report["certificates"]["etc_tlshd_nfs_ca_pem"]["ok"] is True
    prefix = "$.certificates.etc_tlshd_client_pem."
    assert failed_rules(cfg, report) == [(prefix + key, severity) for key, severity in failed]


def test_the_problems_name_no_certificate_content(tmp_path: Path) -> None:
    cfg = client_cfg(mounts=[])
    secret = "-----BEGIN PRIVATE KEY-----\nMIIfixturefixture\n-----END PRIVATE KEY-----\n"

    report = run_exporter(tmp_path, cfg, units=ACTIVE, certificates={**VALID, "/etc/tlshd/client.pem": secret})

    assert "MIIfixturefixture" not in json.dumps(report)


def test_a_broken_config_fails_without_a_report(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text("{}")
    script = Path(nts.__file__).parent / "files" / "nfs_tls_status.py"

    done = subprocess.run(
        [sys.executable, "-I", str(script), "--config", str(config), "--out", str(tmp_path / "status.json")],
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 1
    assert not (tmp_path / "status.json").exists()


# -- plans -----------------------------------------------------------------------------------------

P = "NFS-over-TLS status | "
UNITS = "/etc/systemd/system"
SCRIPTS = "/usr/local/lib/nfs-tls-status"
HTPASSWD = "/etc/nfs-tls-status/htpasswd"
STATE_PROBE = "if test -e /var/lib/nfs-tls-status/status.json"
CHECK: dict[str, Any] = {
    "service_name": "fractal",
    "name": "Fractal NFS TLS",
    "check_interval": 300,
    "auth_username": "nyxmon",
    "data": {"url": "http://192.0.2.1:9109/.well-known/nfs-tls", "checks": server_cfg().check_conditions()},
}


def converged(cfg: NfsTlsStatusConfig) -> dict[str, Any]:
    return {
        **fakehost.UBUNTU,
        "tailscale ip --4": [TAILSCALE_IP],
        STATE_PROBE: ["present"],
        **fakehost.deb_installed(*cfg.packages),
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.stat("/etc/nfs-tls-status", group="metrics", mode="drwxr-x---"),
        **fakehost.stat("/var/lib/nfs-tls-status", group="metrics", mode="drwxr-x---"),
        **fakehost.directory(SCRIPTS),
        **fakehost.directory(UNITS),
        **fakehost.file(f"{SCRIPTS}/nfs_tls_status.py", nts.EXPORTER_SCRIPT),
        **fakehost.file(f"{SCRIPTS}/nfs_tls_status_httpd.py", HTTPD_SCRIPT),
        **fakehost.file("/etc/nfs-tls-status/config.json", nts.render_config(cfg)),
        **fakehost.file(HTPASSWD, f"nyxmon:{hash_password(PASSWORD)}\n"),
        **fakehost.stat(HTPASSWD, group="metrics", mode="-rw-r-----"),
        **fakehost.file(f"{UNITS}/nfs-tls-status-collector.service", nts.render_collector_service(cfg)),
        **fakehost.file(f"{UNITS}/nfs-tls-status-collector.timer", nts.render_timer(cfg)),
        **fakehost.file(f"{UNITS}/nfs-tls-status-endpoint.service", nts.render_endpoint_unit(cfg, TAILSCALE_IP)),
        **fakehost.service("nfs-tls-status-collector.timer"),
        **fakehost.service("nfs-tls-status-endpoint.service"),
    }


def run(responses: dict[str, Any], cfg: NfsTlsStatusConfig, secrets: SecretValues = SECRETS) -> FakeRun:
    result = run_deploy_fake(deploy_nfs_tls_status, cfg, secrets, responses=responses)
    assert result.succeeded, result.error
    return result


def test_a_converged_host_plans_only_read_only_checks() -> None:
    cfg = server_cfg()

    result = run(converged(cfg), cfg)

    assert result.mutating_changed_ops == []
    assert verify_op(P, "nfs-tls-status-endpoint") in [op.name for op in result.ops if op.changed]
    assert without_switch(result.stdin) == []
    assert not any("systemctl start" in c or "restart" in c for c in result.executed_commands)


def test_a_fresh_host_installs_everything_once() -> None:
    cfg = server_cfg()

    result = run({**fakehost.UBUNTU, "tailscale ip --4": [TAILSCALE_IP]}, cfg)

    assert result.mutating_changed_ops == [
        f"{P}Install the NFS-over-TLS status packages",
        f"{P}Ensure group metrics",
        f"{P}Ensure endpoint user metrics",
        f"{P}Ensure /etc/nfs-tls-status",
        f"{P}Ensure /var/lib/nfs-tls-status",
        f"{P}Ensure {SCRIPTS}",
        f"{P}Install {SCRIPTS}/nfs_tls_status.py",
        f"{P}Install /etc/nfs-tls-status/config.json",
        f"{P}Install systemd unit nfs-tls-status-collector.service",
        f"{P}Install systemd unit nfs-tls-status-collector.timer",
        f"{P}Reload systemd for the NFS-over-TLS status collector",
        f"{P}Run nfs-tls-status-collector.service once",
        f"{P}Enable nfs-tls-status-collector.timer",
        f"{P}Start nfs-tls-status-collector.timer",
        f"{P}Install {SCRIPTS}/nfs_tls_status_httpd.py",
        f"{P}Write {HTPASSWD}",
        f"{P}Install systemd unit nfs-tls-status-endpoint.service",
        f"{P}Reload systemd for nfs-tls-status-endpoint",
        f"{P}Enable nfs-tls-status-endpoint.service",
        f"{P}Start nfs-tls-status-endpoint.service",
    ]
    commands = result.executed_commands
    assert any("apt-get" in c and "openssl" in c and "apache2-utils" in c for c in commands)
    assert PASSWORD not in result.all_text()
    assert not any(PASSWORD in op.name for op in result.ops)


def test_a_changed_config_recollects_without_restarting_the_endpoint() -> None:
    cfg = client_cfg()
    responses = {**converged(cfg), **fakehost.file("/etc/nfs-tls-status/config.json", "{}\n")}

    result = run(responses, cfg)

    assert result.mutating_changed_ops == [
        f"{P}Install /etc/nfs-tls-status/config.json",
        f"{P}Run nfs-tls-status-collector.service once",
    ]


def test_a_changed_password_rewrites_the_hash_and_restarts_the_endpoint() -> None:
    cfg = server_cfg()
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: "another-fixture-password"})

    result = run(converged(cfg), cfg, secrets)

    assert result.mutating_changed_ops == [f"{P}Write {HTPASSWD}", f"{P}Restart nfs-tls-status-endpoint.service"]
    assert "another-fixture-password" not in result.all_text()


@pytest.mark.parametrize("password", ["", "CHANGE_ME", "two\nlines", "x" * 73])
def test_unusable_passwords_are_refused_before_any_operation(password: str) -> None:
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: password})
    result = run_deploy_fake(deploy_nfs_tls_status, server_cfg(), secrets, responses=converged(server_cfg()))

    assert not result.succeeded
    assert result.ops == []


def test_no_tailscale_address_stops_the_deploy() -> None:
    cfg = server_cfg()
    result = run_deploy_fake(deploy_nfs_tls_status, cfg, SECRETS, responses={**converged(cfg), "tailscale ip --4": []})

    assert not result.succeeded
    assert result.mutating_changed_ops == []


def test_a_same_host_check_is_upserted_with_the_password_on_stdin_only() -> None:
    cfg = server_cfg(nyxmon_check=CHECK)
    probe = " probe /home/nyxmon/site/db.sqlite3 fractal "

    result = run({**converged(cfg), probe: ["check absent"]}, cfg)

    assert result.mutating_changed_ops == [f"{P}Upsert Nyxmon check Fractal NFS TLS"]
    (upsert,) = [(c, s) for c, s in result.stdin if " apply " in c]
    assert json.loads(upsert[1])["data"]["auth"] == {"username": "nyxmon", "password": PASSWORD}
    assert PASSWORD not in result.all_text()


# -- the check-only deploy (the Nyxmon host) -------------------------------------------------------

C = "NFS-over-TLS status check | "
CHECK_CFG = NfsTlsStatusCheckConfig.model_validate({"secrets": "secrets/fixture.yml", "nyxmon_check": CHECK})
CHECK_PROBE = " probe /home/nyxmon/site/db.sqlite3 fractal "


def test_the_check_only_deploy_touches_nothing_but_the_check() -> None:
    result = run_deploy_fake(
        deploy_nfs_tls_status_check, CHECK_CFG, SECRETS, responses={**fakehost.UBUNTU, CHECK_PROBE: ["check absent"]}
    )

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == [f"{C}Upsert Nyxmon check Fractal NFS TLS"]
    (upsert,) = [(c, s) for c, s in result.stdin if " apply " in c]
    stored = json.loads(upsert[1])
    assert stored["data"]["checks"] == server_cfg().check_conditions()
    assert stored["data"]["auth"] == {"username": "nyxmon", "password": PASSWORD}
    assert PASSWORD not in result.all_text()
    assert not any(c.startswith(("apt", "systemctl", "useradd")) for c in result.executed_commands)


def test_a_current_check_is_left_alone() -> None:
    responses = {**fakehost.UBUNTU, CHECK_PROBE: [f"check {CHECK_CFG.nyxmon_check.digest(PASSWORD)}"]}

    result = run_deploy_fake(deploy_nfs_tls_status_check, CHECK_CFG, SECRETS, responses=responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []


@pytest.mark.parametrize("password", ["", "CHANGE_ME"])
def test_the_check_needs_a_usable_password(password: str) -> None:
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: password})

    result = run_deploy_fake(deploy_nfs_tls_status_check, CHECK_CFG, secrets, responses=fakehost.UBUNTU)

    assert not result.succeeded
    assert result.ops == []


def test_the_check_must_write_this_nyxmon() -> None:
    with pytest.raises(ConfigValidationError, match="this Nyxmon"):
        NfsTlsStatusCheckConfig.model_validate(
            {"secrets": "secrets/fixture.yml", "nyxmon_check": {**CHECK, "user": "other"}}
        )
