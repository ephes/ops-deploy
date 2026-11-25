"""Selected policy/admission, original resources and dedicated SQL continuity."""

from __future__ import annotations

import json
import os
import pwd
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra.tailscale import TailscaleConfig, TailscaleMetricsConfig
from ops_deploy.infra.tailscale.metrics import schema
from ops_deploy.infra.tailscale.nyxmon import TailscaleNyxmonTarget, check_row
from ops_deploy.infra.tailscale.render import render
from tests.goldens import assert_golden

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "values",
    [
        dict(package_version="latest; true"),
        dict(repo_base="https://user:password@example.test"),
        dict(args_extra=("--auth-key=must-use-stdin",)),
        dict(args_extra=("--authkey=must-use-stdin",)),
        dict(args_extra=("-authkey", "must-use-stdin")),
        dict(binary="/usr/bin/../private/tailscale"),
    ],
)
def test_core_rejects_unsafe_native_or_credential_paths(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TailscaleConfig(hostname="owned-node", **values)


def test_latest_retains_present_policy_and_original_false_preferences() -> None:
    cfg = TailscaleConfig(hostname="owned-node")
    assert cfg.package_version == "latest"
    assert not cfg.accept_dns
    assert not cfg.accept_routes
    assert not cfg.manual_up
    assert cfg.repo_base == "https://pkgs.tailscale.com"


@pytest.mark.parametrize(
    "values",
    [
        dict(ip_address_allow=("0.0.0.0/0",)),
        dict(ip_address_allow=("::/0",)),
        dict(require_default_ipv4_route=True),
        dict(warning_days=1, critical_days=3),
        dict(timer_on_calendar=""),
        dict(nvme_devices=("/dev/nvme0n1",)),
        dict(nvme_devices=("/dev/sda",)),
        dict(nvme_devices=("/dev/nvme0", "/dev/nvme0")),
        dict(nvme_devices=tuple(f"/dev/nvme{i}" for i in range(9))),
        dict(require_nvme_healthy=True),
    ],
)
def test_endpoint_retains_original_filter_route_timer_threshold_admission(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TailscaleMetricsConfig(**values)


def test_original_exporter_and_timer_policy_are_rendered_without_source_edits() -> None:
    cfg = TailscaleMetricsConfig(require_effective_ip_filter=True)
    script = render(cfg, "tailscale_metrics_exporter.py")
    compile(script, "owned-exporter", "exec")
    assert "WARNING_DAYS = 3" in script
    assert "CRITICAL_DAYS = 1" in script
    timer = render(cfg, "tailscale-metrics-collector.timer")
    assert "OnActiveSec=300\n" in timer
    assert "OnCalendar=*:0/5\n" in timer
    unit = render(cfg, "tailscale-metrics-endpoint.service")
    assert "cgroup_inet_ingress" in unit
    assert "cgroup_inet_egress" in unit
    assert "IPAddressDeny=any\n" in unit
    assert all(not rule.equals_true for rule in schema())  # Fresh error telemetry remains valid; no forced refresh.


def test_tailscale_nyxmon_rule_order_and_optional_policy_are_exact() -> None:
    target = TailscaleNyxmonTarget(
        hostname="owned",
        url="http://192.0.2.20:9107/.well-known/tailscale",
        require_self_online=True,
        require_default_ipv4_route=True,
        require_mdraid_healthy=True,
        require_nvme_healthy=True,
        notify_consecutive_failures=4,
        max_age_seconds=600,
        check_interval=300,
    )
    row = check_row(target, SecretStr("synthetic-only"))
    data = row["data"]
    assert isinstance(data, dict)
    assert [check["path"] for check in data["checks"]] == [
        "$.summary.backend_running",
        "$.summary.self_online",
        "$.summary.default_ipv4_route_present",
        "$.summary.mdraid_healthy",
        "$.summary.nvme_healthy",
        "$.summary.key_expiry_critical_ok",
        "$.summary.key_expiry_warning_ok",
        "$.meta.age_seconds",
    ]
    assert data["notification_policy"] == {"consecutive_failures": 4}
    assert data["checks"][-1] == dict(path="$.meta.age_seconds", op="<", value=600, severity="critical")
    assert data["checks"][4] == dict(path="$.summary.nvme_healthy", op="==", value=True, severity="critical")


def test_nvme_rule_is_absent_unless_required() -> None:
    row = check_row(
        TailscaleNyxmonTarget(hostname="owned", url="http://192.0.2.20:9107/.well-known/tailscale"),
        SecretStr("synthetic-only"),
    )
    data = row["data"]
    assert isinstance(data, dict)
    assert "$.summary.nvme_healthy" not in [check["path"] for check in data["checks"]]


def _health_log(**overrides: int) -> dict[str, int]:
    log = dict(
        critical_warning=0,
        temperature=51,
        available_spare=68,
        available_spare_threshold=10,
        percentage_used=32,
        media_errors=0,
        num_err_log_entries=0,
    )
    log.update(overrides)
    return log


def _nvme_exporter(tmp_path: Path, reports: dict[str, Any], *, required: bool = True) -> dict[str, Any]:
    """The rendered collector's namespace, reading ``reports`` through a fake smartctl."""

    fixtures = tmp_path / "reports.json"
    fixtures.write_text(json.dumps(reports))
    fake = tmp_path / "smartctl"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"reports = json.load(open({str(fixtures)!r}))\n"
        "device = sys.argv[-1]\n"
        "if reports.get(device) == 'hang':\n"
        "    import time; time.sleep(60)\n"
        "if device not in reports:\n"
        "    print('Smartctl open device: ' + device + ' failed: No such device', file=sys.stderr)\n"
        "    sys.exit(2)\n"
        "print(json.dumps(reports[device]))\n"
        "sys.exit(8 if reports[device].get('smart_status', {}).get('passed') is False else 0)\n"
    )
    fake.chmod(0o755)
    # Stands in for ``systemd-run --scope``: records its options, then becomes the reader.
    launcher = tmp_path / "systemd-run"
    launcher.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "options = []\n"
        "while args and args[0].startswith('--'):\n"
        "    options.append(args.pop(0))\n"
        "unit = next(o for o in options if o.startswith('--unit='))[7:]\n"
        f"if os.path.exists(os.path.join({str(tmp_path)!r}, 'active-' + unit)):\n"
        "    message = 'Failed to start transient scope unit: Unit ' + unit + '.scope was already loaded'\n"
        "    print(message, file=sys.stderr)\n"
        "    sys.exit(1)\n"
        f"with open({str(tmp_path / 'scopes.log')!r}, 'a') as log:\n"
        "    log.write(' '.join(options) + ' | ' + ' '.join(args) + '\\n')\n"
        "try:\n"
        "    os.execv(args[0], args)\n"
        "except OSError as err:\n"
        "    print('Failed to execute ' + args[0] + ': ' + str(err), file=sys.stderr)\n"
        "    sys.exit(1)\n"
    )
    launcher.chmod(0o755)
    cfg = TailscaleMetricsConfig(
        smartctl_bin=str(fake),
        systemd_run_bin=str(launcher),
        nvme_devices=("/dev/nvme0", "/dev/nvme1"),
        require_nvme_healthy=required,
    )
    namespace: dict[str, Any] = {"__name__": "tailscale_exporter_under_test"}
    exec(compile(render(cfg, "tailscale_metrics_exporter.py"), "exporter", "exec"), namespace)
    return namespace


def test_nvme_probe_reports_each_controller_and_healthy_summary(tmp_path: Path) -> None:
    ns = _nvme_exporter(
        tmp_path,
        {
            "/dev/nvme0": {"nvme_smart_health_information_log": _health_log()},
            "/dev/nvme1": {"nvme_smart_health_information_log": _health_log(temperature=62, available_spare=100)},
        },
    )
    healthy, devices, detail = ns["probe_nvme"]()
    assert (healthy, detail) == (True, "")
    assert [entry["name"] for entry in devices] == ["nvme0", "nvme1"]
    assert devices[0] == dict(
        device="/dev/nvme0",
        name="nvme0",
        healthy=True,
        error="",
        critical_warning=0,
        temperature_c=51,
        available_spare=68,
        available_spare_threshold=10,
        percentage_used=32,
        media_errors=0,
        num_err_log_entries=0,
    )
    assert devices[1]["temperature_c"] == 62
    scopes = sorted((tmp_path / "scopes.log").read_text().splitlines())
    assert scopes == [
        f"--scope --quiet --collect --unit=tailscale-metrics-nvme-{name} "
        f"--description=Tailscale metrics NVMe health read {name} | "
        f"{tmp_path / 'smartctl'} -j -H -A -d nvme /dev/{name}"
        for name in ("nvme0", "nvme1")
    ]


@pytest.mark.parametrize(
    ("report", "problem"),
    [
        (
            {"nvme_smart_health_information_log": _health_log(media_errors=3)},
            "nvme1: critical_warning=0 media_errors=3",
        ),
        (
            {"smart_status": {"passed": False}, "nvme_smart_health_information_log": _health_log(critical_warning=1)},
            "nvme1: critical_warning=1 media_errors=0",
        ),
        ({"nvme_smart_health_information_log": {"critical_warning": 0}}, "nvme1: NVMe health log lacks temperature"),
        ({"nvme_smart_health_information_log": _health_log(media_errors=True)}, "lacks media_errors"),
        ({}, "nvme1: no NVMe health log (smartctl exit 0)"),
    ],
)
def test_nvme_probe_fails_closed(tmp_path: Path, report: dict[str, Any], problem: str) -> None:
    ns = _nvme_exporter(
        tmp_path, {"/dev/nvme0": {"nvme_smart_health_information_log": _health_log()}, "/dev/nvme1": report}
    )
    healthy, devices, detail = ns["probe_nvme"]()
    assert healthy is False
    assert problem in detail
    assert devices[0]["healthy"] is True
    assert devices[1]["healthy"] is False


def test_nvme_probe_reports_unreadable_device_and_missing_reader(tmp_path: Path) -> None:
    ns = _nvme_exporter(tmp_path, {"/dev/nvme0": {"nvme_smart_health_information_log": _health_log()}})
    healthy, _, detail = ns["probe_nvme"]()
    assert healthy is False
    assert "nvme1: Smartctl open device: /dev/nvme1 failed: No such device" in detail
    ns["SMARTCTL_BIN"] = str(tmp_path / "absent")
    healthy, devices, detail = ns["probe_nvme"]()
    assert healthy is False
    assert not any(entry["healthy"] for entry in devices)
    assert "nvme0: Failed to execute " in detail
    ns["SYSTEMD_RUN_BIN"] = str(tmp_path / "absent")
    healthy, devices, detail = ns["probe_nvme"]()
    assert healthy is False
    assert not any(entry["healthy"] for entry in devices)
    assert "nvme0: smartctl failed:" in detail


def test_nvme_probe_does_not_wait_for_a_hung_reader(tmp_path: Path) -> None:
    ns = _nvme_exporter(
        tmp_path, {"/dev/nvme0": "hang", "/dev/nvme1": {"nvme_smart_health_information_log": _health_log()}}
    )
    ns["NVME_DEADLINE_SECONDS"] = 1
    started = time.monotonic()
    healthy, devices, detail = ns["probe_nvme"]()
    assert time.monotonic() - started < 10
    assert healthy is False
    assert detail == "nvme0: smartctl did not answer within 1 seconds"
    assert devices[1]["healthy"] is True


def test_nvme_probe_never_starts_a_second_reader_while_a_stuck_one_holds_the_scope(tmp_path: Path) -> None:
    ns = _nvme_exporter(
        tmp_path,
        {
            "/dev/nvme0": {"nvme_smart_health_information_log": _health_log()},
            "/dev/nvme1": {"nvme_smart_health_information_log": _health_log()},
        },
    )
    (tmp_path / "active-tailscale-metrics-nvme-nvme0").touch()
    healthy, devices, detail = ns["probe_nvme"]()
    assert healthy is False
    assert detail == (
        "nvme0: Failed to start transient scope unit: Unit tailscale-metrics-nvme-nvme0.scope was already loaded"
    )
    assert devices[1]["healthy"] is True
    assert [line.split(" | ")[1].rsplit(" ", 1)[1] for line in (tmp_path / "scopes.log").read_text().splitlines()] == [
        "/dev/nvme1"
    ]


def test_nvme_probe_kills_an_unkillable_reader_once_and_never_waits_again(tmp_path: Path) -> None:
    """A reader in uninterruptible I/O survives SIGKILL: only one kill(), no wait()/communicate() after it."""

    ns = _nvme_exporter(tmp_path, {})
    ns["NVME_DEADLINE_SECONDS"] = 0
    events: list[str] = []

    class Unkillable:
        returncode = None

        def __init__(self, argv: list[str], **_: object) -> None:
            self.device = argv[-1]
            self.timed_out = False

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            if self.timed_out:
                raise AssertionError("communicate() again after the deadline")
            events.append(f"communicate {self.device} {timeout}")
            self.timed_out = True
            raise subprocess.TimeoutExpired("smartctl", timeout or 0)

        def kill(self) -> None:
            events.append(f"kill {self.device}")

        def wait(self, timeout: float | None = None) -> int:
            raise AssertionError("wait() for a reader that cannot exit")

        def poll(self) -> int | None:
            raise AssertionError("poll() for a reader that cannot exit")

    shim = type(subprocess)("subprocess_shim")
    shim.__dict__.update(
        Popen=Unkillable, TimeoutExpired=subprocess.TimeoutExpired, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE
    )
    ns["subprocess"] = shim
    healthy, devices, detail = ns["probe_nvme"]()
    assert healthy is False
    assert events == [
        "communicate /dev/nvme0 0.5",
        "kill /dev/nvme0",
        "communicate /dev/nvme1 0.5",
        "kill /dev/nvme1",
    ]
    assert [entry["error"] for entry in devices] == ["smartctl did not answer within 0 seconds"] * 2
    assert detail == "nvme0: smartctl did not answer within 0 seconds; nvme1: smartctl did not answer within 0 seconds"


def test_without_nvme_devices_the_summary_stays_neutral() -> None:
    namespace: dict[str, Any] = {"__name__": "tailscale_exporter_under_test"}
    exec(compile(render(TailscaleMetricsConfig(), "tailscale_metrics_exporter.py"), "exporter", "exec"), namespace)
    assert namespace["probe_nvme"]() == (None, [], "no NVMe devices configured")


def sql_fixture(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE service (id INTEGER PRIMARY KEY, name TEXT); "
            "CREATE TABLE health_check (id INTEGER PRIMARY KEY,name TEXT,service_id INTEGER,check_type TEXT,"
            "url TEXT,check_interval INTEGER,status TEXT,next_check_time INTEGER,processing_started_at INTEGER,"
            "disabled INTEGER,data TEXT); INSERT INTO service VALUES (1,'Tailscale'); "
            "INSERT INTO health_check VALUES (1,'Tailscale key expiry (owned)',1,'old','http://old',"
            "5,'critical',1234,5678,1,'{}'); "
            "INSERT INTO health_check VALUES (2,'unrelated',1,'sentinel','http://unrelated',10,'warning',999,888,1,'{}');"
        )


def sql_run(path: Path, action: str) -> subprocess.CompletedProcess[str]:
    cfg = dict(
        db_path=str(path),
        user=pwd.getpwuid(os.geteuid()).pw_name,
        service_name="Tailscale",
        checks=[
            check_row(
                TailscaleNyxmonTarget(hostname="owned", url="http://192.0.2.20:9107/.well-known/tailscale"),
                SecretStr("synthetic-only"),
            )
        ],
    )
    return subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / "src/ops_deploy/infra/files/tailscale_nyxmon.py"), action],
        input=json.dumps(cfg),
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_dedicated_sql_changes_only_original_configuration_columns(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    sql_fixture(path)
    before = path.read_bytes()
    assert sql_run(path, "check").stdout.strip() == "pending"
    assert path.read_bytes() == before
    result = sql_run(path, "apply")
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute(
            "SELECT status,next_check_time,processing_started_at,disabled FROM health_check WHERE id=1"
        ).fetchone() == ("critical", 1234, 5678, 1)
        assert db.execute("SELECT check_type,url,check_interval FROM health_check WHERE id=2").fetchone() == (
            "sentinel",
            "http://unrelated",
            10,
        )
    current = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ctime_ns)
    assert sql_run(path, "check").stdout.strip() == "current"
    assert (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ctime_ns) == current


def test_sql_missing_and_corrupt_are_distinct_without_creation(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    assert sql_run(path, "check").stdout.strip() == "absent"
    assert not path.exists()
    path.write_bytes(b"not a database")
    before = path.read_bytes()
    result = sql_run(path, "apply")
    assert result.returncode != 0
    assert "suppressed" in result.stderr
    assert path.read_bytes() == before
    assert "synthetic-only" not in result.stdout + result.stderr


GOLDEN = Path(__file__).parent / "golden" / "tailscale_metrics"
METRICS_FILES = (
    "tailscale-metrics-collector.service",
    "tailscale-metrics-collector.timer",
    "tailscale-metrics-endpoint.service",
    "tailscale_metrics_exporter.py",
    "tailscale_metrics_httpd.py",
)


@pytest.mark.parametrize("name", METRICS_FILES)
def test_metrics_endpoint_files_are_golden(name: str) -> None:
    """The endpoint's units and programs: a changed byte restarts the collector or the endpoint."""

    assert_golden(GOLDEN / name, render(TailscaleMetricsConfig(), name))


def test_missing_binary_defers_preferences_until_native_prerequisites(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyinfra.api import DeployError

    from ops_deploy.infra.tailscale import deploy as module

    class Missing:
        def get_fact(self, *args: Any, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(module, "host", Missing())
    monkeypatch.setattr(
        module, "probe", lambda *args, **kwargs: pytest.fail("No failing native probe before package install")
    )
    commands = list(cast(Any, module.preferences).__wrapped__(TailscaleConfig(hostname="owned").model_dump_json()))
    assert len(commands) == 1
    assert "apply-prefs" in commands[0].get_raw_value()

    class Present:
        def get_fact(self, *args: Any, **kwargs: Any) -> str:
            return "/usr/bin/tailscale"

    monkeypatch.setattr(module, "host", Present())
    monkeypatch.setattr(module, "probe", lambda *args, **kwargs: None)
    with pytest.raises(DeployError, match="unavailable"):
        list(cast(Any, module.preferences).__wrapped__(TailscaleConfig(hostname="owned").model_dump_json()))


# -- legacy deb822 stanza (staging's consolidated Debian 13 sources) ---------------------------

CONSOLIDATED = """Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://packages.redis.io/deb
Suites: trixie
Components: main
Signed-By: /etc/apt/keyrings/redis.gpg

Types: deb
URIs: https://pkgs.tailscale.com/stable/debian
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/tailscale-archive-keyring.gpg
"""
WITHOUT_TAILSCALE = CONSOLIDATED.split("\n\nTypes: deb\nURIs: https://pkgs.tailscale.com")[0] + "\n"
LEGACY = "/etc/apt/sources.list.d/staging-trixie.sources"
REPO_URL = "https://pkgs.tailscale.com/stable/debian"


def _stanza() -> str:
    from ops_deploy.infra.tailscale.deploy import legacy_stanza

    cfg = TailscaleConfig(hostname="owned")
    return legacy_stanza(REPO_URL, "trixie", cfg.repo_component, cfg.repo_keyring)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (CONSOLIDATED, WITHOUT_TAILSCALE),
        # the stanza first, last without a final newline, alone
        (
            "Types: deb\nURIs: https://pkgs.tailscale.com/stable/debian\nSuites: trixie\nComponents: main\n"
            "Signed-By: /usr/share/keyrings/tailscale-archive-keyring.gpg\n\nTypes: deb\nURIs: x\n",
            "Types: deb\nURIs: x\n",
        ),
        (CONSOLIDATED.rstrip("\n"), WITHOUT_TAILSCALE),
        (
            "Types: deb\nURIs: https://pkgs.tailscale.com/stable/debian\nSuites: trixie\nComponents: main\n"
            "Signed-By: /usr/share/keyrings/tailscale-archive-keyring.gpg\n",
            "",
        ),
        # another suite, an extra field or another key stays
        (
            CONSOLIDATED.replace(
                "Suites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/t",
                "Suites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/t",
            ),
            None,
        ),
        (CONSOLIDATED.replace("tailscale-archive-keyring.gpg\n", "tailscale-archive-keyring.gpg\nEnabled: no\n"), None),
        (CONSOLIDATED.replace("tailscale-archive-keyring.gpg", "other.gpg"), None),
        (WITHOUT_TAILSCALE, None),
    ],
)
def test_only_the_exact_legacy_stanza_is_removed(text: str, expected: str | None) -> None:
    from ops_deploy.infra.tailscale.deploy import without_legacy_stanza

    assert without_legacy_stanza(text, _stanza()) == (text if expected is None else expected)


@pytest.mark.parametrize(
    "paths",
    [
        ("/etc/apt/sources.list.d/tailscale.sources",),
        ("/etc/apt/sources.list.d/staging-trixie.list",),
        ("relative.sources",),
        ("/etc/apt/../x.sources",),
    ],
)
def test_legacy_files_must_be_other_absolute_sources_files(paths: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        TailscaleConfig(hostname="owned", repo_legacy_deb822_files=paths)


def _cleanup_run(current: str | None) -> Any:
    import base64

    from ops_deploy.infra.tailscale.deploy import remove_legacy_stanzas
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    cfg = TailscaleConfig(hostname="owned", repo_legacy_deb822_files=(LEGACY,))
    answer = ["absent"] if current is None else ["present", base64.b64encode(current.encode()).decode()]
    responses: dict[Any, Any] = {"base64 -w0": answer, **fakehost.stat(LEGACY, user="root", mode="-rw-r--r--")}

    def deploy() -> None:
        remove_legacy_stanzas(cfg, REPO_URL, "trixie")

    return run_deploy_fake(deploy, responses=responses)


def test_the_stanza_is_removed_from_the_consolidated_file_with_a_backup() -> None:
    run = _cleanup_run(CONSOLIDATED)

    assert run.succeeded, run.error
    assert run.upload(LEGACY) == WITHOUT_TAILSCALE.encode()
    (backup,) = [path for path, _ in run.uploads if path.startswith(LEGACY + ".pre-tailscale-")]
    assert backup.endswith("~")
    assert run.upload(backup) == CONSOLIDATED.encode()


@pytest.mark.parametrize("current", [WITHOUT_TAILSCALE, None])
def test_a_file_without_the_stanza_or_no_file_changes_nothing(current: str | None) -> None:
    run = _cleanup_run(current)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_a_legacy_file_that_is_not_utf8_refuses_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64

    from pyinfra.api import DeployError

    from ops_deploy.infra.tailscale import deploy as module

    answer = "present\n" + base64.b64encode(b"\xff\xfe").decode()
    monkeypatch.setattr(module, "probe", lambda *args, **kwargs: answer)
    with pytest.raises(DeployError, match="as UTF-8 text; nothing was changed"):
        module._read(LEGACY)
