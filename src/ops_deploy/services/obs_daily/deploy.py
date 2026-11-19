"""Observability routine: a daily evidence pack for an LLM triage, and a status endpoint for Nyxmon.

Native to ops-deploy. The daily job looks for problems nobody knows about yet,
so it holds no list of known problems:

- ``<service_name>-pack.timer`` runs ``files/obs_pack.py`` (Python stdlib
  only) once a day as the Nyxmon user. It writes an evidence pack from Loki
  and InfluxDB that maps the day for an open-ended LLM review (raw log
  samples of every service at any level, log templates new to a stored
  baseline with raw examples, volume changes per service, metric series
  that deviate from their own two weeks, series that fell silent or
  appeared, filesystems filling up, certificates expiring, systemd restarts,
  Nyxmon checks not ok) to ``site_path/packs``. Raw log text leaves the host
  for the review (owner decision 2026-11-19, docs/services/obs_daily.md).
- The LLM triage runs elsewhere (the Studio). It fetches the pack, drills
  down with bounded read-only queries and hands its result back over root
  SSH through ``files/obs_ctl.py`` (``pack``, ``query``, ``deliver``,
  ``launchd``); ``deliver`` sends the digest as one Telegram message through
  Nyxmon's own notifier (``files/obs_daily_send.py`` with Nyxmon's Python and
  environment file) and records the result in ``site_path/triage.json``.
- ``<service_name>-status.service`` (``files/obs_status.py``) serves
  ``GET /.well-known/obs-daily`` on loopback for Nyxmon: age of the last pack
  and of the last delivered triage, and systemd units in a restart or failure
  loop on any log-shipping host (from Loki).

The deploy also provisions the read-only InfluxDB token
(``files/influx_read_token.py``: ``influx auth create --read-bucket`` inside
the InfluxDB container; the token never leaves the host) and checks once that
Nyxmon's notifier loads with credentials. It never runs the pack or sends a
message itself.
"""

from __future__ import annotations

import json
import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

from pydantic import Field, StrictFloat, StrictInt, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import service_rollout, systemd_unit
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.services.nyxmon_site_checks.deploy import PlainPath

FILES = Path(__file__).parent / "files"
PACK_SCRIPT = (FILES / "obs_pack.py").read_text()
STATUS_SCRIPT = (FILES / "obs_status.py").read_text()
CTL_SCRIPT = (FILES / "obs_ctl.py").read_text()
SEND_SCRIPT = (FILES / "obs_daily_send.py").read_text()
TOKEN_SCRIPT = (FILES / "influx_read_token.py").read_text()
PYTHON = "/usr/bin/python3"
TOKEN_DESCRIPTION = "obs-daily read-only"  # followed by the token file: one deployment's tokens only

Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")]
TlsHost = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?$")]
LocalUrl = Annotated[str, Field(pattern=r"^http://(127\.0\.0\.1|localhost):[0-9]{1,5}$")]
Listen = Annotated[str, Field(pattern=r"^127\.0\.0\.1:[0-9]{1,5}$")]
LineFilter = Annotated[str, Field(min_length=3, max_length=200, pattern=r"^[^\x00-\x1f]+$")]
OnCalendar = Annotated[str, Field(pattern=r"^[A-Za-z0-9*:/ ,.~-]{1,64}$")]
Positive = Annotated[StrictInt, Field(ge=1)]


class Caps(RoleConfig):
    """How many entries each list of the pack keeps (the LLM reads the pack in one go)."""

    volume: Annotated[StrictInt, Field(ge=1, le=200)] = 20
    signatures: Annotated[StrictInt, Field(ge=1, le=200)] = 40
    units: Annotated[StrictInt, Field(ge=1, le=200)] = 15
    deviations: Annotated[StrictInt, Field(ge=1, le=200)] = 25
    series: Annotated[StrictInt, Field(ge=1, le=200)] = 30


class ObsDailyConfig(BaseServiceConfig):
    """The pack, the hand-over point and the status endpoint on the host that runs Loki, InfluxDB and Nyxmon.

    ``service_name`` prefixes the units (``-pack`` service and timer at
    ``on_calendar``, local time, ``Persistent=true``; ``-status`` service).
    ``user`` is the Nyxmon user: the pack reads Nyxmon's database read-only
    and the sender uses Nyxmon's notifier. ``site_path`` holds packs, the
    template baseline and the status files (``user:state_group``, setgid).
    ``sleeping_hosts`` pause their logs and metrics by design (atlas).
    ``log_hosts`` must ship logs every hour; the status endpoint reports one
    that does not until it is removed here.
    ``loki_exclude_lines`` drop Loki's own logs, which come back through
    journald as errors. ``tls_hosts`` are ``host[:port]`` whose certificate
    the pack checks. ``sample_lines_per_window`` lines per service and
    6-hour window go into ``logs.samples``, which shrinks its detail to fit
    ``sample_budget_bytes``; ``pack_max_bytes`` bounds the whole pack (the
    triage model reads it in one go).
    """

    service_name: ServiceName = "obs-daily"
    user: UnixUser = "nyxmon"
    site_path: PlainPath = PurePosixPath("/var/lib/obs-daily")
    state_group: UnixUser = "adm"
    config_dir: PlainPath = PurePosixPath("/etc/obs-daily")
    lib_dir: PlainPath = PurePosixPath("/usr/local/lib/obs-daily")
    on_calendar: OnCalendar = "*-*-* 06:30:00"
    nyxmon_site: PlainPath = PurePosixPath("/home/nyxmon/site")
    loki_url: LocalUrl = "http://127.0.0.1:3101"
    influx_url: LocalUrl = "http://127.0.0.1:8086"
    influx_container: Name = "graphyard-influxdb"
    influx_org: Name = "graphyard"
    influx_bucket: Name = "graphyard"
    status_listen: Listen = "127.0.0.1:9123"
    sleeping_hosts: tuple[Name, ...] = ()
    log_hosts: tuple[Name, ...] = ()
    tls_hosts: tuple[TlsHost, ...] = ()
    loki_exclude_lines: tuple[LineFilter, ...] = ('"syslog_identifier":"logyard-loki"',)
    caps: Caps = Caps()
    backfill_days: Annotated[StrictInt, Field(ge=0, le=13)] = 7
    new_signature_min: Positive = 3
    deviation_z: Annotated[StrictFloat, Field(ge=2)] = 6.0
    deviation_relative: Annotated[StrictFloat, Field(gt=0)] = 0.3
    pack_retention_days: Annotated[StrictInt, Field(ge=7, le=400)] = 35
    signature_retention_days: Annotated[StrictInt, Field(ge=7, le=90)] = 30
    loop_window_seconds: Annotated[StrictInt, Field(ge=300, le=86400)] = 3600
    loop_events: Annotated[StrictInt, Field(ge=2)] = 5
    cache_seconds: Annotated[StrictInt, Field(ge=30, le=900)] = 60
    sample_lines_per_window: Annotated[StrictInt, Field(ge=10, le=500)] = 100
    sample_budget_bytes: Annotated[StrictInt, Field(ge=50_000, le=1_500_000)] = 500_000
    pack_max_bytes: Annotated[StrictInt, Field(ge=200_000, le=2_000_000)] = 1_200_000

    @model_validator(mode="after")
    def _distinct(self) -> ObsDailyConfig:
        for name in ("sleeping_hosts", "tls_hosts", "log_hosts"):
            values = getattr(self, name)
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must be distinct")
        if self.backfill_days >= self.signature_retention_days:
            raise ValueError("backfill_days must be shorter than signature_retention_days")
        for path in (self.site_path, self.lib_dir, self.config_dir, self.nyxmon_site):
            if str(path).startswith("//"):
                raise ValueError(f"{path} must start with a single slash")
        # Root runs obs_ctl.py from lib_dir with config_dir's config: neither may sit in (or hold)
        # a directory the Nyxmon user can change.
        for trusted in (self.lib_dir, self.config_dir):
            for writable in (self.site_path, self.nyxmon_site):
                if trusted.is_relative_to(writable) or writable.is_relative_to(trusted):
                    raise ValueError(f"{trusted} must not overlap {writable}")
        return self

    @property
    def pack_unit(self) -> str:
        return f"{self.service_name}-pack"

    @property
    def status_unit(self) -> str:
        return f"{self.service_name}-status"

    @property
    def config_path(self) -> PurePosixPath:
        return self.config_dir / "config.json"

    @property
    def token_path(self) -> PurePosixPath:
        return self.config_dir / "influx-token"

    def script(self, name: str) -> PurePosixPath:
        return self.lib_dir / name

    @property
    def nyxmon_python(self) -> PurePosixPath:
        return self.nyxmon_site / ".venv/bin/python"

    @property
    def nyxmon_env(self) -> PurePosixPath:
        return self.nyxmon_site / ".env"

    @property
    def nyxmon_db(self) -> PurePosixPath:
        return self.nyxmon_site / "db.sqlite3"

    @property
    def status_url(self) -> str:
        return f"http://{self.status_listen}/.well-known/obs-daily"

    def ctl_command(self, action: str) -> str:
        """The command the triage machine runs over root SSH."""

        return shlex.join([PYTHON, "-I", str(self.script("obs_ctl.py")), "--config", str(self.config_path), action])


# -- rendered files ------------------------------------------------------------------------


def render_config(cfg: ObsDailyConfig) -> str:
    """The shared ``config.json`` of the pack, the status endpoint and the hand-over point."""

    config: dict[str, Any] = {
        "state_dir": str(cfg.site_path),
        "loki_url": cfg.loki_url,
        "influx": {
            "url": cfg.influx_url,
            "org": cfg.influx_org,
            "bucket": cfg.influx_bucket,
            "token_file": str(cfg.token_path),
        },
        "nyxmon_db": str(cfg.nyxmon_db),
        "sleeping_hosts": list(cfg.sleeping_hosts),
        "log_hosts": list(cfg.log_hosts),
        "tls_hosts": list(cfg.tls_hosts),
        "loki_exclude_lines": list(cfg.loki_exclude_lines),
        "caps": cfg.caps.model_dump(mode="json"),
        "backfill_days": cfg.backfill_days,
        "new_signature_min": cfg.new_signature_min,
        "deviation_z": cfg.deviation_z,
        "deviation_relative": cfg.deviation_relative,
        "pack_retention_days": cfg.pack_retention_days,
        "signature_retention_days": cfg.signature_retention_days,
        "status_listen": cfg.status_listen,
        "loop_window_seconds": cfg.loop_window_seconds,
        "loop_events": cfg.loop_events,
        "cache_seconds": cfg.cache_seconds,
        "sample_lines_per_window": cfg.sample_lines_per_window,
        "sample_budget_bytes": cfg.sample_budget_bytes,
        "pack_max_bytes": cfg.pack_max_bytes,
        "sender": {
            "user": cfg.user,
            "python": str(cfg.nyxmon_python),
            "script": str(cfg.script("obs_daily_send.py")),
            "env_file": str(cfg.nyxmon_env),
            "cwd": str(cfg.nyxmon_site),
        },
    }
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def _sandbox(cfg: ObsDailyConfig, *, writable: bool) -> list[str]:
    lines = ["NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=read-only"]
    if writable:
        lines.append(f"ReadWritePaths={cfg.site_path}")
    return lines


def render_pack_service(cfg: ObsDailyConfig) -> str:
    """The Nyxmon user, a read-only system, writing only ``site_path``."""

    command = shlex.join([PYTHON, "-I", str(cfg.script("obs_pack.py")), "--config", str(cfg.config_path)])
    return "\n".join(
        [
            "[Unit]",
            "Description=Daily observability evidence pack for the LLM triage",
            "After=network-online.target docker.service",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            f"User={cfg.user}",
            f"Group={cfg.user}",
            "UMask=0027",
            f"ExecStart={command}",
            "# The first run fills the template baseline from earlier days first.",
            "TimeoutStartSec=3600",
            "Nice=10",
            *_sandbox(cfg, writable=True),
            "",
        ]
    )


def render_pack_timer(cfg: ObsDailyConfig) -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Build the daily observability evidence pack",
            "",
            "[Timer]",
            f"OnCalendar={cfg.on_calendar}",
            "Persistent=true",
            "AccuracySec=1min",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )


def render_status_service(cfg: ObsDailyConfig) -> str:
    command = shlex.join([PYTHON, "-I", str(cfg.script("obs_status.py")), "--config", str(cfg.config_path)])
    return "\n".join(
        [
            "[Unit]",
            "Description=Observability routine status endpoint for Nyxmon",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            f"User={cfg.user}",
            f"Group={cfg.user}",
            f"ExecStart={command}",
            "Restart=on-failure",
            "RestartSec=10",
            *_sandbox(cfg, writable=False),
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def token_command(cfg: ObsDailyConfig, mode: str) -> str:
    args = [
        mode,
        cfg.influx_url,
        cfg.influx_org,
        cfg.influx_bucket,
        cfg.influx_container,
        str(cfg.token_path),
        cfg.user,
        f"{TOKEN_DESCRIPTION} {cfg.token_path}",
    ]
    return shlex.join([PYTHON, "-I", "-c", TOKEN_SCRIPT, *args])


def sender_check_command(cfg: ObsDailyConfig) -> str:
    """Load Nyxmon's notifier as ``obs_ctl.py deliver`` will (user, environment file, Python); sends nothing.

    The sender reads Nyxmon's environment file itself, as the Nyxmon user:
    ``--property=EnvironmentFile=`` would have systemd open that Nyxmon-writable
    path as root.
    """

    return shlex.join(
        [
            "systemd-run",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            f"--uid={cfg.user}",
            f"--gid={cfg.user}",
            f"--working-directory={cfg.nyxmon_site}",
            "--property=RuntimeMaxSec=60",
            str(cfg.nyxmon_python),
            "-I",
            str(cfg.script("obs_daily_send.py")),
            "--env-file",
            str(cfg.nyxmon_env),
            "--check",
        ]
    )


def trusted_paths_command(cfg: ObsDailyConfig) -> str:
    """Prints ``trusted`` when every file the deploy writes as root (scripts, config, token) and
    every directory above them belong to root and are not writable by group or others (a link
    counts as writable: its mode is 0777); paths that do not exist yet are skipped (their existing
    ancestors are checked). Run while planning, before the first privileged access, and again
    after the writes."""

    program = (
        "import os,sys\n"
        "bad=[]\n"
        "cut=sys.argv.index('--')\n"
        "for link in sys.argv[cut+1:]:\n"
        "    if os.path.islink(link):\n"
        "        bad.append(link)\n"
        "for target in sys.argv[1:cut]:\n"
        "    path=target\n"
        "    while True:\n"
        "        try:\n"
        "            st=os.lstat(path)\n"
        "        except FileNotFoundError:\n"
        "            parent=os.path.dirname(path)\n"
        "            if parent==path:\n"
        "                break\n"
        "            path=parent\n"
        "            continue\n"
        "        if st.st_uid!=0 or st.st_mode&0o022:\n"
        "            bad.append(path)\n"
        "        parent=os.path.dirname(path)\n"
        "        if parent==path:\n"
        "            break\n"
        "        path=parent\n"
        "print('trusted' if not bad else 'untrusted: '+' '.join(sorted(set(bad))))\n"
    )
    paths = [str(cfg.script(name)) for name in ("obs_pack.py", "obs_status.py", "obs_ctl.py", "obs_daily_send.py")]
    # site_path itself belongs to the Nyxmon user; everything above it must be root's, and it is no link.
    paths += [str(cfg.config_path), str(cfg.token_path), str(cfg.site_path.parent)]
    return shlex.join([PYTHON, "-I", "-c", program, *paths, "--", str(cfg.site_path)])


def status_probe_command(cfg: ObsDailyConfig) -> str:
    """The endpoint answers with the three sections (retried while the unit starts)."""

    program = (
        "import json,sys,time,urllib.request\n"
        "for _ in range(20):\n"
        "    try:\n"
        "        d=json.load(urllib.request.urlopen(sys.argv[1],timeout=30))\n"
        "        print('sections ok' if {'pack','triage','unit_loops'}<=set(d) else 'sections missing')\n"
        "        break\n"
        "    except OSError:\n"
        "        time.sleep(1)\n"
        "else:\n"
        "    print('unreachable')\n"
    )
    return shlex.join([PYTHON, "-I", "-c", program, cfg.status_url])


# -- the deploy ----------------------------------------------------------------------------


def _put(path: PurePosixPath, content: str, *, group: str = "root", mode: str = "0644") -> OperationMeta:
    return files.put(name=f"Install {path}", src=StringIO(content), dest=str(path), user="root", group=group, mode=mode)


def _nyxmon_present(cfg: ObsDailyConfig) -> None:
    paths = (cfg.nyxmon_python, cfg.nyxmon_env, cfg.nyxmon_db)
    tests = " && ".join(f"test -e {shlex.quote(str(path))}" for path in paths)
    message = shlex.quote(f"obs_daily needs Nyxmon on this host ({cfg.nyxmon_site})")
    mark_read_only(
        server.shell(
            name="Require Nyxmon's Python, environment file and database",
            commands=[f"id -u {shlex.quote(cfg.user)} >/dev/null && {tests} || {{ echo {message} >&2; exit 1; }}"],
        )
    )


@deploy("Observability routine: daily evidence pack and status endpoint")
def deploy_obs_daily(cfg: ObsDailyConfig, secrets: SecretValues | None = None) -> None:
    del secrets  # no deploy secrets: the InfluxDB token is made on the host, Telegram is Nyxmon's
    _nyxmon_present(cfg)
    # While planning, before any fact about the target files is read (files.put reads them as root),
    # and again when the operations run.
    planned = (probe(trusted_paths_command(cfg), name="root's target paths are root-only") or "").strip()
    if planned != "trusted":
        raise DeployError(f"obs_daily: root's target paths are not root-only: {planned or 'probe failed'}")
    verify_probe(trusted_paths_command(cfg), name="root's target paths are root-only", expect="trusted")
    files.directory(name=f"Ensure {cfg.lib_dir}", path=str(cfg.lib_dir), user="root", group="root", mode="0755")
    files.directory(name=f"Ensure {cfg.config_dir}", path=str(cfg.config_dir), user="root", group=cfg.user, mode="0750")
    files.directory(
        name=f"Ensure {cfg.site_path}", path=str(cfg.site_path), user=cfg.user, group=cfg.state_group, mode="2750"
    )
    pack_script = _put(cfg.script("obs_pack.py"), PACK_SCRIPT)
    status_script = _put(cfg.script("obs_status.py"), STATUS_SCRIPT)
    _put(cfg.script("obs_ctl.py"), CTL_SCRIPT)
    _put(cfg.script("obs_daily_send.py"), SEND_SCRIPT)
    config = _put(cfg.config_path, render_config(cfg))

    # The read-only InfluxDB token, made only when the file is missing or no longer works.
    state = probe(token_command(cfg, "check"), name="read-only InfluxDB token")
    if (state or "").strip() != "present":
        server.shell(name="Create the read-only InfluxDB token", commands=[token_command(cfg, "ensure")])
    verify_probe(token_command(cfg, "check"), name="read-only InfluxDB token", expect="present")
    ready = "obs-daily-send: notifier ready"
    verify_probe(sender_check_command(cfg), name="Nyxmon's notifier loads with credentials", expect=ready)

    verify_probe(trusted_paths_command(cfg), name="root's scripts and config sit in root-only paths", expect="trusted")

    pack_service = systemd_unit(f"{cfg.pack_unit}.service", render_pack_service(cfg))
    pack_timer = systemd_unit(f"{cfg.pack_unit}.timer", render_pack_timer(cfg))
    service_rollout(f"{cfg.pack_unit}.timer", units=[pack_service, pack_timer])
    status_service = systemd_unit(f"{cfg.status_unit}.service", render_status_service(cfg))
    # The endpoint imports obs_pack.py and reads the config at start: either change restarts it.
    service_rollout(
        f"{cfg.status_unit}.service", units=[status_service], restart_when=[pack_script, status_script, config]
    )
    verify_probe(status_probe_command(cfg), name="status endpoint answers", expect="sections ok")


__all__ = [
    "Caps",
    "ObsDailyConfig",
    "deploy_obs_daily",
    "render_config",
    "render_pack_service",
    "render_pack_timer",
    "render_status_service",
]
