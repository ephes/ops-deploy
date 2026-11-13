"""Nightly removal of macOS ``.DS_Store`` files below a few directories.

Finder writes ``.DS_Store`` into every folder it opens or copies onto a Samba
share. A Samba ``veto files`` for the name is no way out: Finder then aborts
copying any folder that contains one. This deploy lets the share accept them
and removes them later instead: ``dsstore-cleanup.timer`` starts the oneshot
``dsstore-cleanup.service``, which runs ``/usr/local/sbin/dsstore-cleanup``
(``find <dir> -xdev -type f -name .DS_Store -delete`` per directory) and logs
how many files it removed to the journal. The deploy never starts the service
itself. See ``docs/dsstore-cleanup.md``.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.files import File
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd
from ops_deploy.helpers.systemd import UNIT_DIR, service_rollout, systemd_unit

SERVICE = "dsstore-cleanup.service"
TIMER = "dsstore-cleanup.timer"
SCRIPT_PATH = "/usr/local/sbin/dsstore-cleanup"
SERVICE_PATH = str(UNIT_DIR / SERVICE)
TIMER_PATH = str(UNIT_DIR / TIMER)
SCRIPT = (Path(__file__).parent / "files" / "dsstore_cleanup.sh").read_text()
HEADER = "# Managed by ops-deploy infra.dsstore_cleanup; local changes are overwritten.\n"

# Plain absolute directories: no spaces, quotes, ``%`` (systemd specifiers) or
# ``$``, so the paths go into ExecStart= and ReadWritePaths= unquoted.
CleanupDir = Annotated[str, Field(pattern=r"^(/[A-Za-z0-9_.+-]+)+$")]
# One systemd calendar expression on one line; systemd refuses a bad one when
# the deploy starts the timer.
Calendar = Annotated[str, Field(pattern=r"^[A-Za-z0-9 *:,./~-]+$", min_length=1)]


class DsStoreCleanupConfig(RoleConfig):
    state: Literal["present", "absent"] = "present"
    # Directories searched (each on its own file system only); required when present.
    paths: tuple[CleanupDir, ...] = ()
    on_calendar: Calendar = "*-*-* 22:30:00"

    @model_validator(mode="after")
    def _paths(self) -> DsStoreCleanupConfig:
        for path in self.paths:
            if any(part in {".", ".."} for part in path.split("/")):
                raise ValueError(f"cleanup paths must not contain . or .. components: {path}")
        if len(set(self.paths)) != len(self.paths):
            raise ValueError("cleanup paths must be unique")
        if self.state == "present" and not self.paths:
            raise ValueError("dsstore cleanup needs at least one path")
        return self


def render_script() -> str:
    return SCRIPT


def render_service(cfg: DsStoreCleanupConfig) -> str:
    paths = " ".join(cfg.paths)
    return (
        f"{HEADER}"
        "[Unit]\n"
        "Description=Remove macOS .DS_Store files\n"
        "Documentation=https://github.com/ephes/ops-deploy/blob/main/docs/dsstore-cleanup.md\n"
        f"RequiresMountsFor={paths}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={SCRIPT_PATH} {paths}\n"
        "TimeoutStartSec=1h\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
        # Root, but it may only delete below the configured directories.
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        f"ReadWritePaths={paths}\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "PrivateDevices=true\n"
        "PrivateNetwork=true\n"
        "ProtectKernelTunables=true\n"
        "ProtectKernelModules=true\n"
        "ProtectControlGroups=true\n"
        "RestrictRealtime=true\n"
        "LockPersonality=true\n"
    )


def render_timer(cfg: DsStoreCleanupConfig) -> str:
    return (
        f"{HEADER}"
        "[Unit]\n"
        "Description=Nightly removal of macOS .DS_Store files\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={cfg.on_calendar}\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


@deploy("Configure the nightly .DS_Store cleanup")
def deploy_dsstore_cleanup(cfg: DsStoreCleanupConfig) -> None:
    require_linux("dsstore-cleanup")
    require_systemd("dsstore-cleanup")
    if cfg.state == "absent":
        if host.get_fact(File, path=TIMER_PATH) is not None:
            systemd.service(name=f"Stop and disable {TIMER}", service=TIMER, running=False, enabled=False)
        timer = files.file(name=f"Remove {TIMER_PATH}", path=TIMER_PATH, present=False)
        service = files.file(name=f"Remove {SERVICE_PATH}", path=SERVICE_PATH, present=False)
        files.file(name=f"Remove {SCRIPT_PATH}", path=SCRIPT_PATH, present=False)
        systemd.daemon_reload(name=f"Reload systemd after removing {TIMER}", _if=any_changed(timer, service))
        return
    files.put(
        name=f"Install {SCRIPT_PATH}",
        src=StringIO(render_script()),
        dest=SCRIPT_PATH,
        user="root",
        group="root",
        mode="0755",
    )
    service = systemd_unit(SERVICE, render_service(cfg))
    timer = systemd_unit(TIMER, render_timer(cfg))
    # Only the timer runs; a changed unit reloads systemd and restarts the
    # timer (new schedule). The cleanup service itself is never started here.
    service_rollout(TIMER, units=(service, timer))
