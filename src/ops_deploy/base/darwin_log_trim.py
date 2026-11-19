"""Daily size-capped rotation of launchd-written log files on macOS.

launchd opens a job's ``StandardOutPath``/``StandardErrorPath`` once, in
append mode, and keeps the descriptor for the life of the process. newsyslog
can only rename such a file: the process then goes on writing to the renamed
(and, once compressed, deleted) inode. This deploy installs a root
LaunchDaemon (fixed label ``de.wersdoerfer.log-trim``) that runs the program
``files/darwin_log_trim.py`` daily: copy and compress, truncate in place,
publish as a generation (its docstring has the safety rules).

Fixed paths: the program ``/usr/local/libexec/ops-deploy/log-trim``
(root:wheel 0755), the plist in ``/Library/LaunchDaemons`` (root:wheel 0644),
the job's log ``/private/var/log/ops-log-trim.log`` and the load marker in
``/private/var/db/ops-deploy``. The deploy refuses a host where a directory
on those paths, or the installed program or plist, is not root's alone
(owner, mode, ACL), and (re)loads the job when the fingerprint recorded at the
last load differs or the job is not loaded.
"""

from __future__ import annotations

import hashlib
import posixpath
import shlex
from importlib.resources import files as files_of_package
from io import StringIO
from xml.sax.saxutils import escape

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Os
from pyinfra.operations import files, server

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe

TRIM_PROGRAM = files_of_package("ops_deploy.base").joinpath("files/darwin_log_trim.py")
PYTHON = "/usr/bin/python3"
MARKER_DIR = "/private/var/db/ops-deploy"
LOG_ROOT = "/private/var/log/"
# Fixed, so a config cannot point the root job or its files anywhere else.
LABEL = "de.wersdoerfer.log-trim"
SCRIPT_PATH = "/usr/local/libexec/ops-deploy/log-trim"
PLIST_PATH = f"/Library/LaunchDaemons/{LABEL}.plist"
LOG_PATH = "/private/var/log/ops-log-trim.log"
MARKER_PATH = f"{MARKER_DIR}/{LABEL}.loaded"


class DarwinLogTrimConfig(RoleConfig):
    """Which launchd logs to cap, how large, how many copies, and when."""

    logs: tuple[AbsolutePath, ...] = Field(min_length=1)
    max_bytes: int = Field(default=50 * 1024 * 1024, ge=1024 * 1024)
    keep: int = Field(default=5, ge=1, le=50)
    hour: int = Field(default=4, ge=0, le=23)
    minute: int = Field(default=15, ge=0, le=59)

    @model_validator(mode="after")
    def _paths(self) -> DarwinLogTrimConfig:
        if any(posixpath.normpath(p) != p or "//" in p for p in self.logs):
            raise ValueError("paths must be normalised absolute file paths")
        # Canonical paths below /private/var/log only: the program refuses any
        # other spelling (/var is a symbolic link) and any directory not root's.
        if not all(p.startswith(LOG_ROOT) and p.count("/") >= 4 for p in self.logs):
            raise ValueError(f"logs must be canonical paths below {LOG_ROOT}")
        # APFS volumes are case-insensitive by default: compare folded names.
        folded = [p.casefold() for p in self.logs]
        if len(set(folded)) != len(folded):
            raise ValueError("logs must not repeat")
        if LOG_PATH.casefold() in folded:
            raise ValueError(f"{LOG_PATH} is the job's own log")
        generations = tuple(f".{n}.gz" for n in range(1, self.keep + 1))
        for path in (*folded, LOG_PATH.casefold()):
            for log in folded:
                rest = path[len(log) :] if path.startswith(log) and path != log else None
                if rest is not None and (rest.startswith(".trim-") or rest in generations):
                    raise ValueError("a log collides with another log's rotated copies")
        return self


def render_script() -> str:
    return TRIM_PROGRAM.read_text()


def render_plist(cfg: DarwinLogTrimConfig) -> str:
    args = [PYTHON, "-I", SCRIPT_PATH, str(cfg.max_bytes), str(cfg.keep), *cfg.logs]
    arguments = "".join(f"\n    <string>{escape(a)}</string>" for a in args)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Managed by ops-deploy (darwin_log_trim). -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{escape(LABEL)}</string>
  <key>ProgramArguments</key>
  <array>{arguments}
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>{cfg.hour}</integer>
    <key>Minute</key>
    <integer>{cfg.minute}</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>{escape(LOG_PATH)}</string>
  <key>StandardErrorPath</key>
  <string>{escape(LOG_PATH)}</string>
  <key>LowPriorityIO</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"""


def fingerprint(cfg: DarwinLogTrimConfig) -> str:
    """What the loaded job was loaded from: the plist and the program."""

    return hashlib.sha256((render_plist(cfg) + "\0" + render_script()).encode()).hexdigest()


def loaded_command(cfg: DarwinLogTrimConfig) -> str:
    """The fingerprint the job was last loaded with, or ``missing`` (not loaded, or no marker)."""

    label = shlex.quote(f"system/{LABEL}")
    marker = shlex.quote(MARKER_PATH)
    return f"/bin/launchctl print {label} >/dev/null 2>&1 && cat {marker} 2>/dev/null || echo missing"


def load_command(cfg: DarwinLogTrimConfig) -> str:
    target = shlex.quote(f"system/{LABEL}")
    marker = shlex.quote(MARKER_PATH)
    # The old marker goes first, so a load that stops halfway is redone next
    # time; enable before bootstrap: launchd refuses to bootstrap a disabled job.
    return (
        f"/bin/rm -f {marker} && /bin/launchctl enable {target} && "
        f"{{ /bin/launchctl bootout {target} 2>/dev/null; true; }} && "
        f"/bin/launchctl bootstrap system {shlex.quote(PLIST_PATH)} && "
        f"/bin/mkdir -p {MARKER_DIR} && printf '%s\\n' {fingerprint(cfg)} > {marker}"
    )


def ancestry_command(cfg: DarwinLogTrimConfig) -> str:
    """Prints ``trusted`` if every directory launchd passes through to run the job is root's alone."""

    paths = [SCRIPT_PATH.rsplit("/", 1)[0], "/Library/LaunchDaemons", MARKER_DIR, LOG_PATH.rsplit("/", 1)[0]]
    installed = [SCRIPT_PATH, PLIST_PATH]
    program = (
        "import os,re,stat,subprocess,sys\n"
        "def acl(c):\n"
        " l=subprocess.run(['/bin/ls','-lde',c],capture_output=True,text=True).stdout.splitlines()\n"
        " return not l or (len(l[0])>10 and l[0][10]=='+') or any(re.match(r'^\\s*[0-9]+: ',x) for x in l[1:])\n"
        "def bad(c,kind):\n"
        " i=os.lstat(c)\n"
        " return not kind(i.st_mode) or i.st_uid!=0 or i.st_mode&0o022 or acl(c)\n"
        "ok=True\n"
        "cut=sys.argv.index('--')\n"
        "for p in sys.argv[1:cut]:\n"
        " c='/'\n"
        " for part in ['']+[x for x in p.split('/') if x]:\n"
        "  c=os.path.join(c,part) if part else '/'\n"
        "  if not os.path.lexists(c): break\n"
        "  if bad(c,stat.S_ISDIR): ok=False; print('untrusted '+c)\n"
        "for f in sys.argv[cut+1:]:\n"
        " if os.path.lexists(f) and bad(f,stat.S_ISREG): ok=False; print('untrusted '+f)\n"
        "if ok: print('trusted')\n"
    )
    return shlex.join([PYTHON, "-I", "-c", program, *paths, "--", *installed])


@deploy("Deploy darwin log trim")
def deploy_darwin_log_trim(cfg: DarwinLogTrimConfig) -> None:
    if host.get_fact(Os) != "Darwin":
        raise DeployError("darwin_log_trim supports macOS hosts only")
    trust = probe(ancestry_command(cfg), name="Log trim paths are root's alone")
    if trust != "trusted":
        bad = ", ".join(line.removeprefix("untrusted ") for line in (trust or "probe failed").splitlines())
        raise DeployError(f"darwin_log_trim: not root's alone (owner, mode or ACL): {bad}")
    loaded = probe(loaded_command(cfg), name="Log trim job loaded")
    files.directory(
        name="Ensure the log trim program directory",
        path=str(SCRIPT_PATH).rsplit("/", 1)[0],
        user="root",
        group="wheel",
        mode="0755",
    )
    files.put(
        name="Install the log trim program",
        src=StringIO(render_script()),
        dest=SCRIPT_PATH,
        user="root",
        group="wheel",
        mode="0755",
    )
    files.put(
        name="Install the log trim LaunchDaemon",
        src=StringIO(render_plist(cfg)),
        dest=PLIST_PATH,
        user="root",
        group="wheel",
        mode="0644",
    )
    server.shell(
        name="Load the log trim LaunchDaemon",
        commands=[load_command(cfg)],
        _if=lambda: loaded != fingerprint(cfg),
    )
    mark_read_only(
        server.shell(
            name="Verify the log trim LaunchDaemon is loaded",
            commands=[f"/bin/launchctl print system/{shlex.quote(LABEL)} >/dev/null"],
        )
    )
