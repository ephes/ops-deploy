"""Port of the ``vaultwarden_remove`` role as ``playbooks/remove-vaultwarden.yml`` runs it.

Never dispatched without ``confirm``. The data directory ``/var/lib/vaultwarden``
and ``/var/log/vaultwarden`` always stay: the playbook removes them only with
``-e remove_data=true`` (or ``-e vaultwarden_remove_data=true``), which
``just remove-one vaultwarden`` never passes, and that path (with its archive
under ``/root``) is not ported.

Order and semantics as the role's: stop and disable (failures ignored) only
when a unit file exists; purge (``remove_config``) or remove both packages;
the systemd drop-in directory; a daemon reload; the Traefik route (behind the
transaction guard); the vendor repository line (``apt_repository: absent``,
from every ``.list`` source, followed by an apt cache update when one was
removed), its signing key and ``/etc/vaultwarden.env``. The repository suite
is ``bookworm`` on Ubuntu and the release codename elsewhere, as in the role.

Unlike the role, Traefik is not restarted after the route went (its file
provider watches the directory), as the deploy port never restarts it.
"""

from __future__ import annotations

import shlex
from collections.abc import Generator

from pydantic import StrictBool
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.server import Command
from pyinfra.operations import apt, systemd

from ops_deploy.base._common import RoleConfig, output, require_linux
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent
from ops_deploy.services._lifecycle.apt_purge import purge
from ops_deploy.services.vaultwarden.deploy import DROPIN_DIR, ENV_PATH, KEYRING, PACKAGES

UNIT_PATHS = (
    "/etc/systemd/system/vaultwarden.service",
    "/lib/systemd/system/vaultwarden.service",
    "/usr/lib/systemd/system/vaultwarden.service",
)
ROUTE = "/etc/traefik/dynamic/vaultwarden.yml"
REPO_URL = "https://vaultwarden-deb.pages.dev"
# apt_repository (state: absent) for one line: every enabled copy in
# /etc/apt/sources.list and sources.list.d/*.list goes (compared as the
# module parses it: whitespace-separated fields, a trailing comment ignored);
# commented-out copies stay, as the module removes only enabled sources. A
# file left without lines is deleted. Unlike the module, which rewrites every
# changed file in its normalised form, the other lines stay as they are (read
# and written as text, so CRLF endings become LF); a symlinked .list file is
# replaced by a regular file, not written through; and a failing apt-get
# update (run once, the module retries five times) does not put the line
# back: a rerun finds it absent and goes on. Prints "absent", "present" or,
# with apply, "removed".
REPOSITORY = r"""import glob, os, sys, tempfile
action, keyring, url = sys.argv[1:4]
release = {}
with open('/etc/os-release') as handle:
    for line in handle:
        key, _, value = line.strip().partition('=')
        release[key] = value.strip(chr(34) + chr(39))
suite = 'bookworm' if release.get('ID') == 'ubuntu' else release.get('VERSION_CODENAME', '')
if not suite:
    raise SystemExit('no release codename')
wanted = ' '.join(['deb', '[signed-by=' + keyring + ']', url, suite, 'main'])
def parsed(line):
    line = line.strip()
    if line.startswith('#'):
        return None
    index = line.find('#')
    if index > 0:
        line = line[:index]
    return ' '.join(line.split())
files = ['/etc/apt/sources.list'] + sorted(glob.glob('/etc/apt/sources.list.d/*.list'))
changed = []
for path in files:
    if not os.path.isfile(path):
        continue
    with open(path) as handle:
        lines = handle.readlines()
    kept = [line for line in lines if parsed(line) != wanted]
    if kept != lines:
        changed.append((path, kept))
if action == 'inspect' or not changed:
    print('present' if changed else 'absent')
    raise SystemExit(0)
for path, kept in changed:
    if not kept:
        os.remove(path)
        continue
    mode = os.stat(path).st_mode & 0o7777
    descriptor, temporary = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.vaultwarden-')
    with os.fdopen(descriptor, 'w') as handle:
        handle.writelines(kept)
    os.chmod(temporary, mode)
    os.replace(temporary, path)
print('removed')
"""


class VaultwardenRemoveConfig(RoleConfig):
    """The role's defaults; ``remove_data`` is not offered (see the module docstring)."""

    confirm: StrictBool = False
    remove_config: StrictBool = True
    remove_repository: StrictBool = True
    remove_traefik: StrictBool = True


def _repository(action: str) -> str:
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", REPOSITORY, action, str(KEYRING), REPO_URL])


@operation()
def _repository_absent() -> Generator[StringCommand, None, None]:
    state = host.get_fact(Command, command=_repository("inspect"))
    if state == "present":
        # update_cache: the module refreshes the cache after a change.
        yield StringCommand(_repository("apply"))
        yield StringCommand("apt-get", "-o", "DPkg::Lock::Timeout=60", "update")
    elif state != "absent":
        raise DeployError("Cannot read the apt sources for the Vaultwarden repository")


@deploy("Remove Vaultwarden")
def remove_vaultwarden(cfg: VaultwardenRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("Vaultwarden removal not confirmed (confirm=true)")
    require_linux("Vaultwarden removal")
    probe = "; ".join(f"{{ test -e {path} || test -L {path}; }} && echo {path}" for path in UNIT_PATHS)
    if output(f"{probe}; true").strip():
        service_absent(
            name="Stop and disable Vaultwarden", service="vaultwarden", label="Vaultwarden removal", _ignore_errors=True
        )
    if cfg.remove_config:
        purge(name="Remove Vaultwarden packages", packages=PACKAGES, label="Vaultwarden removal")
    else:
        # purge: false removes the installed packages and keeps their config files.
        apt.packages(name="Remove Vaultwarden packages", packages=list(PACKAGES), present=False)
    absent(f"Remove {DROPIN_DIR}", str(DROPIN_DIR))
    systemd.daemon_reload(name="Reload systemd")
    if cfg.remove_traefik:
        absent(f"Remove {ROUTE}", ROUTE)
    if cfg.remove_repository:
        _repository_absent(name="Remove the Vaultwarden apt repository")
        absent(f"Remove {KEYRING}", str(KEYRING))
    if cfg.remove_config:
        absent(f"Remove {ENV_PATH}", str(ENV_PATH))
