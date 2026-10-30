"""Daily security updates with the distribution's ``unattended-upgrades``.

There is no ops-library role to port: hosts so far ran the package defaults,
and one bootstrap playbook wrote ``20auto-upgrades`` once. This deploy owns
the policy in two drop-ins and leaves every packaged file alone, so a package
upgrade never meets a modified conffile:

* ``/etc/apt/apt.conf.d/52ops-deploy-unattended-upgrades`` turns the daily
  run on (``APT::Periodic``), replaces the packaged origin lists with
  ``#clear`` (security origins, optionally Debian's point releases and
  ``<codename>-updates``, see :func:`origins`), sets the package
  blacklist, kernel and dependency cleanup and the automatic reboot (off by
  default). It sorts after ``20auto-upgrades`` and ``50unattended-upgrades``,
  so its scalar values win and the cleared lists hold only its entries.
* ``/etc/needrestart/conf.d/60-ops-deploy-unattended-upgrades.conf`` sets
  needrestart's mode for the restarts after an upgrade (``automatic`` by
  default) and units it must never restart.

Missing packages are installed after one ``apt-get update``; nothing is
updated or upgraded otherwise, so a converged host plans no change. A
read-only check then compares the effective ``apt-config dump`` with the
policy and requires the ``apt-daily`` timers to be enabled. Debian 12 and 13
and Ubuntu 24.04 under systemd are supported; anything else is refused before
any change.
"""

from __future__ import annotations

import re
import shlex
from io import StringIO
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.deb import DebPackages
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import RoleConfig, output, require_systemd
from ops_deploy.helpers import mark_read_only

APT_DROPIN = "/etc/apt/apt.conf.d/52ops-deploy-unattended-upgrades"
NEEDRESTART_DIR = "/etc/needrestart/conf.d"
NEEDRESTART_DROPIN = f"{NEEDRESTART_DIR}/60-ops-deploy-unattended-upgrades.conf"
HEADER = "Managed by ops-deploy (base.unattended_upgrades). Do not edit by hand."

# (ID, VERSION_ID) from /etc/os-release.
SUPPORTED = frozenset({("debian", "12"), ("debian", "13"), ("ubuntu", "24.04")})
OS_PROBE = '. /etc/os-release && printf "%s %s\\n" "$ID" "$VERSION_ID"'
STAT_KIND = "LC_ALL=C LANG=C stat -c %F"

# Origins-Pattern entries; unattended-upgrade substitutes ``${distro_codename}``.
DEBIAN_SECURITY = ("origin=Debian,codename=${distro_codename}-security,label=Debian-Security",)
# The Debian main archive, which changes at point releases (the package default).
DEBIAN_POINT_RELEASES = "origin=Debian,codename=${distro_codename},label=Debian"
# Debian's ``<codename>-updates`` suite (``stable-updates``): updates that
# cannot wait for the next point release (tzdata, ca-certificates, clamav and
# the like), each part of that point release later. Same origin and label as
# the main archive, so only the codename tells them apart.
DEBIAN_STABLE_UPDATES = "origin=Debian,codename=${distro_codename}-updates,label=Debian"
# Ubuntu's packaged default without ``-updates``: the release pocket (frozen at
# release, so it only supplies new dependencies of security updates), the
# security pocket and the two ESM security pockets (used only with Ubuntu Pro).
UBUNTU_SECURITY = (
    "origin=Ubuntu,archive=${distro_codename}",
    "origin=Ubuntu,archive=${distro_codename}-security",
    "origin=UbuntuESMApps,archive=${distro_codename}-apps-security",
    "origin=UbuntuESM,archive=${distro_codename}-infra-security",
)

# A package name regex as unattended-upgrades matches it, without anything
# that could end the quoted apt.conf string or the statement.
PackagePattern = Annotated[str, Field(pattern=r"^[A-Za-z0-9.+*^$_:-]+$")]
# A systemd service name, matched in full by needrestart.
ServiceName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@:-]+\.service$")]
RebootTime = Annotated[str, Field(pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")]
NEEDRESTART_MODES = {"automatic": "a", "list": "l"}


class UnattendedUpgradesConfig(RoleConfig):
    """The host's update policy; the defaults are security updates without reboots."""

    # Debian only: also take the point-release updates of the main archive
    # (Debian's packaged default). Refused on Ubuntu, whose ``-updates``
    # pocket is never taken.
    debian_point_releases: bool = False
    # Debian only, with ``debian_point_releases``: also take the
    # ``<codename>-updates`` suite (not in Debian's packaged default).
    debian_stable_updates: bool = False
    # Package name regexes unattended-upgrades never upgrades.
    package_blacklist: tuple[PackagePattern, ...] = ()
    remove_unused_kernel_packages: bool = True
    remove_unused_dependencies: bool = False
    # Reboot at ``automatic_reboot_time`` after a run that left
    # /var/run/reboot-required; off unless the host may reboot on its own.
    automatic_reboot: bool = False
    automatic_reboot_time: RebootTime = "04:30"
    # ``APT::Periodic::AutocleanInterval`` in days (0: never).
    autoclean_interval_days: int = Field(default=7, ge=0, le=365)
    # needrestart after an upgrade: restart affected services (``automatic``),
    # only list them (``list``), or leave needrestart alone (``unmanaged``:
    # not installed by this deploy and the managed drop-in is removed).
    needrestart: Literal["automatic", "list", "unmanaged"] = "automatic"
    # Services needrestart never restarts on its own (it already skips
    # docker, dbus, networking, getty and the apt units by default).
    needrestart_skip_services: tuple[ServiceName, ...] = ()

    @field_validator("package_blacklist")
    @classmethod
    def _regexes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"package_blacklist entry {pattern!r} is not a valid regex: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _skip_needs_needrestart(self) -> UnattendedUpgradesConfig:
        if self.needrestart_skip_services and self.needrestart == "unmanaged":
            raise ValueError("needrestart_skip_services needs needrestart 'automatic' or 'list'")
        return self

    @model_validator(mode="after")
    def _updates_need_point_releases(self) -> UnattendedUpgradesConfig:
        # The -updates suite builds on the point-release archive; alone it
        # could pull a package whose dependencies wait in that archive.
        if self.debian_stable_updates and not self.debian_point_releases:
            raise ValueError("debian_stable_updates needs debian_point_releases")
        return self

    @property
    def packages(self) -> tuple[str, ...]:
        return ("unattended-upgrades",) + (() if self.needrestart == "unmanaged" else ("needrestart",))


def origins(cfg: UnattendedUpgradesConfig, distro: str) -> tuple[str, ...]:
    """The ``Unattended-Upgrade::Origins-Pattern`` entries for ``distro``."""

    if distro == "ubuntu":
        if cfg.debian_point_releases:
            raise DeployError("unattended_upgrades: debian_point_releases is for Debian hosts only")
        return UBUNTU_SECURITY
    return (
        DEBIAN_SECURITY
        + ((DEBIAN_POINT_RELEASES,) if cfg.debian_point_releases else ())
        + ((DEBIAN_STABLE_UPDATES,) if cfg.debian_stable_updates else ())
    )


def _flag(value: bool) -> str:
    return "true" if value else "false"


def apt_settings(cfg: UnattendedUpgradesConfig, distro: str) -> list[str]:
    """The managed settings as ``apt-config dump`` prints them, in drop-in order."""

    return [
        'APT::Periodic::Update-Package-Lists "1";',
        'APT::Periodic::Unattended-Upgrade "1";',
        f'APT::Periodic::AutocleanInterval "{cfg.autoclean_interval_days}";',
        *(f'Unattended-Upgrade::Origins-Pattern:: "{entry}";' for entry in origins(cfg, distro)),
        *(f'Unattended-Upgrade::Package-Blacklist:: "{entry}";' for entry in cfg.package_blacklist),
        f'Unattended-Upgrade::Remove-Unused-Kernel-Packages "{_flag(cfg.remove_unused_kernel_packages)}";',
        f'Unattended-Upgrade::Remove-Unused-Dependencies "{_flag(cfg.remove_unused_dependencies)}";',
        f'Unattended-Upgrade::Automatic-Reboot "{_flag(cfg.automatic_reboot)}";',
        f'Unattended-Upgrade::Automatic-Reboot-Time "{cfg.automatic_reboot_time}";',
    ]


def _block(key: str, entries: tuple[str, ...]) -> list[str]:
    return [f"{key} {{", *(f'        "{entry}";' for entry in entries), "};"]


def render_apt_dropin(cfg: UnattendedUpgradesConfig, distro: str) -> str:
    """The apt drop-in for ``distro`` (``debian`` or ``ubuntu``)."""

    scalars = apt_settings(cfg, distro)
    lines = [
        f"// {HEADER}",
        "// Effective configuration: apt-config dump | grep -E '^(APT::Periodic|Unattended-Upgrade)'",
        *scalars[:3],
        "",
        "// Replace the packaged origin lists and blacklist instead of extending them.",
        "#clear Unattended-Upgrade::Allowed-Origins;",
        "#clear Unattended-Upgrade::Origins-Pattern;",
        "#clear Unattended-Upgrade::Package-Blacklist;",
        *_block("Unattended-Upgrade::Origins-Pattern", origins(cfg, distro)),
        *_block("Unattended-Upgrade::Package-Blacklist", cfg.package_blacklist),
        "",
        *scalars[-4:],
        'Unattended-Upgrade::SyslogEnable "true";',
    ]
    return "\n".join(lines) + "\n"


def render_needrestart_dropin(cfg: UnattendedUpgradesConfig) -> str:
    """The needrestart drop-in (Perl, evaluated by needrestart.conf)."""

    lines = [f"# {HEADER}", f"$nrconf{{restart}} = '{NEEDRESTART_MODES[cfg.needrestart]}';"]
    for name in cfg.needrestart_skip_services:
        # Like the packaged entries (``qr(^emergency\.service$)``); ``@`` is
        # escaped so Perl does not interpolate an array.
        literal = name.replace(".", "\\.").replace("@", "\\@")
        lines.append(f"$nrconf{{override_rc}}{{qr(^{literal}$)}} = 0;")
    return "\n".join(lines) + "\n"


def _check_script(expected: list[str]) -> str:
    """Compare the effective managed settings with ``expected``; fail with both on a mismatch.

    Origins, blacklist and the scalar keys are compared as sorted sets, so a
    later drop-in that adds an origin or overrides a value is caught. The
    script holds no backslash pair and no backslash before a quote, so a fish
    login shell passes it unchanged.
    """

    lists = "Unattended-Upgrade::(Origins-Pattern|Allowed-Origins|Package-Blacklist)"
    keys = (
        f"^({lists}::[^ ]* "
        "|Unattended-Upgrade::(Remove-Unused-Kernel-Packages|Remove-Unused-Dependencies|Automatic-Reboot"
        "|Automatic-Reboot-Time) |APT::Periodic::(Update-Package-Lists|Unattended-Upgrade|AutocleanInterval) )"
    )
    # unattended-upgrade reads named list entries (``Origins-Pattern::extra``)
    # like anonymous ones; the name is dropped so such an entry is compared too.
    unname = f"s/^({lists})::[^ ]* /\\1:: /"
    want = "\n".join(sorted(expected)) + "\n"
    return (
        "set -e; dump=$(apt-config dump); "
        f'got=$(printf "%s\\n" "$dump" | grep -E {shlex.quote(keys)} | sed -E {shlex.quote(unname)} | LC_ALL=C sort); '
        f"want=$(printf %s {shlex.quote(want)} | LC_ALL=C sort); "
        'if [ "$got" != "$want" ]; then printf "effective:\\n%s\\nexpected:\\n%s\\n" "$got" "$want" >&2; exit 1; fi; '
        "if printf '%s\\n' \"$dump\" | grep -qx 'APT::Periodic::Enable \"0\";'; then "
        "echo 'APT::Periodic::Enable is 0: no periodic apt run' >&2; exit 1; fi; "
        "command -v unattended-upgrade >/dev/null; "
        "for timer in apt-daily.timer apt-daily-upgrade.timer; do "
        'state=$(systemctl is-enabled "$timer" 2>/dev/null || true); '
        '[ "$state" = enabled ] || { echo "$timer is ${state:-unknown}, not enabled" >&2; exit 1; }; done'
    )


def _distro() -> str:
    found = output(OS_PROBE).split()
    if len(found) != 2 or (found[0], found[1]) not in SUPPORTED:
        supported = ", ".join(f"{name} {version}" for name, version in sorted(SUPPORTED))
        raise DeployError(f"unattended_upgrades: supports {supported}, not {' '.join(found) or 'an unknown OS'}")
    return found[0]


def _refuse_non_files(*paths: str) -> None:
    """Fail before any change unless each path is missing or a regular file (a symlink is refused)."""

    probe = "; ".join(f"{STAT_KIND} {shlex.quote(path)} 2>/dev/null || echo missing" for path in paths)
    kinds = output(probe).splitlines()
    if len(kinds) != len(paths):
        raise DeployError(f"unattended_upgrades: could not read the file types of {', '.join(paths)}")
    for path, kind in zip(paths, kinds, strict=True):
        if kind not in ("missing", "regular file", "regular empty file"):
            raise DeployError(f"unattended_upgrades: {path} is a {kind}, not a regular file")


@deploy("unattended-upgrades")
def deploy_unattended_upgrades(cfg: UnattendedUpgradesConfig) -> None:
    require_systemd("unattended_upgrades")
    distro = _distro()
    apt_dropin = render_apt_dropin(cfg, distro)
    _refuse_non_files(APT_DROPIN, NEEDRESTART_DROPIN)

    installed = host.get_fact(DebPackages) or {}
    if any(package not in installed for package in cfg.packages):
        apt.update(name="Refresh apt cache", cache_time=3600)
        apt.packages(name="Install unattended-upgrades", packages=list(cfg.packages))

    files.put(
        name=f"Write {APT_DROPIN}",
        src=StringIO(apt_dropin),
        dest=APT_DROPIN,
        user="root",
        group="root",
        mode="0644",
    )
    if cfg.needrestart == "unmanaged":
        files.file(name=f"Remove {NEEDRESTART_DROPIN}", path=NEEDRESTART_DROPIN, present=False)
    else:
        files.directory(name=f"Ensure {NEEDRESTART_DIR}", path=NEEDRESTART_DIR, user="root", group="root", mode="0755")
        files.put(
            name=f"Write {NEEDRESTART_DROPIN}",
            src=StringIO(render_needrestart_dropin(cfg)),
            dest=NEEDRESTART_DROPIN,
            user="root",
            group="root",
            mode="0644",
        )

    mark_read_only(
        server.shell(
            name="Check the effective unattended-upgrades policy",
            commands=[_check_script(apt_settings(cfg, distro))],
        )
    )
