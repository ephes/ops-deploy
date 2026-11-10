"""Visible boot on Intel graphics with full disk encryption (the ``boot_visible_i915`` role).

The i915 driver is loaded in the initramfs (blacklist entries removed), and
``/etc/default/grub`` is rendered whole from the role's template, so GRUB's
menu, the kernel messages and the LUKS prompt show on the console.
"""

from __future__ import annotations

import shlex
from io import StringIO
from typing import Annotated

from pydantic import Field
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, server
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output, require_linux
from ops_deploy.base.remote_luks_unlock import backup_command

GRUB = "/etc/default/grub"
MODULES = "/etc/initramfs-tools/modules"
BLACKLIST = r"^\s*blacklist\s+i915"
# The role's template header, kept so a converged host shows no change.
HEADER = (
    "# /etc/default/grub - managed by boot_visible_i915 role\n"
    "# WARNING: This file is managed by Ansible. Local edits will be overwritten.\n"
    "# To customize, set variables in your playbook or host_vars.\n"
)

# A GRUB setting value written unquoted into /etc/default/grub (sourced by sh).
GrubWord = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]*$")]
# A kernel command line token: no quotes, no shell expansion.
KernelParam = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.,:=/+-]+$")]
# A menu entry title path for GRUB_DEFAULT ("Advanced options for Ubuntu>Ubuntu, with Linux 6.8.0-1").
MenuEntry = Annotated[str, Field(pattern=r"^[A-Za-z0-9 _.,:()>+-]+$")]


class BootVisibleI915Config(RoleConfig):
    enable_i915: bool = True
    remove_i915_blacklist: bool = True
    modify_grub_cmdline: bool = True
    # GRUB_DEFAULT: None renders the role's ``0``; a menu entry renders it quoted.
    grub_default_entry: MenuEntry | None = None
    grub_terminal: GrubWord = "console"
    grub_gfxpayload: GrubWord = "text"
    grub_base_cmdline: tuple[KernelParam, ...] = ("quiet", "splash")
    grub_remove_splash: bool = True
    grub_remove_quiet: bool = True
    grub_remove_nomodeset: bool = True
    # Further kernel parameters, e.g. remote_luks_unlock's ``ip_param``.
    grub_extra_params: tuple[KernelParam, ...] = ()
    show_grub_menu: bool = True
    grub_timeout: int = Field(default=5, ge=0)
    grub_timeout_style: GrubWord = "menu"
    grub_timeout_style_hidden: GrubWord = "hidden"
    grub_backup: bool = True


def cmdline(cfg: BootVisibleI915Config) -> str:
    removed = {
        name
        for name, remove in (
            ("splash", cfg.grub_remove_splash),
            ("quiet", cfg.grub_remove_quiet),
            ("nomodeset", cfg.grub_remove_nomodeset),
        )
        if remove
    }
    tokens = [token for token in cfg.grub_base_cmdline if token not in removed] + list(cfg.grub_extra_params)
    return " ".join(dict.fromkeys(tokens))


def grub_file(cfg: BootVisibleI915Config) -> str:
    """The role's ``grub.j2`` as Ansible renders it (``trim_blocks``)."""

    default = "0" if cfg.grub_default_entry is None else f'"{cfg.grub_default_entry}"'
    style = cfg.grub_timeout_style if cfg.show_grub_menu else cfg.grub_timeout_style_hidden
    timeout = cfg.grub_timeout if cfg.show_grub_menu else 0
    lines = [
        f"GRUB_DEFAULT={default}",
        f"GRUB_TIMEOUT_STYLE={style}",
        f"GRUB_TIMEOUT={timeout}",
        "GRUB_DISTRIBUTOR=`lsb_release -i -s 2>/dev/null || echo Debian`",
        f'GRUB_CMDLINE_LINUX_DEFAULT="{cmdline(cfg)}"',
        'GRUB_CMDLINE_LINUX=""',
        "",
    ]
    if cfg.grub_terminal:
        lines.append(f"GRUB_TERMINAL={cfg.grub_terminal}")
    if cfg.grub_gfxpayload:
        lines.append(f"GRUB_GFXPAYLOAD_LINUX={cfg.grub_gfxpayload}")
    lines += ["# Uncomment to disable generation of recovery mode menu entries", '#GRUB_DISABLE_RECOVERY="true"']
    return HEADER + "\n" + "".join(f"{line}\n" for line in lines)


@deploy("Boot visible i915")
def deploy_boot_visible_i915(cfg: BootVisibleI915Config) -> None:
    require_linux("boot_visible_i915")
    initramfs: list[OperationMeta] = []
    if cfg.enable_i915:
        if cfg.remove_i915_blacklist:
            found = output(f"grep -lE {shlex.quote(BLACKLIST)} /etc/modprobe.d/*.conf").split()
            for path in found:
                initramfs.append(
                    files.line(
                        name=f"Remove i915 blacklist from {path}",
                        path=path,
                        line=rf"{BLACKLIST}.*$",
                        present=False,
                        extended_regex=True,
                    )
                )
        # The role touches the file with mode 0644 and keeps its times.
        files.file(name=f"Ensure {MODULES}", path=MODULES, mode="0644")
        initramfs.append(files.line(name="Remove i915 typo 1915", path=MODULES, line="^1915$", present=False))
        initramfs.append(files.line(name="Load i915 in initramfs", path=MODULES, line="^i915$", replace="i915"))
    grub = None
    if cfg.modify_grub_cmdline:
        content = grub_file(cfg)
        current = host.get_fact(FileContents, path=GRUB)
        if cfg.grub_backup and current is not None and "".join(f"{line}\n" for line in current) != content:
            server.shell(name=f"Back up {GRUB}", commands=[backup_command(GRUB)])
        grub = files.put(
            name=f"Render {GRUB}", src=StringIO(content), dest=GRUB, user="root", group="root", mode="0644"
        )
    server.shell(name="Update initramfs", commands=["update-initramfs -u -k all"], _if=any_changed(*initramfs))
    if grub is not None:
        server.shell(name="Update GRUB", commands=["update-grub"], _if=any_changed(grub))
