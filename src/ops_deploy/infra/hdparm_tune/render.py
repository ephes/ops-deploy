"""Render the role's block and boot resources, retaining their original bytes."""

from __future__ import annotations

import shlex
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import HdparmTuneConfig

BEGIN = "# BEGIN ANSIBLE MANAGED BLOCK: hdparm_tune"
END = "# END ANSIBLE MANAGED BLOCK: hdparm_tune"

# The vendored role templates, rendered with Ansible's template defaults
# (trim_blocks, no lstrip_blocks) and its default ``ansible_managed`` text.
ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
)
ENV.filters["quote"] = shlex.quote
BOOT_TEMPLATES = {"script": "hdparm-tune-apply.sh.j2", "unit": "hdparm-tune.service.j2"}


def render_block(cfg: HdparmTuneConfig) -> str:
    lines: list[str] = []
    for device in cfg.devices:
        lines.append(f"{device.device} {{")
        for field in ("apm", "acoustic_management", "spindown_time"):
            value = getattr(device, field)
            if value is not None:
                lines.append(f"  {field} = {value}")
        lines.append("}")
    return "\n".join(lines) + ("\n" if lines else "")


def render_boot(cfg: HdparmTuneConfig, resource: str) -> str:
    """The boot apply ``script`` or ``unit``, byte-equal to the role's template."""

    devices = [device.model_dump(exclude_none=True) for device in cfg.devices]
    return ENV.get_template(BOOT_TEMPLATES[resource]).render(
        ansible_managed="Ansible managed",
        hdparm_tune_devices=devices,
        hdparm_tune_boot_script_path=cfg.boot_script_path,
        hdparm_tune_boot_device_wait_sec=cfg.boot_device_wait_sec,
    )
