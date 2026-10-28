"""Render the role's block, retaining its marker and option ordering."""

from __future__ import annotations

from .config import HdparmTuneConfig

BEGIN = "# BEGIN ANSIBLE MANAGED BLOCK: hdparm_tune"
END = "# END ANSIBLE MANAGED BLOCK: hdparm_tune"


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
