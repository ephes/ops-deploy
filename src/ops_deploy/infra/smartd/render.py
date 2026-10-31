from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import SmartdConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
ENV.filters["bool"] = bool


def render(cfg: SmartdConfig) -> str:
    devices = []
    for row in cfg.devices:
        values = {"name": row.name, "device": row.device, "type": row.type, "smartd_no_spinup": row.no_spinup}
        if row.short_schedule is not None:
            values["smartd_short_test_schedule"] = row.short_schedule
        if row.long_schedule is not None:
            values["smartd_long_test_schedule"] = row.long_schedule
        for key in ("temp_diff", "temp_info", "temp_crit"):
            value = getattr(row, key)
            if value is not None:
                values["smartd_" + key] = value
        devices.append(values)
    values = {"smartd_" + key: value for key, value in cfg.model_dump().items()}
    values["smartd_devices"] = devices
    return ENV.get_template("smartd.conf.j2").render(**values)
